## -------------------------------------------------------------------------
## UDP Forward <- a blind relay that maps one address to another
## -------------------------------------------------------------------------
##
## The shape of the problem, first, because the design falls out of it:
##
##   clients            a small VPS                a home NAS
##   (many, anywhere)   (weak CPU, public IP)      (strong, no public IP)
##        |                    |                        |
##        +---- datagram ----->|                        |
##                             +---- same datagram ---->|
##                             |<--- answer ------------+
##        |<--- answer --------+
##
## The VPS exists only because the NAS has no address the world can reach. It
## is NOT a participant. It does not hold a key, does not open a frame, does
## not know a session id from a sequence number. It moves bytes.
##
## ┊ Why it must not authenticate ┊
##
## Authenticating would mean running the exchange, holding keys, and paying a
## key derivation per datagram on the weakest machine in the picture. It would
## also mean the relay could read everything. Both are the wrong trade: the
## relay is there to solve reachability, not trust. Cheap filtering that needs
## no secrets -- refusing an address range, refusing an oversized datagram --
## is welcome here. Anything that needs a key belongs on the NAS.
##
## ┊ How an answer finds its way back ┊
##
## The relay hands each client a TAG, and uses a different local socket toward
## the NAS for each tag. The NAS answers to whichever socket it was addressed
## from, so the tag comes back with the answer and names the client:
##
##   client A --> [ tag 1 ] --> NAS      NAS --> [ tag 1 ] --> client A
##   client B --> [ tag 2 ] --> NAS      NAS --> [ tag 2 ] --> client B
##
## This is exactly what a home router does, and it is the reason neither end
## has to know the relay is there. Nothing is added to the datagram, so the
## bytes the NAS sees are the bytes the client sent, and the frame the client
## sealed is the frame the NAS opens.
##
## ┊ What happens when the NAS goes away ┊
##
## A NAS on a home line reboots, changes address, or drops off. While it is
## silent, datagrams for it go into a small buffer rather than being thrown
## away instantly:
##
##   NAS answering    -> forward straight through, buffer stays empty
##   NAS silent       -> hold the most recent few, keep listening
##   buffer full      -> drop the OLDEST and count it
##   NAS returns      -> drain in order, then carry on
##
## The buffer is deliberately tiny. It is overflow protection, not a mailbox:
## it covers a reboot, not an outage. Everything in it is a datagram the real
## transport can ask for again -- DAC rebuilds a missing frame from repair
## shards or re-requests it -- so holding more would spend memory to save
## something that is already recoverable.
##
## ┊ No sockets in here ┊
##
## This module is the decision-making half only. It takes "a datagram arrived
## from here at this time" and answers "send these bytes there". The caller
## owns the sockets. That is the same split the DAC link modules use, and it
## is what makes every rule below testable without a network.

import std/[deques, tables, hashes]

import ../types
import ../transport/types as transport_types
import runePragmas

const
  udpForwardMaxClients* = 512
    ## How many clients may hold a slot at once. A ceiling, not a target: the
    ## relay is reached by anyone who can send a datagram, so the table has to
    ## have a top or a stranger can grow it until the VPS runs out of memory.
  udpForwardClientIdleMs* = 120_000'u64
    ## A slot with no traffic either way for this long is released, freeing
    ## its tag for somebody else.
  udpForwardNasKeepaliveMs* = 20_000'u64
    ## How often the relay pokes the NAS when the clients have gone quiet.
    ## Without it the relay cannot tell "nobody is talking" from "the NAS has
    ## gone", and a home router would drop the mapping anyway.
  udpForwardNasSilentMs* = 60_000'u64
    ## No word from the NAS for this long and it counts as away, so datagrams
    ## start going to the buffer instead of into a hole. Three missed
    ## keepalives, which tolerates ordinary datagram loss.
  udpForwardBufferDatagrams* = 64
    ## The whole buffer, in datagrams. Tiny on purpose -- see above.
  udpForwardBufferBytes* = 262_144
    ## And in bytes, because 64 large datagrams is a different amount of
    ## memory from 64 small ones. Whichever ceiling is met first applies.
  udpForwardMaxDatagramBytes* = 65_507
    ## The largest a UDP payload can be. Anything claiming more is refused
    ## without being looked at.

type
  ## UdpForwardEvent: what one call decided to do.
  UdpForwardEvent* = enum
    ufeNone,
    ufeForwarded,
    ufeBuffered,
    ufeDropped,
    ufeNasChanged

  ## UdpForwardOut: one datagram the caller must actually send.
  ## tag: which local socket to send it from, for datagrams going to the NAS.
  ##   Meaningless in the other direction.
  ## peer: where to send it.
  ## payload: the bytes, unchanged from how they arrived.
  UdpForwardOut* {.role: preparedData,
    expectedCount: [0, 64], lifeCycle: lcJob.} = object
    tag*: uint32
    peer*: transport_types.UdpAddress
    payload*: ByteSeq

  ## UdpForwardSlot: one client's place in the table.
  ## tag: the handle the caller maps to a local socket toward the NAS.
  ## lastSeenMs: last traffic in either direction, used to expire the slot.
  UdpForwardSlot* {.role: truthState,
    expectedCount: [0, udpForwardMaxClients], lifeCycle: lcSession.} = object
    client*: transport_types.UdpAddress
    tag*: uint32
    lastSeenMs*: uint64
    inUse*: bool

  ## UdpForwardStep: the outcome of feeding one datagram or one tick.
  ## send: what to put on the wire, in order.
  ## dropped: datagrams given up on during this call.
  UdpForwardStep* {.role: truthState,
    expectedCount: [0, 1], lifeCycle: lcJob.} = object
    event*: UdpForwardEvent
    send*: seq[UdpForwardOut]
    dropped*: int
    err*: string

  ## UdpForwardConfig: the five numbers that decide how the relay behaves.
  UdpForwardConfig* {.role: configurator.} = object
    maxClients*: int
    clientIdleMs*: uint64
    nasKeepaliveMs*: uint64
    nasSilentMs*: uint64
    bufferDatagrams*: int
    bufferBytes*: int
    maxDatagramBytes*: int

  ## UdpForwarder: one relay process's whole state.
  ## nas: where the NAS is reachable right now. It may move.
  ## nasSeenMs/nasPokedMs: when the NAS was last heard from, and when it was
  ##   last poked, which are what "away" and "due a keepalive" are built on.
  ## slots/index: the client table and its lookup. The index holds positions
  ##   into `slots`, so one bound and one hash, never a second structure a
  ##   stranger can grow independently.
  ## buffer: datagrams held while the NAS is away.
  UdpForwarder* {.role: truthState,
    expectedCount: 1, lifeCycle: lcForever.} = object
    cfg*: UdpForwardConfig
    nas*: transport_types.UdpAddress
    nasSeenMs*: uint64
    nasPokedMs*: uint64
    nasPoked*: bool
      ## Whether the NAS has EVER been poked. Not the same as having heard
      ## from it: a NAS that is down must still be poked on a schedule rather
      ## than on every tick, which is what this separates.
    nasStarted*: bool
    slots*: seq[UdpForwardSlot]
    index*: Table[transport_types.UdpAddress, int]
    buffer*: Deque[UdpForwardOut]
    bufferBytes*: int
    droppedTotal*: uint64
    forwardedTotal*: uint64

proc hash*(a: transport_types.UdpAddress): Hash {.role: helper.} =
  ## a: endpoint used as a table key.
  ## Hashing the record rather than a "host:port" string built per datagram
  ## keeps the hot path free of allocation, which matters on the weak machine
  ## this runs on.
  result = !$(hash(a.host) !& hash(a.port))

proc initUdpForwardConfig*(maxClients: int = udpForwardMaxClients,
    clientIdleMs: uint64 = udpForwardClientIdleMs,
    nasKeepaliveMs: uint64 = udpForwardNasKeepaliveMs,
    nasSilentMs: uint64 = udpForwardNasSilentMs,
    bufferDatagrams: int = udpForwardBufferDatagrams,
    bufferBytes: int = udpForwardBufferBytes,
    maxDatagramBytes: int = udpForwardMaxDatagramBytes):
    UdpForwardConfig {.role: configurator.} =
  ## Every field refused rather than silently corrected, because each one is a
  ## bound on memory a stranger can cause this process to spend.
  if maxClients <= 0:
    raise newException(ValueError, "UDP forward client table must hold one")
  if bufferDatagrams < 0 or bufferBytes < 0:
    raise newException(ValueError, "UDP forward buffer must not be negative")
  if maxDatagramBytes <= 0 or maxDatagramBytes > udpForwardMaxDatagramBytes:
    raise newException(ValueError, "UDP forward datagram cap is out of range")
  if nasSilentMs < nasKeepaliveMs:
    raise newException(ValueError,
      "UDP forward NAS must be given longer to answer than the poke interval")
  result.maxClients = maxClients
  result.clientIdleMs = clientIdleMs
  result.nasKeepaliveMs = nasKeepaliveMs
  result.nasSilentMs = nasSilentMs
  result.bufferDatagrams = bufferDatagrams
  result.bufferBytes = bufferBytes
  result.maxDatagramBytes = maxDatagramBytes

proc initUdpForwarder*(nas: transport_types.UdpAddress,
    cfg: UdpForwardConfig = initUdpForwardConfig()): UdpForwarder {.
    role: configurator, tag: "relay|udp".} =
  ## nas/cfg: where the NAS is expected and how the relay should behave.
  if nas.host.len == 0 or nas.port == 0'u16:
    raise newException(ValueError, "UDP forward needs a NAS address")
  result.cfg = cfg
  result.nas = nas
  result.slots = @[]
  result.index = initTable[transport_types.UdpAddress, int]()
  result.buffer = initDeque[UdpForwardOut]()

proc nasIsAway(F: UdpForwarder, nowMs: uint64): bool {.role: parser,
    tag: "relay|udp", inline.} =
  ## F/nowMs: whether the NAS counts as gone right now.
  ##
  ## Before the first answer ever arrives the NAS is NOT treated as away.
  ## A relay that starts up alongside a booting NAS would otherwise buffer
  ## everything until the first reply, which is the opposite of useful.
  if not F.nasStarted:
    return false
  result = nowMs > F.nasSeenMs and nowMs - F.nasSeenMs > F.cfg.nasSilentMs

proc dropOldestBuffered(F: var UdpForwarder): int {.role: actor,
    tag: "relay|udp".} =
  ## F: one datagram given up on to make room, and how many that was.
  ##
  ## The OLDEST goes. What is held is meant to cover a reboot, so the freshest
  ## datagrams are the ones worth keeping; the stale ones have been overtaken
  ## by the transport's own repair anyway.
  var
    gone: UdpForwardOut = default(UdpForwardOut)
  if F.buffer.len == 0:
    return 0
  gone = F.buffer.popFirst()
  F.bufferBytes = F.bufferBytes - gone.payload.len
  F.droppedTotal = F.droppedTotal + 1'u64
  result = 1

proc bufferForNas(F: var UdpForwarder, item: UdpForwardOut): int {.role: actor,
    tag: "relay|udp".} =
  ## F/item: one datagram held for a NAS that is not answering, and how many
  ## older ones had to be given up to hold it.
  ##
  ## A datagram larger than the whole buffer is refused outright rather than
  ## emptying the buffer to fail anyway.
  if F.cfg.bufferDatagrams == 0 or item.payload.len > F.cfg.bufferBytes:
    F.droppedTotal = F.droppedTotal + 1'u64
    return 1
  while F.buffer.len >= F.cfg.bufferDatagrams and F.buffer.len > 0:
    result = result + dropOldestBuffered(F)
  while F.bufferBytes + item.payload.len > F.cfg.bufferBytes and
      F.buffer.len > 0:
    result = result + dropOldestBuffered(F)
  F.buffer.addLast(item)
  F.bufferBytes = F.bufferBytes + item.payload.len

proc drainBuffer(F: var UdpForwarder, S: var UdpForwardStep) {.role: actor,
    tag: "relay|udp".} =
  ## F/S: everything held for the NAS, queued in the order it arrived.
  while F.buffer.len > 0:
    S.send.add(F.buffer.popFirst())
  F.bufferBytes = 0

proc releaseSlot(F: var UdpForwarder, i: int) {.role: actor,
    tag: "relay|udp".} =
  ## F/i: one client's slot returned to the pool.
  if not F.slots[i].inUse:
    return
  F.index.del(F.slots[i].client)
  F.slots[i].inUse = false
  F.slots[i].client = default(transport_types.UdpAddress)

proc reapIdleSlots(F: var UdpForwarder, nowMs: uint64): int {.role: actor,
    tag: "relay|udp".} =
  ## F/nowMs: slots with no traffic for longer than the idle limit, released.
  var
    i: int = 0
  while i < F.slots.len:
    if F.slots[i].inUse and nowMs > F.slots[i].lastSeenMs and
        nowMs - F.slots[i].lastSeenMs > F.cfg.clientIdleMs:
      releaseSlot(F, i)
      result = result + 1
    i = i + 1

proc freeSlotIndex(F: var UdpForwarder): int {.role: parser,
    tag: "relay|udp".} =
  ## F: a slot position that can be handed out, or -1 when the table is full.
  var
    i: int = 0
  while i < F.slots.len:
    if not F.slots[i].inUse:
      return i
    i = i + 1
  if F.slots.len >= F.cfg.maxClients:
    return -1
  F.slots.add(UdpForwardSlot(tag: uint32(F.slots.len) + 1'u32))
  result = F.slots.len - 1

proc slotForClient(F: var UdpForwarder, client: transport_types.UdpAddress,
    nowMs: uint64): int {.role: actor, tag: "relay|udp".} =
  ## F/client/nowMs: the client's slot, opening one if this is the first time
  ## it has been seen. -1 means the table is full and the datagram is dropped.
  ##
  ## Dropping when full is the honest answer. The alternative -- evicting
  ## somebody to make room -- lets a stranger sending from many addresses push
  ## real clients out, which is a worse failure than refusing the stranger.
  result = F.index.getOrDefault(client, -1)
  if result >= 0:
    F.slots[result].lastSeenMs = nowMs
    return
  discard reapIdleSlots(F, nowMs)
  result = freeSlotIndex(F)
  if result < 0:
    return
  F.slots[result].client = client
  F.slots[result].lastSeenMs = nowMs
  F.slots[result].inUse = true
  F.index[client] = result

proc noteNasSeen*(F: var UdpForwarder, nas: transport_types.UdpAddress,
    nowMs: uint64): UdpForwardStep {.role: actor, tag: "appApi|relay|udp".} =
  ## F/nas/nowMs: the NAS answered, possibly from somewhere new.
  ##
  ## A home line hands out a different address after a reconnect, so the
  ## relay follows the NAS rather than insisting on the address it was
  ## configured with. Anything held while it was away is drained here, in the
  ## order it arrived.
  result.event = ufeNone
  if nas.host != F.nas.host or nas.port != F.nas.port:
    F.nas = nas
    result.event = ufeNasChanged
  F.nasSeenMs = nowMs
  F.nasStarted = true
  drainBuffer(F, result)

proc fromClient*(F: var UdpForwarder, client: transport_types.UdpAddress,
    payload: openArray[uint8], nowMs: uint64): UdpForwardStep {.
    role: orchestrator, tag: "appApi|relay|udp".} =
  ## F/client/payload/nowMs: one datagram off the public socket.
  ##
  ## The payload is never read. It is copied once and handed on, and the only
  ## thing this side judges is its length and where it came from.
  var
    slot: int = 0
    item: UdpForwardOut = default(UdpForwardOut)
  if payload.len == 0 or payload.len > F.cfg.maxDatagramBytes:
    result.event = ufeDropped
    result.dropped = 1
    result.err = "UDP forward datagram size is out of range"
    return
  slot = slotForClient(F, client, nowMs)
  if slot < 0:
    result.event = ufeDropped
    result.dropped = 1
    result.err = "UDP forward client table is full"
    return
  item.tag = F.slots[slot].tag
  item.peer = F.nas
  item.payload = @payload
  if nasIsAway(F, nowMs):
    result.event = ufeBuffered
    result.dropped = bufferForNas(F, item)
    return
  result.event = ufeForwarded
  result.send.add(item)
  F.forwardedTotal = F.forwardedTotal + 1'u64

proc slotForTag(F: UdpForwarder, tag: uint32): int {.role: parser,
    tag: "relay|udp".} =
  ## F/tag: which client a tag belongs to, or -1 if its slot has been released.
  var
    i: int = 0
  result = -1
  while i < F.slots.len:
    if F.slots[i].inUse and F.slots[i].tag == tag:
      return i
    i = i + 1

proc fromNas*(F: var UdpForwarder, tag: uint32,
    payload: openArray[uint8], nowMs: uint64): UdpForwardStep {.
    role: orchestrator, tag: "appApi|relay|udp".} =
  ## F/tag/payload/nowMs: one datagram back from the NAS, on the socket that
  ## belongs to `tag`.
  ##
  ## An answer whose slot has already been released is dropped rather than
  ## guessed at. Sending it to whoever happens to hold the tag next would
  ## hand one client another client's bytes.
  var
    slot: int = 0
    item: UdpForwardOut = default(UdpForwardOut)
  F.nasSeenMs = nowMs
  F.nasStarted = true
  if payload.len == 0 or payload.len > F.cfg.maxDatagramBytes:
    result.event = ufeDropped
    result.dropped = 1
    result.err = "UDP forward datagram size is out of range"
    return
  slot = slotForTag(F, tag)
  if slot < 0:
    result.event = ufeDropped
    result.dropped = 1
    result.err = "UDP forward answer has no client"
    return
  F.slots[slot].lastSeenMs = nowMs
  item.peer = F.slots[slot].client
  item.tag = tag
  item.payload = @payload
  result.event = ufeForwarded
  result.send.add(item)
  F.forwardedTotal = F.forwardedTotal + 1'u64

proc keepaliveDue(F: UdpForwarder, nowMs: uint64): bool {.role: parser,
    tag: "relay|udp", inline.} =
  ## F/nowMs: whether the NAS is due a poke.
  ##
  ## Keyed on when it was last POKED, never on when it was last heard from.
  ## A NAS that is down would otherwise look permanently overdue and be sent
  ## a keepalive on every single tick -- a poke storm from the weakest machine
  ## in the picture, at the exact moment the other end is struggling.
  if not F.nasPoked:
    return true
  result = nowMs > F.nasPokedMs and nowMs - F.nasPokedMs >= F.cfg.nasKeepaliveMs

proc tickUdpForwarder*(F: var UdpForwarder, nowMs: uint64,
    keepalive: openArray[uint8] = []): UdpForwardStep {.role: orchestrator,
    tag: "appApi|relay|udp".} =
  ## F/nowMs/keepalive: the periodic call, and the bytes to poke the NAS with.
  ##
  ## The keepalive payload comes from the caller and is not invented here.
  ## The relay holds no keys, so it cannot produce anything the NAS would
  ## accept as authentic -- what it sends must be something the NAS is happy
  ## to receive from an unauthenticated source and answer or ignore cheaply.
  ##
  ## Three jobs, in order, because each depends on the one before:
  ##
  ##   1. release slots nobody has used, freeing tags
  ##   2. drain anything held, if the NAS is back
  ##   3. poke the NAS, if it is due one
  result.dropped = reapIdleSlots(F, nowMs)
  if result.dropped > 0:
    result.event = ufeDropped
  if F.buffer.len > 0 and not nasIsAway(F, nowMs):
    drainBuffer(F, result)
    result.event = ufeForwarded
  if keepalive.len == 0 or not keepaliveDue(F, nowMs):
    return
  F.nasPokedMs = nowMs
  F.nasPoked = true
  result.send.add(UdpForwardOut(tag: 0'u32, peer: F.nas,
    payload: @keepalive))

proc udpForwardClients*(F: UdpForwarder): int {.role: parser,
    tag: "appApi|relay|udp".} =
  ## F: how many clients hold a slot right now.
  var
    i: int = 0
  while i < F.slots.len:
    if F.slots[i].inUse:
      result = result + 1
    i = i + 1

proc udpForwardBuffered*(F: UdpForwarder): int {.role: parser,
    tag: "appApi|relay|udp".} =
  ## F: how many datagrams are being held for a NAS that is not answering.
  result = F.buffer.len
