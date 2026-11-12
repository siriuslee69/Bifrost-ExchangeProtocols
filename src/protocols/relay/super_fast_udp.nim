## -------------------------------------------------------------------------
## relaySuperFastUDP <- a blind relay that maps one address to another
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
## One exception, kept apart in super_fast_control.nim: a single control link to
## the server, so it can pass on "I am crowded". It carries no client bytes and
## opens no client frame.
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

import std/[tables, hashes]

import ../types
import ../transport/types as transport_types
import runePragmas
import ./overflow_ring
import ./restriction_types
import ./restriction_address
import ./restriction_filter

const
  udpForwardMaxClients* = 512
    ## How many clients may hold a slot at once. A ceiling, not a target: the
    ## relay is reached by anyone who can send a datagram, so the table has to
    ## have a top or a stranger can grow it until the VPS runs out of memory.
  udpForwardMaxClientsPerHost* = 64
    ## How many slots ONE host (one IP address, any port) may hold. Without it a
    ## single machine opens 512 ports and takes every place. 64 leaves room for
    ## many people behind one shared address; 0 = no limit per host.
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
  udpForwardBrakePerSecond*: array[4, int] = [0, 4000, 1000, 200]
    ## Datagrams per second the relay lets through from ALL clients together,
    ## per brake level (0 = no limit). The levels are the same four as DAC's
    ## (dac/level0/brake.nim): 00 go ham .. 11 full brakes.
  udpForwardVipSlots* = 8
    ## How many client addresses may be named VIP. A fixed list, set once.
  udpForwardVipBufferDatagrams* = 16
    ## The VIP overflow box, in datagrams, held while the NAS is away.

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
    maxClientsPerHost*: int
    clientIdleMs*: uint64
    nasKeepaliveMs*: uint64
    nasSilentMs*: uint64
    bufferDatagrams*: int
    bufferBytes*: int
    maxDatagramBytes*: int
    brakePerSecond*: array[4, int]
    vipSlots*: int
    vipBufferDatagrams*: int

  ## RelaySuperFastUdp: one relay process's whole state.
  ## nas: where the NAS is reachable right now. It may move.
  ## nasSeenMs/nasPokedMs: when the NAS was last heard from, and when it was
  ##   last poked, which are what "away" and "due a keepalive" are built on.
  ## slots/index: the client table and its lookup. The index holds positions
  ##   into `slots`, so one bound and one hash, never a second structure a
  ##   stranger can grow independently.
  ## buffer: datagrams held while the NAS is away.
  RelaySuperFastUdp* {.role: truthState,
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
    buffer*: OverflowRing[UdpForwardOut]
    bufferBytes*: int
    droppedTotal*: uint64
    forwardedTotal*: uint64
    restriction*: RestrictionMode
      ## Which clients may send to the NAS. The operator sets it: this relay
      ## reads no AME frames, so no device can change it. rmOpen by default.
    filter*: SourceRules
      ## The lists that mode reads: accept and reject for rmListed, allowed
      ## for rmAllowed. Client addresses, as the operator writes them.
    restricted*: uint64
      ## Datagrams refused by the restriction. Never answered: this relay has
      ## no reply format that a client could read as a refusal.
    brake*: uint8
      ## The operator's brake level, 0..3. One level for ALL clients at once:
      ## this relay reads no frame, so it cannot tell a client to slow down and
      ## cannot hear whether one will. See `setSuperFastBrake`.
    brakeWindowMs: uint64
    brakeCount: int
    braked*: uint64
      ## Datagrams dropped by the brake, never answered.
    vips: seq[transport_types.UdpAddress]
      ## The VIP clients (see `addSuperFastVip`): a fixed list, `cfg.vipSlots`
      ## long, filled from the front.
    vipBuffer: OverflowRing[UdpForwardOut]
      ## VIP datagrams held while the NAS is away; they leave before the rest.
    usedSlots*: int
      ## Client slots in use, kept so "is the table full" costs one compare.
    reaped: bool
    reapedMs: uint64
      ## Whether and when idle slots were last freed on behalf of a newcomer
      ## (`reapForNewcomer`).
    foreign*: uint64
      ## Datagrams that arrived on a socket toward the NAS from somebody who is
      ## not the NAS. Dropped, never passed to a client.
    vipForwarded*: uint64
      ## Datagrams passed because their sender is VIP while it mattered
      ## (a brake, a full table or an absent NAS).

proc initUdpForwardConfig*(maxClients: int = udpForwardMaxClients,
    clientIdleMs: uint64 = udpForwardClientIdleMs,
    nasKeepaliveMs: uint64 = udpForwardNasKeepaliveMs,
    nasSilentMs: uint64 = udpForwardNasSilentMs,
    bufferDatagrams: int = udpForwardBufferDatagrams,
    bufferBytes: int = udpForwardBufferBytes,
    maxDatagramBytes: int = udpForwardMaxDatagramBytes,
    brakePerSecond: array[4, int] = udpForwardBrakePerSecond,
    vipSlots: int = udpForwardVipSlots,
    vipBufferDatagrams: int = udpForwardVipBufferDatagrams,
    maxClientsPerHost: int = udpForwardMaxClientsPerHost):
    UdpForwardConfig {.role: configurator.} =
  ## Every field refused rather than silently corrected, because each one is a
  ## bound on memory a stranger can cause this process to spend.
  if maxClients <= 0:
    raise newException(ValueError, "UDP forward client table must hold one")
  if maxClientsPerHost < 0:
    raise newException(ValueError, "UDP forward per-host limit must not be negative")
  if bufferDatagrams < 0 or bufferBytes < 0:
    raise newException(ValueError, "UDP forward buffer must not be negative")
  if vipSlots < 0 or vipBufferDatagrams < 0:
    raise newException(ValueError, "UDP forward VIP lists must not be negative")
  if maxDatagramBytes <= 0 or maxDatagramBytes > udpForwardMaxDatagramBytes:
    raise newException(ValueError, "UDP forward datagram cap is out of range")
  if nasSilentMs < nasKeepaliveMs:
    raise newException(ValueError,
      "UDP forward NAS must be given longer to answer than the poke interval")
  result.maxClients = maxClients
  result.maxClientsPerHost = maxClientsPerHost
  result.clientIdleMs = clientIdleMs
  result.nasKeepaliveMs = nasKeepaliveMs
  result.nasSilentMs = nasSilentMs
  result.bufferDatagrams = bufferDatagrams
  result.bufferBytes = bufferBytes
  for r in brakePerSecond:
    if r < 0:
      raise newException(ValueError, "UDP forward brake rate must not be negative")
  result.brakePerSecond = brakePerSecond
  result.vipSlots = vipSlots
  result.vipBufferDatagrams = vipBufferDatagrams
  result.maxDatagramBytes = maxDatagramBytes

proc initRelaySuperFastUdp*(nas: transport_types.UdpAddress,
    cfg: UdpForwardConfig = initUdpForwardConfig()): RelaySuperFastUdp {.
    role: configurator, tag: "relay|udp".} =
  ## nas/cfg: where the NAS is expected and how the relay should behave.
  if nas.host.len == 0 or nas.port == 0'u16:
    raise newException(ValueError, "UDP forward needs a NAS address")
  result.cfg = cfg
  result.nas = nas
  result.slots = @[]
  result.index = initTable[transport_types.UdpAddress, int]()
  result.buffer = initOverflowRing[UdpForwardOut](cfg.bufferDatagrams)
  result.vips = newSeq[transport_types.UdpAddress](cfg.vipSlots)
  result.vipBuffer = initOverflowRing[UdpForwardOut](cfg.vipBufferDatagrams)

proc dropOldestBuffered(F: var RelaySuperFastUdp): int {.role: actor,
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

proc bufferForNas(F: var RelaySuperFastUdp, item: UdpForwardOut): int {.role: actor,
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
  discard F.buffer.addLast(item)
  F.bufferBytes = F.bufferBytes + item.payload.len

proc releaseSlot(F: var RelaySuperFastUdp, i: int) {.role: actor,
    tag: "relay|udp".} =
  ## F/i: one client's slot returned to the pool.
  if not F.slots[i].inUse:
    return
  F.index.del(F.slots[i].client)
  F.slots[i].inUse = false
  F.usedSlots = F.usedSlots - 1
  F.slots[i].client = default(transport_types.UdpAddress)

proc freeSlotIndex(F: var RelaySuperFastUdp): int {.role: parser,
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

proc reapIdleSlots(F: var RelaySuperFastUdp, nowMs: uint64): int {.role: actor,
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

proc addSuperFastVip*(F: var RelaySuperFastUdp,
    client: transport_types.UdpAddress): tuple[ok: bool, err: string] {.
    role: actor, tag: "appApi|relay|udp".} =
  ## F/client: name a client address VIP. ok when added (or already there),
  ## else err says why not. Port 0 means every port of that host (a phone
  ## changes its port, its address stays).
  ##
  ## A VIP client is only treated differently while the relay is CONGESTED:
  ##
  ##   a brake is on      -> its datagrams are not dropped by the cap
  ##   the table is full  -> it takes the place of the quietest ordinary client
  ##   the NAS is away    -> its datagrams wait in a box of their own and leave first
  ##
  ## When nothing is congested the list is never looked at, so it costs nothing.
  ## The NAS itself is always first: its answers are never braked, never held
  ## back and never refused a place.
  var
    i: int = 0
  if client.host.len == 0:
    return (ok: false, err: "a VIP needs an address")
  while i < F.cfg.vipSlots:
    if F.vips[i].host.len == 0:
      F.vips[i] = client
      return (ok: true, err: "")
    if F.vips[i] == client:
      return (ok: true, err: "")
    i = i + 1
  result = (ok: false,
    err: "the VIP list holds at most " & $F.cfg.vipSlots & " addresses")

proc clearSuperFastVips*(F: var RelaySuperFastUdp) {.role: actor,
    tag: "appApi|relay|udp".} =
  ## F: the VIP list emptied; the width stays.
  F.vips = newSeq[transport_types.UdpAddress](F.cfg.vipSlots)

proc isVip(F: RelaySuperFastUdp, client: transport_types.UdpAddress): bool {.
    role: parser, tag: "relay|udp".} =
  ## F/client: whether this address is on the VIP list. Only called while the
  ## relay is congested (see `congested`); a list of 8 compares two strings
  ## at most 8 times.
  var
    i: int = 0
  while i < F.cfg.vipSlots:
    if F.vips[i].host.len > 0 and
        (F.vips[i].port == 0'u16 or F.vips[i].port == client.port) and
        sameHost(F.vips[i].host, client.host):
      return true
    i = i + 1

proc stalestPlainSlot(F: RelaySuperFastUdp): int {.role: parser,
    tag: "relay|udp".} =
  ## F: the in-use slot of an ordinary (not VIP) client that was seen longest
  ## ago, or -1 when every slot belongs to a VIP.
  var
    i: int = 0
  result = -1
  while i < F.slots.len:
    if F.slots[i].inUse and not F.isVip(F.slots[i].client) and
        (result < 0 or F.slots[i].lastSeenMs < F.slots[result].lastSeenMs):
      result = i
    i = i + 1

proc reapForNewcomer(F: var RelaySuperFastUdp, nowMs: uint64) {.role: actor,
    tag: "relay|udp".} =
  ## F/nowMs: free idle places before a newcomer asks for one -- at most once
  ## a second. A stranger sending from a new address every datagram would
  ## otherwise make the relay walk its whole table for each of them.
  if F.reaped and nowMs >= F.reapedMs and nowMs - F.reapedMs < 1000'u64:
    return
  F.reaped = true
  F.reapedMs = nowMs
  discard reapIdleSlots(F, nowMs)

proc hostIsFull(F: RelaySuperFastUdp, host: string): bool {.role: parser,
    tag: "relay|udp".} =
  ## F/host: true when that host already holds `cfg.maxClientsPerHost` places
  ## (counted over every port). Only asked when a NEW place would be opened.
  ##
  ##   limit 2:  203.0.113.7:4000  203.0.113.7:4001   -> both get a place
  ##             203.0.113.7:4002                      -> refused: host is full
  ##             198.51.100.4:4000                     -> gets a place
  var
    i: int = 0
    n: int = 0
  if F.cfg.maxClientsPerHost == 0:
    return false
  while i < F.slots.len:
    if F.slots[i].inUse and F.slots[i].client.host == host:
      n = n + 1
    i = i + 1
  result = n >= F.cfg.maxClientsPerHost

proc slotForClient(F: var RelaySuperFastUdp, client: transport_types.UdpAddress,
    nowMs: uint64, vip: bool = false): int {.role: actor, tag: "relay|udp".} =
  ## F/client/nowMs: the client's slot, opening one if this is the first time
  ## it has been seen. -1 means the table is full and the datagram is dropped.
  ## vip: this client is VIP and the relay is congested; when the table is full
  ## it takes the place of the quietest ordinary client instead of being refused.
  ##
  ## Dropping when full is the honest answer. The alternative -- evicting
  ## somebody to make room -- lets a stranger sending from many addresses push
  ## real clients out, which is a worse failure than refusing the stranger.
  result = F.index.getOrDefault(client, -1)
  if result >= 0:
    F.slots[result].lastSeenMs = nowMs
    return
  reapForNewcomer(F, nowMs)
  if not vip and F.usedSlots >= F.cfg.maxClients:
    return -1
  if not vip and hostIsFull(F, client.host):
    return -1
  result = freeSlotIndex(F)
  if result < 0 and vip:
    result = stalestPlainSlot(F)
    if result >= 0:
      releaseSlot(F, result)
  if result < 0:
    return
  F.usedSlots = F.usedSlots + 1
  F.slots[result].client = client
  F.slots[result].lastSeenMs = nowMs
  F.slots[result].inUse = true
  F.index[client] = result

proc drainBuffer(F: var RelaySuperFastUdp, S: var UdpForwardStep) {.role: actor,
    tag: "relay|udp".} =
  ## F/S: everything held for the NAS: the VIP box first, then the rest, each
  ## in the order it arrived. Each datagram is addressed NOW, to where the NAS
  ## is at this moment: it may have come back at a new address, and the one
  ## noted when the datagram was held would be a hole.
  var
    first: int = S.send.len
  while F.vipBuffer.len > 0:
    S.send.add(F.vipBuffer.popFirst())
  while F.buffer.len > 0:
    S.send.add(F.buffer.popFirst())
  F.bufferBytes = 0
  while first < S.send.len:
    S.send[first].peer = F.nas
    first = first + 1

proc noteNasSeen*(F: var RelaySuperFastUdp, nas: transport_types.UdpAddress,
    nowMs: uint64): UdpForwardStep {.role: actor, tag: "appApi|relay|udp".} =
  ## F/nas/nowMs: the NAS answered, possibly from somewhere new.
  ##
  ## A home line hands out a different address after a reconnect, so the
  ## relay follows the NAS rather than insisting on the address it was
  ## configured with. Anything held while it was away is drained here, in the
  ## order it arrived.
  ##
  ## WHOEVER IS NAMED HERE GETS EVERY CLIENT'S DATAGRAMS FROM NOW ON. Call it
  ## only for a sign of life the caller can trust: a frame that authenticated
  ## on the control link (super_fast_control.nim), or a reply from the address
  ## the NAS already has. A plain reply from a NEW address proves nothing --
  ## following it lets any stranger take the NAS's place (the content stays
  ## sealed, but nothing arrives any more).
  result.event = ufeNone
  if nas.port != F.nas.port or not sameHost(nas.host, F.nas.host):
    F.nas = nas
    result.event = ufeNasChanged
  F.nasSeenMs = nowMs
  F.nasStarted = true
  drainBuffer(F, result)

proc nasIsAway(F: RelaySuperFastUdp, nowMs: uint64): bool {.role: parser,
    tag: "relay|udp", inline.} =
  ## F/nowMs: whether the NAS counts as gone right now.
  ##
  ## Before the first answer ever arrives the NAS is NOT treated as away.
  ## A relay that starts up alongside a booting NAS would otherwise buffer
  ## everything until the first reply, which is the opposite of useful.
  if not F.nasStarted:
    return false
  result = nowMs > F.nasSeenMs and nowMs - F.nasSeenMs > F.cfg.nasSilentMs

proc setSuperFastRestriction*(F: var RelaySuperFastUdp, mode: RestrictionMode,
    rules: SourceRules): tuple[ok: bool, err: string] {.role: actor,
    tag: "appApi|relay|udp".} =
  ## F/mode/rules: the operator's restriction on who may send to the NAS.
  ## ok when set, else err says why not. rmGroup needs AME control frames,
  ## which this relay never opens, so it is refused here.
  if mode == rmGroup:
    return (ok: false, err: "the super-fast relay cannot run the group mode: " &
      "it reads no control frames")
  if not restrictionBuilt(mode):
    return (ok: false,
      err: "restriction mode " & $mode & " is not compiled into this relay")
  if rules.accept.len > restrictionMaxRules or
      rules.reject.len > restrictionMaxRules or
      rules.allowed.len > restrictionMaxRules:
    return (ok: false, err: "a list holds at most " & $restrictionMaxRules &
      " addresses")
  F.restriction = mode
  F.filter = rules
  result = (ok: true, err: "")

proc congested(F: RelaySuperFastUdp, nowMs: uint64): bool {.role: parser,
    tag: "relay|udp", inline.} =
  ## F/nowMs: whether the relay is under pressure right now: a brake is on, the
  ## client table is full, or the NAS is away. Three cheap compares; this is
  ## the only thing the VIP list costs while nothing is wrong.
  result = F.brake != 0'u8 or F.usedSlots >= F.cfg.maxClients or
    nasIsAway(F, nowMs)

proc vipsMatter(F: RelaySuperFastUdp, client: transport_types.UdpAddress,
    nowMs: uint64): bool {.role: parser, tag: "relay|udp", inline.} =
  ## F/client/nowMs: true when the relay is congested AND this client is VIP.
  ## The list is not looked at when nothing is congested, or when it is empty.
  result = F.cfg.vipSlots > 0 and congested(F, nowMs) and isVip(F, client)

proc bufferVipForNas(F: var RelaySuperFastUdp, item: UdpForwardOut): int {.
    role: actor, tag: "relay|udp".} =
  ## F/item: a VIP datagram held for a NAS that is not answering, in the VIP
  ## box. Returns 1 when it (or an older VIP datagram) was given up.
  if F.cfg.vipBufferDatagrams == 0 or item.payload.len > F.cfg.bufferBytes:
    F.droppedTotal = F.droppedTotal + 1'u64
    return 1
  if F.vipBuffer.isFull:
    F.droppedTotal = F.droppedTotal + 1'u64
    result = 1
  discard F.vipBuffer.addLast(item)

proc clientMayReach(F: RelaySuperFastUdp, client: transport_types.UdpAddress): bool {.
    role: parser.} =
  ## F/client: the operator's list decides for this client's address. Text
  ## is turned into the compact form per datagram, which is only paid while a
  ## restriction is set: the default rmOpen never gets here.
  var
    src: tuple[ok: bool, src: SourceAddr, err: string] = sourceOfAddress(client)
  if not src.ok:
    return false
  result = filterAllows(F.restriction, F.filter, src.src)

proc setSuperFastBrake*(F: var RelaySuperFastUdp, level: uint8): tuple[
    ok: bool, err: string] {.role: actor, tag: "appApi|relay|udp".} =
  ## F/level: the operator's slow-down for ALL clients at once, 0 (go ham)
  ## .. 3 (full brakes). ok when set, else err says why not.
  ##
  ## Two things happen at this level. (1) With a control link to the server
  ## (relay/super_fast_control.nim) the level is SENT to the server, which
  ## tells every client. (2) Always, this relay limits how many datagrams per
  ## second it passes to the NAS, summed over every client:
  ##
  ##   level   datagrams per second (default)
  ##     0     no limit
  ##     1     4000          the rest are dropped and counted in `braked`.
  ##     2     1000          Clients feel it as loss, and DAC's own repair
  ##     3      200          and path reports slow them down.
  if level > 3'u8:
    return (ok: false, err: "the brake level is 0..3")
  F.brake = level
  F.brakeWindowMs = 0'u64
  F.brakeCount = 0
  result = (ok: true, err: "")

proc brakeAllows(F: var RelaySuperFastUdp, nowMs: uint64): bool {.role: parser,
    tag: "relay|udp".} =
  ## F/nowMs: whether one more client datagram fits in this second's budget.
  ## A second is counted from its first datagram, not from the wall clock.
  var
    rate: int = F.cfg.brakePerSecond[int(F.brake)]
  if F.brake == 0'u8 or rate == 0:
    return true
  if nowMs < F.brakeWindowMs or nowMs - F.brakeWindowMs >= 1000'u64:
    F.brakeWindowMs = nowMs
    F.brakeCount = 0
  if F.brakeCount >= rate:
    return false
  F.brakeCount = F.brakeCount + 1
  result = true

proc fromClient*(F: var RelaySuperFastUdp, client: transport_types.UdpAddress,
    payload: openArray[uint8], nowMs: uint64): UdpForwardStep {.
    role: orchestrator, tag: "appApi|relay|udp".} =
  ## F/client/payload/nowMs: one datagram off the public socket.
  ##
  ## The payload is never read. It is copied once and handed on, and the only
  ## thing this side judges is its length and where it came from.
  var
    slot: int = 0
    item: UdpForwardOut = default(UdpForwardOut)
    vip: bool = false
  if payload.len == 0 or payload.len > F.cfg.maxDatagramBytes:
    result.event = ufeDropped
    result.dropped = 1
    result.err = "UDP forward datagram size is out of range"
    return
  vip = F.vipsMatter(client, nowMs)
  if F.restriction != rmOpen and not clientMayReach(F, client):
    F.restricted = F.restricted + 1'u64
    result.event = ufeDropped
    result.dropped = 1
    result.err = "restricted: " & $F.restriction
    return
  if not vip and not brakeAllows(F, nowMs):
    F.braked = F.braked + 1'u64
    result.event = ufeDropped
    result.dropped = 1
    result.err = "braked: level " & $F.brake
    return
  slot = slotForClient(F, client, nowMs, vip)
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
    if vip:
      result.dropped = bufferVipForNas(F, item)
    else:
      result.dropped = bufferForNas(F, item)
    return
  result.event = ufeForwarded
  result.send.add(item)
  F.forwardedTotal = F.forwardedTotal + 1'u64
  if vip:
    F.vipForwarded = F.vipForwarded + 1'u64

proc slotForTag(F: RelaySuperFastUdp, tag: uint32): int {.role: parser,
    tag: "relay|udp".} =
  ## F/tag: which client a tag belongs to, or -1 if its slot has been released.
  var
    i: int = 0
  result = -1
  while i < F.slots.len:
    if F.slots[i].inUse and F.slots[i].tag == tag:
      return i
    i = i + 1

proc fromNas*(F: var RelaySuperFastUdp, source: transport_types.UdpAddress,
    tag: uint32, payload: openArray[uint8], nowMs: uint64): UdpForwardStep {.
    role: orchestrator, tag: "appApi|relay|udp".} =
  ## F/source/tag/payload/nowMs: one datagram that arrived on the socket that
  ## belongs to `tag`, and the address it came from.
  ##
  ## Only the NAS may speak on those sockets. Their ports can be guessed, so
  ## without this check anyone could (1) have the relay pass bytes on to a
  ## client while hiding where they came from, and (2) make a dead NAS look
  ## alive, so nothing is held for it. A datagram from anywhere else is
  ## counted in `foreign` and dropped. When the NAS moves, `noteNasSeen` is
  ## what tells the relay -- never a datagram on a client's socket.
  ##
  ## An answer whose slot has already been released is dropped rather than
  ## guessed at. Sending it to whoever happens to hold the tag next would
  ## hand one client another client's bytes.
  var
    slot: int = 0
    item: UdpForwardOut = default(UdpForwardOut)
  if source.port != F.nas.port or not sameHost(source.host, F.nas.host):
    F.foreign = F.foreign + 1'u64
    result.event = ufeDropped
    result.dropped = 1
    result.err = "UDP forward answer is not from the NAS"
    return
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

proc keepaliveDue(F: RelaySuperFastUdp, nowMs: uint64): bool {.role: parser,
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

proc tickRelaySuperFastUdp*(F: var RelaySuperFastUdp, nowMs: uint64,
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
  if F.buffer.len + F.vipBuffer.len > 0 and not nasIsAway(F, nowMs):
    drainBuffer(F, result)
    result.event = ufeForwarded
  if keepalive.len == 0 or not keepaliveDue(F, nowMs):
    return
  F.nasPokedMs = nowMs
  F.nasPoked = true
  result.send.add(UdpForwardOut(tag: 0'u32, peer: F.nas,
    payload: @keepalive))

proc udpForwardClients*(F: RelaySuperFastUdp): int {.role: parser,
    tag: "appApi|relay|udp".} =
  ## F: how many clients hold a slot right now.
  var
    i: int = 0
  while i < F.slots.len:
    if F.slots[i].inUse:
      result = result + 1
    i = i + 1

proc udpForwardBuffered*(F: RelaySuperFastUdp): int {.role: parser,
    tag: "appApi|relay|udp".} =
  ## F: how many datagrams are being held for a NAS that is not answering,
  ## VIP box included.
  result = F.buffer.len + F.vipBuffer.len
