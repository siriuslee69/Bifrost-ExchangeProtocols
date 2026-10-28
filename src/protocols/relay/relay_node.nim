## -------------------------------------------------------------------------
## Relay Node <- what relayFastExtraFrame and relaySlowExtractEncrypt share:
##               neighbours, the directory, permission, the way onward
## -------------------------------------------------------------------------
##
## Bifrost has three ways to carry traffic through a machine in the middle:
##
##   name                     module                  the middle machine ...
##   -----------------------  ----------------------  -----------------------
##   relaySuperFastUDP        super_fast_udp.nim      moves bytes, holds no key
##   relayFastExtraFrame      fast_extra_frame.nim    re-seals 16 address bytes
##   relaySlowExtractEncrypt  slow_extract_encrypt    opens, reads, re-seals all
##
## The last two decide the same things the same way -- who may reach whom,
## and which neighbour is one hop closer. That part lives here. They differ
## only in how a frame is opened and sealed again, which `kind` selects.
##
## No sockets in here. A frame comes in from an ADDRESS (or a slot), and out
## come frames, each with the address it must be sent to.
##
## ╭─ ❧ Def. 1: the words 🌊
##
##   node        anything holding a relay: a relay in the middle, or an
##               endpoint with one link. It has its own id (`selfId`).
##   neighbour   one machine with a finished link handshake, in a SLOT.
##               It has an id (u64), an identity (the name the handshake
##               proved, e.g. a pin name) and the ADDRESS it talks from.
##   router      a neighbour flagged as another relay. Its origin ids are
##               believed; a client's never are.
##   target      a line in this node's directory: id, name, who may see it,
##               and -- for a target behind another relay -- which relay
##               neighbour leads there (`via`).
##   return      a short-lived note "origin X wrote from behind relay R to
##               target T". It is how T's answer finds X.
##
## ╭─ ❧ Def. 2: one neighbour in memory 🍣
##
##   field      what                                     why it is needed
##   ---------  ---------------------------------------  -------------------
##   id         u64 route id                             addressing
##   identity   proved name ("phone")                    permission
##   address    IP + port its datagrams come from        address -> secret,
##                                                       and where answers go
##   carrier    DAC or TCP                               how to seal for it
##   router     another relay?                           trust its origins?
##   session    the link: TK, two lane chain keys,       open + seal
##              header and route keys, counters
##
## Nothing of it is written to disk. The secrets must not be (a copy on
## disk outlives the session and breaks forward secrecy); the rest is
## rebuilt by the next handshake. A neighbour's session keeps NO inbox
## (`ameNoInbox`): what arrives is passed on, delivered or dropped.
##
## ╭─ ❧ Def. 3: who may send to whom 🐦‍🔥
##
##   sender           target                      allowed when
##   ---------------  --------------------------  ----------------------------
##   anyone           this node itself            always -- the end-to-end
##                                                handshake decides
##   a router         anything                    always -- the relay before
##                                                it already checked
##   a client         a directory target          its identity is in the
##                                                target's `visibleTo` ("*"
##                                                = everyone)
##   a client         another local neighbour     that neighbour's target line
##                                                is visible to it, OR the
##                                                reverse: whoever may write
##                                                to you may be answered
##   a client         an origin from far away     a return note says that
##                                                origin wrote to THIS client
##
## A refusal never says which rule failed: "no such id" and "not for you"
## are the same `arrNoRoute`, so ids cannot be probed.
##
## ╭─ ❧ Def. 4: where a forward goes ❧
##
##   0. target is `selfId`                   -> delivered here
##   1. a local neighbour with that id       -> forward to it
##   2. a target line with `via` = relay R   -> forward to R
##   3. a live return note for that id       -> forward to the relay it
##                                              came from
##   4. nothing, or back where it came from  -> refuse: arrNoRoute
##
## Each node takes one hop from `hopsLeft`. At zero the forward is refused
## with arrHopsSpent, so a loop between relays burns out.
##
## Example 1. Two relays, a phone behind the first, a NAS behind the second:
##
##   relay 1   targets: 0x20 "nas"  visibleTo ["phone"]  via 0x11
##             neighbours: phone (0x30), relay 2 (0x11, router)
##   relay 2   targets: 0x20 "nas"  visibleTo ["relay1"]
##             neighbours: relay 1 (0x10, router), nas (0x20)
##
##   phone   forward(0x20)              -> relay 1: rule "directory"; via
##   relay1  forward(0x20, from 0x30)   -> relay 2: from a router; local 0x20
##   relay2  forward(0x20, from 0x30)   -> nas, notes "0x30 via relay 1"
##   nas     0x20 is me                 -> delivered
##   nas     forward(0x30)              -> relay 2: return note matches
##   relay2  forward(0x30, from 0x20)   -> relay 1: from a router; local 0x30
##   phone   0x30 is me                 -> delivered

import std/tables

import ../types
import ../transport/types as transport_types
import ../ame/types
import ../ame/level2/session
import ../ame/level2/route_wire
import ../ame/level2/route_directory
import ./slow_envelope
import ./restriction
import ./restriction_store
import runePragmas

const
  relayCapacity* = 512
    ## Most neighbours one node holds at once.
  relayReturnCapacity* = 256
    ## Most return notes kept. When full, the oldest is replaced.
  relayReturnMs* = 120_000'u32
    ## How long a return note lives after the last forward that refreshed it.
  relayEveryone* = "*"
    ## Written in `visibleTo` to show a target to every identity.

type
  ## RelayKind: how frames are opened and sealed on every link of a node.
  RelayKind* = enum
    rkFastExtraFrame,
      ## outer "ART" frame, only the 16 address bytes are re-sealed
    rkSlowExtractEncrypt
      ## whole AME data frame opened and sealed again; payload readable

  ## RelayNeighbour: one neighbour (Def. 2).
  RelayNeighbour* {.role: truthState, expectedCount: [0, 512],
      lifeCycle: lcSession.} = object
    used*: bool
    id*: uint64
    identity*: string
    address*: transport_types.UdpAddress
      ## where its datagrams come from, and where frames for it are sent
    source*: SourceAddr
      ## the same address in compact form, for the restriction checks
    carrier*: AmeCarrier
    router*: bool
    session*: AmeSession
    answered*: bool
      ## true once a restricted frame from this neighbour got an answer
    answeredMs*: uint32
      ## when that answer was sent; the next one waits restrictionAnswerMs

  ## RelayTarget: one directory line (Def. 1).
  ## via: 0 for a target that connects to THIS node itself, otherwise the
  ##   id of the relay neighbour that leads to it.
  RelayTarget* {.role: configurator.} = object
    id*: uint64
    name*: string
    visibleTo*: seq[string]
    via*: uint64

  ## RelayReturn: one return note (Def. 1).
  RelayReturn {.role: memory, expectedCount: [0, 256],
      lifeCycle: 120000.} = object
    origin: uint64
    via: uint64
      ## the relay neighbour's id, not its slot: a slot is reused once freed
    reached: uint64
    lastMs: uint32

  ## RelayInspect: relaySlowExtractEncrypt only. Sees each forward that is
  ## about to be passed on, with its payload in clear, and the identity of
  ## the neighbour it came from. May change `f.payload`; false refuses it
  ## (as arrNoRoute, like every other refusal).
  RelayInspect* = proc (identity: string, f: var AmeRouteFrame): bool {.
    closure.}

  ## RelayNode: what both keyed relays are made of.
  RelayNode* {.role: truthState, expectedCount: 1,
      lifeCycle: lcForever.} = object of RootObj
    kind*: RelayKind
    selfId*: uint64
    neighbours*: seq[RelayNeighbour]
    bySource: Table[transport_types.UdpAddress, int]
      ## address -> slot: the first thing every arriving datagram needs
    targets*: seq[RelayTarget]
    returns: seq[RelayReturn]
    inspect: RelayInspect
    forwarded*: uint32
    restriction*: RestrictionMode
      ## The one way this relay decides who may talk to whom (default rmOpen).
    book*: RestrictionBook
      ## What the restriction modes keep: the group object and each
      ## connection's address lists.
    restricted*: uint32
      ## Frames the restriction refused, answered or not.
    restrictionAnswerMs*: uint32
      ## Gap between two answers to one restricted neighbour. A restricted
      ## frame inside the gap is dropped without an answer. 0 never answers.
    bookDir*: string
      ## Where the book is saved through Geist. "" keeps it in memory only.
    delivered*: uint32
    refused*: uint32
    dropped*: uint32

  ## RelayEvent: what one arriving frame led to.
  RelayEvent* = enum
    reNone,
    reDropped,
    reAnswered,
      ## a directory question was answered
    reForwarded,
    reDelivered,
      ## the target was this node: the payload is in `step.frame`
    reRefused

  ## RelaySend: one sealed frame and where it must go.
  RelaySend* {.role: preparedData, expectedCount: [0, 512],
      lifeCycle: lcJob.} = object
    slot*: int
    address*: transport_types.UdpAddress
    frame*: ByteSeq

  ## RelayStep: outcome of one feed.
  ## send: frames to transmit, each to its `address`, in order.
  ## frame: the opened frame, its origin already decided -- read its
  ##   payload on reDelivered, its refusal on reRefused with no `send`.
  ## slot: the neighbour it arrived from.
  RelayStep* {.role: truthState, expectedCount: [0, 512],
      lifeCycle: lcJob.} = object
    event*: RelayEvent
    send*: seq[RelaySend]
    frame*: AmeRouteFrame
    slot*: int
    err*: string

## ---------------------------- setting up ----------------------------

proc setupRelayNode*(R: var RelayNode, kind: RelayKind, selfId: uint64,
    capacity: int, inspect: RelayInspect = nil) {.role: configurator.} =
  ## R: the node being built (a RelayFastExtraFrame or RelaySlowExtractEncrypt).
  ## kind: how its links open and seal. selfId: its own id.
  ## capacity: how many neighbours fit; a ceiling, not a target.
  ## inspect: slow kind only; nil lets every allowed forward through.
  if selfId == 0'u64:
    raise newException(ValueError, "relay id 0 is reserved")
  if capacity <= 0:
    raise newException(ValueError, "relay capacity must be positive")
  if inspect != nil and kind != rkSlowExtractEncrypt:
    raise newException(ValueError,
      "only relaySlowExtractEncrypt can read what it passes on")
  R.kind = kind
  R.selfId = selfId
  R.neighbours = newSeq[RelayNeighbour](capacity)
  R.bySource = initTable[transport_types.UdpAddress, int]()
  R.inspect = inspect
  R.restrictionAnswerMs = restrictionAnswerDefaultMs

proc findRelayTarget*(R: RelayNode, id: uint64): int {.role: parser.} =
  ## R/id: index of the directory line with that id, or -1.
  var
    i: int = 0
  result = -1
  while i < R.targets.len:
    if R.targets[i].id == id:
      return i
    i = i + 1

proc findRelayNeighbour*(R: RelayNode, id: uint64): int {.role: parser.} =
  ## R/id: slot of the live neighbour with that id, or -1.
  var
    i: int = 0
  result = -1
  while i < R.neighbours.len:
    if R.neighbours[i].used and R.neighbours[i].id == id:
      return i
    i = i + 1

proc relaySlotOf*(R: RelayNode, a: transport_types.UdpAddress): int {.
    role: parser, tag: "appApi".} =
  ## R/a: slot of the neighbour talking from that address, or -1.
  result = R.bySource.getOrDefault(a, -1)

proc addRelayTarget*(R: var RelayNode, id: uint64, name: string,
    visibleTo: openArray[string], via: uint64 = 0'u64) {.role: configurator,
    tag: "appApi".} =
  ## R: node whose directory grows by one line.
  ## id/name: what clients address, and what they read in the directory.
  ## visibleTo: identities that may see and reach it; "*" = everyone.
  ## via: 0 when the target connects here; else the next relay's id.
  if id == 0'u64:
    raise newException(ValueError, "relay id 0 is reserved")
  requireRouteName(name)
  if findRelayTarget(R, id) >= 0:
    raise newException(ValueError, "relay target id is already listed")
  R.targets.add(RelayTarget(id: id, name: name, visibleTo: @visibleTo,
    via: via))

proc freeRelaySlot(R: RelayNode): int {.role: parser.} =
  ## R: first unused slot, or -1 when every slot holds a neighbour.
  var
    i: int = 0
  result = -1
  while i < R.neighbours.len:
    if not R.neighbours[i].used:
      return i
    i = i + 1

proc admitError(R: RelayNode, id: uint64,
    a: transport_types.UdpAddress): string {.role: parser.} =
  ## R/id/a: why this neighbour cannot join, or "".
  if id == 0'u64 or id == R.selfId:
    return "relay id is reserved or this node's own"
  if findRelayNeighbour(R, id) >= 0:
    return "relay id is already connected"
  if relaySlotOf(R, a) >= 0:
    return "relay address is already connected"
  if freeRelaySlot(R) < 0:
    return "relay is full"

proc admitRelayNeighbour*(R: var RelayNode, S: AmeSession, id: uint64,
    identity: string, address: transport_types.UdpAddress,
    carrier: AmeCarrier, router: bool = false): tuple[ok: bool, slot: int,
    err: string] {.role: orchestrator, tag: "appApi".} =
  ## R: node the neighbour joins.
  ## S: the link session; its handshake already completed.
  ## id: the neighbour's route id. identity: what its handshake proved.
  ## address: IP + port it talks from (and is answered at).
  ## carrier: the transport its AME frames use. router: true for a relay.
  ## A neighbour enters here and nowhere else, so nothing that did not
  ## finish a handshake ever holds a slot.
  var
    err: string = admitError(R, id, address)
    slot: int = freeRelaySlot(R)
    src: tuple[ok: bool, src: SourceAddr, err: string] = sourceOfAddress(address)
  result.slot = -1
  if err.len > 0:
    result.err = err
    return
  if not src.ok:
    result.err = "relay address must be an IP address: " & src.err
    return
  R.neighbours[slot] = RelayNeighbour(used: true, id: id, identity: identity,
    address: address, source: src.src, carrier: carrier, router: router,
    session: S)
  setAmeInbox(R.neighbours[slot].session, ameNoInbox)
  R.bySource[address] = slot
  result.ok = true
  result.slot = slot

proc releaseRelayNeighbour*(R: var RelayNode, slot: int) {.role: actor,
    tag: "appApi".} =
  ## R/slot: the neighbour leaves; its session and keys are erased.
  if slot < 0 or slot >= R.neighbours.len or not R.neighbours[slot].used:
    return
  R.bySource.del(R.neighbours[slot].address)
  R.neighbours[slot] = default(RelayNeighbour)

proc liveSlot(R: RelayNode, slot: int): bool {.role: parser.} =
  ## R/slot: true when that slot holds a neighbour.
  result = slot >= 0 and slot < R.neighbours.len and R.neighbours[slot].used

proc droppedFromEmptySlot*(R: var RelayNode, slot: int,
    step: var RelayStep): bool {.role: actor.} =
  ## R/slot: true (and `step` filled) when no neighbour sits in that slot,
  ## e.g. a datagram from an address that never finished a handshake.
  if liveSlot(R, slot):
    return false
  R.dropped = R.dropped + 1'u32
  step = RelayStep(event: reDropped, slot: slot,
    err: "relay slot is empty")
  result = true

## ----------------------- permission and lookup ----------------------

proc visibleTo(T: RelayTarget, identity: string): bool {.role: parser.} =
  ## T/identity: true when that identity may see this directory line.
  for v in T.visibleTo:
    if v == relayEveryone or v == identity:
      return true

proc lineVisible(R: RelayNode, id: uint64, identity: string): bool {.
    role: parser.} =
  ## R/id/identity: true when a directory line for `id` exists and that
  ## identity may see it.
  var
    i: int = findRelayTarget(R, id)
  result = i >= 0 and visibleTo(R.targets[i], identity)

proc findLiveReturn(R: RelayNode, origin: uint64, nowMs: uint32): int {.
    role: parser.} =
  ## R/origin/nowMs: index of the unexpired return note for that origin.
  var
    i: int = 0
  result = -1
  while i < R.returns.len:
    if R.returns[i].origin == origin and
        nowMs - R.returns[i].lastMs <= relayReturnMs:
      return i
    i = i + 1

proc mayReach(R: RelayNode, slot: int, target: uint64,
    nowMs: uint32): bool {.role: parser.} =
  ## R/slot/target/nowMs: Def. 3, for the neighbour in `slot`.
  var
    p: RelayNeighbour = R.neighbours[slot]
    local: int = findRelayNeighbour(R, target)
    back: int = findLiveReturn(R, target, nowMs)
  if p.router or lineVisible(R, target, p.identity):
    return true
  if local >= 0 and lineVisible(R, p.id, R.neighbours[local].identity):
    return true
  result = back >= 0 and R.returns[back].reached == p.id

proc nextRelaySlot(R: RelayNode, target: uint64, nowMs: uint32): int {.
    role: parser.} =
  ## R/target/nowMs: Def. 4, steps 1 to 3. -1 means no route.
  var
    local: int = findRelayNeighbour(R, target)
    line: int = findRelayTarget(R, target)
    back: int = findLiveReturn(R, target, nowMs)
  result = -1
  if local >= 0:
    return local
  if line >= 0 and R.targets[line].via != 0'u64:
    return findRelayNeighbour(R, R.targets[line].via)
  if back >= 0:
    return findRelayNeighbour(R, R.returns[back].via)

proc oldestReturn(R: RelayNode): int {.role: parser.} =
  ## R: index of the return note refreshed longest ago.
  var
    i: int = 1
  result = 0
  while i < R.returns.len:
    if R.returns[i].lastMs < R.returns[result].lastMs:
      result = i
    i = i + 1

proc noteReturn(R: var RelayNode, origin, via, reached: uint64,
    nowMs: uint32) {.role: actor.} =
  ## R: node that remembers "origin wrote from behind relay `via` to
  ## `reached`".
  var
    i: int = findLiveReturn(R, origin, nowMs)
    note: RelayReturn = RelayReturn(origin: origin, via: via,
      reached: reached, lastMs: nowMs)
  if i >= 0:
    R.returns[i] = note
    return
  if R.returns.len < relayReturnCapacity:
    R.returns.add(note)
    return
  R.returns[oldestReturn(R)] = note

## ------------------------- sealing per kind -------------------------

proc queueSend(R: RelayNode, slot: int, frame: ByteSeq,
    step: var RelayStep) {.role: actor.} =
  ## R/slot: the neighbour the frame leaves to; its address goes with it.
  step.send.add(RelaySend(slot: slot, address: R.neighbours[slot].address,
    frame: frame))

proc sealForwardFor(R: var RelayNode, slot: int, target, origin: uint64,
    hopsLeft: uint8, payload: openArray[uint8]): ByteSeq {.
    role: encryptor, tag: "cryptoBoundary".} =
  ## R/slot: the next hop. target/origin/hopsLeft/payload: the forward.
  if R.kind == rkFastExtraFrame:
    return sealAmeRouteForward(R.neighbours[slot].session, target, payload,
      hopsLeft, origin)
  result = sealSlowForward(R.neighbours[slot].session,
    R.neighbours[slot].carrier, target, payload, hopsLeft, origin)

proc sealRefuseFor(R: var RelayNode, slot: int, target, origin: uint64,
    reason: AmeRouteRefusal): ByteSeq {.role: encryptor,
    tag: "cryptoBoundary".} =
  ## R/slot: the link back toward the origin. target/origin/reason: what.
  if R.kind == rkFastExtraFrame:
    return sealAmeRouteRefuse(R.neighbours[slot].session, target, origin,
      reason)
  result = sealSlowRefuse(R.neighbours[slot].session,
    R.neighbours[slot].carrier, target, origin, reason)

## ---------------------------- the directory -------------------------

proc directoryPage(R: RelayNode, identity: string,
    start: uint16): AmeRouteDirectory {.role: truthBuilder.} =
  ## R/identity/start: one page of the lines this identity may see.
  var
    seen: int = 0
  result = AmeRouteDirectory(kind: araDirectory, start: start)
  for T in R.targets:
    if not visibleTo(T, identity):
      continue
    if seen >= int(start) and result.entries.len < ameRoutePageEntries:
      result.entries.add(AmeRouteEntry(id: T.id, name: T.name))
    seen = seen + 1
  result.total = uint16(min(seen, int(high(uint16))))
  if int(start) > seen:
    result.start = result.total

proc feedRelayAsk*(R: var RelayNode, slot: int,
    frame: openArray[uint8]): RelayStep {.role: orchestrator.} =
  ## R/slot: the node and the neighbour asking.
  ## frame: one AME frame of kind 0x14 (an ask), FOMKE-sealed on that link.
  ## Answers with one page of the lines that neighbour's identity may see.
  ## Both feed procs call this on their own; a caller never has to.
  var
    D: AmeRouteDirectory = default(AmeRouteDirectory)
    page: ByteSeq = @[]
  result.slot = slot
  if droppedFromEmptySlot(R, slot, result):
    return
  D = openAmeRouteDirectory(R.neighbours[slot].session,
    R.neighbours[slot].carrier, frame)
  if not D.ok or D.kind != araAsk:
    R.dropped = R.dropped + 1'u32
    result.event = reDropped
    result.err = if D.ok: "relay directory frame is not a question" else: D.err
    return
  try:
    page = sealAmeRouteDirectory(R.neighbours[slot].session,
      R.neighbours[slot].carrier,
      directoryPage(R, R.neighbours[slot].identity, D.start))
    queueSend(R, slot, page, result)
    result.event = reAnswered
  except CatchableError as exc:
    R.dropped = R.dropped + 1'u32
    result.event = reDropped
    result.err = exc.msg

proc setRelayRestriction*(R: var RelayNode, mode: RestrictionMode): string {.
    role: actor, tag: "appApi".} =
  ## R/mode: switch the mode on at runtime. "" when it is on, else why not:
  ## the mode was not compiled into this binary.
  result = checkRestrictionMode(mode)
  if result.len == 0:
    R.restriction = mode

proc setRestrictionAnswerMs*(R: var RelayNode, ms: uint32) {.role: actor,
    tag: "appApi".} =
  ## R/ms: the gap between two answers to one restricted neighbour. 0 means a
  ## restricted frame is never answered, only counted and dropped.
  R.restrictionAnswerMs = ms

proc restrictionAnswerDue(R: var RelayNode, slot: int, nowMs: uint32): bool {.
    role: actor.} =
  ## R/slot/nowMs: true when this neighbour may be answered now, and records
  ## that it was. The first restricted frame always gets an answer, unless the
  ## gap is 0.
  if R.restrictionAnswerMs == 0'u32:
    return false
  if R.neighbours[slot].answered and
      nowMs - R.neighbours[slot].answeredMs < R.restrictionAnswerMs:
    return false
  R.neighbours[slot].answered = true
  R.neighbours[slot].answeredMs = nowMs
  result = true

proc attachRestrictionBook*(R: var RelayNode, dir: string): string {.
    role: actor, tag: "storageIo|appApi".} =
  ## R/dir: keep the book in this folder. A book saved there before is read
  ## back now. "" when it is ready, else why not (a damaged book is refused,
  ## and the relay keeps its empty book).
  var
    got: tuple[ok: bool, found: bool, book: RestrictionBook, err: string] =
      loadRestrictionBook(dir)
  if not got.ok:
    return got.err
  if got.found:
    R.book = got.book
  R.bookDir = dir

proc feedRelayRestriction(R: var RelayNode, slot: int,
    frame: openArray[uint8]): RelayStep {.role: orchestrator.} =
  ## R/slot/frame: a neighbour's restriction update (kind 0x17) on its own link.
  ## It is applied to that neighbour's part of the book and acknowledged.
  ## Nothing reaches the application.
  var
    u: RestrictionUpdate = RestrictionUpdate()
    e: string = ""
    prev: RestrictionBook = RestrictionBook()
  result.slot = slot
  if droppedFromEmptySlot(R, slot, result):
    return
  u = openRestrictionFrame(R.neighbours[slot].session,
    R.neighbours[slot].carrier, frame)
  if not u.ok:
    R.dropped = R.dropped + 1'u32
    result.event = reDropped
    result.err = u.err
    return
  prev = R.book
  e = applyRestrictionUpdate(R.book, R.neighbours[slot].identity, u)
  if e.len > 0:
    R.dropped = R.dropped + 1'u32
    result.event = reDropped
    result.err = e
    return
  if R.bookDir.len > 0:
    var w: tuple[ok: bool, err: string] = saveRestrictionBook(R.bookDir, R.book)
    if not w.ok:
      R.book = prev
      R.dropped = R.dropped + 1'u32
      result.event = reDropped
      result.err = w.err
      return
  try:
    queueSend(R, slot, sealRestrictionAck(R.neighbours[slot].session,
      R.neighbours[slot].carrier), result)
    result.event = reAnswered
  except CatchableError as exc:
    R.dropped = R.dropped + 1'u32
    result.event = reDropped
    result.err = exc.msg

proc feedRelayControl*(R: var RelayNode, slot: int,
    frame: openArray[uint8]): RelayStep {.role: orchestrator.} =
  ## R/slot/frame: a control frame from a neighbour: a directory question
  ## (kind 0x14) or a restriction update (kind 0x17). Told apart by the clear
  ## AME header. Both feed procs call this on their own.
  if isRestrictionFrame(frame):
    return feedRelayRestriction(R, slot, frame)
  return feedRelayAsk(R, slot, frame)

## ---------------------------- forwarding ----------------------------

proc refuseTo(R: var RelayNode, slot: int, target, origin: uint64,
    reason: AmeRouteRefusal, step: var RelayStep) {.role: actor.} =
  ## R/slot: tell the neighbour in slot that a forward went nowhere.
  ## target/origin/reason: what was refused, for whom, and why.
  step.event = reRefused
  R.refused = R.refused + 1'u32
  try:
    queueSend(R, slot, sealRefuseFor(R, slot, target, origin, reason), step)
  except CatchableError as exc:
    step.event = reDropped
    step.err = exc.msg

proc inspectAllows(R: RelayNode, slot: int, step: var RelayStep): bool {.
    role: parser.} =
  ## R/slot/step: true when no inspector is set, or it lets this forward on.
  if R.inspect == nil:
    return true
  try:
    result = R.inspect(R.neighbours[slot].identity, step.frame)
  except CatchableError as exc:
    step.err = exc.msg
    result = false

proc passOn(R: var RelayNode, slot: int, origin: uint64, nowMs: uint32,
    step: var RelayStep) {.role: orchestrator.} =
  ## R/slot: the neighbour the forward came from.
  ## origin: who it is from, already decided. step.frame: the forward.
  var
    next: int = nextRelaySlot(R, step.frame.target, nowMs)
    sealed: ByteSeq = @[]
  if next < 0 or next == slot:
    refuseTo(R, slot, step.frame.target, origin, arrNoRoute, step)
    return
  if not restrictionAllows(R.book, R.restriction, R.neighbours[slot].identity,
      R.neighbours[next].identity, R.neighbours[slot].source):
    R.restricted = R.restricted + 1'u32
    if restrictionAnswerDue(R, slot, nowMs):
      refuseTo(R, slot, step.frame.target, origin, arrNoRoute, step)
      return
    step.event = reDropped
    step.err = "restricted: " & $R.restriction
    return
  try:
    sealed = sealForwardFor(R, next, step.frame.target, origin,
      step.frame.hopsLeft - 1'u8, step.frame.payload)
  except CatchableError:
    refuseTo(R, slot, step.frame.target, origin, arrUnreachable, step)
    return
  queueSend(R, next, sealed, step)
  if R.neighbours[slot].router:
    noteReturn(R, origin, R.neighbours[slot].id, step.frame.target, nowMs)
  step.event = reForwarded
  R.forwarded = R.forwarded + 1'u32

proc handleForward(R: var RelayNode, slot: int, nowMs: uint32,
    step: var RelayStep) {.role: orchestrator.} =
  ## R/slot/nowMs: Def. 3 then Def. 4 for the forward in `step.frame`.
  ## The origin is decided first and written back into `step.frame`, so a
  ## delivered frame says who it is from by the handshake, not by claim.
  if not R.neighbours[slot].router:
    step.frame.origin = R.neighbours[slot].id
  if step.frame.origin == 0'u64:
    step.event = reDropped
    step.err = "relay forward from a router names no origin"
    return
  if step.frame.target == R.selfId:
    step.event = reDelivered
    R.delivered = R.delivered + 1'u32
    return
  if step.frame.hopsLeft == 0'u8:
    refuseTo(R, slot, step.frame.target, step.frame.origin, arrHopsSpent,
      step)
    return
  if not mayReach(R, slot, step.frame.target, nowMs) or
      not inspectAllows(R, slot, step):
    refuseTo(R, slot, step.frame.target, step.frame.origin, arrNoRoute, step)
    return
  passOn(R, slot, step.frame.origin, nowMs, step)

proc handleRefusal(R: var RelayNode, slot: int, nowMs: uint32,
    step: var RelayStep) {.role: orchestrator.} =
  ## R/slot: a refusal from the relay after this one, carried back toward
  ## the origin -- or kept, when the origin is this node.
  var
    back: int = -1
  if not R.neighbours[slot].router:
    step.event = reDropped
    step.err = "relay refusal from a client"
    return
  step.event = reRefused
  if step.frame.origin == R.selfId:
    return
  back = nextRelaySlot(R, step.frame.origin, nowMs)
  if back < 0 or back == slot:
    step.event = reDropped
    step.err = "relay refusal has no way back"
    return
  try:
    queueSend(R, back, sealRefuseFor(R, back, step.frame.target,
      step.frame.origin, step.frame.refusal), step)
  except CatchableError as exc:
    step.event = reDropped
    step.err = exc.msg

proc feedOpenedRelayFrame*(R: var RelayNode, slot: int, F: AmeRouteFrame,
    nowMs: uint32): RelayStep {.role: orchestrator.} =
  ## R/slot: the node and the neighbour the frame came from.
  ## F: the frame as its kind's open proc returned it (ok or not).
  ## nowMs: caller's millisecond clock (return notes expire by it).
  ## Called by feedRelayFastExtraFrame / feedRelaySlowExtractEncrypt.
  result.slot = slot
  result.frame = F
  if not F.ok:
    result.event = reDropped
    result.err = F.err
  elif F.kind == arkForward:
    handleForward(R, slot, nowMs, result)
  else:
    handleRefusal(R, slot, nowMs, result)
  if result.event == reDropped:
    R.dropped = R.dropped + 1'u32
