## -------------------------------------------------------------------------
## AME Router <- one session per neighbour, and route frames between them
## -------------------------------------------------------------------------
##
## The router holds one AME session per neighbour. A client does ONE
## handshake -- with the router -- and can then reach every target the
## router lets it see:
##
##   phone ==session A==> router 1 ==session B==> router 2 ==session C==> nas
##     |                     |                       |                    |
##     forward(0x20, "hi")   opens with A, checks,   opens with B,        deliver
##                           re-seals with B         re-seals with C      from 0x30
##
## Each link is sealed by its own session. Every router can read the
## payload; nothing is sealed end to end (see level2/route_frames.nim).
##
## No sockets in here. A frame comes in on a SLOT (one neighbour), and out
## come frames for other slots. The caller owns sockets, clocks and the
## handshakes, exactly like `dac_relay.nim`.
##
## ╭─ ❧ Def. 1: the words 🌊
##
##   peer      one neighbour with a finished session, sitting in a slot.
##             It has an id (u64) and an identity (the name the caller
##             proved for it during the handshake, e.g. a pin name).
##   router    a peer flagged as another router. Its origin ids are
##             believed; a client's never are.
##   target    a line in this router's directory: id, name, who may see
##             it, and -- for a target behind another router -- which
##             router peer leads there (`via`).
##   return    a short-lived note "origin X wrote from behind router
##             peer R to target T". It is how T's answer finds X.
##
## ╭─ ❧ Def. 2: who may send to whom 🐦‍🔥
##
##   sender           target                      allowed when
##   ---------------  --------------------------  ----------------------------
##   a router peer    anything                    always -- the router before
##                                                it already checked
##   a client         a directory target          its identity is in the
##                                                target's `visibleTo` ("*"
##                                                = everyone)
##   a client         another local peer          that peer's target line is
##                                                visible to it, OR the
##                                                reverse: so whoever may
##                                                write to you may be answered
##   a client         an origin from far away     a return note says that
##                                                origin wrote to THIS client
##
## A refusal never says which rule failed: "no such id" and "not for you"
## are the same `arrNoRoute`, so ids cannot be probed.
##
## ╭─ ❧ Def. 3: where a forward goes 🍣
##
##   1. a local peer with that id            -> deliver to it
##   2. a target line with `via` = router R  -> forward to R
##   3. a live return note for that id       -> forward to the router it
##                                              came from
##   4. nothing                              -> refuse: arrNoRoute
##
## Each router takes one hop from `hopsLeft`. At zero the forward is
## refused with arrHopsSpent, so a loop between routers burns out.
##
## Example 1. Two routers, a phone behind the first, a NAS behind the
## second:
##
##   router 1  targets: 0x20 "nas"  visibleTo ["phone"]  via 0x11
##             peers:   phone (0x30), router 2 (0x11, router)
##   router 2  targets: 0x20 "nas"  visibleTo ["router1"]
##             peers:   router 1 (0x10, router), nas (0x20)
##
##   phone   forward(0x20)              -> router 1: rule "directory"; via
##   router1 forward(0x20, from 0x30)   -> router 2: from a router; peer 0x20
##   router2 deliver(0x20, from 0x30)   -> nas, and notes "0x30 via router 1"
##   nas     forward(0x30)              -> router 2: return note matches
##   router2 forward(0x30, from 0x20)   -> router 1: from a router; peer 0x30
##   router1 deliver(0x30, from 0x20)   -> phone

import ../../types
import ../types
import ../level2/route_frames
import ../level2/seal_open
import runePragmas

const
  ameRouterCapacity* = 512
    ## Most neighbours one router holds at once.
  ameRouteReturnCapacity* = 256
    ## Most return notes kept. When full, the oldest is replaced.
  ameRouteReturnMs* = 120_000'u32
    ## How long a return note lives after the last forward that refreshed it.
  ameRouteEveryone* = "*"
    ## Written in `visibleTo` to show a target to every identity.

type
  ## AmeRoutePeer: one neighbour (Def. 1).
  AmeRoutePeer* {.role: truthState, expectedCount: [0, 512],
      lifeCycle: lcSession.} = object
    used*: bool
    id*: uint64
    identity*: string
    carrier*: AmeCarrier
    router*: bool
    session*: AmeSession

  ## AmeRouteTarget: one directory line (Def. 1).
  ## via: 0 for a target that connects to THIS router itself, otherwise the
  ##   id of the router peer that leads to it.
  AmeRouteTarget* {.role: configurator.} = object
    id*: uint64
    name*: string
    visibleTo*: seq[string]
    via*: uint64

  ## AmeRouteReturn: one return note (Def. 1).
  AmeRouteReturn {.role: memory, expectedCount: [0, 256],
      lifeCycle: 120000.} = object
    origin: uint64
    via: uint64
      ## the router peer's id, not its slot: a slot is reused once freed
    reached: uint64
    lastMs: uint32

  ## AmeRouter: the whole router.
  AmeRouter* {.role: truthState, expectedCount: 1,
      lifeCycle: lcForever.} = object
    peers*: seq[AmeRoutePeer]
    targets*: seq[AmeRouteTarget]
    returns: seq[AmeRouteReturn]
    forwarded*: uint32
    delivered*: uint32
    refused*: uint32
    dropped*: uint32

  ## AmeRouteEvent: what one arriving frame led to.
  AmeRouteEvent* = enum
    areNone,
    areDropped,
    areAnswered,
    areForwarded,
    areDelivered,
    areRefused

  ## AmeRouteSend: one sealed frame and the slot it must leave on.
  AmeRouteSend* {.role: preparedData, expectedCount: [0, 512],
      lifeCycle: lcJob.} = object
    slot*: int
    frame*: ByteSeq

  ## AmeRouteStep: outcome of one `feedAmeRouteFrame`.
  ## send: frames to transmit, each to `peers[slot]`, in order.
  AmeRouteStep* {.role: truthState, expectedCount: [0, 512],
      lifeCycle: lcJob.} = object
    event*: AmeRouteEvent
    send*: seq[AmeRouteSend]
    err*: string

## ---------------------------- setting up ----------------------------

proc initAmeRouter*(capacity: int = ameRouterCapacity): AmeRouter {.
    role: configurator, tag: "appApi".} =
  ## capacity: how many neighbours fit; a ceiling, not a target.
  if capacity <= 0:
    raise newException(ValueError, "AME router capacity must be positive")
  result.peers = newSeq[AmeRoutePeer](capacity)

proc findAmeRouteTarget*(R: AmeRouter, id: uint64): int {.role: parser.} =
  ## R/id: index of the directory line with that id, or -1.
  var
    i: int = 0
  result = -1
  while i < R.targets.len:
    if R.targets[i].id == id:
      return i
    i = i + 1

proc findAmeRoutePeer*(R: AmeRouter, id: uint64): int {.role: parser.} =
  ## R/id: slot of the live neighbour with that id, or -1.
  var
    i: int = 0
  result = -1
  while i < R.peers.len:
    if R.peers[i].used and R.peers[i].id == id:
      return i
    i = i + 1

proc addAmeRouteTarget*(R: var AmeRouter, id: uint64, name: string,
    visibleTo: openArray[string], via: uint64 = 0'u64) {.role: configurator,
    tag: "appApi".} =
  ## R: router whose directory grows by one line.
  ## id/name: what clients address, and what they read in the directory.
  ## visibleTo: identities that may see and reach it; "*" = everyone.
  ## via: 0 when the target connects here; else the next router's id.
  if id == 0'u64:
    raise newException(ValueError, "AME route id 0 is reserved")
  if name.len > ameRouteNameMax:
    raise newException(ValueError, "AME route name is longer than 32 bytes")
  if findAmeRouteTarget(R, id) >= 0:
    raise newException(ValueError, "AME route target id is already listed")
  R.targets.add(AmeRouteTarget(id: id, name: name, visibleTo: @visibleTo,
    via: via))

proc freeRouteSlot(R: AmeRouter): int {.role: parser.} =
  ## R: first unused slot, or -1 when every slot holds a neighbour.
  var
    i: int = 0
  result = -1
  while i < R.peers.len:
    if not R.peers[i].used:
      return i
    i = i + 1

proc admitAmeRoutePeer*(R: var AmeRouter, S: AmeSession, id: uint64,
    identity: string, carrier: AmeCarrier, router: bool = false): tuple[
    ok: bool, slot: int, err: string] {.role: orchestrator, tag: "appApi".} =
  ## R: router the neighbour joins.
  ## S: a session whose handshake already completed.
  ## id: the neighbour's route id. identity: what its handshake proved.
  ## carrier: the transport its frames use. router: true for another router.
  ## A neighbour enters here and nowhere else, so nothing that did not
  ## finish a handshake ever holds a slot.
  var
    slot: int = freeRouteSlot(R)
  result.slot = -1
  if id == 0'u64:
    result.err = "AME route id 0 is reserved"
    return
  if findAmeRoutePeer(R, id) >= 0:
    result.err = "AME route id is already connected"
    return
  if slot < 0:
    result.err = "AME router is full"
    return
  R.peers[slot] = AmeRoutePeer(used: true, id: id, identity: identity,
    carrier: carrier, router: router, session: S)
  result.ok = true
  result.slot = slot

proc releaseAmeRoutePeer*(R: var AmeRouter, slot: int) {.role: actor,
    tag: "appApi".} =
  ## R/slot: the neighbour leaves; its session and keys are erased.
  if slot < 0 or slot >= R.peers.len:
    return
  R.peers[slot] = default(AmeRoutePeer)

## ----------------------- permission and lookup ----------------------

proc visibleTo(T: AmeRouteTarget, identity: string): bool {.role: parser.} =
  ## T/identity: true when that identity may see this directory line.
  for v in T.visibleTo:
    if v == ameRouteEveryone or v == identity:
      return true

proc lineVisible(R: AmeRouter, id: uint64, identity: string): bool {.
    role: parser.} =
  ## R/id/identity: true when a directory line for `id` exists and that
  ## identity may see it.
  var
    i: int = findAmeRouteTarget(R, id)
  result = i >= 0 and visibleTo(R.targets[i], identity)

proc findLiveReturn(R: AmeRouter, origin: uint64, nowMs: uint32): int {.
    role: parser.} =
  ## R/origin/nowMs: index of the unexpired return note for that origin.
  var
    i: int = 0
  result = -1
  while i < R.returns.len:
    if R.returns[i].origin == origin and
        nowMs - R.returns[i].lastMs <= ameRouteReturnMs:
      return i
    i = i + 1

proc mayReach(R: AmeRouter, slot: int, target: uint64,
    nowMs: uint32): bool {.role: parser.} =
  ## R/slot/target/nowMs: Def. 2, for the neighbour in `slot`.
  var
    p: AmeRoutePeer = R.peers[slot]
    local: int = findAmeRoutePeer(R, target)
    back: int = findLiveReturn(R, target, nowMs)
  if p.router or lineVisible(R, target, p.identity):
    return true
  if local >= 0 and lineVisible(R, p.id, R.peers[local].identity):
    return true
  result = back >= 0 and R.returns[back].reached == p.id

proc nextRouteSlot(R: AmeRouter, target: uint64, nowMs: uint32): tuple[
    slot: int, deliver: bool] {.role: parser.} =
  ## R/target/nowMs: Def. 3. slot -1 means no route.
  var
    local: int = findAmeRoutePeer(R, target)
    line: int = findAmeRouteTarget(R, target)
    back: int = findLiveReturn(R, target, nowMs)
  result = (slot: -1, deliver: false)
  if local >= 0 and not R.peers[local].router:
    return (slot: local, deliver: true)
  if line >= 0 and R.targets[line].via != 0'u64:
    return (slot: findAmeRoutePeer(R, R.targets[line].via), deliver: false)
  if back >= 0:
    return (slot: findAmeRoutePeer(R, R.returns[back].via), deliver: false)

proc oldestReturn(R: AmeRouter): int {.role: parser.} =
  ## R: index of the return note refreshed longest ago.
  var
    i: int = 1
  result = 0
  while i < R.returns.len:
    if R.returns[i].lastMs < R.returns[result].lastMs:
      result = i
    i = i + 1

proc noteReturn(R: var AmeRouter, origin, via: uint64,
    reached: uint64, nowMs: uint32) {.role: actor.} =
  ## R: router that remembers "origin wrote from behind router via to reached".
  var
    i: int = findLiveReturn(R, origin, nowMs)
    note: AmeRouteReturn = AmeRouteReturn(origin: origin, via: via,
      reached: reached, lastMs: nowMs)
  if i >= 0:
    R.returns[i] = note
    return
  if R.returns.len < ameRouteReturnCapacity:
    R.returns.add(note)
    return
  R.returns[oldestReturn(R)] = note

## ---------------------------- answering -----------------------------

proc directoryPage(R: AmeRouter, identity: string,
    start: uint16): AmeRouteMessage {.role: truthBuilder.} =
  ## R/identity/start: one page of the lines this identity may see.
  var
    seen: int = 0
  result = AmeRouteMessage(kind: arkDirectory, start: start)
  for T in R.targets:
    if not visibleTo(T, identity):
      continue
    if seen >= int(start) and result.entries.len < ameRoutePageEntries:
      result.entries.add(AmeRouteEntry(id: T.id, name: T.name))
    seen = seen + 1
  result.total = uint16(min(seen, int(high(uint16))))
  if int(start) > seen:
    result.start = result.total

proc sealTo(R: var AmeRouter, slot: int, m: AmeRouteMessage,
    step: var AmeRouteStep): bool {.role: dataWriter.} =
  ## R/slot/m: seal m for the neighbour in slot and queue it on `step`.
  ## Returns false, with `step.err` set, when that session cannot send now
  ## (an exchange is in flight, the counter ran out, ...).
  try:
    step.send.add(AmeRouteSend(slot: slot, frame: sealAmeRouteFrame(
      R.peers[slot].session, R.peers[slot].carrier, m)))
    result = true
  except CatchableError as exc:
    step.err = exc.msg

proc refuseTo(R: var AmeRouter, slot: int, target, origin: uint64,
    reason: AmeRouteRefusal, step: var AmeRouteStep) {.role: actor.} =
  ## R/slot: tell the neighbour in slot that its forward went nowhere.
  ## target/origin/reason: what was refused, for whom, and why.
  step.event = areRefused
  R.refused = R.refused + 1'u32
  if not sealTo(R, slot, AmeRouteMessage(kind: arkRefuse, target: target,
      origin: origin, refusal: reason), step):
    step.event = areDropped

proc passOn(R: var AmeRouter, slot: int, m: AmeRouteMessage,
    origin: uint64, nowMs: uint32, step: var AmeRouteStep) {.
    role: orchestrator.} =
  ## R/slot: the neighbour the forward came from.
  ## m: the opened forward. origin: who it is from, already decided.
  var
    next: tuple[slot: int, deliver: bool] = nextRouteSlot(R, m.target, nowMs)
    onward: AmeRouteMessage = AmeRouteMessage(kind: arkForward,
      target: m.target, origin: origin, hopsLeft: m.hopsLeft - 1'u8,
      payload: m.payload)
  if next.slot < 0 or next.slot == slot:
    refuseTo(R, slot, m.target, origin, arrNoRoute, step)
    return
  if next.deliver:
    onward.kind = arkDeliver
  if not sealTo(R, next.slot, onward, step):
    step.err = ""
    refuseTo(R, slot, m.target, origin, arrUnreachable, step)
    return
  if R.peers[slot].router:
    noteReturn(R, origin, R.peers[slot].id, m.target, nowMs)
  step.event = if next.deliver: areDelivered else: areForwarded
  R.delivered = R.delivered + uint32(ord(next.deliver))
  R.forwarded = R.forwarded + uint32(ord(not next.deliver))

proc handleForward(R: var AmeRouter, slot: int, m: AmeRouteMessage,
    nowMs: uint32, step: var AmeRouteStep) {.role: orchestrator.} =
  ## R/slot/m/nowMs: Def. 2 then Def. 3 for one forward.
  var
    origin: uint64 = R.peers[slot].id
  if R.peers[slot].router:
    origin = m.origin
  if origin == 0'u64:
    step.event = areDropped
    step.err = "AME route forward from a router names no origin"
    return
  if m.hopsLeft == 0'u8:
    refuseTo(R, slot, m.target, origin, arrHopsSpent, step)
    return
  if not mayReach(R, slot, m.target, nowMs):
    refuseTo(R, slot, m.target, origin, arrNoRoute, step)
    return
  passOn(R, slot, m, origin, nowMs, step)

proc handleRefusal(R: var AmeRouter, slot: int, m: AmeRouteMessage,
    nowMs: uint32, step: var AmeRouteStep) {.role: orchestrator.} =
  ## R/slot/m: a refusal from the router after this one, carried back
  ## toward the origin. From a client it means nothing and is dropped.
  var
    back: tuple[slot: int, deliver: bool] = (slot: -1, deliver: false)
  if not R.peers[slot].router:
    step.event = areDropped
    step.err = "AME route refusal from a client"
    return
  back = nextRouteSlot(R, m.origin, nowMs)
  if back.slot < 0 or back.slot == slot:
    step.event = areDropped
    step.err = "AME route refusal has no way back"
    return
  step.event = areRefused
  if not sealTo(R, back.slot, m, step):
    step.event = areDropped

## ---------------------------- the entry -----------------------------

proc feedAmeRouteFrame*(R: var AmeRouter, slot: int,
    frame: openArray[uint8], nowMs: uint32): AmeRouteStep {.
    role: orchestrator, tag: "appApi".} =
  ## R: the router.
  ## slot: the neighbour the frame arrived from (from `admitAmeRoutePeer`).
  ## frame: one whole AME frame of kind 0x14.
  ## nowMs: caller's millisecond clock (return notes expire by it).
  ## Nothing here raises, so a neighbour cannot stop the router with junk.
  var
    m: AmeRouteMessage = default(AmeRouteMessage)
  if slot < 0 or slot >= R.peers.len or not R.peers[slot].used:
    R.dropped = R.dropped + 1'u32
    return AmeRouteStep(event: areDropped, err: "AME route slot is empty")
  m = openAmeRouteFrame(R.peers[slot].session, R.peers[slot].carrier, frame)
  if not m.ok:
    R.dropped = R.dropped + 1'u32
    return AmeRouteStep(event: areDropped, err: m.err)
  case m.kind
  of arkAsk:
    result.event = areAnswered
    if not sealTo(R, slot, directoryPage(R, R.peers[slot].identity, m.start),
        result):
      result.event = areDropped
  of arkForward:
    handleForward(R, slot, m, nowMs, result)
  of arkRefuse:
    handleRefusal(R, slot, m, nowMs, result)
  of arkDirectory, arkDeliver, arkUnknown:
    result.event = areDropped
    result.err = "AME route message is not meant for a router"
  if result.event == areDropped:
    R.dropped = R.dropped + 1'u32
