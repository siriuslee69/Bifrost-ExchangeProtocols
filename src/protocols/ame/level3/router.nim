## -------------------------------------------------------------------------
## AME Router <- one link per neighbour, route frames passed between them
## -------------------------------------------------------------------------
##
## A router holds one AME session (a LINK) per neighbour. A client makes
## ONE handshake, with its router, and then:
##
##   asks it "whom may I reach?"     AME frame kind 0x14, FOMKE-sealed
##   sends through it                outer "ART" route frames
##
## Through the routers it runs an end-to-end AM1S or AM1P handshake with
## the target, and later the session that handshake opens. Those records
## are the route frames' PAYLOAD, which no router can open:
##
##   phone ==link A==> router 1 ==link B==> router 2 ==link C==> nas
##     |                  |                    |                  |
##     ART[A: to 0x20]    open with A,         open with B,       target is
##     + E2E hello        seal with B          seal with C        me: E2E
##                        (only the 16-byte address is touched)   hello
##
## No sockets in here. A frame comes in on a SLOT (one neighbour), and out
## come frames for other slots. The caller owns sockets, clocks and the
## link handshakes, exactly like `dac_relay.nim`.
##
## ╭─ ❧ Def. 1: the words 🌊
##
##   node      anything holding an AmeRouter: a router, or an endpoint
##             with one link. It has its own route id (`selfId`).
##   peer      one neighbour with a finished link session, in a slot. It
##             has an id (u64) and an identity (the name the caller proved
##             for it during the link handshake, e.g. a pin name).
##   router    a peer flagged as another router. Its origin ids are
##             believed; a client's never are.
##   target    a line in this node's directory: id, name, who may see it,
##             and -- for a target behind another router -- which router
##             peer leads there (`via`).
##   return    a short-lived note "origin X wrote from behind router peer R
##             to target T". It is how T's answer finds X.
##
## ╭─ ❧ Def. 2: who may send to whom 🐦‍🔥
##
##   sender           target                      allowed when
##   ---------------  --------------------------  ----------------------------
##   anyone           this node itself            always -- the end-to-end
##                                                handshake decides
##   a router peer    anything                    always -- the router before
##                                                it already checked
##   a client         a directory target          its identity is in the
##                                                target's `visibleTo` ("*"
##                                                = everyone)
##   a client         another local peer          that peer's target line is
##                                                visible to it, OR the
##                                                reverse: whoever may write
##                                                to you may be answered
##   a client         an origin from far away     a return note says that
##                                                origin wrote to THIS client
##
## A refusal never says which rule failed: "no such id" and "not for you"
## are the same `arrNoRoute`, so ids cannot be probed.
##
## ╭─ ❧ Def. 3: where a forward goes 🍣
##
##   0. target is `selfId`                   -> delivered here
##   1. a local peer with that id            -> forward to it
##   2. a target line with `via` = router R  -> forward to R
##   3. a live return note for that id       -> forward to the router it
##                                              came from
##   4. nothing, or back where it came from  -> refuse: arrNoRoute
##
## Each node takes one hop from `hopsLeft`. At zero the forward is refused
## with arrHopsSpent, so a loop between routers burns out.
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
##   router2 forward(0x20, from 0x30)   -> nas, and notes "0x30 via router 1"
##   nas     0x20 is me                 -> delivered
##   nas     forward(0x30)              -> router 2: return note matches
##   router2 forward(0x30, from 0x20)   -> router 1: from a router; peer 0x30
##   phone   0x30 is me                 -> delivered

import ../../types
import ../types
import ../level2/route_wire
import ../level2/route_directory
import ../level2/seal_open
import runePragmas

const
  ameRouterCapacity* = 512
    ## Most neighbours one node holds at once.
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
      ## Only for the directory question, which is an ordinary AME frame.
    router*: bool
    session*: AmeSession

  ## AmeRouteTarget: one directory line (Def. 1).
  ## via: 0 for a target that connects to THIS node itself, otherwise the
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

  ## AmeRouter: one node.
  AmeRouter* {.role: truthState, expectedCount: 1,
      lifeCycle: lcForever.} = object
    selfId*: uint64
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
      ## a directory question was answered
    areForwarded,
    areDelivered,
      ## the target was this node: the payload is in `step.frame`
    areRefused

  ## AmeRouteSend: one sealed frame and the slot it must leave on.
  AmeRouteSend* {.role: preparedData, expectedCount: [0, 512],
      lifeCycle: lcJob.} = object
    slot*: int
    frame*: ByteSeq

  ## AmeRouteStep: outcome of one feed.
  ## send: frames to transmit, each to `peers[slot]`, in order.
  ## frame: the opened route frame, its origin already decided -- read its
  ##   payload on areDelivered, its refusal on areRefused with no `send`.
  ## slot: the neighbour it arrived from.
  AmeRouteStep* {.role: truthState, expectedCount: [0, 512],
      lifeCycle: lcJob.} = object
    event*: AmeRouteEvent
    send*: seq[AmeRouteSend]
    frame*: AmeRouteFrame
    slot*: int
    err*: string

## ---------------------------- setting up ----------------------------

proc initAmeRouter*(selfId: uint64,
    capacity: int = ameRouterCapacity): AmeRouter {.role: configurator,
    tag: "appApi".} =
  ## selfId: this node's own route id; frames for it are delivered here.
  ## capacity: how many neighbours fit; a ceiling, not a target.
  if selfId == 0'u64:
    raise newException(ValueError, "AME route id 0 is reserved")
  if capacity <= 0:
    raise newException(ValueError, "AME router capacity must be positive")
  result.selfId = selfId
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
  ## R: node whose directory grows by one line.
  ## id/name: what clients address, and what they read in the directory.
  ## visibleTo: identities that may see and reach it; "*" = everyone.
  ## via: 0 when the target connects here; else the next router's id.
  if id == 0'u64:
    raise newException(ValueError, "AME route id 0 is reserved")
  requireRouteName(name)
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
  ## R: node the neighbour joins.
  ## S: the link session; its handshake already completed.
  ## id: the neighbour's route id. identity: what its handshake proved.
  ## carrier: the transport its AME frames use. router: true for a router.
  ## A neighbour enters here and nowhere else, so nothing that did not
  ## finish a handshake ever holds a slot.
  var
    slot: int = freeRouteSlot(R)
  result.slot = -1
  if id == 0'u64 or id == R.selfId:
    result.err = "AME route id is reserved or this node's own"
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

proc nextRouteSlot(R: AmeRouter, target: uint64, nowMs: uint32): int {.
    role: parser.} =
  ## R/target/nowMs: Def. 3, steps 1 to 3. -1 means no route.
  var
    local: int = findAmeRoutePeer(R, target)
    line: int = findAmeRouteTarget(R, target)
    back: int = findLiveReturn(R, target, nowMs)
  result = -1
  if local >= 0:
    return local
  if line >= 0 and R.targets[line].via != 0'u64:
    return findAmeRoutePeer(R, R.targets[line].via)
  if back >= 0:
    return findAmeRoutePeer(R, R.returns[back].via)

proc oldestReturn(R: AmeRouter): int {.role: parser.} =
  ## R: index of the return note refreshed longest ago.
  var
    i: int = 1
  result = 0
  while i < R.returns.len:
    if R.returns[i].lastMs < R.returns[result].lastMs:
      result = i
    i = i + 1

proc noteReturn(R: var AmeRouter, origin, via, reached: uint64,
    nowMs: uint32) {.role: actor.} =
  ## R: node that remembers "origin wrote from behind router `via` to
  ## `reached`".
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

## ---------------------------- the directory -------------------------

proc directoryPage(R: AmeRouter, identity: string,
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

proc feedAmeRouteAsk*(R: var AmeRouter, slot: int,
    frame: openArray[uint8]): AmeRouteStep {.role: orchestrator,
    tag: "appApi".} =
  ## R/slot: the node and the neighbour asking.
  ## frame: one AME frame of kind 0x14 (an ask), FOMKE-sealed on that link.
  ## Answers with one page of the lines that neighbour's identity may see.
  var
    D: AmeRouteDirectory = default(AmeRouteDirectory)
  result.slot = slot
  if slot < 0 or slot >= R.peers.len or not R.peers[slot].used:
    R.dropped = R.dropped + 1'u32
    return AmeRouteStep(event: areDropped, slot: slot,
      err: "AME route slot is empty")
  D = openAmeRouteDirectory(R.peers[slot].session, R.peers[slot].carrier,
    frame)
  if not D.ok or D.kind != araAsk:
    R.dropped = R.dropped + 1'u32
    result.event = areDropped
    result.err = if D.ok: "AME route directory is not a question" else: D.err
    return
  try:
    result.send.add(AmeRouteSend(slot: slot, frame: sealAmeRouteDirectory(
      R.peers[slot].session, R.peers[slot].carrier,
      directoryPage(R, R.peers[slot].identity, D.start))))
    result.event = areAnswered
  except CatchableError as exc:
    R.dropped = R.dropped + 1'u32
    result.event = areDropped
    result.err = exc.msg

## ---------------------------- forwarding ----------------------------

proc refuseTo(R: var AmeRouter, slot: int, target, origin: uint64,
    reason: AmeRouteRefusal, step: var AmeRouteStep) {.role: actor.} =
  ## R/slot: tell the neighbour in slot that a forward went nowhere.
  ## target/origin/reason: what was refused, for whom, and why.
  step.event = areRefused
  R.refused = R.refused + 1'u32
  try:
    step.send.add(AmeRouteSend(slot: slot, frame: sealAmeRouteRefuse(
      R.peers[slot].session, target, origin, reason)))
  except CatchableError as exc:
    step.event = areDropped
    step.err = exc.msg

proc passOn(R: var AmeRouter, slot: int, origin: uint64, nowMs: uint32,
    step: var AmeRouteStep) {.role: orchestrator.} =
  ## R/slot: the neighbour the forward came from.
  ## origin: who it is from, already decided. step.frame: the forward.
  var
    next: int = nextRouteSlot(R, step.frame.target, nowMs)
  if next < 0 or next == slot:
    refuseTo(R, slot, step.frame.target, origin, arrNoRoute, step)
    return
  try:
    step.send.add(AmeRouteSend(slot: next, frame: sealAmeRouteForward(
      R.peers[next].session, step.frame.target, step.frame.payload,
      step.frame.hopsLeft - 1'u8, origin)))
  except CatchableError:
    refuseTo(R, slot, step.frame.target, origin, arrUnreachable, step)
    return
  if R.peers[slot].router:
    noteReturn(R, origin, R.peers[slot].id, step.frame.target, nowMs)
  step.event = areForwarded
  R.forwarded = R.forwarded + 1'u32

proc handleForward(R: var AmeRouter, slot: int, nowMs: uint32,
    step: var AmeRouteStep) {.role: orchestrator.} =
  ## R/slot/nowMs: Def. 2 then Def. 3 for the forward in `step.frame`.
  ## The origin is decided first and written back into `step.frame`, so a
  ## delivered frame says who it is from by the handshake, not by claim.
  if not R.peers[slot].router:
    step.frame.origin = R.peers[slot].id
  if step.frame.origin == 0'u64:
    step.event = areDropped
    step.err = "AME route forward from a router names no origin"
    return
  if step.frame.target == R.selfId:
    step.event = areDelivered
    R.delivered = R.delivered + 1'u32
    return
  if step.frame.hopsLeft == 0'u8:
    refuseTo(R, slot, step.frame.target, step.frame.origin, arrHopsSpent,
      step)
    return
  if not mayReach(R, slot, step.frame.target, nowMs):
    refuseTo(R, slot, step.frame.target, step.frame.origin, arrNoRoute, step)
    return
  passOn(R, slot, step.frame.origin, nowMs, step)

proc handleRefusal(R: var AmeRouter, slot: int, nowMs: uint32,
    step: var AmeRouteStep) {.role: orchestrator.} =
  ## R/slot: a refusal from the router after this one, carried back toward
  ## the origin -- or kept, when the origin is this node.
  var
    back: int = -1
  if not R.peers[slot].router:
    step.event = areDropped
    step.err = "AME route refusal from a client"
    return
  step.event = areRefused
  if step.frame.origin == R.selfId:
    return
  back = nextRouteSlot(R, step.frame.origin, nowMs)
  if back < 0 or back == slot:
    step.event = areDropped
    step.err = "AME route refusal has no way back"
    return
  try:
    step.send.add(AmeRouteSend(slot: back, frame: sealAmeRouteRefuse(
      R.peers[back].session, step.frame.target, step.frame.origin,
      step.frame.refusal)))
  except CatchableError as exc:
    step.event = areDropped
    step.err = exc.msg

proc feedAmeRouteFrame*(R: var AmeRouter, slot: int,
    frame: openArray[uint8], nowMs: uint32): AmeRouteStep {.
    role: orchestrator, tag: "appApi".} =
  ## R: the node.
  ## slot: the neighbour the frame arrived from (from `admitAmeRoutePeer`).
  ## frame: one outer route frame ("ART", see `isAmeRouteFrame`).
  ## nowMs: caller's millisecond clock (return notes expire by it).
  ## Nothing here raises, so a neighbour cannot stop the node with junk.
  result.slot = slot
  if slot < 0 or slot >= R.peers.len or not R.peers[slot].used:
    R.dropped = R.dropped + 1'u32
    return AmeRouteStep(event: areDropped, slot: slot,
      err: "AME route slot is empty")
  result.frame = openAmeRouteFrame(R.peers[slot].session, frame)
  if not result.frame.ok:
    result.event = areDropped
    result.err = result.frame.err
  elif result.frame.kind == arkForward:
    handleForward(R, slot, nowMs, result)
  else:
    handleRefusal(R, slot, nowMs, result)
  if result.event == areDropped:
    R.dropped = R.dropped + 1'u32
