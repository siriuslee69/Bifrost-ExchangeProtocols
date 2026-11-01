## -------------------------------------------------------------------------
## relay_brake <- a crowded relay tells its neighbours to slow down
## -------------------------------------------------------------------------
##
## Only a relay can do this. A neighbour that is not a relay can only choose
## whether to listen (`relayForceRequest`, default true). The words and the
## numbers are in dac/level0/brake.nim.
##
##   relay                                     neighbour
##   -----                                     ---------
##   setRelayBrake(slot, 2) ---- dmkBrake [2] --------->  slows down
##   tickRelayBrakes()      ---- dmkBrake [2] (repeat) ->  order stays alive
##   resetRelayBrakes()     ---- dmkBrake [0] --------->  back to full speed
##
##   at the start, from a neighbour that will NOT follow:
##                          <--- dmkBrakeStance [0] ----  "do not bother"
##
## The relay keeps ONE byte per neighbour (`RelayNeighbour.brake`):
##
##   bit:   7 6   5      4 3 2   1 0
##          - -   deaf   - - -   level ordered
##                 |
##                 the neighbour said it will not follow
##
## What a relay does about a neighbour that will not follow is its own
## business. This module only stops sending it orders that would be ignored
## and lets the relay ask (`relayFollowsBrake`).
##
## relaySuperFastUDP opens no client frame, so it does not use this module. It
## tells its one server over a control link, and the server tells the clients
## (relay/super_fast_control.nim).

import ../ame/types
import ../ame/level2/seal_open
import ../ame/level2/wire
import ../dac/types
import ../dac/level0/brake
import ./relay_node
import runePragmas
import var_invariants

proc relayBrakeOf*(R: RelayNode, slot: int): uint8 {.role: parser.} =
  ## R/slot: the level last ordered for that neighbour (0 when none, or when
  ## the slot is empty). This is what the relay knows the neighbour is doing.
  if slot < 0 or slot >= R.neighbours.len or not R.neighbours[slot].used:
    return 0'u8
  result = R.neighbours[slot].brake and dacBrakeLevelMask

proc relayFollowsBrake*(R: RelayNode, slot: int): bool {.role: parser.} =
  ## R/slot: false when that neighbour said it will not follow orders.
  if slot < 0 or slot >= R.neighbours.len or not R.neighbours[slot].used:
    return false
  result = (R.neighbours[slot].brake and dacBrakeDeaf) == 0'u8

proc isDacControlFrame*(A: openArray[uint8]): bool {.role: parser.} =
  ## A: one datagram. True when its clear AME header says kind 0x0B (DAC
  ## control). Needs no key; the frame is still authenticated when opened.
  try:
    result = decodeAmeFrame(A).header.packetKind == ampkDacControl
  except CatchableError:
    result = false

proc sendBrake(R: var RelayNode, slot: int, level: uint8, nowMs: uint32,
    step: var RelayStep) {.role: actor, needs: level <= 3'u8.} =
  ## R/slot/level/nowMs/step: seal one order for the neighbour and queue it.
  ## Only a neighbour reached over datagrams has DAC control frames.
  if R.neighbours[slot].carrier != acrDac:
    step.err = "relay brake needs a datagram link to that neighbour"
    return
  try:
    step.send.add(RelaySend(slot: slot, address: R.neighbours[slot].address,
      frame: sealAmeDacControl(R.neighbours[slot].session, dmkBrake,
        encodeDacBrake(level))))
  except CatchableError as exc:
    step.err = exc.msg
    return
  R.neighbours[slot].brake = (R.neighbours[slot].brake and
    not dacBrakeLevelMask) or level
  R.neighbours[slot].brakeMs = nowMs

proc setRelayBrake*(R: var RelayNode, slot: int, level: uint8,
    nowMs: uint32): RelayStep {.role: actor, tag: "appApi",
    needs: level <= 3'u8.} =
  ## R/slot: the neighbour to slow down. level: 0 (go ham) .. 3 (full brakes).
  ## nowMs: caller's millisecond clock.
  ## Nothing is sent when the neighbour already has that level, or when it said
  ## it will not follow. Send `step.send` as it is.
  result.slot = slot
  if slot < 0 or slot >= R.neighbours.len or not R.neighbours[slot].used:
    result.event = reDropped
    result.err = "relay brake: no neighbour in that slot"
    return
  if (R.neighbours[slot].brake and dacBrakeDeaf) != 0'u8:
    return
  if relayBrakeOf(R, slot) == level:
    return
  sendBrake(R, slot, level, nowMs, result)

proc brakeOne(R: var RelayNode, i: int, level: uint8, nowMs: uint32,
    A: var seq[RelayStep]) {.role: actor, inline, needs: level <= 3'u8.} =
  ## R/i/level/nowMs: order one neighbour (if there is one). A: keeps the
  ## step when it has frames to send or something to report.
  var
    step: RelayStep = default(RelayStep)
  if not R.neighbours[i].used:
    return
  step = setRelayBrake(R, i, level, nowMs)
  if step.send.len > 0 or step.err.len > 0:
    A.add(step)

proc setRelayBrakeAll*(R: var RelayNode, level: uint8,
    nowMs: uint32): seq[RelayStep] {.role: orchestrator, tag: "appApi",
    needs: level <= 3'u8.} =
  ## R/level/nowMs: the same level for every neighbour. Only neighbours that
  ## have something to send come back.
  var
    i: int = 0
  while i < R.neighbours.len:
    brakeOne(R, i, level, nowMs, result)
    i = i + 1

proc resetRelayBrakes*(R: var RelayNode, nowMs: uint32): seq[RelayStep] {.
    role: orchestrator, tag: "appApi".} =
  ## R/nowMs: everyone back to 00. Orders go to those that were braked.
  result = setRelayBrakeAll(R, 0'u8, nowMs)

proc applyRelayLoad*(R: var RelayNode, used, capacity: int,
    nowMs: uint32): seq[RelayStep] {.role: orchestrator, tag: "appApi".} =
  ## R/used/capacity: how full the relay is (queue, table, link budget: the
  ## relay chooses). The level follows `dacBrakeForLoad`. Call it on a tick;
  ## frames leave only when a level CHANGES, so a steady load is silent.
  result = setRelayBrakeAll(R, dacBrakeForLoad(used, capacity), nowMs)

proc tickRelayBrakes*(R: var RelayNode, nowMs: uint32): seq[RelayStep] {.
    role: orchestrator, tag: "appApi".} =
  ## R/nowMs: repeat every non-zero order that is `dacBrakeRefreshMs` old, so
  ## it does not lapse at the neighbour (`dacBrakeHoldMs`).
  var
    i: int = 0
    step: RelayStep = default(RelayStep)
  while i < R.neighbours.len:
    step = RelayStep(slot: i)
    if R.neighbours[i].used and relayBrakeOf(R, i) != 0'u8 and
        nowMs > R.neighbours[i].brakeMs and
        nowMs - R.neighbours[i].brakeMs >= dacBrakeRefreshMs:
      sendBrake(R, i, relayBrakeOf(R, i), nowMs, step)
      result.add(step)
    i = i + 1

proc feedRelayBrake*(R: var RelayNode, slot: int,
    frame: openArray[uint8]): RelayStep {.role: orchestrator, tag: "appApi".} =
  ## R/slot/frame: a DAC control frame from a neighbour. A relay runs no DAC
  ## loop, so the one word it reads is dmkBrakeStance: "I follow your orders"
  ## or "I do not". The answer is kept in the neighbour's byte. Anything else
  ## is dropped and counted.
  var
    opened: AmeDacControlOpen = default(AmeDacControlOpen)
    follows: bool = true
  result.slot = slot
  if droppedFromEmptySlot(R, slot, result):
    return
  if R.neighbours[slot].carrier != acrDac:
    R.dropped = R.dropped + 1'u32
    result.event = reDropped
    result.err = "relay brake: DAC control needs a datagram link"
    return
  try:
    opened = openAmeDacControl(R.neighbours[slot].session, frame)
    if opened.ok and opened.kind == dmkBrakeStance:
      follows = decodeDacBrakeStance(opened.body)
  except CatchableError as exc:
    opened.ok = false
    opened.err = exc.msg
  if not opened.ok or opened.kind != dmkBrakeStance:
    R.dropped = R.dropped + 1'u32
    result.event = reDropped
    result.err = if opened.ok: "relay reads only the brake stance" else: opened.err
    return
  if follows:
    R.neighbours[slot].brake = R.neighbours[slot].brake and not dacBrakeDeaf
  else:
    R.neighbours[slot].brake = (R.neighbours[slot].brake or dacBrakeDeaf) and
      not dacBrakeLevelMask
  result.event = reAnswered
