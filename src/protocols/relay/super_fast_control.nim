## -------------------------------------------------------------------------
## super_fast_control <- relaySuperFastUDP's one keyed link, to its server
## -------------------------------------------------------------------------
##
## relaySuperFastUDP (super_fast_udp.nim) moves client bytes and holds no key.
## It still has exactly ONE destination, the server (the "NAS"). This module
## gives it one control link to that server, and nothing else:
##
##   client ===== end-to-end session (the forwarder cannot open it) ===== server
##      \                                                                  /
##       \__ datagram __ forwarder (blind, no key for client traffic) ____/
##                          |
##                          +== control link (ONE session, a few frames) ==+
##
##   1. the forwarder measures how busy it is (datagrams per second)
##   2. it sends the server  dmkBrake [level]        over the control link
##   3. the server slows its own sends and sends every client dmkBrake [level]
##      over the clients' end-to-end links (`setAmeDacBrakeSource`)
##
## The control link rides on the tag-0 socket the forwarder already uses to
## poke the server. Datagrams that come back on tag 0 belong to this module.
##
## ┊ What the key costs ┊
##
## The forwarder now holds ONE session key, for control frames only. A stolen
## VPS gives up that key and no client traffic: client frames are sealed
## end-to-end with the server. The key could make the server slow its clients;
## the forwarder could already drop every datagram, so nothing new is lost.
##
## ┊ The session ┊
##
## The caller hands in a session whose handshake is done, the same way a relay
## node is given its neighbours' sessions. This module does no handshake.
##
## ┊ When the level is sent ┊
##
##   level = the larger of  - the operator's level (`setSuperFastBrake`)
##                          - the level the measured load asks for
##   sent  = when it changes, and again every `dacBrakeRefreshMs` while it is
##           above 0 (an order is a lease, see dac/level0/brake.nim)
##
## A server that said it will not follow is not sent orders; the hard limit
## in super_fast_udp.nim still holds for it.

import ../types
import ../ame/types
import ../ame/level2/seal_open
import ../dac/types
import ../dac/level0/brake
import ./super_fast_udp
import runePragmas
import var_invariants

const
  controlKeepaliveMs* = 30_000'u64
    ## At level 0 the link is still touched this often, so the server does not
    ## drop it as idle. Above 0 the refresh (`dacBrakeRefreshMs`) does that.
  controlSilentMs* = 90_000'u64
    ## No word back from the server for this long and the link counts as dead
    ## (`controlSilent`): the caller makes a new one.

type
  ## SuperFastControl: the control link and what it last said.
  ## capacityPerSecond: datagrams per second that count as 100 % busy. 0 turns
  ##   load measuring off (only the operator's level is sent).
  ## level/told/sentMs: the last level sent, whether any was, and when.
  ## totalAt/totalMs: the forwarder's counter at the last measurement.
  ## deaf: the server said it will not follow orders.
  ## heardMs/startedMs: when the server last answered, and when this link was
  ##   first used. `controlSilent` is built on them.
  SuperFastControl* {.role: truthState, expectedCount: 1,
      lifeCycle: lcForever.} = object
    session*: AmeSession
    capacityPerSecond*: int
    level*: uint8
    told*: bool
    sentMs*: uint64
    totalAt*: uint64
    totalMs*: uint64
    loadLevel*: uint8
    deaf*: bool
    heardMs*: uint64
    startedMs*: uint64

proc initSuperFastControl*(session: AmeSession,
    capacityPerSecond: int = 5000): SuperFastControl {.role: configurator,
    tag: "appApi|relay|udp", needs: capacityPerSecond >= 0.} =
  ## session: the finished link session with the server.
  ## capacityPerSecond: what counts as full load (0 = never measure).
  result.session = session
  result.capacityPerSecond = capacityPerSecond

proc measureLoad(C: var SuperFastControl, F: RelaySuperFastUdp,
    nowMs: uint64) {.role: math.} =
  ## C/F/nowMs: once a second, turn the forwarder's counter into a level.
  var
    rate: uint64 = 0'u64
  if C.capacityPerSecond == 0:
    return
  if nowMs < C.totalMs or nowMs - C.totalMs < 1000'u64:
    if C.totalMs == 0'u64:
      C.totalMs = nowMs
      C.totalAt = F.forwardedTotal
    return
  rate = (F.forwardedTotal - C.totalAt) * 1000'u64 div (nowMs - C.totalMs)
  C.loadLevel = dacBrakeForLoad(int(min(rate, uint64(high(int32)))),
    C.capacityPerSecond)
  C.totalMs = nowMs
  C.totalAt = F.forwardedTotal

proc tickSuperFastControl*(C: var SuperFastControl, F: RelaySuperFastUdp,
    nowMs: uint64): seq[UdpForwardOut] {.role: orchestrator,
    tag: "appApi|relay|udp".} =
  ## C/F/nowMs: the periodic call, beside `tickRelaySuperFastUdp`. Returns the
  ## sealed datagrams to send (tag 0, to the server), usually none.
  var
    want: uint8 = 0'u8
    changed: bool = false
    due: bool = false
  measureLoad(C, F, nowMs)
  want = max(F.brake, C.loadLevel)
  changed = want != C.level
  if C.startedMs == 0'u64:
    C.startedMs = nowMs
  due = C.told and nowMs > C.sentMs and nowMs - C.sentMs >=
    (if want > 0'u8: uint64(dacBrakeRefreshMs) else: controlKeepaliveMs)
  if C.deaf or not (changed or due):
    return
  try:
    result.add(UdpForwardOut(tag: 0'u32, peer: F.nas,
      payload: sealAmeDacControl(C.session, dmkBrake, encodeDacBrake(want))))
  except CatchableError:
    return
  C.level = want
  C.told = true
  C.sentMs = nowMs

proc fromServerControl*(C: var SuperFastControl, payload: openArray[uint8],
    nowMs: uint64): string {.role: actor, tag: "appApi|relay|udp"} =
  ## C/payload/nowMs: a datagram that came back from the server. "" when it was
  ## understood, else why not. Any frame that authenticates counts as a sign of
  ## life (`controlSilent`). The one word read is dmkBrakeStance: whether the
  ## server follows orders. Anything else is refused.
  var
    opened: AmeDacControlOpen = default(AmeDacControlOpen)
  try:
    opened = openAmeDacControl(C.session, payload)
    if opened.ok and opened.kind == dmkBrakeStance:
      C.deaf = not decodeDacBrakeStance(opened.body)
      C.heardMs = nowMs
      return ""
  except CatchableError as exc:
    return exc.msg
  result = if opened.ok: "the forwarder reads only the brake stance"
    else: opened.err

proc controlSilent*(C: SuperFastControl, nowMs: uint64): bool {.role: parser,
    tag: "appApi|relay|udp"} =
  ## C/nowMs: true when the link has been used for `controlSilentMs` and the
  ## server has not answered once in that time (it answers every order with
  ## its stance). The server has then forgotten this link, or is gone: make a
  ## new session and a new `SuperFastControl`.
  var
    last: uint64 = max(C.heardMs, C.startedMs)
  result = C.startedMs > 0'u64 and nowMs > last and nowMs - last > controlSilentMs
