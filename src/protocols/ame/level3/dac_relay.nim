## -------------------------------------------------------------------------
## AME DAC Relay <- where the loop, the peer table and the crypto meet
## -------------------------------------------------------------------------

import ../../dac/build

when not dacAdaptiveBuilt:
  {.error: "This module is part of the DAC adaptive layer, which -d:bifrostDac=off removed from this build.".}

import ../../types
import ../../dac/types
import ../../dac/level1/scramble
import ../../dac/level2/package_transfer
import ../../dac/level3/link
import ../../dac/level3/link_table
import ../level2/session
import runePragmas

const
  ameDacRelayAscii* = """
Three pieces existed and never touched each other. This is the join.

   datagram + peer address
             |
             v
   find the peer's slot          <- no slot, no session: DROPPED
             |
             v
   openAmeDacControl()           <- authenticate, decrypt, recover the kind
             |                       an unauthenticated peer gets no further
             v
   feedDacMessage(link, kind)    <- the loop, now fed only trusted kinds
             |
             v
   sealAmeDacControl() per reply <- every answer authenticated on the way out
             |
             v
   datagrams to send

The admission rule here is stronger than the bare table's. That one had to
guess from a frame whether a stranger deserved a slot. This one does not
guess: a peer gets a slot when the handshake gave it an AME session, and a
datagram from anyone else is dropped before it is parsed. The link loop
therefore only ever sees message kinds that authenticated.

Sessions sit in an array parallel to the table's slots, so the slot index
returned by the table IS the session index. One bound, one lookup, and no
second structure a peer can grow.
"""

type
  ## AmeDacRelayEventKind: what one arriving datagram produced.
  AmeDacRelayEventKind* = enum
    adrNone,
    adrDropped,
    adrProgress,
    adrPackageComplete,
    adrPackageFailed

  ## AmeDacRelayStep: outcome of feeding one datagram or one tick.
  ## send: sealed datagrams the caller must transmit to `peer`, in order.
  ## payload: a finished package, set only on adrPackageComplete.
  AmeDacRelayStep* {.role: truthState.} = object
    kind*: AmeDacRelayEventKind   ## otter:latest
    peer*: DacLinkKey
    send*: seq[ByteSeq]
    payload*: ByteSeq
    err*: string

  ## AmeDacRelay: one process's whole DAC-over-AME surface.
  ## sessions: parallel to `table.slots`; index i belongs to slot i.
  AmeDacRelay* {.role: truthState.} = object
    table*: DacLinkTable
    sessions*: seq[AmeSession]
    dropped*: uint32

proc initAmeDacRelay*(d: DacScenarioDefaults, seed: uint64,
    capacity: int = dacLinkTableCapacity,
    idleMs: uint32 = dacLinkIdleSweepMs,
    policy: DacScramblePolicy = initDacScramblePolicy(),
    limits: DacPackageLimits = defaultDacPackageLimits()): AmeDacRelay {.
    role: configurator.} =
  ## d/seed/capacity/idleMs/policy/limits: passed straight to the link table.
  result.table = initDacLinkTable(d, seed, capacity, idleMs, policy, limits)
  result.sessions = newSeq[AmeSession](result.table.slots.len)

proc admitAmeDacPeer*(R: var AmeDacRelay, key: DacLinkKey, S: AmeSession,
    nowMs: uint32): tuple[ok: bool, slot: int, err: string] {.
    role: orchestrator.} =
  ## R/key: relay and the peer address the session was established with.
  ## S: an AME session whose handshake already completed.
  ## nowMs: caller's millisecond clock.
  ## A peer enters here and nowhere else, so the relay never has to decide
  ## whether an unknown datagram deserves memory.
  var
    a: tuple[admit: DacLinkAdmit, slot: int]
  a = admitDacLink(R.table, key, S.sessionId, S.laneId, nowMs)
  if a.slot < 0:
    result.slot = -1
    result.err = "DAC relay is full of live links"
    return
  R.sessions[a.slot] = S
  result.ok = true
  result.slot = a.slot

proc releaseAmeDacPeer*(R: var AmeDacRelay, key: DacLinkKey): bool {.
    role: actor.} =
  ## R/key: relay and the peer whose slot and session are released together.
  var
    i: int = findDacLinkSlot(R.table, key)
  if i < 0:
    return false
  R.sessions[i] = default(AmeSession)
  result = closeDacLink(R.table, key)

proc ameDacPeerSlot*(R: AmeDacRelay, key: DacLinkKey): int {.role: parser.} =
  ## R/key: relay and peer whose slot index is returned, or -1.
  result = findDacLinkSlot(R.table, key)

proc sealRelayMessages(R: var AmeDacRelay, slot: int,
    M: openArray[DacTaggedMessage], step: var AmeDacRelayStep) {.
    role: dataWriter.} =
  ## R/slot: relay and the slot whose session seals the replies.
  ## M: what the link wants to say.
  ## step: outcome the sealed datagrams are appended to.
  var
    i: int = 0
  while i < M.len:
    try:
      step.send.add(sealAmeDacControl(R.sessions[slot], M[i].kind, M[i].body))
    except CatchableError as e:
      step.err = "DAC relay could not seal a reply: " & e.msg
      return
    i = i + 1

proc applyLinkStep(R: var AmeDacRelay, slot: int, inner: DacLinkStep,
    step: var AmeDacRelayStep) {.role: orchestrator.} =
  ## R/slot/inner: relay, slot, and what the link loop produced.
  ## step: relay-level outcome being filled.
  sealRelayMessages(R, slot, inner.messages, step)
  if step.err.len > 0:
    step.kind = adrDropped
    return
  case inner.kind
  of dlkPackageComplete:
    step.kind = adrPackageComplete
    step.payload = inner.payload
  of dlkPackageFailed:
    step.kind = adrPackageFailed
    step.err = inner.err
  of dlkIgnored, dlkNone:
    step.kind = adrNone
  else:
    step.kind = adrProgress

proc dropRelayStep(R: var AmeDacRelay, key: DacLinkKey, why: string,
    step: var AmeDacRelayStep) {.role: actor.} =
  ## R/key/why: relay, the peer that sent it, and why the datagram is gone.
  ## step: outcome marked as a drop.
  R.dropped = R.dropped + 1'u32
  step.kind = adrDropped
  step.peer = key
  step.err = why

proc feedAmeDacDatagram*(R: var AmeDacRelay, key: DacLinkKey,
    A: openArray[uint8], nowMs: uint32): AmeDacRelayStep {.
    role: orchestrator.} =
  ## R/key: relay and the peer the datagram arrived from.
  ## A: one datagram, of any length and any content.
  ## nowMs: caller's millisecond clock.
  ## A datagram from an address holding no session is dropped without being
  ## parsed. One that does not authenticate is dropped without reaching the
  ## loop. Nothing here raises, so a peer cannot end the relay with rubbish.
  var
    slot: int = findDacLinkSlot(R.table, key)
    opened: tuple[ok: bool, kind: DacMessageKind, body: ByteSeq, err: string]
  result.peer = key
  if slot < 0:
    dropRelayStep(R, key, "DAC datagram from a peer with no session", result)
    return
  try:
    opened = openAmeDacControl(R.sessions[slot], A)
  except CatchableError as e:
    dropRelayStep(R, key, "DAC datagram did not decode: " & e.msg, result)
    return
  if not opened.ok:
    dropRelayStep(R, key, opened.err, result)
    return
  R.table.slots[slot].lastSeenMs = nowMs
  applyLinkStep(R, slot, feedDacMessage(R.table.slots[slot].link, opened.kind,
    opened.body, nowMs), result)

proc sendAmeDacPackage*(R: var AmeDacRelay, key: DacLinkKey,
    packageId: uint64, payload: openArray[uint8],
    nowMs: uint32): AmeDacRelayStep {.role: orchestrator.} =
  ## R/key: relay and the peer the package is sent to.
  ## packageId: non-zero package identity.
  ## payload: application bytes; the relay seals every piece of them.
  ## nowMs: caller's millisecond clock.
  ## Returns the datagrams to transmit, in order. Pace them with
  ## `ameDacSendDelayMs` if the scramble policy asks for a delay.
  var
    slot: int = findDacLinkSlot(R.table, key)
  result.peer = key
  if slot < 0:
    result.kind = adrDropped
    result.err = "DAC relay has no session for that peer"
    return
  try:
    sealRelayMessages(R, slot, beginDacPackage(R.table.slots[slot].link,
      packageId, payload, nowMs), result)
  except CatchableError as e:
    result.kind = adrDropped
    result.err = e.msg
    return
  if result.err.len > 0:
    result.kind = adrDropped
    return
  R.table.slots[slot].lastSeenMs = nowMs
  result.kind = adrProgress

proc ameDacSendDelayMs*(R: var AmeDacRelay, key: DacLinkKey): uint16 {.
    role: math.} =
  ## R/key: relay and peer whose next send delay is drawn.
  ## Nothing sleeps here; pacing belongs to whoever owns the clock.
  var
    slot: int = findDacLinkSlot(R.table, key)
  if slot < 0:
    return 0'u16
  result = dacSendDelayMs(R.table.slots[slot].link)

proc tickAmeDacRelay*(R: var AmeDacRelay,
    nowMs: uint32): seq[AmeDacRelayStep] {.role: orchestrator.} =
  ## R: relay whose every live link acts on elapsed time.
  ## nowMs: caller's millisecond clock.
  ## Only peers that produced something are returned, so a quiet relay costs
  ## one pass over the slots.
  var
    i: int = 0
    step: AmeDacRelayStep
    inner: DacLinkStep
  while i < R.table.slots.len:
    if R.table.slots[i].used:
      step = default(AmeDacRelayStep)
      step.peer = R.table.slots[i].key
      inner = tickDacLink(R.table.slots[i].link, nowMs)
      applyLinkStep(R, i, inner, step)
      if step.kind != adrNone or step.send.len > 0:
        R.table.slots[i].lastSeenMs = nowMs
        result.add(step)
    i = i + 1

proc sweepAmeDacRelay*(R: var AmeDacRelay, nowMs: uint32): int {.
    role: orchestrator.} =
  ## R: relay whose finished, quiet peers release their slot AND their session.
  ## nowMs: caller's millisecond clock. Returns how many were released.
  ## The session is erased BEFORE the slot, so a slot can never be handed to a
  ## new peer while the previous peer's keys still sit beside it.
  var
    i: int = 0
  while i < R.table.slots.len:
    if dacSlotReclaimable(R.table, i, nowMs):
      R.sessions[i] = default(AmeSession)
    i = i + 1
  result = sweepDacLinkTable(R.table, nowMs)

proc ameDacRelayLive*(R: AmeDacRelay): int {.role: parser.} =
  ## R: relay whose live peer count is returned.
  result = dacLinkTableLive(R.table)
