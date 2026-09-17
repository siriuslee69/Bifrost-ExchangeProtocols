## -------------------------------------------------------------------------
## AME DAC Relay <- where the loop, the peer table and the crypto meet
## -------------------------------------------------------------------------

import ../../dac/build

when not dacAdaptiveBuilt:
  {.error: "This module is part of the DAC adaptive layer, which -d:bifrostDac=off removed from this build.".}

import ../../types
import ../types
import ../../dac/types
import ../../dac/level1/scramble
import ../../dac/level2/package_transfer
import ../../dac/level3/link
import ../../dac/level3/link_table
import ../level2/framing
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
    forgotten*: uint32
      ## How many held frame keys this relay has given up on, across every
      ## peer. It is the loss the ratchet SAW, counted where nothing else
      ## counts it: DAC reports chunks, and one lost chunk is one lost frame
      ## only until repair starts sending chunks a second time.

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
    a: tuple[admit: DacLinkAdmit, slot: int] = (dlaExisting, -1)
  a = admitDacLink(R.table, key, nowMs)
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

proc forgetSkippedFrames(R: var AmeDacRelay, slot: int) {.role: actor.} =
  ## R/slot: tell the session that the frames it is still holding keys for are
  ## not coming.
  ##
  ## FOMKE keeps the key of any frame it had to jump over, so that a frame
  ## which merely arrived late still opens. Over DAC a frame that is missing is
  ## usually not late but LOST, and DAC does not re-send a frame -- it re-sends
  ## the CHUNK, inside a new frame at a new position. The key for the old one
  ## then waits for something that will never exist.
  ##
  ##   package starts  ──▶  frames 100..130 sealed
  ##                        104 and 117 lost on the path
  ##                        their keys are held, waiting
  ##   package ends    ──▶  every chunk is either here or given up on
  ##                        so those two keys are waiting on nothing
  ##
  ## The end of a package is the moment that becomes knowable, and this is the
  ## only place that knows it. FOMKE says so itself: giving up is the caller's
  ## decision, because only the caller can tell a slow path from a lost frame.
  ## Leaving it undecided used to cost the link its ability to REKEY, because a
  ## KEM upgrade refuses to run while any skipped key is outstanding.
  if slot < 0 or slot >= R.sessions.len:
    return
  if ameSessionSkippedMessages(R.sessions[slot]) == 0:
    return
  R.forgotten = R.forgotten + uint32(discardAmeSessionSkipped(R.sessions[slot]))

proc applyLinkStep(R: var AmeDacRelay, slot: int, inner: DacLinkStep,
    step: var AmeDacRelayStep) {.role: orchestrator.} =
  ## R/slot/inner: relay, slot, and what the link loop produced.
  ## step: relay-level outcome being filled.
  ##
  ## What ARRIVED is decided before what can be SAID about it. Those are two
  ## different facts and only one of them can fail here:
  ##
  ##   the link completed a package   <- already parsed, repaired, digest-checked
  ##   the reply could not be sealed  <- a separate problem, on the way out
  ##
  ## This used to seal first and bail on failure, which threw the finished
  ## payload away to report that the receipt did not go out. The receive had
  ## already closed by then, so those bytes were gone for good and the caller
  ## was handed a drop -- the one outcome that says nothing arrived.
  case inner.kind
  of dlkPackageComplete:
    step.kind = adrPackageComplete
    step.payload = inner.payload
    forgetSkippedFrames(R, slot)
  of dlkPackageFailed:
    step.kind = adrPackageFailed
    step.err = inner.err
    forgetSkippedFrames(R, slot)
  of dlkIgnored, dlkNone:
    step.kind = adrNone
  else:
    step.kind = adrProgress
  sealRelayMessages(R, slot, inner.messages, step)
  ## A reply that could not be sealed is reported in `err` and leaves `kind`
  ## alone, EXCEPT where there was nothing to report anyway: a step that
  ## produced no event becomes a drop, so a caller watching `kind` still sees
  ## that something went wrong.
  if step.err.len > 0 and step.kind == adrNone:
    step.kind = adrDropped

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
    opened: AmeDacControlOpen = default(AmeDacControlOpen)
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
  ##
  ## A send either happens whole or not at all. `beginDacPackage` claims the
  ## link's one outgoing slot before anything is sealed, so a seal that fails
  ## halfway would otherwise leave the link holding a package no peer has ever
  ## heard of -- and every later send on that link answering "DAC link already
  ## has a package in flight", forever, with no public way to clear it. On any
  ## failure the claim is given back and the half-sealed datagrams are dropped,
  ## so the caller can simply try again.
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
    result.send = @[]
    discard abandonDacPackage(R.table.slots[slot].link)
    return
  if result.err.len > 0:
    result.kind = adrDropped
    result.send = @[]
    discard abandonDacPackage(R.table.slots[slot].link)
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
    step: AmeDacRelayStep = default(AmeDacRelayStep)
    inner: DacLinkStep = default(DacLinkStep)
  while i < R.table.slots.len:
    if R.table.slots[i].used:
      step = default(AmeDacRelayStep)
      step.peer = R.table.slots[i].key
      inner = tickDacLink(R.table.slots[i].link, nowMs)
      applyLinkStep(R, i, inner, step)
      ## `lastSeenMs` is NOT touched here, and that is the point of the field.
      ## It means "when this peer was last HEARD FROM", which only
      ## `feedAmeDacDatagram` can know. A tick is this side SPEAKING, and a
      ## link that keeps speaking to a peer that has gone -- repair rounds, a
      ## receipt, anything -- used to refresh its own timestamp and so never
      ## look quiet:
      ##
      ##   this side sends  ->  lastSeenMs = now  ->  the slot looks alive
      ##                                              because WE are alive
      ##
      ## Nothing is lost by dropping it. A slot mid-transfer is protected by
      ## `dacSlotReclaimable` refusing any link with either direction active,
      ## whatever the timestamp says -- so the timestamp is free to mean the
      ## one thing it should.
      if step.kind != adrNone or step.send.len > 0:
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
