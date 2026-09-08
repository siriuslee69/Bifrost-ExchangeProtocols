## -------------------------------------------------------------------------
## DAC Link <- the loop: send a package, answer receipts, repair, commit
## -------------------------------------------------------------------------

import ../build

when not dacAdaptiveBuilt:
  {.error: "This module is part of the DAC adaptive layer, which -d:bifrostDac=off removed from this build.".}

import ../../types
import ../types
import ../level0/framing
import ../level0/defaults
import ../level0/ack_range
import ../level0/package_commit
import ../level1/package_manifest
import ../level1/package_chunk
import ../level1/parity_shard
import ../level1/repair_hint
import ../level1/repair_chunk
import ../level0/path_stats
import ../level1/ack_policy
import ../level1/path_policy
import ../level1/scramble
import ../level2/package_transfer
import ../../../analysis_pragmas

const
  dacLinkAscii* = """
The link owns no socket and no framing. It turns intent into messages and
messages into events, so the same loop runs over UDP, over a test pipe, or
inside one process.

   caller                    DacLink                    caller
   ------                    -------                    ------
   beginDacPackage() ---->  manifest, chunks, parity  ---> send
                                    |
   feedDacMessage()   --->  parse, place, repair      ---> messages to send
                                    |
   tickDacLink(nowMs) --->  ACK deadline, repair wait ---> messages to send

What carries a message is not DAC's decision. On a live session the AME
carrier seals it, with the kind as the first byte of the protected plaintext,
so an observer cannot tell an ACK from a repair hint and a peer cannot forge
either. `renderDacFrame` still writes the bare DAC1 frame for a path probe
sent before a session exists; nothing authenticates that one.

Every decision is local. The sender picks chunk order, delay, parity width and
its own repair timer; the receiver picks its ACK batch size and deadline. An
ACK says which sequences arrived and a repair hint says which chunks are still
missing -- facts about the speaker, never instructions for the listener.

One package is in flight per direction. That bound is deliberate: it keeps the
state small enough for a sensor and makes the failure modes countable.
"""

type
  ## DacLinkEventKind: what feeding one frame produced.
  DacLinkEventKind* = enum
    dlkNone,
    dlkManifestAccepted,
    dlkChunkAccepted,
    dlkParityStored,
    dlkRepaired,
    dlkPackageComplete,
    dlkPackageFailed,
    dlkAckReceived,
    dlkRepairRequested,
    dlkCommitReceived,
    dlkPathStatsReceived,
    dlkIgnored

  ## DacLinkStep: outcome of one fed frame or one tick.
  ## messages: what the link wants to say, in order. Render them with
  ## `renderDacFrame` for bare DAC1, or seal them through the AME carrier.
  ## payload: the finished package, set only on dlkPackageComplete.
  DacLinkStep* {.role: truthState.} = object
    kind*: DacLinkEventKind
    messages*: seq[DacTaggedMessage]
    payload*: ByteSeq
    err*: string

  ## DacOutgoing: one package this side is sending.
  ## sentMs: when each chunk last left, for measuring receipt latency.
  ## acked: chunks the peer has confirmed.
  ## waitingMs: when the last frame of the package left.
  DacOutgoing* {.role: truthState.} = object
    active*: bool
    plan*: DacPackagePlan
    sentMs*: seq[uint32]
    acked*: seq[bool]
    waitingMs*: uint32
    rounds*: uint8
    timer*: DacRepairTimer
    scramble*: DacScrambleState

  ## DacIncoming: one package this side is receiving.
  ## parity: shards held for the group they belong to, keyed by group id.
  ## lastProgressMs: when the missing count last actually DROPPED. Bytes merely
  ## arriving is not progress: a sender that keeps topping up parity this side
  ## cannot use would otherwise refresh the timer forever and the receiver would
  ## never escalate to asking for exact chunks.
  DacIncoming* {.role: truthState.} = object
    active*: bool
    receiver*: DacPackageReceiver
    ack*: DacAckPolicy
    parity*: seq[DacParityShard]
    lastProgressMs*: uint32

  ## DacLink: one connection's whole adaptive state.
  ## observed: what THIS side measured about the path, which is the only thing
  ## it will ever state as fact.
  ## pathMoves: how many times the peer's report moved this side's lane, so a
  ## caller can see the loop adapting rather than having to infer it.
  DacLink* {.role: truthState.} = object
    sessionId*: uint64
    laneId*: uint32
    epochId*: uint16
    defaults*: DacScenarioDefaults
    policy*: DacScramblePolicy
    limits*: DacPackageLimits
    nextSequence*: uint32
    observed*: DacPathStats
    pathMoves*: uint16
    outgoing*: DacOutgoing
    incoming*: DacIncoming

proc initDacLink*(sessionId: uint64, laneId: uint32,
    d: DacScenarioDefaults, seed: uint64, epochId: uint16 = 0'u16,
    policy: DacScramblePolicy = initDacScramblePolicy(),
    limits: DacPackageLimits = defaultDacPackageLimits()): DacLink {.
    role: configurator.} =
  ## sessionId/laneId/epochId: identity stamped into every frame this link emits.
  ## d: scenario defaults seeding chunk size, repair mode and ACK pacing.
  ## seed: sender-local randomness for send delay and chunk order; feed it
  ## something a peer cannot guess.
  ## policy/limits: scrambling policy and receiver resource bounds.
  if not validateDacDefaults(d):
    raise newException(ValueError, "DAC link defaults are invalid")
  result.sessionId = sessionId
  result.laneId = laneId
  result.epochId = epochId
  result.defaults = d
  result.policy = policy
  result.limits = limits
  result.outgoing.timer = initDacRepairTimer()
  result.outgoing.scramble = initDacScrambleState(seed)
  result.incoming.ack = initDacAckPolicy(d)

proc dacLinkFlags(k: DacMessageKind): DacFrameFlags {.role: helper.} =
  ## k: message kind whose structural flags are derived.
  result.needsAck = k in {dmkPackageChunk, dmkPackageManifest}
  result.isParity = k == dmkParityShard
  result.isRepair = k in {dmkRepairChunk, dmkRepairHint}

proc tagDacBody(S: var DacLink, k: DacMessageKind,
    body: ByteSeq): DacTaggedMessage {.role: truthBuilder.} =
  ## S: link whose sequence counter advances by one.
  ## k: message kind this body answers to.
  ## body: encoded body bytes.
  ## Stamps identity and order onto a message without deciding how it travels.
  if S.nextSequence == high(uint32):
    raise newException(ValueError, "DAC link sequence is exhausted")
  result.kind = k
  result.sequence = S.nextSequence
  result.flags = dacLinkFlags(k)
  result.body = body
  S.nextSequence = S.nextSequence + 1'u32

proc renderDacFrame*(S: DacLink, m: DacTaggedMessage): ByteSeq {.
    role: actor.} =
  ## S: link supplying the session, lane and epoch the frame is stamped with.
  ## m: message to carry as a bare DAC1 frame.
  ## This is the unauthenticated framing: it is what a path probe uses before a
  ## session exists, and what a test pipe uses. Traffic on a live session goes
  ## through the AME carrier instead, which authenticates the kind rather than
  ## writing a header a receiver would have to trust.
  var
    h: DacFrameHeader
  if S.defaults.bodyLenMode == dblU32:
    h = initDacSuperCleanFrameHeader(m.kind, S.sessionId, S.laneId, S.epochId,
      m.sequence, uint32(m.body.len), m.flags)
  else:
    h = initDacFrameHeader(m.kind, S.sessionId, S.laneId, S.epochId,
      m.sequence, uint32(m.body.len), m.flags)
  result = encodeDacFrame(h, m.body)

proc renderDacFrames*(S: DacLink,
    M: openArray[DacTaggedMessage]): seq[ByteSeq] {.role: actor.} =
  ## S/M: link and the messages to render as bare DAC1 frames, in order.
  var
    i: int = 0
  while i < M.len:
    result.add(renderDacFrame(S, M[i]))
    i = i + 1

proc appendDacParityFrames(S: var DacLink, F: var seq[DacTaggedMessage],
    groupId: uint32) {.role: dataWriter.} =
  ## S: link emitting one group's parity.
  ## F: outbox the frames are appended to.
  ## groupId: repair group whose shards are sent.
  var
    shards: seq[DacParityShard] = groupParityShards(S.outgoing.plan, groupId)
    i: int = 0
  while i < shards.len:
    F.add(tagDacBody(S, dmkParityShard, encodeDacParityShard(shards[i])))
    i = i + 1

proc beginDacPackage*(S: var DacLink, packageId: uint64,
    A: openArray[uint8], nowMs: uint32): seq[DacTaggedMessage] {.
    role: orchestrator.} =
  ## S: link that takes ownership of one outgoing package.
  ## packageId: non-zero package identity.
  ## A: payload bytes, already encrypted or compressed by the caller.
  ## nowMs: caller's millisecond clock.
  ## Returns the manifest, then every chunk in scrambled order, then the parity
  ## for each group. Send them in the order returned, through whichever framing
  ## the carrier uses -- `renderDacFrame` for bare DAC1, or the AME carrier,
  ## which authenticates the kind instead of writing it into a header.
  var
    i: int = 0
    order: seq[uint16] = @[]
    g: uint32 = 0'u32
  if S.outgoing.active:
    raise newException(ValueError, "DAC link already has a package in flight")
  S.outgoing.plan = planDacPackage(packageId, A, S.defaults, S.defaults.transferClass,
    S.limits)
  S.outgoing.active = true
  S.outgoing.rounds = 0'u8
  S.outgoing.sentMs = newSeq[uint32](S.outgoing.plan.chunks.len)
  S.outgoing.acked = newSeq[bool](S.outgoing.plan.chunks.len)
  result.add(tagDacBody(S, dmkPackageManifest,
    encodeDacPackageManifest(S.outgoing.plan.manifest)))
  order = dacChunkSendOrder(S.outgoing.scramble, S.policy,
    S.outgoing.plan.chunks.len)
  while i < order.len:
    S.outgoing.sentMs[int(order[i])] = nowMs
    result.add(tagDacBody(S, dmkPackageChunk,
      encodeDacPackageChunk(S.outgoing.plan.chunks[int(order[i])])))
    i = i + 1
  while g < uint32(S.outgoing.plan.repairs.len):
    appendDacParityFrames(S, result, g)
    g = g + 1'u32
  S.outgoing.waitingMs = nowMs

proc dacSendDelayMs*(S: var DacLink): uint16 {.role: math.} =
  ## S: link drawing one send delay.
  ## Returns milliseconds the caller should wait before the next frame leaves.
  ## Nothing sleeps here; pacing belongs to whoever owns the clock.
  result = dacScrambleDelayMs(S.outgoing.scramble, S.policy)

proc clearDacOutgoing(S: var DacLink) {.role: actor.} =
  ## S: link whose finished outgoing package is released.
  S.outgoing.active = false
  S.outgoing.plan = default(DacPackagePlan)
  S.outgoing.sentMs = @[]
  S.outgoing.acked = @[]
  S.outgoing.rounds = 0'u8

proc openDacIncoming(S: var DacLink, m: DacPackageManifest,
    nowMs: uint32) {.
    role: actor.} =
  ## S: link starting a fresh receive.
  ## m: validated manifest describing the package.
  ## nowMs: caller clock, which seeds the progress timer.
  S.incoming.receiver = initDacPackageReceiver(m, S.limits)
  S.incoming.parity = @[]
  S.incoming.ack = initDacAckPolicy(S.defaults)
  S.incoming.lastProgressMs = nowMs
  S.incoming.active = true

proc groupParityFor(S: DacLink, groupId: uint32): seq[DacParityShard] {.
    role: parser.} =
  ## S: link holding the parity shards received so far.
  ## groupId: repair group whose shards are collected.
  var
    i: int = 0
  while i < S.incoming.parity.len:
    if S.incoming.parity[i].groupId == groupId:
      result.add(S.incoming.parity[i])
    i = i + 1

proc tryDacGroupRepair(S: var DacLink, groupId: uint32): bool {.
    role: orchestrator.} =
  ## S: link attempting one group rebuild from the parity it holds.
  ## groupId: repair group to rebuild.
  var
    shards: seq[DacParityShard] = groupParityFor(S, groupId)
    record: DacPackageGroupRepair
    report: DacGroupRepairReport
  if shards.len == 0:
    return false
  try:
    record = collectGroupRepair(S.incoming.receiver.manifest, groupId, shards)
  except CatchableError:
    return false
  report = repairGroup(S.incoming.receiver, record)
  result = report.ok and report.rebuilt.len > 0

proc repairEveryDacGroup(S: var DacLink): bool {.role: orchestrator.} =
  ## S: link sweeping every group it holds parity for.
  ## Returns true when at least one chunk was rebuilt.
  var
    g: uint32 = 0'u32
    groups: uint32 = 0'u32
  if S.incoming.receiver.manifest.dataCount == 0'u16:
    return false
  groups = (uint32(S.incoming.receiver.manifest.dataCount) +
    uint32(dacGroupDataWidth(S.incoming.receiver.manifest)) - 1'u32) div
    uint32(dacGroupDataWidth(S.incoming.receiver.manifest))
  while g < groups:
    if tryDacGroupRepair(S, g):
      result = true
    g = g + 1'u32

proc measureDacPath(S: var DacLink) {.role: math.} =
  ## S: link recording what IT observed, never what it wants the peer to do.
  ## Loss is the share of chunks that had to be repaired rather than arriving,
  ## and the round trip is the receipt latency the sender already measures for
  ## its repair timer. Both are facts about this side of the wire.
  var
    total: int = int(S.incoming.receiver.manifest.dataCount)
  S.observed.rttMs = S.outgoing.timer.peakMs
  S.observed.mtuHint = S.defaults.chunkBytes
  if total > 0:
    S.observed.lossPpm = uint32((int(S.incoming.receiver.repairCount) *
      1_000_000) div total)

proc emitDacPathStats(S: var DacLink, F: var seq[DacTaggedMessage]) {.
    role: dataWriter.} =
  ## S: link stating what it measured.
  ## F: outbox the report is appended to.
  measureDacPath(S)
  F.add(tagDacBody(S, dmkPathStats, encodeDacPathStats(S.observed)))

proc finishDacIncoming(S: var DacLink, R: var DacLinkStep) {.
    role: orchestrator.} =
  ## S: link whose complete package is verified and committed.
  ## R: step filled with the payload and the commit frame.
  var
    outcome: DacPackageResult = finishDacPackage(S.incoming.receiver)
  if not outcome.ok:
    R.kind = dlkPackageFailed
    R.err = outcome.err
    return
  R.kind = dlkPackageComplete
  R.payload = outcome.payload
  R.messages.add(tagDacBody(S, dmkPackageCommit,
    encodeDacPackageCommit(outcome.commit)))
  ## The commit is the honest moment to report the path: the package is done,
  ## so how much of it had to be repaired is a settled number rather than a
  ## guess mid-flight. The peer may move its own lane on the strength of it,
  ## or ignore it entirely.
  emitDacPathStats(S, R.messages)
  S.incoming.active = false

proc emitDacAck(S: var DacLink, F: var seq[DacTaggedMessage], nowMs: uint32) {.
    role: dataWriter.} =
  ## S: link closing its open ACK batch.
  ## F: outbox the receipt is appended to.
  ## nowMs: caller's millisecond clock.
  if S.incoming.ack.pending == 0'u16:
    return
  F.add(tagDacBody(S, dmkAckRange,
    encodeDacAckRange(closeDacAckBatch(S.incoming.ack, 0'u8, nowMs))))

proc feedDacManifest(S: var DacLink, body: openArray[uint8], nowMs: uint32,
    R: var DacLinkStep) {.role: orchestrator.} =
  ## S/body/nowMs/R: link, manifest bytes, clock, and the step being filled.
  var
    m: DacPackageManifest = decodeDacPackageManifest(body)
  if S.incoming.active and S.incoming.receiver.manifest.packageId == m.packageId:
    R.kind = dlkIgnored
    return
  openDacIncoming(S, m, nowMs)
  R.kind = dlkManifestAccepted

proc feedDacChunk(S: var DacLink, body: openArray[uint8], nowMs: uint32,
    R: var DacLinkStep) {.role: orchestrator.} =
  ## S/body/nowMs/R: link, chunk body bytes, clock, and the step being filled.
  var
    c: DacPackageChunk = decodeDacPackageChunk(body)
    before: int = 0
  if not S.incoming.active or c.packageId != S.incoming.receiver.manifest.packageId:
    R.kind = dlkIgnored
    return
  before = missingChunkCount(S.incoming.receiver)
  acceptDacPackageChunk(S.incoming.receiver, c)
  if missingChunkCount(S.incoming.receiver) < before:
    S.incoming.lastProgressMs = nowMs
  discard observeDacArrival(S.incoming.ack, uint32(c.chunkId), nowMs)
  R.kind = dlkChunkAccepted
  if dacAckDue(S.incoming.ack, nowMs):
    emitDacAck(S, R.messages, nowMs)
  if missingChunkCount(S.incoming.receiver) == 0:
    finishDacIncoming(S, R)

proc feedDacParity(S: var DacLink, body: openArray[uint8], nowMs: uint32,
    R: var DacLinkStep) {.role: orchestrator.} =
  ## S/body/nowMs/R: link, parity body bytes, clock, and the step being filled.
  var
    p: DacParityShard = decodeDacParityShard(body)
  if not S.incoming.active or p.packageId != S.incoming.receiver.manifest.packageId:
    R.kind = dlkIgnored
    return
  S.incoming.parity.add(p)
  R.kind = dlkParityStored
  if missingChunkCount(S.incoming.receiver) == 0:
    finishDacIncoming(S, R)
    return
  if not tryDacGroupRepair(S, p.groupId):
    return
  R.kind = dlkRepaired
  S.incoming.lastProgressMs = nowMs
  if missingChunkCount(S.incoming.receiver) == 0:
    finishDacIncoming(S, R)

proc feedDacAck(S: var DacLink, body: openArray[uint8], nowMs: uint32,
    R: var DacLinkStep) {.role: orchestrator.} =
  ## S/body/nowMs/R: link, ACK body bytes, clock, and the step being filled.
  var
    a: DacAckRange = decodeDacAckRange(body)
    i: int = 0
    delta: uint32 = 0'u32
  if not S.outgoing.active:
    R.kind = dlkIgnored
    return
  while i < S.outgoing.acked.len:
    if not S.outgoing.acked[i] and dacAckIncludesSeq(a, uint32(i)):
      S.outgoing.acked[i] = true
      delta = nowMs - S.outgoing.sentMs[i]
      observeDacAckLatency(S.outgoing.timer, uint16(min(delta,
        uint32(high(uint16)))))
    i = i + 1
  R.kind = dlkAckReceived

proc feedDacRepairHint(S: var DacLink, body: openArray[uint8],
    R: var DacLinkStep) {.role: orchestrator.} =
  ## S/body/R: link, repair-hint body bytes, and the step being filled.
  var
    h: DacRepairHint = decodeDacRepairHint(body)
    answers: seq[DacRepairChunk] = @[]
    i: int = 0
  if not S.outgoing.active or h.packageId != S.outgoing.plan.manifest.packageId:
    R.kind = dlkIgnored
    return
  answers = answerDacRepairHint(S.outgoing.plan, h)
  while i < answers.len:
    R.messages.add(tagDacBody(S, dmkRepairChunk,
      encodeDacRepairChunk(answers[i])))
    i = i + 1
  R.kind = dlkRepairRequested

proc feedDacRepairChunk(S: var DacLink, body: openArray[uint8], nowMs: uint32,
    R: var DacLinkStep) {.role: orchestrator.} =
  ## S/body/nowMs/R: link, repair-chunk body bytes, clock, and the step filled.
  var
    c: DacRepairChunk = decodeDacRepairChunk(body)
  if not S.incoming.active or c.packageId != S.incoming.receiver.manifest.packageId:
    R.kind = dlkIgnored
    return
  acceptDacRepairChunk(S.incoming.receiver, c)
  S.incoming.lastProgressMs = nowMs
  discard observeDacArrival(S.incoming.ack, uint32(c.chunkId), nowMs)
  R.kind = dlkRepaired
  if missingChunkCount(S.incoming.receiver) == 0:
    finishDacIncoming(S, R)

proc feedDacPathStats(S: var DacLink, body: openArray[uint8],
    R: var DacLinkStep) {.role: orchestrator.} =
  ## S/body/R: link, path-stats body bytes, and the step being filled.
  ## The peer reports what IT saw. This side decides what to do about it, and
  ## the only thing it changes is its OWN sending: a report is never an
  ## instruction, so nothing here can be driven past one lane step at a time.
  var
    stats: DacPathStats = decodeDacPathStats(body)
    move: DacPathRecommendation = recommendDacPathFromStats(
      S.defaults.pathLane, stats)
  R.kind = dlkPathStatsReceived
  if not move.ok or S.outgoing.active:
    return
  S.defaults = dacDefaultsForPath(move.path, S.defaults.transferClass)
  S.incoming.ack = initDacAckPolicy(S.defaults)
  S.pathMoves = S.pathMoves + 1'u16

proc feedDacCommit(S: var DacLink, body: openArray[uint8],
    R: var DacLinkStep) {.role: orchestrator.} =
  ## S/body/R: link, commit body bytes, and the step being filled.
  var
    c: DacPackageCommit = decodeDacPackageCommit(body)
  if not S.outgoing.active or c.packageId != S.outgoing.plan.manifest.packageId:
    R.kind = dlkIgnored
    return
  if c.digest != S.outgoing.plan.manifest.digest:
    R.kind = dlkPackageFailed
    R.err = "DAC commit digest does not match the package"
    return
  clearDacOutgoing(S)
  R.kind = dlkCommitReceived

proc dispatchDacBody(S: var DacLink, k: DacMessageKind,
    body: openArray[uint8], nowMs: uint32,
    R: var DacLinkStep) {.role: orchestrator.} =
  ## S/k/body/nowMs/R: link, message kind, body bytes, clock, and the step.
  case k
  of dmkPackageManifest:
    feedDacManifest(S, body, nowMs, R)
  of dmkPackageChunk:
    feedDacChunk(S, body, nowMs, R)
  of dmkParityShard:
    feedDacParity(S, body, nowMs, R)
  of dmkAckRange:
    feedDacAck(S, body, nowMs, R)
  of dmkRepairHint:
    feedDacRepairHint(S, body, R)
  of dmkRepairChunk:
    feedDacRepairChunk(S, body, nowMs, R)
  of dmkPackageCommit:
    feedDacCommit(S, body, R)
  of dmkPathStats:
    feedDacPathStats(S, body, R)
  else:
    R.kind = dlkIgnored

proc feedDacMessage*(S: var DacLink, k: DacMessageKind,
    body: openArray[uint8], nowMs: uint32): DacLinkStep {.role: orchestrator.} =
  ## S: link the message belongs to.
  ## k: message kind, already established by whatever framing carried it.
  ## body: body bytes.
  ## nowMs: caller's millisecond clock.
  ## This is the entry point for a carrier that has ALREADY authenticated the
  ## kind, so no header on the wire has to be trusted for it. A body that does
  ## not decode is reported, never raised.
  try:
    dispatchDacBody(S, k, body, nowMs, result)
  except CatchableError:
    result.kind = dlkIgnored
    result.err = "DAC message body did not decode"

proc feedDacFrame*(S: var DacLink, A: openArray[uint8],
    nowMs: uint32): DacLinkStep {.role: orchestrator.} =
  ## S: link the frame belongs to.
  ## A: one complete bare DAC1 frame as it arrived.
  ## nowMs: caller's millisecond clock.
  ## A malformed or foreign frame is reported, never raised: a peer must not be
  ## able to end the loop by sending rubbish. Note that nothing here is
  ## authenticated -- the kind comes off the wire. A live session should use
  ## the AME carrier and `feedDacMessage` instead.
  var
    f: DacDecodedFrame
  try:
    f = decodeDacFrame(A)
  except CatchableError:
    result.kind = dlkIgnored
    result.err = "DAC frame did not decode"
    return
  if f.header.sessionId != S.sessionId or f.header.laneId != S.laneId:
    result.kind = dlkIgnored
    result.err = "DAC frame is for another session or lane"
    return
  result = feedDacMessage(S, f.header.messageKind, f.payload, nowMs)

proc dacSenderRepairDue(S: DacLink, nowMs: uint32): bool {.role: parser.} =
  ## S: link whose outgoing package may need another parity round.
  ## nowMs: caller's millisecond clock.
  ## The wait comes from the receipt latency this sender has actually measured,
  ## so a receiver that merely batches its ACKs is never mistaken for loss.
  if not S.outgoing.active:
    return false
  if S.outgoing.rounds >= S.limits.maxRepairRounds:
    return false
  result = (nowMs - S.outgoing.waitingMs) >=
    uint32(dacRepairWaitMs(S.outgoing.timer, S.defaults))

proc dacReceiverRepairDue(S: DacLink, nowMs: uint32): bool {.role: parser.} =
  ## S: link whose incoming package has stalled with gaps still open.
  ## nowMs: caller's millisecond clock.
  ## A receiver has no outgoing package to hang a timer on, so it uses the only
  ## fact it owns: nothing has arrived for a while and chunks are still missing.
  if not S.incoming.active:
    return false
  if missingChunkCount(S.incoming.receiver) == 0:
    return false
  result = (nowMs - S.incoming.lastProgressMs) >= uint32(S.defaults.repairWaitMs)

proc unackedDacGroups(S: DacLink): seq[uint32] {.role: parser.} =
  ## S: link whose groups still hold an unacknowledged chunk.
  var
    i: int = 0
    g: uint32 = 0'u32
  while i < S.outgoing.acked.len:
    if not S.outgoing.acked[i]:
      g = S.outgoing.plan.chunks[i].groupId
      if g notin result:
        result.add(g)
    i = i + 1

proc resendDacParity(S: var DacLink, F: var seq[DacTaggedMessage]) {.role: actor.} =
  ## S: link sending another parity round for its unacknowledged groups.
  ## F: outbox the frames are appended to.
  var
    groups: seq[uint32] = unackedDacGroups(S)
    i: int = 0
  while i < groups.len:
    appendDacParityFrames(S, F, groups[i])
    i = i + 1

proc dacRepairRoundsLeft*(S: DacLink): bool {.role: parser.} =
  ## S: link asked whether its receiver may still spend a repair round.
  result = S.incoming.active and
    S.incoming.receiver.repairRounds < S.limits.maxRepairRounds

proc requestDacRepair(S: var DacLink, F: var seq[DacTaggedMessage]): bool {.role: actor.} =
  ## S: link asking the peer for the exact chunks it is still missing.
  ## F: outbox the hint is appended to.
  ## Returns false when the round budget is spent, which is the caller's cue
  ## that this package will not complete on its own.
  if not S.incoming.active or missingChunkCount(S.incoming.receiver) == 0:
    return true
  try:
    F.add(tagDacBody(S, dmkRepairHint,
      encodeDacRepairHint(buildDacRepairHint(S.incoming.receiver))))
  except CatchableError:
    return false
  result = true

proc tickDacLink*(S: var DacLink, nowMs: uint32): DacLinkStep {.
    role: orchestrator.} =
  ## S: link given a chance to act on elapsed time alone.
  ## nowMs: caller's millisecond clock.
  ## Call it on any convenient cadence. It closes an ACK batch whose deadline
  ## expired, sends another parity round when the measured receipt latency says
  ## a gap is loss rather than batching, and asks for exact chunks when its own
  ## receive has gone quiet with holes in it. The two repair timers are separate
  ## because the two roles are: a link that only receives still has to be able
  ## to ask, and a link that only sends still has to be able to top up parity.
  if dacAckDue(S.incoming.ack, nowMs):
    emitDacAck(S, result.messages, nowMs)
  if dacSenderRepairDue(S, nowMs):
    S.outgoing.rounds = S.outgoing.rounds + 1'u8
    S.outgoing.waitingMs = nowMs
    resendDacParity(S, result.messages)
  if not dacReceiverRepairDue(S, nowMs):
    return
  S.incoming.lastProgressMs = nowMs
  if repairEveryDacGroup(S) and missingChunkCount(S.incoming.receiver) == 0:
    finishDacIncoming(S, result)
    return
  if requestDacRepair(S, result.messages):
    result.kind = dlkRepairRequested
    return
  S.incoming.active = false
  result.kind = dlkPackageFailed
  result.err = "DAC package exhausted its repair rounds with chunks missing"

proc dacLinkIdle*(S: DacLink): bool {.role: parser.} =
  ## S: link asked whether both directions are finished.
  result = not S.outgoing.active and not S.incoming.active

proc dacLinkMissingCount*(S: DacLink): int {.role: parser.} =
  ## S: link whose still-missing incoming chunk count is returned.
  if not S.incoming.active:
    return 0
  result = missingChunkIds(S.incoming.receiver).len

proc sweepDacRepair*(S: var DacLink): bool {.role: orchestrator.} =
  ## S: link asked to rebuild every group it can from the parity it holds.
  ## Returns true when at least one chunk was rebuilt. Useful after a burst of
  ## parity arrived out of order behind the chunks it repairs.
  result = S.incoming.active and repairEveryDacGroup(S)
