## -------------------------------------------------------------------------
## DAC Link <- the loop: send a package, answer receipts, repair, commit
## -------------------------------------------------------------------------

import ../build

when not dacAdaptiveBuilt:
  {.error: "This module is part of the DAC adaptive layer, which -d:bifrostDac=off removed from this build.".}

import ../../types
import ../types
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
import ../level1/path_meter
import ../level1/path_policy
import ../level1/scramble
import ../level2/package_transfer
import runePragmas

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

What carries a message is not DAC's decision, and DAC frames nothing itself.
The AME carrier seals it, with the kind as the first byte of the protected
plaintext, so an observer cannot tell an ACK from a repair hint and a peer
cannot forge either.

There used to be a second way out of here: a bare DAC1 frame that wrote the
kind into a header nobody had authenticated. It is gone. Every kind the loop
sees has already passed a tag check, so a stranger cannot present one at all.

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
  ## messages: what the link wants to say, in order. A kind and a body each;
  ## the AME carrier is what puts them on a wire.
  ## payload: the finished package, set only on dlkPackageComplete.
  DacLinkStep* {.role: truthState.} = object
    kind*: DacLinkEventKind   ## otter:latest
    messages*: seq[DacTaggedMessage]
    payload*: ByteSeq
    err*: string

  ## DacOutgoing: one package this side is sending.
  ## sentMs: when each chunk last left, for measuring receipt latency.
  ## acked: chunks the peer has confirmed.
  ## waitingMs: when the last frame of the package left.
  ## peerCommitsAtStart: what the peer's commit count read when this package
  ## began. A `damVerified` receiver reports that count in every receipt, so a
  ## DIFFERENT number coming back means it committed something since -- and
  ## with one package in flight per direction, that something is this one.
  ## Every other mode reports zero, so the comparison never fires and this
  ## costs nothing.
  DacOutgoing* {.role: truthState.} = object
    active*: bool
    plan*: DacPackagePlan
    sentMs*: seq[uint32]
    acked*: seq[bool]
    waitingMs*: uint32
    rounds*: uint8
    timer*: DacRepairTimer
    scramble*: DacScrambleState
    peerCommitsAtStart*: uint8

  ## DacIncoming: one package this side is receiving.
  ## parity: shards held for the group they belong to, keyed by group id.
  ## lastProgressMs: when the missing count last actually DROPPED. Bytes merely
  ## arriving is not progress: a sender that keeps topping up parity this side
  ## cannot use would otherwise refresh the timer forever and the receiver would
  ## never escalate to asking for exact chunks.
  ## meter: the arrival pattern, measured as it lands. This is what the path
  ## report is built from, so the report states what this side SAW rather than
  ## what this side is configured to do.
  DacIncoming* {.role: truthState.} = object
    active*: bool
    receiver*: DacPackageReceiver
    ack*: DacAckPolicy
    parity*: seq[DacParityShard]
    lastProgressMs*: uint32
    meter*: DacArrivalMeter

  ## DacLink: one connection's whole adaptive state.
  ## observed: what THIS side measured about the path, which is the only thing
  ## it will ever state as fact.
  ## pathMoves: how many times the peer's report moved this side's lane, so a
  ## caller can see the loop adapting rather than having to infer it.
  ## committed: packages this side has received whole and verified. Only a
  ## `damVerified` receiver says it out loud, in every receipt.
  ## peerCommits: the last commit count the PEER reported.
  DacLink* {.role: truthState.} = object
    defaults*: DacScenarioDefaults
    policy*: DacScramblePolicy
    limits*: DacPackageLimits
    observed*: DacPathStats
    pathMoves*: uint16
    committed*: uint8
    peerCommits*: uint8
    outgoing*: DacOutgoing
    incoming*: DacIncoming

proc initDacLink*(d: DacScenarioDefaults, seed: uint64,
    policy: DacScramblePolicy = initDacScramblePolicy(),
    limits: DacPackageLimits = defaultDacPackageLimits()): DacLink {.
    role: configurator.} =
  ## d: scenario defaults seeding chunk size, repair mode and ACK pacing.
  ## seed: sender-local randomness for send delay and chunk order; feed it
  ## something a peer cannot guess.
  ## policy/limits: scrambling policy and receiver resource bounds.
  ##
  ## A link carries no identity of its own. It used to hold a session id, a
  ## lane id and a path epoch, stamped into the DAC header it no longer
  ## writes; nothing ever read them back. WHO a link belongs to is the peer
  ## table's question, answered by the address it was admitted on, and WHAT
  ## authenticates is the AME session beside it.
  if not validateDacDefaults(d):
    raise newException(ValueError, "DAC link defaults are invalid")
  result.defaults = d
  result.policy = policy
  result.limits = limits
  result.outgoing.timer = initDacRepairTimer()
  result.outgoing.scramble = initDacScrambleState(seed)
  result.incoming.ack = initDacAckPolicy(d, not policy.shuffleChunks)

proc appendDacParityFrames(S: var DacLink, F: var seq[DacTaggedMessage],
    groupId: uint32) {.role: dataWriter.} =
  ## S: link emitting one group's parity.
  ## F: outbox the frames are appended to.
  ## groupId: repair group whose shards are sent.
  var
    shards: seq[DacParityShard] = groupParityShards(S.outgoing.plan, groupId)
    i: int = 0
  while i < shards.len:
    F.add(dacMessage(dmkParityShard, encodeDacParityShard(shards[i])))
    i = i + 1

proc beginDacPackage*(S: var DacLink, packageId: uint64,
    A: openArray[uint8], nowMs: uint32): seq[DacTaggedMessage] {.
    role: orchestrator.} =
  ## S: link that takes ownership of one outgoing package.
  ## packageId: non-zero package identity.
  ## A: payload bytes, already encrypted or compressed by the caller.
  ## nowMs: caller's millisecond clock.
  ## Returns the manifest, then every chunk in scrambled order, then the parity
  ## for each group. Send them in the order returned, through the AME carrier,
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
  result.add(dacMessage(dmkPackageManifest,
    encodeDacPackageManifest(S.outgoing.plan.manifest)))
  order = dacChunkSendOrder(S.outgoing.scramble, S.policy,
    S.outgoing.plan.chunks.len)
  while i < order.len:
    S.outgoing.sentMs[int(order[i])] = nowMs
    result.add(dacMessage(dmkPackageChunk,
      encodeDacPackageChunk(S.outgoing.plan.chunks[int(order[i])])))
    i = i + 1
  while g < uint32(S.outgoing.plan.repairs.len):
    appendDacParityFrames(S, result, g)
    g = g + 1'u32
  S.outgoing.waitingMs = nowMs
  S.outgoing.peerCommitsAtStart = S.peerCommits

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

proc abandonDacPackage*(S: var DacLink): bool {.role: actor.} =
  ## S: link giving up the package it holds in flight. Returns false when it
  ## held none, so calling this twice is harmless.
  ##
  ## `beginDacPackage` claims the one outgoing slot BEFORE its messages have
  ## gone anywhere, which is the right order -- the plan has to exist before it
  ## can be handed out. But it means a carrier that then fails to put those
  ## messages on the wire has left the link owning a package that no peer will
  ## ever acknowledge, and nothing else releases the slot: the only other way
  ## out is a commit, which needs the peer to have received something.
  ##
  ##   beginDacPackage()  ->  outgoing.active = true
  ##          |
  ##          +--> carrier seals and sends  ->  peer commits  ->  slot freed
  ##          |
  ##          +--> carrier cannot seal      ->  nothing sent  ->  STUCK
  ##                                                               here
  ##
  ## This is the way out of that corner. It tells the peer nothing, because
  ## there is nothing to tell: the peer never heard of the package. Whatever
  ## fraction did escape is ignored on arrival once the manifest times out.
  if not S.outgoing.active:
    return false
  clearDacOutgoing(S)
  result = true

proc openDacIncoming(S: var DacLink, m: DacPackageManifest,
    nowMs: uint32) {.
    role: actor.} =
  ## S: link starting a fresh receive.
  ## m: validated manifest describing the package.
  ## nowMs: caller clock, which seeds the progress timer.
  S.incoming.receiver = initDacPackageReceiver(m, S.limits)
  S.incoming.parity = @[]
  S.incoming.ack = initDacAckPolicy(S.defaults, not S.policy.shuffleChunks)
  openDacAckBatchAt(S.incoming.ack, 0'u32, m.dataCount, nowMs)
  S.incoming.lastProgressMs = nowMs
  S.incoming.meter = initDacArrivalMeter(nowMs)
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
    record: DacPackageGroupRepair = default(DacPackageGroupRepair)
    report: DacGroupRepairReport = default(DacGroupRepairReport)
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

proc measureDacPath(S: var DacLink, nowMs: uint32) {.role: math.} =
  ## S: link recording what IT observed, never what it wants the peer to do.
  ## nowMs: caller's millisecond clock.
  ##
  ## Seven numbers go on the wire and every one of them has to be a thing this
  ## side actually saw. Where it saw nothing, it says nothing -- the field stays
  ## zero and the peer's lane policy skips the rule that reads it:
  ##
  ##   lossPpm     chunks that had to be repaired, over chunks expected
  ##   rttMs       the SENDER's measured receipt latency -- reported only when
  ##               this side has sent something and been answered, because a
  ##               link that has only ever received cannot know a round trip
  ##   jitterMs    how much the gap between arrivals kept changing
  ##   reorderDepth  LEFT AT ZERO, on purpose. The sender shuffles its chunks
  ##               deliberately, so chunk-id order says what the SENDER did and
  ##               nothing about the path -- see path_meter.nim
  ##   mtuHint     the chunk size that GOT THROUGH, read off the sender's
  ##               manifest -- not this side's own configured chunk size, which
  ##               is a statement about this side's plans and about nothing else
  ##   queueMs     how long an unfinished package has been held here
  ##   creditHint  chunks of room left on top of what is already held
  ##
  ## This used to fill three of the seven and leave four at zero, which the peer
  ## then read as measurements. One of those four -- creditHint -- is tested
  ## first and reads low as "the receiver is drowning", so every report said so
  ## and every link walked itself down to the recovery lane.
  var
    total: int = int(S.incoming.receiver.manifest.dataCount)
  S.observed = default(DacPathStats)
  S.observed.mtuHint = S.incoming.receiver.manifest.chunkBytes
  S.observed.jitterMs = S.incoming.meter.jitterMs
  S.observed.queueMs = dacQueueMs(S.incoming.meter, nowMs)
  S.observed.creditHint = dacReceiveCreditChunks(S.incoming.receiver)
  if S.outgoing.timer.samples > 0'u16:
    S.observed.rttMs = S.outgoing.timer.peakMs
  if total > 0:
    S.observed.lossPpm = uint32((int(S.incoming.receiver.repairCount) *
      1_000_000) div total)

proc emitDacPathStats(S: var DacLink, F: var seq[DacTaggedMessage],
    nowMs: uint32) {.role: dataWriter.} =
  ## S: link stating what it measured.
  ## F: outbox the report is appended to.
  ## nowMs: caller's millisecond clock.
  measureDacPath(S, nowMs)
  F.add(dacMessage(dmkPathStats, encodeDacPathStats(S.observed)))

proc noteDacAckEvidence(S: var DacLink, lost: bool) {.role: actor, inline.} =
  ## S: link whose ACK levers move on evidence it actually has.
  ## lost: whether this side has just caught the path losing something.
  ##
  ## Only for a stream whose holes say nothing -- one this side's own sender
  ## policy tells it is shuffled. Where holes DO mean loss, `closeDacAckBatch`
  ## has already read them and a second verdict here would double-count.
  if S.incoming.ack.holesMeanLoss:
    return
  adaptDacAckPolicy(S.incoming.ack, if lost: 1'u16 else: 0'u16)

proc emitDacAck(S: var DacLink, F: var seq[DacTaggedMessage], nowMs: uint32) {.
    role: dataWriter.} =
  ## S: link closing its open ACK batch.
  ## F: outbox the receipt is appended to.
  ## nowMs: caller's millisecond clock.
  if not dacAckSpeaks(S.incoming.ack) or S.incoming.ack.pending == 0'u16:
    return
  F.add(dacMessage(dmkAckRange, encodeDacAckRange(closeDacAckBatch(
    S.incoming.ack, dacAckCommitCount(S.incoming.ack, S.committed), nowMs))))
  noteDacAckEvidence(S, false)

proc endDacIncoming(S: var DacLink, F: var seq[DacTaggedMessage],
    nowMs: uint32) {.role: actor.} =
  ## S: link whose receive is over, whichever way it ended.
  ## F: outbox the last receipt is appended to.
  ## nowMs: caller's millisecond clock.
  ##
  ## Two things end together, and they used to end one at a time. The receive
  ## closed; the ACK batch describing it did not.
  ##
  ## `slideDacAckBatch` deliberately refuses to move the base past a hole, so
  ## a package that ended with a hole still in the window -- which is every
  ## package repaired from parity, the normal case under loss -- left
  ## `pending` non-zero with nothing that could ever fill it:
  ##
  ##   base                    the package is complete, and yet
  ##    |  X  .  X  X          pending = 2, so dacAckDue stays true
  ##          ^                -> a receipt every deadline
  ##          the hole that       -> and the batch slides nowhere
  ##          parity filled       -> so it happens again, forever
  ##
  ## That receipt was a sealed datagram to a peer that had stopped listening,
  ## about ten a second per link, for the life of the process. It cost more
  ## than bandwidth: every one refreshed the link's `lastSeenMs`, so the slot
  ## never looked quiet, was never reclaimed, and a relay full of them refused
  ## every new peer for good.
  ##
  ## ONE last receipt still goes out, and that one is load-bearing. A
  ## `damVerified` receiver carries its commit count in every receipt, which is
  ## how a sender whose commit message was lost still learns the package
  ## landed. The count has already been raised by the time this runs, so the
  ## last receipt is the one that says so.
  ##
  ## No other mode gets one, because no other mode has a reason. They have all
  ## just sent a commit, and the commit says everything a receipt could:
  ##
  ##   damVerified  the receipt carries the commit COUNT, which survives the
  ##                commit message being lost -- so it is sent
  ##   damExplicit  the sender already knows; a receipt adds nothing
  ##   damBatch     the same
  ##   damNackOnly  a clean run is silence, and the flush must not break that
  ##   damSilent    silence, always
  if S.incoming.ack.mode == damVerified:
    emitDacAck(S, F, nowMs)
  S.incoming.active = false
  resetDacAckPolicy(S.incoming.ack)
proc finishDacIncoming(S: var DacLink, R: var DacLinkStep,
    nowMs: uint32) {.role: orchestrator.} =
  ## S: link whose complete package is verified and committed.
  ## R: step filled with the payload and the commit frame.
  ## nowMs: caller's millisecond clock.
  var
    outcome: DacPackageResult = finishDacPackage(S.incoming.receiver)
  if not outcome.ok:
    R.kind = dlkPackageFailed
    R.err = outcome.err
    return
  R.kind = dlkPackageComplete
  R.payload = outcome.payload
  ## One more package received whole and verified. A `damVerified` receiver
  ## puts this count in every receipt from here on, so a sender whose commit
  ## message is lost still learns the package landed.
  S.committed = S.committed + 1'u8
  R.messages.add(dacMessage(dmkPackageCommit,
    encodeDacPackageCommit(outcome.commit)))
  ## The commit is the honest moment to report the path: the package is done,
  ## so how much of it had to be repaired is a settled number rather than a
  ## guess mid-flight. The peer may move its own lane on the strength of it,
  ## or ignore it entirely.
  emitDacPathStats(S, R.messages, nowMs)
  endDacIncoming(S, R.messages, nowMs)

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
  ## `observeDacArrival` answers false for an id the open window cannot hold,
  ## and its contract is that the caller closes the batch and offers it again.
  ## That contract was being discarded. With a sender that shuffles, an id
  ## below the window is the common case, not the rare one, and every refused
  ## id is a chunk the sender is never told about.
  if not observeDacArrival(S.incoming.ack, uint32(c.chunkId), nowMs):
    emitDacAck(S, R.messages, nowMs)
    discard observeDacArrival(S.incoming.ack, uint32(c.chunkId), nowMs)
  observeDacChunkArrival(S.incoming.meter, nowMs)
  R.kind = dlkChunkAccepted
  if dacAckDue(S.incoming.ack, nowMs):
    emitDacAck(S, R.messages, nowMs)
  if missingChunkCount(S.incoming.receiver) == 0:
    finishDacIncoming(S, R, nowMs)

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
    finishDacIncoming(S, R, nowMs)
    return
  if not tryDacGroupRepair(S, p.groupId):
    return
  R.kind = dlkRepaired
  S.incoming.lastProgressMs = nowMs
  if missingChunkCount(S.incoming.receiver) == 0:
    finishDacIncoming(S, R, nowMs)

proc feedDacAck(S: var DacLink, body: openArray[uint8], nowMs: uint32,
    R: var DacLinkStep) {.role: orchestrator.} =
  ## S/body/nowMs/R: link, ACK body bytes, clock, and the step being filled.
  var
    a: DacAckRange = decodeDacAckRange(body)
    i: int = 0
    delta: uint32 = 0'u32
  S.peerCommits = a.commitCount
  if not S.outgoing.active:
    R.kind = dlkIgnored
    return
  ## A `damVerified` receiver reports its running commit count in every
  ## receipt. A count that has MOVED since this package began means the peer
  ## committed something, and with one package in flight per direction that
  ## something is this one -- so the package is done even if the commit
  ## message never arrived. Every other mode reports a fixed zero, so this
  ## never fires for them and costs one comparison.
  if a.commitCount != S.outgoing.peerCommitsAtStart:
    clearDacOutgoing(S)
    R.kind = dlkCommitReceived
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
    R.messages.add(dacMessage(dmkRepairChunk,
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
  if not observeDacArrival(S.incoming.ack, uint32(c.chunkId), nowMs):
    emitDacAck(S, R.messages, nowMs)
    discard observeDacArrival(S.incoming.ack, uint32(c.chunkId), nowMs)
  ## Deliberately NOT fed to the arrival meter. A repair chunk is a chunk this
  ## side asked for again, so counting it as a late arrival would report loss
  ## twice -- once honestly as lossPpm, and once as reorder depth and jitter
  ## that the path never actually produced. The meter measures the first pass.
  R.kind = dlkRepaired
  if missingChunkCount(S.incoming.receiver) == 0:
    finishDacIncoming(S, R, nowMs)

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
  S.pathMoves = S.pathMoves + 1'u16
  ## The new lane seeds the NEXT receive's ACK cadence, never this one's. An
  ## open batch holds arrivals nobody has reported yet; rebuilding the policy
  ## under it throws those away, so the sender waits out its repair timer and
  ## re-sends parity for chunks that are sitting here already. The next
  ## manifest calls initDacAckPolicy with these defaults anyway.
  if S.incoming.active:
    return
  S.incoming.ack = initDacAckPolicy(S.defaults, not S.policy.shuffleChunks)

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

proc dacSenderGaveUp(S: DacLink, nowMs: uint32): bool {.role: parser.} =
  ## S: link whose outgoing package has run out of things to try.
  ## nowMs: caller's millisecond clock.
  ##
  ## The receiver has always been able to give up: when its repair rounds are
  ## spent and chunks are still missing, it says so and closes the receive.
  ## The SENDER had no such rule. Once its rounds were spent it simply stopped
  ## speaking, and `outgoing.active` stayed true forever:
  ##
  ##   peer stops answering  ──▶  rounds spent  ──▶  nothing more is sent
  ##                                                 nothing clears outgoing
  ##                                                 the link is never idle
  ##                                                 its relay slot is never
  ##                                                   reclaimed
  ##
  ## A server echoing a receipt to a peer that has gone therefore pinned a slot
  ## for the life of the process, and a table of them filled up and stayed
  ## full. So this is the sender's half of the same sentence: every round was
  ## spent, twice the repair wait has passed since the last one, and nobody has
  ## acknowledged anything. The package is lost.
  ##
  ## Twice the wait, not once, because the last round still has to be answered:
  ## the parity has to arrive, be used, and the receipt has to come back. The
  ## wait itself is measured receipt latency, so two of them is comfortably
  ## more than one round trip on whatever path this actually is.
  if not S.outgoing.active:
    return false
  if S.outgoing.rounds < S.limits.maxRepairRounds:
    return false
  result = (nowMs - S.outgoing.waitingMs) >=
    2'u32 * uint32(dacRepairWaitMs(S.outgoing.timer, S.defaults))

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
    F.add(dacMessage(dmkRepairHint,
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
  elif dacSenderGaveUp(S, nowMs):
    ## Rounds spent and still nothing back. Releasing the package is what lets
    ## this link go idle, and going idle is what lets its slot be handed to
    ## somebody else. Nothing is told: the peer never acknowledged anything, so
    ## there is nobody listening to tell.
    discard abandonDacPackage(S)
    result.kind = dlkPackageFailed
    result.err = "DAC package was never acknowledged after every repair round"
  if not dacReceiverRepairDue(S, nowMs):
    return
  S.incoming.lastProgressMs = nowMs
  noteDacAckEvidence(S, true)
  ## The stream has stopped with holes in it. Whatever the batch is holding,
  ## the sender needs it NOW -- it is about to spend a repair round, and the
  ## worst thing it can do is spend it on chunks already sitting here. This is
  ## the moment a shuffled stream earns back the gap-triggered receipt it does
  ## not get: one flush when the silence says the holes are real, instead of
  ## one after every arrival because the shuffle made a hole.
  emitDacAck(S, result.messages, nowMs)
  if repairEveryDacGroup(S) and missingChunkCount(S.incoming.receiver) == 0:
    finishDacIncoming(S, result, nowMs)
    return
  if requestDacRepair(S, result.messages):
    result.kind = dlkRepairRequested
    return
  endDacIncoming(S, result.messages, nowMs)
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
