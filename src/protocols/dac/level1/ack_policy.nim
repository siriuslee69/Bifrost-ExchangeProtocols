## -------------------------------------------------------------------------
## DAC ACK Policy <- batch pacing and repair timing, inferred from traffic
## -------------------------------------------------------------------------

import ../build

when not dacAdaptiveBuilt:
  {.error: "This module is part of the DAC adaptive layer, which -d:bifrostDac=off removed from this build.".}

import ../../types
import ../types
import ../level0/ack_range
import runePragmas

const
  dacAckMinBatchChunks* = 1'u16
  dacAckMinDeadlineMs* = 5'u16
  dacAckCleanRunsToRelax* = 4'u8
  dacAckPolicyAscii* = """
Nobody asks for anything here. The receiver watches what arrives and picks
its own cadence; the sender watches how long its receipts take and picks
its own repair timer. Two loops, no negotiation, nothing on the wire.

  receiver                                  sender
  --------                                  ------
  sees frames arrive                        sees ACKs come back
  sees gaps in the sequence                 measures send -> ACK delay
        |                                         |
        v                                         v
  batch size + deadline                     repair wait
  (shrink on loss, relax when clean)        (peak delay x 1.5, floored)

A batch closes on whichever comes first:

  +--------------------------------------------------+
  |  enough frames  |  deadline expires  |  a gap     |
  |  (bulk transfer)|  (idle sensor)     |  (loss)    |
  +--------------------------------------------------+

A gap closes the batch at once. Waiting to report loss only makes the
sender wait too, and every un-acknowledged frame is memory it cannot free.
"""

type
  ## DacAckPolicy: receiver-side ACK pacing state for one connection.
  ## Roughly forty bytes plus one bit per pending sequence, so a thousand
  ## connections cost tens of kilobytes rather than megabytes.
  ## base: sequence that bit 0 of `arrivals` belongs to.
  ## arrivals: one set bit per sequence that arrived in the open batch.
  ## pending: sequences observed since the last ACK.
  ## span: sequences the open batch covers, gaps included.
  ## openedMs: clock reading when the batch opened.
  ## batchChunks/deadlineMs: the two levers, moved by observation.
  ## ceilingChunks/ceilingMs: profile starting values, never exceeded.
  ## cleanRuns: consecutive loss-free batches, used to relax slowly.
  ## started: set once the first frame has been seen, so a closed batch keeps
  ## its advanced base instead of silently re-basing onto the next arrival.
  ## windowChunks: how many identifiers the open batch may span at once. Zero
  ## lets the batch ceiling decide, which is all a policy watching an endless
  ## sequence can do. A caller that knows the whole range -- a DAC package
  ## knows its chunk count from the manifest -- should say so, or identifiers
  ## past the window are refused and never make it into any receipt.
  ## holesMeanLoss: whether a hole in the open batch is evidence of anything.
  ## True for a stream that arrives in the order it was sent -- the ordinary
  ## case, and what everything above assumes. False where the SENDER reorders
  ## on purpose, because then a hole means "not sent yet" and fills itself in
  ## a moment later. A DAC sender shuffles a package's chunks so an observer
  ## cannot read the shape of a file out of the order its pieces cross the
  ## wire, which makes a flawless delivery look like relentless loss:
  ##
  ##   34 chunks, nothing dropped, every one delivered
  ##     -> 6 ACKs instead of 1
  ##     -> batch 64 -> 2, deadline 100ms -> 5ms
  ##     -> the sender told only 14 of them arrived
  ##     -> parity re-sent for 20 chunks already sitting at the receiver
  ##
  ## A policy that says false owes its levers a verdict from somewhere that
  ## does know -- the receiver's own stall timer, and what a finished package
  ## had to repair.
  DacAckPolicy* {.role: truthState.} = object
    base*: uint32
    arrivals*: ByteSeq
    pending*: uint16
    span*: uint16
    openedMs*: uint32
    batchChunks*: uint16
    deadlineMs*: uint16
    ceilingChunks*: uint16
    ceilingMs*: uint16
    cleanRuns*: uint8
    started*: bool
    holesMeanLoss*: bool
    windowChunks*: uint16

  ## DacRepairTimer: sender-side repair timing state for one connection.
  ## The sender never reads a receiver-advertised hold time. It measures how
  ## long its own receipts actually take, which is the same number without a
  ## wire field and without trusting the peer to be honest about it.
  ## delayMs: smoothed send-to-ACK latency.
  ## peakMs: decaying worst case, what the timeout is built on.
  ## samples: observations folded in so far, capped.
  DacRepairTimer* {.role: truthState.} = object
    delayMs*: uint16
    peakMs*: uint16
    samples*: uint16

proc initDacAckPolicy*(d: DacScenarioDefaults,
    holesMeanLoss: bool = true): DacAckPolicy {.role: configurator.} =
  ## d: scenario defaults whose ACK batch and deadline seed the levers and
  ## bound how far they may relax back.
  ## holesMeanLoss: false when the sender reorders on purpose. See the type.
  if d.ackBatchChunks == 0'u16:
    raise newException(ValueError, "DAC ACK batch size must be positive")
  result.batchChunks = d.ackBatchChunks
  result.deadlineMs = d.ackMaxDelayMs
  result.ceilingChunks = d.ackBatchChunks
  result.ceilingMs = d.ackMaxDelayMs
  result.holesMeanLoss = holesMeanLoss
  result.arrivals = @[]

proc dacAckWindowLimit(S: DacAckPolicy): int {.role: math.} =
  ## S: policy whose widest open batch is returned.
  ## A caller that declared the stream's whole range gets that range; one that
  ## did not gets twice the batch ceiling, which is the only guess available.
  ## Both are clamped to the widest receipt the wire format can carry.
  if S.windowChunks > 0'u16:
    return min(int(S.windowChunks), dacAckMaxGapBytes * 8)
  result = min(int(S.ceilingChunks) * 2, dacAckMaxGapBytes * 8)

proc resetDacAckBatch*(S: var DacAckPolicy, base: uint32,
    nowMs: uint32) {.role: actor.} =
  ## S: policy whose pending batch is cleared.
  ## base: sequence the next batch starts at.
  ## nowMs: caller's millisecond clock.
  S.base = base
  S.arrivals = @[]
  S.pending = 0'u16
  S.span = 0'u16
  S.openedMs = nowMs

proc openDacAckBatchAt*(S: var DacAckPolicy, base: uint32, window: uint16,
    nowMs: uint32) {.role: actor.} =
  ## S: policy whose first batch is placed deliberately rather than guessed.
  ## base: the lowest identifier this stream will ever use.
  ## window: how many identifiers the stream spans in total, so the batch can
  ## hold all of them at once instead of chasing them. Wider than the widest
  ## encodable receipt is clamped down to that.
  ## nowMs: caller's millisecond clock.
  ##
  ## Left alone, the first arrival decides where the batch starts, which is
  ## the only thing a policy watching an open-ended sequence CAN do. A caller
  ## that knows the range up front -- a DAC package knows its chunk count from
  ## the manifest -- should say so instead, because otherwise every identifier
  ## below that first arrival falls outside the window and is refused. With a
  ## sender that shuffles its chunks on purpose, "below the first arrival" is
  ## most of the package.
  resetDacAckBatch(S, base, nowMs)
  S.windowChunks = window
  S.started = true

proc dacAckGapsPending*(S: DacAckPolicy): uint16 {.role: parser.} =
  ## S: policy whose observed gap count in the open batch is returned.
  result = S.span - S.pending

proc observeDacArrival*(S: var DacAckPolicy, seq: uint32,
    nowMs: uint32): bool {.role: actor.} =
  ## S: policy updated from one arrival.
  ## seq: DAC sequence number that arrived.
  ## nowMs: caller's millisecond clock.
  ## Returns false when the sequence falls outside the open batch, which the
  ## caller answers by closing the batch first and offering it again.
  var
    offset: int = 0
  if not S.started:
    resetDacAckBatch(S, seq, nowMs)
    S.started = true
  if seq < S.base:
    return false
  offset = int(seq - S.base)
  if offset >= dacAckWindowLimit(S):
    return false
  if dacBitSet(S.arrivals, offset):
    return true
  dacSetBit(S.arrivals, offset)
  S.pending = S.pending + 1'u16
  if offset >= int(S.span):
    S.span = uint16(offset + 1)
  result = true

proc dacAckDue*(S: DacAckPolicy, nowMs: uint32): bool {.role: parser.} =
  ## S: policy holding the open batch.
  ## nowMs: caller's millisecond clock.
  ## A gap ends the batch at once; otherwise whichever bound trips first does.
  ##
  ## Where the sender reorders on purpose there is a hole after almost every
  ## arrival -- the shuffle guarantees it -- so closing on holes turns one
  ## receipt for a 40-chunk package into twenty-seven. Such a receiver waits
  ## for the count or the deadline, and its loop flushes the batch on purpose
  ## the moment the stream stalls, which is when the sender needs the truth.
  if S.pending == 0'u16:
    return false
  if S.holesMeanLoss and dacAckGapsPending(S) > 0'u16:
    return true
  if S.pending >= S.batchChunks:
    return true
  result = S.deadlineMs > 0'u16 and
    (nowMs - S.openedMs) >= uint32(S.deadlineMs)

proc halveDacAckLevers(S: var DacAckPolicy) {.role: actor.} =
  ## S: policy whose batch size and deadline are cut after observed loss.
  S.cleanRuns = 0'u8
  S.batchChunks = max(dacAckMinBatchChunks, S.batchChunks div 2'u16)
  if S.deadlineMs > 0'u16:
    S.deadlineMs = max(dacAckMinDeadlineMs, S.deadlineMs div 2'u16)

proc relaxDacAckLevers(S: var DacAckPolicy) {.role: actor.} =
  ## S: policy whose levers creep back toward the profile after clean batches.
  ## Loss halves in one step; recovery adds a quarter at a time, so a single
  ## bad patch does not make the cadence flap.
  if S.cleanRuns < dacAckCleanRunsToRelax:
    S.cleanRuns = S.cleanRuns + 1'u8
    return
  S.cleanRuns = 0'u8
  S.batchChunks = uint16(min(uint32(S.ceilingChunks),
    uint32(S.batchChunks) + (uint32(S.batchChunks) div 4'u32) + 1'u32))
  if S.ceilingMs > 0'u16:
    S.deadlineMs = uint16(min(uint32(S.ceilingMs),
      uint32(S.deadlineMs) + (uint32(S.deadlineMs) div 4'u32) + 1'u32))

proc adaptDacAckPolicy*(S: var DacAckPolicy, gaps: uint16) {.
    role: actor.} =
  ## S: policy whose levers move from the batch just closed.
  ## gaps: sequences the closed batch was missing.
  if gaps > 0'u16:
    halveDacAckLevers(S)
    return
  relaxDacAckLevers(S)

proc arrivedDacPrefix(S: DacAckPolicy): int {.role: math.} =
  ## S: policy whose settled run is measured.
  ## How many sequences from the base have actually arrived, with no hole in
  ## them. Everything in that run is finished business; the first hole is not.
  while result < int(S.span) and dacBitSet(S.arrivals, result):
    result = result + 1

proc slideDacAckBatch(S: var DacAckPolicy, nowMs: uint32) {.role: actor.} =
  ## S: policy whose window moves past the run that is settled, and no further.
  ##
  ## The base advances over arrivals ONLY, never over a hole:
  ##
  ##   base                                    span
  ##    |  0  1  2  3  4  5  6  7  8            |
  ##       X  X  X  .  X  X  .  X  X       X = arrived,  . = still missing
  ##       \_____/
  ##        settled -> base moves 3, and 4,5,7,8 stay in the window
  ##
  ## Sliding the whole span instead -- which is what this used to do -- puts
  ## sequence 3 and 6 permanently below the base, where `observeDacArrival`
  ## refuses them. They then never appear in any receipt, whatever happens
  ## next, and the sender spends repair rounds on chunks already delivered.
  var
    keep: int = arrivedDacPrefix(S)
    rest: ByteSeq = @[]
    i: int = 0
    held: uint16 = 0'u16
  i = keep
  while i < int(S.span):
    if dacBitSet(S.arrivals, i):
      dacSetBit(rest, i - keep)
      held = held + 1'u16
    i = i + 1
  S.base = S.base + uint32(keep)
  S.span = S.span - uint16(keep)
  S.pending = held
  S.arrivals = rest
  S.openedMs = nowMs

proc closeDacAckBatch*(S: var DacAckPolicy, commitCount: uint8,
    nowMs: uint32): DacAckRange {.role: orchestrator.} =
  ## S: policy whose open batch becomes one wire receipt and then slides on.
  ## commitCount: committed package count reported alongside the receipt.
  ## nowMs: caller's millisecond clock.
  ## The levers move from the holes in this batch only where holes mean loss;
  ## see `holesMeanLoss` on the type for who gets to say.
  var
    gaps: uint16 = dacAckGapsPending(S)
  if S.pending == 0'u16:
    raise newException(ValueError, "DAC ACK batch has nothing to report")
  result = buildDacAckRange(S.base, S.arrivals, int(S.span), commitCount)
  if S.holesMeanLoss:
    adaptDacAckPolicy(S, gaps)
  slideDacAckBatch(S, nowMs)

proc initDacRepairTimer*(): DacRepairTimer {.role: configurator.} =
  ## Start with no observations; the profile floor governs until one lands.
  result.delayMs = 0'u16
  result.peakMs = 0'u16
  result.samples = 0'u16

proc observeDacAckLatency*(S: var DacRepairTimer,
    ms: uint16) {.role: actor.} =
  ## S: timer state updated from one measured send-to-ACK delay.
  ## ms: milliseconds between sending a frame and seeing it acknowledged.
  if S.samples < high(uint16):
    S.samples = S.samples + 1'u16
  if S.samples == 1'u16:
    S.delayMs = ms
    S.peakMs = ms
    return
  S.delayMs = uint16((uint32(S.delayMs) * 3'u32 + uint32(ms)) div 4'u32)
  if ms > S.peakMs:
    S.peakMs = ms
    return
  S.peakMs = max(S.delayMs, uint16(uint32(S.peakMs) * 15'u32 div 16'u32))

proc dacRepairWaitMs*(S: DacRepairTimer,
    d: DacScenarioDefaults): uint16 {.role: math.} =
  ## S: timer holding the measured ACK latency.
  ## d: scenario defaults whose repair wait is the floor.
  ## The sender must never call loss on a frame the receiver is merely still
  ## batching, so the wait sits above the worst receipt it has actually seen.
  var
    measured: uint32 = uint32(S.peakMs) + (uint32(S.peakMs) div 2'u32)
  if S.samples == 0'u16:
    return d.repairWaitMs
  if measured > uint32(high(uint16)):
    measured = uint32(high(uint16))
  result = max(d.repairWaitMs, uint16(measured))
