## ---------------------------------------------------------------------
## DAC Path Adaptation <- does the adaptive layer adapt in the right
##                        direction, and only on numbers somebody took?
## ---------------------------------------------------------------------
##
## DAC stands for an adaptive connection, and the adapting happens here: a
## receiver measures what it saw, says so once the package is done, and the
## peer moves its own lane one step on the strength of it.
##
##   receiver                                   sender
##   --------                                   ------
##   package completes                          gets the report
##   measures loss, jitter, queue, credit  -->  moves its lane ONE step
##   says so, once                              or stays exactly where it is
##
## Two ways that can go wrong, and both had happened:
##
##   1. a field nobody fills in is read as a measurement. `creditHint` was
##      never set by anything, and `creditHint <= 32` is the FIRST rule, so
##      every report said "the receiver is drowning" and a flawless LAN walked
##      itself down to the recovery lane in four packages.
##
##   2. a field that IS filled in measures the wrong thing. Chunk-id order
##      looks like reordering and is actually the sender's own deliberate
##      shuffling, so a perfect 34-chunk delivery reported depth 31.
##
## Everything below is about staying out of those two ditches.

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/defaults
import ../../src/protocols/dac/level0/ack_range
import ../../src/protocols/dac/level0/path_stats
import ../../src/protocols/dac/level1/ack_policy
import ../../src/protocols/dac/level1/path_meter
import ../../src/protocols/dac/level1/path_policy
import ../../src/protocols/dac/level2/package_transfer
import ../../src/protocols/dac/level3/link

proc rampBytes(n: int): ByteSeq =
  ## n: payload length filled with a deterministic ramp.
  var
    i: int = 0
  result = newSeq[uint8](n)
  while i < n:
    result[i] = uint8((i * 13 + 7) mod 251)
    i = i + 1

proc runPackages(S0: var DacLink, S1: var DacLink, payload: ByteSeq,
    rounds: int, dropEvery: int): int =
  ## S0/S1: sender and receiver, driven against each other over a fake wire.
  ## payload: the bytes sent in every round.
  ## rounds: how many packages to push through.
  ## dropEvery: drop one chunk in this many; 0 drops nothing.
  ## Returns how many packages the receiver assembled in full.
  var
    clock: uint32 = 0'u32
    pkg: uint64 = 1'u64
    n: int = 0
    r: int = 0
    back: seq[DacTaggedMessage] = @[]
    st: DacLinkStep = default(DacLinkStep)
  while r < rounds:
    back = @[]
    for m in beginDacPackage(S0, pkg, payload, clock):
      clock = clock + 7'u32
      n = n + 1
      if dropEvery > 0 and m.kind == dmkPackageChunk and n mod dropEvery == 0:
        continue
      st = feedDacMessage(S1, m.kind, m.body, clock)
      if st.kind == dlkPackageComplete:
        result = result + 1
      for reply in st.messages:
        back.add(reply)
    clock = clock + 2_000'u32
    st = tickDacLink(S1, clock)
    if st.kind == dlkPackageComplete:
      result = result + 1
    for reply in st.messages:
      back.add(reply)
    for m in back:
      clock = clock + 1'u32
      st = feedDacMessage(S0, m.kind, m.body, clock)
      for answer in st.messages:
        clock = clock + 1'u32
        discard feedDacMessage(S1, answer.kind, answer.body, clock)
    pkg = pkg + 1'u64
    r = r + 1

suite "a clean path is left alone":
  # {.testKind: tkRegression, covers: "measureDacPath", pins: "an unfilled creditHint read as receiver starvation".}
  test "five flawless packages move the lane not at all":
    ## HOLDS: two links on dscCleanLan and a wire that loses nothing.
    ## TRIES: five packages, each answered, each reported on.
    ## GETS:  the same lane it started on. Before the fix this walked
    ##        clean -> mobile -> thin -> lossy -> recovery, and the reason it
    ##        gave was "receiver pressure" on a receiver that was idle.
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscCleanLan)
      sender: DacLink = initDacLink(7'u64, 1'u32, d, 11'u64)
      receiver: DacLink = initDacLink(7'u64, 1'u32, d, 22'u64)
      done: int = 0
    done = runPackages(sender, receiver, rampBytes(4_000), 5, 0)
    check done == 5
    check sender.defaults.pathLane == dplCleanPath
    check sender.pathMoves == 0'u16

  # {.testKind: tkUnit, covers: "measureDacPath".}
  test "the report a clean receiver sends carries real numbers":
    ## Every field is either something this side measured or an explicit zero
    ## meaning "not measured". Nothing in between.
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscCleanLan)
      sender: DacLink = initDacLink(7'u64, 1'u32, d, 11'u64)
      receiver: DacLink = initDacLink(7'u64, 1'u32, d, 22'u64)
    discard runPackages(sender, receiver, rampBytes(4_000), 1, 0)
    check receiver.observed.lossPpm == 0'u32
    check receiver.observed.mtuHint == d.chunkBytes
    check receiver.observed.creditHint > 0'u16
    check receiver.observed.queueMs > 0'u16
    ## A receiver that has never sent cannot know a round trip, and says so
    ## by leaving the field alone rather than by copying the other direction's.
    check receiver.observed.rttMs == 0'u16

suite "a path that really is bad gets treated as bad":
  # {.testKind: tkIntegration, covers: "feedDacPathStats".}
  test "losing one chunk in five walks the lane down and then stops":
    ## A lane move is one step per report, so real loss still reaches the
    ## right lane -- it just takes as many packages as there are steps, and
    ## settles there instead of sliding on to the bottom.
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscCleanLan)
      sender: DacLink = initDacLink(7'u64, 1'u32, d, 11'u64)
      receiver: DacLink = initDacLink(7'u64, 1'u32, d, 22'u64)
    discard runPackages(sender, receiver, rampBytes(4_000), 5, 5)
    check receiver.observed.lossPpm > 50_000'u32
    check sender.defaults.pathLane == dplLossyPath
    check sender.pathMoves == 3'u16

  # {.testKind: tkEdgeCase, covers: "targetDacPathFromStats".}
  test "a receiver that really is out of room still says so":
    ## The guard must not swallow a genuine alarm. A credit of 1 is the
    ## smallest a live receive reports, and it still means recovery.
    var
      stats: DacPathStats = initDacPathStats(0'u32, 0'u16, 0'u16, 0'u16,
        1200'u16, 0'u16, 1'u16)
      rec: DacPathRecommendation = recommendDacPathFromStats(dplCleanPath,
        stats)
    check rec.ok
    check rec.reason == dpsrReceiverPressure
    check rec.path == dplMobilePath

suite "a number nobody took is not a number":
  # {.testKind: tkRegression, covers: "targetDacPathFromStats", pins: "zero read as a measurement".}
  test "an empty report asks for nothing":
    ## This is the shape the bug wore: every field zero. The honest answer is
    ## "no opinion", not "emergency".
    var
      empty: DacPathStats = default(DacPathStats)
      rec: DacPathRecommendation = recommendDacPathFromStats(dplCleanPath,
        empty)
    check not rec.ok

  # {.testKind: tkEdgeCase, covers: "targetDacPathFromStats".}
  test "an empty report cannot promote a link either":
    ## The same rule in the other direction: the top lane needs measurements
    ## that were actually taken, so silence must not buy a promotion.
    var
      empty: DacPathStats = default(DacPathStats)
      rec: DacPathRecommendation = recommendDacPathFromStats(dplCleanPath,
        empty)
    check not rec.ok
    ## A report that DID measure everything, and measured it excellent, does
    ## promote -- so the guard is refusing silence, not refusing good news.
    rec = recommendDacPathFromStats(dplCleanPath,
      initDacPathStats(0'u32, 1'u16, 1'u16, 0'u16, 8192'u16, 1'u16, 4096'u16))
    check rec.ok
    check rec.path == dplSuperCleanPath

suite "the sender's own shuffling is not the path's fault":
  # {.testKind: tkRegression, covers: "measureDacPath", pins: "a deliberate chunk shuffle reported as path reordering".}
  test "a flawless 34-chunk delivery reports no reordering":
    ## `dacChunkSendOrder` shuffles a whole package by design, so the ids land
    ## in a random order on a wire that did nothing at all. Reading that as
    ## reordering put a perfect link over the `> 16` threshold on its first
    ## package. The receiver now declines to report a number it cannot know.
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscCleanLan)
      sender: DacLink = initDacLink(7'u64, 1'u32, d, 11'u64)
      receiver: DacLink = initDacLink(7'u64, 1'u32, d, 22'u64)
      payload: ByteSeq = rampBytes(40_000)
    discard runPackages(sender, receiver, payload, 1, 0)
    check receiver.incoming.receiver.manifest.dataCount > 16'u16
    check receiver.observed.reorderDepth == 0'u16
    check not dacShouldEnterLossyPath(receiver.observed)
    check sender.defaults.pathLane == dplCleanPath

suite "what the arrival meter itself measures":
  # {.testKind: tkUnit, covers: "observeDacChunkArrival".}
  test "a perfectly steady stream has a gap but no jitter":
    ## Jitter is how much the gap CHANGES. A chunk every 20ms forever is the
    ## calmest path there is, and must not be reported as turbulent.
    var
      m: DacArrivalMeter = initDacArrivalMeter(0'u32)
      t: uint32 = 0'u32
      i: int = 0
    while i < 20:
      t = t + 20'u32
      observeDacChunkArrival(m, t)
      i = i + 1
    check m.samples == 20'u16
    check m.lastGapMs == 20'u16
    check m.jitterMs == 0'u16

  # {.testKind: tkUnit, covers: "observeDacChunkArrival".}
  test "a stream whose spacing keeps changing does report jitter":
    var
      m: DacArrivalMeter = initDacArrivalMeter(0'u32)
      t: uint32 = 0'u32
      i: int = 0
    while i < 20:
      t = t + (if (i and 1) == 0: 5'u32 else: 200'u32)
      observeDacChunkArrival(m, t)
      i = i + 1
    check m.jitterMs > 40'u16

  # {.testKind: tkUnit, covers: "dacQueueMs".}
  test "queue time is measured from the manifest, not from the last chunk":
    ## The pressure a receiver is under is how long it has been HOLDING an
    ## unfinished package, so the clock starts when the receive opened.
    var
      m: DacArrivalMeter = initDacArrivalMeter(1_000'u32)
    observeDacChunkArrival(m, 1_500'u32)
    check dacQueueMs(m, 1_800'u32) == 800'u16

suite "the credit a receiver reports":
  # {.testKind: tkUnit, covers: "dacReceiveCreditChunks".}
  test "a roomy receiver reports plenty and a tight one reports little":
    var
      wide: DacPackageLimits = defaultDacPackageLimits()
      tight: DacPackageLimits = defaultDacPackageLimits()
      plan: DacPackagePlan = default(DacPackagePlan)
      roomy: DacPackageReceiver = default(DacPackageReceiver)
      cramped: DacPackageReceiver = default(DacPackageReceiver)
    plan = planDacPackage(9'u64, rampBytes(12_000),
      dacDefaultsFor(dscCleanLan), dtcUserData, wide)
    tight.maxChunks = plan.manifest.dataCount + 8'u16
    roomy = initDacPackageReceiver(plan.manifest, wide)
    cramped = initDacPackageReceiver(plan.manifest, tight)
    check dacReceiveCreditChunks(roomy) > 32'u16
    check dacReceiveCreditChunks(cramped) == 8'u16

  # {.testKind: tkEdgeCase, covers: "dacReceiveCreditChunks".}
  test "a receiver with nothing left still reports 1, never 0":
    ## Zero is reserved for "not measured". A receiver that is genuinely full
    ## reports the smallest real number instead, which is still low enough to
    ## trip the recovery rule.
    var
      exact: DacPackageLimits = defaultDacPackageLimits()
      plan: DacPackagePlan = planDacPackage(9'u64, rampBytes(12_000),
        dacDefaultsFor(dscCleanLan), dtcUserData, exact)
      full: DacPackageReceiver = default(DacPackageReceiver)
    exact.maxChunks = plan.manifest.dataCount
    full = initDacPackageReceiver(plan.manifest, exact)
    check dacReceiveCreditChunks(full) == 1'u16
    check recommendDacPathFromStats(dplCleanPath,
      initDacPathStats(0'u32, 0'u16, 0'u16, 0'u16, 1200'u16, 0'u16,
      dacReceiveCreditChunks(full))).reason == dpsrReceiverPressure

suite "a lane move does not disturb a receive in progress":
  # {.testKind: tkRegression, covers: "feedDacPathStats", pins: "a lane move rebuilding the ACK batch under an open receive".}
  test "the open batch survives the peer's report":
    ## The new lane seeds the NEXT receive's cadence. Rebuilding the ACK
    ## policy under an open batch throws away where the batch is and what it
    ## has counted, so arrivals already recorded are never reported and the
    ## sender re-sends parity for chunks that are sitting here.
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscCleanLan)
      sender: DacLink = initDacLink(7'u64, 1'u32, d, 11'u64)
      receiver: DacLink = initDacLink(7'u64, 1'u32, d, 22'u64)
      payload: ByteSeq = rampBytes(40_000)
      msgs: seq[DacTaggedMessage] = @[]
      i: int = 0
      window: uint16 = 0'u16
      base: uint32 = 0'u32
    msgs = beginDacPackage(sender, 1'u64, payload, 0'u32)
    while i < 6:
      discard feedDacMessage(receiver, msgs[i].kind, msgs[i].body, uint32(i))
      i = i + 1
    check receiver.incoming.ack.started
    window = receiver.incoming.ack.windowChunks
    base = receiver.incoming.ack.base
    check window == receiver.incoming.receiver.manifest.dataCount
    ## A report bad enough to move the lane, arriving mid-receive.
    discard feedDacMessage(receiver, dmkPathStats,
      encodeDacPathStats(initDacPathStats(90_000'u32, 400'u16, 200'u16,
      0'u16, 1200'u16, 50'u16, 4_000'u16)), 100'u32)
    check receiver.pathMoves == 1'u16
    check receiver.incoming.ack.started
    check receiver.incoming.ack.base == base
    check receiver.incoming.ack.windowChunks == window

suite "the receipt tells the sender what really arrived":
  # {.testKind: tkRegression, covers: "closeDacAckBatch", pins: "a batch sliding past sequences that never arrived".}
  test "every delivered chunk is acknowledged, on a wire that lost nothing":
    ## The sender picks its chunk order at random, so ids arrive scattered.
    ## The batch used to slide past the highest id it had seen, which put
    ## every lower id permanently below the base where arrivals are refused.
    ## On a flawless 34-chunk delivery the sender was told 14 had arrived and
    ## re-sent parity for the other 20, which were already in hand.
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscCleanLan)
      sender: DacLink = initDacLink(7'u64, 1'u32, d, 11'u64)
      receiver: DacLink = initDacLink(7'u64, 1'u32, d, 22'u64)
      payload: ByteSeq = rampBytes(40_000)
      msgs: seq[DacTaggedMessage] = @[]
      chunks: int = 0
      delivered: int = 0
      acked: int = 0
      receipts: int = 0
      i: int = 0
      st: DacLinkStep = default(DacLinkStep)
    msgs = beginDacPackage(sender, 1'u64, payload, 0'u32)
    for m in msgs:
      if m.kind == dmkPackageChunk:
        chunks = chunks + 1
    ## Everything except the parity and the very last chunk, so the package
    ## stays open and the sender's view of it survives to be inspected.
    while i < msgs.len:
      if msgs[i].kind == dmkParityShard:
        i = i + 1
        continue
      if msgs[i].kind == dmkPackageChunk:
        delivered = delivered + 1
        if delivered == chunks:
          i = i + 1
          continue
      st = feedDacMessage(receiver, msgs[i].kind, msgs[i].body, uint32(i))
      for reply in st.messages:
        if reply.kind == dmkAckRange:
          receipts = receipts + 1
        discard feedDacMessage(sender, reply.kind, reply.body, uint32(i))
      i = i + 1
    ## One stall-driven flush closes whatever the batch still holds.
    st = tickDacLink(receiver, 5_000'u32)
    for reply in st.messages:
      if reply.kind == dmkAckRange:
        receipts = receipts + 1
      discard feedDacMessage(sender, reply.kind, reply.body, 5_000'u32)
    for a in sender.outgoing.acked:
      if a:
        acked = acked + 1
    check delivered == chunks
    check acked == chunks - 1
    ## And it took a handful of receipts, not one per arrival.
    check receipts <= 4

  # {.testKind: tkRegression, covers: "closeDacAckBatch", pins: "the ACK levers collapsing on a link that lost nothing".}
  test "a flawless delivery leaves the ACK levers at the profile":
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscCleanLan)
      sender: DacLink = initDacLink(7'u64, 1'u32, d, 11'u64)
      receiver: DacLink = initDacLink(7'u64, 1'u32, d, 22'u64)
    discard runPackages(sender, receiver, rampBytes(40_000), 1, 0)
    check receiver.incoming.ack.batchChunks == d.ackBatchChunks
    check receiver.incoming.ack.deadlineMs == d.ackMaxDelayMs

  # {.testKind: tkUnit, covers: "slideDacAckBatch".}
  test "a hole keeps the window open over it":
    ## The base may only advance over sequences that actually arrived. Anything
    ## still missing has to stay inside the window, or it can never be reported.
    var
      S: DacAckPolicy = initDacAckPolicy(dacDefaultsFor(dscCleanLan))
      a: DacAckRange = default(DacAckRange)
    openDacAckBatchAt(S, 0'u32, 40'u16, 0'u32)
    check observeDacArrival(S, 0'u32, 0'u32)
    check observeDacArrival(S, 1'u32, 0'u32)
    check observeDacArrival(S, 5'u32, 0'u32)
    a = closeDacAckBatch(S, 0'u8, 0'u32)
    check dacAckIncludesSeq(a, 0'u32)
    check dacAckIncludesSeq(a, 5'u32)
    check not dacAckIncludesSeq(a, 2'u32)
    ## 0 and 1 are settled, so the base moves two. 2, 3 and 4 are still open
    ## business and must still be accepted when they turn up.
    check S.base == 2'u32
    check observeDacArrival(S, 2'u32, 1'u32)
    check observeDacArrival(S, 3'u32, 1'u32)
    check observeDacArrival(S, 4'u32, 1'u32)
    a = closeDacAckBatch(S, 0'u8, 1'u32)
    check dacAckIncludesSeq(a, 2'u32)
    check dacAckIncludesSeq(a, 4'u32)
    check S.base == 6'u32
