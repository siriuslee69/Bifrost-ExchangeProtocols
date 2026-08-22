## ---------------------------------------------------------------------
## DAC ACK Tests <- receipt encoding and self-inferred batch pacing
## ---------------------------------------------------------------------

import unittest

import ../src/protocols/types
import ../src/protocols/dac/types
import ../src/protocols/dac/level0/defaults
import ../src/protocols/dac/level0/ack_range
import ../src/protocols/dac/level1/ack_policy

proc arrivalBits(A: openArray[bool]): ByteSeq =
  ## A: arrival flag per sequence, converted into the bitmap the wire uses.
  var
    i: int = 0
  result = newSeq[uint8]((A.len + 7) div 8)
  while i < A.len:
    if A[i]:
      dacSetBit(result, i)
    i = i + 1

proc cleanRun(n: int): seq[bool] =
  ## n: number of sequences that all arrived.
  result = newSeq[bool](n)
  var
    i: int = 0
  while i < n:
    result[i] = true
    i = i + 1

proc scattered(n, every: int): seq[bool] =
  ## n: number of sequences covered.
  ## every: drop one sequence out of every `every`.
  result = cleanRun(n)
  var
    i: int = 0
  while i < n:
    if i mod every == 0:
      result[i] = false
    i = i + 1

proc roundTrip(a: DacAckRange): DacAckRange =
  ## a: receipt encoded and parsed back to prove the wire shape holds.
  result = decodeDacAckRange(encodeDacAckRange(a))

suite "DAC ACK encoding":
  test "a clean batch stays in run mode and is tiny":
    var
      A: seq[bool] = cleanRun(256)
      a: DacAckRange = buildDacAckRange(1000'u32, arrivalBits(A), A.len, 3'u8)
    check a.gapMap.len == 0
    check a.ranges.len == 1
    check a.ranges[0].startSeq == 1000'u32
    check a.ranges[0].count == 256'u16
    check encodeDacAckRange(a).len == dacAckRangeHeaderLen + dacAckRangeEntryLen
    check roundTrip(a) == a

  test "scattered loss flips the encoder to the bitmap":
    var
      A: seq[bool] = scattered(256, 8)
      a: DacAckRange = buildDacAckRange(1000'u32, arrivalBits(A), A.len, 0'u8)
    check a.ranges.len == 0
    check a.gapMap.len == 32
    check encodeDacAckRange(a).len == dacAckRangeHeaderLen + 32
    check roundTrip(a) == a

  test "the encoder always picks the shorter of the two":
    var
      n: int = 0
      A: seq[bool] = @[]
      a: DacAckRange
      runBytes: int = 0
      gapBytes: int = 0
    while n <= 200:
      A = scattered(n, 5)
      a = buildDacAckRange(50'u32, arrivalBits(A), n, 0'u8)
      runBytes = dacAckRunBytes(arrivalBits(A), n)
      gapBytes = dacAckGapBytes(n)
      if n > 0:
        check encodeDacAckRange(a).len == min(runBytes, gapBytes)
      check roundTrip(a) == a
      n = n + 1

  test "both shapes answer the same question about every sequence":
    var
      A: seq[bool] = scattered(64, 3)
      bits: ByteSeq = arrivalBits(A)
      runs: DacAckRange = initDacAckRange(500'u32, 0'u8)
      bitmap: DacAckRange = buildDacAckRange(500'u32, bits, 64, 0'u8)
      i: int = 0
    runs = buildDacAckRange(500'u32, bits, 64, 0'u8)
    check bitmap.gapMap.len > 0
    while i < 64:
      check dacAckIncludesSeq(bitmap, 500'u32 + uint32(i)) == A[i]
      i = i + 1
    check not dacAckIncludesSeq(bitmap, 499'u32)
    check not dacAckIncludesSeq(bitmap, 500'u32 + 64'u32)
    check runs == bitmap

  test "malformed receipts are refused":
    var
      A: seq[bool] = scattered(64, 3)
      body: ByteSeq = encodeDacAckRange(buildDacAckRange(1'u32,
        arrivalBits(A), 64, 0'u8))
    expect ValueError:
      discard decodeDacAckRange(body[0 ..< 3])
    body[4] = 4'u8
    expect ValueError:
      discard decodeDacAckRange(body)
    body[4] = 0'u8
    body[5] = 99'u8
    expect ValueError:
      discard decodeDacAckRange(body)

  test "a receipt cannot claim both shapes at once":
    var
      a: DacAckRange = initDacAckGapMap(1'u32, 0'u8, @[byte 0xFF])
    a.ranges.add(initDacAckRangeEntry(1'u32, 1'u16))
    expect ValueError:
      discard encodeDacAckRange(a)

suite "DAC ACK pacing":
  test "a full batch closes on count alone":
    var
      S: DacAckPolicy = initDacAckPolicy(cleanLanDacDefaults())
      i: int = 0
      a: DacAckRange
    check S.batchChunks == 64'u16
    while i < 63:
      check observeDacArrival(S, uint32(i), 0'u32)
      i = i + 1
    check not dacAckDue(S, 0'u32)
    check observeDacArrival(S, 63'u32, 0'u32)
    check dacAckDue(S, 0'u32)
    a = closeDacAckBatch(S, 0'u8, 0'u32)
    check a.ranges.len == 1
    check a.ranges[0].count == 64'u16
    check S.pending == 0'u16
    check S.base == 64'u32

  test "a trickle closes on the deadline, not the count":
    var
      S: DacAckPolicy = initDacAckPolicy(batterySaverDacDefaults())
    check S.deadlineMs == 2500'u16
    check observeDacArrival(S, 0'u32, 1_000'u32)
    check not dacAckDue(S, 3_000'u32)
    check dacAckDue(S, 3_500'u32)

  test "a gap closes the batch immediately":
    var
      S: DacAckPolicy = initDacAckPolicy(cleanLanDacDefaults())
      a: DacAckRange
    check observeDacArrival(S, 10'u32, 0'u32)
    check observeDacArrival(S, 11'u32, 0'u32)
    check not dacAckDue(S, 0'u32)
    check observeDacArrival(S, 13'u32, 0'u32)
    check dacAckGapsPending(S) == 1'u16
    check dacAckDue(S, 0'u32)
    a = closeDacAckBatch(S, 0'u8, 0'u32)
    check dacAckIncludesSeq(a, 11'u32)
    check not dacAckIncludesSeq(a, 12'u32)
    check dacAckIncludesSeq(a, 13'u32)

  test "loss halves the levers and a clean streak walks them back":
    var
      S: DacAckPolicy = initDacAckPolicy(cleanLanDacDefaults())
      i: int = 0
    adaptDacAckPolicy(S, 3'u16)
    check S.batchChunks == 32'u16
    check S.deadlineMs == 50'u16
    adaptDacAckPolicy(S, 1'u16)
    check S.batchChunks == 16'u16
    check S.deadlineMs == 25'u16
    while i < 40:
      adaptDacAckPolicy(S, 0'u16)
      i = i + 1
    check S.batchChunks == S.ceilingChunks
    check S.deadlineMs == S.ceilingMs

  test "the levers never fall below the floor or climb past the profile":
    var
      S: DacAckPolicy = initDacAckPolicy(cleanLanDacDefaults())
      i: int = 0
    while i < 40:
      adaptDacAckPolicy(S, 1'u16)
      i = i + 1
    check S.batchChunks == dacAckMinBatchChunks
    check S.deadlineMs == dacAckMinDeadlineMs
    i = 0
    while i < 200:
      adaptDacAckPolicy(S, 0'u16)
      i = i + 1
    check S.batchChunks == S.ceilingChunks
    check S.deadlineMs == S.ceilingMs

  test "a sequence outside the open window is refused, not mis-filed":
    var
      S: DacAckPolicy = initDacAckPolicy(cleanLanDacDefaults())
    check observeDacArrival(S, 100'u32, 0'u32)
    check not observeDacArrival(S, 99'u32, 0'u32)
    check not observeDacArrival(S, 100'u32 + 5000'u32, 0'u32)
    check S.pending == 1'u16

  test "a duplicate arrival is counted once":
    var
      S: DacAckPolicy = initDacAckPolicy(cleanLanDacDefaults())
    check observeDacArrival(S, 7'u32, 0'u32)
    check observeDacArrival(S, 7'u32, 0'u32)
    check S.pending == 1'u16
    check S.span == 1'u16

  test "closing an empty batch is refused":
    var
      S: DacAckPolicy = initDacAckPolicy(cleanLanDacDefaults())
    expect ValueError:
      discard closeDacAckBatch(S, 0'u8, 0'u32)

  test "a gap straddling two batches is still reported":
    var
      S: DacAckPolicy = initDacAckPolicy(cleanLanDacDefaults())
      i: int = 0
      a: DacAckRange
    while i < 64:
      check observeDacArrival(S, uint32(i), 0'u32)
      i = i + 1
    a = closeDacAckBatch(S, 0'u8, 0'u32)
    check S.base == 64'u32
    check observeDacArrival(S, 65'u32, 0'u32)
    check dacAckGapsPending(S) == 1'u16
    a = closeDacAckBatch(S, 0'u8, 0'u32)
    check not dacAckIncludesSeq(a, 64'u32)
    check dacAckIncludesSeq(a, 65'u32)

suite "DAC repair timing":
  test "with no observations the profile floor governs":
    var
      S: DacRepairTimer = initDacRepairTimer()
      d: DacScenarioDefaults = cleanLanDacDefaults()
    check dacRepairWaitMs(S, d) == d.repairWaitMs

  test "a slow batching receiver pushes the repair wait above the floor":
    var
      S: DacRepairTimer = initDacRepairTimer()
      d: DacScenarioDefaults = cleanLanDacDefaults()
      i: int = 0
    while i < 20:
      observeDacAckLatency(S, 400'u16)
      i = i + 1
    check S.peakMs >= 400'u16
    check dacRepairWaitMs(S, d) >= 600'u16
    check dacRepairWaitMs(S, d) > d.repairWaitMs

  test "one slow receipt raises the peak and it decays back afterwards":
    var
      S: DacRepairTimer = initDacRepairTimer()
      spike: uint16 = 0'u16
      i: int = 0
    observeDacAckLatency(S, 20'u16)
    observeDacAckLatency(S, 900'u16)
    spike = S.peakMs
    check spike == 900'u16
    while i < 60:
      observeDacAckLatency(S, 20'u16)
      i = i + 1
    check S.peakMs < spike
    check S.peakMs >= S.delayMs

  test "a fast receiver never pulls the wait below the profile floor":
    var
      S: DacRepairTimer = initDacRepairTimer()
      d: DacScenarioDefaults = cleanLanDacDefaults()
      i: int = 0
    while i < 20:
      observeDacAckLatency(S, 1'u16)
      i = i + 1
    check dacRepairWaitMs(S, d) == d.repairWaitMs
