## ---------------------------------------------------------
## DAC ACK Range <- compact sequence and commit receipt data
## ---------------------------------------------------------

import ../../types
import ../types
import ./body_codec
import bifrostPragmas

const
  dacAckRangeHeaderLen* = 7
  dacAckRangeEntryLen* = 6
  dacAckMaxGapBytes* = int(high(uint8))
  dacAckMaxRanges* = int(high(uint8))
  dacAckRangeAscii* = """
+--------------- Common DAC1 Envelope ----------------+
| Kind = AckRange | Flags = 0                          |
+----------+----------+----------+----------+----------+
| AckBase  | RangeCt  | GapBytes | CommitCt | Body...  |
| u32      | u8       | u8       | u8       | n bytes  |
+----------+----------+----------+----------+----------+

GapBytes = 0 selects run mode, and RangeCt entries follow:

+----------+----------+
| StartSeq | Count    |     6 bytes per contiguous run of arrivals
| u32      | u16      |
+----------+----------+

GapBytes > 0 selects bitmap mode, RangeCt is 0, and GapBytes bytes follow.
Each bit is one sequence starting at AckBase, most significant bit first.
A SET bit is a GAP -- a sequence that did not arrive -- so a clean batch of
256 sequences is 32 zero bytes:

  AckBase = 1000              bit 0 -> seq 1000
  byte 0: 0 0 1 0 0 0 0 0     bit 2 -> seq 1002 is missing
  byte 1: 0 0 0 0 0 0 0 0     seq 1008..1015 all arrived

Run mode is smaller while loss is rare (13 bytes covers 256 clean sequences).
Bitmap mode is flat under scattered loss and wins past roughly five gaps.
The encoder measures both and sends the shorter one.
"""

proc initDacAckRangeEntry*(startSeq: uint32,
    count: uint16): DacAckRangeEntry {.role: configurator.} =
  ## startSeq/count: contiguous received sequence range.
  if count == 0'u16:
    raise newException(ValueError, "DAC ACK range count must be positive")
  result.startSeq = startSeq
  result.count = count

proc initDacAckRange*(ackBase: uint32,
    commitCount: uint8): DacAckRange {.role: configurator.} =
  ## ackBase: sequence base for the ACK frame.
  ## commitCount: committed package count reported alongside the receipt.
  ## The result starts in run mode with no runs recorded yet.
  result.ackBase = ackBase
  result.commitCount = commitCount
  result.ranges = @[]
  result.gapMap = @[]

proc initDacAckGapMap*(ackBase: uint32, commitCount: uint8,
    gapMap: ByteSeq): DacAckRange {.role: configurator.} =
  ## ackBase: first sequence covered by bit 0 of the bitmap.
  ## commitCount: committed package count reported alongside the receipt.
  ## gapMap: one bit per sequence, set where a sequence is missing.
  if gapMap.len == 0 or gapMap.len > dacAckMaxGapBytes:
    raise newException(ValueError,
      "DAC ACK gap bitmap must be 1 to " & $dacAckMaxGapBytes & " bytes")
  result.ackBase = ackBase
  result.commitCount = commitCount
  result.ranges = @[]
  result.gapMap = gapMap

proc addDacAckRange*(S: var DacAckRange, e: DacAckRangeEntry) {.role: dataWriter.} =
  ## S: ACK range state to mutate.
  ## e: range entry to append.
  if S.gapMap.len > 0:
    raise newException(ValueError, "DAC ACK bitmap mode carries no runs")
  S.ranges.add(e)

proc dacAckSpan*(a: DacAckRange): uint32 {.role: parser.} =
  ## a: ACK body whose covered sequence count is returned.
  ## Run mode has no fixed span, so it reports zero.
  result = uint32(a.gapMap.len) * 8'u32

proc dacAckIncludesSeq*(a: DacAckRange, seq: uint32): bool {.role: parser.} =
  ## a: ACK body to inspect.
  ## seq: DAC sequence number being checked.
  ## Returns true when the receiver confirmed this sequence arrived.
  var
    i: int = 0
    offset: uint32 = 0'u32
    startSeq: uint32 = 0'u32
    delta: uint32 = 0'u32
  if a.gapMap.len > 0:
    if seq < a.ackBase:
      return false
    offset = seq - a.ackBase
    if offset >= dacAckSpan(a):
      return false
    return (a.gapMap[int(offset) div 8] and
      (1'u8 shl (7 - (int(offset) mod 8)))) == 0'u8
  if a.ranges.len == 0:
    return seq == a.ackBase
  if seq == a.ackBase:
    return true
  while i < a.ranges.len:
    startSeq = a.ranges[i].startSeq
    delta = seq - startSeq
    if seq >= startSeq and delta < uint32(a.ranges[i].count):
      return true
    i = i + 1

proc dacBitSet*(A: openArray[uint8], i: int): bool {.role: parser.} =
  ## A: bitmap, most significant bit of each byte first.
  ## i: bit index; anything past the bitmap reads as clear.
  if i < 0 or (i div 8) >= A.len:
    return false
  result = (A[i div 8] and (1'u8 shl (7 - (i mod 8)))) != 0'u8

proc dacSetBit*(A: var ByteSeq, i: int) {.role: actor.} =
  ## A: bitmap mutated in place, grown as needed.
  ## i: bit index to set.
  if i < 0:
    return
  if (i div 8) >= A.len:
    A.setLen((i div 8) + 1)
  A[i div 8] = A[i div 8] or (1'u8 shl (7 - (i mod 8)))

proc dacAckRunBytes*(A: openArray[uint8], n: int): int {.role: math.} =
  ## A: arrival bitmap, one set bit per sequence that arrived.
  ## n: number of sequences the batch covers.
  ## Returns the encoded byte length run mode would need, or -1 when the
  ## arrivals break into more runs than the u8 run counter can carry.
  var
    i: int = 0
    runs: int = 0
  while i < n:
    if dacBitSet(A, i) and not dacBitSet(A, i - 1):
      runs = runs + 1
    i = i + 1
  if runs > dacAckMaxRanges:
    return -1
  result = dacAckRangeHeaderLen + (runs * dacAckRangeEntryLen)

proc dacAckGapBytes*(n: int): int {.role: math.} =
  ## n: number of sequences the batch covers.
  ## Returns the encoded byte length bitmap mode would need, or -1 when the
  ## batch covers more sequences than the u8 width field can carry.
  var
    bytes: int = (n + 7) div 8
  if bytes > dacAckMaxGapBytes:
    return -1
  result = dacAckRangeHeaderLen + bytes

proc buildDacAckRuns(S: var DacAckRange, A: openArray[uint8], n: int,
    ackBase: uint32) {.role: truthBuilder.} =
  ## S: ACK body collecting one entry per contiguous run of arrivals.
  ## A: arrival bitmap.
  ## n: number of sequences the batch covers.
  ## ackBase: sequence bit 0 belongs to.
  var
    i: int = 0
    start: int = -1
  while i <= n:
    if i < n and dacBitSet(A, i) and start < 0:
      start = i
    if (i == n or not dacBitSet(A, i)) and start >= 0:
      addDacAckRange(S, initDacAckRangeEntry(ackBase + uint32(start),
        uint16(i - start)))
      start = -1
    i = i + 1

proc invertDacArrivals(A: openArray[uint8], n: int): ByteSeq {.
    role: truthBuilder.} =
  ## A: arrival bitmap, set where a sequence arrived.
  ## n: number of sequences the batch covers.
  ## Returns the gap bitmap the wire carries, set where one did not.
  var
    i: int = 0
  result = newSeq[uint8]((n + 7) div 8)
  while i < n:
    if not dacBitSet(A, i):
      result[i div 8] = result[i div 8] or (1'u8 shl (7 - (i mod 8)))
    i = i + 1

proc buildDacAckRange*(ackBase: uint32, A: openArray[uint8], n: int,
    commitCount: uint8): DacAckRange {.role: truthBuilder.} =
  ## ackBase: sequence bit 0 of the arrival bitmap belongs to.
  ## A: arrival bitmap, one set bit per sequence that arrived.
  ## n: number of sequences the batch covers.
  ## commitCount: committed package count reported alongside the receipt.
  ## Both encodings are measured and the shorter one is built. Neither form
  ## is a request: it states which sequences arrived, nothing more.
  var
    runBytes: int = dacAckRunBytes(A, n)
    gapBytes: int = dacAckGapBytes(n)
  if n <= 0:
    return initDacAckRange(ackBase, commitCount)
  if gapBytes < 0 and runBytes < 0:
    raise newException(ValueError, "DAC ACK batch is too wide to encode")
  if runBytes >= 0 and (gapBytes < 0 or runBytes <= gapBytes):
    result = initDacAckRange(ackBase, commitCount)
    buildDacAckRuns(result, A, n, ackBase)
    return
  result = initDacAckGapMap(ackBase, commitCount, invertDacArrivals(A, n))

proc encodeDacAckRange*(a: DacAckRange): ByteSeq {.role: helper.} =
  ## a: ACK range body to encode.
  var
    i: int = 0
  if a.gapMap.len > 0 and a.ranges.len > 0:
    raise newException(ValueError, "DAC ACK carries runs or a bitmap, not both")
  if a.ranges.len > dacAckMaxRanges:
    raise newException(ValueError, "DAC ACK range count exceeds u8")
  if a.gapMap.len > dacAckMaxGapBytes:
    raise newException(ValueError, "DAC ACK gap bitmap exceeds u8")
  appendDacU32(result, a.ackBase)
  result.add(uint8(a.ranges.len))
  result.add(uint8(a.gapMap.len))
  result.add(a.commitCount)
  if a.gapMap.len > 0:
    result.add(a.gapMap)
    return
  while i < a.ranges.len:
    appendDacU32(result, a.ranges[i].startSeq)
    appendDacU16(result, a.ranges[i].count)
    i = i + 1

proc decodeDacAckRange*(A: openArray[uint8]): DacAckRange {.role: parser.} =
  ## A: ACK range body bytes.
  var
    rangeCount: int = 0
    gapBytes: int = 0
    offset: int = dacAckRangeHeaderLen
    i: int = 0
  if A.len < dacAckRangeHeaderLen:
    raise newException(ValueError, "DAC ACK range body too short")
  rangeCount = int(A[4])
  gapBytes = int(A[5])
  if rangeCount > 0 and gapBytes > 0:
    raise newException(ValueError, "DAC ACK carries runs or a bitmap, not both")
  if gapBytes > 0:
    if A.len != dacAckRangeHeaderLen + gapBytes:
      raise newException(ValueError, "DAC ACK gap bitmap length mismatch")
    return initDacAckGapMap(readDacU32(A, 0), A[6],
      copyDacSpan(A, dacAckRangeHeaderLen, gapBytes))
  if A.len != dacAckRangeHeaderLen + (rangeCount * dacAckRangeEntryLen):
    raise newException(ValueError, "DAC ACK range body length mismatch")
  result = initDacAckRange(readDacU32(A, 0), A[6])
  while i < rangeCount:
    addDacAckRange(result, initDacAckRangeEntry(readDacU32(A, offset),
      readDacU16(A, offset + 4)))
    offset = offset + dacAckRangeEntryLen
    i = i + 1
