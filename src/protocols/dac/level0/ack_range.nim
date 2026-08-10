## ---------------------------------------------------------
## DAC ACK Range <- compact sequence and commit receipt data
## ---------------------------------------------------------

import ../../types
import ../types
import ./body_codec
import ../../../analysis_pragmas

const
  dacAckRangeHeaderLen* = 7
  dacAckRangeEntryLen* = 6
  dacAckRangeAscii* = """
+--------------- Common DAC1 Envelope ----------------+
| Kind = AckRange | Flags = 0                          |
+----------+----------+----------+----------+----------+
| AckBase  | RangeCt  | GapBits  | CommitCt | Ranges.. |
| u32      | u8       | u8       | u8       | n bytes  |
+----------+----------+----------+----------+----------+

Range entry:
+----------+----------+
| StartSeq | Count    |
| u32      | u16      |
+----------+----------+
"""

proc initDacAckRangeEntry*(startSeq: uint32,
    count: uint16): DacAckRangeEntry {.role: wrapper.} =
  ## startSeq/count: contiguous received sequence range.
  if count == 0'u16:
    raise newException(ValueError, "DAC ACK range count must be positive")
  result.startSeq = startSeq
  result.count = count

proc initDacAckRange*(ackBase: uint32, gapBits,
    commitCount: uint8): DacAckRange {.role: wrapper.} =
  ## ackBase: sequence base for the ACK frame.
  ## gapBits/commitCount: gap bitmap width and committed package count.
  result.ackBase = ackBase
  result.gapBits = gapBits
  result.commitCount = commitCount
  result.ranges = @[]

proc addDacAckRange*(S: var DacAckRange, e: DacAckRangeEntry) {.role: stateController.} =
  ## S: ACK range state to mutate.
  ## e: range entry to append.
  S.ranges.add(e)

proc dacAckIncludesSeq*(a: DacAckRange, seq: uint32): bool {.role: parser.} =
  ## a: ACK body to inspect.
  ## seq: DAC sequence number being checked.
  var
    i: int = 0
    startSeq: uint32 = 0'u32
    delta: uint32 = 0'u32
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

proc encodeDacAckRange*(a: DacAckRange): ByteSeq {.role: wrapper.} =
  ## a: ACK range body to encode.
  var
    i: int = 0
  if a.ranges.len > int(high(uint8)):
    raise newException(ValueError, "DAC ACK range count exceeds u8")
  appendDacU32(result, a.ackBase)
  result.add(uint8(a.ranges.len))
  result.add(a.gapBits)
  result.add(a.commitCount)
  while i < a.ranges.len:
    appendDacU32(result, a.ranges[i].startSeq)
    appendDacU16(result, a.ranges[i].count)
    i = i + 1

proc decodeDacAckRange*(A: openArray[uint8]): DacAckRange {.role: parser.} =
  ## A: ACK range body bytes.
  var
    rangeCount: int = 0
    offset: int = dacAckRangeHeaderLen
    i: int = 0
  if A.len < dacAckRangeHeaderLen:
    raise newException(ValueError, "DAC ACK range body too short")
  rangeCount = int(A[4])
  if A.len != dacAckRangeHeaderLen + (rangeCount * dacAckRangeEntryLen):
    raise newException(ValueError, "DAC ACK range body length mismatch")
  result = initDacAckRange(readDacU32(A, 0), A[5], A[6])
  while i < rangeCount:
    addDacAckRange(result, initDacAckRangeEntry(readDacU32(A, offset),
      readDacU16(A, offset + 4)))
    offset = offset + dacAckRangeEntryLen
    i = i + 1
