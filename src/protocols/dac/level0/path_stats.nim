## ----------------------------------------------------------
## DAC Path Stats <- receiver signal report for path epochs
## ----------------------------------------------------------

import ../../types
import ../types
import ./body_codec
import runePragmas

const
  dacPathStatsLen* = 24
  dacPathStatsAscii* = """
+--------------- Common DAC1 Envelope ----------------+
| Kind = PathStats | Flags = 0 | BodyLen = 24          |
+----------+----------+----------+----------+----------+
| LossPpm  | RttMs    | JitterMs | Reorder  | MtuHint  |
| u32      | u16      | u16      | u16      | u16      |
+----------+----------+----------+----------+----------+
| QueueMs  | Credit   | Reserved                         |
| u16      | u16      | 8 bytes                          |
+----------+----------+----------------------------------+
"""

proc initDacPathStats*(lossPpm: uint32, rttMs, jitterMs, reorderDepth,
    mtuHint, queueMs, creditHint: uint16): DacPathStats {.role: configurator.} =
  ## lossPpm: packet loss in parts per million.
  ## rttMs/jitterMs/reorderDepth/mtuHint/queueMs/creditHint: path metrics.
  result.lossPpm = lossPpm
  result.rttMs = rttMs
  result.jitterMs = jitterMs
  result.reorderDepth = reorderDepth
  result.mtuHint = mtuHint
  result.queueMs = queueMs
  result.creditHint = creditHint

proc dacShouldEnterLossyPath*(s: DacPathStats): bool {.role: parser.} =
  ## s: path stats to inspect.
  result = s.lossPpm > 50000'u32 or s.reorderDepth > 16'u16

proc encodeDacPathStats*(s: DacPathStats): ByteSeq {.role: helper.} =
  ## s: path stats body to encode.
  appendDacU32(result, s.lossPpm)
  appendDacU16(result, s.rttMs)
  appendDacU16(result, s.jitterMs)
  appendDacU16(result, s.reorderDepth)
  appendDacU16(result, s.mtuHint)
  appendDacU16(result, s.queueMs)
  appendDacU16(result, s.creditHint)
  appendDacZeroBytes(result, 8)

proc decodeDacPathStats*(A: openArray[uint8]): DacPathStats {.role: parser.} =
  ## A: path stats body bytes.
  if A.len != dacPathStatsLen:
    raise newException(ValueError, "DAC path stats body length mismatch")
  if not rangeIsZero(A, 16, 8):
    raise newException(ValueError, "DAC path stats reserved bytes mismatch")
  result = initDacPathStats(readDacU32(A, 0), readDacU16(A, 4),
    readDacU16(A, 6), readDacU16(A, 8), readDacU16(A, 10),
    readDacU16(A, 12), readDacU16(A, 14))
