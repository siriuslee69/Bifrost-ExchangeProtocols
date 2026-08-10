## ----------------------------------------------------------
## DAC Repair Hint <- receiver missing/corrupt shard request
## ----------------------------------------------------------

import ../../types
import ../types
import ../level0/body_codec
import ../../../analysis_pragmas

const
  dacRepairHintFixedLen* = 24
  dacRepairHintAscii* = """
+--------------- Common DAC1 Envelope ----------------+
| Kind = RepairHint | Flags = IsRepair                 |
+----------+----------+----------+----------+----------+
| Package  | Group    | Missing  | Corrupt  | Wanted   |
| u64      | u32      | u16      | u16      | u16      |
+----------+----------+----------+----------+----------+
| GapMap   | Codec    | Reason   | Reserved            |
| n bytes  | u8       | u8       | 4 bytes             |
+----------+----------+----------+---------------------+
"""

proc initDacRepairHint*(packageId: uint64, groupId: uint32,
    missingCount, corruptCount, wantedCount: uint16, gapMap: ByteSeq,
    repairMode: DacRepairMode, reason: DacRepairReason): DacRepairHint {.role: wrapper.} =
  ## packageId/groupId: repair group identity.
  ## missingCount/corruptCount/wantedCount: receiver repair counts.
  ## gapMap: compact missing/corrupt shard identity bitmap.
  ## repairMode/reason: desired repair mode and reason.
  if wantedCount == 0'u16:
    raise newException(ValueError, "DAC repair hint wanted count must be positive")
  if int(missingCount) + int(corruptCount) < int(wantedCount):
    raise newException(ValueError, "DAC repair hint counts cannot satisfy wanted count")
  if gapMap.len == 0:
    raise newException(ValueError, "DAC repair hint gap map must not be empty")
  result.packageId = packageId
  result.groupId = groupId
  result.missingCount = missingCount
  result.corruptCount = corruptCount
  result.wantedCount = wantedCount
  result.gapMap = gapMap
  result.repairMode = repairMode
  result.reason = reason

proc initDacRepairHint*(packageId: uint64, groupId: uint32,
    missingCount, corruptCount, wantedCount: uint16, repairMode: DacRepairMode,
    reason: DacRepairReason): DacRepairHint {.role: wrapper.} =
  ## packageId/groupId/counts/repairMode/reason: repair hint fields.
  result = initDacRepairHint(packageId, groupId, missingCount, corruptCount,
    wantedCount, @[], repairMode, reason)

proc encodeDacRepairHint*(h: DacRepairHint): ByteSeq {.role: wrapper.} =
  ## h: repair hint body to encode.
  if h.gapMap.len == 0:
    raise newException(ValueError, "DAC repair hint gap map must not be empty")
  appendDacU64(result, h.packageId)
  appendDacU32(result, h.groupId)
  appendDacU16(result, h.missingCount)
  appendDacU16(result, h.corruptCount)
  appendDacU16(result, h.wantedCount)
  appendDacBytes(result, h.gapMap)
  result.add(uint8(ord(h.repairMode)))
  result.add(uint8(ord(h.reason)))
  appendDacZeroBytes(result, 4)

proc decodeDacRepairHint*(A: openArray[uint8]): DacRepairHint {.role: parser.} =
  ## A: repair hint body bytes.
  var
    gapLen: int = 0
  if A.len < dacRepairHintFixedLen:
    raise newException(ValueError, "DAC repair hint body too short")
  if not rangeIsZero(A, A.len - 4, 4):
    raise newException(ValueError, "DAC repair hint reserved bytes mismatch")
  gapLen = A.len - dacRepairHintFixedLen
  result = initDacRepairHint(readDacU64(A, 0), readDacU32(A, 8),
    readDacU16(A, 12), readDacU16(A, 14), readDacU16(A, 16),
    copyDacSpan(A, 18, gapLen), dacRepairModeFromId(A[18 + gapLen]),
    dacRepairReasonFromId(A[19 + gapLen]))
