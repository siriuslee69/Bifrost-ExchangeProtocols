## ------------------------------------------------
## DAC Parity Shard <- package repair parity frame
## ------------------------------------------------

import ../../types
import ../types
import ../level0/body_codec
import bifrostPragmas

const
  dacParityShardHeaderLen* = 15
  dacParityShardAscii* = """
+--------------- Common DAC1 Envelope ----------------+
| Kind = ParityShard | Flags = IsParity + CreditBound  |
+----------+----------+----------+----------+----------+
| Package  | Group    | ShardId  | Codec    | Raw...   |
| u64      | u32      | u16      | u8       | n bytes  |
+----------+----------+----------+----------+----------+
"""

proc initDacParityShard*(packageId: uint64, groupId: uint32,
    shardId: uint16, repairMode: DacRepairMode,
    payload: ByteSeq): DacParityShard {.role: configurator.} =
  ## packageId/groupId/shardId: parity identity.
  ## repairMode: parity codec.
  ## payload: parity bytes.
  result.packageId = packageId
  result.groupId = groupId
  result.shardId = shardId
  result.repairMode = repairMode
  result.payload = copyDacBytes(payload)

proc encodeDacParityShard*(s: DacParityShard): ByteSeq {.role: helper.} =
  ## s: parity shard body to encode.
  if s.repairMode == drmNone:
    raise newException(ValueError, "DAC parity shard must declare a repair mode")
  appendDacU64(result, s.packageId)
  appendDacU32(result, s.groupId)
  appendDacU16(result, s.shardId)
  result.add(uint8(ord(s.repairMode)))
  appendDacBytes(result, s.payload)

proc decodeDacParityShard*(A: openArray[uint8]): DacParityShard {.role: parser.} =
  ## A: parity shard body bytes.
  if A.len < dacParityShardHeaderLen:
    raise newException(ValueError, "DAC parity shard body too short")
  result = initDacParityShard(readDacU64(A, 0), readDacU32(A, 8),
    readDacU16(A, 12), dacRepairModeFromId(A[14]),
    copyDacSpan(A, 15, A.len - 15))
  if result.repairMode == drmNone:
    raise newException(ValueError, "DAC parity shard must declare a repair mode")
