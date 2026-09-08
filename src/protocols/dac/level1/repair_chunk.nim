## ----------------------------------------------------
## DAC Repair Chunk <- exact chunk or extra parity data
## ----------------------------------------------------

import ../../types
import ../types
import ../level0/body_codec
import ../../../analysis_pragmas

const
  dacRepairChunkHeaderLen* = 15
  dacRepairChunkAscii* = """
+--------------- Common DAC1 Envelope ----------------+
| Kind = RepairChunk | Flags = IsRepair                |
+----------+----------+----------+----------+----------+
| Package  | Group    | ChunkId  | Source   | Raw...   |
| u64      | u32      | u16      | u8       | n bytes  |
+----------+----------+----------+----------+----------+
"""

proc initDacRepairChunk*(packageId: uint64, groupId: uint32,
    chunkId: uint16, source: DacRepairSource,
    payload: ByteSeq): DacRepairChunk {.role: configurator.} =
  ## packageId/groupId/chunkId: repair identity.
  ## source: repair source/method.
  ## payload: repair bytes.
  result.packageId = packageId
  result.groupId = groupId
  result.chunkId = chunkId
  result.source = source
  result.payload = copyDacBytes(payload)

proc encodeDacRepairChunk*(c: DacRepairChunk): ByteSeq {.role: helper.} =
  ## c: repair chunk body to encode.
  appendDacU64(result, c.packageId)
  appendDacU32(result, c.groupId)
  appendDacU16(result, c.chunkId)
  result.add(uint8(ord(c.source)))
  appendDacBytes(result, c.payload)

proc decodeDacRepairChunk*(A: openArray[uint8]): DacRepairChunk {.role: parser.} =
  ## A: repair chunk body bytes.
  if A.len < dacRepairChunkHeaderLen:
    raise newException(ValueError, "DAC repair chunk body too short")
  result = initDacRepairChunk(readDacU64(A, 0), readDacU32(A, 8),
    readDacU16(A, 12), dacRepairSourceFromId(A[14]),
    copyDacSpan(A, 15, A.len - 15))
