## ----------------------------------------------------
## DAC Repair Chunk <- exact chunk or extra parity data
## ----------------------------------------------------

import ../../types
import ../types
import ../level0/body_codec
import ../../byte_codec
import runePragmas

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
  appendU64Le(result, c.packageId)
  appendU32Le(result, c.groupId)
  appendU16Le(result, c.chunkId)
  result.add(uint8(ord(c.source)))
  appendDacBytes(result, c.payload)

proc decodeDacRepairChunk*(A: openArray[uint8]): DacRepairChunk {.role: parser.} =
  ## A: repair chunk body bytes.
  if A.len < dacRepairChunkHeaderLen:
    raise newException(ValueError, "DAC repair chunk body too short")
  result = initDacRepairChunk(readU64Le(A, 0), readU32Le(A, 8),
    readU16Le(A, 12), dacRepairSourceFromId(A[14]),
    copyDacSpan(A, 15, A.len - 15))
