## --------------------------------------------------
## DAC Package Chunk <- unordered original data shard
## --------------------------------------------------

import ../../types
import ../types
import ../level0/body_codec
import ../../../analysis_pragmas

const
  dacPackageChunkHeaderLen* = 18
  dacPackageChunkAscii* = """
+--------------- Common DAC1 Envelope ----------------+
| Kind = PackageChunk | Flags = CreditBound            |
+----------+----------+----------+----------+----------+
| Package  | Group    | ChunkId  | Offset   | Raw...   |
| u64      | u32      | u16      | u32      | n bytes  |
+----------+----------+----------+----------+----------+
"""

proc initDacPackageChunk*(packageId: uint64, groupId: uint32,
    chunkId: uint16, offset: uint32, payload: ByteSeq): DacPackageChunk {.role: wrapper.} =
  ## packageId/groupId/chunkId/offset: chunk identity.
  ## payload: raw chunk bytes.
  result.packageId = packageId
  result.groupId = groupId
  result.chunkId = chunkId
  result.offset = offset
  result.payload = copyDacBytes(payload)

proc encodeDacPackageChunk*(c: DacPackageChunk): ByteSeq {.role: wrapper.} =
  ## c: package chunk body to encode.
  appendDacU64(result, c.packageId)
  appendDacU32(result, c.groupId)
  appendDacU16(result, c.chunkId)
  appendDacU32(result, c.offset)
  appendDacBytes(result, c.payload)

proc decodeDacPackageChunk*(A: openArray[uint8]): DacPackageChunk {.role: parser.} =
  ## A: package chunk body bytes.
  if A.len < dacPackageChunkHeaderLen:
    raise newException(ValueError, "DAC package chunk body too short")
  result = initDacPackageChunk(readDacU64(A, 0), readDacU32(A, 8),
    readDacU16(A, 12), readDacU32(A, 14), copyDacSpan(A, 18, A.len - 18))
