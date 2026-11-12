## --------------------------------------------------
## DAC Package Chunk <- unordered original data shard
## --------------------------------------------------

import ../../types
import ../types
import ../level0/body_codec
import ../../byte_codec
import runePragmas

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
    chunkId: uint16, offset: uint32, payload: ByteSeq): DacPackageChunk {.role: configurator.} =
  ## packageId/groupId/chunkId/offset: chunk identity.
  ## payload: raw chunk bytes.
  result.packageId = packageId
  result.groupId = groupId
  result.chunkId = chunkId
  result.offset = offset
  result.payload = copyDacBytes(payload)

proc encodeDacPackageChunk*(c: DacPackageChunk): ByteSeq {.role: helper.} =
  ## c: package chunk body to encode.
  appendU64Le(result, c.packageId)
  appendU32Le(result, c.groupId)
  appendU16Le(result, c.chunkId)
  appendU32Le(result, c.offset)
  appendDacBytes(result, c.payload)

proc decodeDacPackageChunk*(A: openArray[uint8]): DacPackageChunk {.role: parser.} =
  ## A: package chunk body bytes.
  if A.len < dacPackageChunkHeaderLen:
    raise newException(ValueError, "DAC package chunk body too short")
  result = initDacPackageChunk(readU64Le(A, 0), readU32Le(A, 8),
    readU16Le(A, 12), readU32Le(A, 14), copyDacSpan(A, 18, A.len - 18))
