## ------------------------------------------------------------
## DAC Package Manifest <- package layout and digest preflight
## ------------------------------------------------------------

import ../../types
import ../types
import ../level0/defaults
import ../level0/body_codec
import ../../../analysis_pragmas

const
  dacPackageManifestLen* = 59
  dacPackageManifestAscii* = """
+--------------- Common DAC1 Envelope ----------------+
| Kind = PackageManifest | Flags = NeedsAck            |
+----------+----------+----------+----------+----------+
| Package  | Class    | ChunkSz | DataCnt  | ParityCt |
| u64      | u8       | u16     | u16      | u16      |
+----------+----------+----------+----------+----------+
| GroupSz  | Codec    | Digest  | TotalLen | NameLen  |
| u16      | u8       | 32 byte | u64      | u8       |
+----------+----------+----------+----------+----------+
"""

proc digestIsZero(digest: array[32, uint8]): bool {.role: parser.} =
  ## digest: package digest bytes.
  var
    i: int = 0
  result = true
  while i < digest.len:
    if digest[i] != 0'u8:
      return false
    i = i + 1

proc dacChunkCount(totalLen: uint64, chunkBytes: uint16): uint16 {.role: math.} =
  ## totalLen: total package bytes.
  ## chunkBytes: chunk byte width.
  var
    chunks: uint64 = 0'u64
  if chunkBytes == 0'u16:
    raise newException(ValueError, "DAC manifest chunk size must be positive")
  if totalLen == 0'u64:
    return 0'u16
  chunks = (totalLen + uint64(chunkBytes) - 1'u64) div uint64(chunkBytes)
  if chunks > uint64(high(uint16)):
    raise newException(ValueError, "DAC manifest chunk count exceeds u16")
  result = uint16(chunks)

proc initDacPackageManifest*(packageId: uint64, c: DacTransferClass,
    d: DacScenarioDefaults, totalLen: uint64,
    digest: array[32, uint8]): DacPackageManifest {.role: wrapper.} =
  ## packageId: logical package id.
  ## c: vertical transfer class.
  ## d: active DAC defaults.
  ## totalLen: plaintext or ciphertext package bytes.
  ## digest: package digest bound to this manifest.
  var
    groupSize: uint32 = 0'u32
  if not validateDacDefaults(d):
    raise newException(ValueError, "DAC defaults are invalid")
  if digestIsZero(digest):
    raise newException(ValueError, "DAC manifest digest must not be all zero")
  groupSize = uint32(d.dataShards) + uint32(d.parityShards)
  if groupSize == 0'u32 or groupSize > uint32(high(uint16)):
    raise newException(ValueError,
      "DAC manifest group size must be an integer from 1 to " & $high(uint16))
  result.packageId = packageId
  result.transferClass = c
  result.chunkBytes = d.chunkBytes
  result.dataCount = dacChunkCount(totalLen, d.chunkBytes)
  result.parityCount = d.parityShards
  result.groupSize = uint16(groupSize)
  result.repairMode = d.repairMode
  result.digest = digest
  result.totalLen = totalLen
  result.nameLen = 0'u8

proc validateDacPackageManifest*(m: DacPackageManifest): bool {.role: parser.} =
  ## m: decoded or caller-built manifest to validate before use.
  var
    expectedChunks: uint16 = 0'u16
  if digestIsZero(m.digest):
    return false
  if m.chunkBytes == 0'u16 or m.groupSize == 0'u16:
    return false
  try:
    expectedChunks = dacChunkCount(m.totalLen, m.chunkBytes)
  except CatchableError:
    return false
  if expectedChunks != m.dataCount:
    return false
  if m.repairMode == drmNone:
    return m.parityCount == 0'u16
  result = m.parityCount > 0'u16 and m.groupSize > m.parityCount

proc encodeDacPackageManifest*(m: DacPackageManifest): ByteSeq {.role: wrapper.} =
  ## m: package manifest body to encode.
  if not validateDacPackageManifest(m):
    raise newException(ValueError, "DAC package manifest is invalid")
  appendDacU64(result, m.packageId)
  result.add(uint8(ord(m.transferClass)))
  appendDacU16(result, m.chunkBytes)
  appendDacU16(result, m.dataCount)
  appendDacU16(result, m.parityCount)
  appendDacU16(result, m.groupSize)
  result.add(uint8(ord(m.repairMode)))
  appendDacBytes(result, m.digest)
  appendDacU64(result, m.totalLen)
  result.add(m.nameLen)

proc decodeDacPackageManifest*(A: openArray[uint8]): DacPackageManifest {.role: parser.} =
  ## A: package manifest body bytes.
  var
    digest: array[32, uint8]
    i: int = 0
  if A.len != dacPackageManifestLen:
    raise newException(ValueError, "DAC package manifest body length mismatch")
  while i < digest.len:
    digest[i] = A[18 + i]
    i = i + 1
  result.packageId = readDacU64(A, 0)
  result.transferClass = dacTransferClassFromId(A[8])
  result.chunkBytes = readDacU16(A, 9)
  result.dataCount = readDacU16(A, 11)
  result.parityCount = readDacU16(A, 13)
  result.groupSize = readDacU16(A, 15)
  result.repairMode = dacRepairModeFromId(A[17])
  result.digest = digest
  result.totalLen = readDacU64(A, 50)
  result.nameLen = A[58]
  if not validateDacPackageManifest(result):
    raise newException(ValueError, "DAC package manifest is invalid")
