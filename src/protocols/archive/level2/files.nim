## -------------------------------------------------------------------------
## Archive Files <- a file cut into chunks, each sealed on its own
## -------------------------------------------------------------------------
##
##   big file ──▶ chunk 0 ──▶ sealArchiveFileChunk ──▶ item "f/<fileId>/0"
##            ──▶ chunk 1 ──▶ sealArchiveFileChunk ──▶ item "f/<fileId>/1"
##
## A chunk is at most `archiveFileChunkBytes`, so neither end ever holds the
## whole file in memory, and a broken transfer goes on at the next chunk.
##
## Def. 1 (place): the file id and the chunk's number are sealed into the tag.
##   Moving a chunk to another file, or swapping two chunks, fails to open.
## Def. 2 (manifest): one small sealed record saying what the chunks add up to:
##
##   +------+-------------+------------+--------------+-------------------+
##   | ver  | size        | chunkBytes | chunks       | blake3 of content |
##   | u8   | u64         | u32        | u64          | 32 B              |
##   +------+-------------+------------+--------------+-------------------+
##   | u16 + name (UTF-8)                                                 |
##   +--------------------------------------------------------------------+
##
##   A server that hides the last chunk is caught: the count and the hash are
##   in the sealed manifest.

import ../../types
import ../../ame/level0/bytes
import ../types
import ../level1/keys
import ../level1/sealed
import ./account
import ../../byte_codec
import runePragmas

const
  archiveFileChunkBytes* = 1024 * 1024
  archiveFileHashBytes* = 32
  archiveFileChunkLabel = "ARCHIVE-FILE-CHUNK-v1"
  archiveFileManifestLabel = "ARCHIVE-FILE-MANIFEST-v1"

type
  ArchiveFileManifest* {.role: preparedData, tag: "archive|types".} = object
    ## Def. 2.
    size*: uint64
    chunkBytes*: uint32
    chunks*: uint64
    hash*: ByteSeq
    name*: string

proc chunkPlace(fileId: openArray[uint8], index: uint64): ByteSeq {.
    role: helper, inline.} =
  ## fileId/index: Def. 1.
  appendAmeBytes(result, fileId)
  appendU64Le(result, index)

proc sealArchiveFileChunk*(fileKey, fileId: openArray[uint8], index: uint64,
    plain: openArray[uint8]): ByteSeq {.role: encryptor,
    tag: "archive|appApi|cryptoBoundary".} =
  ## fileKey/fileId/index/plain: one chunk, at most `archiveFileChunkBytes`.
  if plain.len > archiveFileChunkBytes:
    raise newException(ValueError, "archive file chunk is too large")
  result = sealArchiveRecord(fileKey, archiveFileChunkLabel,
    chunkPlace(fileId, index), 0'u16, plain)

proc openArchiveFileChunk*(fileKey, fileId: openArray[uint8], index: uint64,
    A: openArray[uint8]): tuple[ok: bool, plain: ByteSeq] {.role: decryptor,
    tag: "archive|appApi|cryptoBoundary".} =
  ## fileKey/fileId/index/A: as sealed. Nothing here raises.
  var
    opened: tuple[ok: bool, record: ArchiveRecord] = (false, ArchiveRecord())
  opened = openArchiveRecord(fileKey, archiveFileChunkLabel,
    chunkPlace(fileId, index), A)
  result = (opened.ok, opened.record.body)

proc encodeManifest(M: ArchiveFileManifest): ByteSeq {.role: dataWriter.} =
  ## M: Def. 2.
  result.add(archiveRecordVersion)
  appendU64Le(result, M.size)
  appendU32Le(result, M.chunkBytes)
  appendU64Le(result, M.chunks)
  appendAmeBytes(result, M.hash)
  appendSizedArchive(result, toBytesArchive(M.name))

proc decodeManifest(A: openArray[uint8]): ArchiveFileManifest {.role: parser.} =
  ## A: Def. 2. Raises on anything malformed.
  var
    o: int = 21 + archiveFileHashBytes
    name: ByteSeq = @[]
  if A.len < o or A[0] != archiveRecordVersion:
    raise newException(ValueError, "archive file manifest is short")
  result.size = readU64Le(A, 1)
  result.chunkBytes = uint32(A[9]) or (uint32(A[10]) shl 8) or
    (uint32(A[11]) shl 16) or (uint32(A[12]) shl 24)
  result.chunks = readU64Le(A, 13)
  result.hash = @(A.toOpenArray(21, o - 1))
  name = takeSizedArchive(A, o)
  result.name = newString(name.len)
  if name.len > 0:
    copyMem(addr result.name[0], unsafeAddr name[0], name.len)

proc sealArchiveFileManifest*(fileKey, fileId: openArray[uint8],
    M: ArchiveFileManifest): ByteSeq {.role: encryptor,
    tag: "archive|appApi|cryptoBoundary".} =
  ## fileKey/fileId/M: Def. 2, sealed.
  if M.hash.len != archiveFileHashBytes:
    raise newException(ValueError, "archive file manifest needs a 32-byte hash")
  result = sealArchiveRecord(fileKey, archiveFileManifestLabel, fileId, 0'u16,
    encodeManifest(M))

proc openArchiveFileManifest*(fileKey, fileId, A: openArray[uint8]): tuple[
    ok: bool, manifest: ArchiveFileManifest] {.role: decryptor,
    tag: "archive|appApi|cryptoBoundary".} =
  ## fileKey/fileId/A: as sealed. Nothing here raises.
  var
    opened: tuple[ok: bool, record: ArchiveRecord] = (false, ArchiveRecord())
  opened = openArchiveRecord(fileKey, archiveFileManifestLabel, fileId, A)
  if not opened.ok:
    return
  try:
    result = (true, decodeManifest(opened.record.body))
  except ValueError:
    result = (false, ArchiveFileManifest())

proc archiveFileCheckShape*(M: ArchiveFileManifest,
    chunkLens: openArray[int]): tuple[ok: bool, err: string] {.role: parser,
    tag: "archive|appApi".} =
  ## M: the opened manifest. chunkLens: the plain length of each chunk that
  ## OPENED, chunk 0 first. Answers whether they are the whole file:
  ##
  ##   manifest says 3 chunks of 4, size 9      lengths [4, 4, 1]  -> ok
  ##   the same, last chunk cut off             lengths [4, 4]     -> "cut: 2 of 3"
  ##   the same, an extra chunk added           lengths [4, 4, 1, 1] -> "cut: 4 of 3"
  ##   a short chunk in the middle              lengths [4, 3, 2]  -> refused
  ##
  ## Each chunk opens on its own (its place is sealed into its tag), so a server
  ## that hides the LAST chunk gives no error from `openArchiveFileChunk`. The
  ## sealed manifest is what notices. Call this after opening the chunks; it
  ## holds no file data, so a file of any size is checked in one call. The
  ## content hash (`M.hash`) is the caller's second check: it catches a chunk
  ## of an OLDER version of the same file put back in place.
  var
    total: uint64 = 0
    i: int = 0
  if uint64(chunkLens.len) != M.chunks:
    return (false, "the file is cut: " & $chunkLens.len & " of " & $M.chunks &
      " chunks arrived")
  while i < chunkLens.len:
    total = total + uint64(max(chunkLens[i], 0))
    if chunkLens[i] < 0 or uint32(chunkLens[i]) > M.chunkBytes:
      return (false, "chunk " & $i & " is longer than the manifest allows")
    if i + 1 < chunkLens.len and uint32(chunkLens[i]) != M.chunkBytes:
      return (false, "chunk " & $i & " is short, and it is not the last")
    i = i + 1
  if total != M.size:
    return (false, "the chunks add up to " & $total & " bytes, the manifest says " &
      $M.size)
  result = (true, "")
