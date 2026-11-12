## -------------------------------------------------------------------------
## Archive Openings <- "let us start a space", the answer, and read pointers
## -------------------------------------------------------------------------
##
## ╭─ ❧ Def. 1: the opening (CAO1) 🌊
##
##   +-----+----------+-----+-----------+--------------+------------+
##   | ver | spaceId  | gen | epochSize | u16 + layout | u16 + tier |
##   | u8  | 16 B     | u16 | u16       |              |            |
##   +-----+----------+-----+-----------+--------------+------------+
##   | tagLen | u8 n | secret, n = 0 or 32                          |
##   | u8     |      |                                              |
##   +--------+------+----------------------------------------------+
##
##   Two members: n = 0, both derive the secret from their first contact
##   (`deriveArchiveSpaceSecret`), so it never travels.
##   A group: n = 32, the maker chose it at random, and this opening goes
##   sealed to each member one at a time (level2/letters.nim).
##
## ╭─ ❧ Def. 2: the answer (CAA1) 🍣
##
##   | ver u8 | spaceId 16 | gen u16 | answer u8 (1 = accept, 0 = refuse) |
##
## ╭─ ❧ Def. 3: the read pointer (CAR1), not sealed 🐦‍🔥
##
##   | ver u8 | count u16 | count x position 12 |
##
##   Not sealed on purpose: the server counts "unread" with it, and it learns
##   as much anyway from what a device fetches.

import ../../types
import ../../ame/types
import ../../ame/level0/bytes
import ../../ame/level1/suites
import ../types
import ../level0/records
import ./account
import ../../byte_codec
import runePragmas

proc encodeArchiveOpening*(S: ArchiveSpace, carrySecret: bool): ByteSeq {.
    role: dataWriter, tag: "archive|wire".} =
  ## S: the space. carrySecret: Def. 1, true for a group.
  result.add(archiveRecordVersion)
  appendAmeBytes(result, S.spaceId)
  appendU16Le(result, S.gen)
  appendU16Le(result, S.epochSize)
  appendSizedArchive(result, encodeAmeSuiteLayout(S.layout))
  appendSizedArchive(result, encodeAmeMaskTier(S.tier))
  result.add(uint8(ord(S.tagLen)))
  result.add(if carrySecret: uint8(archiveKeyBytes) else: 0'u8)
  if carrySecret:
    appendAmeBytes(result, S.secret)

proc openingTagLen(b: uint8): AmeAuthTagLen {.role: parser.} =
  ## b: 16, 24 or 32. Raises on anything else.
  case b
  of 16'u8: result = aatl16
  of 24'u8: result = aatl24
  of 32'u8: result = aatl32
  else: raise newException(ValueError, "archive opening has a bad tag length")

proc decodeArchiveOpening*(A: openArray[uint8]): tuple[space: ArchiveSpace,
    carriedSecret: bool] {.role: parser, tag: "archive|wire".} =
  ## A: Def. 1. `space.secret` is empty unless the opening carried one.
  ## Raises on anything malformed.
  var
    o: int = 21
    n: int = 0
  if A.len < o or A[0] != archiveRecordVersion:
    raise newException(ValueError, "archive opening is short")
  result.space.spaceId = @(A.toOpenArray(1, 16))
  result.space.gen = readU16Le(A, 17)
  result.space.epochSize = readU16Le(A, 19)
  if result.space.epochSize == 0'u16:
    raise newException(ValueError, "archive epoch size must be at least 1")
  result.space.layout = decodeAmeSuiteLayout(takeSizedArchive(A, o))
  result.space.tier = decodeAmeMaskTier(result.space.layout,
    takeSizedArchive(A, o))
  if o + 2 > A.len:
    raise newException(ValueError, "archive opening is short")
  result.space.tagLen = openingTagLen(A[o])
  n = int(A[o + 1])
  o = o + 2
  if (n != 0 and n != archiveKeyBytes) or o + n != A.len:
    raise newException(ValueError, "archive opening has a bad secret")
  result.carriedSecret = n > 0
  result.space.secret = @(A.toOpenArray(o, A.len - 1))

proc encodeArchiveAnswer*(spaceId: openArray[uint8], gen: uint16,
    accept: bool): ByteSeq {.role: dataWriter, tag: "archive|wire".} =
  ## spaceId/gen/accept: Def. 2, 20 bytes.
  result.add(archiveRecordVersion)
  appendAmeBytes(result, spaceId)
  appendU16Le(result, gen)
  result.add(if accept: 1'u8 else: 0'u8)

proc decodeArchiveAnswer*(A: openArray[uint8]): tuple[spaceId: ByteSeq,
    gen: uint16, accept: bool] {.role: parser, tag: "archive|wire".} =
  ## A: Def. 2. Raises on anything malformed.
  if A.len != 20 or A[0] != archiveRecordVersion or A[19] > 1'u8:
    raise newException(ValueError, "archive answer is malformed")
  result.spaceId = @(A.toOpenArray(1, 16))
  result.gen = readU16Le(A, 17)
  result.accept = A[19] == 1'u8

proc encodeArchiveReadPointer*(P: openArray[ArchivePosition]): ByteSeq {.
    role: dataWriter, tag: "archive|wire".} =
  ## P: the last position read, one per lane. Def. 3.
  requireAmeU16Len(P.len, "archive read pointer")
  result.add(archiveRecordVersion)
  appendU16Le(result, uint16(P.len))
  for x in P:
    appendAmeBytes(result, encodeArchivePosition(x))

proc decodeArchiveReadPointer*(A: openArray[uint8]): seq[ArchivePosition] {.
    role: parser, tag: "archive|wire".} =
  ## A: Def. 3. Raises on anything malformed.
  var
    n: int = 0
    i: int = 0
    o: int = 3
  if A.len < 3 or A[0] != archiveRecordVersion:
    raise newException(ValueError, "archive read pointer is short")
  n = int(readU16Le(A, 1))
  if A.len != 3 + n * archivePositionBytes:
    raise newException(ValueError, "archive read pointer has the wrong size")
  while i < n:
    result.add(decodeArchivePosition(A.toOpenArray(o, o + archivePositionBytes - 1)))
    o = o + archivePositionBytes
    i = i + 1
