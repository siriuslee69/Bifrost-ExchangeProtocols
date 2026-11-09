## -------------------------------------------------------------------------
## Archive Account <- the master key record and the space entries of a vault
## -------------------------------------------------------------------------
##
## Two kinds of sealed record every account keeps, built on ../level1/sealed:
##
##   record          label                key       place     num      body
##   --------------  -------------------  --------  --------  -------  ----------------
##   master key      "ARCHIVE-MASTER-v1"  wrapKey   userId    keyGen   master key (32)
##   space entry     "ARCHIVE-SPACE-v1"   sub key   spaceId   gen      Def. 1 below
##                                        "vault"
##
## A new device needs nothing but the password:
##
##   password ──▶ wrapKey ──opens──▶ master key record ──▶ master key
##   master key ──▶ sub key "vault" ──opens──▶ every space entry ──▶ spaces
##
## ╭─ ❧ Def. 1: the body of a space entry 🌊
##
##   +---------+-----------+-------------+-------------+--------+-------------+
##   | secret  | epochSize | u16 + space | u16 + space | tagLen | u16 + meta  |
##   | 32 B    | u16       | layout      | tier        | u8     | (app bytes) |
##   +---------+-----------+-------------+-------------+--------+-------------+
##
## `meta` is whatever the application keeps beside a space: a chat keeps the
## other user's handle, a mailbox its address. Bifrost never reads it.

import ../../types
import ../../ame/types
import ../../ame/level0/bytes
import ../../ame/level1/suites
import ../types
import ../level1/keys
import ../level1/sealed
import runePragmas
import var_invariants

const
  archiveMasterLabel* = "ARCHIVE-MASTER-v1"
  archiveSpaceLabel* = "ARCHIVE-SPACE-v1"
  archiveVaultKeyName* = "vault"
    ## the sub key that seals space entries

proc sealArchiveMasterKey*(wrapKey: openArray[uint8], userId: string,
    keyGen: uint16, masterKey: openArray[uint8]): ByteSeq {.role: encryptor,
    tag: "archive|appApi|cryptoBoundary",
    needs: masterKey.len == archiveKeyBytes.} =
  ## wrapKey/userId/keyGen/masterKey: the one record a password opens.
  ## 83 bytes. A password change reseals this and nothing else.
  result = sealArchiveRecord(wrapKey, archiveMasterLabel,
    toBytesArchive(userId), keyGen, masterKey)

proc openArchiveMasterKey*(wrapKey: openArray[uint8], userId: string,
    A: openArray[uint8]): tuple[ok: bool, keyGen: uint16, masterKey: ByteSeq] {.
    role: decryptor, tag: "archive|appApi|cryptoBoundary".} =
  ## wrapKey/userId/A: the stored record. ok = false on a wrong password.
  var
    opened: tuple[ok: bool, record: ArchiveRecord] = (false, ArchiveRecord())
  opened = openArchiveRecord(wrapKey, archiveMasterLabel,
    toBytesArchive(userId), A)
  if not opened.ok or opened.record.body.len != archiveKeyBytes:
    return
  result = (true, opened.record.num, opened.record.body)

proc appendSizedArchive*(A: var ByteSeq, B: openArray[uint8]) {.role: dataWriter,
    inline.} =
  ## A/B: B with its u16 length in front.
  if B.len > int(high(uint16)):
    raise newException(ValueError, "archive field is longer than 65535 bytes")
  appendAmeU16(A, uint16(B.len))
  appendAmeBytes(A, B)

proc takeSizedArchive*(A: openArray[uint8], o: var int): ByteSeq {.role: parser.} =
  ## A/o: one u16-sized field at o; o moves past it. Raises when short.
  var
    n: int = 0
  if o + 2 > A.len:
    raise newException(ValueError, "archive space entry is short")
  n = int(A[o]) or (int(A[o + 1]) shl 8)
  if o + 2 + n > A.len:
    raise newException(ValueError, "archive space entry is short")
  result = @(A.toOpenArray(o + 2, o + 2 + n - 1))
  o = o + 2 + n

proc encodeArchiveSpace*(S: ArchiveSpace, meta: openArray[uint8]): ByteSeq {.
    role: dataWriter, tag: "archive|wire".} =
  ## S/meta: Def. 1.
  appendAmeBytes(result, S.secret)
  appendAmeU16(result, S.epochSize)
  appendSizedArchive(result, encodeAmeSuiteLayout(S.layout))
  appendSizedArchive(result, encodeAmeMaskTier(S.tier))
  result.add(uint8(ord(S.tagLen)))
  appendSizedArchive(result, meta)

proc tagLenOfArchive(b: uint8): AmeAuthTagLen {.role: parser.} =
  ## b: 16, 24 or 32. Raises on anything else.
  case b
  of 16'u8: result = aatl16
  of 24'u8: result = aatl24
  of 32'u8: result = aatl32
  else: raise newException(ValueError, "archive tag length must be 16, 24 or 32")

proc decodeArchiveSpace*(spaceId: openArray[uint8], gen: uint16,
    body: openArray[uint8]): tuple[space: ArchiveSpace, meta: ByteSeq] {.
    role: parser, tag: "archive|wire".} =
  ## spaceId/gen: from where the entry was stored. body: Def. 1.
  var
    o: int = archiveKeyBytes + 2
  if body.len < o + 7:
    raise newException(ValueError, "archive space entry is short")
  result.space.spaceId = @spaceId
  result.space.gen = gen
  result.space.secret = @(body.toOpenArray(0, archiveKeyBytes - 1))
  result.space.epochSize = uint16(body[32]) or (uint16(body[33]) shl 8)
  result.space.layout = decodeAmeSuiteLayout(takeSizedArchive(body, o))
  result.space.tier = decodeAmeMaskTier(result.space.layout,
    takeSizedArchive(body, o))
  if o >= body.len:
    raise newException(ValueError, "archive space entry is short")
  result.space.tagLen = tagLenOfArchive(body[o])
  o = o + 1
  result.meta = takeSizedArchive(body, o)
  if result.space.epochSize == 0'u16:
    raise newException(ValueError, "archive epoch size must be at least 1")

proc sealArchiveSpaceEntry*(vaultKey: openArray[uint8], S: ArchiveSpace,
    meta: openArray[uint8]): ByteSeq {.role: encryptor,
    tag: "archive|appApi|cryptoBoundary".} =
  ## vaultKey: the sub key "vault". S/meta: the space and the app's bytes.
  result = sealArchiveRecord(vaultKey, archiveSpaceLabel, S.spaceId, S.gen,
    encodeArchiveSpace(S, meta))

proc openArchiveSpaceEntry*(vaultKey, spaceId: openArray[uint8],
    A: openArray[uint8]): tuple[ok: bool, space: ArchiveSpace, meta: ByteSeq] {.
    role: decryptor, tag: "archive|appApi|cryptoBoundary".} =
  ## vaultKey/spaceId/A: one stored space entry. Nothing here raises.
  var
    opened: tuple[ok: bool, record: ArchiveRecord] = (false, ArchiveRecord())
    decoded: tuple[space: ArchiveSpace, meta: ByteSeq] = (ArchiveSpace(), @[])
  opened = openArchiveRecord(vaultKey, archiveSpaceLabel, spaceId, A)
  if not opened.ok:
    return
  try:
    decoded = decodeArchiveSpace(spaceId, opened.record.num, opened.record.body)
  except ValueError:
    return
  result = (true, decoded.space, decoded.meta)
