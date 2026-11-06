## -------------------------------------------------------------------------
## Archive Log <- one record of a space, stored once, opened by every member
## -------------------------------------------------------------------------
##
## A log record is one message of a chat, one mail of a mailbox, one change
## to a password vault. It is sealed ONCE and stored ONCE; every member of
## the space opens the same bytes.
##
##   offset 0     1      3        7        11      13             29      29+T
##          +-----+------+--------+--------+-------+--------------+-------+------+
##          | ver | gen  | lane   | epoch  | index | salt         | tag   | body |
##          | u8  | u16  | u32    | u32    | u16   | 16 B random  | T B   | n B  |
##          +-----+------+--------+--------+-------+--------------+-------+------+
##
##   K_e       = XHKDF(space secret, "ARCHIVE-EPOCH-KEY-v1" | spaceId | gen
##                     | lane | epoch)                       (one per epoch)
##   key block = XHKDF(K_e, "ARCHIVE-MESSAGE-KEY-v1" | spaceId | gen | lane
##                     | epoch | index | salt)               (one per record)
##   tag input = "ARCHIVE-LOG-v1" | spaceId | the 29-byte header
##               (plus layout, tier, tag length)
##
## The header is unencrypted: a server reads gen, lane, epoch and index to
## store and page records. It cannot change them, the tag covers them. The
## spaceId is not in the record, so a record moved to another space fails to
## open. There is no nonce on the wire: it is the front of the key block.
##
## ╭─ ❧ Why the salt costs 16 bytes per record ⚠️
##
## Without it, one position always gives one key block, so one nonce. A
## device that reuses a position (a crash before the counter was saved, a
## phone restored from an old backup) would seal two texts under one nonce
## and leak both. With it, the second text gets another key block. The
## storing side keeps each position write-once and refuses the second.

import ../../types
import ../../ame/types
import ../../ame/level0/bytes
import ../../ame/level1/suites
import ../../ame/level1/tier_aead
import ../types
import ../level0/records
import ./keys
import ./sealed
import runePragmas
import var_invariants

proc newArchiveSpaceId*(): ByteSeq {.role: dataFetcher,
    tag: "archive|appApi".} =
  ## 16 random bytes that name a new space.
  result = archiveRandom(archiveSpaceIdBytes)

proc newArchiveLane*(): uint32 {.role: dataFetcher, tag: "archive|appApi".} =
  ## A random lane number for a device that first writes into a space. The
  ## store refuses one already taken; then the device draws again.
  var
    A: ByteSeq = archiveRandom(4)
  result = uint32(A[0]) or (uint32(A[1]) shl 8) or (uint32(A[2]) shl 16) or
    (uint32(A[3]) shl 24)

proc initArchiveSpace*(spaceId, secret: openArray[uint8], gen: uint16,
    epochSize: uint16 = archiveDefaultEpochSize,
    layout: AmeSuiteLayout = archiveRecordLayout(),
    tagLen: AmeAuthTagLen = aatl32): ArchiveSpace {.role: truthBuilder,
    tag: "archive|appApi",
    needs: spaceId.len == archiveSpaceIdBytes and
      secret.len == archiveKeyBytes and epochSize > 0'u16.} =
  ## spaceId/secret/gen: which space, its shared secret, which generation.
  ## epochSize/layout/tagLen: agreed once by the members; every slot of the
  ## layout is switched on.
  result.spaceId = @spaceId
  result.gen = gen
  result.secret = @secret
  result.epochSize = epochSize
  result.layout = layout
  result.tier = fullAmeMaskTier(layout)
  result.tagLen = tagLen

proc clearArchiveSpace*(S: var ArchiveSpace) {.role: actor,
    tag: "archive|appApi|cryptoBoundary".} =
  ## S: the secret erased; the rest reset.
  secureClearAmeBytes(S.secret)
  S = default(ArchiveSpace)

proc archiveLogAad(S: ArchiveSpace, header: openArray[uint8]): ByteSeq {.
    role: helper, tag: "archive|cryptoBoundary".} =
  ## S/header: what the tag binds besides the ciphertext.
  appendAmeLabel(result, "ARCHIVE-LOG-v1")
  appendAmeBytes(result, S.spaceId)
  appendAmeBytes(result, header)

proc archiveLogBlock(S: ArchiveSpace, P: ArchivePosition,
    salt: openArray[uint8]): ByteSeq {.role: truthBuilder,
    tag: "archive|cryptoBoundary|kdf".} =
  ## S/P/salt: the key block of one log record. K_e is made and erased here;
  ## a caller sealing many records in a row may cache it later if it costs.
  var
    epochKey: ByteSeq = deriveArchiveEpochKey(S.spaceId, S.secret, P.gen,
      P.lane, P.epoch)
    where: ByteSeq = encodeArchivePosition(P)
  result = deriveArchiveBlock(epochKey, "ARCHIVE-MESSAGE-KEY-v1",
    [S.spaceId, where, @salt], ameTierKeyMaterialLen(S.layout, S.tier))
  secureClearAmeBytes(epochKey)

proc archivePositionError*(S: ArchiveSpace, P: ArchivePosition): string {.
    role: parser, tag: "archive|sanitizer".} =
  ## S/P: "" when P may be sealed or opened in S.
  if S.secret.len != archiveKeyBytes:
    return "archive space holds no secret"
  if P.gen != S.gen:
    return "archive record belongs to another generation"
  if P.index >= S.epochSize:
    return "archive index is past the epoch size"
  result = ""

proc sealArchiveLog*(S: ArchiveSpace, P: ArchivePosition,
    body: openArray[uint8]): ByteSeq {.role: encryptor,
    tag: "archive|appApi|cryptoBoundary".} =
  ## S/P/body: one record sealed at position P. Returns 29 + T + body.len
  ## bytes. The caller saves its next index BEFORE calling this (see top).
  var
    err: string = archivePositionError(S, P)
    salt: ByteSeq = @[]
    header: ByteSeq = @[]
    material: ByteSeq = @[]
    sealed: tuple[ciphertext: ByteSeq, authTag: ByteSeq] = (@[], @[])
  if err.len > 0:
    raise newException(ValueError, err)
  salt = archiveRandom(archiveSaltBytes)
  header = encodeArchiveLogHeader(P, salt)
  material = archiveLogBlock(S, P, salt)
  sealed = sealAmeTier(S.layout, S.tier, material, body,
    archiveLogAad(S, header), S.tagLen)
  secureClearAmeBytes(material)
  result = header
  appendAmeBytes(result, sealed.authTag)
  appendAmeBytes(result, sealed.ciphertext)

proc openArchiveLog*(S: ArchiveSpace, A: openArray[uint8]): tuple[ok: bool,
    position: ArchivePosition, body: ByteSeq, err: string] {.role: decryptor,
    tag: "archive|appApi|cryptoBoundary".} =
  ## S/A: one stored record. Nothing here raises. On ok, `position` is where
  ## it sits and `body` what it says. Pick S by `archiveLogGen(A)` first.
  var
    R: ArchiveLogRecord = default(ArchiveLogRecord)
    material: ByteSeq = @[]
    opened: tuple[ok: bool, payload: ByteSeq] = (false, @[])
  try:
    R = decodeArchiveLogRecord(A, int(ord(S.tagLen)))
  except ValueError as exc:
    result.err = exc.msg
    return
  result.err = archivePositionError(S, R.position)
  if result.err.len > 0:
    return
  material = archiveLogBlock(S, R.position, R.salt)
  opened = openAmeTier(S.layout, S.tier, material, R.ciphertext, R.tag,
    archiveLogAad(S, A.toOpenArray(0, archiveLogHeaderBytes - 1)), S.tagLen)
  secureClearAmeBytes(material)
  if not opened.ok:
    result.err = "archive record does not open"
    return
  result = (true, R.position, opened.payload, "")
