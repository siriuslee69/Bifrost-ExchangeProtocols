## -------------------------------------------------------------------------
## Archive Sealed Records <- one value sealed under a key, a label and a place
## -------------------------------------------------------------------------
##
## The frame every stored secret uses: a wrapped master key, a space entry,
## a device list, a lane record, a settings blob. One routine seals them
## all; only the key, the label, the place and the body differ.
##
##   offset 0     1      3              19          51
##          +-----+------+--------------+-----------+------------------+
##          | ver | num  | salt         | tag       | sealed body      |
##          | u8  | u16  | 16 B random  | 32 B      | n bytes          |
##          +-----+------+--------------+-----------+------------------+
##
## Def. 1 (label): what the record IS, e.g. "ARCHIVE-MASTER-v1". A record
##   sealed under one label never opens under another.
## Def. 2 (place): where the record is STORED, as the caller names it, e.g.
##   the userId, or spaceId. It is not in the record; the opener must know
##   it. A record copied to another place fails to open.
## Def. 3 (num): a number the caller wants to read WITHOUT opening: a key
##   generation, a space generation. The tag covers it.
## Def. 4 (salt): 16 fresh random bytes per seal. The key block comes from
##   key + label + place + num + salt, so resealing the same value (after a
##   crash, a password change) never reuses a nonce.
##
##   key block = XHKDF(key, "ARCHIVE-RECORD-KEY-v1" | label | place | num | salt)
##   tag input = "ARCHIVE-RECORD-v1" | label | place | the 19-byte header
##               (plus layout, tier, tag length: ame/level1/tier_aead.nim)
##
## ╭─ ❧ The record suite is pinned, not taken from the build ⚠️
##
## The ciphers and MACs of a sealed record are fixed by its version byte:
## version 1 = XChaCha20 + Gimli + AES-CTR, MACs Gimli + Poly1305, all on.
## The layout's bytes are written out below instead of built from the
## defaults, because the defaults change with the build flags, and a record
## sealed by one build must open in every later one. A build that left out
## one of these primitives refuses to seal or open, with an error naming it.

import std/strutils

import ../../types
import ../../ame/types
import ../../ame/level0/bytes
import ../../ame/level1/suites
import ../../ame/level1/tier_aead
import ../types
import ../level0/records
import ./keys
import runePragmas

const
  archiveRecordLayoutHex* = "02010f0312300223011001100213"
    ## version 1: KEM X25519 (unused), ciphers XChaCha20 Gimli AES-CTR,
    ## MACs Gimli Poly1305, hash BLAKE3, signature Ed25519 (unused),
    ## KDF BLAKE3 GimliXof. Never change it; add a version instead.

proc decodeAmeHexArchive(s: string): ByteSeq {.role: parser, tag: "archive".} =
  ## s: lowercase hex text -> bytes.
  const digits = "0123456789abcdef"
  var
    i: int = 0
  result = newSeq[uint8](s.len div 2)
  while i < result.len:
    result[i] = uint8(digits.find(s[2 * i]) * 16 + digits.find(s[2 * i + 1]))
    i = i + 1

proc archiveRecordLayout*(): AmeSuiteLayout {.role: configurator,
    tag: "archive|cryptoBoundary".} =
  ## The pinned layout of sealed records, version 1.
  result = decodeAmeSuiteLayout(decodeAmeHexArchive(archiveRecordLayoutHex))

proc archiveRecordAad(label: string, place, header: openArray[uint8]): ByteSeq {.
    role: helper, tag: "archive|cryptoBoundary".} =
  ## label/place/header: what the tag binds besides the ciphertext.
  appendAmeLabel(result, "ARCHIVE-RECORD-v1")
  appendAmeU32(result, uint32(label.len))
  appendAmeBytes(result, toBytesArchive(label))
  appendAmeU32(result, uint32(place.len))
  appendAmeBytes(result, place)
  appendAmeBytes(result, header)

proc archiveRecordBlock(key: openArray[uint8], label: string,
    place: openArray[uint8], num: uint16, salt: openArray[uint8],
    L: AmeSuiteLayout, t: AmeMaskTier): ByteSeq {.role: truthBuilder,
    tag: "archive|cryptoBoundary|kdf".} =
  ## key/label/place/num/salt/L/t: Def. 4, the key block of one record.
  var
    n: ByteSeq = @[]
  appendAmeU16(n, num)
  result = deriveArchiveBlock(key, "ARCHIVE-RECORD-KEY-v1",
    [toBytesArchive(label), @place, n, @salt], ameTierKeyMaterialLen(L, t))

proc sealArchiveRecord*(key: openArray[uint8], label: string,
    place: openArray[uint8], num: uint16, body: openArray[uint8]): ByteSeq {.
    role: encryptor, tag: "archive|appApi|cryptoBoundary".} =
  ## key: 32 bytes (a wrap key or a sub key). label/place/num: Def. 1-3.
  ## body: what is sealed. Returns 51 + body.len bytes.
  var
    L: AmeSuiteLayout = archiveRecordLayout()
    t: AmeMaskTier = fullAmeMaskTier(L)
    salt: ByteSeq = archiveRandom(archiveSaltBytes)
    header: ByteSeq = encodeArchiveRecordHeader(num, salt)
    material: ByteSeq = @[]
    sealed: tuple[ciphertext: ByteSeq, authTag: ByteSeq] = (@[], @[])
  if key.len != archiveKeyBytes or label.len == 0:
    raise newException(ValueError, "archive record needs a 32-byte key and a label")
  material = archiveRecordBlock(key, label, place, num, salt, L, t)
  sealed = sealAmeTier(L, t, material, body,
    archiveRecordAad(label, place, header), aatl32)
  secureClearAmeBytes(material)
  result = header
  appendAmeBytes(result, sealed.authTag)
  appendAmeBytes(result, sealed.ciphertext)

proc openArchiveRecord*(key: openArray[uint8], label: string,
    place: openArray[uint8], A: openArray[uint8]): tuple[ok: bool,
    record: ArchiveRecord] {.role: decryptor,
    tag: "archive|appApi|cryptoBoundary".} =
  ## key/label/place: as sealed. A: the stored record. Nothing here raises:
  ## a wrong key, label, place, or any changed byte gives ok = false.
  var
    L: AmeSuiteLayout = archiveRecordLayout()
    t: AmeMaskTier = fullAmeMaskTier(L)
    material: ByteSeq = @[]
    opened: tuple[ok: bool, payload: ByteSeq] = (false, @[])
    num: uint16 = 0'u16
    tagEnd: int = archiveRecordHeaderBytes + archiveRecordTagBytes
  try:
    num = archiveRecordNum(A)
  except ValueError:
    return
  if key.len != archiveKeyBytes or label.len == 0:
    return
  material = archiveRecordBlock(key, label, place, num,
    A.toOpenArray(3, archiveRecordHeaderBytes - 1), L, t)
  opened = openAmeTier(L, t, material, A.toOpenArray(tagEnd, A.len - 1),
    A.toOpenArray(archiveRecordHeaderBytes, tagEnd - 1),
    archiveRecordAad(label, place, A.toOpenArray(0,
      archiveRecordHeaderBytes - 1)), aatl32)
  secureClearAmeBytes(material)
  if not opened.ok:
    return
  result = (true, ArchiveRecord(num: num, body: opened.payload))
