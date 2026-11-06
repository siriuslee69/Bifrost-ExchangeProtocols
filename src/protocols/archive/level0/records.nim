## -------------------------------------------------------------------------
## Archive Records <- the byte layouts, written and read, nothing sealed here
## -------------------------------------------------------------------------
##
## Every number is little-endian. Every layout has a fixed size, except the
## sealed body that follows a header.
##
## ╭─ ❧ Def. 1: password settings, fixed 42 B, unencrypted 🌊
##
##   offset 0     1           5         9             10                42
##          +-----+-----------+---------+-------------+-------------------+
##          | ver | memoryKiB | passes  | parallelism | userSalt          |
##          | u8  | u32       | u32     | u8          | 32 B random       |
##          +-----+-----------+---------+-------------+-------------------+
##
## ╭─ ❧ Def. 2: sealed record header, 19 B, then tag 32 B, then body 🐦‍🔥
##
##   offset 0     1      3              19          51
##          +-----+------+--------------+-----------+------------------+
##          | ver | num  | salt         | tag       | sealed body      |
##          | u8  | u16  | 16 B random  | 32 B      | n bytes          |
##          +-----+------+--------------+-----------+------------------+
##
## ╭─ ❧ Def. 3: log record header, 29 B, then tag T, then body 🍣
##
##   offset 0     1      3        7        11      13             29      29+T
##          +-----+------+--------+--------+-------+--------------+-------+------+
##          | ver | gen  | lane   | epoch  | index | salt         | tag   | body |
##          | u8  | u16  | u32    | u32    | u16   | 16 B random  | T B   | n B  |
##          +-----+------+--------+--------+-------+--------------+-------+------+
##
## ╭─ ❧ Def. 4: position, 12 B, for one record to point at another ⟡
##
##          +--------+------+--------+-------+
##          | lane   | gen  | epoch  | index |
##          | u32    | u16  | u32    | u16   |
##          +--------+------+--------+-------+
##
## Example 1. Position (gen 1, lane 0xA1B2C3D4, epoch 2, index 255):
##
##   D4 C3 B2 A1 | 01 00 | 02 00 00 00 | FF 00

import ../../types
import ../../ame/level0/bytes
import ../types
import runePragmas
import var_invariants

proc readArchiveU16(A: openArray[uint8], o: int): uint16 {.role: parser,
    inline, needs: o >= 0 and o + 2 <= A.len.} =
  ## A/o: two bytes at o, little-endian.
  result = uint16(A[o]) or (uint16(A[o + 1]) shl 8)

proc readArchiveU32(A: openArray[uint8], o: int): uint32 {.role: parser,
    inline, needs: o >= 0 and o + 4 <= A.len.} =
  ## A/o: four bytes at o, little-endian.
  result = uint32(A[o]) or (uint32(A[o + 1]) shl 8) or
    (uint32(A[o + 2]) shl 16) or (uint32(A[o + 3]) shl 24)

proc encodeArchiveSettings*(S: ArchivePasswordSettings): ByteSeq {.
    role: dataWriter, tag: "archive|wire",
    gives: result.len == archiveSettingsBytes.} =
  ## S: Def. 1.
  if S.userSalt.len != archiveKeyBytes:
    raise newException(ValueError, "archive userSalt must be 32 bytes")
  result.add(archiveRecordVersion)
  appendAmeU32(result, S.memoryKiB)
  appendAmeU32(result, S.passes)
  result.add(S.parallelism)
  appendAmeBytes(result, S.userSalt)

proc decodeArchiveSettings*(A: openArray[uint8]): ArchivePasswordSettings {.
    role: parser, tag: "archive|wire".} =
  ## A: exactly 42 bytes (Def. 1). Raises on anything else.
  if A.len != archiveSettingsBytes or A[0] != archiveRecordVersion:
    raise newException(ValueError, "archive settings are malformed")
  result.memoryKiB = readArchiveU32(A, 1)
  result.passes = readArchiveU32(A, 5)
  result.parallelism = A[9]
  result.userSalt = @(A.toOpenArray(10, 41))

proc encodeArchiveRecordHeader*(num: uint16, salt: openArray[uint8]): ByteSeq {.
    role: dataWriter, tag: "archive|wire",
    gives: result.len == archiveRecordHeaderBytes.} =
  ## num/salt: Def. 2, the 19 bytes in front of the tag.
  if salt.len != archiveSaltBytes:
    raise newException(ValueError, "archive salt must be 16 bytes")
  result.add(archiveRecordVersion)
  appendAmeU16(result, num)
  appendAmeBytes(result, salt)

proc archiveRecordNum*(A: openArray[uint8]): uint16 {.role: parser,
    tag: "archive|wire".} =
  ## A: a sealed record; its `num`, read without opening it. Raises when A
  ## is too short to be one.
  if A.len < archiveRecordHeaderBytes + archiveRecordTagBytes or
      A[0] != archiveRecordVersion:
    raise newException(ValueError, "archive record is malformed")
  result = readArchiveU16(A, 1)

proc encodeArchivePosition*(P: ArchivePosition): ByteSeq {.role: dataWriter,
    tag: "archive|wire", gives: result.len == archivePositionBytes.} =
  ## P: Def. 4.
  appendAmeU32(result, P.lane)
  appendAmeU16(result, P.gen)
  appendAmeU32(result, P.epoch)
  appendAmeU16(result, P.index)

proc decodeArchivePosition*(A: openArray[uint8]): ArchivePosition {.
    role: parser, tag: "archive|wire".} =
  ## A: exactly 12 bytes (Def. 4).
  if A.len != archivePositionBytes:
    raise newException(ValueError, "archive position must be 12 bytes")
  result.lane = readArchiveU32(A, 0)
  result.gen = readArchiveU16(A, 4)
  result.epoch = readArchiveU32(A, 6)
  result.index = readArchiveU16(A, 10)

proc encodeArchiveLogHeader*(P: ArchivePosition,
    salt: openArray[uint8]): ByteSeq {.role: dataWriter, tag: "archive|wire",
    gives: result.len == archiveLogHeaderBytes.} =
  ## P/salt: Def. 3, the 29 bytes in front of the tag.
  if salt.len != archiveSaltBytes:
    raise newException(ValueError, "archive salt must be 16 bytes")
  result.add(archiveRecordVersion)
  appendAmeU16(result, P.gen)
  appendAmeU32(result, P.lane)
  appendAmeU32(result, P.epoch)
  appendAmeU16(result, P.index)
  appendAmeBytes(result, salt)

proc decodeArchiveLogRecord*(A: openArray[uint8],
    tagLen: int): ArchiveLogRecord {.role: parser, tag: "archive|wire".} =
  ## A/tagLen: one log record (Def. 3) and the tag length its space agreed.
  ## The tag length is never read from the record itself.
  if A.len < archiveLogHeaderBytes + tagLen or A[0] != archiveRecordVersion:
    raise newException(ValueError, "archive log record is malformed")
  result.position.gen = readArchiveU16(A, 1)
  result.position.lane = readArchiveU32(A, 3)
  result.position.epoch = readArchiveU32(A, 7)
  result.position.index = readArchiveU16(A, 11)
  result.salt = @(A.toOpenArray(13, 28))
  result.tag = @(A.toOpenArray(29, 29 + tagLen - 1))
  result.ciphertext = @(A.toOpenArray(29 + tagLen, A.len - 1))

proc archiveLogGen*(A: openArray[uint8]): uint16 {.role: parser,
    tag: "archive|wire".} =
  ## A: a log record; its generation, read without opening it, so the caller
  ## can pick the space secret of that generation first.
  if A.len < archiveLogHeaderBytes or A[0] != archiveRecordVersion:
    raise newException(ValueError, "archive log record is malformed")
  result = readArchiveU16(A, 1)

proc nextArchivePosition*(P: ArchivePosition,
    epochSize: uint16): ArchivePosition {.role: math, tag: "archive",
    needs: epochSize > 0'u16 and P.index < epochSize.} =
  ## P/epochSize: the position after P on the same lane. Index E-1 is
  ## followed by index 0 of the next epoch (Def. 3 of ../types).
  result = P
  if P.index + 1'u16 < epochSize:
    result.index = P.index + 1'u16
    return
  if P.epoch == high(uint32):
    raise newException(ValueError, "archive lane is exhausted")
  result.epoch = P.epoch + 1'u32
  result.index = 0'u16
