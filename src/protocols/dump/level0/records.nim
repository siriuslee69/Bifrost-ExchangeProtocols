## -------------------------------------------------------------------------
## Dump Records <- one waiting message as bytes, and "how far am I" as bytes
## -------------------------------------------------------------------------
##
## The caller may keep records in this form, or send them to another machine.
## Every number is little-endian.
##
## ╭─ ❧ Def. 1: one record 🌊
##
##   +-----+--------------+--------+-------+--------------+-------------+
##   | ver | u16 + stream | number | atMs  | u16 + sender | u32 + body  |
##   | u8  |              | u64    | u64   |              |             |
##   +-----+--------------+--------+-------+--------------+-------------+
##
## ╭─ ❧ Def. 2: cursors, "everything up to here is on my disk" 🍣
##
##   +-------+-------------------------------+
##   | count | count x (u16 + stream | u64)  |
##   | u16   |                               |
##   +-------+-------------------------------+
##
## Example 1. Stream "a", number 2, atMs 3, sender "s", body FF:
##
##   01 | 01 00 61 | 02 00.. | 03 00.. | 01 00 73 | 01 00 00 00 FF

import ../../types
import ../../ame/level0/bytes
import ../types
import runePragmas

proc appendDumpName(A: var ByteSeq, s: string) {.role: dataWriter, inline.} =
  ## A/s: s with its u16 length in front.
  requireAmeU16Len(s.len, "dump name")
  appendAmeU16(A, uint16(s.len))
  appendAmeBytes(A, toOpenArrayByte(s, 0, s.len - 1))

proc takeDumpName(A: openArray[uint8], o: var int): string {.role: parser.} =
  ## A/o: a u16-sized name at o; o moves past it. Raises when it runs out.
  var
    n: int = 0
  if o + 2 > A.len:
    raise newException(ValueError, "dump record is short")
  n = int(readAmeU16(A, o))
  if n > dumpNameMax or o + 2 + n > A.len:
    raise newException(ValueError, "dump record is short")
  result = newString(n)
  if n > 0:
    copyMem(addr result[0], unsafeAddr A[o + 2], n)
  o = o + 2 + n

proc takeDumpU64(A: openArray[uint8], o: var int): uint64 {.role: parser.} =
  ## A/o: a u64 at o; o moves past it. Raises when it runs out.
  if o + 8 > A.len:
    raise newException(ValueError, "dump record is short")
  result = readAmeU64(A, o)
  o = o + 8

proc encodeDumpRecord*(R: DumpRecord): ByteSeq {.role: dataWriter,
    tag: "dump|wire".} =
  ## R: Def. 1.
  result.add(dumpRecordVersion)
  appendDumpName(result, R.stream)
  appendAmeU64(result, R.number)
  appendAmeU64(result, R.atMs)
  appendDumpName(result, R.sender)
  requireAmeU32Len(R.body.len, "dump body")
  appendAmeU32(result, uint32(R.body.len))
  appendAmeBytes(result, R.body)

proc decodeDumpRecord*(A: openArray[uint8], o: var int): DumpRecord {.
    role: parser, tag: "dump|wire".} =
  ## A/o: one record at o; o moves past it. Raises on anything malformed.
  var
    n: int = 0
  if o >= A.len or A[o] != dumpRecordVersion:
    raise newException(ValueError, "dump record has an unknown version")
  o = o + 1
  result.stream = takeDumpName(A, o)
  result.number = takeDumpU64(A, o)
  result.atMs = takeDumpU64(A, o)
  result.sender = takeDumpName(A, o)
  if o + 4 > A.len:
    raise newException(ValueError, "dump record is short")
  n = int(A[o]) or (int(A[o + 1]) shl 8) or (int(A[o + 2]) shl 16) or
    (int(A[o + 3]) shl 24)
  if n < 0 or o + 4 + n > A.len:
    raise newException(ValueError, "dump record is short")
  result.body = @(A.toOpenArray(o + 4, o + 4 + n - 1))
  o = o + 4 + n

proc encodeDumpCursors*(C: openArray[tuple[stream: string,
    settled: uint64]]): ByteSeq {.role: dataWriter, tag: "dump|wire".} =
  ## C: Def. 2.
  requireAmeU16Len(C.len, "dump cursor count")
  appendAmeU16(result, uint16(C.len))
  for x in C:
    appendDumpName(result, x.stream)
    appendAmeU64(result, x.settled)

proc decodeDumpCursors*(A: openArray[uint8]): seq[tuple[stream: string,
    settled: uint64]] {.role: parser, tag: "dump|wire".} =
  ## A: Def. 2. Raises on anything malformed.
  var
    o: int = 2
    n: int = 0
    i: int = 0
    name: string = ""
  if A.len < 2:
    raise newException(ValueError, "dump cursors are short")
  n = int(readAmeU16(A, 0))
  while i < n:
    name = takeDumpName(A, o)
    result.add((name, takeDumpU64(A, o)))
    i = i + 1
  if o != A.len:
    raise newException(ValueError, "dump cursors have trailing bytes")
