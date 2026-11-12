## ----------------------------------------------------------------------
## Byte Codec <- the byte helpers every protocol in this repo shares
## ----------------------------------------------------------------------
##
## One copy of each. AME, DAC, the transport, FOMKE, TLS and mail all import
## it, so a fix made here reaches all of them.
##
##   write a number     appendU16Le  appendU32Le  appendU64Le   (little-endian)
##   read a number      readU16Le    readU32Le    readU64Le
##   text <-> bytes     stringToBytes  bytesToString  readText
##   look at bytes      isAllZero   constantTimeEqual
##
## "Little-endian" means the SMALLEST byte goes first:
##
##   appendU32Le(B, 0x11223344'u32)      B = [ 44 | 33 | 22 | 11 ]
##                                              ^ first byte out
##
## Every reader refuses an offset that would reach past the end (`needs`),
## so a short frame can never be read beyond what it holds.
##
## This module depends on `protocols/types` only, so it sits under every
## protocol. Wiping secret rows stays in `ame/level0/bytes`, beside the
## secure-memory call it needs.

import ./types
import var_invariants
import runePragmas

proc appendU16Le*(dst: var ByteSeq, v: uint16) {.role: dataWriter.} =
  ## dst: destination byte sequence.
  ## v: uint16 written as two bytes, smallest first.
  dst.add(uint8(v and 0xff'u16))
  dst.add(uint8((v shr 8) and 0xff'u16))

proc appendU32Le*(dst: var ByteSeq, v: uint32) {.role: dataWriter.} =
  ## dst: destination byte sequence.
  ## v: uint32 written as four bytes, smallest first.
  dst.add(uint8(v and 0xff'u32))
  dst.add(uint8((v shr 8) and 0xff'u32))
  dst.add(uint8((v shr 16) and 0xff'u32))
  dst.add(uint8((v shr 24) and 0xff'u32))

proc appendU64Le*(dst: var ByteSeq, v: uint64) {.role: dataWriter.} =
  ## dst: destination byte sequence.
  ## v: uint64 written as eight bytes, smallest first.
  var
    i: int = 0
  while i < 8:
    dst.add(uint8((v shr (8 * i)) and 0xff'u64))
    i = i + 1

proc readU16Le*(A: openArray[uint8], o: int): uint16 {.role: parser,
    needs: o >= 0 and o <= A.len - 2.} =
  ## A/o: source bytes and the offset of a little-endian uint16.
  result = uint16(A[o]) or (uint16(A[o + 1]) shl 8)

proc readU32Le*(A: openArray[uint8], o: int): uint32 {.role: parser,
    needs: o >= 0 and o <= A.len - 4.} =
  ## A/o: source bytes and the offset of a little-endian uint32.
  result = uint32(A[o]) or (uint32(A[o + 1]) shl 8) or
    (uint32(A[o + 2]) shl 16) or (uint32(A[o + 3]) shl 24)

proc readU64Le*(A: openArray[uint8], o: int): uint64 {.role: parser,
    needs: o >= 0 and o <= A.len - 8.} =
  ## A/o: source bytes and the offset of a little-endian uint64.
  var
    i: int = 0
  while i < 8:
    result = result or (uint64(A[o + i]) shl (8 * i))
    i = i + 1

proc stringToBytes*(s: string): ByteSeq {.role: helper,
    gives: result.len == s.len.} =
  ## s: text whose characters are copied one for one into bytes.
  ##
  ## An explicit copy rather than a cast: `string` and `seq[byte]` happen to
  ## share a layout today, but relying on that turns a future runtime change
  ## into silent memory corruption.
  var
    i: int = 0
  result = newSeq[uint8](s.len)
  while i < s.len:
    result[i] = uint8(ord(s[i]))
    i = i + 1

proc bytesToString*(A: openArray[uint8]): string {.role: helper,
    gives: result.len == A.len.} =
  ## A: bytes whose values are copied one for one into characters.
  var
    i: int = 0
  result = newString(A.len)
  while i < A.len:
    result[i] = char(A[i])
    i = i + 1

proc readText*(A: openArray[uint8], o, n: int): string {.role: parser,
    needs: o >= 0 and n >= 0 and o <= A.len - n,
    gives: result.len == n.} =
  ## A/o/n: `n` bytes starting at offset `o`, read out as text. The caller
  ## has already checked the length against the frame it came from.
  var
    i: int = 0
  result = newString(n)
  while i < n:
    result[i] = char(A[o + i])
    i = i + 1

proc isAllZero*(A: openArray[uint8]): bool {.role: parser.} =
  ## A: bytes (a digest, for example). True when every byte is 0.
  var
    i: int = 0
  result = true
  while i < A.len:
    if A[i] != 0'u8:
      return false
    i = i + 1

proc constantTimeEqual*(A, B: openArray[byte]): bool {.role: helper,
    tag: "cryptoBoundary".} =
  ## A/B: two secrets, tags or digests. The time taken does not depend on
  ## WHERE they first differ: every byte of A is looked at either way. A
  ## length mismatch is a plain "not equal".
  var
    diff: uint = if A.len == B.len: 0'u else: 1'u
    i: int = 0
    b: byte = 0
  while i < A.len:
    b = if i < B.len: B[i] else: 0'u8
    diff = diff or uint(A[i] xor b)
    i = i + 1
  result = diff == 0'u
