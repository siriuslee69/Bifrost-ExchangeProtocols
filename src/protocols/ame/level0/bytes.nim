## ----------------------------------------------------------
## AME Bytes <- shared byte framing, xor, and compare helpers
## ----------------------------------------------------------

import protocols/custom_crypto/symmetric/secure_memory as tyr_secure_memory

import ../../types
import ../../../analysis_pragmas

proc appendAmeBytes*(dst: var ByteSeq, src: openArray[byte]) {.role: stateController.} =
  ## dst: destination byte sequence.
  ## src: bytes to append.
  for b in src:
    dst.add(b)

proc appendAmeU16*(dst: var ByteSeq, v: uint16) {.role: stateController.} =
  ## dst: destination byte sequence.
  ## v: little-endian uint16 to append.
  dst.add(uint8(v and 0xff'u16))
  dst.add(uint8((v shr 8) and 0xff'u16))

proc appendAmeU32*(dst: var ByteSeq, v: uint32) {.role: stateController.} =
  ## dst: destination byte sequence.
  ## v: little-endian uint32 to append.
  dst.add(uint8(v and 0xff'u32))
  dst.add(uint8((v shr 8) and 0xff'u32))
  dst.add(uint8((v shr 16) and 0xff'u32))
  dst.add(uint8((v shr 24) and 0xff'u32))

proc appendAmeU64*(dst: var ByteSeq, v: uint64) {.role: stateController.} =
  ## dst: destination byte sequence.
  ## v: little-endian uint64 to append.
  var
    i: int = 0
  while i < 8:
    dst.add(uint8((v shr (8 * i)) and 0xff'u64))
    i = i + 1

proc appendAmeLabel*(dst: var ByteSeq, label: string) {.role: stateController.} =
  ## dst: destination byte sequence.
  ## label: ASCII label bytes to append.
  for ch in label:
    dst.add(uint8(ord(ch)))

proc copyAmeBytes*(src: openArray[byte]): ByteSeq {.role: helper.} =
  ## src: bytes to copy.
  var
    i: int = 0
  result = newSeq[byte](src.len)
  while i < src.len:
    result[i] = src[i]
    i = i + 1

proc xorAmeOverlay*(a, b: openArray[byte]): ByteSeq {.role: helper.} =
  ## a: first byte sequence.
  ## b: second byte sequence with the same length.
  var
    i: int = 0
  if a.len != b.len:
    raise newException(ValueError, "AME xor overlay length mismatch")
  result = newSeq[byte](a.len)
  while i < a.len:
    result[i] = a[i] xor b[i]
    i = i + 1

proc xorAmeInto*(dst: var ByteSeq, src: openArray[byte]) {.role: stateController.} =
  ## dst: destination byte sequence.
  ## src: source bytes with the same length.
  var
    i: int = 0
  if dst.len != src.len:
    raise newException(ValueError, "AME xor-in length mismatch")
  while i < dst.len:
    dst[i] = dst[i] xor src[i]
    i = i + 1

proc constantTimeEqualAme*(a, b: openArray[byte]): bool {.role: helper.} =
  ## a: first byte sequence.
  ## b: second byte sequence.
  var
    acc: uint8 = 0
    i: int = 0
  if a.len != b.len:
    return false
  while i < a.len:
    acc = acc or (a[i] xor b[i])
    i = i + 1
  result = acc == 0'u8

proc checkedAmeWireLen*(v: uint32, maximum: uint32,
    what: string): int {.role: parser.} =
  ## v/maximum/what: wire length, accepted maximum, and field label.
  if v > maximum or uint64(v) > uint64(high(int)):
    raise newException(ValueError, "AME " & what & " exceeds its limit")
  result = int(v)

proc requireAmeU16Len*(n: int, what: string) {.role: parser.} =
  ## n/what: host length and field label before a u16 wire conversion.
  if n < 0 or uint64(n) > uint64(high(uint16)):
    raise newException(ValueError, "AME " & what & " exceeds u16")

proc requireAmeU32Len*(n: int, what: string) {.role: parser.} =
  ## n/what: host length and field label before a u32 wire conversion.
  if n < 0 or uint64(n) > uint64(high(uint32)):
    raise newException(ValueError, "AME " & what & " exceeds u32")

proc secureClearAmeBytes*(A: var ByteSeq) {.role: stateController.} =
  ## A: secret bytes overwritten before their storage is released.
  tyr_secure_memory.secureClearBytes(A)
  A.setLen(0)
