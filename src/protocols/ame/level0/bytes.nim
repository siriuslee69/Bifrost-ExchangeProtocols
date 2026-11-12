## ----------------------------------------------------------
## AME Bytes <- shared byte framing, xor, and compare helpers
## ----------------------------------------------------------

import tyr/helpers/secure_memory as tyr_secure_memory

import ../../types
import var_invariants
import runePragmas

proc appendAmeBytes*(dst: var ByteSeq, src: openArray[byte]) {.role: dataWriter.} =
  ## dst: destination byte sequence.
  ## src: bytes to append.
  for b in src:
    dst.add(b)

proc appendAmeLabel*(dst: var ByteSeq, label: string) {.role: dataWriter.} =
  ## dst: destination byte sequence.
  ## label: ASCII label bytes to append.
  for ch in label:
    dst.add(uint8(ord(ch)))

proc xorAmeInto*(dst: var ByteSeq, src: openArray[byte]) {.role: dataWriter.} =
  ## dst: destination byte sequence.
  ## src: source bytes with the same length.
  var
    i: int = 0
  if dst.len != src.len:
    raise newException(ValueError, "AME xor-in length mismatch")
  while i < dst.len:
    dst[i] = dst[i] xor src[i]
    i = i + 1

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

proc secureClearAmeBytes*(A: var ByteSeq) {.role: actor.} =
  ## A: secret bytes overwritten before their storage is released.
  tyr_secure_memory.secureClearBytes(A)
  A.setLen(0)

proc clearSecretRows*(S: var seq[ByteSeq]) {.role: actor,
    gives: S.len == 0.} =
  ## S: secret rows (keys, shared secrets, memory blocks). Every row is
  ## overwritten, then the list itself is emptied. The one routine every
  ## handshake, FOMKE and epoch erase goes through:
  ##
  ##   before   S = [ row0 | row1 | row2 ]        three secrets in memory
  ##   after    S = [ ]                           each row overwritten first
  var
    i: int = 0
  while i < S.len:
    secureClearAmeBytes(S[i])
    i = i + 1
  S.setLen(0)
