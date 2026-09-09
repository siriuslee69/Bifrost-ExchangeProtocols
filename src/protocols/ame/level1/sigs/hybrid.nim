## -------------------------------------------------------------------------
## AME Hybrid Signatures <- one Ed25519 and one Falcon claim, both required
## -------------------------------------------------------------------------
##
## A hybrid slot signs the same bytes twice and demands that BOTH verify.
## The point is survival of a break: if Ed25519 falls to a quantum computer,
## Falcon still holds; if Falcon falls to classical cryptanalysis, Ed25519
## still holds. An attacker must break both.
##
## Both halves are carried in one field, each behind its own 4-byte length,
## so nothing has to guess where one ends:
##
##   +--------+---------------+--------+---------------+
##   | len u32| ed25519 bytes | len u32| falcon bytes  |
##   +--------+---------------+--------+---------------+
##
## The same layout carries the keypair halves, so one slot still looks like
## one public key and one secret key to everything above.

import ../../../types
import ../../types
import ./types
import ./ed25519 as ame_ed25519
import ./falcon as ame_falcon
import runePragmas

proc appendPart(A: var ByteSeq, part: openArray[byte]) {.role: helper.} =
  ## A/part: destination and one length-prefixed half.
  if uint64(part.len) > uint64(high(uint32)):
    raise newException(ValueError, "AME hybrid signature half is too long")
  A.add(uint8(part.len and 0xff))
  A.add(uint8((part.len shr 8) and 0xff))
  A.add(uint8((part.len shr 16) and 0xff))
  A.add(uint8((part.len shr 24) and 0xff))
  for b in part:
    A.add(b)

proc framePair(first, second: openArray[byte]): ByteSeq {.role: helper.} =
  ## first/second: the Ed25519 half and the Falcon half, in that order.
  appendPart(result, first)
  appendPart(result, second)

proc parsePair(A: openArray[byte]): tuple[first, second: ByteSeq] {.
    role: parser.} =
  ## A: a framed pair. Any length that does not add up is rejected outright,
  ## so a truncated or padded field can never verify as a shorter claim.
  var
    offset: int = 0
    n: int = 0
    i: int = 0
  while i < 2:
    if offset + 4 > A.len:
      raise newException(ValueError, "AME hybrid payload is truncated")
    n = int(uint32(A[offset]) or (uint32(A[offset + 1]) shl 8) or
      (uint32(A[offset + 2]) shl 16) or (uint32(A[offset + 3]) shl 24))
    offset = offset + 4
    if n < 0 or offset + n > A.len:
      raise newException(ValueError, "AME hybrid payload length mismatch")
    if i == 0:
      result.first = @(A[offset ..< offset + n])
    else:
      result.second = @(A[offset ..< offset + n])
    offset = offset + n
    i = i + 1
  if offset != A.len:
    raise newException(ValueError, "AME hybrid payload has trailing bytes")

proc hybridClassicalSlot(a: AmeSignatureAlgorithm): AmeSignatureAlgorithm {.
    role: parser.} =
  ## a: hybrid slot whose Ed25519 half is named.
  if a notin {asaEd25519Falcon512Hybrid, asaEd25519Falcon1024Hybrid}:
    raise newException(ValueError,
      "AME signature slot is not a hybrid: " & ameSigName(a))
  result = asaEd25519

proc hybridPqSlot(a: AmeSignatureAlgorithm): AmeSignatureAlgorithm {.
    role: parser.} =
  ## a: hybrid slot whose Falcon half is named.
  case a
  of asaEd25519Falcon512Hybrid: result = asaFalcon512
  of asaEd25519Falcon1024Hybrid: result = asaFalcon1024
  else:
    raise newException(ValueError,
      "AME signature slot is not a hybrid: " & ameSigName(a))

proc hybridAmeKeypair*(a: AmeSignatureAlgorithm,
    seed: openArray[byte] = []): AmeSigKeypair {.role: truthBuilder.} =
  ## a/seed: hybrid slot, and optional fixed randomness shared by both halves.
  var
    classical = ame_ed25519.ed25519AmeKeypair(hybridClassicalSlot(a), seed)
    pq = ame_falcon.falconAmeKeypair(hybridPqSlot(a), seed)
  result.publicKey = framePair(classical.publicKey, pq.publicKey)
  result.secretKey = framePair(classical.secretKey, pq.secretKey)

proc hybridAmeSign*(a: AmeSignatureAlgorithm,
    msg, secretKey: openArray[byte]): ByteSeq {.role: encryptor.} =
  ## a/msg/secretKey: hybrid slot, subject bytes, and the framed secret pair.
  var keys = parsePair(secretKey)
  result = framePair(
    ame_ed25519.ed25519AmeSign(hybridClassicalSlot(a), msg, keys.first),
    ame_falcon.falconAmeSign(hybridPqSlot(a), msg, keys.second))

proc hybridAmeVerify*(a: AmeSignatureAlgorithm,
    msg, sig, publicKey: openArray[byte]): bool {.role: parser.} =
  ## a/msg/sig/publicKey: hybrid slot and the claim to check. Both halves
  ## must verify; either one failing fails the whole slot.
  var
    sigs: tuple[first, second: ByteSeq]
    keys: tuple[first, second: ByteSeq]
  try:
    sigs = parsePair(sig)
    keys = parsePair(publicKey)
  except ValueError:
    return false
  if not ame_ed25519.ed25519AmeVerify(hybridClassicalSlot(a), msg, sigs.first,
      keys.first):
    return false
  result = ame_falcon.falconAmeVerify(hybridPqSlot(a), msg, sigs.second,
    keys.second)
