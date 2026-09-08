## -------------------------------------------------------------------------
## AME Ed25519 <- the classical signature slot, mapped onto Tyr
## -------------------------------------------------------------------------

import tyr/signatures/ed25519 as tyr_ed25519

import ../../../types
import ../../types
import ./types
import bifrostPragmas

proc requireEd25519Slot(a: AmeSignatureAlgorithm) {.role: parser.} =
  ## a: slot rejected unless it is the Ed25519 slot.
  if a != asaEd25519:
    raise newException(ValueError,
      "AME signature slot is not Ed25519: " & ameSigName(a))

proc ed25519AmeKeypair*(a: AmeSignatureAlgorithm,
    seed: openArray[byte] = []): AmeSigKeypair {.role: truthBuilder.} =
  ## a/seed: the Ed25519 slot, and optional fixed randomness.
  requireEd25519Slot(a)
  if seed.len == 0:
    assignAmeSigKeypair(tyr_ed25519.ed25519TyrKeypair())
  else:
    assignAmeSigKeypair(tyr_ed25519.ed25519TyrKeypairFromSeed(seed))

proc ed25519AmeSign*(a: AmeSignatureAlgorithm,
    msg, secretKey: openArray[byte]): ByteSeq {.role: encryptor.} =
  ## a/msg/secretKey: the Ed25519 slot, subject bytes, and our secret key.
  requireEd25519Slot(a)
  result = tyr_ed25519.ed25519TyrSign(msg, secretKey)

proc ed25519AmeVerify*(a: AmeSignatureAlgorithm,
    msg, sig, publicKey: openArray[byte]): bool {.role: parser.} =
  ## a/msg/sig/publicKey: the Ed25519 slot and the claim to check.
  requireEd25519Slot(a)
  result = tyr_ed25519.ed25519TyrVerify(msg, sig, publicKey)
