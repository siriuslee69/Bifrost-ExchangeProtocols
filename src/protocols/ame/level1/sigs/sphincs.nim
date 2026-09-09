## -------------------------------------------------------------------------
## AME SPHINCS+ <- the hash-based signature slot, mapped onto Tyr
## -------------------------------------------------------------------------

import tyr/signatures/sphincs as tyr_sphincs

import ../../../types
import ../../types
import ./types
import runePragmas

proc sphincsVariant(a: AmeSignatureAlgorithm): tyr_sphincs.SphincsVariant {.
    role: parser.} =
  ## a: AME slot resolved to the Tyr variant that executes it.
  case a
  of asaSphincsShake128f: result = tyr_sphincs.sphincsShake128fSimple
  else:
    raise newException(ValueError,
      "AME signature slot is not SPHINCS+: " & ameSigName(a))

proc sphincsAmeKeypair*(a: AmeSignatureAlgorithm,
    seed: openArray[byte] = []): AmeSigKeypair {.role: truthBuilder.} =
  ## a/seed: SPHINCS+ slot, and optional fixed randomness.
  assignAmeSigKeypair(tyr_sphincs.sphincsTyrKeypair(sphincsVariant(a), @seed))

proc sphincsAmeSign*(a: AmeSignatureAlgorithm,
    msg, secretKey: openArray[byte]): ByteSeq {.role: encryptor.} =
  ## a/msg/secretKey: SPHINCS+ slot, subject bytes, and our secret key.
  result = tyr_sphincs.sphincsTyrSign(sphincsVariant(a), msg, secretKey)

proc sphincsAmeVerify*(a: AmeSignatureAlgorithm,
    msg, sig, publicKey: openArray[byte]): bool {.role: parser.} =
  ## a/msg/sig/publicKey: SPHINCS+ slot and the claim to check.
  result = tyr_sphincs.sphincsTyrVerify(sphincsVariant(a), msg, sig, publicKey)
