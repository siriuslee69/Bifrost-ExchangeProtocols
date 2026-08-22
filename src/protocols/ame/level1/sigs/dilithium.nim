## -------------------------------------------------------------------------
## AME Dilithium <- the ML-DSA signature slots, mapped onto Tyr
## -------------------------------------------------------------------------

import tyr/signatures/dilithium as tyr_dilithium

import ../../../types
import ../../types
import ./types
import ../../../../analysis_pragmas

proc dilithiumVariant(a: AmeSignatureAlgorithm):
    tyr_dilithium.DilithiumVariant {.role: parser.} =
  ## a: AME slot resolved to the Tyr variant that executes it.
  case a
  of asaDilithium44: result = tyr_dilithium.dilithium44
  of asaDilithium65: result = tyr_dilithium.dilithium65
  of asaDilithium87: result = tyr_dilithium.dilithium87
  else:
    raise newException(ValueError,
      "AME signature slot is not Dilithium: " & ameSigName(a))

proc dilithiumAmeKeypair*(a: AmeSignatureAlgorithm,
    seed: openArray[byte] = []): AmeSigKeypair {.role: wrapper.} =
  ## a/seed: Dilithium slot, and optional fixed randomness.
  assignAmeSigKeypair(tyr_dilithium.dilithiumTyrKeypair(dilithiumVariant(a),
    @seed))

proc dilithiumAmeSign*(a: AmeSignatureAlgorithm,
    msg, secretKey: openArray[byte]): ByteSeq {.role: encryptor.} =
  ## a/msg/secretKey: Dilithium slot, subject bytes, and our secret key.
  result = tyr_dilithium.dilithiumTyrSign(dilithiumVariant(a), msg, secretKey)

proc dilithiumAmeVerify*(a: AmeSignatureAlgorithm,
    msg, sig, publicKey: openArray[byte]): bool {.role: parser.} =
  ## a/msg/sig/publicKey: Dilithium slot and the claim to check.
  result = tyr_dilithium.dilithiumTyrVerify(dilithiumVariant(a), msg, sig,
    publicKey)
