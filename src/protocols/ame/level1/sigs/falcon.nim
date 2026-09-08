## -------------------------------------------------------------------------
## AME Falcon <- the Falcon signature slots, mapped onto Tyr
## -------------------------------------------------------------------------

import tyr/signatures/falcon as tyr_falcon

import ../../../types
import ../../types
import ./types
import bifrostPragmas

proc falconVariant*(a: AmeSignatureAlgorithm): tyr_falcon.FalconVariant {.
    role: parser.} =
  ## a: AME slot resolved to the Tyr variant that executes it. Exported so
  ## the hybrid slots can name their Falcon half without a second table.
  case a
  of asaFalcon512, asaEd25519Falcon512Hybrid: result = tyr_falcon.falcon512
  of asaFalcon1024, asaEd25519Falcon1024Hybrid: result = tyr_falcon.falcon1024
  else:
    raise newException(ValueError,
      "AME signature slot is not Falcon: " & ameSigName(a))

proc falconAmeKeypair*(a: AmeSignatureAlgorithm,
    seed: openArray[byte] = []): AmeSigKeypair {.role: truthBuilder.} =
  ## a/seed: Falcon slot, and optional fixed randomness.
  if seed.len == 0:
    assignAmeSigKeypair(tyr_falcon.falconTyrKeypair(falconVariant(a)))
  else:
    assignAmeSigKeypair(tyr_falcon.falconTyrKeypair(falconVariant(a), seed))

proc falconAmeSign*(a: AmeSignatureAlgorithm,
    msg, secretKey: openArray[byte]): ByteSeq {.role: encryptor.} =
  ## a/msg/secretKey: Falcon slot, subject bytes, and our secret key.
  result = tyr_falcon.falconTyrSign(falconVariant(a), msg, secretKey)

proc falconAmeVerify*(a: AmeSignatureAlgorithm,
    msg, sig, publicKey: openArray[byte]): bool {.role: parser.} =
  ## a/msg/sig/publicKey: Falcon slot and the claim to check.
  result = tyr_falcon.falconTyrVerify(falconVariant(a), msg, sig, publicKey)
