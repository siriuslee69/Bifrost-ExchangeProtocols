## -------------------------------------------------------------------------
## AME Kyber <- the Kyber KEM slots, mapped onto Tyr
## -------------------------------------------------------------------------

import tyr/kems/kyber as tyr_kyber

import ../../../types
import ../../types
import ./types
import ../../../../analysis_pragmas

proc kyberVariant(a: AmeKemAlgorithm): tyr_kyber.KyberVariant {.role: parser.} =
  ## a: AME slot resolved to the Tyr variant that executes it.
  case a
  of akaKyber1024: result = tyr_kyber.kyber1024
  of akaKyber768: result = tyr_kyber.kyber768
  else:
    raise newException(ValueError, "AME KEM slot is not Kyber: " & ameKemName(a))

proc kyberAmeKeypair*(a: AmeKemAlgorithm): AmeKemKeypair {.role: truthBuilder.} =
  ## a: Kyber slot to key independently.
  assignAmeKeypair(tyr_kyber.kyberTyrKeypair(kyberVariant(a)))

proc kyberAmeSeal*(a: AmeKemAlgorithm,
    publicKey: openArray[byte]): AmeKemCipher {.role: encryptor.} =
  ## a/publicKey: Kyber slot and the receiver's public key.
  assignAmeCipher(tyr_kyber.kyberTyrEncaps(kyberVariant(a), publicKey))

proc kyberAmeOpen*(a: AmeKemAlgorithm, env: AmeKemCipher,
    secretKey: openArray[byte]): ByteSeq {.role: decryptor.} =
  ## a/env/secretKey: Kyber slot, received envelope, and our secret key.
  result = tyr_kyber.kyberTyrDecaps(kyberVariant(a), secretKey,
    env.envelope.ciphertext)
