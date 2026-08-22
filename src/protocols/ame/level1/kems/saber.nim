## -------------------------------------------------------------------------
## AME Saber <- the Saber KEM slots, mapped onto Tyr
## -------------------------------------------------------------------------

import tyr/kems/saber as tyr_saber

import ../../../types
import ../../types
import ./types
import ../../../../analysis_pragmas

proc saberVariant(a: AmeKemAlgorithm): tyr_saber.SaberVariant {.role: parser.} =
  ## a: AME slot resolved to the Tyr variant that executes it.
  case a
  of akaFireSaber: result = tyr_saber.fireSaber
  of akaSaber: result = tyr_saber.saber
  of akaLightSaber: result = tyr_saber.lightSaber
  else:
    raise newException(ValueError, "AME KEM slot is not Saber: " & ameKemName(a))

proc saberAmeKeypair*(a: AmeKemAlgorithm): AmeKemKeypair {.role: wrapper.} =
  ## a: Saber slot to key independently.
  assignAmeKeypair(tyr_saber.saberTyrKeypair(saberVariant(a)))

proc saberAmeSeal*(a: AmeKemAlgorithm,
    publicKey: openArray[byte]): AmeKemCipher {.role: encryptor.} =
  ## a/publicKey: Saber slot and the receiver's public key.
  assignAmeCipher(tyr_saber.saberTyrEncaps(saberVariant(a), publicKey))

proc saberAmeOpen*(a: AmeKemAlgorithm, env: AmeKemCipher,
    secretKey: openArray[byte]): ByteSeq {.role: decryptor.} =
  ## a/env/secretKey: Saber slot, received envelope, and our secret key.
  result = tyr_saber.saberTyrDecaps(saberVariant(a), secretKey,
    env.envelope.ciphertext)
