## -------------------------------------------------------------------------
## AME Frodo <- the FrodoKEM slots, mapped onto Tyr
## -------------------------------------------------------------------------

import tyr/kems/frodo as tyr_frodo

import ../../../types
import ../../types
import ./types
import ../../../../analysis_pragmas

proc frodoVariant(a: AmeKemAlgorithm): tyr_frodo.FrodoVariant {.role: parser.} =
  ## a: AME slot resolved to the Tyr variant that executes it.
  case a
  of akaFrodo1344Aes: result = tyr_frodo.frodo1344aes
  of akaFrodo976Aes: result = tyr_frodo.frodo976aes
  of akaFrodo640Aes: result = tyr_frodo.frodo640aes
  else:
    raise newException(ValueError, "AME KEM slot is not Frodo: " & ameKemName(a))

proc frodoAmeKeypair*(a: AmeKemAlgorithm): AmeKemKeypair {.role: truthBuilder.} =
  ## a: Frodo slot to key independently.
  assignAmeKeypair(tyr_frodo.frodoTyrKeypair(frodoVariant(a)))

proc frodoAmeSeal*(a: AmeKemAlgorithm,
    publicKey: openArray[byte]): AmeKemCipher {.role: encryptor.} =
  ## a/publicKey: Frodo slot and the receiver's public key.
  assignAmeCipher(tyr_frodo.frodoTyrEncaps(frodoVariant(a), publicKey))

proc frodoAmeOpen*(a: AmeKemAlgorithm, env: AmeKemCipher,
    secretKey: openArray[byte]): ByteSeq {.role: decryptor.} =
  ## a/env/secretKey: Frodo slot, received envelope, and our secret key.
  result = tyr_frodo.frodoTyrDecaps(frodoVariant(a), secretKey,
    env.envelope.ciphertext)
