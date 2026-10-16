## -------------------------------------------------------------------------
## AME ML-KEM <- the ML-KEM KEM slots, mapped onto Tyr
## -------------------------------------------------------------------------

import tyr/kems/mlkem as tyr_mlkem

import ../../../types
import ../../types
import ./types
import runePragmas

proc mlkemVariant(a: AmeKemAlgorithm): tyr_mlkem.MlKemVariant {.role: parser.} =
  ## a: AME slot resolved to the Tyr variant that executes it.
  case a
  of akaMlKem1024: result = tyr_mlkem.mlkem1024
  of akaMlKem768: result = tyr_mlkem.mlkem768
  else:
    raise newException(ValueError, "AME KEM slot is not ML-KEM: " & ameKemName(a))

proc mlkemAmeKeypair*(a: AmeKemAlgorithm): AmeKemKeypair {.role: truthBuilder.} =
  ## a: ML-KEM slot to key independently.
  assignAmeKeypair(tyr_mlkem.mlkemTyrKeypair(mlkemVariant(a)))

proc mlkemAmeSeal*(a: AmeKemAlgorithm,
    publicKey: openArray[byte]): AmeKemCipher {.role: encryptor.} =
  ## a/publicKey: ML-KEM slot and the receiver's public key.
  assignAmeCipher(tyr_mlkem.mlkemTyrEncaps(mlkemVariant(a), publicKey))

proc mlkemAmeOpen*(a: AmeKemAlgorithm, env: AmeKemCipher,
    secretKey: openArray[byte]): ByteSeq {.role: decryptor.} =
  ## a/env/secretKey: ML-KEM slot, received envelope, and our secret key.
  result = tyr_mlkem.mlkemTyrDecaps(mlkemVariant(a), secretKey,
    env.envelope.ciphertext)
