## -------------------------------------------------------------------------
## AME McEliece <- the Classic McEliece KEM slots, mapped onto Tyr
## -------------------------------------------------------------------------
##
## The largest family by far: its public keys are measured in hundreds of
## kilobytes. Leave it out of small builds unless a peer requires it.

import tyr/kems/mceliece as tyr_mceliece

import ../../../types
import ../../types
import ./types
import ../../../../analysis_pragmas

proc mcelieceVariant(a: AmeKemAlgorithm): tyr_mceliece.McElieceVariant {.
    role: parser.} =
  ## a: AME slot resolved to the Tyr variant that executes it.
  case a
  of akaMcEliece8192: result = tyr_mceliece.mceliece8192128f
  of akaMcEliece6960: result = tyr_mceliece.mceliece6960119f
  of akaMcEliece6688: result = tyr_mceliece.mceliece6688128f
  else:
    raise newException(ValueError,
      "AME KEM slot is not McEliece: " & ameKemName(a))

proc mcelieceAmeKeypair*(a: AmeKemAlgorithm): AmeKemKeypair {.role: truthBuilder.} =
  ## a: McEliece slot to key independently.
  assignAmeKeypair(tyr_mceliece.mcelieceTyrKeypair(mcelieceVariant(a)))

proc mcelieceAmeSeal*(a: AmeKemAlgorithm,
    publicKey: openArray[byte]): AmeKemCipher {.role: encryptor.} =
  ## a/publicKey: McEliece slot and the receiver's public key.
  assignAmeCipher(tyr_mceliece.mcelieceTyrEncaps(mcelieceVariant(a), publicKey))

proc mcelieceAmeOpen*(a: AmeKemAlgorithm, env: AmeKemCipher,
    secretKey: openArray[byte]): ByteSeq {.role: decryptor.} =
  ## a/env/secretKey: McEliece slot, received envelope, and our secret key.
  result = tyr_mceliece.mcelieceTyrDecaps(mcelieceVariant(a), secretKey,
    env.envelope.ciphertext)
