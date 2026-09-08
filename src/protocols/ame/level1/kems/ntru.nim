## -------------------------------------------------------------------------
## AME NTRU <- the NTRU KEM slots, mapped onto Tyr
## -------------------------------------------------------------------------

import tyr/kems/ntru as tyr_ntru

import ../../../types
import ../../types
import ./types
import bifrostPragmas

proc ntruVariant(a: AmeKemAlgorithm): tyr_ntru.NtruVariant {.role: parser.} =
  ## a: AME slot resolved to the Tyr variant that executes it.
  case a
  of akaNtruHps4096821: result = tyr_ntru.ntruHps4096821
  of akaNtruHps2048677: result = tyr_ntru.ntruHps2048677
  of akaNtruHps2048509: result = tyr_ntru.ntruHps2048509
  else:
    raise newException(ValueError, "AME KEM slot is not NTRU: " & ameKemName(a))

proc ntruAmeKeypair*(a: AmeKemAlgorithm): AmeKemKeypair {.role: truthBuilder.} =
  ## a: NTRU slot to key independently.
  assignAmeKeypair(tyr_ntru.ntruTyrKeypair(ntruVariant(a)))

proc ntruAmeSeal*(a: AmeKemAlgorithm,
    publicKey: openArray[byte]): AmeKemCipher {.role: encryptor.} =
  ## a/publicKey: NTRU slot and the receiver's public key.
  assignAmeCipher(tyr_ntru.ntruTyrEncaps(ntruVariant(a), publicKey))

proc ntruAmeOpen*(a: AmeKemAlgorithm, env: AmeKemCipher,
    secretKey: openArray[byte]): ByteSeq {.role: decryptor.} =
  ## a/env/secretKey: NTRU slot, received envelope, and our secret key.
  result = tyr_ntru.ntruTyrDecaps(ntruVariant(a), secretKey,
    env.envelope.ciphertext)
