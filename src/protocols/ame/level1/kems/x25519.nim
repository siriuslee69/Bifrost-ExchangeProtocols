## -------------------------------------------------------------------------
## AME X25519 <- the classical Diffie-Hellman slot, mapped onto Tyr
## -------------------------------------------------------------------------
##
## X25519 is not a true encapsulation scheme: instead of a ciphertext, the
## sender publishes a throwaway public key, and both sides multiply it with
## the other side's key to reach the same secret. AME carries that throwaway
## key in the envelope's `senderPublicKey` field and leaves `ciphertext`
## empty, so one envelope shape serves every family.

import tyr/kems/x25519 as tyr_x25519

import ../../../types
import ../../types
import ./types
import bifrostPragmas

proc requireX25519Slot(a: AmeKemAlgorithm) {.role: parser.} =
  ## a: slot rejected unless it belongs to the X25519 family.
  if a != akaX25519:
    raise newException(ValueError,
      "AME KEM slot is not X25519: " & ameKemName(a))

proc x25519AmeKeypair*(a: AmeKemAlgorithm): AmeKemKeypair {.role: truthBuilder.} =
  ## a: the X25519 slot to key.
  requireX25519Slot(a)
  assignAmeKeypair(tyr_x25519.x25519TyrKeypair())

proc x25519AmeSeal*(a: AmeKemAlgorithm,
    publicKey: openArray[byte]): AmeKemCipher {.role: encryptor.} =
  ## a/publicKey: the X25519 slot and the receiver's public key.
  requireX25519Slot(a)
  var sender = tyr_x25519.x25519TyrKeypair()
  defer:
    tyr_x25519.secureClearBytes(sender.secretKey)
  result.envelope.senderPublicKey = sender.publicKey
  result.sharedSecret = tyr_x25519.x25519TyrShared(sender.secretKey, publicKey)

proc x25519AmeOpen*(a: AmeKemAlgorithm, env: AmeKemCipher,
    secretKey: openArray[byte]): ByteSeq {.role: decryptor.} =
  ## a/env/secretKey: the X25519 slot, the received envelope, and our secret.
  requireX25519Slot(a)
  result = tyr_x25519.x25519TyrShared(secretKey, env.envelope.senderPublicKey)
