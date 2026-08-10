## -------------------------------------------------------------------------
## AME Algorithms <- exact KEM registry mapped to Tyr primitives
## -------------------------------------------------------------------------

import protocols/wrapper/basic_api as tyr_basic
import protocols/custom_crypto/saber as tyr_saber
import protocols/custom_crypto/ntru as tyr_ntru
import protocols/custom_crypto/kyber as tyr_kyber
import protocols/custom_crypto/frodo as tyr_frodo
import protocols/custom_crypto/mceliece as tyr_mceliece
import protocols/custom_crypto/x25519 as tyr_x25519

import ../../types
import ../types
import ../../../analysis_pragmas

template assignAmeKeypair(call: untyped) =
  var k = call
  result.publicKey = k.publicKey
  result.secretKey = k.secretKey

proc ameKemName*(a: AmeKemAlgorithm): string {.role: wrapper.} =
  ## a: stable AME KEM identifier.
  case a
  of akaFireSaber: result = "FireSaber"
  of akaNtruHps4096821: result = "NTRU-HPS-4096-821"
  of akaKyber1024: result = "Kyber1024"
  of akaFrodo1344Aes: result = "FrodoKEM-1344-AES"
  of akaMcEliece8192: result = "Classic-McEliece-8192128f"
  of akaSaber: result = "Saber"
  of akaNtruHps2048677: result = "NTRU-HPS-2048-677"
  of akaKyber768: result = "Kyber768"
  of akaFrodo976Aes: result = "FrodoKEM-976-AES"
  of akaMcEliece6960: result = "Classic-McEliece-6960119f"
  of akaLightSaber: result = "LightSaber"
  of akaNtruHps2048509: result = "NTRU-HPS-2048-509"
  of akaFrodo640Aes: result = "FrodoKEM-640-AES"
  of akaMcEliece6688: result = "Classic-McEliece-6688128f"
  of akaX25519: result = "X25519"

proc ameKemKeypair*(a: AmeKemAlgorithm): tyr_basic.AsymKeypair {.
    role: wrapper.} =
  ## a: exact KEM slot algorithm to key independently.
  case a
  of akaX25519:
    var k = tyr_x25519.x25519TyrKeypair()
    result.publicKey = k.publicKey
    result.secretKey = k.secretKey
  of akaFireSaber:
    assignAmeKeypair(tyr_saber.saberTyrKeypair(tyr_saber.fireSaber))
  of akaSaber:
    assignAmeKeypair(tyr_saber.saberTyrKeypair(tyr_saber.saber))
  of akaLightSaber:
    assignAmeKeypair(tyr_saber.saberTyrKeypair(tyr_saber.lightSaber))
  of akaKyber1024:
    assignAmeKeypair(tyr_kyber.kyberTyrKeypair(tyr_kyber.kyber1024))
  of akaKyber768:
    assignAmeKeypair(tyr_kyber.kyberTyrKeypair(tyr_kyber.kyber768))
  of akaNtruHps4096821:
    assignAmeKeypair(tyr_ntru.ntruTyrKeypair(tyr_ntru.ntruHps4096821))
  of akaNtruHps2048677:
    assignAmeKeypair(tyr_ntru.ntruTyrKeypair(tyr_ntru.ntruHps2048677))
  of akaNtruHps2048509:
    assignAmeKeypair(tyr_ntru.ntruTyrKeypair(tyr_ntru.ntruHps2048509))
  of akaFrodo1344Aes:
    assignAmeKeypair(tyr_frodo.frodoTyrKeypair(tyr_frodo.frodo1344aes))
  of akaFrodo976Aes:
    assignAmeKeypair(tyr_frodo.frodoTyrKeypair(tyr_frodo.frodo976aes))
  of akaFrodo640Aes:
    assignAmeKeypair(tyr_frodo.frodoTyrKeypair(tyr_frodo.frodo640aes))
  of akaMcEliece8192:
    assignAmeKeypair(tyr_mceliece.mcelieceTyrKeypair(
      tyr_mceliece.mceliece8192128f))
  of akaMcEliece6960:
    assignAmeKeypair(tyr_mceliece.mcelieceTyrKeypair(
      tyr_mceliece.mceliece6960119f))
  of akaMcEliece6688:
    assignAmeKeypair(tyr_mceliece.mcelieceTyrKeypair(
      tyr_mceliece.mceliece6688128f))

proc sealAmeKem*(a: AmeKemAlgorithm,
    publicKey: openArray[byte]): tyr_basic.AsymCipher {.role: wrapper.} =
  ## a/publicKey: exact slot algorithm and receiver public key.
  case a
  of akaX25519:
    var sender = tyr_x25519.x25519TyrKeypair()
    defer:
      tyr_x25519.secureClearBytes(sender.secretKey)
    result.envelope.senderPublicKey = sender.publicKey
    result.sharedSecret = tyr_x25519.x25519TyrShared(sender.secretKey,
      publicKey)
  of akaFireSaber:
    var e = tyr_saber.saberTyrEncaps(tyr_saber.fireSaber, publicKey)
    result.envelope.ciphertext = e.ciphertext
    result.sharedSecret = e.sharedSecret
  of akaSaber:
    var e = tyr_saber.saberTyrEncaps(tyr_saber.saber, publicKey)
    result.envelope.ciphertext = e.ciphertext
    result.sharedSecret = e.sharedSecret
  of akaLightSaber:
    var e = tyr_saber.saberTyrEncaps(tyr_saber.lightSaber, publicKey)
    result.envelope.ciphertext = e.ciphertext
    result.sharedSecret = e.sharedSecret
  of akaKyber1024:
    var e = tyr_kyber.kyberTyrEncaps(tyr_kyber.kyber1024, publicKey)
    result.envelope.ciphertext = e.ciphertext
    result.sharedSecret = e.sharedSecret
  of akaKyber768:
    var e = tyr_kyber.kyberTyrEncaps(tyr_kyber.kyber768, publicKey)
    result.envelope.ciphertext = e.ciphertext
    result.sharedSecret = e.sharedSecret
  of akaNtruHps4096821:
    var e = tyr_ntru.ntruTyrEncaps(tyr_ntru.ntruHps4096821, publicKey)
    result.envelope.ciphertext = e.ciphertext
    result.sharedSecret = e.sharedSecret
  of akaNtruHps2048677:
    var e = tyr_ntru.ntruTyrEncaps(tyr_ntru.ntruHps2048677, publicKey)
    result.envelope.ciphertext = e.ciphertext
    result.sharedSecret = e.sharedSecret
  of akaNtruHps2048509:
    var e = tyr_ntru.ntruTyrEncaps(tyr_ntru.ntruHps2048509, publicKey)
    result.envelope.ciphertext = e.ciphertext
    result.sharedSecret = e.sharedSecret
  of akaFrodo1344Aes:
    var e = tyr_frodo.frodoTyrEncaps(tyr_frodo.frodo1344aes, publicKey)
    result.envelope.ciphertext = e.ciphertext
    result.sharedSecret = e.sharedSecret
  of akaFrodo976Aes:
    var e = tyr_frodo.frodoTyrEncaps(tyr_frodo.frodo976aes, publicKey)
    result.envelope.ciphertext = e.ciphertext
    result.sharedSecret = e.sharedSecret
  of akaFrodo640Aes:
    var e = tyr_frodo.frodoTyrEncaps(tyr_frodo.frodo640aes, publicKey)
    result.envelope.ciphertext = e.ciphertext
    result.sharedSecret = e.sharedSecret
  of akaMcEliece8192:
    var e = tyr_mceliece.mcelieceTyrEncaps(tyr_mceliece.mceliece8192128f,
      publicKey)
    result.envelope.ciphertext = e.ciphertext
    result.sharedSecret = e.sharedSecret
  of akaMcEliece6960:
    var e = tyr_mceliece.mcelieceTyrEncaps(tyr_mceliece.mceliece6960119f,
      publicKey)
    result.envelope.ciphertext = e.ciphertext
    result.sharedSecret = e.sharedSecret
  of akaMcEliece6688:
    var e = tyr_mceliece.mcelieceTyrEncaps(tyr_mceliece.mceliece6688128f,
      publicKey)
    result.envelope.ciphertext = e.ciphertext
    result.sharedSecret = e.sharedSecret

proc openAmeKem*(a: AmeKemAlgorithm, env: tyr_basic.AsymCipher,
    secretKey: openArray[byte]): ByteSeq {.role: wrapper.} =
  ## a/env/secretKey: exact slot decapsulation inputs.
  case a
  of akaX25519:
    result = tyr_x25519.x25519TyrShared(secretKey,
      env.envelope.senderPublicKey)
  of akaFireSaber:
    result = tyr_saber.saberTyrDecaps(tyr_saber.fireSaber, secretKey,
      env.envelope.ciphertext)
  of akaSaber:
    result = tyr_saber.saberTyrDecaps(tyr_saber.saber, secretKey,
      env.envelope.ciphertext)
  of akaLightSaber:
    result = tyr_saber.saberTyrDecaps(tyr_saber.lightSaber, secretKey,
      env.envelope.ciphertext)
  of akaKyber1024:
    result = tyr_kyber.kyberTyrDecaps(tyr_kyber.kyber1024, secretKey,
      env.envelope.ciphertext)
  of akaKyber768:
    result = tyr_kyber.kyberTyrDecaps(tyr_kyber.kyber768, secretKey,
      env.envelope.ciphertext)
  of akaNtruHps4096821:
    result = tyr_ntru.ntruTyrDecaps(tyr_ntru.ntruHps4096821, secretKey,
      env.envelope.ciphertext)
  of akaNtruHps2048677:
    result = tyr_ntru.ntruTyrDecaps(tyr_ntru.ntruHps2048677, secretKey,
      env.envelope.ciphertext)
  of akaNtruHps2048509:
    result = tyr_ntru.ntruTyrDecaps(tyr_ntru.ntruHps2048509, secretKey,
      env.envelope.ciphertext)
  of akaFrodo1344Aes:
    result = tyr_frodo.frodoTyrDecaps(tyr_frodo.frodo1344aes, secretKey,
      env.envelope.ciphertext)
  of akaFrodo976Aes:
    result = tyr_frodo.frodoTyrDecaps(tyr_frodo.frodo976aes, secretKey,
      env.envelope.ciphertext)
  of akaFrodo640Aes:
    result = tyr_frodo.frodoTyrDecaps(tyr_frodo.frodo640aes, secretKey,
      env.envelope.ciphertext)
  of akaMcEliece8192:
    result = tyr_mceliece.mcelieceTyrDecaps(tyr_mceliece.mceliece8192128f,
      secretKey, env.envelope.ciphertext)
  of akaMcEliece6960:
    result = tyr_mceliece.mcelieceTyrDecaps(tyr_mceliece.mceliece6960119f,
      secretKey, env.envelope.ciphertext)
  of akaMcEliece6688:
    result = tyr_mceliece.mcelieceTyrDecaps(tyr_mceliece.mceliece6688128f,
      secretKey, env.envelope.ciphertext)
