## -------------------------------------------------------------------------
## AME KEM Types <- key material shapes, family grouping, and the build set
## -------------------------------------------------------------------------
##
## AME names fifteen exact KEM slots on the wire. Those fifteen names come
## from only six implementations ("families"), and an implementation is what
## costs code space:
##
##   family      AME slots it serves
##   ---------   -------------------------------------------------
##   x25519      X25519
##   kyber       Kyber1024, Kyber768
##   saber       FireSaber, Saber, LightSaber
##   ntru        NTRU-HPS-4096-821, -2048-677, -2048-509
##   frodo       FrodoKEM-1344-AES, -976-AES, -640-AES
##   mceliece    Classic-McEliece-8192128f, -6960119f, -6688128f
##
## A build selects families, never single slots, because one family's slots
## share the same code. This file holds that grouping plus the two material
## shapes, and deliberately imports no implementation, so a build that keeps
## one family does not drag in the other five.

import std/strutils

import ../../../types
import ../../types
import runePragmas

type
  AmeKemFamily* = enum
    ## One KEM implementation. Selecting a family compiles its code; the
    ## exact slots above then become usable.
    akfX25519,
    akfKyber,
    akfSaber,
    akfNtru,
    akfFrodo,
    akfMcEliece

  AmeKemCipher* {.role: truthState.} = object
    ## One local KEM result: a wire envelope and its shared secret.
    envelope*: AmeKemEnvelope
    sharedSecret*: ByteSeq

  AmeKemKeypair* {.role: truthState.} = object
    ## Public and secret material for one AME KEM slot.
    publicKey*: ByteSeq
    secretKey*: ByteSeq

template assignAmeKeypair*(call: untyped) =
  ## call: a Tyr keypair call whose public/secret pair fills `result`.
  var k = call
  result.publicKey = k.publicKey
  result.secretKey = k.secretKey

template assignAmeCipher*(call: untyped) =
  ## call: a Tyr encapsulation call whose ciphertext and secret fill `result`.
  var e = call
  result.envelope.ciphertext = e.ciphertext
  result.sharedSecret = e.sharedSecret

proc ameKemName*(a: AmeKemAlgorithm): string {.role: truthBuilder.} =
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

proc ameKemFamily*(a: AmeKemAlgorithm): AmeKemFamily {.role: parser.} =
  ## a: exact AME KEM slot mapped onto the implementation that serves it.
  case a
  of akaX25519: result = akfX25519
  of akaKyber1024, akaKyber768: result = akfKyber
  of akaFireSaber, akaSaber, akaLightSaber: result = akfSaber
  of akaNtruHps4096821, akaNtruHps2048677, akaNtruHps2048509: result = akfNtru
  of akaFrodo1344Aes, akaFrodo976Aes, akaFrodo640Aes: result = akfFrodo
  of akaMcEliece8192, akaMcEliece6960, akaMcEliece6688: result = akfMcEliece

proc ameKemFamilyName*(f: AmeKemFamily): string {.role: parser.} =
  ## f: family rendered as the exact text the build flag accepts.
  case f
  of akfX25519: result = "x25519"
  of akfKyber: result = "kyber"
  of akfSaber: result = "saber"
  of akfNtru: result = "ntru"
  of akfFrodo: result = "frodo"
  of akfMcEliece: result = "mceliece"

proc defaultAmeKemSlot*(f: AmeKemFamily): AmeKemAlgorithm {.role: parser.} =
  ## f: family mapped to the one slot AME picks when it must choose for
  ## itself. Each family names its strongest slot, so an unconfigured build
  ## never quietly settles for a weaker parameter set.
  case f
  of akfX25519: result = akaX25519
  of akfKyber: result = akaKyber1024
  of akfSaber: result = akaFireSaber
  of akfNtru: result = akaNtruHps4096821
  of akfFrodo: result = akaFrodo1344Aes
  of akfMcEliece: result = akaMcEliece8192

proc parseAmeKemFamilies*(s: string): set[AmeKemFamily] {.role: parser.} =
  ## s: comma-separated family names from `-d:bifrostKems=`. An empty string
  ## means every family, so a build with no flag keeps the whole registry.
  ## Runs while compiling; an unknown name stops the build.
  var
    t: string = ""
  if s.strip().len == 0:
    return {akfX25519, akfKyber, akfSaber, akfNtru, akfFrodo, akfMcEliece}
  for raw in s.split(','):
    t = raw.strip()
    case t
    of "x25519": result.incl(akfX25519)
    of "kyber": result.incl(akfKyber)
    of "saber": result.incl(akfSaber)
    of "ntru": result.incl(akfNtru)
    of "frodo": result.incl(akfFrodo)
    of "mceliece": result.incl(akfMcEliece)
    else:
      raise newException(ValueError, "unknown -d:bifrostKems entry '" & t &
        "' (expected: x25519, kyber, saber, ntru, frodo, mceliece, " &
        "or omit the flag for all)")
  if result == {}:
    raise newException(ValueError,
      "-d:bifrostKems= selected no family; omit the flag to keep all")
