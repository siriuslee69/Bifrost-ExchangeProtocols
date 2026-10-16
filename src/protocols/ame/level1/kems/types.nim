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
##   mlkem       ML-KEM-1024, ML-KEM-768
##   saber       FireSaber, Saber, LightSaber
##   ntru        NTRU-HPS-4096-821, -2048-677, -2048-509
##   frodo       FrodoKEM-1344-AES, -976-AES, -640-AES
##   mceliece    Classic-McEliece-8192128f, -6960119f, -6688128f
##
## A build selects slots: a family word (`saber`) takes all of a family's
## slots, a slot word (`lightsaber`) exactly one. What is COMPILED is the
## families of the chosen slots; what may RUN is only the chosen slots, and
## a slot left out is refused like a missing family. Where a family's
## buffers grow with its largest slot (Saber), picking the small slot also
## shrinks the build: config.nims sets Tyr's -d:saberMaxRank from it.
## This file holds the grouping plus the two material shapes, and
## deliberately imports no implementation.

import std/strutils

import ../../../types
import ../../types
import runePragmas

type
  AmeKemFamily* = enum
    ## One KEM implementation. Selecting a family compiles its code; the
    ## exact slots above then become usable.
    akfX25519,
    akfMlKem,
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

template assignAmeKeypair*(call: untyped) {.role: helper.} =
  ## call: a Tyr keypair call whose public/secret pair fills `result`.
  var k = call
  result.publicKey = k.publicKey
  result.secretKey = k.secretKey

template assignAmeCipher*(call: untyped) {.role: helper.} =
  ## call: a Tyr encapsulation call whose ciphertext and secret fill `result`.
  var e = call
  result.envelope.ciphertext = e.ciphertext
  result.sharedSecret = e.sharedSecret

proc ameKemName*(a: AmeKemAlgorithm): string {.role: truthBuilder.} =
  ## a: stable AME KEM identifier.
  case a
  of akaFireSaber: result = "FireSaber"
  of akaNtruHps4096821: result = "NTRU-HPS-4096-821"
  of akaMlKem1024: result = "ML-KEM-1024"
  of akaFrodo1344Aes: result = "FrodoKEM-1344-AES"
  of akaMcEliece8192: result = "Classic-McEliece-8192128f"
  of akaSaber: result = "Saber"
  of akaNtruHps2048677: result = "NTRU-HPS-2048-677"
  of akaMlKem768: result = "ML-KEM-768"
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
  of akaMlKem1024, akaMlKem768: result = akfMlKem
  of akaFireSaber, akaSaber, akaLightSaber: result = akfSaber
  of akaNtruHps4096821, akaNtruHps2048677, akaNtruHps2048509: result = akfNtru
  of akaFrodo1344Aes, akaFrodo976Aes, akaFrodo640Aes: result = akfFrodo
  of akaMcEliece8192, akaMcEliece6960, akaMcEliece6688: result = akfMcEliece

proc ameKemFamilyName*(f: AmeKemFamily): string {.role: parser.} =
  ## f: family rendered as the exact text the build flag accepts.
  case f
  of akfX25519: result = "x25519"
  of akfMlKem: result = "mlkem"
  of akfSaber: result = "saber"
  of akfNtru: result = "ntru"
  of akfFrodo: result = "frodo"
  of akfMcEliece: result = "mceliece"

const
  ameKemSlotsStrongestFirst*: array[15, AmeKemAlgorithm] = [
    akaFireSaber, akaSaber, akaLightSaber,
    akaMlKem1024, akaMlKem768,
    akaNtruHps4096821, akaNtruHps2048677, akaNtruHps2048509,
    akaFrodo1344Aes, akaFrodo976Aes, akaFrodo640Aes,
    akaMcEliece8192, akaMcEliece6960, akaMcEliece6688,
    akaX25519]
    ## Every slot, grouped by family, strongest parameter set first. AME
    ## walks this when it has to pick a slot of a family for itself.

proc ameKemToken*(a: AmeKemAlgorithm): string {.role: parser.} =
  ## a: slot -> the word `-d:bifrostKems=` accepts for this ONE slot.
  ## `saber` alone means the whole family, so the middle Saber set is
  ## written `saber3` (its rank).
  case a
  of akaFireSaber: result = "firesaber"
  of akaSaber: result = "saber3"
  of akaLightSaber: result = "lightsaber"
  of akaMlKem1024: result = "mlkem1024"
  of akaMlKem768: result = "mlkem768"
  of akaNtruHps4096821: result = "ntru821"
  of akaNtruHps2048677: result = "ntru677"
  of akaNtruHps2048509: result = "ntru509"
  of akaFrodo1344Aes: result = "frodo1344"
  of akaFrodo976Aes: result = "frodo976"
  of akaFrodo640Aes: result = "frodo640"
  of akaMcEliece8192: result = "mceliece8192"
  of akaMcEliece6960: result = "mceliece6960"
  of akaMcEliece6688: result = "mceliece6688"
  of akaX25519: result = "x25519"

proc ameKemSlotsOfFamily*(f: AmeKemFamily): set[AmeKemAlgorithm] {.
    role: parser.} =
  ## f: family -> every slot it serves.
  for a in AmeKemAlgorithm:
    if ameKemFamily(a) == f:
      result.incl(a)

proc ameKemFamiliesOf*(S: set[AmeKemAlgorithm]): set[AmeKemFamily] {.
    role: parser.} =
  ## S: slots -> the families that serve them (what has to be compiled).
  for a in S:
    result.incl(ameKemFamily(a))

proc ameKemSlotOfWord(t: string): set[AmeKemAlgorithm] {.role: parser.} =
  ## t: one word of `-d:bifrostKems=` -> the slots it selects: a family
  ## word selects all of its slots, a slot word exactly one. {} = unknown.
  for f in AmeKemFamily:
    if t == ameKemFamilyName(f):
      return ameKemSlotsOfFamily(f)
  for a in AmeKemAlgorithm:
    if t == ameKemToken(a):
      return {a}

proc parseAmeKemSlots*(s: string): set[AmeKemAlgorithm] {.role: parser.} =
  ## s: comma-separated words from `-d:bifrostKems=` -> the slots to build.
  ## Empty means every slot. A word is a family (all its slots) or one
  ## slot; see configs/default.toml for the full list. Runs while
  ## compiling; an unknown word stops the build.
  ##
  ##   "saber,x25519"          FireSaber, Saber, LightSaber, X25519
  ##   "lightsaber,x25519"     LightSaber, X25519 (and Saber arrays sized
  ##                           for rank 2 -- config.nims derives it)
  ##   "mceliece6688"          Classic-McEliece-6688128f only
  var
    t: string = ""
    one: set[AmeKemAlgorithm] = {}
  if s.strip().len == 0:
    return {low(AmeKemAlgorithm) .. high(AmeKemAlgorithm)}
  for raw in s.split(','):
    t = raw.strip().toLowerAscii()
    one = ameKemSlotOfWord(t)
    if one == {}:
      raise newException(ValueError, "unknown -d:bifrostKems entry '" & t &
        "' (a family: x25519 mlkem saber ntru frodo mceliece, or one slot: " &
        "lightsaber saber3 firesaber mlkem768 mlkem1024 ntru509 ntru677 " &
        "ntru821 frodo640 frodo976 frodo1344 mceliece6688 mceliece6960 " &
        "mceliece8192; or omit the flag for all)")
    result = result + one
