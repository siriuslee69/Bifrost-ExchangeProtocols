## -------------------------------------------------------------------------
## AME Signature Types <- key material, family grouping, and the build set
## -------------------------------------------------------------------------
##
## AME names nine exact signature slots on the wire. They come from four
## implementations ("families"), and an implementation is what costs code:
##
##   family      AME slots it serves
##   ---------   -------------------------------------------------
##   ed25519     Ed25519
##   dilithium   Dilithium44, Dilithium65, Dilithium87
##   falcon      Falcon512, Falcon1024
##   sphincs     SPHINCS+-SHAKE-128f
##
## Two slots are HYBRIDS: they sign twice, once with Ed25519 and once with
## Falcon, and both must verify. A hybrid therefore needs BOTH families in
## the build, which is why this file answers with a `set` rather than a
## single family:
##
##   ameSigFamilies(asaEd25519Falcon512Hybrid)  ->  {asfEd25519, asfFalcon}
##
## This file imports no implementation, so a build that keeps one family
## does not drag in the others.

import std/strutils

import ../../../types
import ../../types
import runePragmas

type
  AmeSigFamily* = enum
    ## One signature implementation. Selecting a family compiles its code.
    asfEd25519,
    asfDilithium,
    asfFalcon,
    asfSphincs

  AmeSigKeypair* {.role: truthState.} = object
    ## Public and secret material for one AME signature slot.
    publicKey*: ByteSeq
    secretKey*: ByteSeq

template assignAmeSigKeypair*(call: untyped) {.role: helper.} =
  ## call: a Tyr keypair call whose public/secret pair fills `result`.
  var k = call
  result.publicKey = k.publicKey
  result.secretKey = k.secretKey

proc ameSigName*(a: AmeSignatureAlgorithm): string {.role: truthBuilder.} =
  ## a: stable AME signature identifier.
  case a
  of asaEd25519: result = "Ed25519"
  of asaDilithium44: result = "Dilithium44"
  of asaDilithium65: result = "Dilithium65"
  of asaDilithium87: result = "Dilithium87"
  of asaFalcon512: result = "Falcon512"
  of asaFalcon1024: result = "Falcon1024"
  of asaSphincsShake128f: result = "SPHINCS+-SHAKE-128f"
  of asaEd25519Falcon512Hybrid: result = "Ed25519+Falcon512"
  of asaEd25519Falcon1024Hybrid: result = "Ed25519+Falcon1024"

proc ameSigFamilies*(a: AmeSignatureAlgorithm): set[AmeSigFamily] {.
    role: parser.} =
  ## a: exact slot mapped onto every implementation it needs. Hybrids name
  ## two; everything else names one.
  case a
  of asaEd25519: result = {asfEd25519}
  of asaDilithium44, asaDilithium65, asaDilithium87: result = {asfDilithium}
  of asaFalcon512, asaFalcon1024: result = {asfFalcon}
  of asaSphincsShake128f: result = {asfSphincs}
  of asaEd25519Falcon512Hybrid, asaEd25519Falcon1024Hybrid:
    result = {asfEd25519, asfFalcon}

proc ameSigFamilyName*(f: AmeSigFamily): string {.role: parser.} =
  ## f: family rendered as the exact text the build flag accepts.
  case f
  of asfEd25519: result = "ed25519"
  of asfDilithium: result = "dilithium"
  of asfFalcon: result = "falcon"
  of asfSphincs: result = "sphincs"

proc ameSigToken*(a: AmeSignatureAlgorithm): string {.role: parser.} =
  ## a: slot -> the word `-d:bifrostSigs=` accepts for this ONE slot.
  case a
  of asaEd25519: result = "ed25519"
  of asaDilithium44: result = "dilithium44"
  of asaDilithium65: result = "dilithium65"
  of asaDilithium87: result = "dilithium87"
  of asaFalcon512: result = "falcon512"
  of asaFalcon1024: result = "falcon1024"
  of asaSphincsShake128f: result = "sphincs128f"
  of asaEd25519Falcon512Hybrid: result = "ed25519falcon512"
  of asaEd25519Falcon1024Hybrid: result = "ed25519falcon1024"

proc ameSigFamiliesOf*(S: set[AmeSignatureAlgorithm]): set[AmeSigFamily] {.
    role: parser.} =
  ## S: slots -> every family they need (what has to be compiled).
  for a in S:
    result = result + ameSigFamilies(a)

proc ameSigFamilyOfWord(t: string): set[AmeSigFamily] {.role: parser.} =
  ## t: one word -> the family it names, or {}.
  for f in AmeSigFamily:
    if t == ameSigFamilyName(f):
      result.incl(f)

proc ameSigSlotOfWord(t: string): set[AmeSignatureAlgorithm] {.role: parser.} =
  ## t: one word -> the slot it names, or {}.
  for a in AmeSignatureAlgorithm:
    if t == ameSigToken(a):
      result.incl(a)

proc ameSigWords(s: string): tuple[families: set[AmeSigFamily],
    slots: set[AmeSignatureAlgorithm]] {.role: parser.} =
  ## s: the -d:bifrostSigs value -> its family words and its slot words.
  ## "ed25519" is both (the family has one slot). An unknown word stops
  ## the build.
  var
    t: string = ""
  for raw in s.split(','):
    t = raw.strip().toLowerAscii()
    result.families = result.families + ameSigFamilyOfWord(t)
    result.slots = result.slots + ameSigSlotOfWord(t)
    if ameSigFamilyOfWord(t) == {} and ameSigSlotOfWord(t) == {}:
      raise newException(ValueError, "unknown -d:bifrostSigs entry '" & t &
        "' (a family: ed25519 dilithium falcon sphincs, or one slot: " &
        "dilithium44 dilithium65 dilithium87 falcon512 falcon1024 " &
        "sphincs128f ed25519falcon512 ed25519falcon1024; or omit the flag)")

proc parseAmeSigSlots*(s: string): set[AmeSignatureAlgorithm] {.role: parser.} =
  ## s: comma-separated words from `-d:bifrostSigs=` -> the slots to build.
  ## Empty means every slot. A slot word selects that slot; family words
  ## select every slot whose families are ALL named, so "ed25519,falcon"
  ## also brings the two Ed25519+Falcon hybrids. Runs while compiling.
  var
    w: tuple[families: set[AmeSigFamily], slots: set[AmeSignatureAlgorithm]] =
      ({}, {})
  if s.strip().len == 0:
    return {low(AmeSignatureAlgorithm) .. high(AmeSignatureAlgorithm)}
  w = ameSigWords(s)
  result = w.slots
  for a in AmeSignatureAlgorithm:
    if ameSigFamilies(a) <= w.families:
      result.incl(a)
