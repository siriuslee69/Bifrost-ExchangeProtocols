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
import bifrostPragmas

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

template assignAmeSigKeypair*(call: untyped) =
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

proc ameSigFamilySetName*(F: set[AmeSigFamily]): string {.role: parser.} =
  ## F: families rendered as a comma list for an error message.
  for f in F:
    if result.len > 0:
      result.add(",")
    result.add(ameSigFamilyName(f))

proc defaultAmeSigSlot*(f: AmeSigFamily): AmeSignatureAlgorithm {.
    role: parser.} =
  ## f: family mapped to the slot AME picks when it must choose for itself.
  case f
  of asfEd25519: result = asaEd25519
  of asfDilithium: result = asaDilithium87
  of asfFalcon: result = asaFalcon1024
  of asfSphincs: result = asaSphincsShake128f

proc parseAmeSigFamilies*(s: string): set[AmeSigFamily] {.role: parser.} =
  ## s: comma-separated family names from `-d:bifrostSigs=`. An empty string
  ## means every family. Runs while compiling; an unknown name stops the build.
  var
    t: string = ""
  if s.strip().len == 0:
    return {asfEd25519, asfDilithium, asfFalcon, asfSphincs}
  for raw in s.split(','):
    t = raw.strip()
    case t
    of "ed25519": result.incl(asfEd25519)
    of "dilithium": result.incl(asfDilithium)
    of "falcon": result.incl(asfFalcon)
    of "sphincs": result.incl(asfSphincs)
    else:
      raise newException(ValueError, "unknown -d:bifrostSigs entry '" & t &
        "' (expected: ed25519, dilithium, falcon, sphincs, " &
        "or omit the flag for all)")
  if result == {}:
    raise newException(ValueError,
      "-d:bifrostSigs= selected no family; omit the flag to keep all")
