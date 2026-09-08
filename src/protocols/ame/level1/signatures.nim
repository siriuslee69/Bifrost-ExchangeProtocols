## -------------------------------------------------------------------------
## AME Signatures <- the signature registry, and which of it this build has
## -------------------------------------------------------------------------
##
## Same three shapes as the KEM surface next door, same one flag:
##
##     nim c -d:bifrostSigs=ed25519,falcon firmware.nim
##
##   -d:bifrostSigs=<list>   compiles         example call
##   ---------------------   --------------   ---------------------------
##   (omitted)               every family     any slot
##   ed25519                 Ed25519          ameSigKeypair(asaEd25519)
##   dilithium               ML-DSA           ameSigKeypair(asaDilithium87)
##   falcon                  Falcon           ameSigKeypair(asaFalcon1024)
##   sphincs                 SPHINCS+         ameSigKeypair(asaSphincsShake128f)
##   ed25519,falcon          both, plus the hybrid slots that need the pair
##
## Hybrids need two families. `asaEd25519Falcon512Hybrid` exists only when
## BOTH ed25519 and falcon are in the build; ask for it otherwise and the
## error names exactly what is missing.
##
##   ameSigKeypair(asaFalcon512)   <- constant: settled while compiling,
##                                    no branch, compile error if excluded
##   ameSigKeypair(a)              <- value off the wire: one `case`, and an
##                                    excluded family raises
##
## This surface replaces Tyr's `signatures/registry`, which reached every
## family at once through liboqs. Nothing here binds to liboqs, so an AME
## build no longer needs it at all. The cost is Ed448, which existed only
## as a liboqs algorithm and is gone from the wire.

import ../../types
import ../types
import ./sigs/types as sig_types
import bifrostPragmas

export sig_types

const
  bifrostSigs* {.strdefine.}: string = ""
    ## Comma-separated signature families to compile. Empty is all.
  ameSigsBuilt* = parseAmeSigFamilies(bifrostSigs)
    ## The families this build actually carries.

when asfEd25519 in ameSigsBuilt:
  import ./sigs/ed25519 as ame_ed25519
  export ame_ed25519
when asfDilithium in ameSigsBuilt:
  import ./sigs/dilithium as ame_dilithium
  export ame_dilithium
when asfFalcon in ameSigsBuilt:
  import ./sigs/falcon as ame_falcon
  export ame_falcon
when asfSphincs in ameSigsBuilt:
  import ./sigs/sphincs as ame_sphincs
  export ame_sphincs
when {asfEd25519, asfFalcon} <= ameSigsBuilt:
  import ./sigs/hybrid as ame_hybrid
  export ame_hybrid

template excludedSigMessage(a: untyped): string =
  ## a: the slot this build cannot execute.
  "AME signature " & ameSigName(a) & " is not in this build; add '" &
    ameSigFamilySetName(ameSigFamilies(a) - ameSigsBuilt) &
    "' to -d:bifrostSigs= or omit the flag to compile every family"

proc raiseExcludedSig(a: AmeSignatureAlgorithm) {.role: helper, noreturn.} =
  ## a: slot whose family this build left out.
  raise newException(ValueError, excludedSigMessage(a))

proc ameSigBuilt*(a: AmeSignatureAlgorithm): bool {.role: parser.} =
  ## a: exact signature slot. True when this build can run it, so a peer's
  ## proposal can be refused before any key material is touched.
  result = ameSigFamilies(a) <= ameSigsBuilt

proc requireAmeSigBuilt*(a: AmeSignatureAlgorithm) {.role: parser.} =
  ## a: exact slot rejected unless this build carries every family it needs.
  if not ameSigBuilt(a):
    raiseExcludedSig(a)

proc defaultAmeSigSlots*(): seq[AmeSignatureAlgorithm] {.role: configurator.} =
  ## The signature stack AME uses when nothing else is configured: one
  ## classical slot and one post-quantum slot, each an independent claim
  ## that must verify. A full build gives Ed25519 + Falcon512, which is what
  ## the defaults have always been.
  ##
  ## A build carrying only some of that keeps whichever slots it can run;
  ## the flag guarantees at least one family, so this is never empty.
  when asfEd25519 in ameSigsBuilt:
    result.add(asaEd25519)
  when asfFalcon in ameSigsBuilt:
    result.add(asaFalcon512)
  elif asfDilithium in ameSigsBuilt:
    result.add(asaDilithium65)
  elif asfSphincs in ameSigsBuilt:
    result.add(asaSphincsShake128f)


## ╭⟢ keypair

proc ameSigKeypair*(a: AmeSignatureAlgorithm,
    seed: openArray[byte] = []): AmeSigKeypair {.role: truthBuilder.} =
  ## a/seed: exact slot named by a value only known while running, plus
  ## optional fixed randomness for reproducible tests.
  case a
  of asaEd25519:
    when asfEd25519 in ameSigsBuilt: result = ed25519AmeKeypair(a, seed)
    else: raiseExcludedSig(a)
  of asaDilithium44, asaDilithium65, asaDilithium87:
    when asfDilithium in ameSigsBuilt: result = dilithiumAmeKeypair(a, seed)
    else: raiseExcludedSig(a)
  of asaFalcon512, asaFalcon1024:
    when asfFalcon in ameSigsBuilt: result = falconAmeKeypair(a, seed)
    else: raiseExcludedSig(a)
  of asaSphincsShake128f:
    when asfSphincs in ameSigsBuilt: result = sphincsAmeKeypair(a, seed)
    else: raiseExcludedSig(a)
  of asaEd25519Falcon512Hybrid, asaEd25519Falcon1024Hybrid:
    when {asfEd25519, asfFalcon} <= ameSigsBuilt:
      result = hybridAmeKeypair(a, seed)
    else: raiseExcludedSig(a)

proc ameSigKeypair*(a: static AmeSignatureAlgorithm,
    seed: openArray[byte] = []): AmeSigKeypair {.role: truthBuilder.} =
  ## a/seed: exact slot named by a constant, so the family is settled while
  ## compiling and no branch survives into the binary.
  when not ameSigBuilt(a):
    {.error: excludedSigMessage(a).}
  elif a == asaEd25519: result = ed25519AmeKeypair(a, seed)
  elif a in {asaDilithium44, asaDilithium65, asaDilithium87}:
    result = dilithiumAmeKeypair(a, seed)
  elif a in {asaFalcon512, asaFalcon1024}: result = falconAmeKeypair(a, seed)
  elif a == asaSphincsShake128f: result = sphincsAmeKeypair(a, seed)
  else: result = hybridAmeKeypair(a, seed)

## ╭⟢ sign

proc signAmeMessage*(a: AmeSignatureAlgorithm,
    msg, secretKey: openArray[byte]): ByteSeq {.role: encryptor.} =
  ## a/msg/secretKey: slot named at run time, subject bytes, our secret key.
  case a
  of asaEd25519:
    when asfEd25519 in ameSigsBuilt: result = ed25519AmeSign(a, msg, secretKey)
    else: raiseExcludedSig(a)
  of asaDilithium44, asaDilithium65, asaDilithium87:
    when asfDilithium in ameSigsBuilt:
      result = dilithiumAmeSign(a, msg, secretKey)
    else: raiseExcludedSig(a)
  of asaFalcon512, asaFalcon1024:
    when asfFalcon in ameSigsBuilt: result = falconAmeSign(a, msg, secretKey)
    else: raiseExcludedSig(a)
  of asaSphincsShake128f:
    when asfSphincs in ameSigsBuilt: result = sphincsAmeSign(a, msg, secretKey)
    else: raiseExcludedSig(a)
  of asaEd25519Falcon512Hybrid, asaEd25519Falcon1024Hybrid:
    when {asfEd25519, asfFalcon} <= ameSigsBuilt:
      result = hybridAmeSign(a, msg, secretKey)
    else: raiseExcludedSig(a)

proc signAmeMessage*(a: static AmeSignatureAlgorithm,
    msg, secretKey: openArray[byte]): ByteSeq {.role: encryptor.} =
  ## a/msg/secretKey: slot named by a constant, subject bytes, secret key.
  when not ameSigBuilt(a):
    {.error: excludedSigMessage(a).}
  elif a == asaEd25519: result = ed25519AmeSign(a, msg, secretKey)
  elif a in {asaDilithium44, asaDilithium65, asaDilithium87}:
    result = dilithiumAmeSign(a, msg, secretKey)
  elif a in {asaFalcon512, asaFalcon1024}:
    result = falconAmeSign(a, msg, secretKey)
  elif a == asaSphincsShake128f: result = sphincsAmeSign(a, msg, secretKey)
  else: result = hybridAmeSign(a, msg, secretKey)

## ╭⟢ verify

proc verifyAmeMessage*(a: AmeSignatureAlgorithm,
    msg, sig, publicKey: openArray[byte]): bool {.role: parser.} =
  ## a/msg/sig/publicKey: slot named at run time and the claim to check.
  ## A slot this build lacks verifies as false rather than raising, so a
  ## peer cannot turn an unsupported algorithm into an exception path.
  case a
  of asaEd25519:
    when asfEd25519 in ameSigsBuilt:
      result = ed25519AmeVerify(a, msg, sig, publicKey)
    else: result = false
  of asaDilithium44, asaDilithium65, asaDilithium87:
    when asfDilithium in ameSigsBuilt:
      result = dilithiumAmeVerify(a, msg, sig, publicKey)
    else: result = false
  of asaFalcon512, asaFalcon1024:
    when asfFalcon in ameSigsBuilt:
      result = falconAmeVerify(a, msg, sig, publicKey)
    else: result = false
  of asaSphincsShake128f:
    when asfSphincs in ameSigsBuilt:
      result = sphincsAmeVerify(a, msg, sig, publicKey)
    else: result = false
  of asaEd25519Falcon512Hybrid, asaEd25519Falcon1024Hybrid:
    when {asfEd25519, asfFalcon} <= ameSigsBuilt:
      result = hybridAmeVerify(a, msg, sig, publicKey)
    else: result = false

proc verifyAmeMessage*(a: static AmeSignatureAlgorithm,
    msg, sig, publicKey: openArray[byte]): bool {.role: parser.} =
  ## a/msg/sig/publicKey: slot named by a constant and the claim to check.
  when not ameSigBuilt(a):
    {.error: excludedSigMessage(a).}
  elif a == asaEd25519: result = ed25519AmeVerify(a, msg, sig, publicKey)
  elif a in {asaDilithium44, asaDilithium65, asaDilithium87}:
    result = dilithiumAmeVerify(a, msg, sig, publicKey)
  elif a in {asaFalcon512, asaFalcon1024}:
    result = falconAmeVerify(a, msg, sig, publicKey)
  elif a == asaSphincsShake128f:
    result = sphincsAmeVerify(a, msg, sig, publicKey)
  else: result = hybridAmeVerify(a, msg, sig, publicKey)
