## -------------------------------------------------------------------------
## AME Algorithms <- the KEM registry, and which of it this build carries
## -------------------------------------------------------------------------
##
## Usable straight away, no flag required
## --------------------------------------
##
##     import protocols/ame
##
##     var kp = ameKemKeypair(akaKyber768)
##
## With no flag every family is compiled, exactly as before. Then, for a
## small target, add one flag and change nothing in your source:
##
##     nim c -d:bifrostKems=kyber,x25519 firmware.nim
##
## Now only Kyber and X25519 exist. The same call keeps working; asking for
## a family this build left out fails, and says which flag to change.
##
##   -d:bifrostKems=<list>      compiles              example call
##   -----------------------    -------------------   ---------------------
##   (omitted)                  every family          any slot
##   x25519                     X25519                ameKemKeypair(akaX25519)
##   kyber                      Kyber                 ameKemKeypair(akaKyber768)
##   saber                      Saber                 ameKemKeypair(akaSaber)
##   ntru                       NTRU                  ameKemKeypair(akaNtruHps2048509)
##   frodo                      FrodoKEM              ameKemKeypair(akaFrodo640Aes)
##   mceliece                   Classic McEliece      ameKemKeypair(akaMcEliece6688)
##   kyber,x25519               both of those         either of the two above
##
## Two call shapes, one name
## -------------------------
## The same three procs answer to a constant and to a value:
##
##   ameKemKeypair(akaKyber768)  <- constant. The compiler picks the family
##                                  while compiling, emits no branch at all,
##                                  and refuses to compile if this build
##                                  left Kyber out.
##
##   ameKemKeypair(a)            <- a value read from the wire. One `case`
##                                  decides at run time, and an excluded
##                                  family raises instead of running.
##
## Nothing has to be written twice: the compiler prefers the constant form
## whenever the argument is one, so ordinary code keeps calling one name.
##
## Why the flag, and not a setting in your code
## --------------------------------------------
## Nim resolves every `import` before any of your code exists. A `case` or
## `when` written inside a proc runs long after the imports were read, so it
## cannot un-import anything. What enters the build is therefore a build-time
## decision by nature. This keeps that decision to one flag, and makes the
## no-flag case behave like the full library.

import ../../types
import ../types
import ./kems/types as kem_types
import runePragmas

export kem_types

const
  bifrostKems* {.strdefine.}: string = ""
    ## Comma-separated KEM families to compile. Empty (the default) is all.
  ameKemsBuilt* = parseAmeKemFamilies(bifrostKems)
    ## The families this build actually carries.

when akfX25519 in ameKemsBuilt:
  import ./kems/x25519 as ame_x25519
  export ame_x25519
when akfKyber in ameKemsBuilt:
  import ./kems/kyber as ame_kyber
  export ame_kyber
when akfSaber in ameKemsBuilt:
  import ./kems/saber as ame_saber
  export ame_saber
when akfNtru in ameKemsBuilt:
  import ./kems/ntru as ame_ntru
  export ame_ntru
when akfFrodo in ameKemsBuilt:
  import ./kems/frodo as ame_frodo
  export ame_frodo
when akfMcEliece in ameKemsBuilt:
  import ./kems/mceliece as ame_mceliece
  export ame_mceliece

template excludedKemMessage(a: untyped): string =
  ## a: the slot that this build cannot execute.
  "AME KEM " & ameKemName(a) & " is not in this build; add '" &
    ameKemFamilyName(ameKemFamily(a)) &
    "' to -d:bifrostKems= or omit the flag to compile every family"

proc raiseExcludedKem(a: AmeKemAlgorithm) {.role: helper, noreturn.} =
  ## a: slot whose family this build left out.
  raise newException(ValueError, excludedKemMessage(a))

proc ameKemBuilt*(a: AmeKemAlgorithm): bool {.role: parser.} =
  ## a: exact KEM slot. True when this build can actually run it, so a peer's
  ## proposal can be refused before any key material is touched.
  result = ameKemFamily(a) in ameKemsBuilt

proc requireAmeKemBuilt*(a: AmeKemAlgorithm) {.role: parser.} =
  ## a: exact KEM slot rejected unless this build carries its family.
  if not ameKemBuilt(a):
    raiseExcludedKem(a)

const
  ameKemPqPreference: array[5, AmeKemFamily] = [
    akfSaber, akfKyber, akfNtru, akfFrodo, akfMcEliece]
    ## Order AME walks when it has to pick a post-quantum family unaided.

proc defaultAmeKemSlots*(): seq[AmeKemAlgorithm] {.role: configurator.} =
  ## The KEM slots AME uses when nothing else is configured: the first
  ## post-quantum family this build carries, then X25519 if it is present.
  ##
  ## A build with everything gives FireSaber + X25519, which is what the
  ## defaults have always been. A build that dropped Saber gives its next
  ## post-quantum family instead, so process defaults stay usable rather
  ## than naming a KEM the binary cannot run. The flag guarantees at least
  ## one family, so this is never empty.
  var i: int = 0
  while i < ameKemPqPreference.len:
    if ameKemPqPreference[i] in ameKemsBuilt:
      result.add(defaultAmeKemSlot(ameKemPqPreference[i]))
      break
    i = i + 1
  if akfX25519 in ameKemsBuilt:
    result.add(akaX25519)

## ╭⟢ keypair

proc ameKemKeypair*(a: AmeKemAlgorithm): AmeKemKeypair {.role: truthBuilder.} =
  ## a: exact KEM slot, named by a value only known while running.
  case ameKemFamily(a)
  of akfX25519:
    when akfX25519 in ameKemsBuilt: result = x25519AmeKeypair(a)
    else: raiseExcludedKem(a)
  of akfKyber:
    when akfKyber in ameKemsBuilt: result = kyberAmeKeypair(a)
    else: raiseExcludedKem(a)
  of akfSaber:
    when akfSaber in ameKemsBuilt: result = saberAmeKeypair(a)
    else: raiseExcludedKem(a)
  of akfNtru:
    when akfNtru in ameKemsBuilt: result = ntruAmeKeypair(a)
    else: raiseExcludedKem(a)
  of akfFrodo:
    when akfFrodo in ameKemsBuilt: result = frodoAmeKeypair(a)
    else: raiseExcludedKem(a)
  of akfMcEliece:
    when akfMcEliece in ameKemsBuilt: result = mcelieceAmeKeypair(a)
    else: raiseExcludedKem(a)

proc ameKemKeypair*(a: static AmeKemAlgorithm): AmeKemKeypair {.role: truthBuilder.} =
  ## a: exact KEM slot, named by a constant, so the family is settled while
  ## compiling and no branch survives into the binary.
  when not ameKemBuilt(a):
    {.error: excludedKemMessage(a).}
  elif ameKemFamily(a) == akfX25519: result = x25519AmeKeypair(a)
  elif ameKemFamily(a) == akfKyber: result = kyberAmeKeypair(a)
  elif ameKemFamily(a) == akfSaber: result = saberAmeKeypair(a)
  elif ameKemFamily(a) == akfNtru: result = ntruAmeKeypair(a)
  elif ameKemFamily(a) == akfFrodo: result = frodoAmeKeypair(a)
  else: result = mcelieceAmeKeypair(a)

## ╭⟢ seal (encapsulate)

proc sealAmeKem*(a: AmeKemAlgorithm,
    publicKey: openArray[byte]): AmeKemCipher {.role: encryptor.} =
  ## a/publicKey: exact slot named at run time, and the receiver public key.
  case ameKemFamily(a)
  of akfX25519:
    when akfX25519 in ameKemsBuilt: result = x25519AmeSeal(a, publicKey)
    else: raiseExcludedKem(a)
  of akfKyber:
    when akfKyber in ameKemsBuilt: result = kyberAmeSeal(a, publicKey)
    else: raiseExcludedKem(a)
  of akfSaber:
    when akfSaber in ameKemsBuilt: result = saberAmeSeal(a, publicKey)
    else: raiseExcludedKem(a)
  of akfNtru:
    when akfNtru in ameKemsBuilt: result = ntruAmeSeal(a, publicKey)
    else: raiseExcludedKem(a)
  of akfFrodo:
    when akfFrodo in ameKemsBuilt: result = frodoAmeSeal(a, publicKey)
    else: raiseExcludedKem(a)
  of akfMcEliece:
    when akfMcEliece in ameKemsBuilt: result = mcelieceAmeSeal(a, publicKey)
    else: raiseExcludedKem(a)

proc sealAmeKem*(a: static AmeKemAlgorithm,
    publicKey: openArray[byte]): AmeKemCipher {.role: encryptor.} =
  ## a/publicKey: exact slot named by a constant, and the receiver public key.
  when not ameKemBuilt(a):
    {.error: excludedKemMessage(a).}
  elif ameKemFamily(a) == akfX25519: result = x25519AmeSeal(a, publicKey)
  elif ameKemFamily(a) == akfKyber: result = kyberAmeSeal(a, publicKey)
  elif ameKemFamily(a) == akfSaber: result = saberAmeSeal(a, publicKey)
  elif ameKemFamily(a) == akfNtru: result = ntruAmeSeal(a, publicKey)
  elif ameKemFamily(a) == akfFrodo: result = frodoAmeSeal(a, publicKey)
  else: result = mcelieceAmeSeal(a, publicKey)

## ╭⟢ open (decapsulate)

proc openAmeKem*(a: AmeKemAlgorithm, env: AmeKemCipher,
    secretKey: openArray[byte]): ByteSeq {.role: decryptor.} =
  ## a/env/secretKey: exact slot named at run time, envelope, and our secret.
  case ameKemFamily(a)
  of akfX25519:
    when akfX25519 in ameKemsBuilt: result = x25519AmeOpen(a, env, secretKey)
    else: raiseExcludedKem(a)
  of akfKyber:
    when akfKyber in ameKemsBuilt: result = kyberAmeOpen(a, env, secretKey)
    else: raiseExcludedKem(a)
  of akfSaber:
    when akfSaber in ameKemsBuilt: result = saberAmeOpen(a, env, secretKey)
    else: raiseExcludedKem(a)
  of akfNtru:
    when akfNtru in ameKemsBuilt: result = ntruAmeOpen(a, env, secretKey)
    else: raiseExcludedKem(a)
  of akfFrodo:
    when akfFrodo in ameKemsBuilt: result = frodoAmeOpen(a, env, secretKey)
    else: raiseExcludedKem(a)
  of akfMcEliece:
    when akfMcEliece in ameKemsBuilt: result = mcelieceAmeOpen(a, env, secretKey)
    else: raiseExcludedKem(a)

proc openAmeKem*(a: static AmeKemAlgorithm, env: AmeKemCipher,
    secretKey: openArray[byte]): ByteSeq {.role: decryptor.} =
  ## a/env/secretKey: exact slot named by a constant, envelope, and our secret.
  when not ameKemBuilt(a):
    {.error: excludedKemMessage(a).}
  elif ameKemFamily(a) == akfX25519: result = x25519AmeOpen(a, env, secretKey)
  elif ameKemFamily(a) == akfKyber: result = kyberAmeOpen(a, env, secretKey)
  elif ameKemFamily(a) == akfSaber: result = saberAmeOpen(a, env, secretKey)
  elif ameKemFamily(a) == akfNtru: result = ntruAmeOpen(a, env, secretKey)
  elif ameKemFamily(a) == akfFrodo: result = frodoAmeOpen(a, env, secretKey)
  else: result = mcelieceAmeOpen(a, env, secretKey)
