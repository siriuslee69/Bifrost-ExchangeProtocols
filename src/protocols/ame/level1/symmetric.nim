## -------------------------------------------------------------------------
## AME Symmetric <- ciphers, MACs, hashes, KDFs, and what this build carries
## -------------------------------------------------------------------------
##
## One flag for all four families, because they share implementations:
##
##     nim c -d:bifrostSymmetric=gimli,blake3 firmware.nim
##
##   -d:bifrostSymmetric=<list>   removes
##   --------------------------   -----------------------------------------
##   (omitted)                    nothing; every primitive is compiled
##   blake3                       everything except BLAKE3's own slots
##   gimli                        every cipher but Gimli, every MAC but Gimli
##   chacha20,poly1305,blake3     AES, Gimli, SHA-3, Argon2
##
## BLAKE3 is always present whatever you write: AME normalizes MAC tags and
## derives Argon2's salt with it, so the protocol cannot run without it.
##
## Same three shapes as the KEM and signature surfaces:
##
##   ameCipherXor(acaGimli, k, n, m)   <- constant: settled while compiling
##   ameCipherXor(a, k, n, m)          <- value off the wire: one `case`
##   -d:bifrostSymmetric=gimli         <- decides what exists at all
##
## Stream ciphers here are all XOR keystreams, so one call both seals and
## opens; there is no separate decrypt entry point to get wrong.

import ../../types
import ../types
import ./symmetric/types as sym_types
import runePragmas

export sym_types

const
  bifrostSymmetric* {.strdefine.}: string = ""
    ## Comma-separated symmetric primitives to compile. Empty is all.
  ameSymBuilt* = parseAmeSymPrimitives(bifrostSymmetric)
    ## The primitives this build actually carries. Always includes BLAKE3.

import ./symmetric/blake3 as ame_blake3
export ame_blake3

when aspSha3 in ameSymBuilt:
  import ./symmetric/sha3 as ame_sha3
  export ame_sha3
when aspGimli in ameSymBuilt:
  import ./symmetric/gimli as ame_gimli
  export ame_gimli
when aspChaCha20 in ameSymBuilt:
  import ./symmetric/chacha20 as ame_chacha
  export ame_chacha
when aspAes in ameSymBuilt:
  import ./symmetric/aes as ame_aes
  export ame_aes
when aspPoly1305 in ameSymBuilt:
  import ./symmetric/poly1305 as ame_poly1305
  export ame_poly1305
when aspArgon2 in ameSymBuilt:
  import ./symmetric/argon2 as ame_argon2
  export ame_argon2

template excludedSymMessage(p, what, name: untyped): string =
  ## p/what/name: missing primitive, family label, and the slot's own name.
  "AME " & what & " " & name & " needs primitive '" & ameSymPrimitiveName(p) &
    "', which is not in this build; add it to -d:bifrostSymmetric= or omit " &
    "the flag to compile every primitive"

proc raiseExcludedSym(p: AmeSymPrimitive, what,
    name: string) {.role: helper, noreturn, used.} =
  ## p/what/name: primitive this build left out, family label, slot name.
  raise newException(ValueError, excludedSymMessage(p, what, name))

proc ameCipherBuilt*(a: AmeCipherAlgorithm): bool {.role: parser.} =
  ## a: cipher slot. True when this build can run it.
  result = ameCipherPrimitive(a) in ameSymBuilt

proc ameMacBuilt*(a: AmeMacAlgorithm): bool {.role: parser.} =
  ## a: MAC slot. True when this build can run it.
  result = ameMacPrimitive(a) in ameSymBuilt

proc ameHashBuilt*(a: AmeHashAlgorithm): bool {.role: parser.} =
  ## a: hash slot. True when this build can run it.
  result = ameHashPrimitive(a) in ameSymBuilt

proc ameKdfBuilt*(a: AmeKdfAlgorithm): bool {.role: parser.} =
  ## a: KDF slot. True when this build can run it.
  result = ameKdfPrimitive(a) in ameSymBuilt

proc requireAmeCipherBuilt*(a: AmeCipherAlgorithm) {.role: parser.} =
  ## a: cipher slot refused unless its primitive is compiled.
  if not ameCipherBuilt(a):
    raiseExcludedSym(ameCipherPrimitive(a), "cipher", $a)

proc requireAmeMacBuilt*(a: AmeMacAlgorithm) {.role: parser.} =
  ## a: MAC slot refused unless its primitive is compiled.
  if not ameMacBuilt(a):
    raiseExcludedSym(ameMacPrimitive(a), "MAC", $a)

proc requireAmeHashBuilt*(a: AmeHashAlgorithm) {.role: parser.} =
  ## a: hash slot refused unless its primitive is compiled.
  if not ameHashBuilt(a):
    raiseExcludedSym(ameHashPrimitive(a), "hash", $a)

proc requireAmeKdfBuilt*(a: AmeKdfAlgorithm) {.role: parser.} =
  ## a: KDF slot refused unless its primitive is compiled.
  if not ameKdfBuilt(a):
    raiseExcludedSym(ameKdfPrimitive(a), "KDF", $a)

## ╭⟢ defaults this build can actually run

proc defaultAmeCipherSlot*(): AmeCipherAlgorithm {.role: configurator.} =
  ## The cipher AME picks when nothing else is configured. XChaCha20 unless
  ## its primitive was left out, then Gimli, then AES-CTR.
  when aspChaCha20 in ameSymBuilt: result = acaXChaCha20
  elif aspGimli in ameSymBuilt: result = acaGimli
  elif aspAes in ameSymBuilt: result = acaAesCtr
  else:
    {.error: "-d:bifrostSymmetric= left this build with no cipher; " &
      "keep one of chacha20, gimli, aes".}

proc defaultAmeMacSlot*(): AmeMacAlgorithm {.role: configurator.} =
  ## The MAC AME picks unaided. BLAKE3 is always compiled, so this is always
  ## answerable.
  result = amaBlake3

proc defaultAmeHashSlot*(): AmeHashAlgorithm {.role: configurator.} =
  ## The transcript hash AME picks unaided.
  result = ahaBlake3

proc defaultAmeKdfSlots*(): seq[AmeKdfAlgorithm] {.role: configurator.} =
  ## The KDF stack AME picks unaided: BLAKE3, plus the Gimli XOF as a second
  ## independent overlay when its primitive is present.
  result.add(akfaBlake3)
  when aspGimli in ameSymBuilt:
    result.add(akfaGimliXof)

## ╭⟢ ciphers

proc ameCipherXor*(a: AmeCipherAlgorithm,
    key, nonce, msg: openArray[byte]): ByteSeq {.role: encryptor.} =
  ## a/key/nonce/msg: slot named at run time and stream-cipher inputs.
  case a
  of acaXChaCha20, acaChaCha20:
    when aspChaCha20 in ameSymBuilt: result = chachaAmeXor(a, key, nonce, msg)
    else: raiseExcludedSym(aspChaCha20, "cipher", $a)
  of acaGimli:
    when aspGimli in ameSymBuilt: result = gimliAmeXor(key, nonce, msg)
    else: raiseExcludedSym(aspGimli, "cipher", $a)
  of acaAesCtr:
    when aspAes in ameSymBuilt: result = aesAmeXor(key, nonce, msg)
    else: raiseExcludedSym(aspAes, "cipher", $a)

proc ameCipherXor*(a: static AmeCipherAlgorithm,
    key, nonce, msg: openArray[byte]): ByteSeq {.role: encryptor.} =
  ## a/key/nonce/msg: slot named by a constant, settled while compiling.
  when not ameCipherBuilt(a):
    {.error: excludedSymMessage(ameCipherPrimitive(a), "cipher", $a).}
  elif a in {acaXChaCha20, acaChaCha20}: result = chachaAmeXor(a, key, nonce, msg)
  elif a == acaGimli: result = gimliAmeXor(key, nonce, msg)
  else: result = aesAmeXor(key, nonce, msg)

## ╭⟢ MACs

proc ameMacTag*(a: AmeMacAlgorithm, key, data: openArray[byte],
    outLen: int): ByteSeq {.role: helper.} =
  ## a/key/data/outLen: slot named at run time, key, bytes, native tag length.
  case a
  of amaBlake3: result = blake3AmeMac(key, data, outLen)
  of amaGimli:
    when aspGimli in ameSymBuilt: result = gimliAmeMac(key, data, outLen)
    else: raiseExcludedSym(aspGimli, "MAC", $a)
  of amaPoly1305:
    when aspPoly1305 in ameSymBuilt: result = poly1305AmeMac(key, data)
    else: raiseExcludedSym(aspPoly1305, "MAC", $a)
  of amaSha3:
    when aspSha3 in ameSymBuilt: result = sha3AmeMac(key, data, outLen)
    else: raiseExcludedSym(aspSha3, "MAC", $a)

proc ameMacTag*(a: static AmeMacAlgorithm, key, data: openArray[byte],
    outLen: int): ByteSeq {.role: helper.} =
  ## a/key/data/outLen: slot named by a constant, settled while compiling.
  when not ameMacBuilt(a):
    {.error: excludedSymMessage(ameMacPrimitive(a), "MAC", $a).}
  elif a == amaBlake3: result = blake3AmeMac(key, data, outLen)
  elif a == amaGimli: result = gimliAmeMac(key, data, outLen)
  elif a == amaPoly1305: result = poly1305AmeMac(key, data)
  else: result = sha3AmeMac(key, data, outLen)

## ╭⟢ hashes

proc ameHashBytes*(a: AmeHashAlgorithm, data: openArray[byte],
    outLen: int): ByteSeq {.role: helper.} =
  ## a/data/outLen: slot named at run time, bytes, requested digest length.
  case a
  of ahaBlake3: result = blake3AmeHash(data, outLen)
  of ahaSha3:
    when aspSha3 in ameSymBuilt: result = sha3AmeHash(data, outLen)
    else: raiseExcludedSym(aspSha3, "hash", $a)
  of ahaShake256:
    when aspSha3 in ameSymBuilt: result = shake256AmeHash(data, outLen)
    else: raiseExcludedSym(aspSha3, "hash", $a)
  of ahaGimliXof:
    when aspGimli in ameSymBuilt: result = gimliAmeXof(data, outLen)
    else: raiseExcludedSym(aspGimli, "hash", $a)

proc ameHashBytes*(a: static AmeHashAlgorithm, data: openArray[byte],
    outLen: int): ByteSeq {.role: helper.} =
  ## a/data/outLen: slot named by a constant, settled while compiling.
  when not ameHashBuilt(a):
    {.error: excludedSymMessage(ameHashPrimitive(a), "hash", $a).}
  elif a == ahaBlake3: result = blake3AmeHash(data, outLen)
  elif a == ahaSha3: result = sha3AmeHash(data, outLen)
  elif a == ahaShake256: result = shake256AmeHash(data, outLen)
  else: result = gimliAmeXof(data, outLen)

## ╭⟢ KDFs

proc ameKdfBytes*(a: AmeKdfAlgorithm, seed: openArray[byte],
    outLen: int): ByteSeq {.role: helper.} =
  ## a/seed/outLen: slot named at run time, bound seed, requested key length.
  case a
  of akfaBlake3: result = blake3AmeHash(seed, outLen)
  of akfaSha3Shake256:
    when aspSha3 in ameSymBuilt: result = shake256AmeHash(seed, outLen)
    else: raiseExcludedSym(aspSha3, "KDF", $a)
  of akfaGimliXof:
    when aspGimli in ameSymBuilt: result = gimliAmeXof(seed, outLen)
    else: raiseExcludedSym(aspGimli, "KDF", $a)
  of akfaArgon2id:
    when aspArgon2 in ameSymBuilt:
      result = argon2AmeKdf(seed, blake3AmeHash(seed, 16), outLen)
    else: raiseExcludedSym(aspArgon2, "KDF", $a)

proc ameKdfBytes*(a: static AmeKdfAlgorithm, seed: openArray[byte],
    outLen: int): ByteSeq {.role: helper.} =
  ## a/seed/outLen: slot named by a constant, settled while compiling.
  when not ameKdfBuilt(a):
    {.error: excludedSymMessage(ameKdfPrimitive(a), "KDF", $a).}
  elif a == akfaBlake3: result = blake3AmeHash(seed, outLen)
  elif a == akfaSha3Shake256: result = shake256AmeHash(seed, outLen)
  elif a == akfaGimliXof: result = gimliAmeXof(seed, outLen)
  else: result = argon2AmeKdf(seed, blake3AmeHash(seed, 16), outLen)
