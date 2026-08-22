## -------------------------------------------------------------------------
## AME Symmetric Types <- primitive grouping for ciphers, MACs, hashes, KDFs
## -------------------------------------------------------------------------
##
## AME's four symmetric families name sixteen slots between them, but they
## are built from only seven primitives, and a primitive is what costs code.
## One primitive often serves several families at once:
##
##   primitive    cipher slot   MAC slot    hash slot     KDF slot
##   ----------   -----------   ---------   -----------   --------------
##   blake3       -             Blake3      Blake3        Blake3
##   sha3         -             Sha3        Sha3, Shake   Sha3Shake256
##   gimli        Gimli         Gimli       GimliXof      GimliXof
##   chacha20     XChaCha20,    -           -             -
##                ChaCha20
##   aes          AesCtr        -           -             -
##   poly1305     -             Poly1305    -             -
##   argon2       -             -           -             Argon2id
##
## That overlap is why the build flag selects PRIMITIVES rather than one
## list per family: dropping `sha3` removes a MAC slot, two hash slots and a
## KDF slot in one move, because they are all the same code.
##
## This file imports no implementation, so a build that keeps one primitive
## does not drag in the other six.

import std/strutils

import ../../types
import ../../../../analysis_pragmas

type
  AmeSymPrimitive* = enum
    ## One symmetric implementation. Selecting it compiles its code and
    ## makes every slot in its row above usable.
    aspBlake3,
    aspSha3,
    aspGimli,
    aspChaCha20,
    aspAes,
    aspPoly1305,
    aspArgon2

proc ameCipherPrimitive*(a: AmeCipherAlgorithm): AmeSymPrimitive {.
    role: parser.} =
  ## a: cipher slot mapped onto the implementation that runs it.
  case a
  of acaXChaCha20, acaChaCha20: result = aspChaCha20
  of acaGimli: result = aspGimli
  of acaAesCtr: result = aspAes

proc ameMacPrimitive*(a: AmeMacAlgorithm): AmeSymPrimitive {.role: parser.} =
  ## a: MAC slot mapped onto the implementation that runs it.
  case a
  of amaBlake3: result = aspBlake3
  of amaGimli: result = aspGimli
  of amaPoly1305: result = aspPoly1305
  of amaSha3: result = aspSha3

proc ameHashPrimitive*(a: AmeHashAlgorithm): AmeSymPrimitive {.role: parser.} =
  ## a: hash slot mapped onto the implementation that runs it.
  case a
  of ahaBlake3: result = aspBlake3
  of ahaSha3, ahaShake256: result = aspSha3
  of ahaGimliXof: result = aspGimli

proc ameKdfPrimitive*(a: AmeKdfAlgorithm): AmeSymPrimitive {.role: parser.} =
  ## a: KDF slot mapped onto the implementation that runs it.
  case a
  of akfaBlake3: result = aspBlake3
  of akfaSha3Shake256: result = aspSha3
  of akfaGimliXof: result = aspGimli
  of akfaArgon2id: result = aspArgon2

proc ameSymPrimitiveName*(p: AmeSymPrimitive): string {.role: parser.} =
  ## p: primitive rendered as the exact text the build flag accepts.
  case p
  of aspBlake3: result = "blake3"
  of aspSha3: result = "sha3"
  of aspGimli: result = "gimli"
  of aspChaCha20: result = "chacha20"
  of aspAes: result = "aes"
  of aspPoly1305: result = "poly1305"
  of aspArgon2: result = "argon2"

proc parseAmeSymPrimitives*(s: string): set[AmeSymPrimitive] {.role: parser.} =
  ## s: comma-separated primitive names from `-d:bifrostSymmetric=`. An empty
  ## string means all. Runs while compiling; an unknown name stops the build.
  ##
  ## BLAKE3 is always added, whatever the flag says. AME uses it internally
  ## to normalize a MAC tag to the common length and to derive Argon2's
  ## salt, so the protocol does not work without it. It is also the
  ## cheapest primitive here, so nothing is lost by keeping it.
  var
    t: string = ""
  if s.strip().len == 0:
    return {aspBlake3, aspSha3, aspGimli, aspChaCha20, aspAes, aspPoly1305,
      aspArgon2}
  for raw in s.split(','):
    t = raw.strip()
    case t
    of "blake3": result.incl(aspBlake3)
    of "sha3": result.incl(aspSha3)
    of "gimli": result.incl(aspGimli)
    of "chacha20": result.incl(aspChaCha20)
    of "aes": result.incl(aspAes)
    of "poly1305": result.incl(aspPoly1305)
    of "argon2": result.incl(aspArgon2)
    else:
      raise newException(ValueError,
        "unknown -d:bifrostSymmetric entry '" & t &
        "' (expected: blake3, sha3, gimli, chacha20, aes, poly1305, argon2, " &
        "or omit the flag for all)")
  result.incl(aspBlake3)
