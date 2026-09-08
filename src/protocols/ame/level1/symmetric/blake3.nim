## -------------------------------------------------------------------------
## AME BLAKE3 <- the hash, MAC and KDF slots BLAKE3 serves
## -------------------------------------------------------------------------
##
## Always compiled. Besides its own slots, AME uses BLAKE3 internally to
## normalize a MAC tag to the common length and to derive Argon2's salt, so
## the protocol does not work without it.

import tyr/hashes/blake3 as tyr_blake3
import tyr/macs/hmac as tyr_hmac

import ../../../types
import bifrostPragmas

proc blake3AmeHash*(data: openArray[byte], outLen: int): ByteSeq {.
    role: helper.} =
  ## data/outLen: bytes to hash and requested digest length.
  result = tyr_blake3.blake3Hash(data, outLen)

proc blake3AmeMac*(key, data: openArray[byte], outLen: int): ByteSeq {.
    role: helper.} =
  ## key/data/outLen: MAC key, authenticated bytes, requested tag length.
  result = tyr_hmac.blake3CustomHmac(key, data, outLen)
