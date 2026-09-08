## -------------------------------------------------------------------------
## AME SHA-3 <- the SHA3, SHAKE256, MAC and KDF slots this primitive serves
## -------------------------------------------------------------------------

import tyr/hashes/sha3 as tyr_sha3
import tyr/macs/hmac as tyr_hmac

import ../../../types
import bifrostPragmas

proc sha3AmeHash*(data: openArray[byte], outLen: int): ByteSeq {.
    role: helper.} =
  ## data/outLen: bytes to hash and requested fixed digest length.
  result = tyr_sha3.sha3Hash(data, outLen)

proc shake256AmeHash*(data: openArray[byte], outLen: int): ByteSeq {.
    role: helper.} =
  ## data/outLen: bytes to hash and any requested extendable output length.
  result = tyr_sha3.shake256Tyr(data, outLen)

proc sha3AmeMac*(key, data: openArray[byte], outLen: int): ByteSeq {.
    role: helper.} =
  ## key/data/outLen: MAC key, authenticated bytes, requested tag length.
  result = tyr_hmac.sha3CustomHmac(key, data, outLen)
