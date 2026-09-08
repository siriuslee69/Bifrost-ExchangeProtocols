## ----------------------------------------------------------
## CHUNKYAEAD Nonce Ops <- deterministic per-chunk derivation
## ----------------------------------------------------------

import bifrostPragmas

proc storeU64LE(v: uint64, bs: var openArray[uint8], o: int) {.role: helper,
    metaTags: {tagChunkyAead}.} =
  var i: int
  while i < 8:
    bs[o + i] = uint8((v shr (i * 8)) and 0xff)
    i = i + 1

proc deriveChunkNonce*(bs: array[24, uint8], i: uint64): array[24, uint8] {.
    role: truthBuilder, metaTags: {tagAppApi, tagChunkyAead,
    tagCryptoBoundary}.} =
  ## bs/i: base nonce and zero-based chunk index.
  result = bs
  storeU64LE(i, result, 16)
