## ---------------------------------------------------------------
## CHUNKYAEAD Header Ops <- the 53 bytes at the start of every chunk file
## ---------------------------------------------------------------
##
##   0..7 magic | 8 version | 9 algorithm | 10..11 tag length | 12..19 chunk index
##   20..27 plain length | 28..51 nonce | 52 flags (bit 0: the LAST chunk)
##
## Both directions live here, side by side: the writer's `encodeHeader` and the
## reader's `decodeHeader`. The tag covers exactly these bytes (level1/chunk_crypto_ops).

import ../level0/types
import runePragmas

const
  chunkHeaderLen* = 53

proc storeU16Le(v: uint16, bs: var openArray[uint8], o: int) {.role: helper,
    tag: "chunkyAead|codecBoundary".} =
  bs[o] = uint8(v and 0xff)
  bs[o + 1] = uint8((v shr 8) and 0xff)

proc storeU64Le(v: uint64, bs: var openArray[uint8], o: int) {.role: helper,
    tag: "chunkyAead|codecBoundary".} =
  bs[o] = uint8(v and 0xff)
  bs[o + 1] = uint8((v shr 8) and 0xff)
  bs[o + 2] = uint8((v shr 16) and 0xff)
  bs[o + 3] = uint8((v shr 24) and 0xff)
  bs[o + 4] = uint8((v shr 32) and 0xff)
  bs[o + 5] = uint8((v shr 40) and 0xff)
  bs[o + 6] = uint8((v shr 48) and 0xff)
  bs[o + 7] = uint8((v shr 56) and 0xff)

proc loadU16Le(bs: openArray[uint8], o: int): uint16 {.role: parser,
    tag: "chunkyAead|codecBoundary|parsing".} =
  result = uint16(bs[o]) or (uint16(bs[o + 1]) shl 8)

proc loadU64Le(bs: openArray[uint8], o: int): uint64 {.role: parser,
    tag: "chunkyAead|codecBoundary|parsing".} =
  result =
    (uint64(bs[o]) or
    (uint64(bs[o + 1]) shl 8) or
    (uint64(bs[o + 2]) shl 16) or
    (uint64(bs[o + 3]) shl 24) or
    (uint64(bs[o + 4]) shl 32) or
    (uint64(bs[o + 5]) shl 40) or
    (uint64(bs[o + 6]) shl 48) or
    (uint64(bs[o + 7]) shl 56))

proc encodeHeader*(h: ChunkHeader): array[chunkHeaderLen, uint8] {.
    role: dataWriter, tag: "chunkyAead|codecBoundary".} =
  var
    bs: array[chunkHeaderLen, uint8] = default(array[chunkHeaderLen, uint8])
    o: int = 0
    i: int = 0
  i = 0
  while i < h.magic.len:
    bs[o] = h.magic[i]
    i = i + 1
    o = o + 1
  bs[o] = h.version
  o = o + 1
  bs[o] = uint8(ord(h.algo))
  o = o + 1
  storeU16Le(h.tagLen, bs, o)
  o = o + 2
  storeU64Le(h.chunkIndex, bs, o)
  o = o + 8
  storeU64Le(h.plainLen, bs, o)
  o = o + 8
  i = 0
  while i < h.nonce.len:
    bs[o] = h.nonce[i]
    i = i + 1
    o = o + 1
  bs[o] = h.flags
  result = bs

proc decodeHeader*(bs: array[chunkHeaderLen, uint8]): ChunkHeader {.
    role: parser, tag: "chunkyAead|codecBoundary|parsing".} =
  var
    h: ChunkHeader = default(ChunkHeader)
    o: int = 0
    i: int = 0
  i = 0
  while i < h.magic.len:
    h.magic[i] = bs[o]
    i = i + 1
    o = o + 1
  h.version = bs[o]
  o = o + 1
  if int(bs[o]) > ord(high(ChunkyAlgo)):
    ## An enum built from a byte it does not hold is a crash (or, with
    ## -d:danger, undefined): the byte is checked first.
    raise newException(ValueError, "unsupported chunk algorithm")
  h.algo = ChunkyAlgo(bs[o])
  o = o + 1
  h.tagLen = loadU16Le(bs, o)
  o = o + 2
  h.chunkIndex = loadU64Le(bs, o)
  o = o + 8
  h.plainLen = loadU64Le(bs, o)
  o = o + 8
  i = 0
  while i < h.nonce.len:
    h.nonce[i] = bs[o]
    i = i + 1
    o = o + 1
  h.flags = bs[o]
  result = h

