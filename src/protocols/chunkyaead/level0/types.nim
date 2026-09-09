## -----------------------------------------------------------------------
## CHUNKYAEAD Types <- chunked file format and owned cipher configuration
## -----------------------------------------------------------------------

import runePragmas

const
  chunkyMagic* = [byte('C'), byte('H'), byte('U'), byte('N'), byte('K'),
    byte('Y'), byte('0'), byte('1')]
  chunkyVersion* = 1'u8
  defaultChunkBytes* = 1_073_741_824'i64
  fallbackChunkBytes* = 524_288_000'i64
  lowRamThresholdBytes* = 4_294_967_296'i64
  defaultBufferBytes* = 8_388_608
  defaultTagLen* = 64'u16

type
  ChunkyAlgo* = enum
    caXChaCha20Gimli, caAesGimli, caXChaCha20AesGimli

  HashAlgo* = enum
    haBlake3Tree, haGimliTree

  ChunkyCipherState* {.role: truthState, tag: "chunkyAead|cryptoBoundary|types".} = object
    ## algo: composite chunk transform represented by the ordered keys.
    algo*: ChunkyAlgo
    ## keys: ordered, fixed-width encryption keys for the selected suite.
    keys*: seq[array[32, uint8]]
    ## nonce: 24-byte base nonce from which per-chunk nonces are derived.
    nonce*: array[24, uint8]
    ## tagLen: requested Gimli authentication tag length.
    tagLen*: uint16

  ChunkyOptions* = object
    chunkBytes*: int64
    forceChunkBytes*: bool
    maxThreads*: int
    bufferBytes*: int
    outputDir*: string
    algo*: ChunkyAlgo
    tagLen*: uint16

  ChunkyManifest* = object
    version*: uint8
    algo*: ChunkyAlgo
    chunkBytes*: int64
    tagLen*: uint16
    chunkCount*: int
    originalSize*: int64
    baseNonce*: array[24, uint8]
    fileName*: string
    chunkFiles*: seq[string]

  ChunkHeader* = object
    magic*: array[8, uint8]
    version*: uint8
    algo*: ChunkyAlgo
    tagLen*: uint16
    chunkIndex*: uint64
    plainLen*: uint64
    nonce*: array[24, uint8]

  ChunkEncryptTask* = object
    inputPath*: string
    outputPath*: string
    chunkIndex*: uint64
    chunkOffset*: int64
    chunkLen*: int64
    baseNonce*: array[24, uint8]
    keyXs*: array[32, uint8]
    keyAs*: array[32, uint8]
    keyGs*: array[32, uint8]
    tagLen*: uint16
    bufferBytes*: int
    algo*: ChunkyAlgo
    ok*: bool
    err*: string

  ChunkDecryptTask* = object
    inputPath*: string
    outputPath*: string
    chunkIndex*: uint64
    baseNonce*: array[24, uint8]
    keyXs*: array[32, uint8]
    keyAs*: array[32, uint8]
    keyGs*: array[32, uint8]
    bufferBytes*: int
    ok*: bool
    err*: string

  ChunkHashTask* = object
    inputPath*: string
    chunkOffset*: int64
    chunkLen*: int64
    bufferBytes*: int
    algo*: HashAlgo
    hashs*: seq[uint8]
    ok*: bool
    err*: string

proc chunkyKeyCount(a: ChunkyAlgo): int {.role: parser,
    tag: "chunkyAead|cryptoBoundary".} =
  ## a: selected CHUNKYAEAD transform.
  case a
  of caXChaCha20Gimli, caAesGimli:
    result = 2
  of caXChaCha20AesGimli:
    result = 3

proc initChunkyCipherState*(a: ChunkyAlgo, K: openArray[array[32, uint8]],
    n: array[24, uint8], t: uint16 = defaultTagLen): ChunkyCipherState {.
    role: truthBuilder, tag: "chunkyAead|cryptoBoundary".} =
  ## a/K/n/t: transform, ordered fixed-width keys, base nonce, and tag length.
  if K.len != chunkyKeyCount(a):
    raise newException(ValueError, "CHUNKYAEAD key count mismatch")
  if t == 0'u16:
    raise newException(ValueError, "CHUNKYAEAD tag length must be positive")
  result.algo = a
  result.keys = @K
  result.nonce = n
  result.tagLen = t

proc initChunkyCipherState*(a: ChunkyAlgo, K: openArray[seq[uint8]],
    n: openArray[uint8], t: uint16 = defaultTagLen): ChunkyCipherState {.
    role: truthBuilder, tag: "chunkyAead|cryptoBoundary".} =
  ## a/K/n/t: transform, byte-sequence keys, base nonce, and tag length.
  var
    keys: seq[array[32, uint8]] = @[]
    nonce: array[24, uint8]
    i: int = 0
    j: int = 0
  if K.len != chunkyKeyCount(a):
    raise newException(ValueError, "CHUNKYAEAD key count mismatch")
  if n.len != nonce.len:
    raise newException(ValueError, "CHUNKYAEAD nonce must be 24 bytes")
  keys.setLen(K.len)
  while i < K.len:
    if K[i].len != keys[i].len:
      raise newException(ValueError, "CHUNKYAEAD keys must be 32 bytes")
    j = 0
    while j < keys[i].len:
      keys[i][j] = K[i][j]
      j = j + 1
    i = i + 1
  i = 0
  while i < nonce.len:
    nonce[i] = n[i]
    i = i + 1
  result = initChunkyCipherState(a, keys, nonce, t)

proc initChunkyOptions*(): ChunkyOptions {.role: configurator,
    tag: "chunkyAead".} =
  result.chunkBytes = defaultChunkBytes
  result.bufferBytes = defaultBufferBytes
  result.algo = caXChaCha20AesGimli
  result.tagLen = defaultTagLen
