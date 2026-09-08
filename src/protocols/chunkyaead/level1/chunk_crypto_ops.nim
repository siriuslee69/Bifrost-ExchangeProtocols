## ----------------------------------------------------------------
## CHUNKYAEAD Chunk Ops <- format-compatible per-buffer transform
## ----------------------------------------------------------------

import tyr/ciphers/xchacha20 as tyr_xchacha
import tyr/ciphers/aes_ctr as tyr_aes
import tyr/ciphers/gimli_sponge as tyr_gimli
import ../level0/types
import ../../../analysis_pragmas

const xchachaBlockLen = 64

type ChunkCryptoState* {.role: memory, metaTags: {tagChunkyAead,
    tagCryptoBoundary}.} = object
  algo: ChunkyAlgo
  keyXs: array[32, uint8]
  xEnabled: bool
  ns: array[24, uint8]
  xCounter: uint32
  aes: tyr_aes.AesCtrState
  aesEnabled: bool
  gStream, gTag: tyr_gimli.GimliSpongeState
  streamBufs: seq[uint8]

proc blocksForLen(l, b: int): uint32 {.role: helper,
    metaTags: {tagChunkyAead}.} =
  if l > 0: result = uint32((l + b - 1) div b)

proc deriveAesNonce(ns: array[24, uint8]): array[16, uint8] {.
    role: truthBuilder, metaTags: {tagChunkyAead, tagCryptoBoundary}.} =
  var i: int
  while i < result.len:
    result[i] = ns[i]
    i = i + 1

proc initGimliStream(s: var tyr_gimli.GimliSpongeState,
    ks: array[32, uint8], ns: array[24, uint8]) {.role: actor,
    metaTags: {tagChunkyAead, tagCryptoBoundary}.} =
  tyr_gimli.gimliAbsorbInit(s)
  tyr_gimli.gimliAbsorbUpdate(s, ks)
  tyr_gimli.gimliAbsorbUpdate(s, ns)
  tyr_gimli.gimliAbsorbFinal(s)

proc initGimliTag(s: var tyr_gimli.GimliSpongeState, ks: array[32, uint8],
    ns: array[24, uint8]) {.role: actor,
    metaTags: {tagChunkyAead, tagCryptoBoundary}.} =
  tyr_gimli.gimliAbsorbInit(s)
  tyr_gimli.gimliAbsorbUpdate(s, ks)
  tyr_gimli.gimliAbsorbUpdate(s, ns)

proc gimliStreamXorInPlace(s: var ChunkCryptoState,
    bs: var openArray[uint8]) {.role: encryptor,
    metaTags: {tagChunkyAead, tagCryptoBoundary}.} =
  var i: int
  if bs.len == 0: return
  if s.streamBufs.len < bs.len: s.streamBufs.setLen(bs.len)
  tyr_gimli.gimliSqueezeInto(s.gStream, s.streamBufs.toOpenArray(0, bs.high))
  while i < bs.len:
    bs[i] = bs[i] xor s.streamBufs[i]
    i = i + 1

proc initChunkCryptoState*(s: var ChunkCryptoState, a: ChunkyAlgo, kxs, kas,
    kgs: array[32, uint8], ns: array[24, uint8], b: int) {.role: actor,
    metaTags: {tagChunkyAead, tagCryptoBoundary}.} =
  ## a/kxs/kas/kgs/ns/b: algorithm, stage keys, nonce, and buffer capacity.
  s.algo = a
  s.keyXs = kxs
  s.xEnabled = a in {caXChaCha20Gimli, caXChaCha20AesGimli}
  s.ns = ns
  s.aesEnabled = a in {caAesGimli, caXChaCha20AesGimli}
  if s.aesEnabled: s.aes = tyr_aes.initAesCtrState(kas, deriveAesNonce(ns))
  initGimliStream(s.gStream, kgs, ns)
  initGimliTag(s.gTag, kgs, ns)
  if b > 0: s.streamBufs.setLen(b)

proc encryptChunkBuffer*(s: var ChunkCryptoState,
    bs: var openArray[uint8]) {.role: encryptor,
    metaTags: {tagAppApi, tagChunkyAead, tagCryptoBoundary}.} =
  var blocks: uint32
  if bs.len == 0: return
  if s.xEnabled:
    tyr_xchacha.xchacha20XorInPlace(s.keyXs, s.ns, s.xCounter, bs)
    blocks = blocksForLen(bs.len, xchachaBlockLen)
    s.xCounter = s.xCounter + blocks
  if s.aesEnabled: tyr_aes.aesCtrXorInPlace(s.aes, bs, tyr_aes.acbAuto)
  gimliStreamXorInPlace(s, bs)
  tyr_gimli.gimliAbsorbUpdate(s.gTag, bs)

proc decryptChunkBuffer*(s: var ChunkCryptoState,
    bs: var openArray[uint8]) {.role: decryptor,
    metaTags: {tagAppApi, tagChunkyAead, tagCryptoBoundary}.} =
  var blocks: uint32
  if bs.len == 0: return
  tyr_gimli.gimliAbsorbUpdate(s.gTag, bs)
  gimliStreamXorInPlace(s, bs)
  if s.aesEnabled: tyr_aes.aesCtrXorInPlace(s.aes, bs, tyr_aes.acbAuto)
  if s.xEnabled:
    tyr_xchacha.xchacha20XorInPlace(s.keyXs, s.ns, s.xCounter, bs)
    blocks = blocksForLen(bs.len, xchachaBlockLen)
    s.xCounter = s.xCounter + blocks

proc finalizeChunkTag*(s: var ChunkCryptoState,
    ts: var openArray[uint8]) {.role: truthBuilder,
    metaTags: {tagAppApi, tagChunkyAead, tagCryptoBoundary}.} =
  tyr_gimli.gimliAbsorbFinal(s.gTag)
  tyr_gimli.gimliSqueezeInto(s.gTag, ts)
