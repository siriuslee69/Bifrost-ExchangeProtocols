## -------------------------------------------------------------------------
## GB3HKDF <- XOR-combined Gimli and BLAKE3 forward key derivation
## -------------------------------------------------------------------------

import tyr/hashes/blake3 as tyr_blake3
import tyr/ciphers/gimli_sponge as tyr_gimli

import ../../types
import ../../ame/level0/bytes
import ../types
import ../../../analysis_pragmas

proc initGb3KdfConfig*(rounds: uint32 = gb3DefaultRounds,
    blockIndex: uint64 = 0'u64, mode: Gb3KdfMode = gb3Sequential,
    memoryBlocks: uint32 = gb3DefaultMemoryBlocks): Gb3KdfConfig {.
    role: configurator, metaTags: {tagAppApi, tagFomke, tagKdf}.} =
  ## rounds: sequential iterations or memory-mixing passes.
  ## blockIndex: first 32-byte output block selected by the caller.
  ## mode/memoryBlocks: direct expansion or bounded Argon-style memory mixing.
  if rounds == 0'u32 or rounds > gb3MaxRounds:
    raise newException(ValueError, "GB3HKDF rounds must be in 1..1000000")
  if mode == gb3MemoryMixed and
      (memoryBlocks < 8'u32 or memoryBlocks > gb3MaxMemoryBlocks):
    raise newException(ValueError,
      "GB3HKDF memory blocks must be in 8..65536")
  result.rounds = rounds
  result.blockIndex = blockIndex
  result.mode = mode
  result.memoryBlocks = memoryBlocks

proc validateGb3Request(c: Gb3KdfConfig, outLen: int) {.role: parser,
    metaTags: {tagFomke, tagKdf, tagValidation}.} =
  ## c/outLen: bounded work and output request.
  discard initGb3KdfConfig(c.rounds, c.blockIndex, c.mode, c.memoryBlocks)
  if outLen <= 0 or outLen > gb3MaxOutputBytes:
    raise newException(ValueError,
      "GB3HKDF output length must be in 1..1048576")
  if c.mode == gb3MemoryMixed and
      uint64(c.rounds) * uint64(c.memoryBlocks) > gb3MaxWorkBlocks:
    raise newException(ValueError, "GB3HKDF memory work exceeds its limit")
  if c.mode == gb3Sequential and uint64(c.rounds) *
      uint64((outLen + gb3BlockBytes - 1) div gb3BlockBytes) >
      gb3MaxWorkBlocks:
    raise newException(ValueError, "GB3HKDF sequential work exceeds its limit")

proc appendGb3Field(A: var ByteSeq, B: openArray[uint8]) {.
    role: dataWriter, metaTags: {tagFomke, tagKdf}.} =
  ## A/B: destination and one length-framed byte field.
  if uint64(B.len) > uint64(high(uint32)):
    raise newException(ValueError, "GB3HKDF input field exceeds u32")
  appendAmeU32(A, uint32(B.len))
  appendAmeBytes(A, B)

proc buildGb3Input(ikm, salt, info: openArray[uint8],
    c: Gb3KdfConfig): ByteSeq {.role: truthBuilder,
    metaTags: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## ikm/salt/info/c: secret input, salt, purpose, and work policy.
  appendAmeLabel(result, "BIFROST-GB3HKDF-v1")
  result.add(uint8(ord(c.mode)))
  appendAmeU32(result, c.rounds)
  appendAmeU64(result, c.blockIndex)
  appendAmeU32(result, c.memoryBlocks)
  appendGb3Field(result, salt)
  appendGb3Field(result, info)
  appendGb3Field(result, ikm)

proc deriveGb3Branch(label: string, key, material: openArray[uint8],
    blockIndex: uint64, round: uint32): ByteSeq {.role: truthBuilder,
    metaTags: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## label/key/material/blockIndex/round: one domain-separated 32-byte branch.
  var
    seed: ByteSeq = @[]
    nonce: ByteSeq = @[]
  appendAmeLabel(seed, label)
  appendAmeU64(seed, blockIndex)
  appendAmeU32(seed, round)
  appendGb3Field(seed, material)
  if label == "GB3-GIMLI-v1":
    appendAmeLabel(nonce, "GB3-GIMLI-NONCE-v1")
    appendAmeU64(nonce, blockIndex)
    appendAmeU32(nonce, round)
    result = tyr_gimli.gimliXof(key, nonce, seed, gb3BlockBytes)
  else:
    result = tyr_blake3.blake3DeriveKey("BIFROST-GB3-BLAKE3-v1", seed,
      gb3BlockBytes)
  secureClearAmeBytes(seed)
  secureClearAmeBytes(nonce)

proc deriveGb3SequentialBlock(base: openArray[uint8], blockIndex: uint64,
    rounds: uint32): ByteSeq {.role: truthBuilder,
    metaTags: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## base/blockIndex/rounds: framed input, selected block, and iteration count.
  var
    state: ByteSeq = @base
    gimli: ByteSeq = @[]
    blake: ByteSeq = @[]
    nextState: ByteSeq = @[]
    round: uint32 = 0'u32
  while round < rounds:
    gimli = deriveGb3Branch("GB3-GIMLI-v1", base, state, blockIndex, round)
    blake = deriveGb3Branch("GB3-BLAKE3-v1", base, state, blockIndex, round)
    nextState = xorAmeOverlay(gimli, blake)
    secureClearAmeBytes(gimli)
    secureClearAmeBytes(blake)
    secureClearAmeBytes(state)
    state = nextState
    round = round + 1'u32
  result = state

proc readGb3U64(A: openArray[uint8]): uint64 {.role: parser,
    metaTags: {tagFomke, tagKdf}.} =
  ## A: at least eight bytes interpreted as little-endian u64.
  var
    i: int = 0
  if A.len < 8:
    raise newException(ValueError, "GB3HKDF address block is too short")
  while i < 8:
    result = result or (uint64(A[i]) shl (8 * i))
    i = i + 1

proc gb3MemoryAddress(base: openArray[uint8], pass, position,
    count: uint32): int {.role: parser, metaTags: {tagFomke, tagKdf}.} =
  ## base/pass/position/count: public-shape address schedule for memory mixing.
  var
    seed: ByteSeq = @[]
    digest: ByteSeq = @[]
  appendAmeLabel(seed, "GB3-MEMORY-ADDRESS-v1")
  appendAmeU32(seed, pass)
  appendAmeU32(seed, position)
  appendAmeU32(seed, count)
  appendAmeU32(seed, uint32(base.len))
  appendAmeU32(seed, uint32(base.len))
  digest = tyr_blake3.blake3Hash(seed, 8)
  result = int(readGb3U64(digest) mod uint64(count))
  secureClearAmeBytes(digest)

proc fillGb3Memory(base: openArray[uint8], count: uint32): seq[ByteSeq] {.
    role: truthBuilder, metaTags: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## base/count: framed input and bounded 32-byte memory block count.
  var
    i: uint32 = 0'u32
  result.setLen(int(count))
  while i < count:
    result[int(i)] = deriveGb3SequentialBlock(base, uint64(i), 1'u32)
    i = i + 1'u32

proc mixGb3MemoryPass(M: var seq[ByteSeq], base: openArray[uint8],
    pass: uint32) {.role: actor,
    metaTags: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## M/base/pass: memory matrix, original input, and current mixing pass.
  var
    i: uint32 = 0'u32
    previous: int = 0
    reference: int = 0
    material: ByteSeq = @[]
    mixed: ByteSeq = @[]
  while i < uint32(M.len):
    previous = if i == 0'u32: M.len - 1 else: int(i - 1'u32)
    reference = gb3MemoryAddress(base, pass, i, uint32(M.len))
    secureClearAmeBytes(material)
    material = @[]
    appendAmeLabel(material, "GB3-MEMORY-MIX-v1")
    appendAmeU32(material, pass)
    appendAmeU32(material, i)
    appendGb3Field(material, M[int(i)])
    appendGb3Field(material, M[previous])
    appendGb3Field(material, M[reference])
    mixed = deriveGb3SequentialBlock(material, uint64(i), 1'u32)
    secureClearAmeBytes(M[int(i)])
    M[int(i)] = mixed
    i = i + 1'u32
  secureClearAmeBytes(material)

proc clearGb3Memory(M: var seq[ByteSeq]) {.role: actor,
    metaTags: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## M: secret memory blocks overwritten before release.
  var
    i: int = 0
  while i < M.len:
    secureClearAmeBytes(M[i])
    i = i + 1
  M.setLen(0)

proc appendGb3Output(resultBytes: var ByteSeq, outputChunk: openArray[uint8],
    wanted: int) {.role: dataWriter, metaTags: {tagFomke, tagKdf}.} =
  ## resultBytes/outputChunk/wanted: output, source block, and final total length.
  var
    i: int = 0
    remaining: int = wanted - resultBytes.len
    count: int = min(remaining, outputChunk.len)
  while i < count:
    resultBytes.add(outputChunk[i])
    i = i + 1

proc deriveGb3Sequential(base: openArray[uint8], outLen: int,
    c: Gb3KdfConfig): ByteSeq {.role: truthBuilder,
    metaTags: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## base/outLen/c: framed input, output length, and sequential policy.
  var
    outputChunk: ByteSeq = @[]
    offset: uint64 = 0'u64
  while result.len < outLen:
    if high(uint64) - c.blockIndex < offset:
      raise newException(ValueError, "GB3HKDF block index is exhausted")
    outputChunk = deriveGb3SequentialBlock(base, c.blockIndex + offset,
      c.rounds)
    appendGb3Output(result, outputChunk, outLen)
    secureClearAmeBytes(outputChunk)
    offset = offset + 1'u64

proc deriveGb3Memory(base: openArray[uint8], outLen: int,
    c: Gb3KdfConfig): ByteSeq {.role: truthBuilder,
    metaTags: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## base/outLen/c: framed input, output length, and memory-mixed policy.
  var
    M: seq[ByteSeq] = @[]
    pass: uint32 = 0'u32
    outputBlock: uint64 = 0'u64
    reference: int = 0
    material: ByteSeq = @[]
    outputChunk: ByteSeq = @[]
  M = fillGb3Memory(base, c.memoryBlocks)
  while pass < c.rounds:
    mixGb3MemoryPass(M, base, pass)
    pass = pass + 1'u32
  while result.len < outLen:
    if high(uint64) - c.blockIndex < outputBlock:
      clearGb3Memory(M)
      raise newException(ValueError, "GB3HKDF block index is exhausted")
    reference = gb3MemoryAddress(base, uint32(outputBlock and
      uint64(high(uint32))), uint32(c.blockIndex mod uint64(c.memoryBlocks)),
      c.memoryBlocks)
    secureClearAmeBytes(material)
    material = @[]
    appendAmeLabel(material, "GB3-MEMORY-OUTPUT-v1")
    appendAmeU64(material, c.blockIndex + outputBlock)
    appendGb3Field(material, M[reference])
    outputChunk = deriveGb3SequentialBlock(material, c.blockIndex + outputBlock,
      1'u32)
    appendGb3Output(result, outputChunk, outLen)
    secureClearAmeBytes(outputChunk)
    outputBlock = outputBlock + 1'u64
  secureClearAmeBytes(material)
  clearGb3Memory(M)

proc deriveGb3Hkdf*(ikm, salt, info: openArray[uint8], outLen: int,
    c: Gb3KdfConfig = initGb3KdfConfig()): ByteSeq {.role: truthBuilder,
    metaTags: {tagAppApi, tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## ikm/salt/info: secret input, optional salt, and domain context.
  ## outLen/c: requested bytes and bounded block/round/memory policy.
  var
    base: ByteSeq = @[]
  validateGb3Request(c, outLen)
  if ikm.len == 0:
    raise newException(ValueError, "GB3HKDF input key material is empty")
  base = buildGb3Input(ikm, salt, info, c)
  if c.mode == gb3MemoryMixed:
    result = deriveGb3Memory(base, outLen, c)
  else:
    result = deriveGb3Sequential(base, outLen, c)
  secureClearAmeBytes(base)

proc deriveGb3HkdfInputs*(chainKey: openArray[uint8],
    S: openArray[ByteSeq], info: openArray[uint8], outLen: int,
    c: Gb3KdfConfig = initGb3KdfConfig()): ByteSeq {.role: truthBuilder,
    metaTags: {tagAppApi, tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## chainKey: current forward-only root or chain key.
  ## S: additional secrets consumed in caller-defined canonical order.
  ## info/outLen/c: transcript context, requested bytes, and work policy.
  var
    ikm: ByteSeq = @[]
    i: int = 0
  appendAmeLabel(ikm, "GB3-MULTI-INPUT-v1")
  appendGb3Field(ikm, chainKey)
  appendAmeU32(ikm, uint32(S.len))
  while i < S.len:
    if S[i].len == 0:
      secureClearAmeBytes(ikm)
      raise newException(ValueError, "GB3HKDF additional secret is empty")
    appendGb3Field(ikm, S[i])
    i = i + 1
  result = deriveGb3Hkdf(ikm, @[], info, outLen, c)
  secureClearAmeBytes(ikm)
