## -------------------------------------------------------------------------
## XHKDF <- XOR-combined multi-hash forward key derivation
## -------------------------------------------------------------------------
##
## Every round runs each selected hash function ("branch") over the same
## input and XORs the 32-byte answers. The result stays secret while ANY ONE
## selected branch stays unbroken:
##
##   branches = {xbBlake3, xbGimli}          (the default, bit mask 0x05)
##
##   state(r) --+--> BLAKE3 branch --+
##              |                    +--XOR--> state(r+1)
##              +--> Gimli branch  --+
##
## Which branches run is a bit mask (`set[XhkdfBranch]`, one byte):
##
##   bit  value  branch     compiled when
##   ---  -----  ---------  ----------------------------------------
##    0   0x01   BLAKE3     always (AME cannot run without it)
##    1   0x02   SHAKE256   `sha3` is in -d:bifrostSymmetric
##    2   0x04   Gimli-XOF  `gimli` is in -d:bifrostSymmetric
##
## The mask comes from the agreed layout (`xhkdfBranchesOf`), so both ends
## always pick the same branches. A branch this build left out is refused
## before any key material is touched; its code is not in the program.
##
## Byte compatibility: the default mask {BLAKE3, Gimli} derives exactly the
## bytes the earlier GB3HKDF did. The "GB3-..." domain labels are therefore
## kept as they are -- renaming them would change every derived key.
##
## One copy of every hash: the branches call the same Tyr modules the rest
## of AME calls (tyr/hashes/blake3, tyr/ciphers/gimli_sponge, and SHA-3 via
## AME's own symmetric layer). Nim compiles a module once per program no
## matter how many modules import it, so Gimli used here, in AM1P and in
## the frame tags is one Gimli in the binary.

import tyr/hashes/blake3 as tyr_blake3

import ../../types
import ../../ame/types
import ../../ame/level0/bytes
import ../../ame/level1/exchange_paths
import ../../ame/level1/symmetric
import ../types
import runePragmas

when aspGimli in ameSymBuilt:
  import tyr/ciphers/gimli_sponge as tyr_gimli

const
  xhkdfBranchesBuilt*: set[XhkdfBranch] = block:
    ## The branches this build can run: BLAKE3, plus SHAKE256 and Gimli when
    ## -d:bifrostSymmetric keeps them.
    var
      t: set[XhkdfBranch] = {xbBlake3}
    if aspSha3 in ameSymBuilt: t.incl(xbShake256)
    if aspGimli in ameSymBuilt: t.incl(xbGimli)
    t
  xhkdfLegacyBranches: set[XhkdfBranch] = {xbBlake3, xbGimli}
    ## The pair GB3HKDF always ran. This mask adds nothing to the input, so
    ## it keeps deriving the same bytes as before.
  xhkdfDefaultBranches*: set[XhkdfBranch] =
    xhkdfLegacyBranches * xhkdfBranchesBuilt
    ## BLAKE3 + Gimli, or BLAKE3 alone in a build without Gimli.

proc xhkdfBranchMask*(B: set[XhkdfBranch]): uint8 {.role: parser, inline.} =
  ## B: branch set -> its one-byte bit mask (bit n = branch value n).
  result = cast[uint8](B)

proc xhkdfBranchesFromMask*(m: uint8): set[XhkdfBranch] {.role: parser.} =
  ## m: bit mask read from a checkpoint. Unknown bits are refused.
  if (m and not 0x07'u8) != 0'u8 or m == 0'u8:
    raise newException(ValueError, "XHKDF branch mask is invalid")
  result = cast[set[XhkdfBranch]](m)

proc xhkdfBranchOfKdf(a: AmeKdfAlgorithm): set[XhkdfBranch] {.role: parser.} =
  ## a: one layout KDF slot -> the branch it asks for. Argon2id is a
  ## password-hardening step, not a hash, and asks for none.
  case a
  of akfaBlake3: result = {xbBlake3}
  of akfaSha3Shake256: result = {xbShake256}
  of akfaGimliXof: result = {xbGimli}
  of akfaArgon2id: result = {}

proc xhkdfBranchesOf*(L: AmeSuiteLayout, t: AmeMaskTier): set[XhkdfBranch] {.
    role: parser, tag: "fomke|kdf".} =
  ## L/t: the agreed layout and tier -> the branches its active KDF slots
  ## name. BLAKE3 when they name none (an Argon2-only tier).
  ##
  ##   layout KDF slots        tier mask    branches
  ##   ---------------------   ----------   ---------------------
  ##   BLAKE3, GimliXof        0b11......   {BLAKE3, Gimli} (default)
  ##   BLAKE3, SHAKE256        0b01......   {SHAKE256}
  var
    i: int = 0
  while i < int(L.kdfs.length):
    if algorithmSlotSelected(t.masks.kdf, i):
      result = result + xhkdfBranchOfKdf(L.kdfs.algorithms[i])
    i = i + 1
  if result == {}:
    result = {xbBlake3}

proc initXhkdfConfig*(rounds: uint32 = xhkdfDefaultRounds,
    blockIndex: uint64 = 0'u64, mode: XhkdfMode = xhSequential,
    memoryBlocks: uint32 = xhkdfDefaultMemoryBlocks,
    branches: set[XhkdfBranch] = xhkdfDefaultBranches): XhkdfConfig {.
    role: configurator, tag: "appApi|fomke|kdf".} =
  ## rounds: sequential iterations or memory-mixing passes.
  ## blockIndex: first 32-byte output block selected by the caller.
  ## mode/memoryBlocks: direct expansion or bounded Argon-style memory mixing.
  ## branches: which hash functions run (see the table at the top).
  if rounds == 0'u32 or rounds > xhkdfMaxRounds:
    raise newException(ValueError, "XHKDF rounds must be in 1..1000000")
  if mode == xhMemoryMixed and
      (memoryBlocks < 8'u32 or memoryBlocks > xhkdfMaxMemoryBlocks):
    raise newException(ValueError,
      "XHKDF memory blocks must be in 8..65536")
  if branches == {}:
    raise newException(ValueError, "XHKDF needs at least one branch")
  if not (branches <= xhkdfBranchesBuilt):
    raise newException(ValueError, "XHKDF branch " &
      $(branches - xhkdfBranchesBuilt) & " is not in this build; add it to " &
      "-d:bifrostSymmetric= or omit the flag")
  result.rounds = rounds
  result.blockIndex = blockIndex
  result.mode = mode
  result.memoryBlocks = memoryBlocks
  result.branches = branches

proc validateXhkdfRequest(c: XhkdfConfig, outLen: int) {.role: parser,
    tag: "fomke|kdf|validation".} =
  ## c/outLen: bounded work and output request.
  discard initXhkdfConfig(c.rounds, c.blockIndex, c.mode, c.memoryBlocks,
    c.branches)
  if outLen <= 0 or outLen > xhkdfMaxOutputBytes:
    raise newException(ValueError,
      "XHKDF output length must be in 1..1048576")
  if c.mode == xhMemoryMixed and
      uint64(c.rounds) * uint64(c.memoryBlocks) > xhkdfMaxWorkBlocks:
    raise newException(ValueError, "XHKDF memory work exceeds its limit")
  if c.mode == xhSequential and uint64(c.rounds) *
      uint64((outLen + xhkdfBlockBytes - 1) div xhkdfBlockBytes) >
      xhkdfMaxWorkBlocks:
    raise newException(ValueError, "XHKDF sequential work exceeds its limit")

proc appendXhkdfField(A: var ByteSeq, B: openArray[uint8]) {.
    role: dataWriter, tag: "fomke|kdf".} =
  ## A/B: destination and one length-framed byte field.
  if uint64(B.len) > uint64(high(uint32)):
    raise newException(ValueError, "XHKDF input field exceeds u32")
  appendAmeU32(A, uint32(B.len))
  appendAmeBytes(A, B)

proc buildXhkdfInput(ikm, salt, info: openArray[uint8],
    c: XhkdfConfig): ByteSeq {.role: truthBuilder,
    tag: "cryptoBoundary|fomke|kdf".} =
  ## ikm/salt/info/c: secret input, salt, purpose, and work policy. A branch
  ## set other than the GB3HKDF pair is bound in, so two masks can never
  ## share an output; the pair itself adds nothing and keeps its old bytes.
  appendAmeLabel(result, "BIFROST-GB3HKDF-v1")
  result.add(uint8(ord(c.mode)))
  appendAmeU32(result, c.rounds)
  appendAmeU64(result, c.blockIndex)
  appendAmeU32(result, c.memoryBlocks)
  if c.branches != xhkdfLegacyBranches:
    appendAmeLabel(result, "XHKDF-BRANCHES-v1")
    result.add(xhkdfBranchMask(c.branches))
  appendXhkdfField(result, salt)
  appendXhkdfField(result, info)
  appendXhkdfField(result, ikm)

proc xhkdfBranchSeed(label: string, material: openArray[uint8],
    blockIndex: uint64, round: uint32): ByteSeq {.role: helper,
    tag: "fomke|kdf".} =
  ## label/material/blockIndex/round: the framed input every branch hashes.
  appendAmeLabel(result, label)
  appendAmeU64(result, blockIndex)
  appendAmeU32(result, round)
  appendXhkdfField(result, material)

proc deriveXhkdfBranch(b: XhkdfBranch, key, material: openArray[uint8],
    blockIndex: uint64, round: uint32): ByteSeq {.role: truthBuilder,
    tag: "cryptoBoundary|fomke|kdf".} =
  ## b/key/material/blockIndex/round: one domain-separated 32-byte branch.
  ## A branch left out of the build is refused by `initXhkdfConfig` long
  ## before this runs; the `raise` below only keeps the `case` complete.
  var
    seed: ByteSeq = @[]
    nonce: ByteSeq = @[]
  case b
  of xbBlake3:
    seed = xhkdfBranchSeed("GB3-BLAKE3-v1", material, blockIndex, round)
    result = tyr_blake3.blake3DeriveKey("BIFROST-GB3-BLAKE3-v1", seed,
      xhkdfBlockBytes)
  of xbShake256:
    when aspSha3 in ameSymBuilt:
      seed = xhkdfBranchSeed("XHKDF-SHAKE256-v1", material, blockIndex, round)
      appendXhkdfField(seed, key)
      result = shake256AmeHash(seed, xhkdfBlockBytes)
    else:
      raise newException(ValueError, "XHKDF SHAKE256 branch is not built")
  of xbGimli:
    when aspGimli in ameSymBuilt:
      seed = xhkdfBranchSeed("GB3-GIMLI-v1", material, blockIndex, round)
      appendAmeLabel(nonce, "GB3-GIMLI-NONCE-v1")
      appendAmeU64(nonce, blockIndex)
      appendAmeU32(nonce, round)
      result = tyr_gimli.gimliXof(key, nonce, seed, xhkdfBlockBytes)
    else:
      raise newException(ValueError, "XHKDF Gimli branch is not built")
  secureClearAmeBytes(seed)
  secureClearAmeBytes(nonce)

proc xorXhkdfBranch(layer: var ByteSeq, b: XhkdfBranch, key,
    material: openArray[uint8], blockIndex: uint64, round: uint32) {.
    role: actor, inline, tag: "cryptoBoundary|fomke|kdf".} =
  ## layer/b/...: runs branch b and XORs its 32 bytes into layer.
  var
    part: ByteSeq = deriveXhkdfBranch(b, key, material, blockIndex, round)
  xorAmeInto(layer, part)
  secureClearAmeBytes(part)

proc deriveXhkdfSequentialBlock(base: openArray[uint8], blockIndex: uint64,
    rounds: uint32, B: set[XhkdfBranch]): ByteSeq {.role: truthBuilder,
    tag: "cryptoBoundary|fomke|kdf".} =
  ## base/blockIndex/rounds/B: framed input, selected block, iteration count,
  ## and the branches XORed together each round.
  var
    state: ByteSeq = @base
    layer: ByteSeq = @[]
    round: uint32 = 0'u32
  while round < rounds:
    layer = newSeq[uint8](xhkdfBlockBytes)
    for b in B:
      xorXhkdfBranch(layer, b, base, state, blockIndex, round)
    secureClearAmeBytes(state)
    state = layer
    round = round + 1'u32
  result = state

proc readXhkdfU64(A: openArray[uint8]): uint64 {.role: parser,
    tag: "fomke|kdf".} =
  ## A: at least eight bytes interpreted as little-endian u64.
  var
    i: int = 0
  if A.len < 8:
    raise newException(ValueError, "XHKDF address block is too short")
  while i < 8:
    result = result or (uint64(A[i]) shl (8 * i))
    i = i + 1

proc xhkdfMemoryAddress(base: openArray[uint8], pass, position,
    count: uint32): int {.role: parser, tag: "fomke|kdf".} =
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
  result = int(readXhkdfU64(digest) mod uint64(count))
  secureClearAmeBytes(digest)

proc fillXhkdfMemory(base: openArray[uint8], count: uint32,
    B: set[XhkdfBranch]): seq[ByteSeq] {.
    role: truthBuilder, tag: "cryptoBoundary|fomke|kdf".} =
  ## base/count/B: framed input, bounded 32-byte block count, branches.
  var
    i: uint32 = 0'u32
  result.setLen(int(count))
  while i < count:
    result[int(i)] = deriveXhkdfSequentialBlock(base, uint64(i), 1'u32, B)
    i = i + 1'u32

proc mixXhkdfMemoryPass(M: var seq[ByteSeq], base: openArray[uint8],
    pass: uint32, B: set[XhkdfBranch]) {.role: actor,
    tag: "cryptoBoundary|fomke|kdf".} =
  ## M/base/pass/B: memory matrix, original input, mixing pass, branches.
  var
    i: uint32 = 0'u32
    previous: int = 0
    reference: int = 0
    material: ByteSeq = @[]
    mixed: ByteSeq = @[]
  while i < uint32(M.len):
    previous = if i == 0'u32: M.len - 1 else: int(i - 1'u32)
    reference = xhkdfMemoryAddress(base, pass, i, uint32(M.len))
    secureClearAmeBytes(material)
    material = @[]
    appendAmeLabel(material, "GB3-MEMORY-MIX-v1")
    appendAmeU32(material, pass)
    appendAmeU32(material, i)
    appendXhkdfField(material, M[int(i)])
    appendXhkdfField(material, M[previous])
    appendXhkdfField(material, M[reference])
    mixed = deriveXhkdfSequentialBlock(material, uint64(i), 1'u32, B)
    secureClearAmeBytes(M[int(i)])
    M[int(i)] = mixed
    i = i + 1'u32
  secureClearAmeBytes(material)

proc clearXhkdfMemory(M: var seq[ByteSeq]) {.role: actor,
    tag: "cryptoBoundary|fomke|kdf".} =
  ## M: secret memory blocks overwritten before release.
  var
    i: int = 0
  while i < M.len:
    secureClearAmeBytes(M[i])
    i = i + 1
  M.setLen(0)

proc appendXhkdfOutput(resultBytes: var ByteSeq, outputChunk: openArray[uint8],
    wanted: int) {.role: dataWriter, tag: "fomke|kdf".} =
  ## resultBytes/outputChunk/wanted: output, source block, and final total length.
  var
    i: int = 0
    remaining: int = wanted - resultBytes.len
    count: int = min(remaining, outputChunk.len)
  while i < count:
    resultBytes.add(outputChunk[i])
    i = i + 1

proc deriveXhkdfSequential(base: openArray[uint8], outLen: int,
    c: XhkdfConfig): ByteSeq {.role: truthBuilder,
    tag: "cryptoBoundary|fomke|kdf".} =
  ## base/outLen/c: framed input, output length, and sequential policy.
  var
    outputChunk: ByteSeq = @[]
    offset: uint64 = 0'u64
  while result.len < outLen:
    if high(uint64) - c.blockIndex < offset:
      raise newException(ValueError, "XHKDF block index is exhausted")
    outputChunk = deriveXhkdfSequentialBlock(base, c.blockIndex + offset,
      c.rounds, c.branches)
    appendXhkdfOutput(result, outputChunk, outLen)
    secureClearAmeBytes(outputChunk)
    offset = offset + 1'u64

proc deriveXhkdfMemory(base: openArray[uint8], outLen: int,
    c: XhkdfConfig): ByteSeq {.role: truthBuilder,
    tag: "cryptoBoundary|fomke|kdf".} =
  ## base/outLen/c: framed input, output length, and memory-mixed policy.
  var
    M: seq[ByteSeq] = @[]
    pass: uint32 = 0'u32
    outputBlock: uint64 = 0'u64
    reference: int = 0
    material: ByteSeq = @[]
    outputChunk: ByteSeq = @[]
  M = fillXhkdfMemory(base, c.memoryBlocks, c.branches)
  while pass < c.rounds:
    mixXhkdfMemoryPass(M, base, pass, c.branches)
    pass = pass + 1'u32
  while result.len < outLen:
    if high(uint64) - c.blockIndex < outputBlock:
      clearXhkdfMemory(M)
      raise newException(ValueError, "XHKDF block index is exhausted")
    reference = xhkdfMemoryAddress(base, uint32(outputBlock and
      uint64(high(uint32))), uint32(c.blockIndex mod uint64(c.memoryBlocks)),
      c.memoryBlocks)
    secureClearAmeBytes(material)
    material = @[]
    appendAmeLabel(material, "GB3-MEMORY-OUTPUT-v1")
    appendAmeU64(material, c.blockIndex + outputBlock)
    appendXhkdfField(material, M[reference])
    outputChunk = deriveXhkdfSequentialBlock(material, c.blockIndex + outputBlock,
      1'u32, c.branches)
    appendXhkdfOutput(result, outputChunk, outLen)
    secureClearAmeBytes(outputChunk)
    outputBlock = outputBlock + 1'u64
  secureClearAmeBytes(material)
  clearXhkdfMemory(M)

proc deriveXhkdf*(ikm, salt, info: openArray[uint8], outLen: int,
    c: XhkdfConfig = initXhkdfConfig()): ByteSeq {.role: truthBuilder,
    tag: "appApi|cryptoBoundary|fomke|kdf".} =
  ## ikm/salt/info: secret input, optional salt, and domain context.
  ## outLen/c: requested bytes and bounded block/round/memory policy.
  var
    base: ByteSeq = @[]
  validateXhkdfRequest(c, outLen)
  if ikm.len == 0:
    raise newException(ValueError, "XHKDF input key material is empty")
  base = buildXhkdfInput(ikm, salt, info, c)
  if c.mode == xhMemoryMixed:
    result = deriveXhkdfMemory(base, outLen, c)
  else:
    result = deriveXhkdfSequential(base, outLen, c)
  secureClearAmeBytes(base)

proc deriveXhkdfInputs*(chainKey: openArray[uint8],
    S: openArray[ByteSeq], info: openArray[uint8], outLen: int,
    c: XhkdfConfig = initXhkdfConfig()): ByteSeq {.role: truthBuilder,
    tag: "appApi|cryptoBoundary|fomke|kdf".} =
  ## chainKey: current forward-only root or chain key.
  ## S: additional secrets consumed in caller-defined canonical order.
  ## info/outLen/c: transcript context, requested bytes, and work policy.
  var
    ikm: ByteSeq = @[]
    i: int = 0
  appendAmeLabel(ikm, "GB3-MULTI-INPUT-v1")
  appendXhkdfField(ikm, chainKey)
  appendAmeU32(ikm, uint32(S.len))
  while i < S.len:
    if S[i].len == 0:
      secureClearAmeBytes(ikm)
      raise newException(ValueError, "XHKDF additional secret is empty")
    appendXhkdfField(ikm, S[i])
    i = i + 1
  result = deriveXhkdf(ikm, @[], info, outLen, c)
  secureClearAmeBytes(ikm)
