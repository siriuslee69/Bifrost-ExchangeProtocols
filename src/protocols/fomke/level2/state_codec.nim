## -------------------------------------------------------------------------
## FOMKE State Codec <- strict bounded ratchet checkpoint serialization
## -------------------------------------------------------------------------

import ../../types
import ../../ame/types
import ../../ame/level0/bytes
import ../../ame/level1/exchange_paths
import ../../ame/level1/suites
import ../types
import ../level0/gb3hkdf
import ../level1/chain
import ./wire
import ../../../analysis_pragmas

const
  fomkeStateMagic = [uint8('F'), uint8('S'), uint8('R')]
  fomkeStateVersion = 1'u8

proc requireStateBytes(A: openArray[uint8], cursor, count: int) {.role: parser,
    tag: {tagFomke, tagParsing, tagValidation}.} =
  ## A/cursor/count: bounded source window required by the state decoder.
  if cursor < 0 or count < 0 or cursor > A.len - count:
    raise newException(ValueError, "FOMKE state is truncated")

proc readStateU8(A: openArray[uint8], cursor: var int): uint8 {.role: parser,
    tag: {tagFomke, tagParsing}.} =
  ## A/cursor: consume one byte.
  requireStateBytes(A, cursor, 1)
  result = A[cursor]
  cursor = cursor + 1

proc readStateU32(A: openArray[uint8], cursor: var int): uint32 {.role: parser,
    tag: {tagFomke, tagParsing}.} =
  ## A/cursor: consume one little-endian u32.
  requireStateBytes(A, cursor, 4)
  result = uint32(A[cursor]) or (uint32(A[cursor + 1]) shl 8) or
    (uint32(A[cursor + 2]) shl 16) or (uint32(A[cursor + 3]) shl 24)
  cursor = cursor + 4

proc readStateU64(A: openArray[uint8], cursor: var int): uint64 {.role: parser,
    tag: {tagFomke, tagParsing}.} =
  ## A/cursor: consume one little-endian u64.
  var
    i: int = 0
  requireStateBytes(A, cursor, 8)
  while i < 8:
    result = result or (uint64(A[cursor + i]) shl (8 * i))
    i = i + 1
  cursor = cursor + 8

proc appendStateField(A: var ByteSeq, B: openArray[uint8]) {.
    role: stateController, tag: {tagFomke, tagWrite}.} =
  ## A/B: append one bounded length-prefixed byte field.
  if uint64(B.len) > uint64(fomkeMaxStateBytes):
    raise newException(ValueError, "FOMKE state field exceeds its limit")
  appendAmeU32(A, uint32(B.len))
  appendAmeBytes(A, B)

proc readStateField(A: openArray[uint8], cursor: var int,
    maximum: uint32 = fomkeMaxStateBytes): ByteSeq {.role: parser,
    tag: {tagFomke, tagParsing}.} =
  ## A/cursor/maximum: consume one bounded length-prefixed byte field.
  var
    count: int = 0
  count = checkedAmeWireLen(readStateU32(A, cursor), maximum,
    "FOMKE state field")
  requireStateBytes(A, cursor, count)
  if count > 0:
    result = @A[cursor ..< cursor + count]
  cursor = cursor + count

proc decodeStateRole(v: uint8): FomkeRole {.role: parser,
    tag: {tagFomke, tagParsing}.} =
  ## v: stable local FOMKE endpoint role.
  if v == uint8(ord(frInitiator)):
    return frInitiator
  if v == uint8(ord(frResponder)):
    return frResponder
  raise newException(ValueError, "FOMKE state role is invalid")

proc decodeStateLane(v: uint8): FomkeLane {.role: parser,
    tag: {tagFomke, tagParsing}.} =
  ## v: stable FOMKE lane identifier.
  if v == uint8(ord(flLane1)):
    return flLane1
  if v == uint8(ord(flLane2)):
    return flLane2
  raise newException(ValueError, "FOMKE state lane is invalid")

proc decodeStateKdfMode(v: uint8): Gb3KdfMode {.role: parser,
    tag: {tagFomke, tagParsing}.} =
  ## v: stable GB3HKDF mode identifier.
  if v == uint8(ord(gb3Sequential)):
    return gb3Sequential
  if v == uint8(ord(gb3MemoryMixed)):
    return gb3MemoryMixed
  raise newException(ValueError, "FOMKE state KDF mode is invalid")

proc decodeStateTagLen(v: uint8): AmeAuthTagLen {.role: parser,
    tag: {tagFomke, tagParsing}.} =
  ## v: stable agreed authentication-tag length.
  result = ameAuthTagLenFromId(v)

proc appendStateChain(A: var ByteSeq, C: FomkeChainState) {.
    role: stateController, tag: {tagCryptoBoundary, tagFomke, tagWrite}.} =
  ## A/C: append one directional chain key and next index.
  appendStateField(A, C.chainKey)
  appendAmeU64(A, C.nextIndex)

proc readStateChain(A: openArray[uint8], cursor: var int): FomkeChainState {.
    role: parser, tag: {tagCryptoBoundary, tagFomke, tagParsing}.} =
  ## A/cursor: consume one directional chain.
  result.chainKey = readStateField(A, cursor, fomkeChainKeyBytes.uint32)
  result.nextIndex = readStateU64(A, cursor)
  if result.chainKey.len != fomkeChainKeyBytes:
    raise newException(ValueError, "FOMKE state chain key length is invalid")

proc appendStateSkipped(A: var ByteSeq, K: FomkeSkippedKey) {.
    role: stateController, tag: {tagCryptoBoundary, tagFomke, tagWrite}.} =
  ## A/K: append one skipped message key record.
  appendAmeU32(A, K.epoch)
  appendAmeU64(A, K.index)
  A.add(uint8(ord(K.lane)))
  appendStateField(A, K.keyMaterial)

proc readStateSkipped(A: openArray[uint8], cursor: var int,
    epoch: uint32): FomkeSkippedKey {.
    role: parser,
    tag: {tagCryptoBoundary, tagFomke, tagParsing}.} =
  ## A/cursor/epoch: consume one skipped key belonging to this state.
  result.epoch = readStateU32(A, cursor)
  result.index = readStateU64(A, cursor)
  result.lane = decodeStateLane(readStateU8(A, cursor))
  result.keyMaterial = readStateField(A, cursor,
    fomkeMessageKeyBytes.uint32)
  if result.epoch != epoch or
      result.keyMaterial.len != fomkeMessageKeyBytes:
    raise newException(ValueError, "FOMKE skipped state is invalid")

proc validateDecodedPending(S: FomkeState) {.role: parser,
    tag: {tagExchange, tagFomke, tagValidation}.} =
  ## S: decoded pending transition checked against current state.
  if not S.pending.active:
    return
  if S.pending.commit.baseEpoch != S.epoch or
      S.pending.commit.targetEpoch != S.epoch + 1'u32:
    raise newException(ValueError, "FOMKE pending epoch is invalid")
  if S.pending.candidateLane1.chainKey.len != fomkeChainKeyBytes or
      S.pending.candidateLane2.chainKey.len != fomkeChainKeyBytes:
    raise newException(ValueError, "FOMKE pending chain is invalid")

proc encodeFomkeState*(S: FomkeState): ByteSeq {.role: stateController,
    tag: {tagAppApi, tagCodecBoundary, tagCryptoBoundary, tagFomke,
    tagWrite}.} =
  ## S: complete secret ratchet state for encrypted checkpoint storage only.
  var
    algorithms: ByteSeq = @[]
    commit: ByteSeq = @[]
    i: int = 0
  validateFomkeState(S)
  validateDecodedPending(S)
  appendAmeBytes(result, fomkeStateMagic)
  result.add(fomkeStateVersion)
  result.add(uint8(ord(S.role)))
  result.add(uint8(ord(S.tagLen)))
  appendAmeU32(result, S.epoch)
  algorithms = encodeAmeKemAlgorithms(S.algorithms)
  appendStateField(result, algorithms)
  appendStateField(result, encodeAmeSuiteLayout(S.layout))
  appendStateField(result, encodeAmeMaskTier(S.tier))
  appendStateChain(result, S.lane1)
  appendStateChain(result, S.lane2)
  appendAmeU32(result, S.maxSkip)
  result.add(uint8(ord(S.kdf.mode)))
  appendAmeU32(result, S.kdf.rounds)
  appendAmeU64(result, S.kdf.blockIndex)
  appendAmeU32(result, S.kdf.memoryBlocks)
  appendAmeU32(result, uint32(S.skipped.len))
  while i < S.skipped.len:
    appendStateSkipped(result, S.skipped[i])
    i = i + 1
  result.add(if S.pending.active: 1'u8 else: 0'u8)
  if S.pending.active:
    commit = encodeFomkeUpgradeCommit(S.pending.commit)
    appendStateField(result, commit)
    appendStateChain(result, S.pending.candidateLane1)
    appendStateChain(result, S.pending.candidateLane2)
  if uint64(result.len) > uint64(fomkeMaxStateBytes):
    raise newException(ValueError, "FOMKE encoded state exceeds its limit")

proc decodeFomkeState*(A: openArray[uint8]): FomkeState {.role: parser,
    tag: {tagAppApi, tagCodecBoundary, tagCryptoBoundary, tagFomke,
    tagParsing}.} =
  ## A: strict bounded plaintext state from an authenticated checkpoint.
  var
    algorithms: ByteSeq = @[]
    layout: ByteSeq = @[]
    tier: ByteSeq = @[]
    commit: ByteSeq = @[]
    count: uint32 = 0'u32
    pendingFlag: uint8 = 0'u8
    cursor: int = 0
    i: uint32 = 0'u32
  if A.len < 6 or uint64(A.len) > uint64(fomkeMaxStateBytes):
    raise newException(ValueError, "FOMKE state length is invalid")
  requireStateBytes(A, 0, 4)
  if A[0 .. 2] != fomkeStateMagic:
    raise newException(ValueError, "FOMKE state identity mismatch")
  if A[3] != fomkeStateVersion:
    raise newException(ValueError, "FOMKE state version mismatch")
  cursor = 4
  result.role = decodeStateRole(readStateU8(A, cursor))
  result.tagLen = decodeStateTagLen(readStateU8(A, cursor))
  result.epoch = readStateU32(A, cursor)
  algorithms = readStateField(A, cursor, uint32(ameMaxAlgorithmSlots + 1))
  result.algorithms = decodeAmeKemAlgorithms(algorithms)
  layout = readStateField(A, cursor, 256'u32)
  result.layout = decodeAmeSuiteLayout(layout)
  tier = readStateField(A, cursor, 32'u32)
  result.tier = decodeAmeMaskTier(result.layout, tier)
  result.lane1 = readStateChain(A, cursor)
  result.lane2 = readStateChain(A, cursor)
  result.maxSkip = readStateU32(A, cursor)
  result.kdf.mode = decodeStateKdfMode(readStateU8(A, cursor))
  result.kdf.rounds = readStateU32(A, cursor)
  result.kdf.blockIndex = readStateU64(A, cursor)
  result.kdf.memoryBlocks = readStateU32(A, cursor)
  discard initGb3KdfConfig(result.kdf.rounds, result.kdf.blockIndex,
    result.kdf.mode, result.kdf.memoryBlocks)
  count = readStateU32(A, cursor)
  if count > result.maxSkip or count > fomkeMaxSkipLimit:
    raise newException(ValueError, "FOMKE skipped state exceeds its limit")
  while i < count:
    result.skipped.add(readStateSkipped(A, cursor, result.epoch))
    i = i + 1'u32
  pendingFlag = readStateU8(A, cursor)
  if pendingFlag > 1'u8:
    raise newException(ValueError, "FOMKE pending state flag is invalid")
  result.pending.active = pendingFlag == 1'u8
  if result.pending.active:
    commit = readStateField(A, cursor, 256'u32)
    result.pending.commit = decodeFomkeUpgradeCommit(commit)
    result.pending.candidateLane1 = readStateChain(A, cursor)
    result.pending.candidateLane2 = readStateChain(A, cursor)
  if cursor != A.len:
    raise newException(ValueError, "FOMKE state has trailing bytes")
  validateFomkeState(result)
  validateDecodedPending(result)
