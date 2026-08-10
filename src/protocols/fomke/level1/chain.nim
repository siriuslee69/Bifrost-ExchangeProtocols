## -------------------------------------------------------------------------
## FOMKE Chain <- directional forward-only ratchets and atomic KEM upgrades
## -------------------------------------------------------------------------

import protocols/custom_crypto/blake3 as tyr_blake3

import ../../types
import ../../ame/types
import ../../ame/level0/bytes
import ../../ame/level1/exchange_paths
import ../types
import ../level0/gb3hkdf
import ../../tmeaead
import ../../ggaead
import ../../preparation/types
import ../../tmeaead/types
import ../../ggaead/types
import ../../../analysis_pragmas

type
  FomkeChainBlock = object
    nextChainKey: ByteSeq
    mk1: ByteSeq
    mk2: ByteSeq

proc copyFomkeBytes(A: openArray[uint8]): ByteSeq {.role: helper,
    tag: {tagCryptoBoundary, tagFomke}.} =
  ## A: secret bytes copied into independent owned storage.
  result = @A

proc sliceFomkeBytes(A: openArray[uint8], offset, count: int): ByteSeq {.
    role: parser, tag: {tagCryptoBoundary, tagFomke}.} =
  ## A/offset/count: source and bounded slice coordinates.
  var
    i: int = 0
  if offset < 0 or count < 0 or offset > A.len - count:
    raise newException(ValueError, "FOMKE key slice is out of bounds")
  result.setLen(count)
  while i < count:
    result[i] = A[offset + i]
    i = i + 1

proc appendFomkeField(A: var ByteSeq, B: openArray[uint8]) {.
    role: stateController, tag: {tagFomke, tagKdf}.} =
  ## A/B: destination and one length-framed field.
  if uint64(B.len) > uint64(high(uint32)):
    raise newException(ValueError, "FOMKE field exceeds u32")
  appendAmeU32(A, uint32(B.len))
  appendAmeBytes(A, B)

proc outboundFomkeLane*(r: FomkeRole): FomkeLane {.role: parser,
    tag: {tagAppApi, tagFomke}.} =
  ## r: local role mapped to its sender lane.
  if r == frInitiator:
    return flLane1
  result = flLane2

proc inboundFomkeLane*(r: FomkeRole): FomkeLane {.role: parser,
    tag: {tagAppApi, tagFomke}.} =
  ## r: local role mapped to the remote sender lane.
  if r == frInitiator:
    return flLane2
  result = flLane1

proc clearFomkeChain(C: var FomkeChainState) {.role: stateController,
    tag: {tagCryptoBoundary, tagFomke}.} =
  ## C: chain key and counter reset after secure erasure.
  secureClearAmeBytes(C.chainKey)
  C = default(FomkeChainState)

proc clearFomkeSkipped(S: var seq[FomkeSkippedKey]) {.role: stateController,
    tag: {tagCryptoBoundary, tagFomke}.} =
  ## S: cached skipped message keys erased before release.
  var
    i: int = 0
  while i < S.len:
    secureClearAmeBytes(S[i].keyMaterial)
    i = i + 1
  S.setLen(0)

proc clearFomkePending(P: var FomkePendingUpgrade) {.role: stateController,
    tag: {tagCryptoBoundary, tagExchange, tagFomke}.} =
  ## P: candidate chains erased when committed or cancelled.
  clearFomkeChain(P.candidateLane1)
  clearFomkeChain(P.candidateLane2)
  secureClearAmeBytes(P.commit.confirmationTag)
  P = default(FomkePendingUpgrade)

proc clearFomkeState*(S: var FomkeState) {.role: stateController,
    tag: {tagAppApi, tagCryptoBoundary, tagFomke}.} =
  ## S: all current, skipped, and candidate secret material erased.
  clearFomkeChain(S.lane1)
  clearFomkeChain(S.lane2)
  clearFomkeSkipped(S.skipped)
  clearFomkePending(S.pending)
  S = default(FomkeState)

proc cloneFomkeChain(C: FomkeChainState): FomkeChainState {.role: helper,
    tag: {tagCryptoBoundary, tagFomke}.} =
  ## C: chain copied without sharing secret byte storage.
  result.chainKey = copyFomkeBytes(C.chainKey)
  result.nextIndex = C.nextIndex

proc cloneFomkeSkipped(S: openArray[FomkeSkippedKey]): seq[FomkeSkippedKey] {.
    role: helper, tag: {tagCryptoBoundary, tagFomke}.} =
  ## S: skipped-key cache copied without sharing key storage.
  var
    i: int = 0
    item: FomkeSkippedKey
  while i < S.len:
    item = S[i]
    item.keyMaterial = copyFomkeBytes(S[i].keyMaterial)
    result.add(item)
    i = i + 1

proc cloneFomkeState*(S: FomkeState): FomkeState {.role: helper,
    tag: {tagCryptoBoundary, tagFomke}.} =
  ## S: complete state copied for transactional authenticated receive.
  result = S
  result.lane1 = cloneFomkeChain(S.lane1)
  result.lane2 = cloneFomkeChain(S.lane2)
  result.skipped = cloneFomkeSkipped(S.skipped)
  result.pending.candidateLane1 = cloneFomkeChain(S.pending.candidateLane1)
  result.pending.candidateLane2 = cloneFomkeChain(S.pending.candidateLane2)
  result.pending.commit.confirmationTag = copyFomkeBytes(
    S.pending.commit.confirmationTag)

proc clearFomkePreparedEntry(E: var FomkePreparedSendEntry) {.
    role: stateController, tag: {tagCryptoBoundary, tagFomke}.} =
  ## E: one unused future message slot securely erased.
  secureClearAmeBytes(E.keyMaterial)
  secureClearAmeBytes(E.nonce)
  secureClearAmeBytes(E.gimli.key)
  secureClearAmeBytes(E.gimli.nonce)
  secureClearAmeBytes(E.gimli.bytes)
  secureClearAmeBytes(E.xchacha.key)
  secureClearAmeBytes(E.xchacha.nonce)
  secureClearAmeBytes(E.xchacha.bytes)
  secureClearAmeBytes(E.nextChainKey)
  E = default(FomkePreparedSendEntry)

proc clearFomkeSendCache*(C: var FomkeSendCache) {.role: stateController,
    tag: {tagAppApi, tagCryptoBoundary, tagFomke}.} =
  ## C: caller-owned future-message keys, nonces, and stream bytes erased.
  var
    i: int = 0
  while i < C.entries.len:
    clearFomkePreparedEntry(C.entries[i])
    i = i + 1
  secureClearAmeBytes(C.chainKey)
  C.entries.setLen(0)
  C = default(FomkeSendCache)

proc cloneFomkeSendCache*(C: FomkeSendCache): FomkeSendCache {.role: helper,
    tag: {tagAppApi, tagCryptoBoundary, tagFomke}.} =
  ## C: future-message cache copied without sharing mutable secret storage.
  var
    i: int = 0
  result = C
  result.chainKey = copyFomkeBytes(C.chainKey)
  result.entries = newSeq[FomkePreparedSendEntry](C.entries.len)
  while i < C.entries.len:
    result.entries[i] = C.entries[i]
    result.entries[i].keyMaterial = copyFomkeBytes(C.entries[i].keyMaterial)
    result.entries[i].nonce = copyFomkeBytes(C.entries[i].nonce)
    result.entries[i].gimli.key = copyFomkeBytes(C.entries[i].gimli.key)
    result.entries[i].gimli.nonce = copyFomkeBytes(C.entries[i].gimli.nonce)
    result.entries[i].gimli.bytes = copyFomkeBytes(C.entries[i].gimli.bytes)
    result.entries[i].xchacha.key = copyFomkeBytes(C.entries[i].xchacha.key)
    result.entries[i].xchacha.nonce = copyFomkeBytes(
      C.entries[i].xchacha.nonce)
    result.entries[i].xchacha.bytes = copyFomkeBytes(
      C.entries[i].xchacha.bytes)
    result.entries[i].nextChainKey = copyFomkeBytes(
      C.entries[i].nextChainKey)
    i = i + 1

proc fomkePreparedMessages*(C: FomkeSendCache): int {.role: parser,
    tag: {tagAppApi, tagCryptoBoundary, tagFomke}.} =
  ## C: cache whose number of unused sequential send slots is returned.
  if C.nextEntry < 0 or C.nextEntry > C.entries.len:
    return
  result = C.entries.len - C.nextEntry

proc fomkePreparedSecretBytes*(C: FomkeSendCache): int {.role: parser,
    tag: {tagAppApi, tagCryptoBoundary, tagFomke}.} =
  ## C: currently allocated secret bytes, excluding sequence/object overhead.
  var
    i: int = 0
  result = C.chainKey.len
  while i < C.entries.len:
    result = result + C.entries[i].keyMaterial.len + C.entries[i].nonce.len +
      C.entries[i].gimli.key.len + C.entries[i].gimli.nonce.len +
      C.entries[i].gimli.bytes.len + C.entries[i].xchacha.key.len +
      C.entries[i].xchacha.nonce.len + C.entries[i].xchacha.bytes.len +
      C.entries[i].nextChainKey.len
    i = i + 1

proc validateFomkeState*(S: FomkeState) {.role: parser,
    tag: {tagCryptoBoundary, tagFomke, tagValidation}.} =
  ## S: initialized state checked before key progression.
  var
    i: int = 0
    keyBytes: int = fomkeMessageKeyBytesFor(S.messageCipher)
  if S.epoch == 0'u32:
    raise newException(ValueError, "FOMKE epoch must be positive")
  if S.algorithms.length == 0'u8:
    raise newException(ValueError, "FOMKE AME path is empty")
  if S.lane1.chainKey.len != fomkeChainKeyBytes or
      S.lane2.chainKey.len != fomkeChainKeyBytes:
    raise newException(ValueError, "FOMKE directional chain key is invalid")
  if S.maxSkip > fomkeMaxSkipLimit:
    raise newException(ValueError, "FOMKE skipped-key limit is too large")
  while i < S.skipped.len:
    if S.skipped[i].keyMaterial.len != keyBytes:
      raise newException(ValueError, "FOMKE skipped message key is invalid")
    i = i + 1

proc fomkeSendCacheMatches*(S: FomkeState, C: FomkeSendCache): bool {.
    role: parser, tag: {tagAppApi, tagCryptoBoundary, tagFomke,
    tagValidation}.} =
  ## S/C: live outbound chain and one non-mutating prepared snapshot.
  var
    lane: FomkeLane
    chain: FomkeChainState
  if S.pending.active or fomkePreparedMessages(C) == 0:
    return
  lane = outboundFomkeLane(S.role)
  if lane == flLane1:
    chain = S.lane1
  else:
    chain = S.lane2
  result = C.epoch == S.epoch and C.lane == lane and
    C.messageCipher == S.messageCipher and C.nextIndex == chain.nextIndex and
    C.chainKey.len == fomkeChainKeyBytes and
    constantTimeEqualAme(C.chainKey, chain.chainKey)

proc requireFomkeQuiescent(S: FomkeState) {.role: parser,
    tag: {tagExchange, tagFomke, tagValidation}.} =
  ## S: message state that must not progress during a KEM upgrade commit.
  validateFomkeState(S)
  if S.pending.active:
    raise newException(ValueError, "FOMKE KEM upgrade is pending")

proc buildFomkeRootInfo(A: AmeKemAlgorithms, epoch: uint32,
    context: openArray[uint8]): ByteSeq {.role: truthBuilder,
    tag: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## A/epoch/context: exact AME path, root epoch, and caller transcript binding.
  appendAmeLabel(result, "FOMKE-ROOT-v1")
  appendAmeU32(result, epoch)
  appendFomkeField(result, encodeAmeKemAlgorithms(A))
  appendFomkeField(result, context)

proc deriveFomkeLaneRoot(root: openArray[uint8], lane: FomkeLane,
    epoch: uint32, c: Gb3KdfConfig): FomkeChainState {.role: truthBuilder,
    tag: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## root/lane/epoch/c: ephemeral root and direction-bound chain derivation.
  var
    info: ByteSeq = @[]
  appendAmeLabel(info, "FOMKE-DIRECTION-ROOT-v1")
  info.add(uint8(ord(lane)))
  appendAmeU32(info, epoch)
  result.chainKey = deriveGb3Hkdf(root, @[], info, fomkeChainKeyBytes, c)

proc initFomke*(sharedSecret: var ByteSeq, A: AmeKemAlgorithms,
    initialSlot: int, role: FomkeRole, context: openArray[uint8] = [],
    c: Gb3KdfConfig = initGb3KdfConfig(),
    maxSkip: uint32 = fomkeDefaultMaxSkip,
    messageCipher: FomkeMessageCipher = fmcTmeAead): FomkeState {.
    role: truthBuilder,
    tag: {tagAppApi, tagCryptoBoundary, tagExchange, tagFomke}.} =
  ## sharedSecret: one AME KEM result consumed and erased on return.
  ## A/initialSlot/role/context/c/maxSkip/messageCipher: path and chain policy.
  var
    info: ByteSeq = @[]
    root: ByteSeq = @[]
  if sharedSecret.len == 0:
    raise newException(ValueError, "FOMKE initial shared secret is empty")
  if initialSlot < 0 or initialSlot >= int(A.length):
    raise newException(ValueError, "FOMKE initial KEM slot is outside the path")
  if maxSkip > fomkeMaxSkipLimit:
    raise newException(ValueError, "FOMKE skipped-key limit is too large")
  info = buildFomkeRootInfo(A, 1'u32, context)
  info.add(uint8(initialSlot))
  info.add(uint8(ord(A.algorithms[initialSlot])))
  root = deriveGb3Hkdf(sharedSecret, @[], info, fomkeChainKeyBytes, c)
  result.role = role
  result.messageCipher = messageCipher
  result.epoch = 1'u32
  result.algorithms = A
  result.lane1 = deriveFomkeLaneRoot(root, flLane1, result.epoch, c)
  result.lane2 = deriveFomkeLaneRoot(root, flLane2, result.epoch, c)
  result.maxSkip = maxSkip
  result.kdf = c
  secureClearAmeBytes(root)
  secureClearAmeBytes(sharedSecret)
  validateFomkeState(result)

proc initFomkeFromAme*(E: AmeExchangeState, initialSlot: int,
    role: FomkeRole, context: openArray[uint8] = [],
    c: Gb3KdfConfig = initGb3KdfConfig(),
    maxSkip: uint32 = fomkeDefaultMaxSkip,
    messageCipher: FomkeMessageCipher = fmcTmeAead): FomkeState {.
    role: truthBuilder,
    tag: {tagAppApi, tagAme, tagCryptoBoundary, tagExchange, tagFomke}.} =
  ## E/initialSlot: AME state and one active KEM slot copied into FOMKE.
  ## role/context/c/maxSkip/messageCipher: endpoint and derivation policy.
  var
    secret: ByteSeq = @[]
  if initialSlot < 0 or initialSlot >= int(E.algorithms.length) or
      not algorithmSlotSelected(E.activeMask, initialSlot) or
      E.generation[initialSlot] == 0'u32:
    raise newException(ValueError, "FOMKE initial AME slot is not active")
  secret = copyFomkeBytes(E.sharedSecrets[initialSlot])
  result = initFomke(secret, E.algorithms, initialSlot, role, context, c,
    maxSkip, messageCipher)

proc buildFomkeBlockInfo(lane: FomkeLane, epoch: uint32,
    index: uint64, messageCipher: FomkeMessageCipher): ByteSeq {.
    role: truthBuilder,
    tag: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## lane/epoch/index/messageCipher: exact directional chain block identity.
  case messageCipher
  of fmcTmeAead:
    appendAmeLabel(result, "FOMKE-CHAIN-BLOCK-v1")
  of fmcGgAead:
    appendAmeLabel(result, "FOMKE-GGAEAD-CHAIN-BLOCK-v1")
  result.add(uint8(ord(lane)))
  appendAmeU32(result, epoch)
  appendAmeU64(result, index)

proc deriveFomkeChainBlock(C: FomkeChainState, lane: FomkeLane,
    epoch: uint32, c: Gb3KdfConfig,
    messageCipher: FomkeMessageCipher): FomkeChainBlock {.role: truthBuilder,
    tag: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## C/lane/epoch/c/messageCipher: chain and exact derivation context.
  var
    info: ByteSeq = @[]
    output: ByteSeq = @[]
    keyBytes: int = fomkeMessageKeyBytesFor(messageCipher)
    outputBytes: int = fomkeChainKeyBytes + keyBytes * 2
  if C.chainKey.len != fomkeChainKeyBytes or C.nextIndex == high(uint64):
    raise newException(ValueError, "FOMKE chain is invalid or exhausted")
  info = buildFomkeBlockInfo(lane, epoch, C.nextIndex, messageCipher)
  output = deriveGb3Hkdf(C.chainKey, @[], info, outputBytes, c)
  result.nextChainKey = sliceFomkeBytes(output, 0, fomkeChainKeyBytes)
  result.mk1 = sliceFomkeBytes(output, fomkeChainKeyBytes,
    keyBytes)
  result.mk2 = sliceFomkeBytes(output,
    fomkeChainKeyBytes + keyBytes, keyBytes)
  secureClearAmeBytes(output)

proc advanceFomkeChain(C: var FomkeChainState, lane: FomkeLane,
    epoch: uint32, c: Gb3KdfConfig,
    messageCipher: FomkeMessageCipher): tuple[index: uint64,
    keyMaterial: ByteSeq] {.role: stateController,
    tag: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## C/lane/epoch/c/messageCipher: chain advanced with one directional key.
  var
    derivedBlock: FomkeChainBlock
  result.index = C.nextIndex
  derivedBlock = deriveFomkeChainBlock(C, lane, epoch, c, messageCipher)
  if lane == flLane1:
    result.keyMaterial = derivedBlock.mk1
    secureClearAmeBytes(derivedBlock.mk2)
  else:
    result.keyMaterial = derivedBlock.mk2
    secureClearAmeBytes(derivedBlock.mk1)
  secureClearAmeBytes(C.chainKey)
  C.chainKey = derivedBlock.nextChainKey
  C.nextIndex = C.nextIndex + 1'u64

proc buildFomkeMessageAad(epoch: uint32, index: uint64, lane: FomkeLane,
    messageCipher: FomkeMessageCipher, aad: openArray[uint8]): ByteSeq

proc deriveFomkeNonce(K: openArray[uint8], epoch: uint32, index: uint64,
    lane: FomkeLane, c: Gb3KdfConfig,
    messageCipher: FomkeMessageCipher): ByteSeq

proc sealFomkeMessage*(S: var FomkeState, plaintext: openArray[uint8],
    aad: openArray[uint8] = []): FomkeMessage

proc requireFomkeSendCacheBounds(messageCount, payloadBytes: int) {.
    role: parser, tag: {tagCryptoBoundary, tagFomke, tagValidation}.} =
  ## messageCount/payloadBytes: bounded cache dimensions before secret work.
  if messageCount <= 0 or messageCount > fomkeMaxPreparedMessages:
    raise newException(ValueError, "FOMKE prepared message count is invalid")
  if payloadBytes < 0 or payloadBytes > int(fomkeMaxCiphertextBytes):
    raise newException(ValueError, "FOMKE prepared payload size is invalid")
  if payloadBytes > 0 and
      messageCount > fomkeMaxPreparedStreamBytes div payloadBytes:
    raise newException(ValueError, "FOMKE prepared stream cache is too large")

proc prepareFomkeSendCache*(S: FomkeState,
    messageCount: int = fomkeDefaultPreparedMessages,
    payloadBytes: int = fomkeDefaultPreparedPayloadBytes): FomkeSendCache {.
    role: truthBuilder, tag: {tagAppApi, tagCryptoBoundary, tagFomke}.} =
  ## S/messageCount/payloadBytes: outbound snapshot and bounded future slots.
  ## This does not advance S; callers may build it off the latency-sensitive path.
  var
    C: FomkeChainState
    lane: FomkeLane
    key: tuple[index: uint64, keyMaterial: ByteSeq]
    keys: seq[ByteSeq] = @[]
    nonces: seq[ByteSeq] = @[]
    gimliStreams: seq[PreparedStream] = @[]
    xChaChaStreams: seq[PreparedStream] = @[]
    i: int = 0
  requireFomkeQuiescent(S)
  requireFomkeSendCacheBounds(messageCount, payloadBytes)
  lane = outboundFomkeLane(S.role)
  if lane == flLane1:
    C = cloneFomkeChain(S.lane1)
  else:
    C = cloneFomkeChain(S.lane2)
  result.epoch = S.epoch
  result.lane = lane
  result.messageCipher = S.messageCipher
  result.nextIndex = C.nextIndex
  result.chainKey = copyFomkeBytes(C.chainKey)
  result.payloadBytes = payloadBytes
  result.entries.setLen(messageCount)
  keys.setLen(messageCount)
  nonces.setLen(messageCount)
  try:
    while i < messageCount:
      key = advanceFomkeChain(C, lane, S.epoch, S.kdf, S.messageCipher)
      result.entries[i].epoch = S.epoch
      result.entries[i].index = key.index
      result.entries[i].lane = lane
      result.entries[i].messageCipher = S.messageCipher
      result.entries[i].keyMaterial = move(key.keyMaterial)
      result.entries[i].nonce = deriveFomkeNonce(
        result.entries[i].keyMaterial, S.epoch, result.entries[i].index,
        lane, S.kdf, S.messageCipher)
      result.entries[i].nextChainKey = copyFomkeBytes(C.chainKey)
      keys[i] = result.entries[i].keyMaterial
      nonces[i] = result.entries[i].nonce
      i = i + 1
    case S.messageCipher
    of fmcTmeAead:
      gimliStreams = prepareTmeGimliStreams(keys, nonces, payloadBytes)
      xChaChaStreams = prepareTmeXChaChaStreams(keys, nonces, payloadBytes)
    of fmcGgAead:
      gimliStreams = prepareGgGimliStreams(keys, nonces, payloadBytes)
    i = 0
    while i < result.entries.len:
      result.entries[i].gimli = move(gimliStreams[i])
      if S.messageCipher == fmcTmeAead:
        result.entries[i].xchacha = move(xChaChaStreams[i])
      i = i + 1
    clearFomkeChain(C)
  except:
    clearFomkeChain(C)
    clearFomkeSendCache(result)
    raise

proc preparedEntryMatches(E: FomkePreparedSendEntry, S: FomkeState,
    C: FomkeSendCache, lane: FomkeLane): bool {.role: parser,
    tag: {tagCryptoBoundary, tagFomke, tagValidation}.} =
  ## E/S/C/lane: next entry bound to the current epoch, direction, and cipher.
  result = E.epoch == S.epoch and E.index == C.nextIndex and E.lane == lane and
    E.messageCipher == S.messageCipher and
    E.keyMaterial.len == fomkeMessageKeyBytesFor(S.messageCipher) and
    E.nonce.len == fomkeAeadNonceBytes and
    E.gimli.key.len == gb3BlockBytes and
    E.gimli.nonce.len == fomkeAeadNonceBytes and
    E.gimli.bytes.len == C.payloadBytes and
    E.nextChainKey.len == fomkeChainKeyBytes
  if result and S.messageCipher == fmcTmeAead:
    result = E.xchacha.key.len == gb3BlockBytes and
      E.xchacha.nonce.len == fomkeAeadNonceBytes and
      E.xchacha.bytes.len == C.payloadBytes

proc commitFomkePreparedChain(S: var FomkeState, C: var FomkeSendCache,
    E: FomkePreparedSendEntry, lane: FomkeLane) {.role: stateController,
    tag: {tagCryptoBoundary, tagFomke}.} =
  ## S/C/E/lane: authenticated send slot committed to live and cache cursors.
  var
    nextChainKey: ByteSeq = copyFomkeBytes(E.nextChainKey)
    nextCacheKey: ByteSeq = copyFomkeBytes(E.nextChainKey)
  if lane == flLane1:
    clearFomkeChain(S.lane1)
    S.lane1.chainKey = move(nextChainKey)
    S.lane1.nextIndex = E.index + 1'u64
  else:
    clearFomkeChain(S.lane2)
    S.lane2.chainKey = move(nextChainKey)
    S.lane2.nextIndex = E.index + 1'u64
  secureClearAmeBytes(C.chainKey)
  C.chainKey = move(nextCacheKey)
  C.nextIndex = E.index + 1'u64
  clearFomkePreparedEntry(C.entries[C.nextEntry])
  C.nextEntry = C.nextEntry + 1

proc sealFomkeMessagePrepared*(S: var FomkeState, C: var FomkeSendCache,
    plaintext: openArray[uint8], aad: openArray[uint8] = []): FomkeMessage {.
    role: orchestrator, tag: {tagAppApi, tagCryptoBoundary, tagFomke}.} =
  ## S/C/plaintext/aad: live state, future cache, payload, and external binding.
  var
    lane: FomkeLane
    entry: FomkePreparedSendEntry
    messageAad: ByteSeq = @[]
    tmeSealed: TmeAeadCiphertext
    ggSealed: GgAeadCiphertext
  requireFomkeQuiescent(S)
  lane = outboundFomkeLane(S.role)
  if plaintext.len > C.payloadBytes or not fomkeSendCacheMatches(S, C):
    clearFomkeSendCache(C)
    return sealFomkeMessage(S, plaintext, aad)
  entry = C.entries[C.nextEntry]
  if not preparedEntryMatches(entry, S, C, lane):
    clearFomkeSendCache(C)
    return sealFomkeMessage(S, plaintext, aad)
  result.epoch = entry.epoch
  result.index = entry.index
  result.senderLane = lane
  result.nonce = copyFomkeBytes(entry.nonce)
  messageAad = buildFomkeMessageAad(result.epoch, result.index, lane,
    S.messageCipher, aad)
  case S.messageCipher
  of fmcTmeAead:
    tmeSealed = sealTmeAeadPrepared(entry.keyMaterial, entry.nonce, plaintext,
      entry.gimli, entry.xchacha, messageAad)
    result.authTag = tmeSealed.authTag
    result.ciphertext = tmeSealed.ciphertext
  of fmcGgAead:
    ggSealed = sealGgAeadPrepared(entry.keyMaterial, entry.nonce, plaintext,
      entry.gimli, messageAad)
    result.authTag = ggSealed.authTag
    result.ciphertext = ggSealed.ciphertext
  secureClearAmeBytes(messageAad)
  commitFomkePreparedChain(S, C, entry, lane)
  if fomkePreparedMessages(C) == 0:
    clearFomkeSendCache(C)

proc buildFomkeMessageAad(epoch: uint32, index: uint64, lane: FomkeLane,
    messageCipher: FomkeMessageCipher, aad: openArray[uint8]): ByteSeq {.
    role: truthBuilder, tag: {tagCryptoBoundary, tagFomke}.} =
  ## epoch/index/lane/messageCipher/aad: message identity and caller binding.
  case messageCipher
  of fmcTmeAead:
    appendAmeLabel(result, "FOMKE-MESSAGE-AAD-v1")
  of fmcGgAead:
    appendAmeLabel(result, "FOMKE-GGAEAD-MESSAGE-AAD-v1")
  appendAmeU32(result, epoch)
  appendAmeU64(result, index)
  result.add(uint8(ord(lane)))
  appendFomkeField(result, aad)

proc deriveFomkeNonce(K: openArray[uint8], epoch: uint32, index: uint64,
    lane: FomkeLane, c: Gb3KdfConfig,
    messageCipher: FomkeMessageCipher): ByteSeq {.role: truthBuilder,
    tag: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## K/epoch/index/lane/c/messageCipher: deterministic one-time nonce identity.
  var
    info: ByteSeq = @[]
  case messageCipher
  of fmcTmeAead:
    appendAmeLabel(info, "FOMKE-TMEAEAD-NONCE-v1")
  of fmcGgAead:
    appendAmeLabel(info, "FOMKE-GGAEAD-NONCE-v1")
  appendAmeU32(info, epoch)
  appendAmeU64(info, index)
  info.add(uint8(ord(lane)))
  result = deriveGb3Hkdf(K, @[], info, fomkeAeadNonceBytes, c)

proc sealFomkeMessage*(S: var FomkeState, plaintext: openArray[uint8],
    aad: openArray[uint8]): FomkeMessage {.role: orchestrator,
    tag: {tagAppApi, tagCryptoBoundary, tagFomke}.} =
  ## S/plaintext/aad: sender state, one message, and external binding.
  var
    lane: FomkeLane
    key: tuple[index: uint64, keyMaterial: ByteSeq]
    messageAad: ByteSeq = @[]
    tmeSealed: TmeAeadCiphertext
    ggSealed: GgAeadCiphertext
  requireFomkeQuiescent(S)
  lane = outboundFomkeLane(S.role)
  if lane == flLane1:
    key = advanceFomkeChain(S.lane1, lane, S.epoch, S.kdf,
      S.messageCipher)
  else:
    key = advanceFomkeChain(S.lane2, lane, S.epoch, S.kdf,
      S.messageCipher)
  result.epoch = S.epoch
  result.index = key.index
  result.senderLane = lane
  result.nonce = deriveFomkeNonce(key.keyMaterial, result.epoch, result.index,
    lane, S.kdf, S.messageCipher)
  messageAad = buildFomkeMessageAad(result.epoch, result.index, lane,
    S.messageCipher, aad)
  case S.messageCipher
  of fmcTmeAead:
    tmeSealed = sealTmeAead(key.keyMaterial, result.nonce, plaintext,
      messageAad)
    result.authTag = tmeSealed.authTag
    result.ciphertext = tmeSealed.ciphertext
  of fmcGgAead:
    ggSealed = sealGgAead(key.keyMaterial, result.nonce, plaintext, messageAad)
    result.authTag = ggSealed.authTag
    result.ciphertext = ggSealed.ciphertext
  secureClearAmeBytes(key.keyMaterial)
  secureClearAmeBytes(messageAad)

proc takeSkippedFomkeKey(S: var seq[FomkeSkippedKey], epoch: uint32,
    index: uint64, lane: FomkeLane): ByteSeq {.role: stateController,
    tag: {tagCryptoBoundary, tagFomke}.} =
  ## S/epoch/index/lane: cache and exact previously skipped key identity.
  var
    i: int = 0
  while i < S.len:
    if S[i].epoch == epoch and S[i].index == index and S[i].lane == lane:
      result = copyFomkeBytes(S[i].keyMaterial)
      secureClearAmeBytes(S[i].keyMaterial)
      S.delete(i)
      return
    i = i + 1

proc acquireFomkeInboundKey(S: var FomkeState, index: uint64,
    lane: FomkeLane): ByteSeq {.role: stateController,
    tag: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## S/index/lane: receive chain advanced transactionally up to one message.
  var
    C: FomkeChainState
    key: tuple[index: uint64, keyMaterial: ByteSeq]
    skipped: FomkeSkippedKey
  if lane == flLane1:
    C = cloneFomkeChain(S.lane1)
  else:
    C = cloneFomkeChain(S.lane2)
  if index < C.nextIndex:
    clearFomkeChain(C)
    return takeSkippedFomkeKey(S.skipped, S.epoch, index, lane)
  if index - C.nextIndex > uint64(S.maxSkip):
    clearFomkeChain(C)
    raise newException(ValueError, "FOMKE message gap exceeds skipped-key limit")
  while C.nextIndex <= index:
    key = advanceFomkeChain(C, lane, S.epoch, S.kdf, S.messageCipher)
    if key.index == index:
      result = key.keyMaterial
    else:
      if uint32(S.skipped.len) >= S.maxSkip:
        secureClearAmeBytes(key.keyMaterial)
        clearFomkeChain(C)
        raise newException(ValueError, "FOMKE skipped-key cache is full")
      skipped.epoch = S.epoch
      skipped.index = key.index
      skipped.lane = lane
      skipped.keyMaterial = key.keyMaterial
      S.skipped.add(skipped)
  if lane == flLane1:
    clearFomkeChain(S.lane1)
    S.lane1 = C
  else:
    clearFomkeChain(S.lane2)
    S.lane2 = C

proc openFomkeMessage*(S: var FomkeState, message: FomkeMessage,
    aad: openArray[uint8] = []): FomkeOpenResult {.role: orchestrator,
    tag: {tagAppApi, tagCryptoBoundary, tagFomke}.} =
  ## S/message/aad: transactional receiver state, envelope, and binding bytes.
  var
    pending: FomkeState
    expectedLane: FomkeLane
    key: ByteSeq = @[]
    messageAad: ByteSeq = @[]
    tmeSealed: TmeAeadCiphertext
    ggSealed: GgAeadCiphertext
    opened: tuple[ok: bool, payload: ByteSeq]
  try:
    requireFomkeQuiescent(S)
    expectedLane = inboundFomkeLane(S.role)
    if message.epoch != S.epoch or message.senderLane != expectedLane:
      result.err = "FOMKE epoch or sender lane mismatch"
      return
    pending = cloneFomkeState(S)
    key = acquireFomkeInboundKey(pending, message.index, expectedLane)
    if key.len == 0:
      clearFomkeState(pending)
      result.err = "FOMKE message key is unavailable or replayed"
      return
    messageAad = buildFomkeMessageAad(message.epoch, message.index,
      message.senderLane, S.messageCipher, aad)
    case S.messageCipher
    of fmcTmeAead:
      tmeSealed.ciphertext = message.ciphertext
      tmeSealed.authTag = message.authTag
      opened = openTmeAead(key, message.nonce, tmeSealed, messageAad)
    of fmcGgAead:
      ggSealed.ciphertext = message.ciphertext
      ggSealed.authTag = message.authTag
      opened = openGgAead(key, message.nonce, ggSealed, messageAad)
    secureClearAmeBytes(key)
    secureClearAmeBytes(messageAad)
    if not opened.ok:
      clearFomkeState(pending)
      result.err = "FOMKE authentication failed"
      return
    clearFomkeState(S)
    S = pending
    result.ok = true
    result.payload = opened.payload
  except ValueError as exc:
    secureClearAmeBytes(key)
    secureClearAmeBytes(messageAad)
    clearFomkeState(pending)
    result.err = exc.msg

proc canonicalFomkeLaneMaterial(S: FomkeState): ByteSeq {.role: truthBuilder,
    tag: {tagCryptoBoundary, tagExchange, tagFomke, tagKdf}.} =
  ## S: current lane keys and counters framed in role-independent lane order.
  appendAmeLabel(result, "FOMKE-CURRENT-LANES-v1")
  appendAmeU64(result, S.lane1.nextIndex)
  appendFomkeField(result, S.lane1.chainKey)
  appendAmeU64(result, S.lane2.nextIndex)
  appendFomkeField(result, S.lane2.chainKey)

proc buildFomkeUpgradeMetadata(c: FomkeUpgradeCommit,
    A: AmeKemAlgorithms, messageCipher: FomkeMessageCipher): ByteSeq {.
    role: truthBuilder,
    tag: {tagExchange, tagFomke, tagKdf}.} =
  ## c/A/messageCipher: public commit fields, AME path, and fixed inner AEAD.
  var
    i: int = 0
  case messageCipher
  of fmcTmeAead:
    appendAmeLabel(result, "FOMKE-UPGRADE-COMMIT-v2")
  of fmcGgAead:
    appendAmeLabel(result, "FOMKE-GGAEAD-UPGRADE-COMMIT-v2")
  appendAmeU32(result, c.requestId)
  appendAmeU32(result, c.baseEpoch)
  appendAmeU32(result, c.targetEpoch)
  appendAmeU32(result, c.targetTier.tierId)
  result.add(c.targetTier.masks.kem)
  result.add(c.targetTier.masks.cipher)
  result.add(c.targetTier.masks.mac)
  result.add(c.targetTier.masks.hash)
  result.add(c.targetTier.masks.signature)
  result.add(c.targetTier.masks.kdf)
  result.add(c.exchangeMask)
  appendAmeU64(result, c.lane1Index)
  appendAmeU64(result, c.lane2Index)
  appendFomkeField(result, encodeAmeKemAlgorithms(A))
  while i < ameMaxAlgorithmSlots:
    appendAmeU32(result, c.generations[i])
    i = i + 1

proc collectFomkeUpgradeSecrets(E: AmeExchangeState, r: AmeExchangeRequest,
    generations: var array[ameMaxAlgorithmSlots, uint32]): seq[ByteSeq] {.
    role: truthBuilder, tag: {tagAme, tagCryptoBoundary, tagExchange,
    tagFomke}.} =
  ## E/r/generations: candidate AME state, exact mask, and bound slot counters.
  var
    i: int = 0
    row: ByteSeq = @[]
  while i < int(E.algorithms.length):
    if algorithmSlotSelected(r.exchangeMask, i):
      if not algorithmSlotSelected(E.activeMask, i) or
          E.generation[i] == 0'u32 or E.sharedSecrets[i].len == 0:
        raise newException(ValueError,
          "FOMKE upgrade selected an unavailable AME secret")
      generations[i] = E.generation[i]
      row = @[]
      row.add(uint8(i))
      row.add(uint8(ord(E.algorithms.algorithms[i])))
      appendAmeU32(row, E.generation[i])
      appendFomkeField(row, E.sharedSecrets[i])
      result.add(row)
    i = i + 1

proc clearFomkeSecretRows(S: var seq[ByteSeq]) {.role: stateController,
    tag: {tagCryptoBoundary, tagExchange, tagFomke}.} =
  ## S: temporary framed secret rows erased after derivation.
  var
    i: int = 0
  while i < S.len:
    secureClearAmeBytes(S[i])
    i = i + 1
  S.setLen(0)

proc prepareFomkeUpgrade*(S: var FomkeState, requestId,
    targetEpoch: uint32, r: AmeExchangeRequest,
    candidate: AmeExchangeState): FomkeUpgradeCommit {.role: orchestrator,
    tag: {tagAppApi, tagAme, tagCryptoBoundary, tagExchange, tagFomke}.} =
  ## S/requestId/targetEpoch: quiescent chain and authenticated AME transaction.
  ## r/candidate: exact upgrade mask and resulting AME state.
  var
    laneMaterial: ByteSeq = @[]
    metadata: ByteSeq = @[]
    secretRows: seq[ByteSeq] = @[]
    root: ByteSeq = @[]
    confirmInfo: ByteSeq = @[]
  requireFomkeQuiescent(S)
  if S.skipped.len != 0:
    raise newException(ValueError,
      "FOMKE skipped messages must be resolved before a KEM upgrade")
  if requestId == 0'u32 or S.epoch == high(uint32) or
      targetEpoch != S.epoch + 1'u32:
    raise newException(ValueError, "FOMKE upgrade epoch identity is invalid")
  discard initAmeExchangeRequest(S.algorithms, r.targetTier, r.exchangeMask)
  result.requestId = requestId
  result.baseEpoch = S.epoch
  result.targetEpoch = targetEpoch
  result.targetTier = r.targetTier
  result.exchangeMask = r.exchangeMask
  result.lane1Index = S.lane1.nextIndex
  result.lane2Index = S.lane2.nextIndex
  secretRows = collectFomkeUpgradeSecrets(candidate, r, result.generations)
  metadata = buildFomkeUpgradeMetadata(result, S.algorithms,
    S.messageCipher)
  laneMaterial = canonicalFomkeLaneMaterial(S)
  root = deriveGb3HkdfInputs(laneMaterial, secretRows, metadata,
    fomkeChainKeyBytes, S.kdf)
  S.pending.active = true
  S.pending.commit = result
  S.pending.candidateLane1 = deriveFomkeLaneRoot(root, flLane1,
    targetEpoch, S.kdf)
  S.pending.candidateLane2 = deriveFomkeLaneRoot(root, flLane2,
    targetEpoch, S.kdf)
  case S.messageCipher
  of fmcTmeAead:
    appendAmeLabel(confirmInfo, "FOMKE-UPGRADE-CONFIRM-v2")
  of fmcGgAead:
    appendAmeLabel(confirmInfo, "FOMKE-GGAEAD-UPGRADE-CONFIRM-v2")
  appendFomkeField(confirmInfo, metadata)
  result.confirmationTag = tyr_blake3.blake3KeyedHash(
    root.toOpenArray(0, gb3BlockBytes - 1), confirmInfo, gb3BlockBytes)
  S.pending.commit.confirmationTag = copyFomkeBytes(result.confirmationTag)
  secureClearAmeBytes(laneMaterial)
  secureClearAmeBytes(metadata)
  clearFomkeSecretRows(secretRows)
  secureClearAmeBytes(root)
  secureClearAmeBytes(confirmInfo)

proc fomkeUpgradeCommitsEqual*(a, b: FomkeUpgradeCommit): bool {.
    role: parser, tag: {tagAppApi, tagExchange, tagFomke}.} =
  ## a/b: local candidate identity and authenticated peer confirmation.
  var
    i: int = 0
  if a.requestId != b.requestId or a.baseEpoch != b.baseEpoch or
      a.targetEpoch != b.targetEpoch or a.targetTier != b.targetTier or
      a.exchangeMask != b.exchangeMask or
      a.lane1Index != b.lane1Index or a.lane2Index != b.lane2Index:
    return false
  while i < ameMaxAlgorithmSlots:
    if a.generations[i] != b.generations[i]:
      return false
    i = i + 1
  result = constantTimeEqualAme(a.confirmationTag, b.confirmationTag)

proc validateFomkeUpgrade*(S: FomkeState, c: FomkeUpgradeCommit) {.
    role: parser, tag: {tagAppApi, tagExchange, tagFomke, tagValidation}.} =
  ## S/c: pending local candidate and peer-confirmed commit.
  if not S.pending.active or not fomkeUpgradeCommitsEqual(S.pending.commit, c):
    raise newException(ValueError, "FOMKE upgrade confirmation mismatch")

proc confirmFomkeUpgrade*(S: var FomkeState, c: FomkeUpgradeCommit) {.
    role: stateController, tag: {tagAppApi, tagCryptoBoundary, tagExchange,
    tagFomke}.} =
  ## S/c: state atomically replaced after exact authenticated confirmation.
  var
    lane1: FomkeChainState
    lane2: FomkeChainState
    targetEpoch: uint32 = 0'u32
  validateFomkeUpgrade(S, c)
  lane1 = cloneFomkeChain(S.pending.candidateLane1)
  lane2 = cloneFomkeChain(S.pending.candidateLane2)
  targetEpoch = S.pending.commit.targetEpoch
  clearFomkeChain(S.lane1)
  clearFomkeChain(S.lane2)
  clearFomkeSkipped(S.skipped)
  clearFomkePending(S.pending)
  S.lane1 = lane1
  S.lane2 = lane2
  S.epoch = targetEpoch
  validateFomkeState(S)

proc cancelFomkeUpgrade*(S: var FomkeState) {.role: stateController,
    tag: {tagAppApi, tagCryptoBoundary, tagExchange, tagFomke}.} =
  ## S: unconfirmed candidate erased while current chains remain unchanged.
  clearFomkePending(S.pending)
