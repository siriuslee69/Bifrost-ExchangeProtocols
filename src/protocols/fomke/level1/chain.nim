## -------------------------------------------------------------------------
## FOMKE Chain <- directional forward-only ratchets and atomic KEM upgrades
## -------------------------------------------------------------------------
##
## A chain is a key that is replaced every time it is used:
##
##   chainKey(0) --step--> chainKey(1) --step--> chainKey(2) --> ...
##        |                     |                     |
##        v                     v                     v
##    messageKey 0          messageKey 1          messageKey 2
##
## Each step throws the previous chain key away. The step function only runs
## forwards, so holding chainKey(2) tells you nothing about messageKey 0 or 1.
## That is the whole of "forward secrecy": taking the machine today does not
## open yesterday's messages.
##
## Two chains run side by side, one per direction, so a message a peer sent
## can never be replayed back at it as if it had come the other way.
##
##   initiator sends on lane 1        responder sends on lane 2
##   ------------------------>        <------------------------
##
## The message key is not used to encrypt directly. It is expanded into one
## block that holds, in this order:
##
##   [ nonce ][ key for cipher slot 0 ][ key for cipher slot 1 ][ mac keys... ]
##
## and level1/tier_aead turns that block plus the payload into ciphertext and
## a tag. So the algorithms in play come from the session's slot layout, not
## from anything FOMKE picks for itself.

import tyr/hashes/blake3 as tyr_blake3

import ../../types
import ../../ame/types
import ../../ame/level0/bytes
import ../../ame/level1/exchange_paths
import ../../ame/level1/suites
import ../../ame/level1/tier_aead
import ../types
import ../level0/gb3hkdf
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
  secureClearAmeBytes(E.material)
  secureClearAmeBytes(E.nextChainKey)
  E = default(FomkePreparedSendEntry)

proc clearFomkeSendCache*(C: var FomkeSendCache) {.role: stateController,
    tag: {tagAppApi, tagCryptoBoundary, tagFomke}.} =
  ## C: caller-owned future-message key blocks erased.
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
    result.entries[i].material = copyFomkeBytes(C.entries[i].material)
    result.entries[i].nextChainKey = copyFomkeBytes(C.entries[i].nextChainKey)
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
    result = result + C.entries[i].material.len +
      C.entries[i].nextChainKey.len
    i = i + 1

proc validateFomkeState*(S: FomkeState) {.role: parser,
    tag: {tagCryptoBoundary, tagFomke, tagValidation}.} =
  ## S: initialized state checked before key progression.
  var
    i: int = 0
  if S.epoch == 0'u32:
    raise newException(ValueError, "FOMKE epoch must be positive")
  if S.algorithms.length == 0'u8:
    raise newException(ValueError, "FOMKE AME path is empty")
  validateAmeTier(S.layout, S.tier)
  if S.lane1.chainKey.len != fomkeChainKeyBytes or
      S.lane2.chainKey.len != fomkeChainKeyBytes:
    raise newException(ValueError, "FOMKE directional chain key is invalid")
  if S.maxSkip > fomkeMaxSkipLimit:
    raise newException(ValueError, "FOMKE skipped-key limit is too large")
  while i < S.skipped.len:
    if S.skipped[i].keyMaterial.len != fomkeMessageKeyBytes:
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
    C.nextIndex == chain.nextIndex and
    C.chainKey.len == fomkeChainKeyBytes and
    constantTimeEqualAme(C.chainKey, chain.chainKey)

proc requireFomkeQuiescent(S: FomkeState) {.role: parser,
    tag: {tagExchange, tagFomke, tagValidation}.} =
  ## S: message state that must not progress during a KEM upgrade commit.
  validateFomkeState(S)
  if S.pending.active:
    raise newException(ValueError, "FOMKE KEM upgrade is pending")

proc buildFomkeRootInfo(A: AmeKemAlgorithms, L: AmeSuiteLayout,
    t: AmeMaskTier, epoch: uint32,
    context: openArray[uint8]): ByteSeq {.role: truthBuilder,
    tag: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## A/L/t/epoch/context: KEM path, slot layout, active slots, root epoch, and
  ## the handshake transcript the caller binds in.
  appendAmeLabel(result, "FOMKE-ROOT-v2")
  appendAmeU32(result, epoch)
  appendFomkeField(result, encodeAmeKemAlgorithms(A))
  appendFomkeField(result, encodeAmeSuiteLayout(L))
  appendFomkeField(result, encodeAmeMaskTier(t))
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

proc initFomke*(S: var seq[ByteSeq], A: AmeKemAlgorithms,
    L: AmeSuiteLayout, t: AmeMaskTier, role: FomkeRole,
    context: openArray[uint8] = [],
    c: Gb3KdfConfig = initGb3KdfConfig(),
    maxSkip: uint32 = fomkeDefaultMaxSkip,
    tagLen: AmeAuthTagLen = aatl32): FomkeState {.
    role: truthBuilder,
    tag: {tagAppApi, tagCryptoBoundary, tagExchange, tagFomke}.} =
  ## S: EVERY shared secret the exchange produced, in slot order. All of them
  ##    are consumed and erased on return. Mixing all of them is what makes a
  ##    hybrid exchange worth having: an attacker must break every slot, not
  ##    the weakest one.
  ## A/L/t/role/context/c/maxSkip/tagLen: KEM path, slot layout, active slots,
  ##    endpoint direction, transcript binding, work policy, skip budget, and
  ##    the tag length this session agreed.
  var
    info: ByteSeq = @[]
    root: ByteSeq = @[]
    seed: ByteSeq = @[]
    i: int = 0
  if S.len == 0:
    raise newException(ValueError, "FOMKE needs at least one shared secret")
  while i < S.len:
    if S[i].len == 0:
      raise newException(ValueError, "FOMKE shared secret row is empty")
    i = i + 1
  if maxSkip > fomkeMaxSkipLimit:
    raise newException(ValueError, "FOMKE skipped-key limit is too large")
  validateAmeTier(L, t)
  info = buildFomkeRootInfo(A, L, t, 1'u32, context)
  appendAmeLabel(seed, "FOMKE-ROOT-SECRETS-v1")
  root = deriveGb3HkdfInputs(seed, S, info, fomkeChainKeyBytes, c)
  result.role = role
  result.epoch = 1'u32
  result.algorithms = A
  result.layout = L
  result.tier = t
  result.tagLen = tagLen
  result.lane1 = deriveFomkeLaneRoot(root, flLane1, result.epoch, c)
  result.lane2 = deriveFomkeLaneRoot(root, flLane2, result.epoch, c)
  result.maxSkip = maxSkip
  result.kdf = c
  secureClearAmeBytes(seed)
  secureClearAmeBytes(root)
  i = 0
  while i < S.len:
    secureClearAmeBytes(S[i])
    i = i + 1
  S.setLen(0)
  validateFomkeState(result)

proc initFomkeFromAme*(E: AmeExchangeState, L: AmeSuiteLayout,
    t: AmeMaskTier, role: FomkeRole, context: openArray[uint8] = [],
    c: Gb3KdfConfig = initGb3KdfConfig(),
    maxSkip: uint32 = fomkeDefaultMaxSkip,
    tagLen: AmeAuthTagLen = aatl32): FomkeState {.
    role: truthBuilder,
    tag: {tagAppApi, tagAme, tagCryptoBoundary, tagExchange, tagFomke}.} =
  ## E/L/t: finished exchange plus the slot layout and active slots.
  ## role/context/c/maxSkip/tagLen: endpoint and derivation policy.
  ##
  ## Every KEM slot the tier switches on must have produced a secret, and all
  ## of them go into the root. A tier that names two KEMs but derives from one
  ## would be a hybrid in name only.
  var
    secrets: seq[ByteSeq] = @[]
    row: ByteSeq = @[]
    i: int = 0
  validateAmeTier(L, t)
  if not kemLayoutsEquivalent(L.kems, E.algorithms):
    raise newException(ValueError, "FOMKE exchange layout mismatch")
  while i < int(E.algorithms.length):
    if algorithmSlotSelected(t.masks.kem, i):
      if not algorithmSlotSelected(E.activeMask, i) or
          E.generation[i] == 0'u32 or E.sharedSecrets[i].len == 0:
        raise newException(ValueError,
          "FOMKE initial tier selects a KEM slot with no secret")
      row = @[]
      row.add(uint8(i))
      row.add(uint8(ord(E.algorithms.algorithms[i])))
      appendAmeU32(row, E.generation[i])
      appendFomkeField(row, E.sharedSecrets[i])
      secrets.add(row)
    i = i + 1
  result = initFomke(secrets, E.algorithms, L, t, role, context, c, maxSkip,
    tagLen)

proc buildFomkeBlockInfo(lane: FomkeLane, epoch: uint32,
    index: uint64): ByteSeq {.role: truthBuilder,
    tag: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## lane/epoch/index: exact directional chain block identity.
  appendAmeLabel(result, "FOMKE-CHAIN-BLOCK-v2")
  result.add(uint8(ord(lane)))
  appendAmeU32(result, epoch)
  appendAmeU64(result, index)

proc deriveFomkeChainBlock(C: FomkeChainState, lane: FomkeLane,
    epoch: uint32, c: Gb3KdfConfig): FomkeChainBlock {.role: truthBuilder,
    tag: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## C/lane/epoch/c: chain and exact derivation context. One step yields the
  ## replacement chain key plus one message key per direction; the caller
  ## keeps the one for its own lane and destroys the other immediately.
  var
    info: ByteSeq = @[]
    output: ByteSeq = @[]
    outputBytes: int = fomkeChainKeyBytes + fomkeMessageKeyBytes * 2
  if C.chainKey.len != fomkeChainKeyBytes or C.nextIndex == high(uint64):
    raise newException(ValueError, "FOMKE chain is invalid or exhausted")
  info = buildFomkeBlockInfo(lane, epoch, C.nextIndex)
  output = deriveGb3Hkdf(C.chainKey, @[], info, outputBytes, c)
  result.nextChainKey = sliceFomkeBytes(output, 0, fomkeChainKeyBytes)
  result.mk1 = sliceFomkeBytes(output, fomkeChainKeyBytes,
    fomkeMessageKeyBytes)
  result.mk2 = sliceFomkeBytes(output,
    fomkeChainKeyBytes + fomkeMessageKeyBytes, fomkeMessageKeyBytes)
  secureClearAmeBytes(output)

proc advanceFomkeChain(C: var FomkeChainState, lane: FomkeLane,
    epoch: uint32, c: Gb3KdfConfig): tuple[index: uint64,
    keyMaterial: ByteSeq] {.role: stateController,
    tag: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## C/lane/epoch/c: chain advanced by exactly one message key.
  ## The old chain key is erased here, which is the step that makes the
  ## ratchet one-way.
  var
    derivedBlock: FomkeChainBlock
  result.index = C.nextIndex
  derivedBlock = deriveFomkeChainBlock(C, lane, epoch, c)
  if lane == flLane1:
    result.keyMaterial = derivedBlock.mk1
    secureClearAmeBytes(derivedBlock.mk2)
  else:
    result.keyMaterial = derivedBlock.mk2
    secureClearAmeBytes(derivedBlock.mk1)
  secureClearAmeBytes(C.chainKey)
  C.chainKey = derivedBlock.nextChainKey
  C.nextIndex = C.nextIndex + 1'u64

proc buildFomkeMessageAad(S: FomkeState, epoch: uint32, index: uint64,
    lane: FomkeLane, aad: openArray[uint8]): ByteSeq {.
    role: truthBuilder, tag: {tagCryptoBoundary, tagFomke}.} =
  ## S/epoch/index/lane/aad: message identity and the caller's own binding.
  ## The message position is authenticated even though it also travels in
  ## the clear header, so a header field cannot be edited in flight.
  appendAmeLabel(result, "FOMKE-MESSAGE-AAD-v2")
  appendAmeU32(result, epoch)
  appendAmeU64(result, index)
  result.add(uint8(ord(lane)))
  result.add(uint8(ord(S.tagLen)))
  appendFomkeField(result, aad)

proc deriveFomkeMessageMaterial(S: FomkeState, mk: openArray[uint8],
    epoch: uint32, index: uint64, lane: FomkeLane): ByteSeq {.
    role: truthBuilder, tag: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## S/mk/epoch/index/lane: one ratchet key expanded into the whole block the
  ## slot construction needs -- nonce, then one key per switched-on cipher,
  ## then one per switched-on authenticator. Derived in ONE pass, so the cost
  ## does not grow with the number of derivation calls, only with the bytes.
  var
    info: ByteSeq = @[]
  appendAmeLabel(info, "FOMKE-MESSAGE-KEYS-v1")
  appendFomkeField(info, encodeAmeSuiteLayout(S.layout))
  appendFomkeField(info, encodeAmeMaskTier(S.tier))
  appendAmeU32(info, epoch)
  appendAmeU64(info, index)
  info.add(uint8(ord(lane)))
  result = deriveGb3Hkdf(mk, @[], info,
    ameTierKeyMaterialLen(S.layout, S.tier), S.kdf)
  secureClearAmeBytes(info)

proc sealFomkeMessage*(S: var FomkeState, plaintext: openArray[uint8],
    aad: openArray[uint8] = []): FomkeMessage {.role: orchestrator,
    tag: {tagAppApi, tagCryptoBoundary, tagFomke}.} =
  ## S/plaintext/aad: sender state, one message, and external binding.
  var
    lane: FomkeLane
    key: tuple[index: uint64, keyMaterial: ByteSeq]
    material: ByteSeq = @[]
    messageAad: ByteSeq = @[]
    sealed: tuple[ciphertext: ByteSeq, authTag: ByteSeq]
  requireFomkeQuiescent(S)
  lane = outboundFomkeLane(S.role)
  if lane == flLane1:
    key = advanceFomkeChain(S.lane1, lane, S.epoch, S.kdf)
  else:
    key = advanceFomkeChain(S.lane2, lane, S.epoch, S.kdf)
  result.epoch = S.epoch
  result.index = key.index
  result.senderLane = lane
  result.tagLen = S.tagLen
  material = deriveFomkeMessageMaterial(S, key.keyMaterial, result.epoch,
    result.index, lane)
  messageAad = buildFomkeMessageAad(S, result.epoch, result.index, lane, aad)
  sealed = sealAmeTier(S.layout, S.tier, material, plaintext, messageAad,
    S.tagLen)
  result.ciphertext = sealed.ciphertext
  result.authTag = sealed.authTag
  secureClearAmeBytes(key.keyMaterial)
  secureClearAmeBytes(material)
  secureClearAmeBytes(messageAad)

proc requireFomkeSendCacheBounds(messageCount: int) {.
    role: parser, tag: {tagCryptoBoundary, tagFomke, tagValidation}.} =
  ## messageCount: bounded cache size before any secret work is done.
  if messageCount <= 0 or messageCount > fomkeMaxPreparedMessages:
    raise newException(ValueError, "FOMKE prepared message count is invalid")

proc prepareFomkeSendCache*(S: FomkeState,
    messageCount: int = fomkeDefaultPreparedMessages): FomkeSendCache {.
    role: truthBuilder, tag: {tagAppApi, tagCryptoBoundary, tagFomke}.} =
  ## S/messageCount: outbound snapshot and bounded future slots. This does not
  ## advance S, so it can be built off the latency-sensitive path.
  ##
  ## Trade-off worth knowing: a filled cache holds the key material for the
  ## next `messageCount` messages in memory. Forward secrecy for messages
  ## already SENT is unaffected, but a machine seized while the cache is full
  ## gives up the next `messageCount` messages that had not been sent yet.
  ## Keep the count small on a device that can be taken.
  var
    C: FomkeChainState
    lane: FomkeLane
    key: tuple[index: uint64, keyMaterial: ByteSeq]
    i: int = 0
  requireFomkeQuiescent(S)
  requireFomkeSendCacheBounds(messageCount)
  lane = outboundFomkeLane(S.role)
  if lane == flLane1:
    C = cloneFomkeChain(S.lane1)
  else:
    C = cloneFomkeChain(S.lane2)
  result.epoch = S.epoch
  result.lane = lane
  result.nextIndex = C.nextIndex
  result.chainKey = copyFomkeBytes(C.chainKey)
  result.entries.setLen(messageCount)
  try:
    while i < messageCount:
      key = advanceFomkeChain(C, lane, S.epoch, S.kdf)
      result.entries[i].epoch = S.epoch
      result.entries[i].index = key.index
      result.entries[i].lane = lane
      result.entries[i].material = deriveFomkeMessageMaterial(S,
        key.keyMaterial, S.epoch, key.index, lane)
      secureClearAmeBytes(key.keyMaterial)
      result.entries[i].nextChainKey = copyFomkeBytes(C.chainKey)
      i = i + 1
    clearFomkeChain(C)
  except CatchableError:
    secureClearAmeBytes(key.keyMaterial)
    clearFomkeChain(C)
    clearFomkeSendCache(result)
    raise

proc preparedEntryMatches(E: FomkePreparedSendEntry, S: FomkeState,
    C: FomkeSendCache, lane: FomkeLane): bool {.role: parser,
    tag: {tagCryptoBoundary, tagFomke, tagValidation}.} =
  ## E/S/C/lane: next entry bound to the current epoch and direction.
  result = E.epoch == S.epoch and E.index == C.nextIndex and E.lane == lane and
    E.material.len == ameTierKeyMaterialLen(S.layout, S.tier) and
    E.nextChainKey.len == fomkeChainKeyBytes

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
  ## Falls back to the plain path whenever the cache no longer lines up, so a
  ## stale cache can never seal under a key the live chain has moved past.
  var
    lane: FomkeLane
    entry: FomkePreparedSendEntry
    messageAad: ByteSeq = @[]
    sealed: tuple[ciphertext: ByteSeq, authTag: ByteSeq]
  requireFomkeQuiescent(S)
  lane = outboundFomkeLane(S.role)
  if not fomkeSendCacheMatches(S, C):
    clearFomkeSendCache(C)
    return sealFomkeMessage(S, plaintext, aad)
  entry = C.entries[C.nextEntry]
  if not preparedEntryMatches(entry, S, C, lane):
    clearFomkeSendCache(C)
    return sealFomkeMessage(S, plaintext, aad)
  result.epoch = entry.epoch
  result.index = entry.index
  result.senderLane = lane
  result.tagLen = S.tagLen
  messageAad = buildFomkeMessageAad(S, result.epoch, result.index, lane, aad)
  sealed = sealAmeTier(S.layout, S.tier, entry.material, plaintext,
    messageAad, S.tagLen)
  result.ciphertext = sealed.ciphertext
  result.authTag = sealed.authTag
  secureClearAmeBytes(messageAad)
  commitFomkePreparedChain(S, C, entry, lane)
  if fomkePreparedMessages(C) == 0:
    clearFomkeSendCache(C)

proc takeSkippedFomkeKey(S: var seq[FomkeSkippedKey], epoch: uint32,
    index: uint64, lane: FomkeLane): ByteSeq {.role: stateController,
    tag: {tagCryptoBoundary, tagFomke}.} =
  ## S/epoch/index/lane: cache and exact previously skipped key identity.
  ## Taking a key removes it, so the same message can never open twice.
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
  ## S/index/lane: receive chain advanced up to one message, at most `maxSkip`
  ## steps ahead. Keys for the messages that were jumped over are cached, so a
  ## datagram that arrives late still opens; anything further ahead is refused
  ## rather than letting a peer make this side derive without bound.
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
    key = advanceFomkeChain(C, lane, S.epoch, S.kdf)
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
  ##
  ## The whole state is copied first and only swapped in once the tag has
  ## verified. A forged message therefore costs one derivation and changes
  ## nothing -- it cannot burn ratchet positions or fill the skipped cache.
  var
    pending: FomkeState
    expectedLane: FomkeLane
    key: ByteSeq = @[]
    material: ByteSeq = @[]
    messageAad: ByteSeq = @[]
    opened: tuple[ok: bool, payload: ByteSeq]
  try:
    requireFomkeQuiescent(S)
    expectedLane = inboundFomkeLane(S.role)
    if message.epoch != S.epoch or message.senderLane != expectedLane:
      result.err = "FOMKE epoch or sender lane mismatch"
      return
    if message.tagLen != S.tagLen or
        message.authTag.len != int(ord(S.tagLen)):
      result.err = "FOMKE tag length does not match the agreed length"
      return
    pending = cloneFomkeState(S)
    key = acquireFomkeInboundKey(pending, message.index, expectedLane)
    if key.len == 0:
      clearFomkeState(pending)
      result.err = "FOMKE message key is unavailable or replayed"
      return
    material = deriveFomkeMessageMaterial(S, key, message.epoch,
      message.index, expectedLane)
    messageAad = buildFomkeMessageAad(S, message.epoch, message.index,
      message.senderLane, aad)
    opened = openAmeTier(S.layout, S.tier, material, message.ciphertext,
      message.authTag, messageAad, S.tagLen)
    secureClearAmeBytes(key)
    secureClearAmeBytes(material)
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
    secureClearAmeBytes(material)
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
    A: AmeKemAlgorithms, L: AmeSuiteLayout): ByteSeq {.
    role: truthBuilder,
    tag: {tagExchange, tagFomke, tagKdf}.} =
  ## c/A/L: public commit fields, KEM path, and the slot layout they sit in.
  var
    i: int = 0
  appendAmeLabel(result, "FOMKE-UPGRADE-COMMIT-v3")
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
  appendFomkeField(result, encodeAmeSuiteLayout(L))
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
  ##
  ## The new epoch's root is derived from BOTH the current chain keys and the
  ## fresh KEM secrets. Mixing the old keys keeps an attacker who only saw the
  ## new exchange out; mixing the new secrets lets a session recover from a
  ## past compromise, because the attacker never saw the new KEM result.
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
  validateAmeTier(S.layout, r.targetTier)
  result.requestId = requestId
  result.baseEpoch = S.epoch
  result.targetEpoch = targetEpoch
  result.targetTier = r.targetTier
  result.exchangeMask = r.exchangeMask
  result.lane1Index = S.lane1.nextIndex
  result.lane2Index = S.lane2.nextIndex
  secretRows = collectFomkeUpgradeSecrets(candidate, r, result.generations)
  metadata = buildFomkeUpgradeMetadata(result, S.algorithms, S.layout)
  laneMaterial = canonicalFomkeLaneMaterial(S)
  root = deriveGb3HkdfInputs(laneMaterial, secretRows, metadata,
    fomkeChainKeyBytes, S.kdf)
  S.pending.active = true
  S.pending.commit = result
  S.pending.candidateLane1 = deriveFomkeLaneRoot(root, flLane1,
    targetEpoch, S.kdf)
  S.pending.candidateLane2 = deriveFomkeLaneRoot(root, flLane2,
    targetEpoch, S.kdf)
  appendAmeLabel(confirmInfo, "FOMKE-UPGRADE-CONFIRM-v3")
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
  ## The new tier takes effect here and nowhere else, so the slot selection
  ## and the chain keys always change together.
  var
    lane1: FomkeChainState
    lane2: FomkeChainState
    targetEpoch: uint32 = 0'u32
    targetTier: AmeMaskTier
  validateFomkeUpgrade(S, c)
  lane1 = cloneFomkeChain(S.pending.candidateLane1)
  lane2 = cloneFomkeChain(S.pending.candidateLane2)
  targetEpoch = S.pending.commit.targetEpoch
  targetTier = S.pending.commit.targetTier
  clearFomkeChain(S.lane1)
  clearFomkeChain(S.lane2)
  clearFomkeSkipped(S.skipped)
  clearFomkePending(S.pending)
  S.lane1 = lane1
  S.lane2 = lane2
  S.epoch = targetEpoch
  S.tier = targetTier
  validateFomkeState(S)

proc cancelFomkeUpgrade*(S: var FomkeState) {.role: stateController,
    tag: {tagAppApi, tagCryptoBoundary, tagExchange, tagFomke}.} =
  ## S: unconfirmed candidate erased while current chains remain unchanged.
  clearFomkePending(S.pending)
