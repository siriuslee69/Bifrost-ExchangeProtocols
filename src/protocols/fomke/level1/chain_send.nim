## -------------------------------------------------------------------------
## FOMKE Chain Send <- the two chains: made from an epoch, stepped to seal
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
## ╭─ ❧ where the two chains come from 🌊
##
## ONE XHKDF call, and its output cut into three pieces. There is no root
## key in between -- nothing is left over to erase, because nothing else
## was made:
##
##   every KEM secret (ISS) + transcript + layout + tier
##                 │
##              XHKDF  (one call, 160 bytes out)
##                 │
##   ┌─────────────┼──────────────┬──────────────────┐
##   │ LK1  0..63  │ LK2  64..127 │ TK  128..159     │
##   └─────────────┴──────────────┴──────────────────┘
##     lane 1 chain   lane 2 chain   tight key: never used directly;
##                                   NK, JK and CS are derived from it
##                                   only when needed (see `fomkeTightKeyBytes`)
##
## A KEM rotation does the same with the NEXT KEY (NK, derived from TK) in
## place of nothing:
##
##   NK + the fresh KEM secrets + the commit ──XHKDF──▶
##       [ LK1' | LK2' | TK' | confirmation key ]
##
## So the new epoch needs BOTH the old TK and the new KEM result. An
## attacker who only broke the new KEM lacks the TK; one who stole the TK
## lacks the new KEM result.
##
## The message key is not used to encrypt directly. It is expanded into one
## block that holds, in this order:
##
##   [ nonce ][ key for cipher slot 0 ][ key for cipher slot 1 ][ mac keys... ]
##
## and level1/tier_aead turns that block plus the payload into ciphertext and
## a tag. So the algorithms in play come from the session's slot layout, not
## from anything FOMKE picks for itself.


import ../../types
import ../../ame/types
import ../../ame/level0/bytes
import ../../ame/level1/exchange_paths
import ../../ame/level1/suites
import ../../ame/level1/tier_aead
import ../types
import ../level0/xhkdf
import runePragmas

const
  fomkeEpochKeyBytes = fomkeChainKeyBytes * 2 + fomkeTightKeyBytes
    ## [ LK1 | LK2 | TK ] -- what one epoch derivation hands out.
  fomkeConfirmKeyBytes = xhkdfBlockBytes
    ## A rotation also derives the key its confirmation tag is taken with.

type
  FomkeChainBlock = object
    nextChainKey: ByteSeq
    mk1: ByteSeq
    mk2: ByteSeq

proc copyFomkeBytes*(A: openArray[uint8]): ByteSeq {.role: helper,
    tag: "cryptoBoundary|fomke".} =
  ## A: secret bytes copied into independent owned storage.
  result = @A

proc cloneFomkeSendCache*(C: FomkeSendCache): FomkeSendCache {.role: helper,
    tag: "appApi|cryptoBoundary|fomke".} =
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

proc fomkePreparedSecretBytes*(C: FomkeSendCache): int {.role: parser,
    tag: "appApi|cryptoBoundary|fomke".} =
  ## C: currently allocated secret bytes, excluding sequence/object overhead.
  var
    i: int = 0
  result = C.chainKey.len
  while i < C.entries.len:
    result = result + C.entries[i].material.len +
      C.entries[i].nextChainKey.len
    i = i + 1

proc appendFomkeField*(A: var ByteSeq, B: openArray[uint8]) {.
    role: dataWriter, tag: "fomke|kdf".} =
  ## A/B: destination and one length-framed field.
  if uint64(B.len) > uint64(high(uint32)):
    raise newException(ValueError, "FOMKE field exceeds u32")
  appendAmeU32(A, uint32(B.len))
  appendAmeBytes(A, B)

proc buildFomkeEpochInfo(A: AmeKemAlgorithms, L: AmeSuiteLayout,
    t: AmeMaskTier, epoch: uint32,
    context: openArray[uint8]): ByteSeq {.role: truthBuilder,
    tag: "cryptoBoundary|fomke|kdf".} =
  ## A/L/t/epoch/context: KEM path, slot layout, active slots, epoch, and
  ## the handshake transcript the caller binds in.
  appendAmeLabel(result, "FOMKE-EPOCH-KEYS-v4")
  appendAmeU32(result, epoch)
  appendFomkeField(result, encodeAmeKemAlgorithms(A))
  appendFomkeField(result, encodeAmeSuiteLayout(L))
  appendFomkeField(result, encodeAmeMaskTier(t))
  appendFomkeField(result, context)

proc sliceFomkeBytes*(A: openArray[uint8], offset, count: int): ByteSeq {.
    role: parser, tag: "cryptoBoundary|fomke".} =
  ## A/offset/count: source and bounded slice coordinates.
  var
    i: int = 0
  if offset < 0 or count < 0 or offset > A.len - count:
    raise newException(ValueError, "FOMKE key slice is out of bounds")
  result.setLen(count)
  while i < count:
    result[i] = A[offset + i]
    i = i + 1

proc validateFomkeState*(S: FomkeState) {.role: parser,
    tag: "cryptoBoundary|fomke|validation".} =
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
  if S.tightKey.len != fomkeTightKeyBytes:
    raise newException(ValueError, "FOMKE tight key is invalid")
  if S.reorderCeiling > fomkeMaxReorderWindow or
      S.reorderCeiling < fomkeMinReorderWindow:
    raise newException(ValueError, "FOMKE reorder ceiling is out of range")
  if S.reorderWindow > S.reorderCeiling or
      S.reorderWindow < fomkeMinReorderWindow:
    raise newException(ValueError, "FOMKE reorder window is out of range")
  while i < S.skipped.len:
    if S.skipped[i].keyMaterial.len != fomkeMessageKeyBytes:
      raise newException(ValueError, "FOMKE skipped message key is invalid")
    i = i + 1

proc takeFomkeEpochKeys*(K: var ByteSeq, lane1, lane2: var FomkeChainState,
    tightKey: var ByteSeq) {.role: actor,
    tag: "cryptoBoundary|fomke|kdf".} =
  ## K: one epoch derivation's output, cut apart and then erased.
  ## lane1/lane2/tightKey: where the three pieces go.
  ##
  ##   offset   0 .. 63   lane 1 chain key
  ##   offset  64 ..127   lane 2 chain key
  ##   offset 128 ..159   tight key (TK)
  ##   anything after that belongs to the caller (the rotation's
  ##   confirmation key) and is left in K for it to take.
  if K.len < fomkeEpochKeyBytes:
    raise newException(ValueError, "FOMKE epoch key block is too short")
  lane1.chainKey = sliceFomkeBytes(K, 0, fomkeChainKeyBytes)
  lane1.nextIndex = 0'u64
  lane2.chainKey = sliceFomkeBytes(K, fomkeChainKeyBytes, fomkeChainKeyBytes)
  lane2.nextIndex = 0'u64
  tightKey = sliceFomkeBytes(K, fomkeChainKeyBytes * 2,
    fomkeTightKeyBytes)

proc deriveFomkeTightChild*(S: FomkeState, label: string,
    extra: openArray[uint8] = []): ByteSeq {.role: truthBuilder,
    tag: "cryptoBoundary|fomke|kdf".} =
  ## S: state whose tight key (TK) is the parent.
  ## label: which child -- "FOMKE-NEXT-KEY-v1" (NK), "FOMKE-JUMP-KEY-v1"
  ##   (JK), "FOMKE-NEXT-HANDSHAKE-v2" (CS).
  ## extra: anything else the child is bound to (a jump's lane and number).
  ##
  ##   TK ──XHKDF( label | epoch u32 | len u32 | extra )──▶ 32 bytes
  ##
  ## The epoch is always bound in, so no child of one epoch equals a child
  ## of the next. The caller erases the child as soon as it is used; only TK
  ## is ever held.
  var
    info: ByteSeq = @[]
  if S.tightKey.len != fomkeTightKeyBytes:
    raise newException(ValueError, "FOMKE tight key is invalid")
  appendAmeLabel(info, label)
  appendAmeU32(info, S.epoch)
  appendFomkeField(info, extra)
  result = deriveXhkdf(S.tightKey, @[], info, fomkeTightKeyBytes, S.kdf)
  secureClearAmeBytes(info)

proc initFomke*(S: var seq[ByteSeq], A: AmeKemAlgorithms,
    L: AmeSuiteLayout, t: AmeMaskTier, role: FomkeRole,
    context: openArray[uint8] = [],
    c: XhkdfConfig = initXhkdfConfig(),
    reorderCeiling: uint32 = fomkeDefaultReorderCeiling,
    tagLen: AmeAuthTagLen = aatl32): FomkeState {.
    role: truthBuilder,
    tag: "appApi|cryptoBoundary|exchange|fomke".} =
  ## S: EVERY shared secret the exchange produced, in slot order. All of them
  ##    are consumed and erased on return. Mixing all of them is what makes a
  ##    hybrid exchange worth having: an attacker must break every slot, not
  ##    the weakest one.
  ## A/L/t/role/context/c/reorderCeiling/tagLen: KEM path, slot layout, active
  ##    slots, endpoint direction, transcript binding, work policy, the widest
  ##    the reorder window may ever grow, and the tag length this session
  ##    agreed. The window itself starts well below that ceiling and is only
  ##    widened by reordering a verified message has proved.
  var
    info: ByteSeq = @[]
    keys: ByteSeq = @[]
    seed: ByteSeq = @[]
    i: int = 0
  if S.len == 0:
    raise newException(ValueError, "FOMKE needs at least one shared secret")
  while i < S.len:
    if S[i].len == 0:
      raise newException(ValueError, "FOMKE shared secret row is empty")
    i = i + 1
  if reorderCeiling > fomkeMaxReorderWindow or
      reorderCeiling < fomkeMinReorderWindow:
    raise newException(ValueError, "FOMKE reorder ceiling is out of range")
  validateAmeTier(L, t)
  info = buildFomkeEpochInfo(A, L, t, 1'u32, context)
  appendAmeLabel(seed, "FOMKE-INITIAL-SECRETS-v2")
  keys = deriveXhkdfInputs(seed, S, info, fomkeEpochKeyBytes, c)
  result.role = role
  result.epoch = 1'u32
  result.algorithms = A
  result.layout = L
  result.tier = t
  result.tagLen = tagLen
  takeFomkeEpochKeys(keys, result.lane1, result.lane2, result.tightKey)
  result.reorderCeiling = reorderCeiling
  result.reorderWindow = min(fomkeDefaultReorderWindow, reorderCeiling)
  result.orderedRun = 0'u32
  result.kdf = c
  secureClearAmeBytes(seed)
  secureClearAmeBytes(keys)
  i = 0
  while i < S.len:
    secureClearAmeBytes(S[i])
    i = i + 1
  S.setLen(0)
  validateFomkeState(result)

proc initFomkeFromAme*(E: AmeExchangeState, L: AmeSuiteLayout,
    t: AmeMaskTier, role: FomkeRole, context: openArray[uint8] = [],
    c: XhkdfConfig = initXhkdfConfig(),
    reorderCeiling: uint32 = fomkeDefaultReorderCeiling,
    tagLen: AmeAuthTagLen = aatl32): FomkeState {.
    role: truthBuilder,
    tag: "appApi|ame|cryptoBoundary|exchange|fomke".} =
  ## E/L/t: finished exchange plus the slot layout and active slots.
  ## role/context/c/reorderCeiling/tagLen: endpoint and derivation policy.
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
          E.generation[i] == 0'u32 or E.stackedSecrets[i].len == 0:
        raise newException(ValueError,
          "FOMKE initial tier selects a KEM slot with no secret")
      row = @[]
      row.add(uint8(i))
      row.add(uint8(ord(E.algorithms.algorithms[i])))
      appendAmeU32(row, E.generation[i])
      appendFomkeField(row, E.stackedSecrets[i])
      secrets.add(row)
    i = i + 1
  result = initFomke(secrets, E.algorithms, L, t, role, context, c,
    reorderCeiling, tagLen)

proc buildFomkeBlockInfo(lane: FomkeLane, epoch: uint32,
    index: uint64): ByteSeq {.role: truthBuilder,
    tag: "cryptoBoundary|fomke|kdf".} =
  ## lane/epoch/index: exact directional chain block identity.
  appendAmeLabel(result, "FOMKE-CHAIN-BLOCK-v2")
  result.add(uint8(ord(lane)))
  appendAmeU32(result, epoch)
  appendAmeU64(result, index)

proc deriveFomkeChainBlock(C: FomkeChainState, lane: FomkeLane,
    epoch: uint32, c: XhkdfConfig): FomkeChainBlock {.role: truthBuilder,
    tag: "cryptoBoundary|fomke|kdf".} =
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
  output = deriveXhkdf(C.chainKey, @[], info, outputBytes, c)
  result.nextChainKey = sliceFomkeBytes(output, 0, fomkeChainKeyBytes)
  result.mk1 = sliceFomkeBytes(output, fomkeChainKeyBytes,
    fomkeMessageKeyBytes)
  result.mk2 = sliceFomkeBytes(output,
    fomkeChainKeyBytes + fomkeMessageKeyBytes, fomkeMessageKeyBytes)
  secureClearAmeBytes(output)

proc clearFomkePreparedEntry(E: var FomkePreparedSendEntry) {.
    role: actor, tag: "cryptoBoundary|fomke".} =
  ## E: one unused future message slot securely erased.
  secureClearAmeBytes(E.material)
  secureClearAmeBytes(E.nextChainKey)
  E = default(FomkePreparedSendEntry)

proc requireFomkeQuiescent*(S: FomkeState) {.role: parser,
    tag: "exchange|fomke|validation".} =
  ## S: message state that must not progress during a KEM upgrade commit.
  validateFomkeState(S)
  if S.pending.active:
    raise newException(ValueError, "FOMKE KEM upgrade is pending")

proc advanceFomkeChain*(C: var FomkeChainState, lane: FomkeLane,
    epoch: uint32, c: XhkdfConfig): tuple[index: uint64,
    keyMaterial: ByteSeq] {.role: actor,
    tag: "cryptoBoundary|fomke|kdf".} =
  ## C/lane/epoch/c: chain advanced by exactly one message key.
  ## The old chain key is erased here, which is the step that makes the
  ## ratchet one-way.
  var
    derivedBlock: FomkeChainBlock = default(FomkeChainBlock)
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

proc deriveFomkeMessageMaterial*(S: FomkeState, mk: openArray[uint8],
    epoch: uint32, index: uint64, lane: FomkeLane): ByteSeq {.
    role: truthBuilder, tag: "cryptoBoundary|fomke|kdf".} =
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
  result = deriveXhkdf(mk, @[], info,
    ameTierKeyMaterialLen(S.layout, S.tier), S.kdf)
  secureClearAmeBytes(info)

proc clearFomkeChain*(C: var FomkeChainState) {.role: actor,
    tag: "cryptoBoundary|fomke".} =
  ## C: chain key and counter reset after secure erasure.
  secureClearAmeBytes(C.chainKey)
  C = default(FomkeChainState)

proc requireFomkeSendCacheBounds(messageCount: int) {.
    role: parser, tag: "cryptoBoundary|fomke|validation".} =
  ## messageCount: bounded cache size before any secret work is done.
  if messageCount <= 0 or messageCount > fomkeMaxPreparedMessages:
    raise newException(ValueError, "FOMKE prepared message count is invalid")

proc outboundFomkeLane*(r: FomkeRole): FomkeLane {.role: parser,
    tag: "appApi|fomke".} =
  ## r: local role mapped to its sender lane.
  if r == frInitiator:
    return flLane1
  result = flLane2

proc cloneFomkeChain*(C: FomkeChainState): FomkeChainState {.role: helper,
    tag: "cryptoBoundary|fomke".} =
  ## C: chain copied without sharing secret byte storage.
  result.chainKey = copyFomkeBytes(C.chainKey)
  result.nextIndex = C.nextIndex

proc clearFomkeSendCache*(C: var FomkeSendCache) {.role: actor,
    tag: "appApi|cryptoBoundary|fomke".} =
  ## C: caller-owned future-message key blocks erased.
  var
    i: int = 0
  while i < C.entries.len:
    clearFomkePreparedEntry(C.entries[i])
    i = i + 1
  secureClearAmeBytes(C.chainKey)
  C.entries.setLen(0)
  C = default(FomkeSendCache)

proc prepareFomkeSendCache*(S: FomkeState,
    messageCount: int = fomkeDefaultPreparedMessages): FomkeSendCache {.
    role: truthBuilder, tag: "appApi|cryptoBoundary|fomke".} =
  ## S/messageCount: outbound snapshot and bounded future slots. This does not
  ## advance S, so it can be built off the latency-sensitive path.
  ##
  ## Trade-off worth knowing: a filled cache holds the key material for the
  ## next `messageCount` messages in memory. Forward secrecy for messages
  ## already SENT is unaffected, but a machine seized while the cache is full
  ## gives up the next `messageCount` messages that had not been sent yet.
  ## Keep the count small on a device that can be taken.
  var
    C: FomkeChainState = default(FomkeChainState)
    lane: FomkeLane = flLane1
    key: tuple[index: uint64, keyMaterial: ByteSeq] = (0'u64, @[])
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

proc fomkePreparedMessages*(C: FomkeSendCache): int {.role: parser,
    tag: "appApi|cryptoBoundary|fomke".} =
  ## C: cache whose number of unused sequential send slots is returned.
  if C.nextEntry < 0 or C.nextEntry > C.entries.len:
    return
  result = C.entries.len - C.nextEntry

proc commitFomkePreparedChain(S: var FomkeState, C: var FomkeSendCache,
    E: FomkePreparedSendEntry, lane: FomkeLane) {.role: actor,
    tag: "cryptoBoundary|fomke".} =
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

proc fomkeSendCacheMatches*(S: FomkeState, C: FomkeSendCache): bool {.
    role: parser, tag: "appApi|cryptoBoundary|fomke|validation".} =
  ## S/C: live outbound chain and one non-mutating prepared snapshot.
  var
    lane: FomkeLane = flLane1
    chain: FomkeChainState = default(FomkeChainState)
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

proc buildFomkeMessageAad*(S: FomkeState, epoch: uint32, index: uint64,
    lane: FomkeLane, aad: openArray[uint8]): ByteSeq {.
    role: truthBuilder, tag: "cryptoBoundary|fomke".} =
  ## S/epoch/index/lane/aad: message identity and the caller's own binding.
  ## The message position is authenticated even though it also travels in
  ## the clear header, so a header field cannot be edited in flight.
  appendAmeLabel(result, "FOMKE-MESSAGE-AAD-v2")
  appendAmeU32(result, epoch)
  appendAmeU64(result, index)
  result.add(uint8(ord(lane)))
  result.add(uint8(ord(S.tagLen)))
  appendFomkeField(result, aad)

proc sealFomkeMessage*(S: var FomkeState, plaintext: openArray[uint8],
    aad: openArray[uint8] = []): FomkeMessage {.role: orchestrator,
    tag: "appApi|cryptoBoundary|fomke".} =
  ## S/plaintext/aad: sender state, one message, and external binding.
  var
    lane: FomkeLane = flLane1
    key: tuple[index: uint64, keyMaterial: ByteSeq] = (0'u64, @[])
    material: ByteSeq = @[]
    messageAad: ByteSeq = @[]
    sealed: tuple[ciphertext: ByteSeq, authTag: ByteSeq] = (@[], @[])
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

proc preparedEntryMatches(E: FomkePreparedSendEntry, S: FomkeState,
    C: FomkeSendCache, lane: FomkeLane): bool {.role: parser,
    tag: "cryptoBoundary|fomke|validation".} =
  ## E/S/C/lane: next entry bound to the current epoch and direction.
  result = E.epoch == S.epoch and E.index == C.nextIndex and E.lane == lane and
    E.material.len == ameTierKeyMaterialLen(S.layout, S.tier) and
    E.nextChainKey.len == fomkeChainKeyBytes

proc sealFomkeMessagePrepared*(S: var FomkeState, C: var FomkeSendCache,
    plaintext: openArray[uint8], aad: openArray[uint8] = []): FomkeMessage {.
    role: orchestrator, tag: "appApi|cryptoBoundary|fomke".} =
  ## S/C/plaintext/aad: live state, future cache, payload, and external binding.
  ## Falls back to the plain path whenever the cache no longer lines up, so a
  ## stale cache can never seal under a key the live chain has moved past.
  var
    lane: FomkeLane = flLane1
    entry: FomkePreparedSendEntry = default(FomkePreparedSendEntry)
    messageAad: ByteSeq = @[]
    sealed: tuple[ciphertext: ByteSeq, authTag: ByteSeq] = (@[], @[])
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

