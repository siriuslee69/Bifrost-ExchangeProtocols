## -------------------------------------------------------------------------
## FOMKE Chain <- opening, the reorder window, and atomic KEM upgrades
## -------------------------------------------------------------------------
##
## `chain_send.nim` makes the two chains from an epoch and steps the sending
## one for every sealed message; its header explains the chains themselves.
## This file is the rest of a FOMKE state's life:
##
##   opening        a message, including one that arrived out of order,
##                  using a key held back for it (the skipped keys)
##   reorder window how far ahead a message may be; it narrows on a clean
##                  path and widens, up to a ceiling, on proved reordering
##   whole state    clear it, clone it
##   upgrades       prepare, confirm or cancel a KEM rotation to a new epoch
##
##   chain.nim  --imports and passes on-->  chain_send.nim
##
## Import this file: it passes on everything `chain_send.nim` offers.

import tyr/hashes/blake3 as tyr_blake3

import ../../types
import ../../ame/types
import ../../ame/level0/bytes
import ../../ame/level1/exchange_paths
import ../../ame/level1/suites
import ../../ame/level1/tier_aead
import ../types
import ../level0/xhkdf
import runePragmas
import ./chain_send

export chain_send

const
  fomkeEpochKeyBytes = fomkeChainKeyBytes * 2 + fomkeTightKeyBytes
    ## [ LK1 | LK2 | TK ] -- what one epoch derivation hands out.
  fomkeConfirmKeyBytes = xhkdfBlockBytes
    ## A rotation also derives the key its confirmation tag is taken with.

proc dropOldestFomkeSkipped(S: var FomkeState) {.role: actor,
    tag: "cryptoBoundary|fomke".} =
  ## S: erase the one held key whose message has been missing longest.
  ##
  ## The backstop for the rule above. Distance clears keys that are provably
  ## gone; this one makes room when the cache is at its ceiling and every
  ## entry is still inside the window. The oldest is chosen because it is the
  ## one least likely to arrive, and giving it up costs at most one dropped
  ## message on a carrier that re-sends anyway.
  var
    i: int = 0
    oldest: int = -1
  while i < S.skipped.len:
    if oldest < 0 or S.skipped[i].index < S.skipped[oldest].index:
      oldest = i
    i = i + 1
  if oldest < 0:
    return
  secureClearAmeBytes(S.skipped[oldest].keyMaterial)
  S.skipped.delete(oldest)

proc takeSkippedFomkeKey(S: var seq[FomkeSkippedKey], epoch: uint32,
    index: uint64, lane: FomkeLane): ByteSeq {.role: actor,
    tag: "cryptoBoundary|fomke".} =
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

proc narrowFomkeReorderWindow(S: var FomkeState) {.role: actor,
    tag: "fomke", inline.} =
  ## S: window halved one step, once enough messages have arrived in order.
  ##
  ## Every message that turns up exactly where it was expected is one piece of
  ## evidence that the path is not reordering anything and the room being held
  ## open is not being used. After `fomkeReorderRelaxRuns` of them the window
  ## halves, down to `fomkeMinReorderWindow` and no further.
  S.orderedRun = S.orderedRun + 1'u32
  if S.orderedRun < fomkeReorderRelaxRuns:
    return
  S.orderedRun = 0'u32
  ## Never narrow below the number of keys this lane is HOLDING. A held key is
  ## evidence that this lane recently had a gap, and the window is what lets
  ## the next one through:
  ##
  ##   12 keys held, window narrowed to 4  ->  the next gap of 5 is refused,
  ##                                           and a refused message advances
  ##                                           nothing, so every message after
  ##                                           it sits further ahead still
  ##
  ## That is a lane that cannot recover. The floor cannot be driven by a
  ## stranger either: a key only enters the cache from a message whose tag
  ## verified, on the clone that is kept only if it did.
  ##
  ## The `min` is what keeps this a NARROWING. A floor above the current
  ## window must leave the window alone, never raise it -- widening is the
  ## other routine's job and it has evidence this one does not.
  S.reorderWindow = min(S.reorderWindow, max(S.reorderWindow div 2'u32,
    max(fomkeMinReorderWindow, uint32(S.skipped.len))))

proc widenFomkeReorderWindow(S: var FomkeState, distance: uint64) {.
    role: actor, tag: "fomke", inline.} =
  ## S/distance: window opened to cover a message that sat `distance` places
  ## out of position, with the same again as headroom so the next one being
  ## slightly worse does not cost a refusal.
  ##
  ## Only ever called for a message whose key was really produced, and only
  ## ever on the copy of the state that is kept if the tag then verifies. A
  ## forged message therefore cannot widen the window it is being measured by.
  var
    target: uint32 = S.reorderCeiling
  S.orderedRun = 0'u32
  if distance < uint64(S.reorderCeiling div 2'u32):
    target = uint32(distance) * 2'u32
  if target <= S.reorderWindow:
    return
  S.reorderWindow = min(target, S.reorderCeiling)

proc forgetUnreachableFomkeSkipped(S: var FomkeState, lane: FomkeLane,
    nextIndex: uint64) {.role: actor, tag: "cryptoBoundary|fomke".} =
  ## S/lane/nextIndex: erase the keys of messages that can no longer turn up.
  ##
  ## A skipped key is only worth anything while the message it belongs to
  ## might still arrive. `reorderCeiling` is the widest this lane will ever
  ## agree a path reorders, so a message further behind than that is not late
  ## -- it is gone:
  ##
  ##   nextIndex 900, ceiling 64
  ##       index 880   still plausible   keep
  ##       index 830   70 behind         gone, erase
  ##
  ## Without this the cache only ever grows. Reordering takes keys back out of
  ## it; LOSS never does, because a lost message is replaced by a re-send at a
  ## NEW index, and the old key waits for something that no longer exists. A
  ## few hundred lost datagrams then fill the cache with keys for messages
  ## that will never come, and the session stops receiving for good.
  var
    i: int = 0
  while i < S.skipped.len:
    if S.skipped[i].lane == lane and S.skipped[i].epoch == S.epoch and
        nextIndex > S.skipped[i].index and
        nextIndex - S.skipped[i].index > uint64(S.reorderCeiling):
      secureClearAmeBytes(S.skipped[i].keyMaterial)
      S.skipped.delete(i)
    else:
      i = i + 1

proc cloneFomkeSkipped(S: openArray[FomkeSkippedKey]): seq[FomkeSkippedKey] {.
    role: helper, tag: "cryptoBoundary|fomke".} =
  ## S: skipped-key cache copied without sharing key storage.
  var
    i: int = 0
    item: FomkeSkippedKey = default(FomkeSkippedKey)
  while i < S.len:
    item = S[i]
    item.keyMaterial = copyFomkeBytes(S[i].keyMaterial)
    result.add(item)
    i = i + 1

proc clearFomkePending(P: var FomkePendingUpgrade) {.role: actor,
    tag: "cryptoBoundary|exchange|fomke".} =
  ## P: candidate chains erased when committed or cancelled.
  clearFomkeChain(P.candidateLane1)
  clearFomkeChain(P.candidateLane2)
  secureClearAmeBytes(P.candidateTightKey)
  secureClearAmeBytes(P.commit.confirmationTag)
  P = default(FomkePendingUpgrade)

proc clearFomkeSkipped(S: var seq[FomkeSkippedKey]) {.role: actor,
    tag: "cryptoBoundary|fomke".} =
  ## S: cached skipped message keys erased before release.
  var
    i: int = 0
  while i < S.len:
    secureClearAmeBytes(S[i].keyMaterial)
    i = i + 1
  S.setLen(0)

proc clearFomkeState*(S: var FomkeState) {.role: actor,
    tag: "appApi|cryptoBoundary|fomke".} =
  ## S: all current, skipped, and candidate secret material erased.
  clearFomkeChain(S.lane1)
  clearFomkeChain(S.lane2)
  secureClearAmeBytes(S.tightKey)
  clearFomkeSkipped(S.skipped)
  clearFomkePending(S.pending)
  S = default(FomkeState)

proc cloneFomkeState*(S: FomkeState): FomkeState {.role: helper,
    tag: "cryptoBoundary|fomke".} =
  ## S: complete state copied for transactional authenticated receive.
  result = S
  result.lane1 = cloneFomkeChain(S.lane1)
  result.lane2 = cloneFomkeChain(S.lane2)
  result.tightKey = copyFomkeBytes(S.tightKey)
  result.skipped = cloneFomkeSkipped(S.skipped)
  result.pending.candidateLane1 = cloneFomkeChain(S.pending.candidateLane1)
  result.pending.candidateLane2 = cloneFomkeChain(S.pending.candidateLane2)
  result.pending.candidateTightKey = copyFomkeBytes(
    S.pending.candidateTightKey)
  result.pending.commit.confirmationTag = copyFomkeBytes(
    S.pending.commit.confirmationTag)

proc acquireFomkeInboundKey(S: var FomkeState, index: uint64,
    lane: FomkeLane): ByteSeq {.role: actor,
    tag: "cryptoBoundary|fomke|kdf".} =
  ## S/index/lane: receive chain advanced up to one message, at most
  ## `reorderWindow` steps ahead. Keys for the messages that were jumped over
  ## are cached, so a datagram that arrives late still opens; anything further
  ## ahead is refused rather than letting a peer make this side derive without
  ## bound.
  ##
  ## The cache never refuses. It holds at most `reorderCeiling` keys and gives
  ## up the least useful one to make room -- first anything further behind
  ## than the ceiling, which cannot arrive any more, then the oldest. Giving a
  ## key up costs one message that a carrier re-sends; REFUSING cost the whole
  ## session, because nothing ever took a lost message's key back out again.
  ##
  ## The window moves with what this lane actually sees:
  ##
  ##   message sits exactly where expected  -> narrow, slowly
  ##   message sits out of position         -> widen, at once
  ##
  ## A jump FORWARD widens it as well as a late arrival does. It has to: the
  ## window is what gates a forward jump in the first place, so a window that
  ## only grew on late arrivals could never grow enough to let a bigger jump
  ## through and would never see one.
  var
    C: FomkeChainState = default(FomkeChainState)
    key: tuple[index: uint64, keyMaterial: ByteSeq] = (0'u64, @[])
    skipped: FomkeSkippedKey = default(FomkeSkippedKey)
    distance: uint64 = 0'u64
  if lane == flLane1:
    C = cloneFomkeChain(S.lane1)
  else:
    C = cloneFomkeChain(S.lane2)
  if index < C.nextIndex:
    distance = C.nextIndex - index
    clearFomkeChain(C)
    result = takeSkippedFomkeKey(S.skipped, S.epoch, index, lane)
    if result.len > 0:
      widenFomkeReorderWindow(S, distance)
    return
  distance = index - C.nextIndex
  if distance > uint64(S.reorderWindow):
    clearFomkeChain(C)
    raise newException(ValueError, "FOMKE message gap exceeds the reorder window")
  forgetUnreachableFomkeSkipped(S, lane, index)
  while C.nextIndex <= index:
    key = advanceFomkeChain(C, lane, S.epoch, S.kdf)
    if key.index == index:
      result = key.keyMaterial
      break
    ## The cache is capped by the CEILING, not by the window that moves.
    ## Those are different quantities: the ceiling is the memory bound this
    ## lane was built with, the window is how far ahead a message may sit.
    ## Capping held keys with the moving window meant a path that went quiet
    ## -- narrowing the window towards four -- could no longer hold the keys
    ## it was already holding, and refused instead.
    if uint32(S.skipped.len) >= S.reorderCeiling:
      dropOldestFomkeSkipped(S)
    skipped.epoch = S.epoch
    skipped.index = key.index
    skipped.lane = lane
    skipped.keyMaterial = key.keyMaterial
    S.skipped.add(skipped)
  if distance == 0'u64:
    narrowFomkeReorderWindow(S)
  else:
    widenFomkeReorderWindow(S, distance)
  if lane == flLane1:
    clearFomkeChain(S.lane1)
    S.lane1 = C
  else:
    clearFomkeChain(S.lane2)
    S.lane2 = C

proc fomkeGapTooWide(S: FomkeState, index: uint64,
    lane: FomkeLane): bool {.role: parser, inline.} =
  ## S/index/lane: true when a message sits further ahead of the lane than
  ## the reorder window lets through. Checked before anything is derived, so
  ## it can be told apart from a bad tag -- see `FomkeOpenResult.behind`.
  var
    nextIndex: uint64 = S.lane1.nextIndex
  if lane == flLane2:
    nextIndex = S.lane2.nextIndex
  result = index > nextIndex and index - nextIndex > uint64(S.reorderWindow)

proc inboundFomkeLane*(r: FomkeRole): FomkeLane {.role: parser,
    tag: "appApi|fomke".} =
  ## r: local role mapped to the remote sender lane.
  if r == frInitiator:
    return flLane2
  result = flLane1

proc openFomkeMessage*(S: var FomkeState, message: FomkeMessage,
    aad: openArray[uint8] = []): FomkeOpenResult {.role: orchestrator,
    tag: "appApi|cryptoBoundary|fomke".} =
  ## S/message/aad: transactional receiver state, envelope, and binding bytes.
  ##
  ## The whole state is copied first and only swapped in once the tag has
  ## verified. A forged message therefore costs one derivation and changes
  ## nothing -- it cannot burn ratchet positions or fill the skipped cache.
  var
    pending: FomkeState = default(FomkeState)
    expectedLane: FomkeLane = flLane1
    key: ByteSeq = @[]
    material: ByteSeq = @[]
    messageAad: ByteSeq = @[]
    opened: tuple[ok: bool, payload: ByteSeq] = (ok: false, payload: @[])
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
    if fomkeGapTooWide(S, message.index, expectedLane):
      result.behind = true
      result.err = "FOMKE message gap exceeds the reorder window"
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

proc buildFomkeUpgradeMetadata(c: FomkeUpgradeCommit,
    A: AmeKemAlgorithms, L: AmeSuiteLayout): ByteSeq {.
    role: truthBuilder,
    tag: "exchange|fomke|kdf".} =
  ## c/A/L: public commit fields, KEM path, and the slot layout they sit in.
  var
    i: int = 0
  appendAmeLabel(result, "FOMKE-UPGRADE-COMMIT-v4")
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
    role: truthBuilder, tag: "ame|cryptoBoundary|exchange|fomke".} =
  ## E/r/generations: candidate AME state, exact mask, and bound slot counters.
  var
    i: int = 0
    row: ByteSeq = @[]
  while i < int(E.algorithms.length):
    if algorithmSlotSelected(r.exchangeMask, i):
      if not algorithmSlotSelected(E.activeMask, i) or
          E.generation[i] == 0'u32 or E.stackedSecrets[i].len == 0:
        raise newException(ValueError,
          "FOMKE upgrade selected an unavailable AME secret")
      generations[i] = E.generation[i]
      row = @[]
      row.add(uint8(i))
      row.add(uint8(ord(E.algorithms.algorithms[i])))
      appendAmeU32(row, E.generation[i])
      appendFomkeField(row, E.stackedSecrets[i])
      result.add(row)
    i = i + 1

proc clearFomkeSecretRows(S: var seq[ByteSeq]) {.role: actor,
    tag: "cryptoBoundary|exchange|fomke".} =
  ## S: temporary framed secret rows erased after derivation.
  var
    i: int = 0
  while i < S.len:
    secureClearAmeBytes(S[i])
    i = i + 1
  S.setLen(0)

proc fomkeKdfFor(S: FomkeState, t: AmeMaskTier): XhkdfConfig {.
    role: parser, tag: "fomke|kdf".} =
  ## S/t: the XHKDF settings an epoch with selection t runs: this state's
  ## rounds and mode, and the branches t's KDF slots switch on. An upgrade
  ## derives the new epoch with these, and confirming installs them -- in the
  ## same step as the new ciphers and MACs, so nothing switches early:
  ##
  ##   epoch n    KDF slots BLAKE3          -> branches {BLAKE3}
  ##   upgrade    target switches Gimli on  -> derived with {BLAKE3, Gimli}
  ##   epoch n+1  every step from here      -> {BLAKE3, Gimli}
  result = S.kdf
  result.branches = xhkdfBranchesOf(S.layout, t)

proc prepareFomkeUpgrade*(S: var FomkeState, requestId,
    targetEpoch: uint32, r: AmeExchangeRequest,
    candidate: AmeExchangeState): FomkeUpgradeCommit {.role: orchestrator,
    tag: "appApi|ame|cryptoBoundary|exchange|fomke".} =
  ## S/requestId/targetEpoch: quiescent chain and authenticated AME transaction.
  ## r/candidate: exact upgrade mask and resulting AME state.
  ##
  ## The new epoch is derived from BOTH this epoch's next key (NK, made from
  ## the tight key TK right here and erased right after) and the
  ## fresh KEM secrets, in one XHKDF call:
  ##
  ##   NK + new KEM secrets + commit ──▶ [ LK1' | LK2' | TK' | confirm key ]
  ##
  ## Mixing the NK keeps an attacker who only saw the new exchange out;
  ## mixing the new secrets lets a session recover from a past compromise,
  ## because the attacker never saw the new KEM result.
  ##
  ## The lane keys themselves are NOT an input. They were once, and that tied
  ## the new epoch to the exact position each lane had reached -- a value the
  ## two sides only agree on once every message in flight has landed. The TK
  ## is fixed for the whole epoch, so both sides always hold the same one.
  var
    metadata: ByteSeq = @[]
    secretRows: seq[ByteSeq] = @[]
    keys: ByteSeq = @[]
    confirmKey: ByteSeq = @[]
    confirmInfo: ByteSeq = @[]
    nextKey: ByteSeq = @[]
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
  nextKey = deriveFomkeTightChild(S, "FOMKE-NEXT-KEY-v1")
  keys = deriveXhkdfInputs(nextKey, secretRows, metadata,
    fomkeEpochKeyBytes + fomkeConfirmKeyBytes, fomkeKdfFor(S, r.targetTier))
  S.pending.active = true
  S.pending.commit = result
  takeFomkeEpochKeys(keys, S.pending.candidateLane1,
    S.pending.candidateLane2, S.pending.candidateTightKey)
  confirmKey = sliceFomkeBytes(keys, fomkeEpochKeyBytes, fomkeConfirmKeyBytes)
  appendAmeLabel(confirmInfo, "FOMKE-UPGRADE-CONFIRM-v4")
  appendFomkeField(confirmInfo, metadata)
  result.confirmationTag = tyr_blake3.blake3KeyedHash(confirmKey, confirmInfo,
    xhkdfBlockBytes)
  S.pending.commit.confirmationTag = copyFomkeBytes(result.confirmationTag)
  secureClearAmeBytes(metadata)
  clearFomkeSecretRows(secretRows)
  secureClearAmeBytes(keys)
  secureClearAmeBytes(confirmKey)
  secureClearAmeBytes(confirmInfo)
  secureClearAmeBytes(nextKey)

proc fomkeUpgradeCommitsEqual*(a, b: FomkeUpgradeCommit): bool {.
    role: parser, tag: "appApi|exchange|fomke".} =
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
    role: parser, tag: "appApi|exchange|fomke|validation".} =
  ## S/c: pending local candidate and peer-confirmed commit.
  if not S.pending.active or not fomkeUpgradeCommitsEqual(S.pending.commit, c):
    raise newException(ValueError, "FOMKE upgrade confirmation mismatch")

proc confirmFomkeUpgrade*(S: var FomkeState, c: FomkeUpgradeCommit) {.
    role: actor, tag: "appApi|cryptoBoundary|exchange|fomke".} =
  ## S/c: state atomically replaced after exact authenticated confirmation.
  ## The new tier takes effect here and nowhere else, so the slot selection
  ## and the chain keys always change together.
  var
    lane1: FomkeChainState = default(FomkeChainState)
    lane2: FomkeChainState = default(FomkeChainState)
    tightKey: ByteSeq = @[]
    targetEpoch: uint32 = 0'u32
    targetTier: AmeMaskTier = default(AmeMaskTier)
  validateFomkeUpgrade(S, c)
  lane1 = cloneFomkeChain(S.pending.candidateLane1)
  lane2 = cloneFomkeChain(S.pending.candidateLane2)
  tightKey = copyFomkeBytes(S.pending.candidateTightKey)
  targetEpoch = S.pending.commit.targetEpoch
  targetTier = S.pending.commit.targetTier
  clearFomkeChain(S.lane1)
  clearFomkeChain(S.lane2)
  secureClearAmeBytes(S.tightKey)
  clearFomkeSkipped(S.skipped)
  clearFomkePending(S.pending)
  S.lane1 = lane1
  S.lane2 = lane2
  S.tightKey = move(tightKey)
  ## Jump numbers start again in every epoch: JK binds the epoch, so jump 0
  ## of this epoch and jump 0 of the last one are different keys.
  S.sendJumps = 0'u32
  S.recvJumps = 0'u32
  S.epoch = targetEpoch
  S.kdf = fomkeKdfFor(S, targetTier)
  S.tier = targetTier
  validateFomkeState(S)

proc cancelFomkeUpgrade*(S: var FomkeState) {.role: actor,
    tag: "appApi|cryptoBoundary|exchange|fomke".} =
  ## S: unconfirmed candidate erased while current chains remain unchanged.
  clearFomkePending(S.pending)

proc fomkeSkippedMessages*(S: FomkeState): int {.role: parser,
    tag: "appApi|fomke".} =
  ## S: how many jumped-over messages this side is still holding keys for.
  ## A caller watches this to decide when to give up on them.
  result = S.skipped.len

proc fomkeReorderWindow*(S: FomkeState): uint32 {.role: parser,
    tag: "appApi|fomke".} =
  ## S: how far out of order this lane is currently willing to accept a
  ## message. It is the reorder depth this lane has measured, plus headroom,
  ## so a transport that reports path statistics can read the number here
  ## instead of measuring the same thing a second time.
  result = S.reorderWindow

proc discardFomkeSkipped*(S: var FomkeState): int {.role: actor,
    tag: "appApi|cryptoBoundary|fomke".} =
  ## S: give up on every message that was jumped over, and say how many were
  ## given up on. Their keys are erased, so those messages can never be
  ## opened afterwards, even if they do turn up.
  ##
  ## This exists because two rules would otherwise trap a session on a lossy
  ## link forever:
  ##
  ##   1. a gap wider than `reorderWindow`, or a full cache, refuses the
  ##      message
  ##   2. a KEM upgrade refuses to run while any skipped key is outstanding
  ##
  ## A message that is lost for good is never taken out of the cache by
  ## anything else, so after enough permanent losses the session can neither
  ## receive across a gap nor rekey out of the state:
  ##
  ##   losses pile up ──▶ cache full ──▶ receive refuses
  ##          │                          upgrade refuses
  ##          ╰────── discardFomkeSkipped ──▶ both work again
  ##
  ## Calling this is the caller saying "those messages are not coming".
  ## Nothing calls it automatically, because only the caller knows whether a
  ## gap means a slow path or a dropped one.
  result = S.skipped.len
  clearFomkeSkipped(S.skipped)

proc fomkeHandshakeSecret*(S: FomkeState): ByteSeq {.role: truthBuilder,
    tag: "appApi|cryptoBoundary|fomke|kdf".} =
  ## S: the live ratchet whose carried secret (CS) is handed to the NEXT
  ## handshake.
  ##
  ## When a session ends and the two sides later run a fresh AM1P handshake,
  ## they can carry this into it (see `withAmeNextSecret`). It then keys the
  ## sealed hello and joins the new key schedule, so the new session needs
  ## the pre-shared key AND this -- a stolen pre-shared key alone no longer
  ## opens the next hello.
  ##
  ## One child of the tight key, like NK and JK, each under its own label --
  ## one secret doing two jobs is how a proof about one of them stops
  ## holding for the other:
  ##
  ##   TK ──XHKDF("FOMKE-NEXT-HANDSHAKE-v2", epoch)──▶ 32 bytes
  validateFomkeState(S)
  result = deriveFomkeTightChild(S, "FOMKE-NEXT-HANDSHAKE-v2")
