## -------------------------------------------------------------------------
## AME Session <- immutable-layout mask-tier epochs, sealed into frames
## -------------------------------------------------------------------------
##
## This module owns the epoch state machine and turns payloads into sealed
## frames for either carrier. It deliberately opens no socket: the two
## carrier modules under `level2/carriers/` do that, so a build keeps only
## the network stack it uses. See `protocols/ame` for the build flags.

import protocols/containers/circ_seq as circ_seq

import ../../types
import ../../transport/types as transport_types
import ../types
import ../level0/bytes
import ../level1/exchange_paths
import ../level1/suites
import ../level1/path_triggers
import ./protection
import ./wire
import ../../fomke/types
import ../../fomke/level0/gb3hkdf
import ../../fomke/level1/chain
import ../../fomke/level2/wire
import ../../config
import ../../dac/types
import ../../dac/level0/framing
import ../../../analysis_pragmas

const
  ameRetiringGraceFrames* = 100
    ## Frames the previous epoch stays openable after a rotation, so packets
    ## already in flight under the old keys are not dropped.

type
  AmeSession* {.role: truthState.} = object
    auth*: AmeAuthPackage
    path*: AmeTierPath
    sessionId*: uint64
    rootLaneId*: uint32
    parentLaneId*: uint32
    laneId*: uint32
    nextAmeSequence*: uint32
    messageClass*: AmeMessageClass
    pathLane*: DacPathLane
    peerTrustRequired*: bool
    peerTrust*: AmePeerTrustResult
    inbox*: circ_seq.CircSeq[AmePacket]
    lastTrigger*: AmeTierStep
    nextExchangeRequestId*: uint32
    pendingExchange*: AmePendingExchange
    pendingIncoming*: AmePendingIncomingExchange
    fomkeEnabled*: bool
    fomke*: FomkeState
    fomkePregenerationEnabled*: bool
    fomkePregenerationMessages*: int
    fomkePregenerationPayloadBytes*: int
    fomkeSendCache*: FomkeSendCache
    tcpRecvSequence*: uint32
    dacAmeReplay*: AmeReplayWindow
    pendingParams*: AmeRuntimeParams

    lastErr*: string

  AmeSendRollback {.role: memory.} = object
    nextAmeSequence: uint32
    path: AmeTierPath
    lastTrigger: AmeTierStep

proc copyBytes(A: openArray[uint8]): ByteSeq {.role: helper.} =
  ## A: source bytes copied into owned storage.
  result = @A

proc readU16(A: openArray[uint8], o: int): uint16 {.role: parser.} =
  ## A/o: source bytes and little-endian offset.
  result = uint16(A[o]) or (uint16(A[o + 1]) shl 8)

proc readU32(A: openArray[uint8], o: int): uint32 {.role: parser.} =
  ## A/o: source bytes and little-endian offset.
  result = uint32(A[o]) or (uint32(A[o + 1]) shl 8) or
    (uint32(A[o + 2]) shl 16) or (uint32(A[o + 3]) shl 24)

proc requireEpoch(E: AmeEpochKeySet) {.role: parser.} =
  ## E: exact epoch state required for data protection.
  if E.epochId == 0'u32:
    raise newException(ValueError, "AME epoch id must be positive")
  if E.exchange.activeMask == 0'u8:
    raise newException(ValueError, "AME epoch has no active KEM slot")
  if not kemLayoutsEquivalent(E.layout.kems, E.exchange.algorithms):
    raise newException(ValueError, "AME epoch layout and KEM state differ")
  validateAmeTier(E.layout, E.tier)
  if (E.tier.masks.kem and not E.exchange.activeMask) != 0'u8:
    raise newException(ValueError, "AME epoch tier lacks an active KEM secret")

proc clearExchangeState(E: var AmeExchangeState) {.role: stateController.} =
  ## E: exchange state whose secret slots are overwritten.
  var
    i: int = 0
  while i < ameMaxAlgorithmSlots:
    secureClearAmeBytes(E.sharedSecrets[i])
    i = i + 1
  E = default(AmeExchangeState)

proc clearEpoch(E: var AmeEpochKeySet) {.role: stateController.} =
  ## E: epoch whose exchange secrets and transcript salt are cleared.
  clearExchangeState(E.exchange)
  secureClearAmeBytes(E.transcriptSalt)
  E = default(AmeEpochKeySet)

proc clearSignatureSecretKeys(K: var seq[ByteSeq]) {.
    role: stateController.} =
  ## K: complete identity signature private-key stack to erase.
  var
    i: int = 0
  while i < K.len:
    secureClearAmeBytes(K[i])
    i = i + 1
  K.setLen(0)

proc clearPendingExchange(P: var AmePendingExchange) {.
    role: stateController.} =
  ## P: outgoing exchange whose private keys are cleared.
  var
    i: int = 0
  while i < P.secretKeys.len:
    secureClearAmeBytes(P.secretKeys[i])
    i = i + 1
  P = default(AmePendingExchange)

proc cloneExchangeState(E: AmeExchangeState): AmeExchangeState {.
    role: helper.} =
  ## E: exchange state copied without sharing secret byte storage.
  var
    i: int = 0
  result.algorithms = E.algorithms
  result.activeMask = E.activeMask
  result.generation = E.generation
  while i < ameMaxAlgorithmSlots:
    result.sharedSecrets[i] = copyBytes(E.sharedSecrets[i])
    i = i + 1

proc cloneEpoch(E: AmeEpochKeySet): AmeEpochKeySet {.role: helper.} =
  ## E: epoch copied without sharing secret or transcript byte storage.
  result.epochId = E.epochId
  result.layout = E.layout
  result.tier = E.tier
  result.exchange = cloneExchangeState(E.exchange)
  result.transcriptSalt = copyBytes(E.transcriptSalt)

proc requireAmeAuth*(a: AmeAuthPackage) {.role: parser.} =
  ## a: exact current and optional retiring epoch state.
  requireEpoch(a.current)
  if a.retiring.epochId == 0'u32:
    return
  if a.retiring.epochId >= a.current.epochId:
    raise newException(ValueError, "AME retiring epoch must be older")
  requireEpoch(a.retiring)

proc initAmeAuthPackage*(L: AmeSuiteLayout, t: AmeMaskTier,
    E: AmeExchangeState, transcriptSalt: openArray[uint8] = [],
    epochId: uint32 = 1'u32, sessionId: uint64 = 1'u64,
    endpointRole: AmeEndpointRole = aerInitiator,
    params: AmeRuntimeParams = AmeRuntimeParams(authTagLen: aatl32)):
    AmeAuthPackage {.role: wrapper.} =
  ## L/t/E/transcriptSalt/epoch/session/role: exact initial epoch inputs.
  ## params: tunables both endpoints must hold identically. They are bound
  ## into every tag, so a peer with different values fails authentication
  ## rather than silently disagreeing.
  if sessionId == 0'u64:
    raise newException(ValueError, "AME auth session id must be positive")
  result.current.epochId = epochId
  result.current.layout = L
  result.current.tier = t
  result.current.exchange = E
  result.current.transcriptSalt = copyBytes(transcriptSalt)
  result.retiringFramesLeft = 0
  result.sessionId = sessionId
  result.endpointRole = endpointRole
  result.current.params = params
  requireAmeAuth(result)

proc outboundAmeDirection*(r: AmeEndpointRole): AmeTrafficDirection {.
    role: parser.} =
  ## r: local endpoint role mapped to its global send direction.
  if r == aerInitiator:
    return atdInitiatorToResponder
  result = atdResponderToInitiator

proc inboundAmeDirection*(r: AmeEndpointRole): AmeTrafficDirection {.
    role: parser.} =
  ## r: local endpoint role mapped to its global receive direction.
  if r == aerInitiator:
    return atdResponderToInitiator
  result = atdInitiatorToResponder

proc ameEpochKeyContext*(E: AmeEpochKeySet, sessionId: uint64,
    direction: AmeTrafficDirection): ByteSeq {.role: truthBuilder.} =
  ## E/sessionId/direction: authenticated channel and global traffic direction.
  if E.epochId == 0'u32 or sessionId == 0'u64:
    raise newException(ValueError, "AME traffic key context is incomplete")
  appendAmeLabel(result, "AME-TRAFFIC-CONTEXT-v1")
  appendAmeU64(result, sessionId)
  appendAmeU32(result, E.epochId)
  result.add(uint8(ord(direction)))
  appendAmeU32(result, uint32(E.transcriptSalt.len))
  appendAmeBytes(result, E.transcriptSalt)

proc rotateAmeTier*(S: var AmeSession, r: AmeExchangeRequest,
    sharedSecrets: openArray[ByteSeq], transcriptSalt: openArray[uint8]) {.
    role: stateController.} =
  ## S/r/sharedSecrets/transcriptSalt: atomic authenticated epoch rotation.
  var
    next: AmeEpochKeySet = cloneEpoch(S.auth.current)
  if S.fomkeEnabled:
    clearFomkeSendCache(S.fomkeSendCache)
  if S.auth.current.epochId == high(uint32):
    raise newException(ValueError, "AME epoch id is exhausted")
  validateAmeTierTransition(next.layout, next.tier, r.targetTier,
    r.exchangeMask, next.exchange.activeMask)
  applyAmeExchange(next.exchange, r, sharedSecrets)
  next.tier = r.targetTier
  next.params = r.params
  next.epochId = S.auth.current.epochId + 1'u32
  secureClearAmeBytes(next.transcriptSalt)
  next.transcriptSalt = copyBytes(transcriptSalt)
  clearEpoch(S.auth.retiring)
  S.auth.retiring = cloneEpoch(S.auth.current)
  S.auth.retiringFramesLeft = ameRetiringGraceFrames
  S.auth.current = next
  requireAmeAuth(S.auth)

proc transitionTranscriptSalt(E: AmeEpochKeySet, o: AmeExchangeOffer,
    r: AmeExchangeReply): ByteSeq {.role: truthBuilder.} =
  ## E/o/r: previous channel binding and complete signed KEM transaction.
  var
    transcript: ByteSeq = @[]
  appendAmeLabel(transcript, "AME-EPOCH-TRANSITION-v1")
  appendAmeU32(transcript, uint32(E.transcriptSalt.len))
  appendAmeBytes(transcript, E.transcriptSalt)
  appendAmeU32(transcript, uint32(encodeAmeExchangeOffer(o).len))
  appendAmeBytes(transcript, encodeAmeExchangeOffer(o))
  appendAmeU32(transcript, uint32(encodeAmeExchangeReply(r).len))
  appendAmeBytes(transcript, encodeAmeExchangeReply(r))
  result = hashAmeTier(E.layout, r.request.targetTier, transcript, 32)

proc enableAmeFomke*(S: var AmeSession, role: FomkeRole,
    initialSlot: int, context: openArray[uint8] = [],
    kdf: Gb3KdfConfig = initGb3KdfConfig(),
    maxSkip: uint32 = fomkeDefaultMaxSkip,
    messageCipher: FomkeMessageCipher = fmcTmeAead) {.
    role: stateController,
    tag: {tagAppApi, tagCryptoBoundary, tagFomke, tagProtocol}.} =
  ## S/role/initialSlot: AME connection, endpoint direction, and initial KEM.
  ## context/kdf/maxSkip/messageCipher: transcript, work, gap, and inner AEAD.
  var
    c: BifrostConfig
  if S.auth.current.epochId != 1'u32:
    raise newException(ValueError, "AME FOMKE must be enabled at epoch 1")
  if S.fomkeEnabled:
    raise newException(ValueError, "AME FOMKE is already enabled")
  if (S.auth.endpointRole == aerInitiator and role != frInitiator) or
      (S.auth.endpointRole == aerResponder and role != frResponder):
    raise newException(ValueError, "AME and FOMKE endpoint roles differ")
  if initialSlot < 0 or initialSlot >= int(S.auth.current.layout.kems.length) or
      not algorithmSlotSelected(S.auth.current.tier.masks.kem, initialSlot):
    raise newException(ValueError, "AME FOMKE initial slot is outside the active tier")
  S.fomke = initFomkeFromAme(S.auth.current.exchange, initialSlot, role,
    context, kdf, maxSkip, messageCipher)
  clearFomkeSendCache(S.fomkeSendCache)
  c = currentBifrostConfig()
  S.fomkePregenerationEnabled = fomkePregenerationEnabledFor(c, messageCipher)
  S.fomkePregenerationMessages = c.fomkePregenerationMessages
  S.fomkePregenerationPayloadBytes = c.fomkePregenerationPayloadBytes
  try:
    if S.fomkePregenerationEnabled:
      S.fomkeSendCache = prepareFomkeSendCache(S.fomke,
        S.fomkePregenerationMessages, S.fomkePregenerationPayloadBytes)
    S.fomkeEnabled = true
  except:
    clearFomkeSendCache(S.fomkeSendCache)
    clearFomkeState(S.fomke)
    S.fomkePregenerationEnabled = false
    raise

proc buildAmeFomkeSendCache*(S: AmeSession,
    messageCount: int = fomkeDefaultPreparedMessages,
    payloadBytes: int = fomkeDefaultPreparedPayloadBytes): FomkeSendCache {.
    role: truthBuilder,
    tag: {tagAppApi, tagCryptoBoundary, tagFomke, tagProtocol}.} =
  ## S/messageCount/payloadBytes: connection snapshot and future send capacity.
  var
    snapshot: FomkeState
  if not S.fomkeEnabled:
    raise newException(ValueError, "AME FOMKE is not enabled")
  snapshot = cloneFomkeState(S.fomke)
  try:
    result = prepareFomkeSendCache(snapshot, messageCount, payloadBytes)
    clearFomkeState(snapshot)
  except:
    clearFomkeState(snapshot)
    raise

proc snapshotAmeFomkeSendState*(S: AmeSession): FomkeState {.
    role: helper,
    tag: {tagAppApi, tagCryptoBoundary, tagFomke, tagProtocol}.} =
  ## S: connection copied deeply under its caller-owned synchronization lock.
  if not S.fomkeEnabled:
    raise newException(ValueError, "AME FOMKE is not enabled")
  result = cloneFomkeState(S.fomke)

proc installAmeFomkeSendCache*(S: var AmeSession,
    C: var FomkeSendCache): bool {.role: stateController,
    tag: {tagAppApi, tagCryptoBoundary, tagFomke, tagProtocol}.} =
  ## S/C: live connection and caller-owned cache built from a prior snapshot.
  if not S.fomkeEnabled or not S.fomkePregenerationEnabled or
      not fomkeSendCacheMatches(S.fomke, C):
    clearFomkeSendCache(C)
    return
  clearFomkeSendCache(S.fomkeSendCache)
  S.fomkeSendCache = move(C)
  result = true

proc prepareAmeFomkeSendCache*(S: var AmeSession,
    messageCount: int = fomkeDefaultPreparedMessages,
    payloadBytes: int = fomkeDefaultPreparedPayloadBytes) {.
    role: orchestrator,
    tag: {tagAppApi, tagCryptoBoundary, tagFomke, tagProtocol}.} =
  ## S/messageCount/payloadBytes: synchronously build and install future slots.
  var
    C: FomkeSendCache
  C = buildAmeFomkeSendCache(S, messageCount, payloadBytes)
  S.fomkePregenerationEnabled = true
  S.fomkePregenerationMessages = messageCount
  S.fomkePregenerationPayloadBytes = payloadBytes
  if not installAmeFomkeSendCache(S, C):
    raise newException(ValueError, "AME FOMKE send state changed during prepare")

proc setAmeFomkePregeneration*(S: var AmeSession, enabled: bool,
    messageCount: int = fomkeDefaultPreparedMessages,
    payloadBytes: int = fomkeDefaultPreparedPayloadBytes) {.
    role: stateController,
    tag: {tagAppApi, tagCryptoBoundary, tagFomke, tagProtocol}.} =
  ## S/enabled/messageCount/payloadBytes: per-connection policy override.
  var
    C: FomkeSendCache
  if not S.fomkeEnabled:
    raise newException(ValueError, "AME FOMKE is not enabled")
  if enabled:
    C = buildAmeFomkeSendCache(S, messageCount, payloadBytes)
  clearFomkeSendCache(S.fomkeSendCache)
  S.fomkePregenerationEnabled = enabled
  S.fomkePregenerationMessages = messageCount
  S.fomkePregenerationPayloadBytes = payloadBytes
  if enabled:
    S.fomkeSendCache = move(C)

proc ameFomkeSendCacheNeedsRefill*(S: AmeSession): bool {.role: parser,
    tag: {tagAppApi, tagCryptoBoundary, tagFomke, tagProtocol}.} =
  ## S: connection whose configured cache has fallen below half capacity.
  var
    remaining: int = fomkePreparedMessages(S.fomkeSendCache)
    threshold: int = S.fomkePregenerationMessages div 2
  if threshold < 1:
    threshold = 1
  result = S.fomkeEnabled and S.fomkePregenerationEnabled and
    not S.fomke.pending.active and remaining <= threshold

proc restoreConfiguredAmeFomkeCache(S: var AmeSession) {.
    role: stateController,
    tag: {tagCryptoBoundary, tagFomke, tagProtocol}.} =
  ## S: quiescent configured connection whose cache is rebuilt off data paths.
  clearFomkeSendCache(S.fomkeSendCache)
  if S.fomkeEnabled and S.fomkePregenerationEnabled and
      not S.fomke.pending.active:
    S.fomkeSendCache = prepareFomkeSendCache(S.fomke,
      S.fomkePregenerationMessages, S.fomkePregenerationPayloadBytes)

proc disableAmeFomke*(S: var AmeSession) {.role: stateController,
    tag: {tagAppApi, tagCryptoBoundary, tagFomke, tagProtocol}.} =
  ## S: AME connection whose forward-only message state is erased.
  clearFomkeSendCache(S.fomkeSendCache)
  clearFomkeState(S.fomke)
  S.fomkeEnabled = false
  S.fomkePregenerationEnabled = false

proc clearAmeSession*(S: var AmeSession) {.role: stateController,
    tag: {tagAppApi, tagCryptoBoundary, tagProtocol}.} =
  ## S: current, retiring, pending AME, and optional FOMKE secrets to erase.
  clearEpoch(S.auth.current)
  clearEpoch(S.auth.retiring)
  clearSignatureSecretKeys(S.auth.localSignatureSecretKeys)
  S.auth.peerSignaturePublicKeys.setLen(0)
  clearPendingExchange(S.pendingExchange)
  clearEpoch(S.pendingIncoming.candidate)
  clearFomkeSendCache(S.fomkeSendCache)
  if S.fomkeEnabled:
    clearFomkeState(S.fomke)
  S = default(AmeSession)

proc cancelAmeSessionExchange*(S: var AmeSession) {.role: stateController.} =
  ## S: outgoing exchange cancelled and trigger returned to the due queue.
  if S.path.inFlightTierId != 0'u32:
    releaseAmeTier(S.path)
  clearPendingExchange(S.pendingExchange)
  if S.fomkeEnabled:
    cancelFomkeUpgrade(S.fomke)
    restoreConfiguredAmeFomkeCache(S)
proc beginAmeSessionExchange*(S: var AmeSession,
    r: AmeExchangeRequest): AmeExchangeOffer {.role: orchestrator.} =
  ## S/r: connection, target tier, and exact fresh/rekey KEM slots.
  ## Only one epoch transition may be in flight in either direction. Starting
  ## an outgoing exchange while a peer candidate epoch is waiting would rotate
  ## both endpoints to the same epoch id from different key material, so a
  ## pending incoming exchange blocks here. See `answerAmeSessionExchange` for
  ## the tie-break that resolves a genuine simultaneous start.
  var
    r: AmeExchangeRequest = r
      ## Shadowed on purpose. The caller may hand a request built before the
      ## observer changed its mind, so the STAGED parameters always win and a
      ## value set through `setAmeAuthTagLen` reaches the peer on the very
      ## next exchange without the caller having to rebuild anything.
    keys: AmeExchangeKeys
    step: AmeTierStep
    signatureTier: AmeMaskTier
    targetIndex: int = 0
  r.params = S.pendingParams
  if S.pendingExchange.active:
    raise newException(ValueError, "AME already has a pending exchange")
  if S.pendingIncoming.active:
    raise newException(ValueError,
      "AME cannot start an exchange while a peer candidate epoch is pending")
  if not ameTierPathAllowsTransition(S.path, S.auth.current.tier,
      r.targetTier):
    raise newException(ValueError, "AME target tier is outside the session path")
  validateAmeTierTransition(S.auth.current.layout, S.auth.current.tier,
    r.targetTier, r.exchangeMask, S.auth.current.exchange.activeMask)
  if S.path.inFlightTierId != 0'u32:
    raise newException(ValueError, "AME tier transition is already in flight")
  S.nextExchangeRequestId = S.nextExchangeRequestId + 1'u32
  if S.nextExchangeRequestId == 0'u32:
    S.nextExchangeRequestId = 1'u32
  keys = generateAmeExchangeKeys(S.auth.current.layout.kems, r)
  result = initAmeExchangeOffer(S.nextExchangeRequestId,
    S.auth.current.epochId, r, keys.publicKeys)
  signatureTier = transitionAmeSignatureTier(S.auth.current.layout,
    S.auth.current.tier, r.targetTier)
  result.signatures = signAmeTier(S.auth.current.layout, signatureTier,
    encodeAmeExchangeOfferSubject(result), activeAmeSignatureKeys(
      S.auth.current.layout, signatureTier,
      S.auth.localSignatureSecretKeys))
  S.pendingExchange.active = true
  S.pendingExchange.offer = result
  S.pendingExchange.secretKeys = keys.secretKeys
  step.available = true
  step.targetTier = r.targetTier
  step.exchangeMask = r.exchangeMask
  step.request = r
  while targetIndex < int(S.path.tierCount):
    if tiersEquivalent(S.path.tiers[targetIndex], r.targetTier) and
        algorithmSlotSelected(S.path.dueMask, targetIndex):
      claimAmeTier(S.path, step)
      break
    targetIndex = targetIndex + 1

proc answerAmeSessionExchange*(S: var AmeSession, o: AmeExchangeOffer):
    AmeExchangeReply {.role: orchestrator.} =
  ## S/o: peer connection and received offer; applies sender-side secrets.
  ## Cheap state guards run before any signature work so that replayed offers
  ## on a busy session cannot force repeated post-quantum verifications.
  ## When both endpoints start an exchange at the same time the roles decide:
  ## the responder drops its own outgoing exchange and answers, the initiator
  ## keeps its own and rejects the offer. Both endpoints therefore converge on
  ## the initiator's transition instead of rotating to divergent epochs.
  var
    answer: tuple[reply: AmeExchangeReply, sharedSecrets: seq[ByteSeq]]
    signatureTier: AmeMaskTier
  if S.pendingIncoming.active:
    raise newException(ValueError, "AME already has an incoming exchange")
  if S.auth.current.epochId == high(uint32):
    raise newException(ValueError, "AME epoch id is exhausted")
  if S.pendingExchange.active:
    if S.auth.endpointRole == aerInitiator:
      raise newException(ValueError,
        "AME initiator keeps its own exchange during a simultaneous start")
    cancelAmeSessionExchange(S)
  if o.baseEpochId != S.auth.current.epochId:
    raise newException(ValueError, "AME exchange offer base epoch mismatch")
  if not ameTierPathAllowsTransition(S.path, S.auth.current.tier,
      o.request.targetTier):
    raise newException(ValueError, "AME target tier is outside the session path")
  validateAmeTierTransition(S.auth.current.layout, S.auth.current.tier,
    o.request.targetTier, o.request.exchangeMask,
    S.auth.current.exchange.activeMask)
  signatureTier = transitionAmeSignatureTier(S.auth.current.layout,
    S.auth.current.tier, o.request.targetTier)
  if not verifyAmeTier(S.auth.current.layout, signatureTier,
      encodeAmeExchangeOfferSubject(o), activeAmeSignatureKeys(
        S.auth.current.layout, signatureTier,
        S.auth.peerSignaturePublicKeys), o.signatures):
    raise newException(ValueError, "AME exchange offer signature stack is invalid")
  answer = answerAmeExchangeOffer(S.auth.current.layout.kems, o)
  answer.reply.signatures = signAmeTier(S.auth.current.layout, signatureTier,
    encodeAmeExchangeReplySubject(o, answer.reply),
    activeAmeSignatureKeys(S.auth.current.layout, signatureTier,
      S.auth.localSignatureSecretKeys))
  S.pendingIncoming.active = true
  S.pendingIncoming.requestId = o.requestId
  S.pendingIncoming.request = o.request
  S.pendingIncoming.candidate = cloneEpoch(S.auth.current)
  applyAmeExchange(S.pendingIncoming.candidate.exchange, o.request,
    answer.sharedSecrets)
  S.pendingIncoming.candidate.tier = o.request.targetTier
  S.pendingIncoming.candidate.params = o.request.params
  S.pendingParams = o.request.params
  S.pendingIncoming.candidate.epochId = S.auth.current.epochId + 1'u32
  secureClearAmeBytes(S.pendingIncoming.candidate.transcriptSalt)
  S.pendingIncoming.candidate.transcriptSalt = transitionTranscriptSalt(
    S.auth.current, o, answer.reply)
  if S.fomkeEnabled:
    clearFomkeSendCache(S.fomkeSendCache)
    discard prepareFomkeUpgrade(S.fomke, o.requestId,
      S.pendingIncoming.candidate.epochId, o.request,
      S.pendingIncoming.candidate.exchange)
  result = answer.reply

proc finishAmeSessionExchange*(S: var AmeSession, r: AmeExchangeReply) {.
    role: orchestrator.} =
  ## S/r: initiating connection and matching reply.
  var
    secrets: seq[ByteSeq] = @[]
    candidate: AmeEpochKeySet
    signatureTier: AmeMaskTier
    transcriptSalt: ByteSeq = @[]
  if not S.pendingExchange.active:
    raise newException(ValueError, "AME session has no pending exchange")
  if S.pendingExchange.offer.baseEpochId != S.auth.current.epochId:
    raise newException(ValueError, "AME pending exchange base epoch changed")
  signatureTier = transitionAmeSignatureTier(S.auth.current.layout,
    S.auth.current.tier, r.request.targetTier)
  if not verifyAmeTier(S.auth.current.layout, signatureTier,
      encodeAmeExchangeReplySubject(S.pendingExchange.offer, r),
      activeAmeSignatureKeys(S.auth.current.layout, signatureTier,
        S.auth.peerSignaturePublicKeys), r.signatures):
    raise newException(ValueError, "AME exchange reply signature stack is invalid")
  secrets = openAmeExchangeReply(S.auth.current.layout.kems,
    S.pendingExchange.offer, r,
    S.pendingExchange.secretKeys)
  transcriptSalt = transitionTranscriptSalt(S.auth.current,
    S.pendingExchange.offer, r)
  if S.fomkeEnabled:
    clearFomkeSendCache(S.fomkeSendCache)
    candidate = cloneEpoch(S.auth.current)
    applyAmeExchange(candidate.exchange, r.request, secrets)
    candidate.tier = r.request.targetTier
    candidate.epochId = S.auth.current.epochId + 1'u32
    discard prepareFomkeUpgrade(S.fomke, r.requestId, candidate.epochId,
      r.request, candidate.exchange)
    clearEpoch(candidate)
  rotateAmeTier(S, r.request, secrets, transcriptSalt)
  if S.path.inFlightTierId == r.request.targetTier.tierId:
    completeAmeTier(S.path, r.request.targetTier)
  else:
    setCurrentAmeTier(S.path, r.request.targetTier)
  clearPendingExchange(S.pendingExchange)

proc confirmAmeSessionExchange*(S: var AmeSession, requestId,
    epochId: uint32, targetTier: AmeMaskTier,
    fomkeCommit: FomkeUpgradeCommit = default(FomkeUpgradeCommit)) {.
    role: stateController.} =
  ## S/requestId/epochId/targetTier/fomkeCommit: authenticated candidate identity.
  if not S.pendingIncoming.active or
      S.pendingIncoming.requestId != requestId or
       S.pendingIncoming.candidate.epochId != epochId or
       not tiersEquivalent(S.pendingIncoming.request.targetTier, targetTier) or
       not tiersEquivalent(S.pendingIncoming.candidate.tier, targetTier):
    raise newException(ValueError, "AME epoch-ready confirmation mismatch")
  if S.fomkeEnabled:
    validateFomkeUpgrade(S.fomke, fomkeCommit)
  elif fomkeCommit.confirmationTag.len != 0:
    raise newException(ValueError, "AME received unexpected FOMKE confirmation")
  clearEpoch(S.auth.retiring)
  S.auth.retiring = cloneEpoch(S.auth.current)
  S.auth.retiringFramesLeft = ameRetiringGraceFrames
  S.auth.current = S.pendingIncoming.candidate
  S.pendingIncoming = default(AmePendingIncomingExchange)
  setCurrentAmeTier(S.path, targetTier)
  if S.fomkeEnabled:
    confirmFomkeUpgrade(S.fomke, fomkeCommit)
    restoreConfiguredAmeFomkeCache(S)
  requireAmeAuth(S.auth)

proc cancelIncomingAmeSessionExchange*(S: var AmeSession) {.
    role: stateController.} =
  ## S: incoming candidate epoch discarded before confirmation.
  clearEpoch(S.pendingIncoming.candidate)
  S.pendingIncoming = default(AmePendingIncomingExchange)
  if S.fomkeEnabled:
    cancelFomkeUpgrade(S.fomke)
    restoreConfiguredAmeFomkeCache(S)

proc amePeerTrustError*(S: AmeSession): string {.role: parser.} =
  ## S: connection whose trust gate is checked.
  if not S.peerTrustRequired or S.peerTrust.ok:
    return ""
  if S.peerTrust.err.len > 0:
    return "AME peer trust not established: " & S.peerTrust.err
  result = "AME peer trust not established"

proc requireAmePeerTrust*(S: AmeSession) {.role: parser.} =
  ## S: connection whose required trust must be present.
  var err: string = amePeerTrustError(S)
  if err.len > 0:
    raise newException(ValueError, err)

proc initAmeSession*(a: AmeAuthPackage,
    path: AmeTierPath, sessionId: uint64 = 0'u64,
    rootLaneId: uint32 = 1'u32, laneId: uint32 = 5'u32,
    pathLane: DacPathLane = dplCleanPath,
    messageClass: AmeMessageClass = amcUserdata,
    inboxCapacity: int = defaultAmeInboxCapacity,
    peerTrustRequired: bool = true,
    peerTrust: AmePeerTrustResult = default(AmePeerTrustResult)):
    AmeSession {.role: wrapper.} =
  ## a/path/session/lane/runtime: exact connection configuration.
  if inboxCapacity < 0:
    raise newException(ValueError, "AME inbox capacity must not be negative")
  requireAmeAuth(a)
  if a.sessionId == 0'u64:
    raise newException(ValueError, "AME authenticated session id is missing")
  if a.current.transcriptSalt.len > 0 and sessionId != 0'u64 and
      sessionId != a.sessionId:
    raise newException(ValueError,
      "AME live session id differs from the authenticated session")
  if not layoutsEquivalent(a.current.layout, path.layout):
    raise newException(ValueError, "AME tier path layout differs from auth layout")
  result.auth = a
  result.pendingParams = a.current.params
  if sessionId != 0'u64:
    result.auth.sessionId = sessionId
  result.path = path
  result.sessionId = result.auth.sessionId
  result.rootLaneId = rootLaneId
  result.parentLaneId = rootLaneId
  result.laneId = laneId
  result.pathLane = pathLane
  result.messageClass = messageClass
  result.peerTrustRequired = peerTrustRequired
  result.peerTrust = peerTrust
  result.inbox = circ_seq.initCircSeq[AmePacket](inboxCapacity)
  setCurrentAmeTier(result.path, result.auth.current.tier)

proc initAmeSession*(a: AmeAuthPackage,
    sessionId: uint64 = 0'u64, rootLaneId: uint32 = 1'u32,
    laneId: uint32 = 5'u32, pathLane: DacPathLane = dplCleanPath,
    messageClass: AmeMessageClass = amcUserdata,
    inboxCapacity: int = defaultAmeInboxCapacity,
    peerTrustRequired: bool = true,
    peerTrust: AmePeerTrustResult = default(AmePeerTrustResult)):
    AmeSession {.role: wrapper.} =
  ## a/session/lane/runtime: exact auth package with default AME triggers.
  var path: AmeTierPath
  path = initAmeTierPath(a.current.layout, [a.current.tier])
  result = initAmeSession(a, path, sessionId, rootLaneId, laneId, pathLane,
    messageClass, inboxCapacity, peerTrustRequired, peerTrust)

proc pending*(S: AmeSession): int {.role: parser.} =
  ## S: connection whose parsed inbox count is returned.
  result = circ_seq.len(S.inbox)

proc inboxCapacity*(S: AmeSession): int {.role: parser.} =
  ## S: connection whose inbox capacity is returned.
  result = circ_seq.capacity(S.inbox)

proc recv*(S: var AmeSession, p: var AmePacket): bool {.
    role: stateController.} =
  ## S/p: connection inbox and destination packet.
  result = circ_seq.pop(S.inbox, p)

proc recordTransferredBytes*(S: var AmeSession, n: uint64): AmeTierStep {.
    role: stateController.} =
  ## S/n: connection and newly successful plaintext transfer bytes.
  result = feedTransferredBytes(S.path, n)
  S.lastTrigger = result

proc feedAmeElapsedMs*(S: var AmeSession, elapsedMs: uint64): AmeTierStep {.
    role: stateController.} =
  ## S/elapsedMs: connection and monotonic elapsed clock.
  result = feedElapsedMs(S.path, elapsedMs)
  S.lastTrigger = result

proc requestAmeTier*(S: var AmeSession, tierId: uint32,
    rekeyMask: uint8 = 0'u8): AmeTierStep {.
    role: stateController.} =
  ## S/tierId/rekeyMask: exact target tier and selected active KEM rekeys.
  result = requestTier(S.path, tierId, rekeyMask)
  S.lastTrigger = result

## ╭⟢ runtime parameters
##
## AME exposes its tunables here rather than holding a policy of its own.
## Something above it - the DAC observer, or a caller with its own opinion -
## writes them per connection. AME only enforces that both endpoints agree,
## which it gets for free by binding the values into every tag.

proc ameParams*(S: AmeSession): AmeRuntimeParams {.role: parser.} =
  ## S: session whose current epoch tunables are read back.
  result = S.auth.current.params

proc nextAmeParams*(S: AmeSession): AmeRuntimeParams {.role: parser.} =
  ## S: session whose STAGED tunables are read back. These are what the next
  ## exchange this endpoint initiates will ask the peer to adopt.
  result = S.pendingParams

proc setAmeAuthTagLen*(S: var AmeSession, n: AmeAuthTagLen) {.
    role: configurator.} =
  ## S/n: session and the tag length its next epoch should carry.
  ##
  ## Staged, not applied. A live epoch's tags are bound to the length it was
  ## created with, so switching underneath one would break every message
  ## until the peer caught up. The value rides in the next exchange request
  ## this endpoint sends; the responder adopts it, and both rotate together.
  ## Until then nothing changes on the wire.
  ##
  ## Shorter tags trade authentication strength for bytes. 32 is 256-bit and
  ## the default; 16 is the conventional 128-bit floor, worth it when a
  ## payload is a handful of bytes and the tag dominates the frame.
  S.pendingParams.authTagLen = n

proc info*(S: AmeSession): AmeSessionInfo {.role: wrapper.} =
  ## S: connection summarized by stable tier identity and masks.
  result.layoutBytes = encodeAmeSuiteLayout(S.auth.current.layout).len
  result.tierId = S.auth.current.tier.tierId
  result.tierMasks = S.auth.current.tier.masks
  result.activeKemMask = S.auth.current.exchange.activeMask
  result.epochId = S.auth.current.epochId
  result.sessionId = S.sessionId
  result.laneId = S.laneId
  result.pending = S.pending
  result.capacity = S.inboxCapacity
  result.transferredBytes = S.path.transferredBytes
  result.peerTrustRequired = S.peerTrustRequired
  result.peerTrusted = S.peerTrust.ok
  result.peerAuthority = S.peerTrust.authority

proc `$`*(i: AmeSessionInfo): string {.role: wrapper.} =
  ## i: mask-tier connection summary.
  result = "AME session=" & $i.sessionId & " lane=" & $i.laneId &
    " epoch=" & $i.epochId & " tier=" & $i.tierId &
    " activeMask=" & $i.activeKemMask &
    " layoutBytes=" & $i.layoutBytes & " transferred=" &
    $i.transferredBytes

proc envelopeLen(L: AmeSuiteLayout, t: AmeMaskTier, payloadLen: int,
    tagLen: AmeAuthTagLen): int {.role: helper.} =
  ## L/t/payloadLen/tagLen: selected tier, plaintext length, agreed tag size.
  result = ameProtectedBodyHeaderLen + ameProtectionNonceLen(L, t) +
    int(ord(tagLen)) + payloadLen

proc checkedEnvelopeLen(L: AmeSuiteLayout, t: AmeMaskTier,
    payloadLen: int, what: string,
    tagLen: AmeAuthTagLen = aatl32): uint32 {.role: parser.} =
  ## L/t/payloadLen/what: sealed envelope length checked before it is narrowed
  ## to the u32 wire field. Every seal path goes through here so that a large
  ## KEM stack (eight Classic-McEliece slots carry megabytes of public keys)
  ## cannot overflow the length field instead of failing closed.
  var
    n: int = envelopeLen(L, t, payloadLen, tagLen)
  if payloadLen < 0 or n > defaultAmeMaxFrameBytes - ameFrameHeaderLen:
    raise newException(ValueError, "AME " & what & " exceeds maximum")
  result = uint32(n)

proc ameInnerPayloadLen(S: AmeSession, payloadLen: int): int {.
    role: helper.} =
  ## S/payloadLen: optional FOMKE envelope length inside outer AME protection.
  if S.fomkeEnabled:
    return fomkeWireLen(payloadLen)
  result = payloadLen

proc buildAmeFomkeAad(S: AmeSession, carrier: AmeCarrier,
    ameSequence: uint32): ByteSeq {.role: truthBuilder,
    tag: {tagCryptoBoundary, tagFomke, tagProtocol}.} =
  ## S/carrier/ameSequence: stable AME identity bound into inner FOMKE
  ## protection. The label moved to v2 when the separate DAC sequence was
  ## dropped: on a DAC session it advanced in lockstep with the AME sequence,
  ## so it bound nothing the AME sequence did not already bind.
  appendAmeLabel(result, "AME-FOMKE-AAD-v2")
  result.add(uint8(ord(carrier)))
  appendAmeU64(result, S.sessionId)
  appendAmeU32(result, S.rootLaneId)
  appendAmeU32(result, S.parentLaneId)
  appendAmeU32(result, S.laneId)
  appendAmeU32(result, ameSequence)

proc sealAmeInnerPayload(S: var AmeSession, carrier: AmeCarrier,
    payload: openArray[uint8], ameSequence: uint32): ByteSeq {.
    role: orchestrator, tag: {tagCryptoBoundary, tagFomke, tagProtocol}.} =
  ## S/carrier/payload/ameSequence: optional forward-only inner message.
  var
    message: FomkeMessage
    aad: ByteSeq = @[]
  if not S.fomkeEnabled:
    return @payload
  aad = buildAmeFomkeAad(S, carrier, ameSequence)
  if fomkePreparedMessages(S.fomkeSendCache) > 0:
    message = sealFomkeMessagePrepared(S.fomke, S.fomkeSendCache,
      payload, aad)
  else:
    message = sealFomkeMessage(S.fomke, payload, aad)
  result = encodeFomkeMessage(message)
  secureClearAmeBytes(aad)

proc openAmeInnerPayload(S: var AmeSession, carrier: AmeCarrier,
    payload: openArray[uint8], ameSequence: uint32):
    FomkeOpenResult {.role: orchestrator,
    tag: {tagCryptoBoundary, tagFomke, tagProtocol}.} =
  ## S/carrier/payload/ameSequence: optional FOMKE envelope opened
  ## transactionally.
  var
    message: FomkeMessage
    aad: ByteSeq = @[]
  if not S.fomkeEnabled:
    result.ok = true
    result.payload = @payload
    return
  try:
    message = decodeFomkeMessage(payload)
    aad = buildAmeFomkeAad(S, carrier, ameSequence)
    result = openFomkeMessage(S.fomke, message, aad)
    secureClearAmeBytes(aad)
  except ValueError as exc:
    secureClearAmeBytes(aad)
    result.err = exc.msg

proc encodeAmeProtectedBody*(e: AmeProtectedBody): ByteSeq {.
    role: stateController.} =
  ## e: epoch-bound nonce, tag, and ciphertext (AME2 payload body).
  requireAmeU16Len(e.nonce.len, "AME nonce")
  requireAmeU16Len(e.authTag.len, "AME authentication tag")
  requireAmeU32Len(e.payload.len, "AME protected body payload")
  appendAmeU32(result, e.epochId)
  appendAmeU16(result, uint16(e.nonce.len))
  appendAmeU16(result, uint16(e.authTag.len))
  appendAmeU32(result, uint32(e.payload.len))
  appendAmeBytes(result, e.nonce)
  appendAmeBytes(result, e.authTag)
  appendAmeBytes(result, e.payload)

proc decodeAmeProtectedBody*(A: openArray[uint8]): AmeProtectedBody {.
    role: parser.} =
  ## A: AME2 payload = epoch | nonceLen | tagLen | cipherLen | nonce | tag | ct.
  var
    nonceLen: int = 0
    tagLen: int = 0
    payloadLen: int = 0
    offset: int = ameProtectedBodyHeaderLen
  if A.len < ameProtectedBodyHeaderLen:
    raise newException(ValueError, "AME protected body is truncated")
  result.epochId = readU32(A, 0)
  nonceLen = int(readU16(A, 4))
  tagLen = int(readU16(A, 6))
  payloadLen = checkedAmeWireLen(readU32(A, 8),
    uint32(defaultAmeMaxFrameBytes), "AME protected body payload")
  if result.epochId == 0'u32 or nonceLen <= 0 or
      tagLen notin {16, 24, 32} or
      A.len != offset + nonceLen + tagLen + payloadLen:
    raise newException(ValueError, "AME protected body length mismatch")
  result.nonce = @A[offset ..< offset + nonceLen]
  offset = offset + nonceLen
  result.authTag = @A[offset ..< offset + tagLen]
  offset = offset + tagLen
  result.payload = @A[offset ..< offset + payloadLen]

proc buildAad(carrier: AmeCarrier,
    h: AmeFrameHeader): ByteSeq {.role: truthBuilder.} =
  ## carrier/h: transport and AME metadata bound to protection.
  ## A DAC-carried frame used to bind a second header here as well. Every field
  ## in that header was already in the AME header beside it -- session, lane,
  ## sequence -- or was the protected epoch restated, so binding it twice only
  ## created a pair that could disagree. The AME header is the one identity.
  appendAmeLabel(result, "AME-AAD")
  result.add(uint8(ord(carrier)))
  appendAmeBytes(result, encodeAmeFrameHeader(h))

proc sealEnvelope(S: AmeSession, h: AmeFrameHeader, carrier: AmeCarrier,
    payload: openArray[uint8]): AmeProtectedBody {.role: orchestrator.} =
  ## S/h/carrier/payload: complete exact protection inputs.
  var
    context: ByteSeq = ameEpochKeyContext(S.auth.current, S.sessionId,
      outboundAmeDirection(S.auth.endpointRole))
    sealed = protectAmeMessage(S.auth.current.layout, S.auth.current.tier,
      S.auth.current.exchange, payload, buildAad(carrier, h), context,
      S.auth.current.params.authTagLen)
  result.epochId = S.auth.current.epochId
  result.nonce = sealed.nonce
  result.authTag = sealed.message.authTag
  result.payload = sealed.message.payload

proc sealAmeTcpFrame*(S: var AmeSession,
    payload: openArray[uint8]): ByteSeq {.role: orchestrator.} =
  ## S/payload: connection and plaintext; transfer accounting occurs after send.
  requireAmeAuth(S.auth)
  requireAmePeerTrust(S)
  if S.nextAmeSequence == high(uint32):
    raise newException(ValueError, "AME send sequence is exhausted")
  var
    innerLen: int = ameInnerPayloadLen(S, payload.len)
    inner: ByteSeq = @[]
    h = initAmeFrameHeader(ampkLaneData, S.messageClass, S.sessionId,
      S.rootLaneId, S.parentLaneId, S.laneId, S.nextAmeSequence,
      checkedEnvelopeLen(S.auth.current.layout, S.auth.current.tier, innerLen,
        "TCP payload", S.auth.current.params.authTagLen))
    e: AmeProtectedBody
  inner = sealAmeInnerPayload(S, acrTcp, payload, S.nextAmeSequence)
  e = sealEnvelope(S, h, acrTcp, inner)
  result = encodeAmeFrame(h, encodeAmeProtectedBody(e))
  secureClearAmeBytes(inner)
  S.nextAmeSequence = S.nextAmeSequence + 1'u32

proc sealAmeDacFrame*(S: var AmeSession,
    payload: openArray[uint8]): ByteSeq {.role: orchestrator.} =
  ## S/payload: connection and plaintext; caller accounts successful queue/send.
  ## The datagram is one AME frame. It used to carry a DAC header in front of
  ## that, 27 bytes restating the session, lane, epoch and a sequence that
  ## advanced in step with the AME one -- a second identity a receiver had to
  ## parse and reconcile before it could authenticate anything.
  requireAmeAuth(S.auth)
  requireAmePeerTrust(S)
  if S.nextAmeSequence == high(uint32):
    raise newException(ValueError, "AME DAC send sequence is exhausted")
  var
    innerLen: int = ameInnerPayloadLen(S, payload.len)
    h = initAmeFrameHeader(ampkLaneData, S.messageClass, S.sessionId,
      S.rootLaneId, S.parentLaneId, S.laneId, S.nextAmeSequence,
      checkedEnvelopeLen(S.auth.current.layout, S.auth.current.tier, innerLen,
        "DAC payload", S.auth.current.params.authTagLen))
    inner: ByteSeq = @[]
    e: AmeProtectedBody
  inner = sealAmeInnerPayload(S, acrDac, payload, S.nextAmeSequence)
  e = sealEnvelope(S, h, acrDac, inner)
  result = encodeAmeFrame(h, encodeAmeProtectedBody(e))
  secureClearAmeBytes(inner)
  S.nextAmeSequence = S.nextAmeSequence + 1'u32

proc openWithEpoch(E: AmeEpochKeySet, e: AmeProtectedBody,
    aad, keyContext: openArray[uint8]): tuple[ok: bool, payload: ByteSeq] {.
    role: orchestrator.} =
  ## E/e/aad: exact epoch, protected envelope, and metadata binding. The tag
  ## length comes from the epoch itself, so a retiring epoch keeps opening
  ## frames sealed under its own value after the current one has moved on.
  var message: AmeProtectedMessage
  if E.epochId != e.epochId:
    return
  if e.nonce.len != ameProtectionNonceLen(E.layout, E.tier):
    return
  message.payload = e.payload
  message.authTag = e.authTag
  result = openAmeMessage(E.layout, E.tier, E.exchange, e.nonce, message, aad,
    keyContext, E.params.authTagLen)

proc consumeRetiringGrace(S: var AmeSession) {.role: stateController.} =
  ## S: connection whose old epoch expires after authenticated frame progress.
  if S.auth.retiring.epochId == 0'u32:
    return
  if S.auth.retiringFramesLeft > 0:
    S.auth.retiringFramesLeft = S.auth.retiringFramesLeft - 1
  if S.auth.retiringFramesLeft > 0:
    return
  clearEpoch(S.auth.retiring)
  S.auth.retiringFramesLeft = 0

proc validateFrameBinding(S: AmeSession, f: AmeDecodedFrame,
    expected: AmePacketKind): string {.role: parser.} =
  ## S/f/expected: expected connection identity and the packet kind this path
  ## accepts. One header carries the identity now, so there is no second one to
  ## agree with.
  if f.header.packetKind != expected:
    return "AME expected lane data"
  if f.header.messageClass != S.messageClass or
      f.header.sessionId != S.sessionId or f.header.rootLaneId != S.rootLaneId or
      f.header.parentLaneId != S.parentLaneId or f.header.laneId != S.laneId:
    return "AME frame binding mismatch"

proc replayAccept(W: var AmeReplayWindow, sequence: uint32): bool {.
    role: stateController.} =
  ## W/sequence: bounded 64-packet replay window and authenticated sequence.
  var
    distance: uint32 = 0'u32
    bit: uint64 = 0'u64
  if not W.initialized:
    W.initialized = true
    W.highest = sequence
    W.bitmap = 1'u64
    return true
  if sequence > W.highest:
    distance = sequence - W.highest
    if distance >= 64'u32:
      W.bitmap = 1'u64
    else:
      W.bitmap = (W.bitmap shl int(distance)) or 1'u64
    W.highest = sequence
    return true
  distance = W.highest - sequence
  if distance >= 64'u32:
    return false
  bit = 1'u64 shl int(distance)
  if (W.bitmap and bit) != 0'u64:
    return false
  W.bitmap = W.bitmap or bit
  result = true

proc openDecoded(S: var AmeSession, f: AmeDecodedFrame,
    carrier: AmeCarrier,
    remoteDac: DacAddress = default(DacAddress),
    remoteTcp: transport_types.TcpAddress = default(transport_types.TcpAddress)):
    AmeOpenResult {.role: orchestrator.} =
  ## S/f/carrier/remote: complete receive inputs.
  var
    err: string = amePeerTrustError(S)
    e: AmeProtectedBody
    opened: tuple[ok: bool, payload: ByteSeq]
    fomkeOpened: FomkeOpenResult
    aad: ByteSeq = @[]
    currentContext: ByteSeq = @[]
    retiringContext: ByteSeq = @[]
  if err.len == 0:
    err = validateFrameBinding(S, f, ampkLaneData)
  if err.len > 0:
    result.err = err
    S.lastErr = err
    return
  e = decodeAmeProtectedBody(f.payload)
  aad = buildAad(carrier, f.header)
  currentContext = ameEpochKeyContext(S.auth.current, S.sessionId,
    inboundAmeDirection(S.auth.endpointRole))
  opened = openWithEpoch(S.auth.current, e, aad, currentContext)
  if not opened.ok and S.auth.retiring.epochId != 0'u32:
    retiringContext = ameEpochKeyContext(S.auth.retiring, S.sessionId,
      inboundAmeDirection(S.auth.endpointRole))
    opened = openWithEpoch(S.auth.retiring, e, aad, retiringContext)
  if not opened.ok:
    result.err = "AME authentication failed"
    S.lastErr = result.err
    return
  if carrier == acrTcp and f.header.sequence != S.tcpRecvSequence:
    result.err = "AME receive sequence mismatch"
    S.lastErr = result.err
    return
  if carrier == acrDac and not replayAccept(S.dacAmeReplay,
      f.header.sequence):
    result.err = "AME replay rejected"
    S.lastErr = result.err
    return
  fomkeOpened = openAmeInnerPayload(S, carrier, opened.payload,
    f.header.sequence)
  if not fomkeOpened.ok:
    result.err = "AME FOMKE open failed: " & fomkeOpened.err
    S.lastErr = result.err
    return
  result.ok = true
  result.packet.payload = fomkeOpened.payload
  result.packet.carrier = carrier
  result.packet.remoteDac = remoteDac
  result.packet.remoteTcp = remoteTcp
  result.packet.sessionId = f.header.sessionId
  result.packet.rootLaneId = f.header.rootLaneId
  result.packet.parentLaneId = f.header.parentLaneId
  result.packet.laneId = f.header.laneId
  result.packet.ameSequence = f.header.sequence
  if carrier == acrDac:
    result.packet.dacSequence = f.header.sequence
  else:
    if S.tcpRecvSequence == high(uint32):
      result.ok = false
      result.err = "AME TCP receive sequence is exhausted"
      S.lastErr = result.err
      return
    S.tcpRecvSequence = S.tcpRecvSequence + 1'u32
  consumeRetiringGrace(S)
  circ_seq.push(S.inbox, result.packet)
  S.lastErr = ""

proc openAmeTcpFrame*(S: var AmeSession, frame: openArray[uint8],
    remote: transport_types.TcpAddress = default(transport_types.TcpAddress)):
    AmeOpenResult {.role: orchestrator.} =
  ## S/frame/remote: TCP-carried AME2 frame.
  result = openDecoded(S, decodeAmeFrame(frame), acrTcp,
    remoteTcp = remote)

proc openAmeDacFrame*(S: var AmeSession, frame: openArray[uint8],
    remote: DacAddress = default(DacAddress)):
    AmeOpenResult {.role: orchestrator.} =
  ## S/frame/remote: DAC-carried AME2 frame. The datagram is the AME frame
  ## itself; there is no outer header to strip or to disagree with it.
  result = openDecoded(S, decodeAmeFrame(frame), acrDac, remoteDac = remote)

proc sealControlFrame(S: var AmeSession, kind: AmePacketKind,
    carrier: AmeCarrier, payload: openArray[uint8]): ByteSeq {.
    role: orchestrator.} =
  ## S/kind/carrier/payload: authenticated AME control message.
  var
    h: AmeFrameHeader
    e: AmeProtectedBody
  requireAmeAuth(S.auth)
  requireAmePeerTrust(S)
  if kind notin {ampkExchangeKeys, ampkExchangeEnvelopes, ampkEpochReady}:
    raise newException(ValueError, "AME control packet kind is invalid")
  if S.nextAmeSequence == high(uint32):
    raise newException(ValueError, "AME send sequence is exhausted")
  h = initAmeFrameHeader(kind, amcControl, S.sessionId, S.rootLaneId,
    S.parentLaneId, S.laneId, S.nextAmeSequence,
    checkedEnvelopeLen(S.auth.current.layout, S.auth.current.tier,
      payload.len, "control payload", S.auth.current.params.authTagLen))
  e = sealEnvelope(S, h, carrier, payload)
  result = encodeAmeFrame(h, encodeAmeProtectedBody(e))
  S.nextAmeSequence = S.nextAmeSequence + 1'u32

proc controlBindingError(S: AmeSession, f: AmeDecodedFrame,
    expected: AmePacketKind): string {.role: parser.} =
  ## S/f/expected: expected authenticated control metadata.
  if f.header.packetKind != expected or f.header.messageClass != amcControl:
    return "AME control packet kind mismatch"
  if f.header.sessionId != S.sessionId or
      f.header.rootLaneId != S.rootLaneId or
      f.header.parentLaneId != S.parentLaneId or f.header.laneId != S.laneId:
    return "AME control frame binding mismatch"

proc openControlFrame(S: var AmeSession, frame: openArray[uint8],
    expected: AmePacketKind, carrier: AmeCarrier,
    useCandidate: bool = false): tuple[ok: bool, payload: ByteSeq,
    err: string] {.role: orchestrator.} =
  ## S/frame/expected/carrier/useCandidate: authenticated control open inputs.
  var
    f: AmeDecodedFrame = decodeAmeFrame(frame)
    e: AmeProtectedBody
    aad: ByteSeq = @[]
    opened: tuple[ok: bool, payload: ByteSeq]
    context: ByteSeq = @[]
  result.err = controlBindingError(S, f, expected)
  if result.err.len > 0:
    return
  e = decodeAmeProtectedBody(f.payload)
  aad = buildAad(carrier, f.header)
  if useCandidate:
    if not S.pendingIncoming.active:
      result.err = "AME session has no candidate epoch"
      return
    context = ameEpochKeyContext(S.pendingIncoming.candidate, S.sessionId,
      inboundAmeDirection(S.auth.endpointRole))
    opened = openWithEpoch(S.pendingIncoming.candidate, e, aad, context)
  else:
    context = ameEpochKeyContext(S.auth.current, S.sessionId,
      inboundAmeDirection(S.auth.endpointRole))
    opened = openWithEpoch(S.auth.current, e, aad, context)
  if not opened.ok:
    result.err = "AME control authentication failed"
    return
  if carrier == acrTcp and f.header.sequence != S.tcpRecvSequence:
    result.err = "AME control receive sequence mismatch"
    return
  if carrier == acrDac and not replayAccept(S.dacAmeReplay,
      f.header.sequence):
    result.err = "AME control AME replay rejected"
    return
  if carrier == acrTcp:
    if S.tcpRecvSequence == high(uint32):
      result.err = "AME TCP receive sequence is exhausted"
      return
    S.tcpRecvSequence = S.tcpRecvSequence + 1'u32
  result.ok = true
  result.payload = opened.payload

proc sealAmeDacControl*(S: var AmeSession, kind: DacMessageKind,
    body: openArray[uint8]): ByteSeq {.role: orchestrator.} =
  ## S: connection the DAC message belongs to.
  ## kind: which DAC message this is.
  ## body: the encoded DAC body.
  ## The kind becomes the FIRST BYTE OF THE PROTECTED PLAINTEXT rather than a
  ## field in a header. So it is encrypted as well as authenticated: an
  ## observer cannot tell an ACK from a repair hint by looking, and a peer that
  ## rewrites it fails verification instead of being believed. DAC control
  ## traffic used to ride bare, where anyone could forge a receipt.
  requireAmeAuth(S.auth)
  requireAmePeerTrust(S)
  if kind == dmkUnknown:
    raise newException(ValueError, "DAC control message kind is unknown")
  if S.nextAmeSequence == high(uint32):
    raise newException(ValueError, "AME send sequence is exhausted")
  var
    tagged: ByteSeq = @[uint8(ord(kind))]
    inner: ByteSeq = @[]
    h: AmeFrameHeader
    e: AmeProtectedBody
  appendAmeBytes(tagged, body)
  inner = sealAmeInnerPayload(S, acrDac, tagged, S.nextAmeSequence)
  h = initAmeFrameHeader(ampkDacControl, amcControl, S.sessionId,
    S.rootLaneId, S.parentLaneId, S.laneId, S.nextAmeSequence,
    checkedEnvelopeLen(S.auth.current.layout, S.auth.current.tier, inner.len,
      "DAC control payload", S.auth.current.params.authTagLen))
  e = sealEnvelope(S, h, acrDac, inner)
  result = encodeAmeFrame(h, encodeAmeProtectedBody(e))
  secureClearAmeBytes(inner)
  secureClearAmeBytes(tagged)
  S.nextAmeSequence = S.nextAmeSequence + 1'u32

proc openAmeDacControl*(S: var AmeSession, frame: openArray[uint8]): tuple[
    ok: bool, kind: DacMessageKind, body: ByteSeq, err: string] {.
    role: orchestrator.} =
  ## S/frame: connection and one DAC-carried control datagram.
  ## Returns the kind and body only after the frame authenticates, so the
  ## caller never dispatches on a kind an attacker chose.
  var
    f: AmeDecodedFrame
    e: AmeProtectedBody
    aad: ByteSeq = @[]
    context: ByteSeq = @[]
    opened: tuple[ok: bool, payload: ByteSeq]
    fomkeOpened: FomkeOpenResult
  result.err = amePeerTrustError(S)
  if result.err.len > 0:
    return
  try:
    f = decodeAmeFrame(frame)
    e = decodeAmeProtectedBody(f.payload)
  except CatchableError as exc:
    result.err = exc.msg
    return
  result.err = controlBindingError(S, f, ampkDacControl)
  if result.err.len > 0:
    return
  aad = buildAad(acrDac, f.header)
  context = ameEpochKeyContext(S.auth.current, S.sessionId,
    inboundAmeDirection(S.auth.endpointRole))
  opened = openWithEpoch(S.auth.current, e, aad, context)
  if not opened.ok and S.auth.retiring.epochId != 0'u32:
    context = ameEpochKeyContext(S.auth.retiring, S.sessionId,
      inboundAmeDirection(S.auth.endpointRole))
    opened = openWithEpoch(S.auth.retiring, e, aad, context)
  if not opened.ok:
    result.err = "AME DAC control authentication failed"
    return
  if not replayAccept(S.dacAmeReplay, f.header.sequence):
    result.err = "AME DAC control replay rejected"
    return
  fomkeOpened = openAmeInnerPayload(S, acrDac, opened.payload,
    f.header.sequence)
  if not fomkeOpened.ok:
    result.err = "AME DAC control FOMKE open failed: " & fomkeOpened.err
    return
  if fomkeOpened.payload.len < 1:
    result.err = "AME DAC control message carries no kind"
    return
  result.kind = dacMessageKindFromId(fomkeOpened.payload[0])
  if result.kind == dmkUnknown:
    result.err = "AME DAC control message kind is unknown"
    return
  result.body = fomkeOpened.payload[1 .. ^1]
  consumeRetiringGrace(S)
  result.ok = true

proc encodeEpochReady(requestId, epochId: uint32, targetTier: AmeMaskTier,
    fomkeCommit: FomkeUpgradeCommit = default(FomkeUpgradeCommit)): ByteSeq {.
    role: stateController.} =
  ## requestId/epochId/targetTier/fomkeCommit: complete candidate identity.
  var
    encoded: ByteSeq = @[]
    tierBytes: ByteSeq = encodeAmeMaskTier(targetTier)
  appendAmeU32(result, requestId)
  appendAmeU32(result, epochId)
  appendAmeBytes(result, tierBytes)
  if fomkeCommit.confirmationTag.len != 0:
    encoded = encodeFomkeUpgradeCommit(fomkeCommit)
  appendAmeU32(result, uint32(encoded.len))
  appendAmeBytes(result, encoded)

proc decodeEpochReady(L: AmeSuiteLayout,
    A: openArray[uint8]): tuple[requestId, epochId: uint32,
    targetTier: AmeMaskTier, fomkeCommit: FomkeUpgradeCommit] {.role: parser.} =
  ## L/A: immutable layout and exact tier-bound epoch-ready body.
  var
    commitLen: int = 0
  if A.len < 23:
    raise newException(ValueError, "AME epoch-ready body length mismatch")
  result.requestId = readU32(A, 0)
  result.epochId = readU32(A, 4)
  result.targetTier = decodeAmeMaskTier(L, A.toOpenArray(8, 18))
  if result.requestId == 0'u32 or result.epochId == 0'u32:
    raise newException(ValueError, "AME epoch-ready identity is invalid")
  commitLen = checkedAmeWireLen(readU32(A, 19),
    uint32(defaultAmeMaxFrameBytes), "AME FOMKE commit")
  if A.len != 23 + commitLen:
    raise newException(ValueError, "AME FOMKE commit length mismatch")
  if commitLen > 0:
    result.fomkeCommit = decodeFomkeUpgradeCommit(A.toOpenArray(23, A.len - 1))

proc beginAmeTcpExchangeFrame*(S: var AmeSession,
    r: AmeExchangeRequest): ByteSeq {.role: orchestrator.} =
  ## S/r: initiator and exact request sealed under the current epoch.
  var
    o: AmeExchangeOffer = beginAmeSessionExchange(S, r)
  result = sealControlFrame(S, ampkExchangeKeys, acrTcp,
    encodeAmeExchangeOffer(o))

proc answerAmeTcpExchangeFrame*(S: var AmeSession,
    frame: openArray[uint8]): ByteSeq {.role: orchestrator.} =
  ## S/frame: responder opens an offer and seals its candidate reply.
  var
    opened = openControlFrame(S, frame, ampkExchangeKeys, acrTcp)
    reply: AmeExchangeReply
  if not opened.ok:
    raise newException(ValueError, opened.err)
  reply = answerAmeSessionExchange(S,
    decodeAmeExchangeOffer(S.auth.current.layout.kems, opened.payload))
  result = sealControlFrame(S, ampkExchangeEnvelopes, acrTcp,
    encodeAmeExchangeReply(reply))

proc finishAmeTcpExchangeFrame*(S: var AmeSession,
    frame: openArray[uint8]): ByteSeq {.role: orchestrator.} =
  ## S/frame: initiator opens the reply and seals epoch-ready under the new key.
  var
    opened = openControlFrame(S, frame, ampkExchangeEnvelopes, acrTcp)
    requestId: uint32 = 0'u32
    fomkeCommit: FomkeUpgradeCommit
  if not opened.ok:
    raise newException(ValueError, opened.err)
  requestId = S.pendingExchange.offer.requestId
  finishAmeSessionExchange(S,
    decodeAmeExchangeReply(S.auth.current.layout.kems, opened.payload))
  if S.fomkeEnabled:
    fomkeCommit = S.fomke.pending.commit
  result = sealControlFrame(S, ampkEpochReady, acrTcp,
    encodeEpochReady(requestId, S.auth.current.epochId,
      S.auth.current.tier, fomkeCommit))
  if S.fomkeEnabled:
    confirmFomkeUpgrade(S.fomke, fomkeCommit)
    restoreConfiguredAmeFomkeCache(S)

proc confirmAmeTcpExchangeFrame*(S: var AmeSession,
    frame: openArray[uint8]) {.role: orchestrator.} =
  ## S/frame: responder authenticates epoch-ready with its candidate key.
  var
    opened = openControlFrame(S, frame, ampkEpochReady, acrTcp,
      useCandidate = true)
    ready: tuple[requestId, epochId: uint32, targetTier: AmeMaskTier,
      fomkeCommit: FomkeUpgradeCommit]
  if not opened.ok:
    raise newException(ValueError, opened.err)
  ready = decodeEpochReady(S.auth.current.layout, opened.payload)
  confirmAmeSessionExchange(S, ready.requestId, ready.epochId,
    ready.targetTier, ready.fomkeCommit)

proc beginAmeDacExchangeFrame*(S: var AmeSession,
    r: AmeExchangeRequest): ByteSeq {.role: orchestrator.} =
  ## S/r: initiator and exact request sealed through DAC under the current epoch.
  var
    o: AmeExchangeOffer = beginAmeSessionExchange(S, r)
  result = sealControlFrame(S, ampkExchangeKeys, acrDac,
    encodeAmeExchangeOffer(o))

proc answerAmeDacExchangeFrame*(S: var AmeSession,
    frame: openArray[uint8]): ByteSeq {.role: orchestrator.} =
  ## S/frame: responder opens a DAC offer and seals its candidate reply.
  var
    opened = openControlFrame(S, frame, ampkExchangeKeys, acrDac)
    reply: AmeExchangeReply
  if not opened.ok:
    raise newException(ValueError, opened.err)
  reply = answerAmeSessionExchange(S,
    decodeAmeExchangeOffer(S.auth.current.layout.kems, opened.payload))
  result = sealControlFrame(S, ampkExchangeEnvelopes, acrDac,
    encodeAmeExchangeReply(reply))

proc finishAmeDacExchangeFrame*(S: var AmeSession,
    frame: openArray[uint8]): ByteSeq {.role: orchestrator.} =
  ## S/frame: initiator opens the DAC reply and returns candidate epoch-ready.
  var
    opened = openControlFrame(S, frame, ampkExchangeEnvelopes, acrDac)
    requestId: uint32 = 0'u32
    fomkeCommit: FomkeUpgradeCommit
  if not opened.ok:
    raise newException(ValueError, opened.err)
  requestId = S.pendingExchange.offer.requestId
  finishAmeSessionExchange(S,
    decodeAmeExchangeReply(S.auth.current.layout.kems, opened.payload))
  if S.fomkeEnabled:
    fomkeCommit = S.fomke.pending.commit
  result = sealControlFrame(S, ampkEpochReady, acrDac,
    encodeEpochReady(requestId, S.auth.current.epochId,
      S.auth.current.tier, fomkeCommit))
  if S.fomkeEnabled:
    confirmFomkeUpgrade(S.fomke, fomkeCommit)
    restoreConfiguredAmeFomkeCache(S)

proc confirmAmeDacExchangeFrame*(S: var AmeSession,
    frame: openArray[uint8]) {.role: orchestrator.} =
  ## S/frame: responder authenticates DAC epoch-ready with its candidate key.
  var
    opened = openControlFrame(S, frame, ampkEpochReady, acrDac,
      useCandidate = true)
    ready: tuple[requestId, epochId: uint32, targetTier: AmeMaskTier,
      fomkeCommit: FomkeUpgradeCommit]
  if not opened.ok:
    raise newException(ValueError, opened.err)
  ready = decodeEpochReady(S.auth.current.layout, opened.payload)
  confirmAmeSessionExchange(S, ready.requestId, ready.epochId,
    ready.targetTier, ready.fomkeCommit)

proc captureAmeSendRollback(S: AmeSession): AmeSendRollback {.role: helper.} =
  ## S: connection whose send-mutable counters are snapshotted before a write.
  ## Only these fields change while sealing and accounting for one frame, so a
  ## failed send is undone without copying epoch secrets or the inbox.
  result.nextAmeSequence = S.nextAmeSequence
  result.path = S.path
  result.lastTrigger = S.lastTrigger

proc restoreAmeSend(S: var AmeSession, r: AmeSendRollback,
    fomke: var FomkeState, cache: var FomkeSendCache) {.
    role: stateController.} =
  ## S/r/fomke/cache: failed send rewound to its pre-send counters and, when
  ## FOMKE is enabled, to its pre-send ratchet. The advanced ratchet is erased
  ## before the saved one replaces it.
  S.nextAmeSequence = r.nextAmeSequence
  S.path = r.path
  S.lastTrigger = r.lastTrigger
  if not S.fomkeEnabled:
    return
  clearFomkeSendCache(S.fomkeSendCache)
  clearFomkeState(S.fomke)
  S.fomke = move(fomke)
  S.fomkeSendCache = move(cache)

proc discardAmeSendRollback(S: AmeSession, fomke: var FomkeState,
    cache: var FomkeSendCache) {.role: stateController.} =
  ## S/fomke/cache: successful send erases the superseded FOMKE ratchet copy
  ## instead of releasing its storage unwiped.
  if not S.fomkeEnabled:
    return
  clearFomkeSendCache(cache)
  clearFomkeState(fomke)

template ameSendTransaction*(S: var AmeSession, payload: openArray[uint8],
    body: untyped) =
  ## S/payload/body: `body` seals and writes one frame. If it raises, every
  ## send-mutable counter, the tier path, and the FOMKE ratchet are rewound to
  ## their pre-send values, so a failed write leaves no half-advanced state.
  ## On success the transferred bytes are accounted and the superseded ratchet
  ## copy is erased rather than released unwiped.
  ##
  ## The carrier modules share this one transaction instead of each repeating
  ## the capture/restore dance around their own socket write.
  var
    rollback: AmeSendRollback = captureAmeSendRollback(S)
    fomke: FomkeState
    cache: FomkeSendCache
  if S.fomkeEnabled:
    fomke = cloneFomkeState(S.fomke)
    cache = cloneFomkeSendCache(S.fomkeSendCache)
  try:
    body
    discard recordTransferredBytes(S, uint64(payload.len))
  except:
    restoreAmeSend(S, rollback, fomke, cache)
    raise
  discardAmeSendRollback(S, fomke, cache)
