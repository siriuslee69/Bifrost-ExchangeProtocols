## -------------------------------------------------------------------------
## AME Session <- WHAT a connection is: its keys, and how they change
## -------------------------------------------------------------------------
##
## A session is one conversation's state. This file owns all of it and
## nothing else:
##
##   the epoch      which algorithms and which keys are live right now
##   the exchange   the four-step transaction that replaces them
##   the ratchet    the FOMKE state that gives each message its own key
##   the settings   padding, tag length, what this side is willing to send
##
## What it does NOT own is what a message LOOKS LIKE. Sealing a payload into
## a frame and opening one again lives next door in `framing.nim`, including
## the AME/DAC seam. The split is the obvious one: this file answers "what
## do I know", that one answers "what do I send".
##
## It opens no socket either. The two carrier modules under
## `level2/carriers/` do that, so a build keeps only the network stack it
## uses. See `protocols/ame` for the build flags.

import protocols/containers/circ_seq as circ_seq

import ../../types
import ../../transport/types as transport_types
import ../types
import ../level0/bytes
import ../level1/exchange_paths
import ../level1/derivation
import ../level1/secret_stack
import ../level1/suites
import ../level1/symmetric
import ../level1/path_triggers
import ../level1/padding
import ../level1/header_protection
import ./wire
import ../../fomke/types
import ../../fomke/level0/gb3hkdf
import ../../fomke/level1/chain
import ../../fomke/level2/wire
import ../../config
import ../../dac/types
import ../../dac/level0/wire_helpers
import ../../dac/level0/defaults as dac_defaults
import runePragmas

const
  ameSessionIdGraceFrames* = 100
    ## How many arriving frames may still carry the session id this side used
    ## before the last rotation. It bounds frames that were already in the
    ## air, which is the one thing a frame count is actually a good clock for.

type
  AmeSession* {.role: truthState.} = object
    auth*: AmeAuthPackage
    path*: AmeTierPath
    sessionId*: uint64
    rootLaneId*: uint32
    laneId*: uint32
    nextAmeSequence*: uint32
    messageClass*: AmeMessageClass
    pathLane*: DacPathLane
    peerTrustRequired*: bool
    peerTrust*: AmePeerTrustResult
    inbox*: circ_seq.CircSeq[AmePacket]
    lastTrigger*: AmeTierStep   ## otter:latest
    nextExchangeRequestId*: uint32
    pendingExchange*: AmePendingExchange
    pendingIncoming*: AmePendingIncomingExchange
    fomke*: FomkeState
      ## The one thing that protects payloads. Always present on a live
      ## session -- there is no mode in which a frame body is unprotected or
      ## protected twice.
    fomkeCandidate*: FomkeState
      ## The ratchet as it WOULD be after the staged epoch change. The last
      ## message of a rotation -- epoch-ready -- is the first message of the
      ## new epoch, so a responder needs this to open it before it has agreed
      ## to commit. Adopted on confirmation, erased on cancellation.
    fomkeCandidateActive*: bool
    fomkePregenerationEnabled*: bool
    fomkePregenerationMessages*: int
    fomkeSendCache*: FomkeSendCache
    tcpRecvSequence*: uint32
    dacAmeReplay*: AmeReplayWindow
    pendingParams*: AmeRuntimeParams
    previousSessionId*: uint64
      ## The id this session answered to before the last rotation. Accepted on
      ## RECEIVE only -- nothing is ever sealed under it again.
    previousSessionIdFramesLeft*: int
      ## How many more arriving frames may still carry the old id. Counts down
      ## on every accepted frame and the old id is forgotten at zero.
      ##
      ## A frame count is the right clock here, unlike the epoch case, because
      ## what it bounds IS a number of frames: the ones that were already in
      ## the air when the id changed. And unlike the epoch case it is
      ## reachable, on the datagram carrier, where nothing keeps a data frame
      ## from overtaking the assign message that changed the id:
      ##
      ##   TCP   order is guaranteed, so every frame after the assign
      ##         already carries the new id and this never fires
      ##   DAC   datagrams reorder, so a frame sealed before the assign can
      ##         easily land after it
      ##
      ## What it holds is one integer, not key material -- forgetting it early
      ## costs a dropped frame the transport re-sends, never a lost secret.
    headerKeySend*: ByteSeq
      ## Masks the sequence number on frames leaving this side.
    headerKeyRecv*: ByteSeq
      ## Unmasks it on frames arriving. Two keys, not one, for the same reason
      ## the ratchet has two lanes: a frame this side sent must not be
      ## reflectable back at it looking like a frame it received.
      ##
      ## Both are derived once per epoch, not once per frame -- deriving one
      ## runs every switched-on KDF slot, and a frame only needs a keyed
      ## BLAKE3 call over 16 bytes.

    lastErr*: string

proc copyBytes(A: openArray[uint8]): ByteSeq {.role: helper.} =
  ## A: source bytes copied into owned storage.
  result = @A

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

proc clearExchangeState(E: var AmeExchangeState) {.role: actor.} =
  ## E: exchange state whose secret slots are overwritten.
  var
    i: int = 0
  while i < ameMaxAlgorithmSlots:
    secureClearAmeBytes(E.stackedSecrets[i])
    i = i + 1
  E = default(AmeExchangeState)

proc clearEpoch(E: var AmeEpochKeySet) {.role: actor.} =
  ## E: epoch whose exchange secrets and transcript salt are cleared.
  clearExchangeState(E.exchange)
  secureClearAmeBytes(E.transcriptSalt)
  E = default(AmeEpochKeySet)

proc clearSignatureSecretKeys(K: var seq[ByteSeq]) {.
    role: actor.} =
  ## K: complete identity signature private-key stack to erase.
  var
    i: int = 0
  while i < K.len:
    secureClearAmeBytes(K[i])
    i = i + 1
  K.setLen(0)

proc clearPendingExchange(P: var AmePendingExchange) {.
    role: actor.} =
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
    result.stackedSecrets[i] = copyBytes(E.stackedSecrets[i])
    i = i + 1

proc cloneEpoch(E: AmeEpochKeySet): AmeEpochKeySet {.role: helper.} =
  ## E: epoch copied without sharing secret or transcript byte storage.
  ##
  ## `params` is copied like everything else, and that is load-bearing rather
  ## than tidy. A retiring epoch is asked for its OWN tag length and padding
  ## policy when it opens a sealed package that was stored under it
  ## (`openAmeSecurePackage`). Leaving the field at its default made that read
  ## answer `apadNone` no matter what the epoch actually used, so with
  ## `apadBlock64` switched on the package was refused for disagreeing with a
  ## policy it had never been sealed under.
  result.epochId = E.epochId
  result.layout = E.layout
  result.tier = E.tier
  result.exchange = cloneExchangeState(E.exchange)
  result.transcriptSalt = copyBytes(E.transcriptSalt)
  result.params = E.params

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
    AmeAuthPackage {.role: configurator.} =
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
  result.sessionId = sessionId
  result.endpointRole = endpointRole
  result.current.params = params
  requireAmeAuth(result)

## ╭⟢ proving an epoch change
##
## Rotating an epoch means sending an offer and a reply, and each has to be
## proved by the endpoint that sent it. HOW it is proved depends on what the
## handshake established:
##
##   AM1C / AM1S  ->  one signature per active signature slot
##   AM1M         ->  one tag under the session's own exchange key
##
## AM1M sessions hold no signature keys at all, so there is nothing there to
## sign with. Both shapes travel in the same `signatures` field, and both are
## taken over the same subject bytes, so nothing below this point has to know
## which one it is looking at.

proc exchangeProofKey(A: AmeAuthPackage): ByteSeq {.role: parser,
    tag: "cryptoBoundary".} =
  ## A: the AM1M exchange key, checked before it is used.
  if A.exchangeAuthenticationKey.len < 32:
    raise newException(ValueError, "AME session has no exchange proof key")
  result = A.exchangeAuthenticationKey

proc proveExchangeSubject(S: AmeSession, t: AmeMaskTier,
    subject: openArray[uint8]): seq[ByteSeq] {.role: truthBuilder,
    tag: "cryptoBoundary|exchange".} =
  ## S/t/subject: this endpoint's proof over one offer or reply.
  if S.auth.authenticationMode == am1m:
    return @[ameMacTag(amaBlake3, exchangeProofKey(S.auth), subject, 32)]
  result = signAmeTier(S.auth.current.layout, t, subject,
    activeAmeSignatureKeys(S.auth.current.layout, t,
      S.auth.localSignatureSecretKeys))

proc exchangeSubjectProved(S: AmeSession, t: AmeMaskTier,
    subject: openArray[uint8], P: openArray[ByteSeq]): bool {.role: parser,
    tag: "cryptoBoundary|exchange|validation".} =
  ## S/t/subject/P: the peer's proof over one offer or reply.
  var expected: ByteSeq = @[]
  if S.auth.authenticationMode != am1m:
    return verifyAmeTier(S.auth.current.layout, t, subject,
      activeAmeSignatureKeys(S.auth.current.layout, t,
        S.auth.peerSignaturePublicKeys), P)
  if P.len != 1:
    return
  expected = ameMacTag(amaBlake3, exchangeProofKey(S.auth), subject, 32)
  result = constantTimeEqualAme(expected, P[0])
  secureClearAmeBytes(expected)

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

proc refreshAmeHeaderKeys*(S: var AmeSession) {.role: actor,
    tag: "ame|cryptoBoundary|kdf".} =
  ## S: header-protection keys rebuilt for whatever epoch is now current.
  ##
  ## Must be called wherever `auth.current` changes. The keys are bound to the
  ## epoch id, so a stale pair produces a mask the peer cannot reproduce and
  ## every frame fails to open -- loudly, which is the right way for this to
  ## go wrong if a future rotation path forgets to call it.
  secureClearAmeBytes(S.headerKeySend)
  secureClearAmeBytes(S.headerKeyRecv)
  S.headerKeySend = deriveAmeHeaderKey(S.auth.current.exchange,
    S.auth.current.layout, S.auth.current.tier,
    ameEpochKeyContext(S.auth.current, S.auth.sessionId,
      outboundAmeDirection(S.auth.endpointRole)))
  S.headerKeyRecv = deriveAmeHeaderKey(S.auth.current.exchange,
    S.auth.current.layout, S.auth.current.tier,
    ameEpochKeyContext(S.auth.current, S.auth.sessionId,
      inboundAmeDirection(S.auth.endpointRole)))

proc rotateAmeTier*(S: var AmeSession, r: AmeExchangeRequest,
    sharedSecrets: openArray[ByteSeq], transcriptSalt: openArray[uint8]) {.
    role: actor.} =
  ## S/r/sharedSecrets/transcriptSalt: atomic authenticated epoch rotation.
  var
    next: AmeEpochKeySet = cloneEpoch(S.auth.current)
  clearFomkeSendCache(S.fomkeSendCache)
  if S.auth.current.epochId == high(uint32):
    raise newException(ValueError, "AME epoch id is exhausted")
  validateAmeTierTransition(next.layout, next.tier, r.targetTier,
    r.exchangeMask, next.exchange.activeMask)
  applyAmeExchange(next.exchange, next.layout, r, sharedSecrets,
    S.auth.exchangeBinder)
  next.tier = r.targetTier
  next.params = r.params
  next.epochId = S.auth.current.epochId + 1'u32
  secureClearAmeBytes(next.transcriptSalt)
  next.transcriptSalt = copyBytes(transcriptSalt)
  clearEpoch(S.auth.retiring)
  S.auth.retiring = cloneEpoch(S.auth.current)
  S.auth.current = next
  requireAmeAuth(S.auth)
  refreshAmeHeaderKeys(S)

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

## ╭⟢ the message ratchet
##
## A session starts its ratchet the moment it is built, from the exchange the
## handshake finished and from that handshake's transcript. There is no
## "enable" step and no way to run without it: a session either has a working
## ratchet or it does not exist.

proc fomkeRoleFor(r: AmeEndpointRole): FomkeRole {.role: parser.} =
  ## r: AME endpoint role mapped to its ratchet direction.
  if r == aerInitiator:
    return frInitiator
  result = frResponder

proc buildAmeFomkeSendCache*(S: AmeSession,
    messageCount: int = fomkeDefaultPreparedMessages): FomkeSendCache {.
    role: truthBuilder,
    tag: "appApi|cryptoBoundary|fomke|protocol".} =
  ## S/messageCount: connection snapshot and future send capacity. Built off
  ## a clone, so it never disturbs the live ratchet.
  var
    snapshot: FomkeState = default(FomkeState)
  snapshot = cloneFomkeState(S.fomke)
  try:
    result = prepareFomkeSendCache(snapshot, messageCount)
    clearFomkeState(snapshot)
  except CatchableError:
    clearFomkeState(snapshot)
    raise

proc snapshotAmeFomkeSendState*(S: AmeSession): FomkeState {.
    role: helper,
    tag: "appApi|cryptoBoundary|fomke|protocol".} =
  ## S: connection copied deeply under its caller-owned synchronization lock.
  result = cloneFomkeState(S.fomke)

proc installAmeFomkeSendCache*(S: var AmeSession,
    C: var FomkeSendCache): bool {.role: actor,
    tag: "appApi|cryptoBoundary|fomke|protocol".} =
  ## S/C: live connection and caller-owned cache built from a prior snapshot.
  ## A cache that no longer lines up with the live chain is destroyed rather
  ## than installed, so a stale cache can never seal under a spent key.
  if not S.fomkePregenerationEnabled or
      not fomkeSendCacheMatches(S.fomke, C):
    clearFomkeSendCache(C)
    return
  clearFomkeSendCache(S.fomkeSendCache)
  S.fomkeSendCache = move(C)
  result = true

proc prepareAmeFomkeSendCache*(S: var AmeSession,
    messageCount: int = fomkeDefaultPreparedMessages) {.
    role: orchestrator,
    tag: "appApi|cryptoBoundary|fomke|protocol".} =
  ## S/messageCount: synchronously build and install future send slots.
  var
    C: FomkeSendCache = default(FomkeSendCache)
  C = buildAmeFomkeSendCache(S, messageCount)
  S.fomkePregenerationEnabled = true
  S.fomkePregenerationMessages = messageCount
  if not installAmeFomkeSendCache(S, C):
    raise newException(ValueError, "AME FOMKE send state changed during prepare")

proc setAmeFomkePregeneration*(S: var AmeSession, enabled: bool,
    messageCount: int = fomkeDefaultPreparedMessages) {.
    role: actor,
    tag: "appApi|cryptoBoundary|fomke|protocol".} =
  ## S/enabled/messageCount: per-connection policy override.
  ## Preparing ahead costs forward secrecy for messages not yet sent; see
  ## `prepareFomkeSendCache`. Turn it off on a device that can be seized.
  var
    C: FomkeSendCache = default(FomkeSendCache)
  if enabled:
    C = buildAmeFomkeSendCache(S, messageCount)
  clearFomkeSendCache(S.fomkeSendCache)
  S.fomkePregenerationEnabled = enabled
  S.fomkePregenerationMessages = messageCount
  if enabled:
    S.fomkeSendCache = move(C)

proc ameFomkeSendCacheNeedsRefill*(S: AmeSession): bool {.role: parser,
    tag: "appApi|cryptoBoundary|fomke|protocol".} =
  ## S: connection whose configured cache has fallen below half capacity.
  var
    remaining: int = fomkePreparedMessages(S.fomkeSendCache)
    threshold: int = S.fomkePregenerationMessages div 2
  if threshold < 1:
    threshold = 1
  result = S.fomkePregenerationEnabled and
    not S.fomke.pending.active and remaining <= threshold

proc restoreConfiguredAmeFomkeCache*(S: var AmeSession) {.
    role: actor,
    tag: "cryptoBoundary|fomke|protocol".} =
  ## S: quiescent configured connection whose cache is rebuilt off data paths.
  clearFomkeSendCache(S.fomkeSendCache)
  if S.fomkePregenerationEnabled and not S.fomke.pending.active:
    S.fomkeSendCache = prepareFomkeSendCache(S.fomke,
      S.fomkePregenerationMessages)

proc clearAmeSession*(S: var AmeSession) {.role: actor,
    tag: "appApi|cryptoBoundary|protocol".} =
  ## S: current, retiring, pending AME, and FOMKE secrets to erase.
  clearEpoch(S.auth.current)
  clearEpoch(S.auth.retiring)
  clearSignatureSecretKeys(S.auth.localSignatureSecretKeys)
  S.auth.peerSignaturePublicKeys.setLen(0)
  secureClearAmeBytes(S.auth.exchangeAuthenticationKey)
  clearPendingExchange(S.pendingExchange)
  clearEpoch(S.pendingIncoming.candidate)
  clearFomkeSendCache(S.fomkeSendCache)
  clearFomkeState(S.fomke)
  clearFomkeState(S.fomkeCandidate)
  S = default(AmeSession)

proc cancelAmeSessionExchange*(S: var AmeSession) {.role: actor.} =
  ## S: outgoing exchange cancelled and trigger returned to the due queue.
  if S.path.inFlightTierId != 0'u32:
    releaseAmeTier(S.path)
  clearPendingExchange(S.pendingExchange)
  clearFomkeState(S.fomkeCandidate)
  S.fomkeCandidateActive = false
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
    keys: AmeExchangeKeys = default(AmeExchangeKeys)
    step: AmeTierStep = default(AmeTierStep)
    signatureTier: AmeMaskTier = default(AmeMaskTier)
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
  result.signatures = proveExchangeSubject(S, signatureTier,
    encodeAmeExchangeOfferSubject(result))
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
    answer: tuple[reply: AmeExchangeReply, sharedSecrets: seq[ByteSeq]] = (
      reply: default(AmeExchangeReply), sharedSecrets: @[])
    signatureTier: AmeMaskTier = default(AmeMaskTier)
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
  if not exchangeSubjectProved(S, signatureTier,
      encodeAmeExchangeOfferSubject(o), o.signatures):
    raise newException(ValueError, "AME exchange offer proof is invalid")
  answer = answerAmeExchangeOffer(S.auth.current.layout.kems, o)
  answer.reply.signatures = proveExchangeSubject(S, signatureTier,
    encodeAmeExchangeReplySubject(o, answer.reply))
  S.pendingIncoming.active = true
  S.pendingIncoming.requestId = o.requestId
  S.pendingIncoming.request = o.request
  S.pendingIncoming.candidate = cloneEpoch(S.auth.current)
  applyAmeExchange(S.pendingIncoming.candidate.exchange,
    S.auth.current.layout, o.request, answer.sharedSecrets,
    S.auth.exchangeBinder)
  S.pendingIncoming.candidate.tier = o.request.targetTier
  S.pendingIncoming.candidate.params = o.request.params
  S.pendingParams = o.request.params
  S.pendingIncoming.candidate.epochId = S.auth.current.epochId + 1'u32
  secureClearAmeBytes(S.pendingIncoming.candidate.transcriptSalt)
  S.pendingIncoming.candidate.transcriptSalt = transitionTranscriptSalt(
    S.auth.current, o, answer.reply)
  clearFomkeSendCache(S.fomkeSendCache)
  result = answer.reply
  ## The ratchet upgrade is NOT staged here. Staging it freezes the lane
  ## counters, and this side still has to seal the reply -- which advances
  ## one of them. `stageAmeSessionFomkeUpgrade` runs after that send, so both
  ## endpoints stage at the same lane positions and derive the same root.

proc stageAmeSessionFomkeUpgrade*(S: var AmeSession) {.role: actor,
    tag: "cryptoBoundary|exchange|fomke".} =
  ## S: responder that has already SENT its reply. Stages the ratchet upgrade
  ## at the lane positions both endpoints now share.
  ##
  ## Forgetting this call cannot produce a bad session: `confirmAmeSessionExchange`
  ## checks that an upgrade is staged and refuses the epoch-ready frame
  ## otherwise.
  if not S.pendingIncoming.active:
    raise newException(ValueError, "AME has no incoming exchange to stage")
  if S.fomke.pending.active:
    raise newException(ValueError, "AME FOMKE upgrade is already staged")
  clearFomkeSendCache(S.fomkeSendCache)
  discard prepareFomkeUpgrade(S.fomke, S.pendingIncoming.requestId,
    S.pendingIncoming.candidate.epochId, S.pendingIncoming.request,
    S.pendingIncoming.candidate.exchange)

proc finishAmeSessionExchange*(S: var AmeSession, r: AmeExchangeReply) {.
    role: orchestrator.} =
  ## S/r: initiating connection and matching reply.
  var
    secrets: seq[ByteSeq] = @[]
    candidate: AmeEpochKeySet = default(AmeEpochKeySet)
    signatureTier: AmeMaskTier = default(AmeMaskTier)
    transcriptSalt: ByteSeq = @[]
  if not S.pendingExchange.active:
    raise newException(ValueError, "AME session has no pending exchange")
  if S.pendingExchange.offer.baseEpochId != S.auth.current.epochId:
    raise newException(ValueError, "AME pending exchange base epoch changed")
  signatureTier = transitionAmeSignatureTier(S.auth.current.layout,
    S.auth.current.tier, r.request.targetTier)
  if not exchangeSubjectProved(S, signatureTier,
      encodeAmeExchangeReplySubject(S.pendingExchange.offer, r),
      r.signatures):
    raise newException(ValueError, "AME exchange reply proof is invalid")
  secrets = openAmeExchangeReply(S.auth.current.layout.kems,
    S.pendingExchange.offer, r,
    S.pendingExchange.secretKeys)
  transcriptSalt = transitionTranscriptSalt(S.auth.current,
    S.pendingExchange.offer, r)
  clearFomkeSendCache(S.fomkeSendCache)
  candidate = cloneEpoch(S.auth.current)
  applyAmeExchange(candidate.exchange, S.auth.current.layout, r.request,
    secrets, S.auth.exchangeBinder)
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
    role: actor.} =
  ## S/requestId/epochId/targetTier/fomkeCommit: authenticated candidate identity.
  if not S.pendingIncoming.active or
      S.pendingIncoming.requestId != requestId or
       S.pendingIncoming.candidate.epochId != epochId or
       not tiersEquivalent(S.pendingIncoming.request.targetTier, targetTier) or
       not tiersEquivalent(S.pendingIncoming.candidate.tier, targetTier):
    raise newException(ValueError, "AME epoch-ready confirmation mismatch")
  validateFomkeUpgrade(S.fomke, fomkeCommit)
  clearEpoch(S.auth.retiring)
  S.auth.retiring = cloneEpoch(S.auth.current)
  S.auth.current = S.pendingIncoming.candidate
  refreshAmeHeaderKeys(S)
  S.pendingIncoming = default(AmePendingIncomingExchange)
  setCurrentAmeTier(S.path, targetTier)
  if S.fomkeCandidateActive:
    ## The candidate already opened the epoch-ready frame, so its receive
    ## chain has moved past that message. Adopting it -- rather than deriving
    ## the same epoch a second time -- keeps both sides at the same position.
    clearFomkeState(S.fomke)
    S.fomke = move(S.fomkeCandidate)
    S.fomkeCandidateActive = false
  else:
    confirmFomkeUpgrade(S.fomke, fomkeCommit)
  S.fomke.tagLen = S.auth.current.params.authTagLen
  restoreConfiguredAmeFomkeCache(S)
  requireAmeAuth(S.auth)

proc cancelIncomingAmeSessionExchange*(S: var AmeSession) {.
    role: actor.} =
  ## S: incoming candidate epoch discarded before confirmation.
  clearEpoch(S.pendingIncoming.candidate)
  S.pendingIncoming = default(AmePendingIncomingExchange)
  clearFomkeState(S.fomkeCandidate)
  S.fomkeCandidateActive = false
  cancelFomkeUpgrade(S.fomke)
  restoreConfiguredAmeFomkeCache(S)

## ╭⟢ what the path profile says this session should send with
##
## The session records which DAC path profile it is running over. That byte
## used to be written and never read, which made it look as though the
## parameter feedback existed when it did not.
##
## What it decides, and what it must never decide:
##
##   follows the path   chunk size, repair mode and strength, ACK batching,
##                      repair timeouts -- how the bytes are shaped
##   never follows it   which algorithms are switched on, tag length,
##                      padding policy -- how the bytes are protected
##
## The second row is the important one. Loss is something an attacker on the
## path can cause at will. If padding switched off on a "thin" profile, an
## attacker would induce loss and get message lengths back -- exactly what
## the padding is there to hide. So cipher strength, tag length and padding
## stay where the handshake and the caller put them, whatever the link does.

proc dacTransferClassFor(c: AmeMessageClass): DacTransferClass {.role: parser.} =
  ## c: what the session says its traffic is, named the way DAC names it.
  case c
  of amcStatus, amcTelemetry: result = dtcStatus
  of amcControl, amcProfile: result = dtcControl
  else: result = dtcUserData

proc ameSessionPathDefaults*(S: AmeSession): DacScenarioDefaults {.
    role: parser, tag: "appApi|protocol".} =
  ## S: session whose recorded path profile becomes a full parameter set.
  ## One preset per lane, so reading this is a complete validated set rather
  ## than a handful of fields a caller has to keep consistent by hand.
  result = dac_defaults.dacDefaultsForPath(S.pathLane,
    dacTransferClassFor(S.messageClass))

proc ameSessionSkippedMessages*(S: AmeSession): int {.role: parser,
    tag: "appApi|fomke|protocol".} =
  ## S: how many jumped-over messages the ratchet is still holding keys for.
  result = fomkeSkippedMessages(S.fomke)

proc discardAmeSessionSkipped*(S: var AmeSession): int {.
    role: actor,
    tag: "appApi|cryptoBoundary|fomke|protocol".} =
  ## S: give up on the messages this side jumped over, and say how many.
  ##
  ## A rotation refuses to run while any of them are outstanding, so a link
  ## that loses packets for good will eventually be unable to rekey. Call
  ## this first when `ameSessionSkippedMessages` stops going down and the
  ## messages behind it are not worth waiting for any longer. The keys are
  ## erased, so those messages can never be opened afterwards.
  result = discardFomkeSkipped(S.fomke)
  clearFomkeSendCache(S.fomkeSendCache)
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
    AmeSession {.role: orchestrator.} =
  ## a/path/session/lane/runtime: exact connection configuration.
  var
    runtime: BifrostConfig = default(BifrostConfig)
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

  result.laneId = laneId
  result.pathLane = pathLane
  result.messageClass = messageClass
  result.peerTrustRequired = peerTrustRequired
  result.peerTrust = peerTrust
  result.inbox = circ_seq.initCircSeq[AmePacket](inboxCapacity)
  setCurrentAmeTier(result.path, result.auth.current.tier)
  ## The ratchet is started here, from the finished exchange and from the
  ## handshake transcript that produced it. Binding the transcript means two
  ## sessions that negotiated different things can never derive the same keys
  ## even if every KEM secret somehow matched.
  result.fomke = initFomkeFromAme(result.auth.current.exchange,
    result.auth.current.layout, result.auth.current.tier,
    fomkeRoleFor(result.auth.endpointRole),
    result.auth.current.transcriptSalt,
    initGb3KdfConfig(), fomkeDefaultReorderCeiling,
    result.auth.current.params.authTagLen)
  refreshAmeHeaderKeys(result)
  runtime = currentBifrostConfig()
  result.fomkePregenerationEnabled = fomkePregenerationEnabled(runtime)
  result.fomkePregenerationMessages = runtime.fomkePregenerationMessages
  if result.fomkePregenerationEnabled:
    result.fomkeSendCache = prepareFomkeSendCache(result.fomke,
      result.fomkePregenerationMessages)

proc initAmeSession*(a: AmeAuthPackage,
    sessionId: uint64 = 0'u64, rootLaneId: uint32 = 1'u32,
    laneId: uint32 = 5'u32, pathLane: DacPathLane = dplCleanPath,
    messageClass: AmeMessageClass = amcUserdata,
    inboxCapacity: int = defaultAmeInboxCapacity,
    peerTrustRequired: bool = true,
    peerTrust: AmePeerTrustResult = default(AmePeerTrustResult)):
    AmeSession {.role: configurator.} =
  ## a/session/lane/runtime: exact auth package with default AME triggers.
  var path: AmeTierPath = default(AmeTierPath)
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
    role: actor.} =
  ## S/p: connection inbox and destination packet.
  result = circ_seq.pop(S.inbox, p)

proc recordTransferredBytes*(S: var AmeSession, n: uint64): AmeTierStep {.
    role: actor.} =
  ## S/n: connection and newly successful plaintext transfer bytes.
  result = feedTransferredBytes(S.path, n)
  S.lastTrigger = result

proc feedAmeElapsedMs*(S: var AmeSession, elapsedMs: uint64): AmeTierStep {.
    role: actor.} =
  ## S/elapsedMs: connection and monotonic elapsed clock.
  result = feedElapsedMs(S.path, elapsedMs)
  S.lastTrigger = result

proc requestAmeTier*(S: var AmeSession, tierId: uint32,
    rekeyMask: uint8 = 0'u8): AmeTierStep {.
    role: actor.} =
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

proc setAmePadding*(S: var AmeSession, p: AmePaddingPolicy) {.
    role: configurator.} =
  ## S/p: session and the padding its next epoch should apply.
  ##
  ## Staged like the tag length, and for the same reason: the padded flag is
  ## bound into every tag, so a value that changed underneath a live epoch
  ## would fail to open rather than take effect.
  ##
  ## Off by default. Padding costs 1 to 64 bytes on EVERY frame, which is
  ## real money on a link that carries small messages, and the length of a
  ## frame that was never compressed is a weak signal on its own. Switch it
  ## on when traffic analysis is part of the threat -- when message sizes
  ## would say what a command was, or who is typing.
  S.pendingParams.padding = p

proc ameFrameOverheadBytes*(S: AmeSession): int {.role: parser.} =
  ## S: session whose worst-case per-frame overhead is returned: the fixed
  ## header, the ratchet envelope and tag, and the largest padding this
  ## epoch can add. A caller sizing datagrams against a link MTU subtracts
  ## this from the MTU to get the plaintext it may hand over at once.
  result = ameFrameHeaderLen + fomkeWireLen(0, S.fomke.tagLen) +
    amePaddingBlock(S.auth.current.params.padding)

proc info*(S: AmeSession): AmeSessionInfo {.role: truthBuilder.} =
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

proc `$`*(i: AmeSessionInfo): string {.role: truthBuilder.} =
  ## i: mask-tier connection summary.
  result = "AME session=" & $i.sessionId & " lane=" & $i.laneId &
    " epoch=" & $i.epochId & " tier=" & $i.tierId &
    " activeMask=" & $i.activeKemMask &
    " layoutBytes=" & $i.layoutBytes & " transferred=" &
    $i.transferredBytes
