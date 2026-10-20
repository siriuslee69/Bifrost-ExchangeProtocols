## -------------------------------------------------------------------------
## AME Epochs <- what a connection knows, and how its keys change
## -------------------------------------------------------------------------
##
## The `AmeSession` type and everything that changes its keys:
##
##   the epoch      which algorithms and which keys are live right now
##   the exchange   the four-step transaction that replaces them
##   the ratchet    the FOMKE state that gives each message its own key
##   saying no      a deny, and the one rule both sides judge a request by
##
## `session.nim` builds on this: starting a session, reading its state, and
## its settings. Import `session`, not this file; it passes all of this on.
##
## What neither owns is what a message LOOKS LIKE. Sealing a payload into a
## frame and opening one again lives in `seal_open.nim` and `framing.nim`.

import protocols/containers/circ_seq as circ_seq

import ../../types
import ../types
import ../level0/bytes
import ../level1/exchange_paths
import ../level1/secret_stack
import ../level1/suites
import ../level1/path_triggers
import ../level1/header_protection
import ../level1/route_block
import ../../fomke/types
import ../../fomke/level1/chain
import ../../config
import ../../dac/types
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
      ## This side's own request, from sending it until the answer. While
      ## it is active this side sends NOTHING: whatever it sent would be
      ## sealed with the old algorithms or the requested ones, and which is
      ## right is only known once the peer has accepted or denied.
    pendingIncoming*: AmePendingIncomingExchange
    lastExchangeDenial*: string
      ## Why the peer denied this side's last request ("" if it did not).
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
    unsentFrame*: ByteSeq
      ## A sealed DAC datagram whose write failed. The next send writes these
      ## exact bytes first; sealing again at the same ratchet step would
      ## reuse its key and nonce (see framing.nim, "sending one frame").
    unsentPayloadLen*: int
      ## Payload bytes behind `unsentFrame`, accounted once it goes out.
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
    routeKeySend*: ByteSeq
      ## Seals the target/origin block of route frames leaving this side.
      ## See level1/route_block.nim.
    routeKeyRecv*: ByteSeq
      ## Opens the block on route frames arriving. Split by direction for
      ## the header keys' reason: a block this side sealed must not open as
      ## one it received.

    lastErr*: string

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

proc copyBytes(A: openArray[uint8]): ByteSeq {.role: helper.} =
  ## A: source bytes copied into owned storage.
  result = @A

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

## ╭⟢ proving an in-session exchange
##
## Every exchange request after the handshake (more key material, a change
## of algorithms) is an offer and a reply. The REQUEST says how each is
## proved (`AmeExchangeProof`):
##
##   aepFrame (default)  nothing extra. Offers and replies only travel as
##                       control frames, sealed and tagged by the session
##                       ratchet. Only the two ends hold those keys, so a
##                       frame that opens was sent by the other end.
##   aepSignatures       one signature per switched-on signature slot --
##                       the AM1S way, tied to a long-term identity key.
##                       Needs signature keys, so never AM1P.
##
##   ┌──────────── control frame (ratchet-sealed) ────────────┐
##   │ index | encrypted offer, `signatures` empty | frame tag│
##   └────────────────────────────────────────────────────────┘
##                                                     ▲ the proof
##
## The session-level procs below take an offer or reply that has ALREADY
## been opened from such a frame (framing.nim). Handed one from anywhere
## else, an aepFrame offer is proved by nothing.

proc exchangeProofError*(S: AmeSession, p: AmeExchangeProof): string {.
    role: parser.} =
  ## S/p: "" when this session can make and check proof `p`, else why not.
  if p == aepSignatures and (S.auth.localSignatureSecretKeys.len == 0 or
      S.auth.peerSignaturePublicKeys.len == 0):
    result = "AME signed exchange needs signature keys on both sides " &
      "(this session has none)"

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

## ╭⟢ the message ratchet
##
## A session starts its ratchet the moment it is built, from the exchange the
## handshake finished and from that handshake's transcript. There is no
## "enable" step and no way to run without it: a session either has a working
## ratchet or it does not exist.

proc fomkeRoleFor*(r: AmeEndpointRole): FomkeRole {.role: parser.} =
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

proc clearEpoch(E: var AmeEpochKeySet) {.role: actor.} =
  ## E: epoch whose exchange secrets and transcript salt are cleared.
  clearExchangeState(E.exchange)
  secureClearAmeBytes(E.transcriptSalt)
  E = default(AmeEpochKeySet)

proc clearAmeSession*(S: var AmeSession) {.role: actor,
    tag: "appApi|cryptoBoundary|protocol".} =
  ## S: current, retiring, pending AME, and FOMKE secrets to erase.
  clearEpoch(S.auth.current)
  clearEpoch(S.auth.retiring)
  clearSignatureSecretKeys(S.auth.localSignatureSecretKeys)
  S.auth.peerSignaturePublicKeys.setLen(0)
  clearPendingExchange(S.pendingExchange)
  clearEpoch(S.pendingIncoming.candidate)
  secureClearAmeBytes(S.unsentFrame)
  clearFomkeSendCache(S.fomkeSendCache)
  clearFomkeState(S.fomke)
  clearFomkeState(S.fomkeCandidate)
  S = default(AmeSession)

proc ameRequestPolicyError*(S: AmeSession, r: AmeExchangeRequest): string {.
    role: parser.} =
  ## S/r: a request either side makes -> "" when this side accepts it, else
  ## the reason. One rule for both directions:
  ##
  ##   at least `ameMinPqKems` post-quantum KEMs stay switched on
  ##   the proof is one this session can check (signatures need keys)
  ##   `ameSignedExchanges = true` -> only signed requests
  result = ameTierPolicyError(S.auth.current.layout, r.targetTier,
    currentBifrostConfig().ameMinPqKems)
  if result.len > 0:
    return
  result = exchangeProofError(S, r.proof)
  if result.len == 0 and r.proof == aepFrame and
      currentBifrostConfig().ameSignedExchanges:
    result = "AME this side accepts only signed exchange requests " &
      "(ameSignedExchanges)"

proc proveExchangeSubject(S: AmeSession, t: AmeMaskTier,
    p: AmeExchangeProof, subject: openArray[uint8]): seq[ByteSeq] {.
    role: truthBuilder, tag: "cryptoBoundary|exchange".} =
  ## S/t/p/subject: this endpoint's proof of kind `p` over one offer or
  ## reply; empty for aepFrame (the frame tag proves it).
  if p == aepFrame:
    return @[]
  result = signAmeTier(S.auth.current.layout, t, subject,
    activeAmeSignatureKeys(S.auth.current.layout, t,
      S.auth.localSignatureSecretKeys))

proc requireAmeRequestPolicy(S: AmeSession, r: AmeExchangeRequest) {.
    role: parser.} =
  ## S/r: refuses to SEND (or answer) a request this side would deny.
  var
    reason: string = ameRequestPolicyError(S, r)
  if reason.len > 0:
    raise newException(ValueError, reason)

proc beginAmeSessionExchange*(S: var AmeSession,
    r: AmeExchangeRequest): AmeExchangeOffer {.role: orchestrator.} =
  ## S/r: connection, target tier, and the KEM slots that run an exchange.
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
  if currentBifrostConfig().ameSignedExchanges:
    r.proof = aepSignatures
  ## The peer reads the KEMs back from their ids (see exchange_paths.nim,
  ## "ids on the wire"); take the same slots here, so both feed the same
  ## stacks even when a KEM sits in the layout twice.
  r = initAmeExchangeRequest(S.auth.current.layout.kems, r.targetTier,
    canonicalExchangeMask(S.auth.current.layout.kems, r.targetTier.masks.kem,
    S.auth.current.tier.masks.kem, r.exchangeMask), r.params, r.proof)
  if S.pendingExchange.active:
    raise newException(ValueError, "AME already has a pending exchange")
  if S.pendingIncoming.active:
    raise newException(ValueError,
      "AME cannot start an exchange while a peer candidate epoch is pending")
  ## Any selection over the session's layout may be asked for -- more
  ## algorithms, fewer, different ones -- as long as it meets this side's own
  ## minimum. The session's tier path only schedules AUTOMATIC steps; it no
  ## longer limits what either side may request.
  requireAmeRequestPolicy(S, r)
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
  result.signatures = proveExchangeSubject(S, signatureTier, r.proof,
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

proc restoreConfiguredAmeFomkeCache*(S: var AmeSession) {.
    role: actor,
    tag: "cryptoBoundary|fomke|protocol".} =
  ## S: quiescent configured connection whose cache is rebuilt off data paths.
  clearFomkeSendCache(S.fomkeSendCache)
  if S.fomkePregenerationEnabled and not S.fomke.pending.active:
    S.fomkeSendCache = prepareFomkeSendCache(S.fomke,
      S.fomkePregenerationMessages)

proc cancelAmeSessionExchange*(S: var AmeSession) {.role: actor.} =
  ## S: outgoing exchange cancelled and trigger returned to the due queue.
  if S.path.inFlightTierId != 0'u32:
    releaseAmeTier(S.path)
  clearPendingExchange(S.pendingExchange)
  clearFomkeState(S.fomkeCandidate)
  S.fomkeCandidateActive = false
  cancelFomkeUpgrade(S.fomke)
  restoreConfiguredAmeFomkeCache(S)

proc exchangeSubjectProved(S: AmeSession, t: AmeMaskTier,
    p: AmeExchangeProof, subject: openArray[uint8],
    P: openArray[ByteSeq]): bool {.role: parser,
    tag: "cryptoBoundary|exchange|validation".} =
  ## S/t/p/subject/P: the peer's proof of kind `p` over one offer or reply.
  ## aepFrame carries none: anything in P is refused.
  if p == aepFrame:
    return P.len == 0
  result = verifyAmeTier(S.auth.current.layout, t, subject,
    activeAmeSignatureKeys(S.auth.current.layout, t,
      S.auth.peerSignaturePublicKeys), P)

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
  ## The frame layer answers a refusable request with a deny before it gets
  ## here (`ameExchangeDenyReason`); a direct caller gets the same rule as an
  ## error.
  requireAmeRequestPolicy(S, o.request)
  validateAmeTierTransition(S.auth.current.layout, S.auth.current.tier,
    o.request.targetTier, o.request.exchangeMask,
    S.auth.current.exchange.activeMask)
  signatureTier = transitionAmeSignatureTier(S.auth.current.layout,
    S.auth.current.tier, o.request.targetTier)
  if not exchangeSubjectProved(S, signatureTier, o.request.proof,
      encodeAmeExchangeOfferSubject(o), o.signatures):
    raise newException(ValueError, "AME exchange offer proof is invalid")
  answer = answerAmeExchangeOffer(S.auth.current.layout.kems, o)
  answer.reply.signatures = proveExchangeSubject(S, signatureTier, o.request.proof,
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

proc refreshAmeFrameKeys*(S: var AmeSession) {.role: actor,
    tag: "ame|cryptoBoundary|kdf".} =
  ## S: the per-frame side keys rebuilt for whatever epoch is now current:
  ##
  ##   key pair        used for
  ##   --------------  ---------------------------------------------
  ##   headerKey*      masking the frame counter (header_protection)
  ##   routeKey*       sealing a route frame's ids (route_block)
  ##
  ## Must be called wherever `auth.current` changes. The keys are bound to the
  ## epoch id, so a stale pair produces a mask the peer cannot reproduce and
  ## every frame fails to open -- loudly, which is the right way for this to
  ## go wrong if a future rotation path forgets to call it.
  var
    outbound: ByteSeq = ameEpochKeyContext(S.auth.current, S.auth.sessionId,
      outboundAmeDirection(S.auth.endpointRole))
    inbound: ByteSeq = ameEpochKeyContext(S.auth.current, S.auth.sessionId,
      inboundAmeDirection(S.auth.endpointRole))
  secureClearAmeBytes(S.headerKeySend)
  secureClearAmeBytes(S.headerKeyRecv)
  secureClearAmeBytes(S.routeKeySend)
  secureClearAmeBytes(S.routeKeyRecv)
  S.headerKeySend = deriveAmeHeaderKey(S.auth.current.exchange,
    S.auth.current.layout, S.auth.current.tier, outbound)
  S.headerKeyRecv = deriveAmeHeaderKey(S.auth.current.exchange,
    S.auth.current.layout, S.auth.current.tier, inbound)
  S.routeKeySend = deriveAmeRouteKey(S.auth.current.exchange,
    S.auth.current.layout, S.auth.current.tier, outbound)
  S.routeKeyRecv = deriveAmeRouteKey(S.auth.current.exchange,
    S.auth.current.layout, S.auth.current.tier, inbound)
  secureClearAmeBytes(outbound)
  secureClearAmeBytes(inbound)

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
  refreshAmeFrameKeys(S)

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
  if not exchangeSubjectProved(S, signatureTier, r.request.proof,
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
  refreshAmeFrameKeys(S)
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

## ╭⟢ saying no
##
## Either side may ask for any change at any time. The answer is one of two
## frames, and the requester sends nothing until one has arrived:
##
##   requester                                   responder
##     |--- request (offer) ----------------------->|
##     |    [sends nothing now]                     |  acceptable?
##     |<-- reply ---------------------------------|  yes: stages the switch
##     |--- epoch-ready (first NEW message) ------>|  both now on the new
##     |                                            |  algorithms
##   or
##     |<-- deny (reason) -------------------------|  no: nothing changes
##     |    back to normal on the OLD algorithms    |
##
## Only a request the responder can read and prove is answered at all; a
## deny is for honest requests this side does not want (its minimum) or
## cannot run (a selection that breaks the rules), so a requester never
## waits on a request that was silently dropped.

proc ameExchangeDenyReason*(S: AmeSession, o: AmeExchangeOffer): string {.
    role: parser.} =
  ## S/o: an incoming request -> "" when this side will switch to it, else
  ## the reason it answers with a deny instead.
  result = ameRequestPolicyError(S, o.request)
  if result.len > 0:
    return
  try:
    validateAmeTierTransition(S.auth.current.layout, S.auth.current.tier,
      o.request.targetTier, o.request.exchangeMask,
      S.auth.current.exchange.activeMask)
  except ValueError as e:
    result = e.msg

proc denyAmeSessionExchange*(S: var AmeSession, requestId: uint32,
    reason: string) {.role: actor.} =
  ## S/requestId/reason: the peer refused this side's request. The request
  ## is dropped, the current algorithms stay, and sending is allowed again.
  if not S.pendingExchange.active or
      S.pendingExchange.offer.requestId != requestId:
    raise newException(ValueError, "AME deny does not match the pending request")
  cancelAmeSessionExchange(S)
  S.lastExchangeDenial = reason

