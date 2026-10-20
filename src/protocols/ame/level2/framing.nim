## -------------------------------------------------------------------------
## AME Framing <- conversations made of frames, and sending one safely
## -------------------------------------------------------------------------
##
## `seal_open.nim` turns one message into one frame and back. This file
## strings frames together into the conversations a session has with its
## peer:
##
##   the exchange steps     begin -> answer -> finish -> confirm
##   sending one frame      seal (undoable), then write (never undone)
##   session-id rotation    the three notices that change the wire label
##
##   framing.nim  --imports and passes on-->  seal_open.nim  -->  session.nim
##                                         +  requests.nim
##
## Import this file to seal, open, or exchange: it passes on everything the
## two files below it offer.

import ../../types
import ../types
import ../level0/bytes
import ../level1/exchange_paths
import ../level1/suites
import ../level1/symmetric
import ./session
import ../../fomke/types
import ../../fomke/level1/chain
import ../../fomke/level2/wire
import runePragmas
import ./seal_open
import ./requests

export seal_open
export requests

type
  ## AmeSendRollback: what a send has to be able to put back.
  ## Sealing a frame advances three things at once -- the sequence, the tier
  ## path and its last trigger -- and a SEAL that fails halfway must leave
  ## none of them moved. Never used after a write has started (see
  ## "sending one frame"). Private to this file.
  AmeSendRollback {.role: memory.} = object
    nextAmeSequence: uint32
    path: AmeTierPath
    lastTrigger: AmeTierStep

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

## ╭⟢ the four exchange steps, one body each
##
## TCP and DAC carry the same four steps; only the carrier differs, so each
## step is written once and the carrier is a parameter. The public names
## below (`beginAmeTcpExchangeFrame`, `...Dac...`) are one-line wrappers.
##
##   step      who         sends / reads                      frame kind
##   --------  ----------  ---------------------------------  --------------
##   begin     requester   request (offer)                    ExchangeKeys
##   answer    responder   reply, or a deny                   ExchangeEnvelopes
##                                                            / ExchangeDeny
##   finish    requester   reads the answer; on a reply it    EpochReady
##                         switches and sends epoch-ready;
##                         on a deny it sends nothing
##   confirm   responder   reads epoch-ready, switches        -
##
## Deny body:  requestId u32 | baseEpoch u32 | reason length u16 | reason
##             (UTF-8, at most 256 bytes)

const
  ameDenyReasonMax: int = 256
    ## Longest reason a deny carries; longer ones are cut.

proc encodeExchangeDeny(requestId, baseEpoch: uint32,
    reason: string): ByteSeq {.role: dataWriter.} =
  ## requestId/baseEpoch/reason: the refused request and why.
  var
    text: string = reason[0 ..< min(reason.len, ameDenyReasonMax)]
  appendAmeU32(result, requestId)
  appendAmeU32(result, baseEpoch)
  result.add(uint8(text.len and 0xff))
  result.add(uint8(text.len shr 8))
  for c in text:
    result.add(uint8(ord(c)))

proc decodeExchangeDeny(A: openArray[uint8]): tuple[requestId,
    baseEpoch: uint32, reason: string] {.role: parser.} =
  ## A: deny body -> its fields; a malformed body is refused.
  var
    n: int = 0
  if A.len < 10:
    raise newException(ValueError, "AME exchange deny is truncated")
  result.requestId = readU32(A, 0)
  result.baseEpoch = readU32(A, 4)
  n = int(A[8]) or (int(A[9]) shl 8)
  if n > ameDenyReasonMax or A.len != 10 + n:
    raise newException(ValueError, "AME exchange deny length mismatch")
  for b in A[10 ..< 10 + n]:
    result.reason.add(char(b))

proc beginAmeExchangeFrameVia(S: var AmeSession, r: AmeExchangeRequest,
    carrier: AmeCarrier): ByteSeq {.role: orchestrator.} =
  ## S/r/carrier: requester seals its request under the current epoch. From
  ## here until the answer, this side sends nothing else.
  var
    o: AmeExchangeOffer = beginAmeSessionExchange(S, r)
  S.lastExchangeDenial = ""
  result = sealControlFrame(S, ampkExchangeKeys, carrier,
    encodeAmeExchangeOffer(o))

proc answerAmeExchangeFrameVia(S: var AmeSession, frame: openArray[uint8],
    carrier: AmeCarrier): ByteSeq {.role: orchestrator.} =
  ## S/frame/carrier: responder answers a request -- a reply that stages the
  ## switch, or a deny that changes nothing. Check `S.pendingIncoming.active`
  ## afterwards: true means a reply went out and epoch-ready will follow.
  var
    opened = openControlFrame(S, frame, ampkExchangeKeys, carrier)
    offer: AmeExchangeOffer = default(AmeExchangeOffer)
    reply: AmeExchangeReply = default(AmeExchangeReply)
    reason: string = ""
  if not opened.ok:
    raise newException(ValueError, opened.err)
  offer = decodeAmeExchangeOffer(S.auth.current.layout.kems,
    S.auth.current.tier.masks.kem, opened.payload)
  reason = ameExchangeDenyReason(S, offer)
  if reason.len > 0:
    return sealControlFrame(S, ampkExchangeDeny, carrier,
      encodeExchangeDeny(offer.requestId, offer.baseEpochId, reason))
  reply = answerAmeSessionExchange(S, offer)
  result = sealControlFrame(S, ampkExchangeEnvelopes, carrier,
    encodeAmeExchangeReply(reply))
  stageAmeSessionFomkeUpgrade(S)

proc encodeEpochReady(requestId, epochId: uint32, targetTier: AmeMaskTier,
    fomkeCommit: FomkeUpgradeCommit = default(FomkeUpgradeCommit)): ByteSeq {.
    role: dataWriter.} =
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

proc controlFrameKind(S: AmeSession, frame: openArray[uint8]): AmePacketKind {.
    role: parser.} =
  ## S/frame: the packet kind in a frame's header, read without opening its
  ## body (and without changing S), so an answer can be told apart.
  result = decodeProtectedFrame(S, frame).header.packetKind

proc finishDeniedExchange(S: var AmeSession, frame: openArray[uint8],
    carrier: AmeCarrier) {.role: orchestrator.} =
  ## S/frame/carrier: requester reads a deny and drops its request.
  var
    opened = openControlFrame(S, frame, ampkExchangeDeny, carrier)
    deny: tuple[requestId, baseEpoch: uint32, reason: string] = (
      requestId: 0'u32, baseEpoch: 0'u32, reason: "")
  if not opened.ok:
    raise newException(ValueError, opened.err)
  deny = decodeExchangeDeny(opened.payload)
  denyAmeSessionExchange(S, deny.requestId, deny.reason)

proc finishAmeExchangeFrameVia(S: var AmeSession, frame: openArray[uint8],
    carrier: AmeCarrier): ByteSeq {.role: orchestrator.} =
  ## S/frame/carrier: requester reads the answer. A reply: switch, and return
  ## epoch-ready -- the first message under the new algorithms. A deny:
  ## return nothing (empty), stay on the old algorithms; the reason is in
  ## `S.lastExchangeDenial`. Either way this side may send again afterwards.
  var
    opened: AmeControlOpened = default(AmeControlOpened)
    requestId: uint32 = 0'u32
    fomkeCommit: FomkeUpgradeCommit = default(FomkeUpgradeCommit)
  if controlFrameKind(S, frame) == ampkExchangeDeny:
    finishDeniedExchange(S, frame, carrier)
    return
  opened = openControlFrame(S, frame, ampkExchangeEnvelopes, carrier)
  if not opened.ok:
    raise newException(ValueError, opened.err)
  requestId = S.pendingExchange.offer.requestId
  finishAmeSessionExchange(S,
    decodeAmeExchangeReply(S.auth.current.layout.kems,
      S.auth.current.tier.masks.kem, opened.payload))
  ## The ratchet turns BEFORE this frame is sealed, so epoch-ready is the
  ## first message of the new epoch. That is what lets the responder tell a
  ## genuine rotation from a replayed one: it can only open this frame with a
  ## ratchet it derived itself from the same exchange.
  fomkeCommit = S.fomke.pending.commit
  confirmFomkeUpgrade(S.fomke, fomkeCommit)
  ## The new epoch may have agreed a different tag length. The envelope no
  ## longer states one, so the ratchet has to be moved onto it here or the
  ## two sides would split the tag at different offsets.
  S.fomke.tagLen = S.auth.current.params.authTagLen
  result = sealControlFrame(S, ampkEpochReady, carrier,
    encodeEpochReady(requestId, S.auth.current.epochId,
      S.auth.current.tier, fomkeCommit))
  restoreConfiguredAmeFomkeCache(S)

proc confirmAmeExchangeFrameVia(S: var AmeSession, frame: openArray[uint8],
    carrier: AmeCarrier) {.role: orchestrator.} =
  ## S/frame/carrier: responder authenticates epoch-ready with its candidate
  ## key and switches.
  var
    opened = openControlFrame(S, frame, ampkEpochReady, carrier,
      useCandidate = true)
    ready: tuple[requestId, epochId: uint32, targetTier: AmeMaskTier,
      fomkeCommit: FomkeUpgradeCommit] = (requestId: 0'u32, epochId: 0'u32,
      targetTier: default(AmeMaskTier),
      fomkeCommit: default(FomkeUpgradeCommit))
  if not opened.ok:
    raise newException(ValueError, opened.err)
  ready = decodeEpochReady(S.auth.current.layout, opened.payload)
  confirmAmeSessionExchange(S, ready.requestId, ready.epochId,
    ready.targetTier, ready.fomkeCommit)

proc beginAmeTcpExchangeFrame*(S: var AmeSession,
    r: AmeExchangeRequest): ByteSeq {.role: orchestrator.} =
  ## S/r: requester, TCP. See `beginAmeExchangeFrameVia`.
  result = beginAmeExchangeFrameVia(S, r, acrTcp)

proc answerAmeTcpExchangeFrame*(S: var AmeSession,
    frame: openArray[uint8]): ByteSeq {.role: orchestrator.} =
  ## S/frame: responder, TCP. See `answerAmeExchangeFrameVia`.
  result = answerAmeExchangeFrameVia(S, frame, acrTcp)

proc finishAmeTcpExchangeFrame*(S: var AmeSession,
    frame: openArray[uint8]): ByteSeq {.role: orchestrator.} =
  ## S/frame: requester, TCP. See `finishAmeExchangeFrameVia`.
  result = finishAmeExchangeFrameVia(S, frame, acrTcp)

proc confirmAmeTcpExchangeFrame*(S: var AmeSession,
    frame: openArray[uint8]) {.role: orchestrator.} =
  ## S/frame: responder, TCP. See `confirmAmeExchangeFrameVia`.
  confirmAmeExchangeFrameVia(S, frame, acrTcp)

proc beginAmeDacExchangeFrame*(S: var AmeSession,
    r: AmeExchangeRequest): ByteSeq {.role: orchestrator.} =
  ## S/r: requester, DAC. See `beginAmeExchangeFrameVia`.
  result = beginAmeExchangeFrameVia(S, r, acrDac)

proc answerAmeDacExchangeFrame*(S: var AmeSession,
    frame: openArray[uint8]): ByteSeq {.role: orchestrator.} =
  ## S/frame: responder, DAC. See `answerAmeExchangeFrameVia`.
  result = answerAmeExchangeFrameVia(S, frame, acrDac)

proc finishAmeDacExchangeFrame*(S: var AmeSession,
    frame: openArray[uint8]): ByteSeq {.role: orchestrator.} =
  ## S/frame: requester, DAC. See `finishAmeExchangeFrameVia`.
  result = finishAmeExchangeFrameVia(S, frame, acrDac)

proc confirmAmeDacExchangeFrame*(S: var AmeSession,
    frame: openArray[uint8]) {.role: orchestrator.} =
  ## S/frame: responder, DAC. See `confirmAmeExchangeFrameVia`.
  confirmAmeExchangeFrameVia(S, frame, acrDac)

proc captureAmeSendRollback(S: AmeSession): AmeSendRollback {.role: helper.} =
  ## S: connection whose send-mutable counters are snapshotted before a seal.
  ## Only these fields change while sealing and accounting for one frame, so a
  ## failed send is undone without copying epoch secrets or the inbox.
  result.nextAmeSequence = S.nextAmeSequence
  result.path = S.path
  result.lastTrigger = S.lastTrigger

proc restoreAmeSend(S: var AmeSession, r: AmeSendRollback,
    fomke: var FomkeState, cache: var FomkeSendCache) {.
    role: actor.} =
  ## S/r/fomke/cache: failed seal rewound to its pre-seal counters and to its
  ## pre-seal ratchet. The advanced ratchet is erased
  ## before the saved one replaces it.
  S.nextAmeSequence = r.nextAmeSequence
  S.path = r.path
  S.lastTrigger = r.lastTrigger
  clearFomkeSendCache(S.fomkeSendCache)
  clearFomkeState(S.fomke)
  S.fomke = move(fomke)
  S.fomkeSendCache = move(cache)

proc discardAmeSendRollback(S: AmeSession, fomke: var FomkeState,
    cache: var FomkeSendCache) {.role: actor.} =
  ## S/fomke/cache: successful seal erases the superseded FOMKE ratchet copy
  ## instead of releasing its storage unwiped.
  clearFomkeSendCache(cache)
  clearFomkeState(fomke)

## ╭⟢ sending one frame: what may be undone, and what never
##
## A send is two steps, and only the first may ever be taken back:
##
##   1. seal    ratchet step n -> key n + nonce n -> sealed frame
##              nothing has left the machine yet
##   2. write   the frame goes to the socket
##              from the first byte on, an observer may hold it
##
## Undoing step 1 is safe: nobody saw key n in use. Undoing step 2 is not.
## The next message would be sealed with key n and nonce n AGAIN, and two
## different messages under one key + nonce give an observer their XOR:
##
##   C1 = "PAY 100€" XOR stream(n)      (half on the wire, then an error)
##   C2 = "hello"    XOR stream(n)      (after a rewind)
##   C1 XOR C2 = "PAY 100€" XOR "hello" -- the key cancels out
##
## So a failed WRITE never rewinds. What happens instead depends on the
## carrier:
##
##   failure                         what happens
##   ------------------------------  -----------------------------------------
##   while sealing / before 1st byte rewind (`ameSealTransaction`)
##   TCP write                       step n is given up, the connection is
##                                   closed, `AmeConnectionLost` is raised:
##                                   a half-written stream cannot be read
##                                   past, and TCP refuses a sequence gap
##   DAC write                       the sealed bytes are kept; the next send
##                                   writes THOSE EXACT BYTES first (the same
##                                   bytes again leak nothing). Give them up
##                                   with `discardAmeUnsentFrame`.

type
  AmeConnectionLost* = object of IOError
    ## A write failed after the frame was sealed. The stream is closed; the
    ## session cannot go on over it. Reconnect with a new handshake.

template ameSealTransaction*(S: var AmeSession, body: untyped) {.
    role: orchestrator.} =
  ## S/body: `body` SEALS one frame and checks it can be written -- it must
  ## never write to the network. If it raises, the sequence, the tier path
  ## and the FOMKE ratchet are rewound, so a failed seal leaves no
  ## half-advanced state. On success the superseded ratchet copy is erased.
  var
    rollback: AmeSendRollback = captureAmeSendRollback(S)
    fomke: FomkeState = cloneFomkeState(S.fomke)
    cache: FomkeSendCache = cloneFomkeSendCache(S.fomkeSendCache)
  try:
    body
  except:
    restoreAmeSend(S, rollback, fomke, cache)
    raise
  discardAmeSendRollback(S, fomke, cache)

proc keepAmeUnsentFrame*(S: var AmeSession, frame: openArray[uint8],
    payloadLen: int) {.role: actor.} =
  ## S/frame/payloadLen: a sealed datagram whose write failed. Kept so the
  ## next send writes these exact bytes instead of sealing at step n again.
  secureClearAmeBytes(S.unsentFrame)
  S.unsentFrame = @frame
  S.unsentPayloadLen = payloadLen

proc sentAmeUnsentFrame*(S: var AmeSession) {.role: actor.} =
  ## S: the kept frame went out; account for it and forget it.
  discard recordTransferredBytes(S, uint64(S.unsentPayloadLen))
  secureClearAmeBytes(S.unsentFrame)
  S.unsentFrame = @[]
  S.unsentPayloadLen = 0

proc ameHasUnsentFrame*(S: AmeSession): bool {.role: parser.} =
  ## S: true while a sealed datagram waits to be written again.
  result = S.unsentFrame.len > 0

proc discardAmeUnsentFrame*(S: var AmeSession) {.role: actor.} =
  ## S: give the kept frame up. Its ratchet step stays used -- the receiver
  ## sees a lost message and steps past it.
  secureClearAmeBytes(S.unsentFrame)
  S.unsentFrame = @[]
  S.unsentPayloadLen = 0

## ╭⟢ rotating the session id 🌊
##
## The session id is eight bytes in the clear on every single frame, and until
## now it never changed. With the sequence number masked it became the last
## field that links a conversation to itself:
##
##   what an observer sees          before        after masking the counter
##   -------------------------      -----------   --------------------------
##   sequence                       0,1,2,3...    noise
##   session id                     same, always  same, always   <- this one
##
## For a relay that matters most of all. Traffic going into the relay and
## traffic coming out of it carry the same id, so anyone watching both sides
## can pair them up without touching a single encrypted byte.
##
## So the id is rotated, and the exchange is three frames:
##
##   requester                             responder
##   ---------                             ---------
##   SessionIdRequest  ------------------>
##                                         picks an id nothing else is using
##                     <------------------ SessionIdAssign (new id inside)
##   adopts the new id                     adopts the new id
##
## Both frames are sealed under the OLD id, because that is the only id both
## sides share while the exchange is in flight. Each side switches only after
## the assign frame is safely sealed or safely opened.
##
## ┊ Why this does not change any key ┊
##
## There are two session ids and it is worth being clear about which is which:
##
##   auth.sessionId   the CRYPTOGRAPHIC identity. Agreed at the handshake,
##                    mixed into every derived key, and never rotated.
##   sessionId        the id written into the header. A label for routing and
##                    demultiplexing, and the one that rotates.
##
## Rotating the label therefore re-derives nothing. Every traffic key, the
## header keys and any sealed package stay exactly as they were. The label is
## still authenticated -- it is part of the header, and the header is part of
## the tag -- so nobody can edit it in flight either.

proc deriveAmeSessionIdCandidate*(S: AmeSession,
    attempt: uint32 = 0'u32): uint64 {.role: truthBuilder,
    tag: "ame|cryptoBoundary|kdf".} =
  ## S/attempt: an id no observer can predict, for the side that assigns one.
  ##
  ## Derived from this side's header key rather than drawn from a random
  ## source. Two reasons: the value has to be unpredictable to anyone without
  ## the keys, which a key-derived value is by construction; and a protocol
  ## that needs no entropy source is one less thing to get wrong on a small
  ## device that may not have a good one.
  ##
  ## `attempt` exists because the assigning side owns the id space and has to
  ## avoid handing out one it is already using for somebody else. It bumps the
  ## input to get a different answer, and does not have to be kept.
  var
    seed: ByteSeq = @[]
    digest: ByteSeq = @[]
    i: int = 0
  appendAmeLabel(seed, "AME-SESSION-ID-v1")
  appendAmeU64(seed, S.auth.sessionId)
  appendAmeU32(seed, S.auth.current.epochId)
  appendAmeU32(seed, attempt)
  appendAmeU64(seed, S.sessionId)
  digest = blake3AmeMac(S.headerKeySend, seed, 16)
  while i < 8:
    result = result or (uint64(digest[i]) shl (8 * i))
    i = i + 1
  secureClearAmeBytes(seed)
  secureClearAmeBytes(digest)
  ## Zero is not an id -- it is what an unset field reads as, and
  ## `acceptsSessionId` uses that to tell "no previous id" from a real one.
  if result == 0'u64:
    result = 1'u64

proc adoptAmeSessionId(S: var AmeSession, next: uint64) {.role: actor,
    tag: "ame|protocol".} =
  ## S/next: the new label taken up, with the old one kept for arrivals only.
  if next == 0'u64:
    raise newException(ValueError, "AME session id must be positive")
  if next == S.sessionId:
    raise newException(ValueError, "AME session id did not change")
  S.previousSessionId = S.sessionId
  S.previousSessionIdFramesLeft = ameSessionIdGraceFrames
  S.sessionId = next

proc beginAmeSessionIdRotation*(S: var AmeSession,
    carrier: AmeCarrier = acrDac): ByteSeq {.role: orchestrator,
    tag: "appApi|ame|protocol".} =
  ## S/carrier: ask the other side for a new label. Nothing changes here yet;
  ## this side keeps sealing under the id it has until the answer arrives.
  result = sealControlFrame(S, ampkSessionIdRequest, carrier, @[])

proc answerAmeSessionIdRotation*(S: var AmeSession, frame: openArray[uint8],
    carrier: AmeCarrier = acrDac, assigned: uint64 = 0'u64): ByteSeq {.
    role: orchestrator, tag: "appApi|ame|protocol".} =
  ## S/frame/carrier: the request, opened and answered.
  ## assigned: the id to hand out. Zero means "derive one", which is right for
  ##   a single session; a server holding many at once passes its own choice
  ##   so it can be sure the id is free.
  ##
  ## The answer is sealed BEFORE this side switches, so it travels under the
  ## id the requester still knows.
  var
    opened: AmeControlOpened = default(AmeControlOpened)
    next: uint64 = assigned
    body: ByteSeq = @[]
  opened = openControlFrame(S, frame, ampkSessionIdRequest, carrier)
  if not opened.ok:
    raise newException(ValueError, opened.err)
  if next == 0'u64:
    next = deriveAmeSessionIdCandidate(S)
  appendAmeU64(body, next)
  result = sealControlFrame(S, ampkSessionIdAssign, carrier, body)
  adoptAmeSessionId(S, next)

proc finishAmeSessionIdRotation*(S: var AmeSession, frame: openArray[uint8],
    carrier: AmeCarrier = acrDac): uint64 {.role: orchestrator,
    tag: "appApi|ame|protocol".} =
  ## S/frame/carrier: the assignment, opened and taken up. Returns the id this
  ## side now answers to.
  var
    opened: AmeControlOpened = default(AmeControlOpened)
    i: int = 0
  opened = openControlFrame(S, frame, ampkSessionIdAssign, carrier)
  if not opened.ok:
    raise newException(ValueError, opened.err)
  if opened.payload.len != 8:
    raise newException(ValueError, "AME session id assignment is malformed")
  while i < 8:
    result = result or (uint64(opened.payload[i]) shl (8 * i))
    i = i + 1
  adoptAmeSessionId(S, result)
