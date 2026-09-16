## -------------------------------------------------------------------------
## AME Framing <- wrapping a message up, and getting it back out
## -------------------------------------------------------------------------
##
## `session.nim` next door owns WHAT a connection is: its keys, its epoch,
## what it is allowed to change. This file owns the other half -- WHAT ONE
## MESSAGE LOOKS LIKE on the wire, and it is the only place in AME that turns
## bytes into a frame or a frame back into bytes.
##
## ╭─ ❧ one frame, from the outside in 🌊
##
##   +--------------------- what leaves the machine ----------------------+
##   |  AME header (26 bytes)  |  FOMKE envelope (13) | tag | ciphertext  |
##   +-------------------------+-------------------------------------------+
##      who + which lane +          which message          the payload,
##      which sequence                key                  sealed
##
## Everything past the header is unreadable to anyone without the key. The
## header itself is not secret, but its sequence counter is MASKED -- see
## `level1/header_protection.nim` -- so a watcher cannot count a connection's
## frames or tie two of them together.
##
## ╭─ ❧ the four things that can be inside 🐦‍🔥
##
## Every frame carries one of four kinds of payload, and the kind is part of
## what the tag commits to, so it cannot be changed in flight:
##
##   application bytes   what the caller asked to send
##   an exchange step    the four messages that rotate an epoch
##   a session-id notice the three that rotate the wire label
##   ONE DAC MESSAGE     this is the AME/DAC seam -- see below
##
## ╭─ ❧ where DAC meets AME ⟡
##
## DAC frames nothing. Not one byte of DAC ever travels on its own. When the
## DAC loop decides to send an ACK, a repair hint, a parity shard or a whole
## package chunk, it hands over a KIND and a BODY, and `sealAmeDacControl`
## puts the kind in front of the body and seals the pair:
##
##   the DAC loop says:   dmkAckRange + <14 bytes of receipt>
##                                |
##                                v
##   sealAmeDacControl()  [ 0x05 | 14 bytes of receipt ]   <- one plaintext
##                                |
##                                v
##                        AME header | FOMKE | tag | ciphertext
##                                |
##                                v
##                        one datagram on the wire
##
## The kind is the FIRST BYTE OF THE PLAINTEXT, not a field in the header.
## Two things follow from that, and both are the point:
##
##   an observer cannot tell an ACK from a repair hint, because the byte
##     that says which is encrypted along with everything else
##   a peer cannot forge one, because changing that byte breaks the tag and
##     `openAmeDacControl` never gets far enough to read it
##
## So the DAC loop is only ever handed kinds that authenticated. There used
## to be a second road -- a bare `DAC1` frame with the kind in a plain header
## that nobody had checked -- and it is gone.
##
## ╭─ ❧ protecting one frame 🍣
##
## There is exactly one construction on this path and it runs exactly once:
##
##   plaintext --> FOMKE envelope --> AME frame
##                 (ciphertext+tag)   (26-byte header + that envelope)
##
## The header is written FIRST, because it is the thing the tag commits to.
## Its payload length is worked out ahead of the seal, which is possible
## because every cipher in the layout is keystream XOR: the ciphertext is
## exactly as long as the plaintext, so the envelope size is arithmetic, not
## a guess.

import protocols/containers/circ_seq as circ_seq

import ../../types
import ../../transport/types as transport_types
import ../types
import ../level0/bytes
import ../level1/exchange_paths
import ../level1/suites
import ../level1/symmetric
import ../level1/path_triggers
import ../level1/padding
import ../level1/header_protection
import ./wire
import ./session
import ../../fomke/types
import ../../fomke/level0/gb3hkdf
import ../../fomke/level1/chain
import ../../fomke/level2/wire
import ../../config
import ../../dac/types
import ../../dac/level0/wire_helpers
import ../../dac/level0/defaults as dac_defaults
import runePragmas

## Everything a caller reached for through `session` still reaches through
## here, so a module that seals frames imports this one and gets both halves.
export session

type
  ## AmeSendRollback: what a send has to be able to put back.
  ## Sealing a frame advances three things at once -- the sequence, the tier
  ## path and its last trigger -- and a send that fails halfway must leave
  ## none of them moved. Private to this file, because sealing is the only
  ## thing that ever needs to undo itself.
  AmeSendRollback {.role: memory.} = object
    nextAmeSequence: uint32
    path: AmeTierPath
    lastTrigger: AmeTierStep

proc readU32(A: openArray[uint8], o: int): uint32 {.role: parser.} =
  ## A/o: source bytes and little-endian offset.
  result = uint32(A[o]) or (uint32(A[o + 1]) shl 8) or
    (uint32(A[o + 2]) shl 16) or (uint32(A[o + 3]) shl 24)

proc requireFrameBodyFits(S: AmeSession, payloadLen: int, what: string) {.
    role: parser.} =
  ## S/payloadLen/what: refuse an oversized payload before anything is sealed.
  ## The frame carries no length field any more, so this is not about a field
  ## overflowing -- it is about not handing a peer a frame it must refuse.
  var
    n: int = 0
  if payloadLen < 0:
    raise newException(ValueError, "AME " & what & " length is negative")
  n = fomkeWireLen(payloadLen, S.fomke.tagLen)
  if n > defaultAmeMaxFrameBytes - ameFrameHeaderLen:
    raise newException(ValueError, "AME " & what & " exceeds maximum")

proc frameFlags(S: AmeSession): uint8 {.role: parser.} =
  ## S: session whose epoch decides what the header must announce about the
  ## payload. One flag today: whether the body was padded before sealing.
  if S.auth.current.params.padding != apadNone:
    result = ameFrameFlagPadded

proc padFramePayload(S: AmeSession,
    payload: openArray[uint8]): ByteSeq {.role: encryptor.} =
  ## S/payload: plaintext rounded up to whole blocks when this epoch says so.
  ## Done before the header is built, because the header states the sealed
  ## length and that length must already include the padding.
  result = padAmeMessage(payload, S.auth.current.params.padding)

proc buildAad(carrier: AmeCarrier,
    h: AmeFrameHeader): ByteSeq {.role: truthBuilder.} =
  ## carrier/h: transport and the whole frame header, bound into the tag.
  ## Everything a receiver reads before it can pick keys is in here, so a
  ## header field edited in flight makes the body fail to open.
  appendAmeLabel(result, "AME-AAD-v2")
  result.add(uint8(ord(carrier)))
  appendAmeBytes(result, encodeAmeFrameHeader(h))

proc encodeProtectedFrame(S: AmeSession, h: AmeFrameHeader,
    body: openArray[uint8]): ByteSeq {.role: dataWriter,
    tag: "ame|cryptoBoundary|wire".} =
  ## S/h/body: one finished frame, with its counter masked on the way out.
  ##
  ## The header goes into the tag with the TRUE sequence and is masked only
  ## afterwards, so the number the tag commits to and the number on the wire
  ## are deliberately different. A receiver undoes the mask first and then
  ## computes the same tag input this side did.
  result = encodeAmeFrame(h, body)
  maskAmeFrameHeader(result, S.headerKeySend)

proc recvHeaderKey(S: AmeSession, useCandidate: bool = false): ByteSeq {.
    role: parser, tag: "ame|cryptoBoundary".} =
  ## S/useCandidate: which epoch's header key an arriving frame was masked
  ## with.
  ##
  ## Almost always the current epoch's. The exception is epoch-ready, which
  ## the peer seals as the FIRST frame of the epoch it is asking this side to
  ## move to -- so it is the one frame whose counter was masked with a key
  ## `auth.current` cannot produce yet. The candidate epoch can, and this side
  ## has already built it in order to open the body at all.
  ##
  ## Falling back when there is no candidate is not a silent pass: the frame
  ## then unmasks to the wrong sequence, that wrong number goes into the tag
  ## input, and the open fails with the message the caller expects.
  if not useCandidate or S.pendingIncoming.candidate.epochId == 0'u32:
    return S.headerKeyRecv
  result = deriveAmeHeaderKey(S.pendingIncoming.candidate.exchange,
    S.pendingIncoming.candidate.layout, S.pendingIncoming.candidate.tier,
    ameEpochKeyContext(S.pendingIncoming.candidate, S.auth.sessionId,
      inboundAmeDirection(S.auth.endpointRole)))

proc decodeProtectedFrame(S: AmeSession, frame: openArray[uint8],
    useCandidate: bool = false): AmeDecodedFrame {.role: parser,
    tag: "ame|cryptoBoundary|parsing".} =
  ## S/frame/useCandidate: one arriving frame, with its counter put back the
  ## way the sender wrote it before anything else looks at it.
  ##
  ## Everything downstream -- the binding checks, the replay window, the tag
  ## itself -- reads `header.sequence`, so this is the only place that needs
  ## to know the number on the wire was ever masked.
  result = decodeAmeFrame(frame)
  result.header.sequence = unmaskedAmeFrameSequence(frame,
    recvHeaderKey(S, useCandidate))

proc sealFrameBody(S: var AmeSession, h: AmeFrameHeader, carrier: AmeCarrier,
    payload: openArray[uint8]): ByteSeq {.role: orchestrator,
    tag: "cryptoBoundary|fomke|protocol".} =
  ## S/h/carrier/payload: one ratchet step turned into one frame body.
  var
    aad: ByteSeq = buildAad(carrier, h)
    message: FomkeMessage = default(FomkeMessage)
  try:
    if fomkePreparedMessages(S.fomkeSendCache) > 0:
      message = sealFomkeMessagePrepared(S.fomke, S.fomkeSendCache, payload,
        aad)
    else:
      message = sealFomkeMessage(S.fomke, payload, aad)
    result = encodeFomkeMessage(message)
  finally:
    secureClearAmeBytes(aad)

proc openFrameBody(S: var AmeSession, f: AmeDecodedFrame,
    carrier: AmeCarrier): tuple[ok: bool, payload: ByteSeq, err: string] {.
    role: orchestrator, tag: "cryptoBoundary|fomke|protocol".} =
  ## S/f/carrier: authenticate and open one frame body.
  ##
  ## There is one ratchet and it is the current one. A frame sealed under the
  ## previous epoch is refused here, and the transport is what recovers it --
  ## DAC rebuilds it from repair shards or asks for it again, TCP retransmits.
  ##
  ## This used to keep the PREVIOUS ratchet alive for a hundred frames as a
  ## second way to open such a frame. It never once ran, because three other
  ## rules each make the situation it was built for impossible:
  ##
  ##   TCP needs an exact sequence, so a held-back frame is a gap and is
  ##     refused before it ever reaches a ratchet
  ##   FOMKE refuses to rotate while a skipped key is outstanding, so a frame
  ##     cannot be held back across the rotation from before it
  ##   FOMKE refuses to seal while an upgrade is pending, so one cannot be
  ##     made after it either
  ##
  ## Keeping a whole second ratchet -- including its cache of skipped keys --
  ## to answer a question the protocol refuses to ask was memory and key
  ## material spent on nothing.
  var
    aad: ByteSeq = @[]
    message: FomkeMessage = default(FomkeMessage)
    opened: FomkeOpenResult = default(FomkeOpenResult)
    padding: AmePaddingPolicy = S.auth.current.params.padding
  ## The envelope carries no tag length, so the split between tag and
  ## ciphertext comes from what THIS epoch agreed.
  aad = buildAad(carrier, f.header)
  try:
    message = decodeFomkeMessage(f.payload, S.fomke.tagLen)
    opened = openFomkeMessage(S.fomke, message, aad)
  except ValueError as exc:
    secureClearAmeBytes(aad)
    result.err = exc.msg
    return
  secureClearAmeBytes(aad)
  if not opened.ok:
    result.err = "AME authentication failed: " & opened.err
    return
  ## The flag and the policy have to say the same thing. Both were bound into
  ## the tag, so a disagreement here is a peer configured differently, never
  ## an attacker: an edited flag bit would already have failed to open.
  if ((f.header.flags and ameFrameFlagPadded) != 0'u8) !=
      (padding != apadNone):
    result.err = "AME frame padding disagrees with the epoch policy"
    return
  try:
    result.payload = unpadAmeMessage(opened.payload, padding)
  except ValueError as exc:
    result.err = exc.msg
    return
  result.ok = true

proc sealAmeTcpFrame*(S: var AmeSession,
    payload: openArray[uint8]): ByteSeq {.role: orchestrator.} =
  ## S/payload: connection and plaintext; transfer accounting occurs after send.
  requireAmeAuth(S.auth)
  requireAmePeerTrust(S)
  if S.nextAmeSequence == high(uint32):
    raise newException(ValueError, "AME send sequence is exhausted")
  var
    body: ByteSeq = padFramePayload(S, payload)
    h: AmeFrameHeader = default(AmeFrameHeader)
  requireFrameBodyFits(S, body.len, "TCP payload")
  h = initAmeFrameHeader(ampkLaneData, S.messageClass, frameFlags(S),
    S.sessionId, S.rootLaneId, S.laneId, S.nextAmeSequence)
  result = encodeProtectedFrame(S, h, sealFrameBody(S, h, acrTcp, body))
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
    body: ByteSeq = padFramePayload(S, payload)
    h: AmeFrameHeader = default(AmeFrameHeader)
  requireFrameBodyFits(S, body.len, "DAC payload")
  h = initAmeFrameHeader(ampkLaneData, S.messageClass, frameFlags(S),
    S.sessionId, S.rootLaneId, S.laneId, S.nextAmeSequence)
  result = encodeProtectedFrame(S, h, sealFrameBody(S, h, acrDac, body))
  S.nextAmeSequence = S.nextAmeSequence + 1'u32


proc acceptsSessionId(S: AmeSession, id: uint64): bool {.role: parser,
    tag: "ame|validation".} =
  ## S/id: the id an arriving frame claims.
  ##
  ## Two ids are answered to, never more: the current one and the one used
  ## before the last rotation, and the second only while frames sealed before
  ## the change could still be in the air.
  if id == S.sessionId:
    return true
  result = S.previousSessionIdFramesLeft > 0 and id == S.previousSessionId and
    id != 0'u64

proc consumeSessionIdGrace(S: var AmeSession) {.role: actor,
    tag: "ame|protocol".} =
  ## S: connection whose old session id expires as frames go by.
  if S.previousSessionIdFramesLeft <= 0:
    return
  S.previousSessionIdFramesLeft = S.previousSessionIdFramesLeft - 1
  if S.previousSessionIdFramesLeft > 0:
    return
  S.previousSessionId = 0'u64
  S.previousSessionIdFramesLeft = 0

proc validateFrameBinding(S: AmeSession, f: AmeDecodedFrame,
    expected: AmePacketKind): string {.role: parser.} =
  ## S/f/expected: expected connection identity and the packet kind this path
  ## accepts. One header carries the identity now, so there is no second one to
  ## agree with.
  if f.header.packetKind != expected:
    return "AME expected lane data"
  if f.header.messageClass != S.messageClass or
      not acceptsSessionId(S, f.header.sessionId) or
      f.header.rootLaneId != S.rootLaneId or
      f.header.laneId != S.laneId:
    return "AME frame binding mismatch"

proc replayAccept(W: var AmeReplayWindow, sequence: uint32): bool {.
    role: actor.} =
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
  ##
  ## Order matters here. The body is authenticated BEFORE the sequence is
  ## looked at, so a forged frame carrying a wild sequence number cannot push
  ## the replay window forward and make honest frames get dropped.
  var
    err: string = amePeerTrustError(S)
    opened: tuple[ok: bool, payload: ByteSeq, err: string] = (
      ok: false, payload: @[], err: "")
  if err.len == 0:
    err = validateFrameBinding(S, f, ampkLaneData)
  if err.len > 0:
    result.err = err
    S.lastErr = err
    return
  opened = openFrameBody(S, f, carrier)
  if not opened.ok:
    result.err = opened.err
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
  result.ok = true
  result.packet.payload = opened.payload
  result.packet.carrier = carrier
  result.packet.remoteDac = remoteDac
  result.packet.remoteTcp = remoteTcp
  result.packet.sessionId = f.header.sessionId
  result.packet.rootLaneId = f.header.rootLaneId
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
  consumeSessionIdGrace(S)
  circ_seq.push(S.inbox, result.packet)
  S.lastErr = ""

proc openAmeTcpFrame*(S: var AmeSession, frame: openArray[uint8],
    remote: transport_types.TcpAddress = default(transport_types.TcpAddress)):
    AmeOpenResult {.role: orchestrator.} =
  ## S/frame/remote: TCP-carried AME2 frame.
  result = openDecoded(S, decodeProtectedFrame(S, frame), acrTcp,
    remoteTcp = remote)

proc openAmeDacFrame*(S: var AmeSession, frame: openArray[uint8],
    remote: DacAddress = default(DacAddress)):
    AmeOpenResult {.role: orchestrator.} =
  ## S/frame/remote: DAC-carried AME2 frame. The datagram is the AME frame
  ## itself; there is no outer header to strip or to disagree with it.
  result = openDecoded(S, decodeProtectedFrame(S, frame), acrDac, remoteDac = remote)

proc sealControlFrame(S: var AmeSession, kind: AmePacketKind,
    carrier: AmeCarrier, payload: openArray[uint8]): ByteSeq {.
    role: orchestrator.} =
  ## S/kind/carrier/payload: authenticated AME control message. Control rides
  ## the same ratchet as data -- there is no second construction to review.
  var
    h: AmeFrameHeader = default(AmeFrameHeader)
    body: ByteSeq = @[]
  requireAmeAuth(S.auth)
  requireAmePeerTrust(S)
  if kind notin {ampkExchangeKeys, ampkExchangeEnvelopes, ampkEpochReady,
      ampkSessionIdRequest, ampkSessionIdAssign}:
    raise newException(ValueError, "AME control packet kind is invalid")
  if S.nextAmeSequence == high(uint32):
    raise newException(ValueError, "AME send sequence is exhausted")
  body = padFramePayload(S, payload)
  requireFrameBodyFits(S, body.len, "control payload")
  h = initAmeFrameHeader(kind, amcControl, frameFlags(S), S.sessionId,
    S.rootLaneId, S.laneId, S.nextAmeSequence)
  result = encodeProtectedFrame(S, h, sealFrameBody(S, h, carrier, body))
  S.nextAmeSequence = S.nextAmeSequence + 1'u32

proc controlBindingError(S: AmeSession, f: AmeDecodedFrame,
    expected: AmePacketKind): string {.role: parser.} =
  ## S/f/expected: expected authenticated control metadata.
  if f.header.packetKind != expected or f.header.messageClass != amcControl:
    return "AME control packet kind mismatch"
  if not acceptsSessionId(S, f.header.sessionId) or
      f.header.rootLaneId != S.rootLaneId or
      f.header.laneId != S.laneId:
    return "AME control frame binding mismatch"

proc openControlFrame(S: var AmeSession, frame: openArray[uint8],
    expected: AmePacketKind, carrier: AmeCarrier,
    useCandidate: bool = false): tuple[ok: bool, payload: ByteSeq,
    err: string] {.role: orchestrator.} =
  ## S/frame/expected/carrier/useCandidate: authenticated control open inputs.
  ##
  ## `useCandidate` is the epoch-ready case. The peer sealed that frame as the
  ## FIRST message of the epoch it is asking us to move to, so this side has
  ## to build the ratchet it would have after committing, open the frame with
  ## it, and hold it aside. Nothing is committed until the payload inside has
  ## been checked against what this side independently derived.
  var
    f: AmeDecodedFrame = decodeProtectedFrame(S, frame, useCandidate)
    aad: ByteSeq = @[]
    message: FomkeMessage = default(FomkeMessage)
    fomkeOpened: FomkeOpenResult = default(FomkeOpenResult)
    opened: tuple[ok: bool, payload: ByteSeq, err: string] = (
      ok: false, payload: @[], err: "")
    candidatePadding: AmePaddingPolicy = apadNone
  result.err = controlBindingError(S, f, expected)
  if result.err.len > 0:
    return
  if useCandidate:
    if not S.pendingIncoming.active or not S.fomke.pending.active:
      result.err = "AME session has no candidate epoch"
      return
    try:
      message = decodeFomkeMessage(f.payload,
        S.pendingIncoming.candidate.params.authTagLen)
    except ValueError as exc:
      result.err = exc.msg
      return
    clearFomkeState(S.fomkeCandidate)
    S.fomkeCandidateActive = false
    S.fomkeCandidate = cloneFomkeState(S.fomke)
    confirmFomkeUpgrade(S.fomkeCandidate, S.fomkeCandidate.pending.commit)
    S.fomkeCandidate.tagLen = S.pendingIncoming.candidate.params.authTagLen
    aad = buildAad(carrier, f.header)
    fomkeOpened = openFomkeMessage(S.fomkeCandidate, message, aad)
    secureClearAmeBytes(aad)
    if not fomkeOpened.ok:
      clearFomkeState(S.fomkeCandidate)
      result.err = "AME control authentication failed: " & fomkeOpened.err
      return
    ## Epoch-ready is the first frame of the epoch being moved to, so it was
    ## padded under THAT epoch's policy -- the one the peer asked for and
    ## this side has staged, not the one still in force here.
    candidatePadding = S.pendingIncoming.candidate.params.padding
    if ((f.header.flags and ameFrameFlagPadded) != 0'u8) !=
        (candidatePadding != apadNone):
      clearFomkeState(S.fomkeCandidate)
      result.err = "AME frame padding disagrees with the epoch policy"
      return
    try:
      opened.payload = unpadAmeMessage(fomkeOpened.payload, candidatePadding)
    except ValueError as exc:
      clearFomkeState(S.fomkeCandidate)
      result.err = exc.msg
      return
    S.fomkeCandidateActive = true
    opened.ok = true
  else:
    opened = openFrameBody(S, f, carrier)
  if not opened.ok:
    result.err = "AME control authentication failed: " & opened.err
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
    h: AmeFrameHeader = default(AmeFrameHeader)
  appendAmeBytes(tagged, body)
  tagged = padFramePayload(S, tagged)
  requireFrameBodyFits(S, tagged.len, "DAC control payload")
  h = initAmeFrameHeader(ampkDacControl, amcControl, frameFlags(S),
    S.sessionId, S.rootLaneId, S.laneId, S.nextAmeSequence)
  result = encodeProtectedFrame(S, h, sealFrameBody(S, h, acrDac, tagged))
  secureClearAmeBytes(tagged)
  S.nextAmeSequence = S.nextAmeSequence + 1'u32

proc openAmeDacControl*(S: var AmeSession,
    frame: openArray[uint8]): AmeDacControlOpen {.role: orchestrator.} =
  ## S/frame: connection and one DAC-carried control datagram.
  ## Returns the kind and body only after the frame authenticates, so the
  ## caller never dispatches on a kind an attacker chose.
  var
    f: AmeDecodedFrame = default(AmeDecodedFrame)
    opened: tuple[ok: bool, payload: ByteSeq, err: string] = (
      ok: false, payload: @[], err: "")
  result.err = amePeerTrustError(S)
  if result.err.len > 0:
    return
  try:
    f = decodeProtectedFrame(S, frame)
  except CatchableError as exc:
    result.err = exc.msg
    return
  result.err = controlBindingError(S, f, ampkDacControl)
  if result.err.len > 0:
    return
  opened = openFrameBody(S, f, acrDac)
  if not opened.ok:
    result.err = "AME DAC control " & opened.err
    return
  if not replayAccept(S.dacAmeReplay, f.header.sequence):
    result.err = "AME DAC control replay rejected"
    return
  if opened.payload.len < 1:
    result.err = "AME DAC control message carries no kind"
    return
  consumeSessionIdGrace(S)
  result.kind = dacMessageKindFromId(opened.payload[0])
  if result.kind == dmkUnknown:
    result.err = "AME DAC control message kind is unknown"
    return
  result.body = opened.payload[1 .. ^1]
  result.ok = true

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
    reply: AmeExchangeReply = default(AmeExchangeReply)
  if not opened.ok:
    raise newException(ValueError, opened.err)
  reply = answerAmeSessionExchange(S,
    decodeAmeExchangeOffer(S.auth.current.layout.kems, opened.payload))
  result = sealControlFrame(S, ampkExchangeEnvelopes, acrTcp,
    encodeAmeExchangeReply(reply))
  stageAmeSessionFomkeUpgrade(S)

proc finishAmeTcpExchangeFrame*(S: var AmeSession,
    frame: openArray[uint8]): ByteSeq {.role: orchestrator.} =
  ## S/frame: initiator opens the reply and seals epoch-ready under the new key.
  var
    opened = openControlFrame(S, frame, ampkExchangeEnvelopes, acrTcp)
    requestId: uint32 = 0'u32
    fomkeCommit: FomkeUpgradeCommit = default(FomkeUpgradeCommit)
  if not opened.ok:
    raise newException(ValueError, opened.err)
  requestId = S.pendingExchange.offer.requestId
  finishAmeSessionExchange(S,
    decodeAmeExchangeReply(S.auth.current.layout.kems, opened.payload))
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
  result = sealControlFrame(S, ampkEpochReady, acrTcp,
    encodeEpochReady(requestId, S.auth.current.epochId,
      S.auth.current.tier, fomkeCommit))
  restoreConfiguredAmeFomkeCache(S)

proc confirmAmeTcpExchangeFrame*(S: var AmeSession,
    frame: openArray[uint8]) {.role: orchestrator.} =
  ## S/frame: responder authenticates epoch-ready with its candidate key.
  var
    opened = openControlFrame(S, frame, ampkEpochReady, acrTcp,
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
    reply: AmeExchangeReply = default(AmeExchangeReply)
  if not opened.ok:
    raise newException(ValueError, opened.err)
  reply = answerAmeSessionExchange(S,
    decodeAmeExchangeOffer(S.auth.current.layout.kems, opened.payload))
  result = sealControlFrame(S, ampkExchangeEnvelopes, acrDac,
    encodeAmeExchangeReply(reply))
  stageAmeSessionFomkeUpgrade(S)

proc finishAmeDacExchangeFrame*(S: var AmeSession,
    frame: openArray[uint8]): ByteSeq {.role: orchestrator.} =
  ## S/frame: initiator opens the DAC reply and returns candidate epoch-ready.
  var
    opened = openControlFrame(S, frame, ampkExchangeEnvelopes, acrDac)
    requestId: uint32 = 0'u32
    fomkeCommit: FomkeUpgradeCommit = default(FomkeUpgradeCommit)
  if not opened.ok:
    raise newException(ValueError, opened.err)
  requestId = S.pendingExchange.offer.requestId
  finishAmeSessionExchange(S,
    decodeAmeExchangeReply(S.auth.current.layout.kems, opened.payload))
  fomkeCommit = S.fomke.pending.commit
  confirmFomkeUpgrade(S.fomke, fomkeCommit)
  ## The new epoch may have agreed a different tag length. The envelope no
  ## longer states one, so the ratchet has to be moved onto it here or the
  ## two sides would split the tag at different offsets.
  S.fomke.tagLen = S.auth.current.params.authTagLen
  result = sealControlFrame(S, ampkEpochReady, acrDac,
    encodeEpochReady(requestId, S.auth.current.epochId,
      S.auth.current.tier, fomkeCommit))
  restoreConfiguredAmeFomkeCache(S)

proc confirmAmeDacExchangeFrame*(S: var AmeSession,
    frame: openArray[uint8]) {.role: orchestrator.} =
  ## S/frame: responder authenticates DAC epoch-ready with its candidate key.
  var
    opened = openControlFrame(S, frame, ampkEpochReady, acrDac,
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

proc captureAmeSendRollback(S: AmeSession): AmeSendRollback {.role: helper.} =
  ## S: connection whose send-mutable counters are snapshotted before a write.
  ## Only these fields change while sealing and accounting for one frame, so a
  ## failed send is undone without copying epoch secrets or the inbox.
  result.nextAmeSequence = S.nextAmeSequence
  result.path = S.path
  result.lastTrigger = S.lastTrigger

proc restoreAmeSend(S: var AmeSession, r: AmeSendRollback,
    fomke: var FomkeState, cache: var FomkeSendCache) {.
    role: actor.} =
  ## S/r/fomke/cache: failed send rewound to its pre-send counters and to its
  ## pre-send ratchet. The advanced ratchet is erased
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
  ## S/fomke/cache: successful send erases the superseded FOMKE ratchet copy
  ## instead of releasing its storage unwiped.
  clearFomkeSendCache(cache)
  clearFomkeState(fomke)

template ameSendTransaction*(S: var AmeSession, payload: openArray[uint8],
    body: untyped) {.role: orchestrator.} =
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
    fomke: FomkeState = cloneFomkeState(S.fomke)
    cache: FomkeSendCache = cloneFomkeSendCache(S.fomkeSendCache)
  try:
    body
    discard recordTransferredBytes(S, uint64(payload.len))
  except:
    restoreAmeSend(S, rollback, fomke, cache)
    raise
  discardAmeSendRollback(S, fomke, cache)

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
    opened: tuple[ok: bool, payload: ByteSeq, err: string] = (false, @[], "")
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
    opened: tuple[ok: bool, payload: ByteSeq, err: string] = (false, @[], "")
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
