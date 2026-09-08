## -------------------------------------------------------------------------
## AME Mask Tier Tests <- AME2 frames and atomic epoch transitions
## -------------------------------------------------------------------------

import std/[strutils, unittest]

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/derivation
import ../../src/protocols/ame/level1/padding
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level2/protection
import ../../src/protocols/fomke/types
import ../../src/protocols/fomke/level2/wire
import ../../src/protocols/fomke/level1/chain
import ../../src/protocols/ame/level2/session
import ../../src/protocols/ame/level2/wire
import ../../src/protocols/ame/level1/path_triggers
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/framing
import ../../src/analysis_pragmas

const
  exactKems: AmeKemAlgorithms = [akaFireSaber, akaX25519, akaFireSaber]

proc exactLayout(): AmeSuiteLayout =
  result = defaultAmeLayout(exactKems)

proc exactTier(L: AmeSuiteLayout, id: uint32, kem: uint8): AmeMaskTier {.role: configurator.} =
  result = initAmeMaskTier(L, id, initAmeTierMasks(kem,
    occupiedAmeMask(L.ciphers.length), occupiedAmeMask(L.macs.length),
    occupiedAmeMask(L.hashes.length), occupiedAmeMask(L.signatures.length),
    occupiedAmeMask(L.kdfs.length)))

proc exactAuth(role: AmeEndpointRole = aerInitiator): AmeAuthPackage =
  var
    layout: AmeSuiteLayout = exactLayout()
    tier: AmeMaskTier = exactTier(layout, 1'u32, 0b10000000'u8)
    state: AmeExchangeState = initAmeExchangeState(exactKems)
  applyAmeExchange(state, initAmeExchangeRequest(exactKems, tier,
    0b10000000'u8),
    [@[byte 9, 8, 7, 6, 5, 4, 3, 2]])
  ## The role has to be settled before the session is built: the session
  ## starts its ratchet at once, and the role decides which lane it sends on.
  result = initAmeAuthPackage(layout, tier, state, endpointRole = role)

proc layeredAuth(role: AmeEndpointRole = aerInitiator): AmeAuthPackage =
  var
    layout: AmeSuiteLayout = initAmeSuiteLayout(exactKems,
      initAmeCipherAlgorithms([acaXChaCha20, acaGimli]),
      initAmeMacAlgorithms([amaBlake3, amaGimli]),
      initAmeHashAlgorithms([ahaBlake3, ahaShake256]),
      initAmeSignatureAlgorithms([asaEd25519, asaFalcon512]),
      initAmeKdfAlgorithms([akfaBlake3, akfaGimliXof]))
    tier: AmeMaskTier = initAmeMaskTier(layout, 1'u32,
      initAmeTierMasks(0b10000000'u8, 0b10000000'u8, 0b10000000'u8,
        0b10000000'u8, 0b10000000'u8, 0b10000000'u8))
    state: AmeExchangeState = initAmeExchangeState(layout.kems)
  applyAmeExchange(state, initAmeExchangeRequest(layout.kems, tier,
    tier.masks.kem), [@[byte 9, 8, 7, 6]])
  result = initAmeAuthPackage(layout, tier, state, endpointRole = role)

proc exactUpgradeSession(role: AmeEndpointRole = aerInitiator): AmeSession =
  var
    auth: AmeAuthPackage = exactAuth(role)
    target: AmeMaskTier = exactTier(auth.current.layout, 2'u32,
      0b11000000'u8)
    path: AmeTierPath = initAmeTierPath(auth.current.layout,
      [auth.current.tier, target])
  result = initAmeSession(auth, path, peerTrustRequired = false)

proc layeredUpgradeSession(role: AmeEndpointRole = aerInitiator): AmeSession =
  var
    auth: AmeAuthPackage = layeredAuth(role)
    layout: AmeSuiteLayout = auth.current.layout
    target: AmeMaskTier = initAmeMaskTier(layout, 2'u32,
      initAmeTierMasks(0b10000000'u8, 0b11000000'u8, 0b11000000'u8,
        0b11000000'u8, 0b11000000'u8, 0b11000000'u8))
    path: AmeTierPath = initAmeTierPath(layout, [auth.current.tier, target])
  result = initAmeSession(auth, path, peerTrustRequired = false)

proc installSignaturePeers(A, B: var AmeSession) {.role: actor.} =
  var
    aKeys = generateAmeSigningKeys(A.auth.current.layout,
      fullAmeMaskTier(A.auth.current.layout))
    bKeys = generateAmeSigningKeys(B.auth.current.layout,
      fullAmeMaskTier(B.auth.current.layout))
  A.auth.localSignatureSecretKeys = aKeys.secretKeys
  A.auth.peerSignaturePublicKeys = bKeys.publicKeys
  B.auth.localSignatureSecretKeys = bKeys.secretKeys
  B.auth.peerSignaturePublicKeys = aKeys.publicKeys

proc installLoopbackSignatures(S: var AmeSession) {.role: actor.} =
  var
    keys = generateAmeSigningKeys(S.auth.current.layout,
      fullAmeMaskTier(S.auth.current.layout))
  S.auth.localSignatureSecretKeys = keys.secretKeys
  S.auth.peerSignaturePublicKeys = keys.publicKeys

suite "AME mask-tier sessions":
  # {.testKind: tkIntegration.}
  test "TCP frame roundtrips under exact agreement":
    var
      sender: AmeSession = initAmeSession(exactAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(exactAuth(aerResponder),
        peerTrustRequired = false)
      payload: ByteSeq = @[byte 1, 2, 3, 4]
      frame: ByteSeq = @[]
      opened: AmeOpenResult
    frame = sealAmeTcpFrame(sender, payload)
    opened = openAmeTcpFrame(receiver, frame)
    check opened.ok
    check opened.packet.payload == payload
    check receiver.pending == 1

  # {.testKind: tkRegression.}
  test "directional keys reject reflected TCP and DAC frames":
    var
      sender: AmeSession = initAmeSession(exactAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(exactAuth(aerResponder),
        peerTrustRequired = false)
      tcpFrame: ByteSeq = @[]
      dacFrame: ByteSeq = @[]
      opened: AmeOpenResult
    tcpFrame = sealAmeTcpFrame(sender, @[byte 1, 2])
    opened = openAmeTcpFrame(sender, tcpFrame)
    check not opened.ok
    check opened.err.startsWith("AME authentication failed")
    opened = openAmeTcpFrame(receiver, tcpFrame)
    check opened.ok
    dacFrame = sealAmeDacFrame(sender, @[byte 3, 4])
    opened = openAmeDacFrame(sender, dacFrame)
    check not opened.ok
    check opened.err.startsWith("AME authentication failed")
    opened = openAmeDacFrame(receiver, dacFrame)
    check opened.ok

  # {.testKind: tkUnit.}
  test "transcript salt and direction separate traffic keys":
    var
      auth0: AmeAuthPackage = exactAuth()
      auth1: AmeAuthPackage = exactAuth()
      context0: ByteSeq = @[]
      context1: ByteSeq = @[]
      key0: ByteSeq = @[]
      key1: ByteSeq = @[]
    auth0.current.transcriptSalt = @[byte 1, 2, 3]
    auth1.current.transcriptSalt = @[byte 1, 2, 4]
    context0 = ameEpochKeyContext(auth0.current, auth0.sessionId,
      atdInitiatorToResponder)
    context1 = ameEpochKeyContext(auth1.current, auth1.sessionId,
      atdInitiatorToResponder)
    key0 = deriveAmeMasterKey(auth0.current.exchange, auth0.current.layout,
      auth0.current.tier, context = context0)
    key1 = deriveAmeMasterKey(auth1.current.exchange, auth1.current.layout,
      auth1.current.tier, context = context1)
    check key0 != key1
    context1 = ameEpochKeyContext(auth0.current, auth0.sessionId,
      atdResponderToInitiator)
    key1 = deriveAmeMasterKey(auth0.current.exchange, auth0.current.layout,
      auth0.current.tier, context = context1)
    check key0 != key1

  # {.testKind: tkIntegration.}
  test "DAC frame roundtrips and binds carrier metadata":
    var
      sender: AmeSession = initAmeSession(exactAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(exactAuth(aerResponder),
        peerTrustRequired = false)
      payload: ByteSeq = @[byte 5, 6, 7]
      frame: ByteSeq = @[]
      opened: AmeOpenResult
    frame = sealAmeDacFrame(sender, payload)
    opened = openAmeDacFrame(receiver, frame)
    check opened.ok
    check opened.packet.payload == payload
    frame[^1] = frame[^1] xor 1'u8
    receiver = initAmeSession(exactAuth(aerResponder), peerTrustRequired = false)
    opened = openAmeDacFrame(receiver, frame)
    check not opened.ok

  # {.testKind: tkUnit.}
  test "a DAC datagram is exactly one AME frame, with no outer header":
    var
      sender: AmeSession = initAmeSession(exactAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(exactAuth(aerResponder),
        peerTrustRequired = false)
      frame: ByteSeq = @[]
      decoded: AmeDecodedFrame
      opened: AmeOpenResult
    frame = sealAmeDacFrame(sender, @[byte 5, 6, 7])
    decoded = decodeAmeFrame(frame)
    check decoded.header.sessionId == sender.sessionId
    check decoded.header.laneId == sender.laneId
    check frame.len == ameFrameHeaderLen + decoded.payload.len
    check not peekDacFrameIdentity(frame).ok
    opened = openAmeDacFrame(receiver, frame)
    check opened.ok
    check opened.packet.payload == @[byte 5, 6, 7]

  # {.testKind: tkRegression.}
  test "the epoch lives in the FOMKE envelope and tampering is caught":
    var
      sender: AmeSession = initAmeSession(exactAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(exactAuth(aerResponder),
        peerTrustRequired = false)
      frame: ByteSeq = @[]
      body: FomkeMessage
      opened: AmeOpenResult
    frame = sealAmeDacFrame(sender, @[byte 5, 6, 7])
    body = decodeFomkeMessage(decodeAmeFrame(frame).payload, sender.fomke.tagLen)
    check body.epoch == sender.fomke.epoch
    check body.senderLane == flLane1
    ## No nonce on the wire and no nonce-length field: both sides derive the
    ## nonce from the same ratchet step, so the envelope is header, tag,
    ## ciphertext and nothing else.
    check frame.len == ameFrameHeaderLen + fomkeHeaderLen +
      int(ord(body.tagLen)) + 3
    frame[24] = frame[24] xor 0x01'u8
    opened = openAmeDacFrame(receiver, frame)
    check not opened.ok

  # {.testKind: tkEdgeCase.}
  test "an epoch past 65535 now rides DAC, which the old u16 field refused":
    var
      sender: AmeSession = initAmeSession(exactAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(exactAuth(aerResponder),
        peerTrustRequired = false)
      frame: ByteSeq = @[]
      opened: AmeOpenResult
    sender.auth.current.epochId = uint32(high(uint16)) + 7'u32
    receiver.auth.current.epochId = sender.auth.current.epochId
    frame = sealAmeDacFrame(sender, @[byte 5])
    opened = openAmeDacFrame(receiver, frame)
    check opened.ok
    check opened.packet.payload == @[byte 5]

  # {.testKind: tkUnit.}
  test "a payload past 65535 needs no widened framing on any path lane":
    var
      lanes: seq[DacPathLane] = @[dplSuperCleanPath, dplCleanPath, dplThinPath]
      payload: ByteSeq = newSeq[byte](70_000)
      sender: AmeSession
      receiver: AmeSession
      frame: ByteSeq = @[]
      opened: AmeOpenResult
      i: int = 0
    payload[0] = 1'u8
    payload[^1] = 2'u8
    while i < lanes.len:
      sender = initAmeSession(exactAuth(aerInitiator), pathLane = lanes[i],
        peerTrustRequired = false)
      receiver = initAmeSession(exactAuth(aerResponder), pathLane = lanes[i],
        peerTrustRequired = false)
      frame = sealAmeDacFrame(sender, payload)
      check frame.len == ameFrameHeaderLen +
        decodeAmeFrame(frame).payload.len
      opened = openAmeDacFrame(receiver, frame)
      check opened.ok
      check opened.packet.payload == payload
      i = i + 1

  # {.testKind: tkUnit.}
  test "a DAC control message round-trips with its kind authenticated":
    var
      sender: AmeSession = initAmeSession(exactAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(exactAuth(aerResponder),
        peerTrustRequired = false)
      body: ByteSeq = @[byte 9, 8, 7, 6]
      frame: ByteSeq = @[]
      got: tuple[ok: bool, kind: DacMessageKind, body: ByteSeq, err: string]
    frame = sealAmeDacControl(sender, dmkAckRange, body)
    got = openAmeDacControl(receiver, frame)
    check got.ok
    check got.kind == dmkAckRange
    check got.body == body

  # {.testKind: tkUnit.}
  test "the DAC kind is inside the ciphertext, not readable on the wire":
    var
      sender: AmeSession = initAmeSession(exactAuth(aerInitiator),
        peerTrustRequired = false)
      ack: ByteSeq = @[]
      hint: ByteSeq = @[]
      body: ByteSeq = @[byte 1, 2, 3, 4]
    ack = sealAmeDacControl(sender, dmkAckRange, body)
    hint = sealAmeDacControl(sender, dmkRepairHint, body)
    check ack.len == hint.len
    check decodeAmeFrame(ack).header.packetKind == ampkDacControl
    check decodeAmeFrame(hint).header.packetKind == ampkDacControl

  # {.testKind: tkRegression.}
  test "a forged or altered DAC control message is refused":
    var
      sender: AmeSession = initAmeSession(exactAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(exactAuth(aerResponder),
        peerTrustRequired = false)
      frame: ByteSeq = @[]
      tampered: ByteSeq = @[]
      got: tuple[ok: bool, kind: DacMessageKind, body: ByteSeq, err: string]
      i: int = 0
    frame = sealAmeDacControl(sender, dmkAckRange, @[byte 1, 2, 3, 4])
    while i < frame.len:
      tampered = frame
      tampered[i] = tampered[i] xor 0x01'u8
      got = openAmeDacControl(receiver, tampered)
      check not got.ok
      i = i + 1

  # {.testKind: tkEdgeCase.}
  test "an unknown DAC kind is refused after authentication, not dispatched":
    var
      sender: AmeSession = initAmeSession(exactAuth(aerInitiator),
        peerTrustRequired = false)
    expect ValueError:
      discard sealAmeDacControl(sender, dmkUnknown, @[byte 1])

  # {.testKind: tkRegression.}
  test "a replayed DAC control message is refused":
    var
      sender: AmeSession = initAmeSession(exactAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(exactAuth(aerResponder),
        peerTrustRequired = false)
      frame: ByteSeq = @[]
    frame = sealAmeDacControl(sender, dmkPackageCommit, @[byte 4, 5])
    check openAmeDacControl(receiver, frame).ok
    check not openAmeDacControl(receiver, frame).ok

  # {.testKind: tkUnit.}
  test "authenticated progress expires the retiring epoch":
    var
      sender: AmeSession = initAmeSession(exactAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(exactAuth(aerResponder),
        peerTrustRequired = false)
      frame: ByteSeq = @[]
      opened: AmeOpenResult
    receiver.auth.retiring = receiver.auth.current
    receiver.auth.retiringFramesLeft = 1
    receiver.auth.current.epochId = receiver.auth.current.epochId + 1'u32
    frame = sealAmeTcpFrame(sender, @[byte 3, 2, 1])
    opened = openAmeTcpFrame(receiver, frame)
    check opened.ok
    check receiver.auth.retiring.epochId == 0'u32
    check receiver.auth.retiringFramesLeft == 0

  # {.testKind: tkUnit.}
  test "only successful transfer accounting emits data trigger":
    var
      connection: AmeSession = initAmeSession(exactAuth(),
        peerTrustRequired = false)
      layout: AmeSuiteLayout = connection.auth.current.layout
      tier2: AmeMaskTier = exactTier(layout, 2'u32, 0b11000000'u8)
      path: AmeTierPath = initAmeTierPath(layout,
        [connection.auth.current.tier, tier2])
      step: AmeTierStep
    connection = initAmeSession(connection.auth, path,
      peerTrustRequired = false)
    connection.path.setTrigger(1, 200'u64)
    step = connection.recordTransferredBytes(199'u64 * ameBytesPerMiB)
    check not step.available
    step = connection.recordTransferredBytes(1'u64 * ameBytesPerMiB)
    check step.exchangeMask == 0b01000000'u8

  # {.testKind: tkUnit.}
  test "authenticated TCP exchange commits only after epoch-ready":
    var
      client: AmeSession = exactUpgradeSession(aerInitiator)
      server: AmeSession = exactUpgradeSession(aerResponder)
      target: AmeMaskTier = exactTier(client.auth.current.layout, 2'u32,
        0b11000000'u8)
      request: AmeExchangeRequest = initAmeExchangeRequest(exactKems,
        target, 0b01000000'u8)
      offerFrame: ByteSeq = @[]
      replyFrame: ByteSeq = @[]
      readyFrame: ByteSeq = @[]
    installSignaturePeers(client, server)
    offerFrame = beginAmeTcpExchangeFrame(client, request)
    replyFrame = answerAmeTcpExchangeFrame(server, offerFrame)
    check server.auth.current.epochId == 1'u32
    check server.pendingIncoming.active
    readyFrame = finishAmeTcpExchangeFrame(client, replyFrame)
    check client.auth.current.epochId == 2'u32
    check client.auth.current.tier.tierId == 2'u32
    check client.auth.current.transcriptSalt ==
      server.pendingIncoming.candidate.transcriptSalt
    check server.auth.current.epochId == 1'u32
    confirmAmeTcpExchangeFrame(server, readyFrame)
    check server.auth.current.epochId == 2'u32
    check server.auth.current.tier.masks.kem == 0b11000000'u8
    check client.auth.current.exchange.sharedSecrets[1] ==
      server.auth.current.exchange.sharedSecrets[1]
    check client.auth.current.transcriptSalt == server.auth.current.transcriptSalt

  # {.testKind: tkUnit.}
  test "the ratchet direction follows the endpoint role, with no way to differ":
    var
      initiator: AmeSession = initAmeSession(exactAuth(aerInitiator),
        peerTrustRequired = false)
      responder: AmeSession = initAmeSession(exactAuth(aerResponder),
        peerTrustRequired = false)
    ## There is no separate switch to get wrong. The session reads the role
    ## off its own auth package when it starts the ratchet, so the two can
    ## never disagree.
    check initiator.fomke.role == frInitiator
    check responder.fomke.role == frResponder
    check outboundFomkeLane(initiator.fomke.role) == flLane1
    check outboundFomkeLane(responder.fomke.role) == flLane2

  # {.testKind: tkFuzz.}
  test "candidate rekey does not mutate the current epoch":
    var
      client: AmeSession = initAmeSession(exactAuth(aerInitiator),
        peerTrustRequired = false)
      server: AmeSession = initAmeSession(exactAuth(aerResponder),
        peerTrustRequired = false)
      target: AmeMaskTier = client.auth.current.tier
      request: AmeExchangeRequest = initAmeExchangeRequest(exactKems,
        target, 0b10000000'u8)
      before: ByteSeq = server.auth.current.exchange.sharedSecrets[0] & @[]
      offerFrame: ByteSeq = @[]
      replyFrame: ByteSeq = @[]
    installSignaturePeers(client, server)
    offerFrame = beginAmeTcpExchangeFrame(client, request)
    replyFrame = answerAmeTcpExchangeFrame(server, offerFrame)
    check server.auth.current.exchange.sharedSecrets[0] == before
    check server.pendingIncoming.candidate.exchange.sharedSecrets[0] != before
    discard finishAmeTcpExchangeFrame(client, replyFrame)

  # {.testKind: tkFuzz.}
  test "receiver rejects either KEM offer signature before candidate mutation":
    var
      client: AmeSession = exactUpgradeSession(aerInitiator)
      server: AmeSession = exactUpgradeSession(aerResponder)
      target: AmeMaskTier = exactTier(client.auth.current.layout, 2'u32,
        0b11000000'u8)
      request: AmeExchangeRequest = initAmeExchangeRequest(exactKems,
        target, 0b01000000'u8)
      offer: AmeExchangeOffer
      before: ByteSeq = server.auth.current.exchange.sharedSecrets[0] & @[]
    installSignaturePeers(client, server)
    offer = beginAmeSessionExchange(client, request)
    check offer.signatures.len == 2
    offer.signatures[1][0] = offer.signatures[1][0] xor 1'u8
    expect ValueError:
      discard answerAmeSessionExchange(server, offer)
    check not server.pendingIncoming.active
    check server.auth.current.epochId == 1'u32
    check server.auth.current.exchange.sharedSecrets[0] == before

  # {.testKind: tkEdgeCase.}
  test "initiator rejects KEM reply signature before epoch rotation":
    var
      client: AmeSession = exactUpgradeSession(aerInitiator)
      server: AmeSession = exactUpgradeSession(aerResponder)
      target: AmeMaskTier = exactTier(client.auth.current.layout, 2'u32,
        0b11000000'u8)
      request: AmeExchangeRequest = initAmeExchangeRequest(exactKems,
        target, 0b01000000'u8)
      offer: AmeExchangeOffer
      reply: AmeExchangeReply
    installSignaturePeers(client, server)
    offer = beginAmeSessionExchange(client, request)
    reply = answerAmeSessionExchange(server, offer)
    check reply.signatures.len == 2
    reply.signatures[0][0] = reply.signatures[0][0] xor 1'u8
    expect ValueError:
      finishAmeSessionExchange(client, reply)
    check client.auth.current.epochId == 1'u32
    check client.pendingExchange.active

  # {.testKind: tkEdgeCase.}
  test "tier paths reject backward transitions":
    var
      connection: AmeSession = exactUpgradeSession()
      first: AmeMaskTier = connection.auth.current.tier
      second: AmeMaskTier = exactTier(connection.auth.current.layout, 2'u32,
        0b11000000'u8)
    setCurrentAmeTier(connection.path, second)
    connection.auth.current.tier = second
    expect ValueError:
      discard requestAmeTier(connection, first.tierId)

  # {.testKind: tkUnit.}
  test "transition authorization retains current signature slots":
    var
      layout: AmeSuiteLayout = layeredAuth().current.layout
      current: AmeMaskTier = initAmeMaskTier(layout, 1'u32,
        initAmeTierMasks(0b10000000'u8, 0b10000000'u8, 0b10000000'u8,
          0b10000000'u8, 0b11000000'u8, 0b10000000'u8))
      target: AmeMaskTier = initAmeMaskTier(layout, 2'u32,
        initAmeTierMasks(0b10000000'u8, 0b10000000'u8, 0b10000000'u8,
          0b10000000'u8, 0b10000000'u8, 0b10000000'u8))
      authorization: AmeMaskTier = transitionAmeSignatureTier(layout,
        current, target)
    check authorization.tierId == target.tierId
    check authorization.masks.signature == 0b11000000'u8

  # {.testKind: tkEdgeCase.}
  test "session rejects valid masks outside its configured tier path":
    var
      connection: AmeSession = initAmeSession(exactAuth(),
        peerTrustRequired = false)
      target: AmeMaskTier = exactTier(connection.auth.current.layout, 2'u32,
        0b11000000'u8)
      request: AmeExchangeRequest = initAmeExchangeRequest(exactKems,
        target, 0b01000000'u8)
    installLoopbackSignatures(connection)
    expect ValueError:
      discard beginAmeSessionExchange(connection, request)

  # {.testKind: tkUnit.}
  test "non-KEM masks rotate atomically without replacing KEM secrets":
    var
      client: AmeSession = layeredUpgradeSession(aerInitiator)
      server: AmeSession = layeredUpgradeSession(aerResponder)
      layout: AmeSuiteLayout = client.auth.current.layout
      target: AmeMaskTier = initAmeMaskTier(layout, 2'u32,
        initAmeTierMasks(0b10000000'u8, 0b11000000'u8, 0b11000000'u8,
          0b11000000'u8, 0b11000000'u8, 0b11000000'u8))
      request: AmeExchangeRequest = initAmeExchangeRequest(layout.kems,
        target, 0'u8)
      secret: ByteSeq = client.auth.current.exchange.sharedSecrets[0] & @[]
      offerFrame: ByteSeq = @[]
      replyFrame: ByteSeq = @[]
      readyFrame: ByteSeq
    installSignaturePeers(client, server)
    offerFrame = beginAmeTcpExchangeFrame(client, request)
    replyFrame = answerAmeTcpExchangeFrame(server, offerFrame)
    check server.auth.current.tier.tierId == 1'u32
    check server.pendingIncoming.candidate.tier.tierId == 2'u32
    readyFrame = finishAmeTcpExchangeFrame(client, replyFrame)
    check client.auth.current.tier.masks.cipher == 0b11000000'u8
    check client.auth.current.exchange.sharedSecrets[0] == secret
    check server.auth.current.tier.tierId == 1'u32
    confirmAmeTcpExchangeFrame(server, readyFrame)
    check server.auth.current.tier.masks.kdf == 0b11000000'u8
    check server.auth.current.exchange.sharedSecrets[0] == secret
    check client.fomke.epoch == 2'u32
    check server.fomke.epoch == 2'u32

  # {.testKind: tkRegression.}
  test "authenticated DAC exchange rejects tampering and replay":
    var
      client: AmeSession = exactUpgradeSession(aerInitiator)
      server: AmeSession = exactUpgradeSession(aerResponder)
      target: AmeMaskTier = exactTier(client.auth.current.layout, 2'u32,
        0b11000000'u8)
      request: AmeExchangeRequest = initAmeExchangeRequest(exactKems,
        target, 0b01000000'u8)
      offerFrame: ByteSeq = @[]
      tampered: ByteSeq = @[]
      replyFrame: ByteSeq = @[]
      readyFrame: ByteSeq = @[]
    installSignaturePeers(client, server)
    offerFrame = beginAmeDacExchangeFrame(client, request)
    tampered = offerFrame
    tampered[^1] = tampered[^1] xor 1'u8
    expect ValueError:
      discard answerAmeDacExchangeFrame(server, tampered)
    replyFrame = answerAmeDacExchangeFrame(server, offerFrame)
    expect ValueError:
      discard answerAmeDacExchangeFrame(server, offerFrame)
    readyFrame = finishAmeDacExchangeFrame(client, replyFrame)
    confirmAmeDacExchangeFrame(server, readyFrame)
    check client.auth.current.epochId == server.auth.current.epochId

  # {.testKind: tkUnit.}
  test "DAC exchange control frames bind the embedded epoch":
    var
      client: AmeSession = exactUpgradeSession(aerInitiator)
      server: AmeSession = exactUpgradeSession(aerResponder)
      target: AmeMaskTier = exactTier(client.auth.current.layout, 2'u32,
        0b11000000'u8)
      request: AmeExchangeRequest = initAmeExchangeRequest(exactKems,
        target, 0b01000000'u8)
      offerFrame: ByteSeq = @[]
    installSignaturePeers(client, server)
    offerFrame = beginAmeDacExchangeFrame(client, request)
    offerFrame[19] = offerFrame[19] xor 0x01'u8
    expect ValueError:
      discard answerAmeDacExchangeFrame(server, offerFrame)

  # {.testKind: tkUnit.}
  test "cancelled trigger exchange returns its mask to due":
    var
      connection: AmeSession = initAmeSession(exactAuth(),
        peerTrustRequired = false)
      layout: AmeSuiteLayout = connection.auth.current.layout
      tier2: AmeMaskTier = exactTier(layout, 2'u32, 0b11000000'u8)
      path: AmeTierPath = initAmeTierPath(layout,
        [connection.auth.current.tier, tier2])
      step: AmeTierStep
    connection = initAmeSession(connection.auth, path,
      peerTrustRequired = false)
    connection.path.setTrigger(1, 1'u64)
    step = connection.recordTransferredBytes(ameBytesPerMiB)
    installLoopbackSignatures(connection)
    discard beginAmeSessionExchange(connection, step.request)
    check connection.path.inFlightTierId == 2'u32
    cancelAmeSessionExchange(connection)
    check connection.path.inFlightTierId == 0'u32
    check connection.path.dueMask == 0b01000000'u8
    check not connection.pendingExchange.active

  # {.testKind: tkEdgeCase.}
  test "DAC accepts bounded out-of-order frames and rejects duplicates":
    var
      sender: AmeSession = initAmeSession(exactAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(exactAuth(aerResponder),
        peerTrustRequired = false)
      first: ByteSeq = @[]
      second: ByteSeq = @[]
      opened: AmeOpenResult
    first = sealAmeDacFrame(sender, @[byte 1])
    second = sealAmeDacFrame(sender, @[byte 2])
    opened = openAmeDacFrame(receiver, second)
    check opened.ok
    opened = openAmeDacFrame(receiver, first)
    check opened.ok
    opened = openAmeDacFrame(receiver, first)
    check not opened.ok
    ## The ratchet catches this before the header's replay window is even
    ## consulted: the one-time key for that position was destroyed when the
    ## frame was first opened, so there is nothing left to open it with.
    check opened.err.startsWith("AME authentication failed")

  # {.testKind: tkEdgeCase.}
  test "envelope and sequence limits fail closed":
    var
      connection: AmeSession = initAmeSession(exactAuth(),
        peerTrustRequired = false)
      envelope: ByteSeq = @[]
      decoded: FomkeMessage
      i: int = 0
    ## The envelope used to carry a ciphertext length, and this test used to
    ## check that a header claiming eight megabytes on a short datagram was
    ## refused rather than believed. That field is gone, and with it the
    ## whole class of lie: the ciphertext is whatever actually arrived after
    ## the tag, so a short datagram can only ever produce a short ciphertext.
    ## Thirteen header bytes, a 32-byte tag, and two bytes of ciphertext.
    while i < fomkeHeaderLen + 32 + 2:
      envelope.add(if i == 0: 1'u8 elif i == 12: 1'u8 else: 0'u8)
      i = i + 1
    decoded = decodeFomkeMessage(envelope, aatl32)
    check decoded.ciphertext.len == 2
    ## Under the header-plus-tag floor there is nothing to authenticate, and
    ## the decoder stops rather than reading past the end.
    envelope.setLen(fomkeHeaderLen + 31)
    expect ValueError:
      discard decodeFomkeMessage(envelope, aatl32)
    connection.nextAmeSequence = high(uint32)
    expect ValueError:
      discard sealAmeTcpFrame(connection, @[byte 1])

  # {.testKind: tkEdgeCase.}
  test "trigger threshold multiplication rejects overflow":
    var
      path: AmeTierPath = exactKems.ameInitTierPath()
    expect ValueError:
      path.setTrigger(1, high(uint64))

  # {.testKind: tkUnit.}
  test "simultaneous rekey converges instead of splitting the epoch":
    var
      A: AmeSession = exactUpgradeSession(aerInitiator)
      B: AmeSession = exactUpgradeSession(aerResponder)
      target: AmeMaskTier = exactTier(A.auth.current.layout, 2'u32,
        0b11000000'u8)
      request: AmeExchangeRequest
      offerA: AmeExchangeOffer
      offerB: AmeExchangeOffer
      replyB: AmeExchangeReply
      commit: FomkeUpgradeCommit
    installSignaturePeers(A, B)
    request = initAmeExchangeRequest(A.auth.current.layout.kems, target,
      0b01000000'u8)
    # both endpoints trip their transfer trigger at the same time
    offerA = beginAmeSessionExchange(A, request)
    offerB = beginAmeSessionExchange(B, request)
    # the responder yields its own exchange and answers the initiator
    replyB = answerAmeSessionExchange(B, offerA)
    # the responder stages its ratchet upgrade after it has sent the reply,
    # so both endpoints stage at the same lane positions
    stageAmeSessionFomkeUpgrade(B)
    check not B.pendingExchange.active
    # the initiator keeps its own exchange and refuses the responder's offer
    expect ValueError:
      discard answerAmeSessionExchange(A, offerB)
    finishAmeSessionExchange(A, replyB)
    commit = A.fomke.pending.commit
    confirmFomkeUpgrade(A.fomke, commit)
    confirmAmeSessionExchange(B, offerA.requestId,
      B.pendingIncoming.candidate.epochId, target, commit)
    # both derived the same ratchet root, independently
    check A.fomke.epoch == B.fomke.epoch
    check A.fomke.lane1.chainKey == B.fomke.lane1.chainKey
    # both land on one epoch built from one set of KEM secrets
    check A.auth.current.epochId == B.auth.current.epochId
    check A.auth.current.exchange.sharedSecrets[1] ==
      B.auth.current.exchange.sharedSecrets[1]

  # {.testKind: tkEdgeCase.}
  test "outgoing exchange is refused while a candidate epoch is pending":
    var
      A: AmeSession = exactUpgradeSession(aerInitiator)
      B: AmeSession = exactUpgradeSession(aerResponder)
      target: AmeMaskTier = exactTier(A.auth.current.layout, 2'u32,
        0b11000000'u8)
      request: AmeExchangeRequest
      offer: AmeExchangeOffer
    installSignaturePeers(A, B)
    request = initAmeExchangeRequest(A.auth.current.layout.kems, target,
      0b01000000'u8)
    offer = beginAmeSessionExchange(A, request)
    discard answerAmeSessionExchange(B, offer)
    check B.pendingIncoming.active
    expect ValueError:
      discard beginAmeSessionExchange(B, request)

  # {.testKind: tkEdgeCase.}
  test "truncated authentication tags are rejected outright":
    var
      auth: AmeAuthPackage = exactAuth()
      sealed = protectAmeMessage(auth.current.layout, auth.current.tier,
        auth.current.exchange, @[byte 1, 2, 3, 4])
      forged: AmeProtectedMessage
      accepted: int = 0
      i: int = 0
    forged.payload = sealed.message.payload
    while i < 256:
      forged.authTag = @[uint8(i)]
      if openAmeMessage(auth.current.layout, auth.current.tier,
          auth.current.exchange, sealed.nonce, forged).ok:
        accepted = accepted + 1
      i = i + 1
    check accepted == 0
    # the full-length tag still opens
    check openAmeMessage(auth.current.layout, auth.current.tier,
      auth.current.exchange, sealed.nonce, sealed.message).ok

proc paddedAuth(role: AmeEndpointRole = aerInitiator): AmeAuthPackage =
  ## The same epoch as `exactAuth`, with payload padding switched on. Both
  ## endpoints have to be built this way: the policy is part of the epoch,
  ## and a session that disagrees about it refuses the frame rather than
  ## guessing what the bytes at the end were.
  var
    layout: AmeSuiteLayout = exactLayout()
    tier: AmeMaskTier = exactTier(layout, 1'u32, 0b10000000'u8)
    state: AmeExchangeState = initAmeExchangeState(exactKems)
  applyAmeExchange(state, initAmeExchangeRequest(exactKems, tier,
    0b10000000'u8),
    [@[byte 9, 8, 7, 6, 5, 4, 3, 2]])
  result = initAmeAuthPackage(layout, tier, state, endpointRole = role,
    params = AmeRuntimeParams(authTagLen: aatl32, padding: apadBlock64))

suite "AME payload padding":
  # {.testKind: tkUnit.}
  test "padding rounds up to whole blocks and always adds filler":
    check amePaddedLen(0, apadBlock64) == 64
    check amePaddedLen(1, apadBlock64) == 64
    check amePaddedLen(63, apadBlock64) == 64
    ## A plaintext that already fills a block still gets a whole block of
    ## filler. Without that there would be no last byte to state the count.
    check amePaddedLen(64, apadBlock64) == 128
    check amePaddedLen(65, apadBlock64) == 128
    check amePaddedLen(4096, apadBlock64) == 4160
    check amePaddedLen(17, apadNone) == 17

  # {.testKind: tkIntegration.}
  test "every plaintext length survives the round trip":
    var
      lengths: array[8, int] = [0, 1, 2, 63, 64, 65, 127, 300]
      plaintext: ByteSeq = @[]
      padded: ByteSeq = @[]
      i: int = 0
      j: int = 0
    while i < lengths.len:
      plaintext = newSeq[byte](lengths[i])
      j = 0
      while j < plaintext.len:
        plaintext[j] = uint8((j * 7 + 3) and 0xff)
        j = j + 1
      padded = padAmeMessage(plaintext, apadBlock64)
      check padded.len mod 64 == 0
      check padded.len > plaintext.len
      check padded.len - plaintext.len <= 64
      check unpadAmeMessage(padded, apadBlock64) == plaintext
      i = i + 1

  # {.testKind: tkUnit.}
  test "different lengths in one block become the same length":
    ## This is the whole point. Five bytes and fifty bytes are the same size
    ## on the wire, so the size stops saying which one went past.
    check padAmeMessage(newSeq[byte](5), apadBlock64).len ==
      padAmeMessage(newSeq[byte](50), apadBlock64).len

  # {.testKind: tkEdgeCase.}
  test "malformed padding is refused rather than trimmed":
    var
      body: ByteSeq = padAmeMessage(@[byte 1, 2, 3], apadBlock64)
      broken: ByteSeq = @[]
    ## Not a whole number of blocks.
    expect ValueError:
      discard unpadAmeMessage(@[byte 1, 2, 3], apadBlock64)
    ## An empty buffer has no length byte to read.
    expect ValueError:
      discard unpadAmeMessage(@[], apadBlock64)
    ## A filler count of zero, and one past the block size.
    broken = body
    broken[broken.len - 1] = 0'u8
    expect ValueError:
      discard unpadAmeMessage(broken, apadBlock64)
    broken = body
    broken[broken.len - 1] = 65'u8
    expect ValueError:
      discard unpadAmeMessage(broken, apadBlock64)
    ## Filler that is not zero. Nothing can be smuggled in the space that
    ## gets discarded.
    broken = body
    broken[10] = 1'u8
    expect ValueError:
      discard unpadAmeMessage(broken, apadBlock64)

  # {.testKind: tkUnit.}
  test "only the two defined policy bytes decode":
    check amePaddingPolicyFromId(0'u8) == apadNone
    check amePaddingPolicyFromId(64'u8) == apadBlock64
    expect ValueError:
      discard amePaddingPolicyFromId(32'u8)
    expect ValueError:
      discard amePaddingPolicyFromId(255'u8)

  # {.testKind: tkUnit.}
  test "a padded session hides the payload length in the frame":
    var
      sender: AmeSession = initAmeSession(paddedAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(paddedAuth(aerResponder),
        peerTrustRequired = false)
      short: ByteSeq = sealAmeTcpFrame(sender, @[byte 1])
      longer: ByteSeq = sealAmeTcpFrame(sender, newSeq[byte](40))
      opened: AmeOpenResult
    ## One byte and forty bytes leave the same size frame.
    check short.len == longer.len
    check ameFrameOverheadBytes(sender) ==
      ameFrameHeaderLen + fomkeWireLen(0, aatl32) + 64
    opened = openAmeTcpFrame(receiver, short)
    check opened.ok
    check opened.packet.payload == @[byte 1]
    opened = openAmeTcpFrame(receiver, longer)
    check opened.ok
    check opened.packet.payload == newSeq[byte](40)

  # {.testKind: tkUnit.}
  test "the header says a frame is padded and the tag covers that":
    var
      sender: AmeSession = initAmeSession(paddedAuth(aerInitiator),
        peerTrustRequired = false)
      plain: AmeSession = initAmeSession(exactAuth(aerInitiator),
        peerTrustRequired = false)
      padded: ByteSeq = sealAmeTcpFrame(sender, @[byte 1, 2, 3])
      bare: ByteSeq = sealAmeTcpFrame(plain, @[byte 1, 2, 3])
      receiver: AmeSession = initAmeSession(exactAuth(aerResponder),
        peerTrustRequired = false)
      opened: AmeOpenResult
    check (decodeAmeFrameHeader(padded).flags and ameFrameFlagPadded) != 0'u8
    check decodeAmeFrameHeader(bare).flags == 0'u8
    ## An endpoint that did not agree to padding refuses the frame instead of
    ## handing 61 bytes of filler up as data.
    opened = openAmeTcpFrame(receiver, padded)
    check not opened.ok

  # {.testKind: tkEdgeCase.}
  test "an unknown frame flag is refused, not ignored":
    var
      plain: AmeSession = initAmeSession(exactAuth(aerInitiator),
        peerTrustRequired = false)
      frame: ByteSeq = sealAmeTcpFrame(plain, @[byte 1, 2, 3])
    ## Bit 4 means nothing today. A build that meets it must stop, because a
    ## flag it cannot honour may change what the payload means.
    frame[5] = frame[5] or 0x10'u8
    expect ValueError:
      discard decodeAmeFrameHeader(frame)

  # {.testKind: tkUnit.}
  test "the padding policy travels with the exchange request":
    var
      layout: AmeSuiteLayout = exactLayout()
      tier: AmeMaskTier = exactTier(layout, 2'u32, 0b11000000'u8)
      request: AmeExchangeRequest = initAmeExchangeRequest(exactKems, tier,
        0b01000000'u8, AmeRuntimeParams(authTagLen: aatl16,
        padding: apadBlock64))
      encoded: ByteSeq = encodeAmeExchangeRequest(request)
      decoded: AmeExchangeRequest
    check encoded.len == ameExchangeRequestLen
    decoded = decodeAmeExchangeRequest(exactKems, encoded)
    check decoded.params.padding == apadBlock64
    check decoded.params.authTagLen == aatl16
    ## A byte that names no policy is refused rather than read as "off".
    encoded[12] = 7'u8
    expect ValueError:
      discard decodeAmeExchangeRequest(exactKems, encoded)

  # {.testKind: tkIntegration.}
  test "padding can be switched on at a rotation and both sides follow":
    var
      client: AmeSession = exactUpgradeSession(aerInitiator)
      server: AmeSession = exactUpgradeSession(aerResponder)
      target: AmeMaskTier = exactTier(client.auth.current.layout, 2'u32,
        0b11000000'u8)
      request: AmeExchangeRequest
      offerFrame: ByteSeq = @[]
      replyFrame: ByteSeq = @[]
      readyFrame: ByteSeq = @[]
      frame: ByteSeq = @[]
      opened: AmeOpenResult
    installSignaturePeers(client, server)
    ## Nothing changes on the wire yet: the live epoch's tags are bound to
    ## the values it was created with.
    setAmePadding(client, apadBlock64)
    check nextAmeParams(client).padding == apadBlock64
    check ameParams(client).padding == apadNone
    frame = sealAmeTcpFrame(client, @[byte 1])
    check decodeAmeFrameHeader(frame).flags == 0'u8
    check openAmeTcpFrame(server, frame).ok
    ## The staged value rides in the exchange request, so the responder
    ## adopts it and the two rotate onto it together.
    request = initAmeExchangeRequest(exactKems, target, 0b01000000'u8,
      nextAmeParams(client))
    offerFrame = beginAmeTcpExchangeFrame(client, request)
    replyFrame = answerAmeTcpExchangeFrame(server, offerFrame)
    ## Epoch-ready is the first frame of the NEW epoch, so it is already
    ## padded, and the responder has to strip it with the policy it has only
    ## staged -- not the one still in force on its side.
    readyFrame = finishAmeTcpExchangeFrame(client, replyFrame)
    check (decodeAmeFrameHeader(readyFrame).flags and
      ameFrameFlagPadded) != 0'u8
    confirmAmeTcpExchangeFrame(server, readyFrame)
    check ameParams(client).padding == apadBlock64
    check ameParams(server).padding == apadBlock64
    frame = sealAmeTcpFrame(client, @[byte 2, 3])
    check (decodeAmeFrameHeader(frame).flags and ameFrameFlagPadded) != 0'u8
    opened = openAmeTcpFrame(server, frame)
    check opened.ok
    check opened.packet.payload == @[byte 2, 3]

suite "the path profile reaches the session":
  ## `AmeSession.pathLane` used to be written and never read, which made it
  ## look as though DAC's parameter feedback reached a live session when it
  ## did not.
  # {.testKind: tkRegression.}
  test "a session hands back the parameter set its path profile calls for":
    var
      clean: AmeSession = initAmeSession(exactAuth(aerInitiator),
        pathLane = dplCleanPath)
      lossy: AmeSession = initAmeSession(exactAuth(aerInitiator),
        pathLane = dplLossyPath)
      thin: AmeSession = initAmeSession(exactAuth(aerInitiator),
        pathLane = dplThinPath)
    check clean.ameSessionPathDefaults().pathLane == dplCleanPath
    check lossy.ameSessionPathDefaults().pathLane == dplLossyPath
    ## A lossy path asks for more repair than a clean one, and a thin path
    ## asks for smaller chunks. That is the whole point of the feedback.
    check lossy.ameSessionPathDefaults().parityShards >
      clean.ameSessionPathDefaults().parityShards
    check thin.ameSessionPathDefaults().chunkBytes <
      clean.ameSessionPathDefaults().chunkBytes

  # {.testKind: tkRegression.}
  test "the path profile never moves a protection parameter":
    var
      clean: AmeSession = initAmeSession(exactAuth(aerInitiator),
        pathLane = dplCleanPath)
      lossy: AmeSession = initAmeSession(exactAuth(aerInitiator),
        pathLane = dplLossyPath)
    ## Loss is attacker-induced. If the tier, the tag length or the padding
    ## followed it, an attacker who can drop packets could weaken the
    ## protection by dropping them.
    check clean.auth.current.tier == lossy.auth.current.tier
    check clean.auth.current.params.authTagLen ==
      lossy.auth.current.params.authTagLen
    check clean.auth.current.params.padding ==
      lossy.auth.current.params.padding
