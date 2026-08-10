## -------------------------------------------------------------------------
## AME Mask Tier Tests <- AME2 frames and atomic epoch transitions
## -------------------------------------------------------------------------

import std/unittest

import ../src/protocols/types
import ../src/protocols/ame/types
import ../src/protocols/ame/level1/exchange_paths
import ../src/protocols/ame/level1/suites
import ../src/protocols/ame/level1/derivation
import ../src/protocols/ame/types
import ../src/protocols/ame/level2/protection
import ../src/protocols/ame/level2/session
import ../src/protocols/ame/level1/path_triggers
import ../src/protocols/fomke/types
import ../src/protocols/dac/types
import ../src/protocols/dac/level0/framing

const
  exactKems: AmeKemAlgorithms = [akaFireSaber, akaX25519, akaFireSaber]

proc exactLayout(): AmeSuiteLayout =
  result = defaultAmeLayout(exactKems)

proc exactTier(L: AmeSuiteLayout, id: uint32, kem: uint8): AmeMaskTier =
  result = initAmeMaskTier(L, id, initAmeTierMasks(kem,
    occupiedAmeMask(L.ciphers.length), occupiedAmeMask(L.macs.length),
    occupiedAmeMask(L.hashes.length), occupiedAmeMask(L.signatures.length),
    occupiedAmeMask(L.kdfs.length)))

proc exactAuth(): AmeAuthPackage =
  var
    layout: AmeSuiteLayout = exactLayout()
    tier: AmeMaskTier = exactTier(layout, 1'u32, 0b10000000'u8)
    state: AmeExchangeState = initAmeExchangeState(exactKems)
  applyAmeExchange(state, initAmeExchangeRequest(exactKems, tier,
    0b10000000'u8),
    [@[byte 9, 8, 7, 6, 5, 4, 3, 2]])
  result = initAmeAuthPackage(layout, tier, state)

proc layeredAuth(): AmeAuthPackage =
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
  result = initAmeAuthPackage(layout, tier, state)

proc exactUpgradeSession(): AmeSession =
  var
    auth: AmeAuthPackage = exactAuth()
    target: AmeMaskTier = exactTier(auth.current.layout, 2'u32,
      0b11000000'u8)
    path: AmeTierPath = initAmeTierPath(auth.current.layout,
      [auth.current.tier, target])
  result = initAmeSession(auth, path, peerTrustRequired = false)

proc layeredUpgradeSession(): AmeSession =
  var
    auth: AmeAuthPackage = layeredAuth()
    layout: AmeSuiteLayout = auth.current.layout
    target: AmeMaskTier = initAmeMaskTier(layout, 2'u32,
      initAmeTierMasks(0b10000000'u8, 0b11000000'u8, 0b11000000'u8,
        0b11000000'u8, 0b11000000'u8, 0b11000000'u8))
    path: AmeTierPath = initAmeTierPath(layout, [auth.current.tier, target])
  result = initAmeSession(auth, path, peerTrustRequired = false)

proc installSignaturePeers(A, B: var AmeSession) =
  var
    aKeys = generateAmeSigningKeys(A.auth.current.layout,
      fullAmeMaskTier(A.auth.current.layout))
    bKeys = generateAmeSigningKeys(B.auth.current.layout,
      fullAmeMaskTier(B.auth.current.layout))
  A.auth.localSignatureSecretKeys = aKeys.secretKeys
  A.auth.peerSignaturePublicKeys = bKeys.publicKeys
  B.auth.localSignatureSecretKeys = bKeys.secretKeys
  B.auth.peerSignaturePublicKeys = aKeys.publicKeys
  A.auth.endpointRole = aerInitiator
  B.auth.endpointRole = aerResponder

proc installTrafficPeers(A, B: var AmeSession) =
  A.auth.endpointRole = aerInitiator
  B.auth.endpointRole = aerResponder

proc installLoopbackSignatures(S: var AmeSession) =
  var
    keys = generateAmeSigningKeys(S.auth.current.layout,
      fullAmeMaskTier(S.auth.current.layout))
  S.auth.localSignatureSecretKeys = keys.secretKeys
  S.auth.peerSignaturePublicKeys = keys.publicKeys

suite "AME mask-tier sessions":
  test "TCP frame roundtrips under exact agreement":
    var
      sender: AmeSession = initAmeSession(exactAuth(),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(exactAuth(),
        peerTrustRequired = false)
      payload: ByteSeq = @[byte 1, 2, 3, 4]
      frame: ByteSeq = @[]
      opened: AmeOpenResult
    installTrafficPeers(sender, receiver)
    frame = sealAmeTcpFrame(sender, payload)
    opened = openAmeTcpFrame(receiver, frame)
    check opened.ok
    check opened.packet.payload == payload
    check receiver.pending == 1

  test "directional keys reject reflected TCP and DAC frames":
    var
      sender: AmeSession = initAmeSession(exactAuth(),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(exactAuth(),
        peerTrustRequired = false)
      tcpFrame: ByteSeq = @[]
      dacFrame: ByteSeq = @[]
      opened: AmeOpenResult
    installTrafficPeers(sender, receiver)
    tcpFrame = sealAmeTcpFrame(sender, @[byte 1, 2])
    opened = openAmeTcpFrame(sender, tcpFrame)
    check not opened.ok
    check opened.err == "AME authentication failed"
    opened = openAmeTcpFrame(receiver, tcpFrame)
    check opened.ok
    dacFrame = sealAmeDacFrame(sender, @[byte 3, 4])
    opened = openAmeDacFrame(sender, dacFrame)
    check not opened.ok
    check opened.err == "AME authentication failed"
    opened = openAmeDacFrame(receiver, dacFrame)
    check opened.ok

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

  test "DAC frame roundtrips and binds carrier metadata":
    var
      sender: AmeSession = initAmeSession(exactAuth(),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(exactAuth(),
        peerTrustRequired = false)
      payload: ByteSeq = @[byte 5, 6, 7]
      frame: ByteSeq = @[]
      opened: AmeOpenResult
    installTrafficPeers(sender, receiver)
    frame = sealAmeDacFrame(sender, payload)
    opened = openAmeDacFrame(receiver, frame)
    check opened.ok
    check opened.packet.payload == payload
    frame[^1] = frame[^1] xor 1'u8
    receiver = initAmeSession(exactAuth(), peerTrustRequired = false)
    installTrafficPeers(sender, receiver)
    opened = openAmeDacFrame(receiver, frame)
    check not opened.ok

  test "DAC epoch is derived from and bound to the protected AME epoch":
    var
      sender: AmeSession = initAmeSession(exactAuth(),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(exactAuth(),
        peerTrustRequired = false)
      frame: ByteSeq = @[]
      decoded: DacDecodedFrame
      opened: AmeOpenResult
    installTrafficPeers(sender, receiver)
    frame = sealAmeDacFrame(sender, @[byte 5, 6, 7])
    decoded = decodeDacFrame(frame)
    check decoded.header.epochId == uint16(sender.auth.current.epochId)
    frame[19] = frame[19] xor 0x01'u8
    opened = openAmeDacFrame(receiver, frame)
    check not opened.ok
    check opened.err == "AME DAC epoch mismatch"

  test "DAC rejects epochs that cannot fit its wire field":
    var
      sender: AmeSession = initAmeSession(exactAuth(),
        peerTrustRequired = false)
    sender.auth.current.epochId = uint32(high(uint16)) + 1'u32
    expect ValueError:
      discard sealAmeDacFrame(sender, @[byte 5])

  test "DAC SuperClean path carries extended AME frames":
    var
      sender: AmeSession = initAmeSession(exactAuth(),
        pathLane = dplSuperCleanPath, peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(exactAuth(),
        pathLane = dplSuperCleanPath, peerTrustRequired = false)
      payload: ByteSeq = newSeq[byte](70_000)
      frame: ByteSeq = @[]
      decoded: DacDecodedFrame
      opened: AmeOpenResult
    installTrafficPeers(sender, receiver)
    payload[0] = 1'u8
    payload[^1] = 2'u8
    frame = sealAmeDacFrame(sender, payload)
    decoded = decodeDacFrame(frame)
    opened = openAmeDacFrame(receiver, frame)
    check decoded.header.bodyLenMode == dblU32
    check decoded.flags.extendedBodyLen
    check opened.ok
    check opened.packet.payload == payload

  test "DAC normal paths widen framing for extended AME frames":
    var
      sender: AmeSession = initAmeSession(exactAuth(),
        pathLane = dplCleanPath, peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(exactAuth(),
        pathLane = dplCleanPath, peerTrustRequired = false)
      payload: ByteSeq = newSeq[byte](70_000)
      frame: ByteSeq = @[]
      decoded: DacDecodedFrame
      opened: AmeOpenResult
    installTrafficPeers(sender, receiver)
    frame = sealAmeDacFrame(sender, payload)
    decoded = decodeDacFrame(frame)
    opened = openAmeDacFrame(receiver, frame)
    check decoded.header.bodyLenMode == dblU32
    check decoded.flags.extendedBodyLen
    check opened.ok
    check opened.packet.payload == payload

  test "authenticated progress expires the retiring epoch":
    var
      sender: AmeSession = initAmeSession(exactAuth(),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(exactAuth(),
        peerTrustRequired = false)
      frame: ByteSeq = @[]
      opened: AmeOpenResult
    installTrafficPeers(sender, receiver)
    receiver.auth.retiring = receiver.auth.current
    receiver.auth.retiringFramesLeft = 1
    receiver.auth.current.epochId = receiver.auth.current.epochId + 1'u32
    frame = sealAmeTcpFrame(sender, @[byte 3, 2, 1])
    opened = openAmeTcpFrame(receiver, frame)
    check opened.ok
    check receiver.auth.retiring.epochId == 0'u32
    check receiver.auth.retiringFramesLeft == 0

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

  test "authenticated TCP exchange commits only after epoch-ready":
    var
      client: AmeSession = exactUpgradeSession()
      server: AmeSession = exactUpgradeSession()
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

  test "FOMKE role must match the AME endpoint role":
    var
      connection: AmeSession = initAmeSession(exactAuth(),
        peerTrustRequired = false)
    connection.auth.endpointRole = aerResponder
    expect ValueError:
      enableAmeFomke(connection, frInitiator, 0)

  test "candidate rekey does not mutate the current epoch":
    var
      client: AmeSession = initAmeSession(exactAuth(),
        peerTrustRequired = false)
      server: AmeSession = initAmeSession(exactAuth(),
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

  test "receiver rejects either KEM offer signature before candidate mutation":
    var
      client: AmeSession = exactUpgradeSession()
      server: AmeSession = exactUpgradeSession()
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

  test "initiator rejects KEM reply signature before epoch rotation":
    var
      client: AmeSession = exactUpgradeSession()
      server: AmeSession = exactUpgradeSession()
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

  test "non-KEM masks rotate atomically without replacing KEM secrets":
    var
      client: AmeSession = layeredUpgradeSession()
      server: AmeSession = layeredUpgradeSession()
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
    enableAmeFomke(client, frInitiator, 0)
    enableAmeFomke(server, frResponder, 0)
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

  test "authenticated DAC exchange rejects tampering and replay":
    var
      client: AmeSession = exactUpgradeSession()
      server: AmeSession = exactUpgradeSession()
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

  test "DAC exchange control frames bind the embedded epoch":
    var
      client: AmeSession = exactUpgradeSession()
      server: AmeSession = exactUpgradeSession()
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

  test "DAC accepts bounded out-of-order frames and rejects duplicates":
    var
      sender: AmeSession = initAmeSession(exactAuth(),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(exactAuth(),
        peerTrustRequired = false)
      first: ByteSeq = @[]
      second: ByteSeq = @[]
      opened: AmeOpenResult
    installTrafficPeers(sender, receiver)
    first = sealAmeDacFrame(sender, @[byte 1])
    second = sealAmeDacFrame(sender, @[byte 2])
    opened = openAmeDacFrame(receiver, second)
    check opened.ok
    opened = openAmeDacFrame(receiver, first)
    check opened.ok
    opened = openAmeDacFrame(receiver, first)
    check not opened.ok
    check opened.err == "AME replay rejected"

  test "envelope and sequence limits fail closed":
    var
      connection: AmeSession = initAmeSession(exactAuth(),
        peerTrustRequired = false)
      envelope: ByteSeq = @[byte 'A', byte 'E', byte 'C', byte '3',
        3, 0, 1, 0, 0, 0, 24, 0, 32, 0, 0, 0, 0x00, 0x80]
    expect ValueError:
      discard decodeAmeProtectedBody(envelope)
    connection.nextAmeSequence = high(uint32)
    expect ValueError:
      discard sealAmeTcpFrame(connection, @[byte 1])

  test "trigger threshold multiplication rejects overflow":
    var
      path: AmeTierPath = exactKems.ameInitTierPath()
    expect ValueError:
      path.setTrigger(1, high(uint64))

  test "simultaneous rekey converges instead of splitting the epoch":
    var
      A: AmeSession = exactUpgradeSession()
      B: AmeSession = exactUpgradeSession()
      target: AmeMaskTier = exactTier(A.auth.current.layout, 2'u32,
        0b11000000'u8)
      request: AmeExchangeRequest
      offerA: AmeExchangeOffer
      offerB: AmeExchangeOffer
      replyB: AmeExchangeReply
    installSignaturePeers(A, B)
    request = initAmeExchangeRequest(A.auth.current.layout.kems, target,
      0b01000000'u8)
    # both endpoints trip their transfer trigger at the same time
    offerA = beginAmeSessionExchange(A, request)
    offerB = beginAmeSessionExchange(B, request)
    # the responder yields its own exchange and answers the initiator
    replyB = answerAmeSessionExchange(B, offerA)
    check not B.pendingExchange.active
    # the initiator keeps its own exchange and refuses the responder's offer
    expect ValueError:
      discard answerAmeSessionExchange(A, offerB)
    finishAmeSessionExchange(A, replyB)
    confirmAmeSessionExchange(B, offerA.requestId,
      B.pendingIncoming.candidate.epochId, target)
    # both land on one epoch built from one set of KEM secrets
    check A.auth.current.epochId == B.auth.current.epochId
    check A.auth.current.exchange.sharedSecrets[1] ==
      B.auth.current.exchange.sharedSecrets[1]

  test "outgoing exchange is refused while a candidate epoch is pending":
    var
      A: AmeSession = exactUpgradeSession()
      B: AmeSession = exactUpgradeSession()
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
