## -------------------------------------------------------------------------
## AME Handshake/Package Tests <- authority trust, compression, and repair
## -------------------------------------------------------------------------

import std/unittest

import ../src/protocols/types
import ../src/protocols/ame/types
import ../src/protocols/ame/level1/exchange_paths
import ../src/protocols/ame/level1/suites
import ../src/protocols/ame/level1/path_triggers
import ../src/protocols/ame/types
import ../src/protocols/ame/level3/handshake
import ../src/protocols/ame/level2/session
import ../src/protocols/ame/level1/compression
import ../src/protocols/ame/level3/secure_package
import ../src/protocols/ame/level3/handshake_wire
import ../src/protocols/dac/types
import ../src/protocols/dac/level0/defaults
import ../src/protocols/dac/level2/package_transfer

const
  handshakeKems: AmeKemAlgorithms = [akaX25519, akaFireSaber]

proc handshakeLayout(): AmeSuiteLayout =
  result = defaultAmeLayout(handshakeKems)

proc handshakeTier(L: AmeSuiteLayout,
    kemMask: uint8 = 0b11000000'u8): AmeMaskTier =
  result = initAmeMaskTier(L, 1'u32, initAmeTierMasks(kemMask,
    occupiedAmeMask(L.ciphers.length), occupiedAmeMask(L.macs.length),
    occupiedAmeMask(L.hashes.length), occupiedAmeMask(L.signatures.length),
    occupiedAmeMask(L.kdfs.length)))

proc handshakePath(L: AmeSuiteLayout, t: AmeMaskTier): AmeTierPath =
  result = initAmeTierPath(L, [t])

proc authorityRoot(a: AmeAuthorityKey): AmeAuthorityRoot =
  result = initAmeAuthorityRoot(a)

suite "AME authority handshake and secure package":
  test "seeded authority and peer identities are reproducible":
    var
      authoritySeed: ByteSeq = newSeq[byte](32)
      identitySeed: ByteSeq = newSeq[byte](32)
      authority0: AmeAuthorityKey
      authority1: AmeAuthorityKey
      identity0: AmeIdentityKey
      identity1: AmeIdentityKey
      i: int = 0
    while i < authoritySeed.len:
      authoritySeed[i] = uint8(i + 1)
      identitySeed[i] = uint8(i + 33)
      i = i + 1
    authority0 = initAmeAuthorityKey("seeded-root", asaEd25519, authoritySeed)
    authority1 = initAmeAuthorityKey("seeded-root", asaEd25519, authoritySeed)
    identity0 = initAmeIdentityKey("seeded-peer", asaEd25519, identitySeed)
    identity1 = initAmeIdentityKey("seeded-peer", asaEd25519, identitySeed)
    check authority0.publicKey == authority1.publicKey
    check authority0.secretKey == authority1.secretKey
    check identity0.signingKeys == identity1.signingKeys
    check identity0.secretKeys == identity1.secretKeys

  test "seeded signature stacks are reproducible per layout slot":
    var
      algorithms: AmeSignatureAlgorithms = initAmeSignatureAlgorithms([
        asaEd25519, asaFalcon512])
      seeds: seq[ByteSeq] = @[newSeq[byte](32), newSeq[byte](48)]
      identity0: AmeIdentityKey
      identity1: AmeIdentityKey
      i: int = 0
    while i < seeds[0].len:
      seeds[0][i] = uint8(i + 1)
      i = i + 1
    i = 0
    while i < seeds[1].len:
      seeds[1][i] = uint8(i + 65)
      i = i + 1
    identity0 = initAmeIdentityKey("seeded-stack", algorithms, seeds)
    identity1 = initAmeIdentityKey("seeded-stack", algorithms, seeds)
    check identity0.signingKeys == identity1.signingKeys
    check identity0.secretKeys == identity1.secretKeys

  test "initial handshake preserves an exact caller-selected KEM mask":
    var
      authority: AmeAuthorityKey = initAmeAuthorityKey("mask-root")
      root: AmeAuthorityRoot = authority.authorityRoot()
      clientKey: AmeIdentityKey = initAmeIdentityKey("mask-client")
      serverKey: AmeIdentityKey = initAmeIdentityKey("mask-server")
      clientCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, clientKey, 100'i64, 1000'i64)
      serverCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, serverKey, 100'i64, 1000'i64)
      layout: AmeSuiteLayout = handshakeLayout()
      tier: AmeMaskTier = handshakeTier(layout, 0b10000000'u8)
      client: AmeClientHandshake
      server: tuple[ok: bool, state: AmeServerHandshake,
        peerTrust: AmePeerTrustResult, err: string]
      clientDone: AmeHandshakeResult
      serverDone: AmeHandshakeResult
    client = beginAmeHandshake(71'u64, layout, tier, clientCert, clientKey)
    check client.hello.offer.request.exchangeMask == 0b10000000'u8
    check client.hello.proofs.len == 2
    server = answerAmeHandshake(client.hello, @[handshakePath(layout, tier)],
      root, serverCert,
      serverKey, 500'i64)
    check server.ok
    clientDone = finishAmeHandshake(client, server.state.serverHello,
      root, clientKey, 500'i64)
    check clientDone.ok
    serverDone = acceptAmeHandshake(server.state, clientDone.finish)
    check serverDone.ok
    check clientDone.auth.current.exchange.activeMask == 0b10000000'u8
    check serverDone.auth.current.exchange.activeMask == 0b10000000'u8

  test "authority-authenticated initial handshake creates equal epochs":
    var
      authority: AmeAuthorityKey = initAmeAuthorityKey("example-root")
      root: AmeAuthorityRoot = authority.authorityRoot()
      clientKey: AmeIdentityKey = initAmeIdentityKey("client-1")
      serverKey: AmeIdentityKey = initAmeIdentityKey("server-1")
      clientCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, clientKey, 100'i64, 1000'i64)
      serverCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, serverKey, 100'i64, 1000'i64)
      layout: AmeSuiteLayout = handshakeLayout()
      tier: AmeMaskTier = handshakeTier(layout)
      client: AmeClientHandshake = beginAmeHandshake(42'u64, layout, tier,
        clientCert, clientKey)
      server = answerAmeHandshake(client.hello, [handshakePath(layout, tier)],
        root, serverCert,
        serverKey, 500'i64)
      clientDone: AmeHandshakeResult
      serverDone: AmeHandshakeResult
      helloWire: ByteSeq = @[]
      serverWire: ByteSeq = @[]
      finishWire: ByteSeq = @[]
    helloWire = encodeAmeClientHello(client.hello)
    client.hello = decodeAmeClientHello(helloWire)
    check server.ok
    serverWire = encodeAmeServerHello(server.state.serverHello)
    server.state.serverHello = decodeAmeServerHello(layout, serverWire)
    check client.hello.proofs.len == 2
    check server.state.serverHello.proofs.len == 2
    clientDone = finishAmeHandshake(client, server.state.serverHello, root,
      clientKey, 500'i64)
    check clientDone.ok
    finishWire = encodeAmeClientFinish(clientDone.finish)
    clientDone.finish = decodeAmeClientFinish(finishWire)
    serverDone = acceptAmeHandshake(server.state, clientDone.finish)
    check serverDone.ok
    check clientDone.auth.current.epochId == 1'u32
    check clientDone.auth.sessionId == 42'u64
    check clientDone.auth.endpointRole == aerInitiator
    check serverDone.auth.sessionId == 42'u64
    check serverDone.auth.endpointRole == aerResponder
    check clientDone.auth.current.exchange.sharedSecrets[0] ==
      serverDone.auth.current.exchange.sharedSecrets[0]
    check clientDone.peerTrust.subjectKeyId == "server-1"
    check serverDone.peerTrust.subjectKeyId == "client-1"
    helloWire.setLen(helloWire.len - 1)
    expect ValueError:
      discard decodeAmeClientHello(helloWire)

  test "authenticated session id cannot be replaced by live session setup":
    var
      authority: AmeAuthorityKey = initAmeAuthorityKey("session-root")
      root: AmeAuthorityRoot = authority.authorityRoot()
      clientKey: AmeIdentityKey = initAmeIdentityKey("session-client")
      serverKey: AmeIdentityKey = initAmeIdentityKey("session-server")
      clientCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, clientKey, 1'i64, 1000'i64)
      serverCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, serverKey, 1'i64, 1000'i64)
      layout: AmeSuiteLayout = handshakeLayout()
      tier: AmeMaskTier = handshakeTier(layout)
      client: AmeClientHandshake = beginAmeHandshake(77'u64, layout, tier,
        clientCert, clientKey)
      server = answerAmeHandshake(client.hello, [handshakePath(layout, tier)],
        root, serverCert, serverKey, 5'i64)
      clientDone: AmeHandshakeResult = finishAmeHandshake(client,
        server.state.serverHello, root, clientKey, 5'i64)
    expect ValueError:
      discard initAmeSession(clientDone.auth, sessionId = 78'u64,
        peerTrustRequired = false)
    check initAmeSession(clientDone.auth,
      peerTrustRequired = false).sessionId == 77'u64

  test "consumptive finish erases retained handshake secrets":
    var
      authority: AmeAuthorityKey = initAmeAuthorityKey("clear-root")
      root: AmeAuthorityRoot = authority.authorityRoot()
      clientKey: AmeIdentityKey = initAmeIdentityKey("clear-client")
      serverKey: AmeIdentityKey = initAmeIdentityKey("clear-server")
      clientCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, clientKey, 1'i64, 1000'i64)
      serverCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, serverKey, 1'i64, 1000'i64)
      layout: AmeSuiteLayout = handshakeLayout()
      tier: AmeMaskTier = handshakeTier(layout)
      client: AmeClientHandshake = beginAmeHandshake(88'u64, layout, tier,
        clientCert, clientKey)
      server = answerAmeHandshake(client.hello, [handshakePath(layout, tier)],
        root, serverCert, serverKey, 5'i64)
      clientDone: AmeHandshakeResult = finishAmeHandshake(client,
        server.state.serverHello, root, clientKey, 5'i64)
      serverDone: AmeHandshakeResult = acceptAmeHandshake(server.state,
        clientDone.finish)
    check clientDone.ok and serverDone.ok
    check client.secretKeys.len == 0
    check client.hello.sessionId == 0'u64
    check server.state.sharedSecrets.len == 0
    check server.state.localSignatureSecretKeys.len == 0

  test "handshake rejects a tier outside the supported path and mask tampering":
    var
      authority: AmeAuthorityKey = initAmeAuthorityKey("tier-root")
      root: AmeAuthorityRoot = authority.authorityRoot()
      clientKey: AmeIdentityKey = initAmeIdentityKey("tier-client")
      serverKey: AmeIdentityKey = initAmeIdentityKey("tier-server")
      clientCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, clientKey, 1'i64, 1000'i64)
      serverCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, serverKey, 1'i64, 1000'i64)
      layout: AmeSuiteLayout = handshakeLayout()
      initial: AmeMaskTier = handshakeTier(layout, 0b10000000'u8)
      other: AmeMaskTier = initial
      client: AmeClientHandshake
      answer: tuple[ok: bool, state: AmeServerHandshake,
        peerTrust: AmePeerTrustResult, err: string]
    other.tierId = 2'u32
    client = beginAmeHandshake(72'u64, layout, other, clientCert, clientKey)
    answer = answerAmeHandshake(client.hello,
      [handshakePath(layout, initial)], root, serverCert, serverKey, 5'i64)
    check not answer.ok
    check answer.err == "client exact AME layout and initial tier are not supported"
    client = beginAmeHandshake(73'u64, layout, initial, clientCert, clientKey)
    client.hello.initialTier.tierId = 3'u32
    answer = answerAmeHandshake(client.hello,
      [handshakePath(layout, client.hello.initialTier)], root, serverCert,
      serverKey, 5'i64)
    check not answer.ok
    check answer.err == "client hello initial tier exchange is invalid"

  test "reciprocal public-key pins authenticate the complete handshake":
    var
      clientKey: AmeIdentityKey = initAmeIdentityKey("pinned-client")
      serverKey: AmeIdentityKey = initAmeIdentityKey("pinned-server")
      clientPin: AmePinnedPeerIdentity = pinnedPeerIdentity(clientKey)
      serverPin: AmePinnedPeerIdentity = pinnedPeerIdentity(serverKey)
      layout: AmeSuiteLayout = handshakeLayout()
      tier: AmeMaskTier = handshakeTier(layout)
      client: AmeClientHandshake = beginAmePinnedHandshake(84'u64, layout,
        tier, clientKey)
      server = answerAmePinnedHandshake(client.hello,
        [handshakePath(layout, tier)], clientPin,
        serverKey)
      clientDone: AmeHandshakeResult
      serverDone: AmeHandshakeResult
      helloWire: ByteSeq = @[]
      serverWire: ByteSeq = @[]
    helloWire = encodeAmeClientHello(client.hello)
    client.hello = decodeAmeClientHello(helloWire)
    check server.ok
    serverWire = encodeAmeServerHello(server.state.serverHello)
    server.state.serverHello = decodeAmeServerHello(layout, serverWire)
    clientDone = finishAmePinnedHandshake(client, server.state.serverHello,
      serverPin, clientKey)
    check clientDone.ok
    serverDone = acceptAmeHandshake(server.state, clientDone.finish)
    check serverDone.ok
    check clientDone.peerTrust.authority == "pinned-peer"
    check clientDone.peerTrust.subjectKeyId == "pinned-server"
    check serverDone.peerTrust.authority == "pinned-peer"
    check serverDone.peerTrust.subjectKeyId == "pinned-client"
    check clientDone.auth.current.exchange.sharedSecrets[0] ==
      serverDone.auth.current.exchange.sharedSecrets[0]

  test "wrong pins and certificate descriptors fail closed":
    var
      authority: AmeAuthorityKey = initAmeAuthorityKey("pin-root")
      clientKey: AmeIdentityKey = initAmeIdentityKey("pin-client")
      serverKey: AmeIdentityKey = initAmeIdentityKey("pin-server")
      strangerKey: AmeIdentityKey = initAmeIdentityKey("pin-stranger")
      clientCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, clientKey, 1'i64, 1000'i64)
      layout: AmeSuiteLayout = handshakeLayout()
      tier: AmeMaskTier = handshakeTier(layout)
      pinnedClient: AmeClientHandshake = beginAmePinnedHandshake(85'u64,
        layout, tier, clientKey)
      certifiedClient: AmeClientHandshake = beginAmeHandshake(86'u64,
        layout, tier, clientCert, clientKey)
      answer: tuple[ok: bool, state: AmeServerHandshake,
        peerTrust: AmePeerTrustResult, err: string]
    answer = answerAmePinnedHandshake(pinnedClient.hello,
      [handshakePath(layout, tier)],
      pinnedPeerIdentity(strangerKey), serverKey)
    check not answer.ok
    check answer.err == "peer identity does not match the pinned public key"
    answer = answerAmePinnedHandshake(certifiedClient.hello,
      [handshakePath(layout, tier)],
      pinnedPeerIdentity(clientKey), serverKey)
    check not answer.ok
    check answer.err ==
      "pinned peer sent a certificate instead of a direct identity"

  test "tampered and expired authority handshakes fail closed":
    var
      authority: AmeAuthorityKey = initAmeAuthorityKey("root-a")
      root: AmeAuthorityRoot = authority.authorityRoot()
      clientKey: AmeIdentityKey = initAmeIdentityKey("client-a")
      serverKey: AmeIdentityKey = initAmeIdentityKey("server-a")
      clientCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, clientKey, 100'i64, 200'i64)
      serverCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, serverKey, 100'i64, 200'i64)
      layout: AmeSuiteLayout = handshakeLayout()
      tier: AmeMaskTier = handshakeTier(layout)
      client: AmeClientHandshake = beginAmeHandshake(7'u64, layout, tier,
        clientCert, clientKey)
      answer: tuple[ok: bool, state: AmeServerHandshake,
        peerTrust: AmePeerTrustResult, err: string]
    answer = answerAmeHandshake(client.hello, [handshakePath(layout, tier)],
      root, serverCert,
      serverKey, 300'i64)
    check not answer.ok
    check answer.err == "certificate is outside its validity period"
    client.hello.proofs[0][0] = client.hello.proofs[0][0] xor 1'u8
    answer = answerAmeHandshake(client.hello, [handshakePath(layout, tier)],
      root, serverCert,
      serverKey, 150'i64)
    check not answer.ok
    check answer.err == "client hello identity proof is invalid"
    client = beginAmeHandshake(8'u64, layout, tier, clientCert, clientKey)
    answer = answerAmeHandshake(client.hello, [handshakePath(layout, tier)],
      root, serverCert,
      serverKey, 150'i64, ["client-a"])
    check not answer.ok
    check answer.err == "certificate subject is revoked"

  test "every selected initial KEM signature is required":
    var
      authority: AmeAuthorityKey = initAmeAuthorityKey("stack-root")
      root: AmeAuthorityRoot = authority.authorityRoot()
      clientKey: AmeIdentityKey = initAmeIdentityKey("stack-client")
      serverKey: AmeIdentityKey = initAmeIdentityKey("stack-server")
      clientCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, clientKey, 1'i64, 1000'i64)
      serverCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, serverKey, 1'i64, 1000'i64)
      layout: AmeSuiteLayout = handshakeLayout()
      tier: AmeMaskTier = handshakeTier(layout)
      client: AmeClientHandshake = beginAmeHandshake(9'u64, layout, tier,
        clientCert, clientKey)
      answer: tuple[ok: bool, state: AmeServerHandshake,
        peerTrust: AmePeerTrustResult, err: string]
    check client.hello.proofs.len == 2
    client.hello.proofs[1][0] = client.hello.proofs[1][0] xor 1'u8
    answer = answerAmeHandshake(client.hello, [handshakePath(layout, tier)],
      root, serverCert, serverKey, 5'i64)
    check not answer.ok
    check answer.err == "client hello identity proof is invalid"
    check answer.state.sharedSecrets.len == 0

  test "compressed authenticated package repairs loss and restores plaintext":
    var
      authority: AmeAuthorityKey = initAmeAuthorityKey("package-root")
      root: AmeAuthorityRoot = authority.authorityRoot()
      clientKey: AmeIdentityKey = initAmeIdentityKey("sender")
      serverKey: AmeIdentityKey = initAmeIdentityKey("receiver")
      clientCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, clientKey, 1'i64, 1000'i64)
      serverCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, serverKey, 1'i64, 1000'i64)
      layout: AmeSuiteLayout = handshakeLayout()
      tier: AmeMaskTier = handshakeTier(layout)
      clientHs: AmeClientHandshake = beginAmeHandshake(99'u64, layout, tier,
        clientCert, clientKey)
      serverHs = answerAmeHandshake(clientHs.hello,
        [handshakePath(layout, tier)], root, serverCert,
        serverKey, 5'i64)
      sender: AmeHandshakeResult = finishAmeHandshake(clientHs,
        serverHs.state.serverHello, root, clientKey, 5'i64)
      receiver: AmeHandshakeResult = acceptAmeHandshake(serverHs.state,
        sender.finish)
      plaintext: ByteSeq = newSeq[byte](20_000)
      plan: AmeSecurePackagePlan
      packageReceiver: DacPackageReceiver
      hint: DacRepairHint
      exactRepairs: seq[DacRepairChunk] = @[]
      packageResult: DacPackageResult
      restored: AmeSecurePackageResult
      i: int = 0
    while i < plaintext.len:
      plaintext[i] = uint8(i mod 251)
      i = i + 1
    check sender.ok and receiver.ok
    plan = planAmeSecurePackage(sender.auth, 55'u64, plaintext,
      cleanLanDacDefaults())
    packageReceiver = initDacPackageReceiver(plan.package.manifest)
    for chunk in plan.package.chunks:
      if chunk.chunkId notin {1'u16, 3'u16}:
        packageReceiver.acceptDacPackageChunk(chunk)
    check packageReceiver.repairGroup(plan.package.repairs[0]) == false
    hint = packageReceiver.buildDacRepairHint()
    exactRepairs = answerDacRepairHint(plan.package, hint)
    for repair in exactRepairs:
      packageReceiver.acceptDacRepairChunk(repair)
    packageResult = finishDacPackage(packageReceiver)
    check packageResult.ok
    check packageResult.commit.status == dcsCommittedWithRepair
    restored = finishAmeSecurePackage(receiver.auth, packageReceiver,
      plan.compression)
    check restored.err == ""
    check restored.ok
    check restored.payload == plaintext
    check restored.status == dcsCommittedWithRepair

  test "Eir compression shrinks repeated data and restores it exactly":
    var
      plaintext: ByteSeq = newSeq[byte](10_000)
      policy: AmeCompressionPolicy = defaultAmeCompressionPolicy()
      encoded: ByteSeq = @[]
      decoded: ByteSeq = @[]
    for i in 0 ..< plaintext.len:
      plaintext[i] = if i < 5000: 4'u8 else: 8'u8
    encoded = encodeAmeCompressed(plaintext, policy)
    check encoded[4] == uint8(ord(aczEirRle))
    check encoded.len < plaintext.len
    decoded = decodeAmeCompressed(encoded, policy)
    check decoded == plaintext

  test "one missing chunk is recovered by XOR and checked by Eir parity":
    var
      data: ByteSeq = newSeq[byte](5000)
      plan: DacPackagePlan
      receiver: DacPackageReceiver
      result: DacPackageResult
      i: int = 0
    while i < data.len:
      data[i] = uint8(i mod 251)
      i = i + 1
    plan = planDacPackage(8'u64, data, cleanLanDacDefaults())
    receiver = initDacPackageReceiver(plan.manifest)
    for chunk in plan.chunks:
      if chunk.chunkId != 2'u16:
        receiver.acceptDacPackageChunk(chunk)
    check receiver.repairGroup(plan.repairs[0])
    result = finishDacPackage(receiver)
    check result.ok
    check result.payload == data

  test "decompression bomb metadata is rejected before Eir decode":
    var
      envelope: ByteSeq = @[byte 'E', byte 'I', byte 'R', byte '1',
        byte ord(aczEirRle), 0, 0, 1, 0, 1, 0, 0, 0, 0]
    expect ValueError:
      discard decodeAmeCompressed(envelope)

  test "authority root construction rejects incomplete pinning material":
    var
      authority: AmeAuthorityKey = initAmeAuthorityKey("root-guard")
    expect ValueError:
      discard initAmeAuthorityRoot("", authority.algorithm, authority.publicKey)
    expect ValueError:
      discard initAmeAuthorityRoot(authority.name, authority.algorithm, @[])

  test "certificate path refuses unsigned pinned descriptors":
    var
      layout: AmeSuiteLayout = handshakeLayout()
      authority: AmeAuthorityKey = initAmeAuthorityKey("real-root")
      peer: AmeIdentityKey = initAmeIdentityKey("peer", layout.signatures)
      descriptor: AmeIdentityCertificate
      emptyRoot: AmeAuthorityRoot
      trust: AmePeerTrustResult
    # a pinned descriptor carries no authority and no authority signature
    descriptor.subject = peer.subject
    descriptor.signingKeys = peer.signingKeys
    descriptor.validFromUnix = 0'i64
    descriptor.validUntilUnix = high(int64)
    # a default-constructed root must never match its empty authority field
    trust = verifyAmeIdentityCertificate(descriptor, emptyRoot, 500'i64)
    check not trust.ok
    check trust.err == "pinned authority root is incomplete"
    # nor may a real root accept an unsigned descriptor
    trust = verifyAmeIdentityCertificate(descriptor, authority.authorityRoot(),
      500'i64)
    check not trust.ok
    check trust.err == "certificate carries no authority signature"

  test "zero session id is refused by policy instead of raising":
    var
      layout: AmeSuiteLayout = handshakeLayout()
      tier: AmeMaskTier = handshakeTier(layout)
      authority: AmeAuthorityKey = initAmeAuthorityKey("policy-root")
      clientKey: AmeIdentityKey = initAmeIdentityKey("client",
        layout.signatures)
      serverKey: AmeIdentityKey = initAmeIdentityKey("server",
        layout.signatures)
      clientCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, clientKey, 1'i64, 1000'i64)
      serverCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, serverKey, 1'i64, 1000'i64)
      client: AmeClientHandshake = beginAmeHandshake(64'u64, layout, tier,
        clientCert, clientKey)
      server: tuple[ok: bool, state: AmeServerHandshake,
        peerTrust: AmePeerTrustResult, err: string]
    client.hello.sessionId = 0'u64
    server = answerAmeHandshake(client.hello, [handshakePath(layout, tier)],
      authority.authorityRoot(), serverCert, serverKey, 500'i64)
    check not server.ok
    check server.err == "client hello shape is invalid"

  test "responder state without verified trust cannot accept a finish":
    var
      untrusted: AmeServerHandshake
      accepted: AmeHandshakeResult
    accepted = acceptAmeHandshake(untrusted, default(AmeClientFinish))
    check not accepted.ok
    check accepted.err == "AME responder state carries no verified peer trust"
