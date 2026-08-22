## -------------------------------------------------------------------------
## AME Handshake/Package Tests <- private identities, trust, and repair
## -------------------------------------------------------------------------
##
## The handshake under test hides who is talking. Only the two nonces and the
## key material travel in the clear; both certificates ride inside sealed
## blocks. These tests check that, and check what happens when each of the
## things that could go wrong does.

import std/unittest

import ../src/protocols/types
import ../src/protocols/ame/types
import ../src/protocols/ame/level1/exchange_paths
import ../src/protocols/ame/level1/suites
import ../src/protocols/ame/level1/path_triggers
import ../src/protocols/ame/level1/signatures
import ../src/protocols/ame/level2/wire
import ../src/protocols/ame/level3/handshake
import ../src/protocols/ame/level2/session
import ../src/protocols/ame/level1/compression
import ../src/protocols/ame/level3/secure_package
import ../src/protocols/ame/level3/handshake_wire
import ../src/protocols/ame/level3/handshake_transport
import ../src/protocols/dac/types
import ../src/protocols/dac/level0/defaults
import ../src/protocols/dac/level2/package_transfer

const
  handshakeKems: AmeKemAlgorithms = [akaX25519, akaFireSaber]
  nowUnix: int64 = 500'i64
  validFrom: int64 = 100'i64
  validUntil: int64 = 1000'i64

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

## One complete pair of endpoints, run to a finished session. Every test that
## needs a working handshake starts from here rather than repeating it.
type
  Pair = object
    authority: AmeAuthorityKey
    root: AmeAuthorityRoot
    clientKey: AmeIdentityKey
    serverKey: AmeIdentityKey
    clientCert: AmeIdentityCertificate
    serverCert: AmeIdentityCertificate
    layout: AmeSuiteLayout
    tier: AmeMaskTier

proc newPair(name: string): Pair =
  result.authority = initAmeAuthorityKey(name & "-root")
  result.root = initAmeAuthorityRoot(result.authority)
  result.clientKey = initAmeIdentityKey(name & "-client")
  result.serverKey = initAmeIdentityKey(name & "-server")
  result.clientCert = issueAmeIdentityCertificate(result.authority,
    result.clientKey, 11'u64, validFrom, validUntil)
  result.serverCert = issueAmeIdentityCertificate(result.authority,
    result.serverKey, 22'u64, validFrom, validUntil)
  result.layout = handshakeLayout()
  result.tier = handshakeTier(result.layout)

suite "AME private handshake":
  test "seeded authority and peer identities are reproducible":
    var
      authoritySeeds: seq[ByteSeq] = @[]
      identitySeeds: seq[ByteSeq] = @[]
      algorithms: AmeSignatureAlgorithms = initAmeSignatureAlgorithms(
        defaultAmeSigSlots())
      authority0: AmeAuthorityKey
      authority1: AmeAuthorityKey
      identity0: AmeIdentityKey
      identity1: AmeIdentityKey
      seed: ByteSeq = @[]
      i: int = 0
      j: int = 0
    while i < int(algorithms.length):
      seed = newSeq[byte](32)
      j = 0
      while j < seed.len:
        seed[j] = uint8(j + 1 + i * 7)
        j = j + 1
      authoritySeeds.add(seed)
      seed = newSeq[byte](32)
      j = 0
      while j < seed.len:
        seed[j] = uint8(j + 33 + i * 7)
        j = j + 1
      identitySeeds.add(seed)
      i = i + 1
    authority0 = initAmeAuthorityKey("seeded-root", algorithms, authoritySeeds)
    authority1 = initAmeAuthorityKey("seeded-root", algorithms, authoritySeeds)
    identity0 = initAmeIdentityKey("seeded-peer", algorithms, identitySeeds)
    identity1 = initAmeIdentityKey("seeded-peer", algorithms, identitySeeds)
    check authority0.signingKeys == authority1.signingKeys
    check authority0.secretKeys == authority1.secretKeys
    check identity0.signingKeys == identity1.signingKeys
    check authority0.signingKeys.len == int(algorithms.length)

  test "neither certificate appears anywhere in the clear":
    var
      p: Pair = newPair("private")
      client: AmeClientHandshake = beginAmeHandshake(42'u64, p.layout, p.tier)
      server = answerAmeHandshake(client.hello, [handshakePath(p.layout,
        p.tier)], p.serverCert, p.serverKey)
      helloWire: ByteSeq = @[]
      serverWire: ByteSeq = @[]
      finishWire: ByteSeq = @[]
      clientDone: AmeHandshakeResult
      subject: ByteSeq = @[]
      i: int = 0
      found: bool = false
    check server.ok
    helloWire = encodeAmeClientHello(client.hello)
    serverWire = encodeAmeServerHello(server.state.serverHello)
    clientDone = finishAmeHandshake(client, server.state.serverHello, p.root,
      p.clientCert, p.clientKey, nowUnix)
    check clientDone.ok
    finishWire = encodeAmeClientFinish(clientDone.finish)
    ## The subject name is the most recognisable thing in a certificate. If
    ## it appeared in any record on the wire, an observer would learn who is
    ## connecting without breaking anything.
    subject = @[]
    for c in "private-server":
      subject.add(uint8(ord(c)))
    for wire in [helloWire, serverWire, finishWire]:
      i = 0
      while i + subject.len <= wire.len:
        if wire[i ..< i + subject.len] == subject:
          found = true
        i = i + 1
    check not found

  test "authority-authenticated handshake creates equal epochs":
    var
      p: Pair = newPair("example")
      client: AmeClientHandshake = beginAmeHandshake(42'u64, p.layout, p.tier)
      server = answerAmeHandshake(client.hello, [handshakePath(p.layout,
        p.tier)], p.serverCert, p.serverKey)
      clientDone: AmeHandshakeResult
      serverDone: AmeHandshakeResult
      helloWire: ByteSeq = @[]
      serverWire: ByteSeq = @[]
      finishWire: ByteSeq = @[]
    check server.ok
    ## Every record makes a full round trip through its codec, so the test
    ## exercises the wire form and not just the in-memory objects.
    helloWire = encodeAmeClientHello(client.hello)
    client.hello = decodeAmeClientHello(helloWire)
    serverWire = encodeAmeServerHello(server.state.serverHello)
    server.state.serverHello = decodeAmeServerHello(p.layout, serverWire)
    clientDone = finishAmeHandshake(client, server.state.serverHello, p.root,
      p.clientCert, p.clientKey, nowUnix)
    check clientDone.ok
    finishWire = encodeAmeClientFinish(clientDone.finish)
    clientDone.finish = decodeAmeClientFinish(finishWire)
    serverDone = acceptAmeHandshake(server.state, clientDone.finish, p.root,
      nowUnix)
    check serverDone.err == ""
    check serverDone.ok
    check clientDone.auth.current.epochId == 1'u32
    check clientDone.auth.sessionId == 42'u64
    check clientDone.auth.endpointRole == aerInitiator
    check serverDone.auth.sessionId == 42'u64
    check serverDone.auth.endpointRole == aerResponder
    check clientDone.auth.current.exchange.sharedSecrets[0] ==
      serverDone.auth.current.exchange.sharedSecrets[0]
    check clientDone.auth.current.transcriptSalt ==
      serverDone.auth.current.transcriptSalt
    check clientDone.peerTrust.subjectKeyId == "example-server"
    check serverDone.peerTrust.subjectKeyId == "example-client"
    check clientDone.peerTrust.serial == 22'u64
    check serverDone.peerTrust.serial == 11'u64
    helloWire.setLen(helloWire.len - 1)
    expect ValueError:
      discard decodeAmeClientHello(helloWire)

  test "both sides start a working ratchet from the finished handshake":
    var
      p: Pair = newPair("ratchet")
      client: AmeClientHandshake = beginAmeHandshake(7'u64, p.layout, p.tier)
      server = answerAmeHandshake(client.hello, [handshakePath(p.layout,
        p.tier)], p.serverCert, p.serverKey)
      clientDone: AmeHandshakeResult
      serverDone: AmeHandshakeResult
      clientSession: AmeSession
      serverSession: AmeSession
      frame: ByteSeq = @[]
      opened: AmeOpenResult
    clientDone = finishAmeHandshake(client, server.state.serverHello, p.root,
      p.clientCert, p.clientKey, nowUnix)
    serverDone = acceptAmeHandshake(server.state, clientDone.finish, p.root,
      nowUnix)
    check clientDone.ok and serverDone.ok
    clientSession = initAmeSession(clientDone.auth,
      peerTrust = clientDone.peerTrust)
    serverSession = initAmeSession(serverDone.auth,
      peerTrust = serverDone.peerTrust)
    frame = sealAmeTcpFrame(clientSession, @[byte 1, 2, 3])
    opened = openAmeTcpFrame(serverSession, frame)
    check opened.ok
    check opened.packet.payload == @[byte 1, 2, 3]
    frame = sealAmeTcpFrame(serverSession, @[byte 4, 5])
    opened = openAmeTcpFrame(clientSession, frame)
    check opened.ok
    check opened.packet.payload == @[byte 4, 5]

  test "one broken authority algorithm is not enough to forge a certificate":
    var
      p: Pair = newPair("hybrid")
      forged: AmeIdentityCertificate = p.serverCert
      trust: AmePeerTrustResult
    check p.serverCert.authorityProofs.len == p.root.signingKeys.len
    check p.serverCert.authorityProofs.len >= 2
    ## Keep the first proof valid and destroy the second. An implementation
    ## that stopped after one good signature would accept this.
    forged.authorityProofs[1][0] = forged.authorityProofs[1][0] xor 0xFF'u8
    trust = verifyAmeIdentityCertificate(forged, p.root, nowUnix)
    check not trust.ok
    check trust.err == "certificate authority proof is invalid"
    ## Dropping the post-quantum half entirely must not work either.
    forged = p.serverCert
    forged.authorityProofs.setLen(1)
    trust = verifyAmeIdentityCertificate(forged, p.root, nowUnix)
    check not trust.ok
    check trust.err == "certificate proof count does not match the pinned root"

  test "a revoked serial is refused while the same subject can be reissued":
    var
      p: Pair = newPair("revoke")
      replacement: AmeIdentityCertificate
      trust: AmePeerTrustResult
    trust = verifyAmeIdentityCertificate(p.serverCert, p.root, nowUnix,
      [22'u64])
    check not trust.ok
    check trust.err == "certificate serial is revoked"
    ## Revocation names the certificate, not the holder, so the same subject
    ## gets a fresh one and carries on.
    replacement = issueAmeIdentityCertificate(p.authority, p.serverKey,
      23'u64, validFrom, validUntil)
    trust = verifyAmeIdentityCertificate(replacement, p.root, nowUnix,
      [22'u64])
    check trust.ok
    check trust.subjectKeyId == "revoke-server"

  test "certificate validity and a wildly wrong clock both fail closed":
    var
      p: Pair = newPair("clock")
      trust: AmePeerTrustResult
    trust = verifyAmeIdentityCertificate(p.serverCert, p.root, 50'i64)
    check not trust.ok
    check trust.err == "identity is outside its validity period"
    trust = verifyAmeIdentityCertificate(p.serverCert, p.root, 5000'i64)
    check not trust.ok
    ## A clock a year out of step does not get to guess. It is refused as
    ## unusable rather than silently accepting or rejecting everything.
    trust = verifyAmeIdentityCertificate(p.serverCert, p.root,
      validUntil + ameMaxCertificateSkewSeconds + 1'i64)
    check not trust.ok
    check trust.err ==
      "local clock is too far outside the identity validity window"
    trust = verifyAmeIdentityCertificate(p.serverCert, p.root, 0'i64)
    check not trust.ok

  test "a pinned identity expires like any other":
    var
      identity: AmeIdentityKey = initAmeIdentityKey("pinned-peer")
      descriptor: AmeIdentityCertificate = pinnedIdentityDescriptor(identity,
        validFrom, validUntil)
      pin: AmePinnedPeerIdentity = pinnedPeerIdentity(identity)
      trust: AmePeerTrustResult
    trust = verifyPinnedPeerIdentity(descriptor, pin, nowUnix)
    check trust.ok
    check trust.authority == "pinned-peer"
    trust = verifyPinnedPeerIdentity(descriptor, pin, validUntil + 1'i64)
    check not trust.ok
    check trust.err == "identity is outside its validity period"
    expect ValueError:
      discard pinnedIdentityDescriptor(identity, 500'i64, 100'i64)

  test "reciprocal public-key pins authenticate the complete handshake":
    var
      clientKey: AmeIdentityKey = initAmeIdentityKey("pin-client")
      serverKey: AmeIdentityKey = initAmeIdentityKey("pin-server")
      clientDesc: AmeIdentityCertificate = pinnedIdentityDescriptor(clientKey,
        validFrom, validUntil)
      serverDesc: AmeIdentityCertificate = pinnedIdentityDescriptor(serverKey,
        validFrom, validUntil)
      clientPin: AmePinnedPeerIdentity = pinnedPeerIdentity(clientKey)
      serverPin: AmePinnedPeerIdentity = pinnedPeerIdentity(serverKey)
      layout: AmeSuiteLayout = handshakeLayout()
      tier: AmeMaskTier = handshakeTier(layout)
      client: AmeClientHandshake = beginAmeHandshake(9'u64, layout, tier)
      server = answerAmeHandshake(client.hello, [handshakePath(layout, tier)],
        serverDesc, serverKey)
      clientDone: AmeHandshakeResult
      serverDone: AmeHandshakeResult
    check server.ok
    clientDone = finishAmePinnedHandshake(client, server.state.serverHello,
      serverPin, clientDesc, clientKey, nowUnix)
    check clientDone.err == ""
    check clientDone.ok
    serverDone = acceptAmePinnedHandshake(server.state, clientDone.finish,
      clientPin, nowUnix)
    check serverDone.ok
    check clientDone.peerTrust.authority == "pinned-peer"
    check serverDone.peerTrust.subjectKeyId == "pin-client"
    check clientDone.auth.current.transcriptSalt ==
      serverDone.auth.current.transcriptSalt

  test "the wrong pin and a mixed-up trust mode both fail closed":
    var
      clientKey: AmeIdentityKey = initAmeIdentityKey("mix-client")
      serverKey: AmeIdentityKey = initAmeIdentityKey("mix-server")
      otherKey: AmeIdentityKey = initAmeIdentityKey("mix-server")
      clientDesc: AmeIdentityCertificate = pinnedIdentityDescriptor(clientKey,
        validFrom, validUntil)
      serverDesc: AmeIdentityCertificate = pinnedIdentityDescriptor(serverKey,
        validFrom, validUntil)
      wrongPin: AmePinnedPeerIdentity = pinnedPeerIdentity(otherKey)
      layout: AmeSuiteLayout = handshakeLayout()
      tier: AmeMaskTier = handshakeTier(layout)
      client: AmeClientHandshake = beginAmeHandshake(9'u64, layout, tier)
      server = answerAmeHandshake(client.hello, [handshakePath(layout, tier)],
        serverDesc, serverKey)
      clientDone: AmeHandshakeResult
      certified: Pair = newPair("mixed")
    ## Same subject name, different keys. The name is not what is checked.
    clientDone = finishAmePinnedHandshake(client, server.state.serverHello,
      wrongPin, clientDesc, clientKey, nowUnix)
    check not clientDone.ok
    check clientDone.err == "peer identity does not match the pinned public key"
    ## An unsigned pinned descriptor offered where a certificate is required.
    check not verifyAmeIdentityCertificate(serverDesc, certified.root,
      nowUnix).ok
    ## A signed certificate offered where a direct pin is required.
    check not verifyPinnedPeerIdentity(certified.serverCert,
      pinnedPeerIdentity(certified.serverKey), nowUnix).ok

  test "tampering anywhere in the server hello fails closed":
    var
      p: Pair = newPair("tamper")
      client: AmeClientHandshake = beginAmeHandshake(3'u64, p.layout, p.tier)
      server = answerAmeHandshake(client.hello, [handshakePath(p.layout,
        p.tier)], p.serverCert, p.serverKey)
      saved: AmeClientHandshake = client
      hello: AmeServerHello
      done: AmeHandshakeResult
    hello = server.state.serverHello
    hello.nonce[0] = hello.nonce[0] xor 0x01'u8
    client = saved
    done = finishAmeHandshake(client, hello, p.root, p.clientCert,
      p.clientKey, nowUnix)
    check not done.ok
    hello = server.state.serverHello
    hello.sealed[0] = hello.sealed[0] xor 0x01'u8
    client = saved
    done = finishAmeHandshake(client, hello, p.root, p.clientCert,
      p.clientKey, nowUnix)
    check not done.ok
    hello = server.state.serverHello
    hello.authTag[0] = hello.authTag[0] xor 0x01'u8
    client = saved
    done = finishAmeHandshake(client, hello, p.root, p.clientCert,
      p.clientKey, nowUnix)
    check not done.ok

  test "an unsupported layout or tier is refused before any key work":
    var
      p: Pair = newPair("policy")
      other: AmeMaskTier = handshakeTier(p.layout, 0b10000000'u8)
      client: AmeClientHandshake = beginAmeHandshake(5'u64, p.layout, p.tier)
      server = answerAmeHandshake(client.hello,
        [handshakePath(p.layout, other)], p.serverCert, p.serverKey)
    check not server.ok
    check server.err == "client exact AME layout and initial tier are not supported"

  test "a zero session id is refused rather than raising":
    var
      p: Pair = newPair("zero")
      client: AmeClientHandshake = beginAmeHandshake(5'u64, p.layout, p.tier)
      server: tuple[ok: bool, state: AmeServerHandshake, err: string]
    client.hello.sessionId = 0'u64
    server = answerAmeHandshake(client.hello, [handshakePath(p.layout,
      p.tier)], p.serverCert, p.serverKey)
    check not server.ok
    check server.err == "client hello shape is invalid"
    expect ValueError:
      discard beginAmeHandshake(0'u64, p.layout, p.tier)

  test "the finish erases the handshake secrets it consumed":
    var
      p: Pair = newPair("erase")
      client: AmeClientHandshake = beginAmeHandshake(8'u64, p.layout, p.tier)
      server = answerAmeHandshake(client.hello, [handshakePath(p.layout,
        p.tier)], p.serverCert, p.serverKey)
      clientDone: AmeHandshakeResult
      serverDone: AmeHandshakeResult
    check client.secretKeys.len > 0
    clientDone = finishAmeHandshake(client, server.state.serverHello, p.root,
      p.clientCert, p.clientKey, nowUnix)
    check clientDone.ok
    check client.secretKeys.len == 0
    check client.hello.sessionId == 0'u64
    serverDone = acceptAmeHandshake(server.state, clientDone.finish, p.root,
      nowUnix)
    check serverDone.ok
    check server.state.sharedSecrets.len == 0

suite "AME anti-flood cookie":
  test "a cookie only verifies for the address it was minted for":
    var
      p: Pair = newPair("cookie")
      secret: AmeCookieSecret = initAmeCookieSecret()
      here: ByteSeq = @[byte 10, 0, 0, 1]
      elsewhere: ByteSeq = @[byte 10, 0, 0, 2]
      client: AmeClientHandshake = beginAmeHandshake(4'u64, p.layout, p.tier)
      cookie: ByteSeq = @[]
      retried: AmeClientHandshake
    check not ameCookieValid(secret, here, nowUnix, client.hello)
    cookie = issueAmeCookie(secret, here, nowUnix, client.hello)
    retried = beginAmeHandshake(4'u64, p.layout, p.tier, 1'u32, cookie)
    ## The cookie is bound to the hello it was minted for, so it has to be
    ## replayed with that same nonce.
    retried.hello.nonce = client.hello.nonce
    check ameCookieValid(secret, here, nowUnix, retried.hello)
    check not ameCookieValid(secret, elsewhere, nowUnix, retried.hello)
    check not ameCookieValid(secret, here,
      nowUnix + ameCookieLifetimeSeconds + 1'i64, retried.hello)
    check not ameCookieValid(initAmeCookieSecret(), here, nowUnix,
      retried.hello)
    retried.hello.cookie[9] = retried.hello.cookie[9] xor 0xFF'u8
    check not ameCookieValid(secret, here, nowUnix, retried.hello)

suite "AME handshake transport":
  test "records ride ordinary AME frames and refuse to arrive out of order":
    var
      p: Pair = newPair("transport")
      client: AmeClientHandshake = beginAmeHandshake(77'u64, p.layout, p.tier)
      frame: ByteSeq = encodeAmeClientHelloFrame(client.hello)
      decoded: AmeHandshakeFrame = decodeAmeHandshakeFrame(frame)
      retry: AmeHelloRetry
    check decoded.kind == ampkClientHello
    check decoded.sessionId == 77'u64
    check decoded.step == ameHandshakeStepHello
    check decodeAmeClientHello(decoded.record).sessionId == 77'u64
    requireHandshakeFrame(decoded, ampkClientHello, ameHandshakeStepHello)
    ## A record that shows up where a different one belongs is refused before
    ## it is even parsed.
    expect ValueError:
      requireHandshakeFrame(decoded, ampkServerHello,
        ameHandshakeStepServerHello)
    expect ValueError:
      requireHandshakeFrame(decoded, ampkClientHello,
        ameHandshakeStepRetriedHello)
    expect ValueError:
      requireHandshakeFrame(decoded, ampkClientHello,
        ameHandshakeStepHello, 78'u64)
    retry.sessionId = 77'u64
    retry.cookie = newSeq[byte](40)
    decoded = decodeAmeHandshakeFrame(encodeAmeHelloRetryFrame(retry))
    check decoded.kind == ampkHelloRetry
    check decoded.step == ameHandshakeStepRetry
    ## A lane-data frame is not a handshake record and must not be read as one.
    expect ValueError:
      discard decodeAmeHandshakeFrame(encodeAmeFrame(ampkLaneData,
        amcUserdata, 1'u64, 0'u32, 0'u32, 0'u32, 0'u32, @[byte 1, 2, 3]))

suite "AME secure package":
  test "an authenticated package repairs loss and restores plaintext":
    var
      p: Pair = newPair("package")
      client: AmeClientHandshake = beginAmeHandshake(99'u64, p.layout, p.tier)
      server = answerAmeHandshake(client.hello, [handshakePath(p.layout,
        p.tier)], p.serverCert, p.serverKey)
      sender: AmeHandshakeResult
      receiver: AmeHandshakeResult
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
    sender = finishAmeHandshake(client, server.state.serverHello, p.root,
      p.clientCert, p.clientKey, nowUnix)
    receiver = acceptAmeHandshake(server.state, sender.finish, p.root, nowUnix)
    check sender.ok and receiver.ok
    plan = planAmeSecurePackage(sender.auth, 55'u64, plaintext,
      cleanLanDacDefaults())
    packageReceiver = initDacPackageReceiver(plan.package.manifest)
    for chunk in plan.package.chunks:
      if chunk.chunkId notin {1'u16, 3'u16}:
        packageReceiver.acceptDacPackageChunk(chunk)
    check not packageReceiver.repairGroup(plan.package.repairs[0]).ok
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

  test "compression is off by default and must be asked for by name":
    var
      plaintext: ByteSeq = newSeq[byte](10_000)
      plain: AmeCompressionPolicy = defaultAmeCompressionPolicy()
      squeezed: AmeCompressionPolicy = compressedAmeCompressionPolicy()
      encoded: ByteSeq = @[]
      decoded: ByteSeq = @[]
    for i in 0 ..< plaintext.len:
      plaintext[i] = if i < 5000: 4'u8 else: 8'u8
    ## Compressing before encrypting leaks: the ciphertext length reveals how
    ## well the plaintext compressed. So the default policy does not.
    check plain.algorithm == aczNone
    encoded = encodeAmeCompressed(plaintext, plain)
    check encoded[4] == uint8(ord(aczNone))
    check decodeAmeCompressed(encoded, plain) == plaintext
    encoded = encodeAmeCompressed(plaintext, squeezed)
    check encoded[4] == uint8(ord(aczEirRle))
    check encoded.len < plaintext.len
    decoded = decodeAmeCompressed(encoded, squeezed)
    check decoded == plaintext

  test "one missing chunk is recovered from the group XOR shard":
    var
      data: ByteSeq = newSeq[byte](5000)
      plan: DacPackagePlan
      receiver: DacPackageReceiver
      outcome: DacPackageResult
      i: int = 0
    while i < data.len:
      data[i] = uint8(i mod 251)
      i = i + 1
    plan = planDacPackage(8'u64, data, cleanLanDacDefaults())
    receiver = initDacPackageReceiver(plan.manifest)
    for chunk in plan.chunks:
      if chunk.chunkId != 2'u16:
        receiver.acceptDacPackageChunk(chunk)
    check receiver.repairGroup(plan.repairs[0]).ok
    outcome = finishDacPackage(receiver)
    check outcome.ok
    check outcome.payload == data

  test "decompression bomb metadata is rejected before Eir decode":
    var
      envelope: ByteSeq = @[byte 'E', byte 'I', byte 'R', byte '1',
        byte ord(aczEirRle), 0, 0, 1, 0, 1, 0, 0, 0, 0]
    expect ValueError:
      discard decodeAmeCompressed(envelope,
        compressedAmeCompressionPolicy())

  test "authority root construction rejects incomplete pinning material":
    expect ValueError:
      discard initAmeAuthorityRoot("", [AmeIdentitySigningKey(
        algorithm: asaEd25519, publicKey: @[byte 1])])
    expect ValueError:
      discard initAmeAuthorityRoot("root", [])
    expect ValueError:
      discard initAmeAuthorityRoot("root", [AmeIdentitySigningKey(
        algorithm: asaEd25519, publicKey: @[])])
