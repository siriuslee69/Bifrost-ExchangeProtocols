## ---------------------------------------------------------
## TLS 1.3 Foundation Tests <- bounded codecs and AEAD record
## ---------------------------------------------------------

import std/unittest

import protocols/certificates
import protocols/custom_crypto/sha256
import protocols/custom_crypto/ed25519
import protocols/custom_crypto/x25519

import ../src/protocols/types
import ../src/protocols/tls13

const
  fixtureCertificate = """-----BEGIN CERTIFICATE-----
MIIBPDCB76ADAgECAhQkqENccCvOQyI4iKFuuOKwl860bTAFBgMrZXAwFDESMBAG
A1UEAwwJbG9jYWxob3N0MB4XDTIxMDcyNjE0MjcwN1oXDTIxMDgyNTE0MjcwN1ow
FDESMBAGA1UEAwwJbG9jYWxob3N0MCowBQYDK2VwAyEA1KMGmAZealfgakBuCx/E
n69fo072qm90eM40ulGex0ajUzBRMB0GA1UdDgQWBBTHKWv5l/SxnkkYJhh5r3Pv
ESAh1DAfBgNVHSMEGDAWgBTHKWv5l/SxnkkYJhh5r3PvESAh1DAPBgNVHRMBAf8E
BTADAQH/MAUGAytlcANBAF/vSBfOHAdRl29sWDTkuqy1dCuSf7j7jKE/Be8Fk7xs
WteXJmIa0HlRAZjxNfWbsSGLnTYbsGTbxKx3QU9H9g0=
-----END CERTIFICATE-----"""
  fixturePrivateKey = """-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAjtEwCECqbot5RZxSmiNDWcPp+Xc9Y9WJcUhti3JgSP
-----END PRIVATE KEY-----"""

suite "TLS 1.3 foundation":
  test "record codec supports partial input and one complete record":
    var
      r: Tls13Record
      A: seq[byte] = @[]
      d: Tls13RecordResult
    r.contentType = tctHandshake
    r.legacyVersion = tls13LegacyRecordVersion
    r.fragment = @[byte 1, 2, 3]
    A = encodeTls13Record(r)
    d = decodeTls13Record(A.toOpenArray(0, 3))
    check d.needMore
    d = decodeTls13Record(A)
    check d.ok
    check d.consumed == A.len
    check d.record.fragment == r.fragment

  test "handshake codec preserves exact transcript bytes":
    var
      h: Tls13Handshake
      A: seq[byte] = @[]
      d: Tls13HandshakeResult
    h.messageType = thtClientHello
    h.body = @[byte 3, 3, 0, 1]
    A = encodeTls13Handshake(h)
    d = decodeTls13Handshake(A)
    check d.ok
    check d.message.body == h.body
    check d.message.encoded == A

  test "legacy compression accepts null and rejects non-null-only offers":
    check validateTls13LegacyCompression([byte 0])
    check not validateTls13LegacyCompression([byte 1, 0])
    check not validateTls13LegacyCompression([byte 1, 2])

  test "encrypted record roundtrip authenticates header content and padding":
    var
      W, R: Tls13TrafficKeys
      record: Tls13Record
      opened: Tls13OpenResult
      i: int = 0
    while i < W.key.len:
      W.key[i] = byte(i)
      i = i + 1
    i = 0
    while i < W.iv.len:
      W.iv[i] = byte(0xa0 + i)
      i = i + 1
    R = W
    record = sealTls13Record(W, tctApplicationData,
      @[byte 9, 8, 7, 6], paddingLen = 7)
    opened = openTls13Record(R, record)
    check opened.ok
    check opened.contentType == tctApplicationData
    check opened.content == @[byte 9, 8, 7, 6]
    check W.sequence == 1'u64
    check R.sequence == 1'u64
    record.fragment[0] = record.fragment[0] xor 1'u8
    opened = openTls13Record(R, record)
    check not opened.ok
    check R.sequence == 1'u64

  test "key schedule separates endpoints and derives record keys":
    var
      shared: seq[byte] = newSeq[byte](32)
      helloHash: Sha256Digest = sha256Hash([byte 1, 2, 3])
      finishedHash: Sha256Digest = sha256Hash([byte 4, 5, 6])
      H: Tls13HandshakeSecrets
      A: Tls13ApplicationSecrets
      clientKeys, serverKeys: Tls13TrafficKeys
      finishedKey: Tls13Secret
      updated: Tls13Secret
      i: int = 0
    while i < shared.len:
      shared[i] = byte(i + 1)
      i = i + 1
    H = buildTls13HandshakeSecrets([], shared, helloHash)
    check H.clientHandshakeTraffic != H.serverHandshakeTraffic
    finishedKey = deriveTls13FinishedKey(H.serverHandshakeTraffic)
    check finishedKey != default(Tls13Secret)
    A = buildTls13ApplicationSecrets(H.handshakeSecret, finishedHash)
    check A.clientApplicationTraffic != A.serverApplicationTraffic
    clientKeys = deriveTls13TrafficKeys(A.clientApplicationTraffic)
    serverKeys = deriveTls13TrafficKeys(A.serverApplicationTraffic)
    check clientKeys.key != serverKeys.key
    check clientKeys.iv != serverKeys.iv
    check clientKeys.sequence == 0'u64
    updated = nextTls13TrafficSecret(A.clientApplicationTraffic)
    check updated != A.clientApplicationTraffic

  test "narrow client and server hello codecs preserve required profile":
    var
      C: Tls13ClientHello
      S: Tls13ServerHello
      clientBody, serverBody: ByteSeq = @[]
      clientParsed: Tls13ClientHelloResult
      serverParsed: Tls13ServerHelloResult
      i: int = 0
    C.serverName = "example.com"
    C.alpn = @["http/1.1"]
    C.legacySessionId = @[byte 1, 2, 3]
    C.x25519PublicKey = newSeq[byte](32)
    S.legacySessionId = C.legacySessionId
    S.x25519PublicKey = newSeq[byte](32)
    while i < 32:
      C.random[i] = byte(i)
      S.random[i] = byte(255 - i)
      C.x25519PublicKey[i] = byte(i + 1)
      S.x25519PublicKey[i] = byte(i + 33)
      i = i + 1
    clientBody = encodeTls13ClientHello(C)
    serverBody = encodeTls13ServerHello(S)
    clientParsed = decodeTls13ClientHello(clientBody)
    serverParsed = decodeTls13ServerHello(serverBody)
    check clientParsed.ok
    check clientParsed.hello.serverName == "example.com"
    check clientParsed.hello.alpn == @["http/1.1"]
    check clientParsed.hello.x25519PublicKey == C.x25519PublicKey
    check serverParsed.ok
    check serverParsed.hello.x25519PublicKey == S.x25519PublicKey

  test "transcript Finished and CertificateVerify are role bound":
    var
      T: Tls13Transcript = initTls13Transcript()
      H: Sha256Digest
      traffic: Tls13Secret
      finished0, finished1: Tls13Secret
      kp = ed25519TyrKeypair()
      sig: ByteSeq = @[]
    T.appendTls13Transcript([byte 1, 0, 0, 0])
    H = T.tls13TranscriptHash()
    traffic = initTls13EarlySecret([byte 7, 8, 9])
    finished0 = tls13FinishedVerifyData(traffic, H)
    finished1 = tls13FinishedVerifyData(traffic, H)
    check constantTimeFinishedEqual(finished0, finished1)
    sig = signTls13CertificateVerify(kp.secretKey, true, H)
    check verifyTls13CertificateVerify(kp.publicKey, sig, true, H)
    check not verifyTls13CertificateVerify(kp.publicKey, sig, false, H)

  test "controlled pinned Ed25519 handshake promotes matching application keys":
    if fixtureCertificate.len > 0:
      var
        certPem: PemReadResult = readPemBlock(fixtureCertificate, "CERTIFICATE")
        key = parseEd25519PrivateKeyPem(fixturePrivateKey)
        keypair: Ed25519Keypair
        C: Tls13ControlledConfig
        R: Tls13ControlledResult
        clientWrite, serverRead, serverWrite, clientRead: Tls13TrafficKeys
        record: Tls13Record
        opened: Tls13OpenResult
      check certPem.ok
      check key.ok
      keypair = ed25519TyrKeypairFromSeed(key.seed)
      C.serverCertificateDer = certPem.pemBlock.der
      C.pinnedRootCertificateDer = certPem.pemBlock.der
      C.serverEd25519SecretKey = keypair.secretKey
      C.nowUnix = 1_627_310_000'i64
      C.clientX25519Seed = newSeq[byte](32)
      C.serverX25519Seed = newSeq[byte](32)
      for i in 0 ..< 32:
        C.clientX25519Seed[i] = byte(i + 1)
        C.serverX25519Seed[i] = byte(i + 65)
      R = runControlledTls13Handshake(C)
      check R.ok
      check R.clientState == thsConnected
      check R.serverState == thsConnected
      clientWrite = R.clientWriteKeys
      serverRead = R.serverReadKeys
      record = sealTls13Record(clientWrite, tctApplicationData,
        @[byte 1, 3, 3, 7])
      opened = openTls13Record(serverRead, record)
      check opened.ok
      check opened.content == @[byte 1, 3, 3, 7]
      serverWrite = R.serverWriteKeys
      clientRead = R.clientReadKeys
      record = sealTls13Record(serverWrite, tctApplicationData,
        @[byte 9, 8, 7])
      opened = openTls13Record(clientRead, record)
      check opened.ok
      check opened.content == @[byte 9, 8, 7]

  test "server session emits a verifiable flight and accepts client Finished":
    if fixtureCertificate.len > 0:
      var
        certPem: PemReadResult = readPemBlock(fixtureCertificate, "CERTIFICATE")
        key = parseEd25519PrivateKeyPem(fixturePrivateKey)
        signingKeypair: Ed25519Keypair
        clientKeypair: X25519TyrKeypair
        clientHello: Tls13ClientHello
        clientHelloMessage, clientHelloRecord: ByteSeq = @[]
        serverConfig: Tls13ServerConfig
        server: Tls13ServerSession
        output: Tls13ServerOutput
        recordResult: Tls13RecordResult
        handshakeResult: Tls13HandshakeResult
        serverHelloResult: Tls13ServerHelloResult
        transcript: Tls13Transcript = initTls13Transcript()
        shared: ByteSeq = @[]
        handshakeSecrets: Tls13HandshakeSecrets
        applicationSecrets: Tls13ApplicationSecrets
        serverHandshakeKeys, clientHandshakeKeys: Tls13TrafficKeys
        clientApplicationKeys, serverApplicationKeys: Tls13TrafficKeys
        opened: Tls13OpenResult
        transcriptHash: Sha256Digest
        clientFinished, wire: ByteSeq = @[]
        events: seq[ByteSeq] = @[]
        i: int = 0
      check certPem.ok
      check key.ok
      signingKeypair = ed25519TyrKeypairFromSeed(key.seed)
      clientKeypair = x25519TyrKeypairFromSeed(newSeq[byte](32))
      clientHello.serverName = "localhost"
      clientHello.alpn = @["http/1.1"]
      clientHello.x25519PublicKey = clientKeypair.publicKey
      while i < clientHello.random.len:
        clientHello.random[i] = byte(i + 1)
        i = i + 1
      clientHelloMessage = encodeTls13Handshake(Tls13Handshake(
        messageType: thtClientHello,
        body: encodeTls13ClientHello(clientHello)))
      clientHelloRecord = encodeTls13PlainHandshakeRecord(clientHelloMessage)
      transcript.appendTls13Transcript(clientHelloMessage)
      serverConfig.certificateChainDer = @[certPem.pemBlock.der]
      serverConfig.ed25519SecretKey = signingKeypair.secretKey
      serverConfig.alpn = @["http/1.1"]
      server = initTls13ServerSession(serverConfig)
      output = server.feedTls13Server(clientHelloRecord)
      check output.err.len == 0
      check output.outbound.len == 5
      recordResult = decodeTls13Record(output.outbound[0])
      check recordResult.ok
      handshakeResult = decodeTls13Handshake(recordResult.record.fragment)
      check handshakeResult.ok
      check handshakeResult.message.messageType == thtServerHello
      serverHelloResult = decodeTls13ServerHello(handshakeResult.message.body)
      check serverHelloResult.ok
      transcript.appendTls13Transcript(handshakeResult.message.encoded)
      shared = x25519TyrShared(clientKeypair.secretKey,
        serverHelloResult.hello.x25519PublicKey)
      transcriptHash = transcript.tls13TranscriptHash()
      handshakeSecrets = buildTls13HandshakeSecrets([], shared, transcriptHash)
      serverHandshakeKeys = deriveTls13TrafficKeys(
        handshakeSecrets.serverHandshakeTraffic)
      clientHandshakeKeys = deriveTls13TrafficKeys(
        handshakeSecrets.clientHandshakeTraffic)
      i = 1
      while i < output.outbound.len:
        recordResult = decodeTls13Record(output.outbound[i])
        check recordResult.ok
        opened = openTls13Record(serverHandshakeKeys, recordResult.record)
        check opened.ok
        check opened.contentType == tctHandshake
        handshakeResult = decodeTls13Handshake(opened.content)
        check handshakeResult.ok
        if handshakeResult.message.messageType == thtFinished:
          transcriptHash = transcript.tls13TranscriptHash()
          check constantTimeFinishedEqual(handshakeResult.message.body,
            tls13FinishedVerifyData(handshakeSecrets.serverHandshakeTraffic,
            transcriptHash))
        transcript.appendTls13Transcript(handshakeResult.message.encoded)
        events.add(handshakeResult.message.encoded)
        i = i + 1
      check events.len == 4
      check decodeTls13Handshake(events[0]).message.messageType ==
        thtEncryptedExtensions
      check decodeTls13Handshake(events[1]).message.messageType == thtCertificate
      check decodeTls13Handshake(events[2]).message.messageType ==
        thtCertificateVerify
      check decodeTls13Handshake(events[3]).message.messageType == thtFinished
      transcriptHash = transcript.tls13TranscriptHash()
      applicationSecrets = buildTls13ApplicationSecrets(
        handshakeSecrets.handshakeSecret, transcriptHash)
      clientFinished = encodeTls13Finished(tls13FinishedVerifyData(
        handshakeSecrets.clientHandshakeTraffic, transcriptHash))
      wire = encodeTls13Record(sealTls13Record(clientHandshakeKeys,
        tctHandshake, clientFinished))
      output = server.feedTls13Server(wire)
      check output.err.len == 0
      check output.connected
      check server.state == tssConnected
      clientApplicationKeys = deriveTls13TrafficKeys(
        applicationSecrets.clientApplicationTraffic)
      serverApplicationKeys = deriveTls13TrafficKeys(
        applicationSecrets.serverApplicationTraffic)
      wire = encodeTls13Record(sealTls13Record(clientApplicationKeys,
        tctApplicationData, @[byte 4, 2]))
      output = server.feedTls13Server(wire)
      check output.applicationData == @[@[byte 4, 2]]
      wire = server.encodeTls13ServerApplication(@[byte 7, 9])
      recordResult = decodeTls13Record(wire)
      check recordResult.ok
      opened = openTls13Record(serverApplicationKeys, recordResult.record)
      check opened.ok
      check opened.content == @[byte 7, 9]
      wire = encodeTls13Record(sealTls13Record(clientApplicationKeys,
        tctHandshake, encodeTls13Handshake(Tls13Handshake(
        messageType: thtNewSessionTicket, body: @[]))))
      output = server.feedTls13Server(wire)
      check server.state == tssFailed
      check output.err == "TLS post-handshake message is unsupported"
      check output.outbound.len == 1
      recordResult = decodeTls13Record(output.outbound[0])
      check recordResult.ok
      opened = openTls13Record(serverApplicationKeys, recordResult.record)
      check opened.ok
      check opened.contentType == tctAlert
      check opened.content.len == 2
      check opened.content[0] == byte(ord(talFatal))

  test "server session rejects mismatched keys and invalid X25519 shares":
    if fixtureCertificate.len > 0:
      var
        certPem: PemReadResult = readPemBlock(fixtureCertificate, "CERTIFICATE")
        key = parseEd25519PrivateKeyPem(fixturePrivateKey)
        signingKeypair: Ed25519Keypair = ed25519TyrKeypairFromSeed(key.seed)
        otherKeypair: Ed25519Keypair = ed25519TyrKeypair()
        clientHello: Tls13ClientHello
        serverConfig: Tls13ServerConfig
        server: Tls13ServerSession
        output: Tls13ServerOutput
        recordResult: Tls13RecordResult
        wire: ByteSeq = @[]
      check certPem.ok
      check key.ok
      serverConfig.certificateChainDer = @[certPem.pemBlock.der]
      serverConfig.ed25519SecretKey = otherKeypair.secretKey
      expect ValueError:
        discard initTls13ServerSession(serverConfig)
      serverConfig.ed25519SecretKey = signingKeypair.secretKey
      server = initTls13ServerSession(serverConfig)
      clientHello.x25519PublicKey = newSeq[byte](32)
      wire = encodeTls13PlainHandshakeRecord(encodeTls13Handshake(
        Tls13Handshake(messageType: thtClientHello,
        body: encodeTls13ClientHello(clientHello))))
      output = server.feedTls13Server(wire)
      check server.state == tssFailed
      check output.err.len > 0
      check output.outbound.len == 1
      recordResult = decodeTls13Record(output.outbound[0])
      check recordResult.ok
      check recordResult.record.contentType == tctAlert
      check recordResult.record.fragment.len == 2
      check recordResult.record.fragment[0] == byte(ord(talFatal))

  test "client and server sessions complete from coalesced server records":
    var
      certPem: PemReadResult = readPemBlock(fixtureCertificate, "CERTIFICATE")
      key = parseEd25519PrivateKeyPem(fixturePrivateKey)
      signingKeypair: Ed25519Keypair = ed25519TyrKeypairFromSeed(key.seed)
      clientConfig: Tls13ClientConfig
      serverConfig: Tls13ServerConfig
      client: Tls13ClientSession
      server: Tls13ServerSession
      clientOutput: Tls13ClientOutput
      serverOutput: Tls13ServerOutput
      clientHello, serverFlight, wire: ByteSeq = @[]
      i: int = 0
    check certPem.ok
    check key.ok
    clientConfig.pinnedRootCertificateDer = certPem.pemBlock.der
    clientConfig.alpn = @["http/1.1"]
    clientConfig.nowUnix = 1_627_310_000'i64
    clientConfig.x25519Seed = newSeq[byte](32)
    while i < clientConfig.x25519Seed.len:
      clientConfig.x25519Seed[i] = byte(i + 1)
      i = i + 1
    serverConfig.certificateChainDer = @[certPem.pemBlock.der]
    serverConfig.ed25519SecretKey = signingKeypair.secretKey
    serverConfig.alpn = @["http/1.1"]
    client = initTls13ClientSession(clientConfig)
    server = initTls13ServerSession(serverConfig)
    clientHello = client.startTls13Client()
    check client.state == tcsAwaitServerHello
    serverOutput = server.feedTls13Server(clientHello)
    check serverOutput.err.len == 0
    check serverOutput.outbound.len == 5
    i = 0
    while i < serverOutput.outbound.len:
      serverFlight.add(serverOutput.outbound[i])
      i = i + 1
    clientOutput = client.feedTls13Client(serverFlight)
    check clientOutput.err.len == 0
    check clientOutput.connected
    check clientOutput.outbound.len == 1
    check client.state == tcsConnected
    wire = clientOutput.outbound[0]
    wire.add(client.encodeTls13ClientApplication(@[byte 1, 2, 3]))
    serverOutput = server.feedTls13Server(wire)
    check serverOutput.err.len == 0
    check serverOutput.connected
    check server.state == tssConnected
    check serverOutput.applicationData == @[@[byte 1, 2, 3]]
    wire = server.encodeTls13ServerApplication(@[byte 4, 5, 6])
    clientOutput = client.feedTls13Client(wire)
    check clientOutput.applicationData == @[@[byte 4, 5, 6]]
    wire = client.encodeTls13ClientKeyUpdate(requestPeerUpdate = true)
    serverOutput = server.feedTls13Server(wire)
    check serverOutput.err.len == 0
    check serverOutput.outbound.len == 1
    clientOutput = client.feedTls13Client(serverOutput.outbound[0])
    check clientOutput.err.len == 0
    check clientOutput.outbound.len == 0
    wire = client.encodeTls13ClientApplication(@[byte 7, 8])
    serverOutput = server.feedTls13Server(wire)
    check serverOutput.applicationData == @[@[byte 7, 8]]
    wire = server.encodeTls13ServerApplication(@[byte 9, 10])
    clientOutput = client.feedTls13Client(wire)
    check clientOutput.applicationData == @[@[byte 9, 10]]
    wire = client.closeTls13Client()
    serverOutput = server.feedTls13Server(wire)
    check serverOutput.closed
    check server.state == tssConnected

  test "connection buffers fragmented records and handshake messages":
    var
      C: Tls13Connection = initTls13Connection()
      h0 = encodeTls13Handshake(Tls13Handshake(
        messageType: thtClientHello, body: @[byte 1, 2, 3]))
      h1 = encodeTls13Handshake(Tls13Handshake(
        messageType: thtFinished, body: newSeq[byte](32)))
      wire: ByteSeq = encodeTls13PlainHandshakeRecord(h0 & h1)
      E: seq[Tls13Event] = @[]
    E = C.feedTls13(wire.toOpenArray(0, 2))
    check E.len == 0
    E = C.feedTls13(wire.toOpenArray(3, wire.len - 1))
    check E.len == 2
    check E[0].kind == tekHandshake
    check E[0].handshake.messageType == thtClientHello
    check E[1].handshake.messageType == thtFinished

  test "connection decrypts application data and detects clean shutdown":
    var
      sender, receiver: Tls13Connection
      K: Tls13TrafficKeys
      wire: ByteSeq = @[]
      E: seq[Tls13Event] = @[]
      i: int = 0
    sender = initTls13Connection()
    receiver = initTls13Connection()
    while i < K.key.len:
      K.key[i] = byte(i + 9)
      i = i + 1
    i = 0
    while i < K.iv.len:
      K.iv[i] = byte(i + 71)
      i = i + 1
    sender.installTls13WriteKeys(K)
    receiver.installTls13ReadKeys(K)
    wire = sender.encodeTls13Application(@[byte 4, 5, 6], 3)
    E = receiver.feedTls13(wire)
    check E.len == 1
    check E[0].kind == tekApplicationData
    check E[0].data == @[byte 4, 5, 6]
    wire = sender.encodeTls13CloseNotify()
    E = receiver.feedTls13(wire)
    check E.len == 1
    check E[0].kind == tekClosed
    check receiver.peerClosed
    check sender.localClosed

  test "connection decrypts and reassembles protected handshake fragments":
    var
      sender, receiver: Tls13Connection
      K: Tls13TrafficKeys
      h: ByteSeq = encodeTls13Handshake(Tls13Handshake(
        messageType: thtEncryptedExtensions, body: @[byte 0, 0]))
      wire0, wire1: ByteSeq = @[]
      E: seq[Tls13Event] = @[]
      i: int = 0
    sender = initTls13Connection()
    receiver = initTls13Connection()
    while i < K.key.len:
      K.key[i] = byte(i + 31)
      i = i + 1
    i = 0
    while i < K.iv.len:
      K.iv[i] = byte(i + 101)
      i = i + 1
    sender.installTls13WriteKeys(K)
    receiver.installTls13ReadKeys(K)
    wire0 = sender.encodeTls13Protected(tctHandshake,
      h.toOpenArray(0, 2))
    wire1 = sender.encodeTls13Protected(tctHandshake,
      h.toOpenArray(3, h.len - 1))
    E = receiver.feedTls13(wire0)
    check E.len == 0
    E = receiver.feedTls13(wire1)
    check E.len == 1
    check E[0].kind == tekHandshake
    check E[0].handshake.messageType == thtEncryptedExtensions
    check E[0].handshake.body == @[byte 0, 0]

  test "post-handshake KeyUpdate rotates both traffic directions":
    var
      sender, receiver: Tls13Connection
      S: Tls13Secret
      wire: ByteSeq = @[]
      E: seq[Tls13Event] = @[]
      i: int = 0
    while i < S.len:
      S[i] = byte(i + 1)
      i = i + 1
    sender = initTls13Connection()
    receiver = initTls13Connection()
    sender.installTls13WriteTrafficSecret(S)
    receiver.installTls13ReadTrafficSecret(S)
    wire = sender.encodeTls13KeyUpdate()
    E = receiver.feedTls13(wire)
    check E.len == 1
    check E[0].kind == tekHandshake
    check E[0].handshake.messageType == thtKeyUpdate
    wire = sender.encodeTls13Application(@[byte 7, 7, 7])
    E = receiver.feedTls13(wire)
    check E.len == 1
    check E[0].kind == tekApplicationData
    check E[0].data == @[byte 7, 7, 7]

  test "alert helpers preserve close and hide internal failure details":
    var
      wire = encodeTls13PlainAlert(talWarning, tadCloseNotify)
      R = decodeTls13Record(wire)
    check R.ok
    check R.record.fragment == @[byte 1, 0]
    check tls13AlertForError("certificate parser internal path") ==
      tadBadCertificate
