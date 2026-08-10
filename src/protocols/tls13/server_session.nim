## -----------------------------------------------------------------------
## TLS 1.3 Server Session <- event-driven controlled-profile server flight
## -----------------------------------------------------------------------

import protocols/certificates
import protocols/custom_crypto/[ed25519, random, sha256, x25519]
import protocols/custom_crypto/[rsa, bigint, ecdsa_p256]

import ../types
import ./[types, codec, connection, hello, key_schedule, transcript,
  handshake_messages, alerts]
import ../../analysis_pragmas

type
  Tls13ServerSessionState* = enum
    tssAwaitClientHello,
    tssAwaitClientFinished,
    tssConnected,
    tssClosed,
    tssFailed

  Tls13ServerKeyKind* {.role: configurator.} = enum
    tskEd25519, tskRsa, tskEcdsaP256

  Tls13ServerConfig* {.role: configurator.} = object
    certificateChainDer*: seq[ByteSeq]
    ed25519SecretKey*: ByteSeq   ## used when the leaf carries an Ed25519 key
    rsaPrivateKeyDer*: ByteSeq   ## PKCS#1 or PKCS#8 DER for an RSA leaf
    ecdsaPrivateScalar*: ByteSeq ## 32-byte P-256 scalar for an EC leaf
    alpn*: seq[string]

  Tls13ServerOutput* {.role: truthState.} = object
    outbound*: seq[ByteSeq]
    applicationData*: seq[ByteSeq]
    connected*: bool
    closed*: bool
    err*: string

  Tls13ServerSession* {.role: memory,
      tag: {tagTls, tagTransport, tagCryptoBoundary}.} = object
    state*: Tls13ServerSessionState
    config: Tls13ServerConfig
    connection: Tls13Connection
    transcript: Tls13Transcript
    x25519SecretKey: ByteSeq
    handshakeSecrets: Tls13HandshakeSecrets
    applicationSecrets: Tls13ApplicationSecrets
    selectedAlpn*: string
    requestedServerName*: string
    keyKind: Tls13ServerKeyKind
    rsaKey: RsaPrivateKey
    ecdsaScalar: BigInt

proc initTls13ServerSession*(C: Tls13ServerConfig): Tls13ServerSession {.
    role: truthBuilder, tag: {tagTls, tagTransport}.} =
  ## C: server certificate chain, Ed25519 key, and supported ALPN identifiers.
  var
    R: X509ReadResult
    leaf: X509Certificate
    publicKey: ByteSeq = @[]
    i: int = 0
    rsaParsed: RsaPrivateKeyResult
    ecParsed: P256PublicKeyResult
    derived: P256AffinePoint
    scalar: BigInt
  if C.certificateChainDer.len == 0:
    raise newException(ValueError, "TLS server certificate chain is empty")
  while i < C.certificateChainDer.len:
    R = parseX509CertificateDer(C.certificateChainDer[i])
    if not R.ok:
      raise newException(ValueError, "TLS server certificate is invalid: " & R.err)
    if i == 0:
      leaf = R.certificate
      publicKey = R.certificate.publicKey
    i = i + 1
  # Bind the configured private key to the leaf certificate's key algorithm,
  # and prove possession before the session can ever use it.
  case leaf.publicKeyAlgorithm
  of oidEd25519:
    if C.ed25519SecretKey.len != 64:
      raise newException(ValueError, "TLS Ed25519 leaf needs a 64-byte secret key")
    if publicKey.len != 32:
      raise newException(ValueError, "TLS leaf certificate has no Ed25519 public key")
    if ed25519TyrPublicKey(C.ed25519SecretKey.toOpenArray(0, 31)) != publicKey or
        C.ed25519SecretKey[32 .. 63] != publicKey:
      raise newException(ValueError,
        "TLS Ed25519 private key does not match the leaf certificate")
    result.keyKind = tskEd25519
  of oidRsaEncryption:
    if C.rsaPrivateKeyDer.len == 0:
      raise newException(ValueError, "TLS RSA leaf needs an RSA private key")
    rsaParsed = parseRsaPkcs8PrivateKey(C.rsaPrivateKeyDer)
    if not rsaParsed.ok:
      rsaParsed = parseRsaPkcs1PrivateKey(C.rsaPrivateKeyDer)
    if not rsaParsed.ok:
      raise newException(ValueError,
        "TLS RSA private key is invalid: " & rsaParsed.err)
    var leafRsa = parseRsaSpki(leaf.publicKeySpki)
    if not leafRsa.ok:
      raise newException(ValueError,
        "TLS RSA leaf certificate key is invalid: " & leafRsa.err)
    if bigCmp(leafRsa.key.n, rsaParsed.key.n) != 0:
      raise newException(ValueError,
        "TLS RSA private key does not match the leaf certificate")
    result.rsaKey = rsaParsed.key
    result.keyKind = tskRsa
  of oidEcPublicKey:
    if C.ecdsaPrivateScalar.len != 32:
      raise newException(ValueError, "TLS EC leaf needs a 32-byte P-256 scalar")
    ecParsed = parseP256Spki(leaf.publicKeySpki)
    if not ecParsed.ok:
      raise newException(ValueError,
        "TLS EC leaf certificate key is invalid: " & ecParsed.err)
    scalar = bigFromBytesBe(C.ecdsaPrivateScalar)
    derived = p256PublicFromScalar(scalar)
    if bigCmp(derived.x, ecParsed.point.x) != 0 or
        bigCmp(derived.y, ecParsed.point.y) != 0:
      raise newException(ValueError,
        "TLS P-256 private key does not match the leaf certificate")
    result.ecdsaScalar = scalar
    result.keyKind = tskEcdsaP256
  else:
    raise newException(ValueError,
      "TLS leaf certificate key algorithm is unsupported: " &
      leaf.publicKeyAlgorithm)
  result.state = tssAwaitClientHello
  result.config = C
  result.connection = initTls13Connection()
  result.transcript = initTls13Transcript()

proc chooseAlpn(offered, supported: openArray[string]): string {.role: parser,
    tag: {tagTls, tagValidation}.} =
  var
    i, j: int = 0
  while i < supported.len:
    j = 0
    while j < offered.len:
      if offered[j] == supported[i]:
        return supported[i]
      j = j + 1
    i = i + 1

proc schemeForKeyKind(k: Tls13ServerKeyKind): uint16 {.role: helper,
    tag: {tagTls}.} =
  ## k: server key kind whose TLS signature scheme code is returned.
  case k
  of tskEd25519:
    result = tls13SignatureEd25519
  of tskRsa:
    result = tls13SignatureRsaPssRsaeSha256
  of tskEcdsaP256:
    result = tls13SignatureEcdsaSecp256r1Sha256

proc clientOffered(offered: openArray[uint16], scheme: uint16): bool {.
    role: parser, tag: {tagTls, tagValidation}.} =
  ## offered/scheme: client's signature_algorithms list and one scheme code.
  var i: int = 0
  while i < offered.len:
    if offered[i] == scheme:
      return true
    i = i + 1

proc failServer(S: var Tls13ServerSession, O: var Tls13ServerOutput,
    e: string) {.role: stateController,
    tag: {tagTls, tagValidation, tagCryptoBoundary}.} =
  S.state = tssFailed
  O.err = e
  try:
    if not S.connection.tls13WriteKeysInstalled():
      O.outbound.add(encodeTls13PlainAlert(talFatal, tls13AlertForError(e)))
    else:
      O.outbound.add(S.connection.encodeTls13Protected(tctAlert,
        [byte 2, byte(ord(tls13AlertForError(e)))]))
  except CatchableError:
    discard
  secureClearBytes(S.x25519SecretKey)
  clearTls13HandshakeSecrets(S.handshakeSecrets)
  clearTls13ApplicationSecrets(S.applicationSecrets)
  S.connection.clearTls13ConnectionSecrets()

proc random32(): array[32, byte] {.role: dataFetcher,
    tag: {tagTls, tagCryptoBoundary}.} =
  var
    A: seq[byte] = cryptoRandomBytes(32)
    i: int = 0
  defer:
    secureClearBytes(A)
  while i < result.len:
    result[i] = A[i]
    i = i + 1

proc emitServerFlight(S: var Tls13ServerSession, H: Tls13ClientHello,
    encodedClientHello: openArray[byte], O: var Tls13ServerOutput) {.
    role: orchestrator, tag: {tagTls, tagCryptoBoundary}.} =
  var
    kp: X25519TyrKeypair
    SH: Tls13ServerHello
    serverHelloBody, serverHelloMessage, ee, cert, cv, finished: ByteSeq = @[]
    shared: ByteSeq = @[]
    helloHash, transcriptHash: Sha256Digest
    certificateMessage: Tls13CertificateMessage
    signature: ByteSeq = @[]
    serverHandshakeKeys, clientHandshakeKeys: Tls13TrafficKeys
    scheme: uint16 = 0
    i: int = 0
  S.transcript.appendTls13Transcript(encodedClientHello)
  kp = x25519TyrKeypair()
  S.x25519SecretKey = kp.secretKey
  SH.random = random32()
  SH.legacySessionId = H.legacySessionId
  SH.x25519PublicKey = kp.publicKey
  serverHelloBody = encodeTls13ServerHello(SH)
  serverHelloMessage = encodeTls13Handshake(Tls13Handshake(
    messageType: thtServerHello, body: serverHelloBody))
  shared = x25519TyrShared(S.x25519SecretKey, H.x25519PublicKey)
  S.transcript.appendTls13Transcript(serverHelloMessage)
  O.outbound.add(encodeTls13PlainHandshakeRecord(serverHelloMessage))
  helloHash = S.transcript.tls13TranscriptHash()
  S.handshakeSecrets = buildTls13HandshakeSecrets([], shared, helloHash)
  serverHandshakeKeys = deriveTls13TrafficKeys(
    S.handshakeSecrets.serverHandshakeTraffic)
  clientHandshakeKeys = deriveTls13TrafficKeys(
    S.handshakeSecrets.clientHandshakeTraffic)
  S.connection.installTls13WriteKeys(serverHandshakeKeys)
  S.connection.installTls13ReadKeys(clientHandshakeKeys)
  S.requestedServerName = H.serverName
  S.selectedAlpn = chooseAlpn(H.alpn, S.config.alpn)
  # RFC 7301: a client that sends no ALPN extension gets no ALPN back, and
  # the connection proceeds normally. Only an ALPN list we share nothing
  # with is a failure. Treating silence as a failure breaks every client
  # that does not bother with ALPN, which includes plain `openssl
  # s_client` and a good deal of monitoring tooling.
  if S.config.alpn.len > 0 and H.alpn.len > 0 and S.selectedAlpn.len == 0:
    S.failServer(O, "TLS client offered no supported ALPN")
    return
  ee = encodeTls13EncryptedExtensions(S.selectedAlpn)
  S.transcript.appendTls13Transcript(ee)
  O.outbound.add(S.connection.encodeTls13Protected(tctHandshake, ee))
  while i < S.config.certificateChainDer.len:
    certificateMessage.entries.add(Tls13CertificateEntry(
      certificateDer: S.config.certificateChainDer[i]))
    i = i + 1
  cert = encodeTls13Certificate(certificateMessage)
  S.transcript.appendTls13Transcript(cert)
  O.outbound.add(S.connection.encodeTls13Protected(tctHandshake, cert))
  transcriptHash = S.transcript.tls13TranscriptHash()
  scheme = schemeForKeyKind(S.keyKind)
  # RFC 8446 4.4.3: only sign with a scheme the client advertised.
  if H.signatureSchemes.len > 0 and not clientOffered(H.signatureSchemes, scheme):
    S.failServer(O,
      "TLS client does not accept the server certificate's signature scheme")
    return
  case S.keyKind
  of tskEd25519:
    signature = signTls13CertificateVerify(S.config.ed25519SecretKey, true,
      transcriptHash)
  of tskRsa:
    signature = signTls13CertificateVerifyRsaPss(S.rsaKey, true, transcriptHash)
  of tskEcdsaP256:
    signature = signTls13CertificateVerifyEcdsaP256(S.ecdsaScalar, true,
      transcriptHash)
  cv = encodeTls13CertificateVerify(signature, scheme)
  S.transcript.appendTls13Transcript(cv)
  O.outbound.add(S.connection.encodeTls13Protected(tctHandshake, cv))
  transcriptHash = S.transcript.tls13TranscriptHash()
  finished = encodeTls13Finished(tls13FinishedVerifyData(
    S.handshakeSecrets.serverHandshakeTraffic, transcriptHash))
  S.transcript.appendTls13Transcript(finished)
  O.outbound.add(S.connection.encodeTls13Protected(tctHandshake, finished))
  transcriptHash = S.transcript.tls13TranscriptHash()
  S.applicationSecrets = buildTls13ApplicationSecrets(
    S.handshakeSecrets.handshakeSecret, transcriptHash)
  S.connection.installTls13WriteTrafficSecret(
    S.applicationSecrets.serverApplicationTraffic)
  S.state = tssAwaitClientFinished
  secureClearBytes(shared)

proc acceptClientFinished(S: var Tls13ServerSession, H: Tls13Handshake,
    O: var Tls13ServerOutput) {.role: actor,
    tag: {tagTls, tagValidation, tagCryptoBoundary}.} =
  var
    transcriptHash: Sha256Digest = S.transcript.tls13TranscriptHash()
    expected: Tls13Secret = tls13FinishedVerifyData(
      S.handshakeSecrets.clientHandshakeTraffic, transcriptHash)
  if H.messageType != thtFinished or
      not constantTimeFinishedEqual(H.body, expected):
    S.failServer(O, "TLS client Finished is invalid")
    return
  S.transcript.appendTls13Transcript(H.encoded)
  S.connection.installTls13ReadTrafficSecret(
    S.applicationSecrets.clientApplicationTraffic)
  S.state = tssConnected
  O.connected = true
  secureClearBytes(S.x25519SecretKey)
  clearTls13HandshakeSecrets(S.handshakeSecrets)
  clearTls13ApplicationSecrets(S.applicationSecrets)

proc feedTls13Server*(S: var Tls13ServerSession,
    A: openArray[byte]): Tls13ServerOutput {.role: orchestrator,
    tag: {tagTls, tagTransport, tagCryptoBoundary}.} =
  ## S/A: server session and arbitrary next transport bytes.
  var
    step: Tls13FeedStep = S.connection.feedTls13One(A)
    clientHello: Tls13ClientHelloResult
    i: int = 0
  while true:
    i = 0
    while i < step.events.len:
      case step.events[i].kind
      of tekError:
        S.failServer(result, step.events[i].err)
        return
      of tekClosed:
        result.closed = true
        if S.state != tssConnected:
          S.state = tssClosed
        return
      of tekAlert:
        S.state = tssFailed
        result.err = "TLS peer sent alert " & $step.events[i].alertDescription
        return
      of tekApplicationData:
        if S.state != tssConnected:
          S.failServer(result,
            "TLS application data arrived before handshake completion")
          return
        result.applicationData.add(step.events[i].data)
      of tekHandshake:
        case S.state
        of tssAwaitClientHello:
          if step.events[i].handshake.messageType != thtClientHello:
            S.failServer(result, "TLS server expected ClientHello")
            return
          clientHello = decodeTls13ClientHello(step.events[i].handshake.body)
          if not clientHello.ok:
            S.failServer(result, clientHello.err)
            return
          try:
            S.emitServerFlight(clientHello.hello,
              step.events[i].handshake.encoded, result)
          except CatchableError as e:
            S.failServer(result, e.msg)
          if S.state == tssFailed:
            return
        of tssAwaitClientFinished:
          S.acceptClientFinished(step.events[i].handshake, result)
          if S.state == tssFailed:
            return
        of tssConnected:
          if step.events[i].handshake.messageType != thtKeyUpdate:
            S.failServer(result, "TLS post-handshake message is unsupported")
            return
          if step.events[i].handshake.body.len == 1 and
              step.events[i].handshake.body[0] == 1'u8:
            result.outbound.add(S.connection.encodeTls13KeyUpdate())
        else:
          S.failServer(result,
            "TLS handshake message arrived in invalid server state")
          return
      i = i + 1
    if not step.progressed:
      return
    step = S.connection.feedTls13One([])

proc encodeTls13ServerApplication*(S: var Tls13ServerSession,
    A: openArray[byte]): ByteSeq {.role: dataWriter,
    tag: {tagTls, tagTransport, tagCryptoBoundary}.} =
  ## S/A: connected server session and application bytes.
  if S.state != tssConnected:
    raise newException(IOError, "TLS server session is not connected")
  result = S.connection.encodeTls13Application(A)

proc encodeTls13ServerKeyUpdate*(S: var Tls13ServerSession,
    requestPeerUpdate: bool = false): ByteSeq {.role: dataWriter,
    tag: {tagTls, tagTransport, tagCryptoBoundary}.} =
  ## S/requestPeerUpdate: connected server and peer-update request flag.
  if S.state != tssConnected:
    raise newException(IOError, "TLS server session is not connected")
  result = S.connection.encodeTls13KeyUpdate(requestPeerUpdate)

proc closeTls13Server*(S: var Tls13ServerSession): ByteSeq {.
    role: dataWriter, tag: {tagTls, tagTransport, tagCryptoBoundary}.} =
  ## S: connected server session to close cleanly.
  if S.state != tssConnected:
    raise newException(IOError, "TLS server session is not connected")
  result = S.connection.encodeTls13CloseNotify()
  S.connection.clearTls13ConnectionSecrets()
  S.state = tssClosed
