## -----------------------------------------------------------------------
## TLS 1.3 Client Session <- event-driven controlled-profile client engine
## -----------------------------------------------------------------------

import tyr/certs/[der, pem, oid, keys, x509, verify, chain]
import tyr/helpers/random
import tyr/hashes/sha256
import tyr/kems/x25519
import tyr/certs/rsa
import tyr/signatures/ecdsa_p256

import ../types
import ./[types, codec, connection, hello, key_schedule, transcript,
  handshake_messages, alerts]
import ../../analysis_pragmas

type
  Tls13ClientSessionState* = enum
    tcsStart,
    tcsAwaitServerHello,
    tcsAwaitEncryptedExtensions,
    tcsAwaitCertificate,
    tcsAwaitCertificateVerify,
    tcsAwaitServerFinished,
    tcsConnected,
    tcsClosed,
    tcsFailed

  Tls13ClientConfig* {.role: configurator.} = object
    pinnedRootCertificateDer*: ByteSeq
    serverName*: string
    alpn*: seq[string]
    nowUnix*: int64
    x25519Seed*: ByteSeq

  Tls13ClientOutput* {.role: truthState.} = object
    outbound*: seq[ByteSeq]
    applicationData*: seq[ByteSeq]
    connected*: bool
    closed*: bool
    err*: string

  Tls13ClientSession* {.role: memory,
      tag: {tagTls, tagTransport, tagCryptoBoundary}.} = object
    state*: Tls13ClientSessionState
    config: Tls13ClientConfig
    connection: Tls13Connection
    transcript: Tls13Transcript
    rootCertificate: X509Certificate
    peerCertificate*: X509Certificate
    x25519SecretKey: ByteSeq
    handshakeSecrets: Tls13HandshakeSecrets
    applicationSecrets: Tls13ApplicationSecrets
    selectedAlpn*: string

proc random32(): array[32, byte] {.role: dataFetcher,
    tag: {tagTls, tagCryptoBoundary}.} =
  var
    A: ByteSeq = cryptoRandomBytes(32)
    i: int = 0
  defer:
    secureClearBytes(A)
  while i < result.len:
    result[i] = A[i]
    i = i + 1

proc offeredAlpn(S: Tls13ClientSession, selected: string): bool {.role: parser,
    tag: {tagTls, tagValidation}.} =
  var i: int = 0
  while i < S.config.alpn.len:
    if S.config.alpn[i] == selected:
      return true
    i = i + 1

proc failClient(S: var Tls13ClientSession, O: var Tls13ClientOutput,
    e: string) {.role: stateController,
    tag: {tagTls, tagValidation, tagCryptoBoundary}.} =
  S.state = tcsFailed
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

proc initTls13ClientSession*(C: Tls13ClientConfig): Tls13ClientSession {.
    role: truthBuilder, tag: {tagTls, tagTransport}.} =
  ## C: pinned root, expected identity, ALPN list, time, and optional test seed.
  var R: X509ReadResult = parseX509CertificateDer(C.pinnedRootCertificateDer)
  if not R.ok:
    raise newException(ValueError, "TLS pinned root is invalid: " & R.err)
  if C.x25519Seed.len notin {0, 32}:
    raise newException(ValueError, "TLS client X25519 seed must be empty or 32 bytes")
  result.state = tcsStart
  result.config = C
  result.connection = initTls13Connection()
  result.transcript = initTls13Transcript()
  result.rootCertificate = R.certificate

proc startTls13Client*(S: var Tls13ClientSession): ByteSeq {.
    role: dataWriter, tag: {tagTls, tagTransport, tagCryptoBoundary}.} =
  ## S: fresh client session whose encoded ClientHello is returned.
  var
    kp: X25519TyrKeypair
    H: Tls13ClientHello
    message: ByteSeq = @[]
  if S.state != tcsStart:
    raise newException(IOError, "TLS client session has already started")
  if S.config.x25519Seed.len == 32:
    kp = x25519TyrKeypairFromSeed(S.config.x25519Seed)
  else:
    kp = x25519TyrKeypair()
  S.x25519SecretKey = kp.secretKey
  H.random = random32()
  H.serverName = S.config.serverName
  H.alpn = S.config.alpn
  H.x25519PublicKey = kp.publicKey
  message = encodeTls13Handshake(Tls13Handshake(
    messageType: thtClientHello, body: encodeTls13ClientHello(H)))
  S.transcript.appendTls13Transcript(message)
  S.state = tcsAwaitServerHello
  result = encodeTls13PlainHandshakeRecord(message)

proc acceptServerHello(S: var Tls13ClientSession, H: Tls13Handshake,
    O: var Tls13ClientOutput) {.role: actor,
    tag: {tagTls, tagValidation, tagCryptoBoundary}.} =
  var
    R: Tls13ServerHelloResult = decodeTls13ServerHello(H.body)
    shared: ByteSeq = @[]
    transcriptHash: Sha256Digest
  defer:
    secureClearBytes(shared)
  if not R.ok:
    S.failClient(O, R.err)
    return
  try:
    shared = x25519TyrShared(S.x25519SecretKey, R.hello.x25519PublicKey)
  except CatchableError as e:
    S.failClient(O, e.msg)
    return
  S.transcript.appendTls13Transcript(H.encoded)
  transcriptHash = S.transcript.tls13TranscriptHash()
  S.handshakeSecrets = buildTls13HandshakeSecrets([], shared, transcriptHash)
  S.connection.installTls13ReadKeys(deriveTls13TrafficKeys(
    S.handshakeSecrets.serverHandshakeTraffic))
  S.connection.installTls13WriteKeys(deriveTls13TrafficKeys(
    S.handshakeSecrets.clientHandshakeTraffic))
  S.state = tcsAwaitEncryptedExtensions

proc acceptEncryptedExtensions(S: var Tls13ClientSession, H: Tls13Handshake,
    O: var Tls13ClientOutput) {.role: actor,
    tag: {tagTls, tagValidation}.} =
  var R = decodeTls13EncryptedExtensions(H.body)
  if not R.ok:
    S.failClient(O, R.err)
    return
  if S.config.alpn.len > 0 and
      (R.alpn.len == 0 or not S.offeredAlpn(R.alpn)):
    S.failClient(O, "TLS server selected no offered ALPN")
    return
  S.selectedAlpn = R.alpn
  S.transcript.appendTls13Transcript(H.encoded)
  S.state = tcsAwaitCertificate

proc acceptCertificate(S: var Tls13ClientSession, H: Tls13Handshake,
    O: var Tls13ClientOutput) {.role: actor,
    tag: {tagTls, tagValidation, tagCryptoBoundary}.} =
  var
    R = decodeTls13Certificate(H.body)
    leaf: X509ReadResult
    policy: tuple[ok: bool, err: string]
  if not R.ok or R.message.requestContext.len != 0 or
      R.message.entries.len != 1:
    S.failClient(O, if R.err.len > 0: R.err else:
      "TLS controlled profile requires one server certificate")
    return
  leaf = parseX509CertificateDer(R.message.entries[0].certificateDer)
  if not leaf.ok:
    S.failClient(O, leaf.err)
    return
  policy = verifyPinnedServerCertificate(leaf.certificate,
    S.rootCertificate, S.config.nowUnix, S.config.serverName)
  if not policy.ok:
    S.failClient(O, policy.err)
    return
  S.peerCertificate = leaf.certificate
  S.transcript.appendTls13Transcript(H.encoded)
  S.state = tcsAwaitCertificateVerify

proc acceptCertificateVerify(S: var Tls13ClientSession, H: Tls13Handshake,
    O: var Tls13ClientOutput) {.role: actor,
    tag: {tagTls, tagValidation, tagCryptoBoundary}.} =
  var
    R = decodeTls13CertificateVerify(H.body)
    transcriptHash: Sha256Digest = S.transcript.tls13TranscriptHash()
    verified: bool = false
    rsaKey: RsaPublicKeyResult
    ecKey: P256PublicKeyResult
  if not R.ok:
    S.failClient(O, if R.err.len > 0: R.err else:
      "TLS server CertificateVerify is invalid")
    return
  # The signature scheme must match the leaf certificate's key algorithm,
  # otherwise a peer could sign with an algorithm the certificate never
  # authorized.
  case S.peerCertificate.publicKeyAlgorithm
  of oidEd25519:
    if R.scheme == tls13SignatureEd25519:
      verified = verifyTls13CertificateVerify(S.peerCertificate.publicKey,
        R.signature, true, transcriptHash)
  of oidRsaEncryption:
    if R.scheme == tls13SignatureRsaPssRsaeSha256:
      rsaKey = parseRsaSpki(S.peerCertificate.publicKeySpki)
      if rsaKey.ok:
        verified = verifyTls13CertificateVerifyRsaPss(rsaKey.key, R.signature,
          true, transcriptHash)
  of oidEcPublicKey:
    if R.scheme == tls13SignatureEcdsaSecp256r1Sha256:
      ecKey = parseP256Spki(S.peerCertificate.publicKeySpki)
      if ecKey.ok:
        verified = verifyTls13CertificateVerifyEcdsaP256(ecKey.point,
          R.signature, true, transcriptHash)
  else:
    verified = false
  if not verified:
    S.failClient(O, "TLS server CertificateVerify is invalid")
    return
  S.transcript.appendTls13Transcript(H.encoded)
  S.state = tcsAwaitServerFinished

proc acceptServerFinished(S: var Tls13ClientSession, H: Tls13Handshake,
    O: var Tls13ClientOutput) {.role: actor,
    tag: {tagTls, tagValidation, tagCryptoBoundary}.} =
  var
    transcriptHash: Sha256Digest = S.transcript.tls13TranscriptHash()
    expected: Tls13Secret = tls13FinishedVerifyData(
      S.handshakeSecrets.serverHandshakeTraffic, transcriptHash)
    finished: ByteSeq = @[]
  if not constantTimeFinishedEqual(H.body, expected):
    S.failClient(O, "TLS server Finished is invalid")
    return
  S.transcript.appendTls13Transcript(H.encoded)
  transcriptHash = S.transcript.tls13TranscriptHash()
  S.applicationSecrets = buildTls13ApplicationSecrets(
    S.handshakeSecrets.handshakeSecret, transcriptHash)
  finished = encodeTls13Finished(tls13FinishedVerifyData(
    S.handshakeSecrets.clientHandshakeTraffic, transcriptHash))
  S.transcript.appendTls13Transcript(finished)
  O.outbound.add(S.connection.encodeTls13Protected(tctHandshake, finished))
  S.connection.installTls13ReadTrafficSecret(
    S.applicationSecrets.serverApplicationTraffic)
  S.connection.installTls13WriteTrafficSecret(
    S.applicationSecrets.clientApplicationTraffic)
  S.state = tcsConnected
  O.connected = true
  secureClearBytes(S.x25519SecretKey)
  clearTls13HandshakeSecrets(S.handshakeSecrets)
  clearTls13ApplicationSecrets(S.applicationSecrets)

proc acceptClientHandshake(S: var Tls13ClientSession, H: Tls13Handshake,
    O: var Tls13ClientOutput) {.role: orchestrator,
    tag: {tagTls, tagValidation}.} =
  case S.state
  of tcsAwaitServerHello:
    if H.messageType != thtServerHello:
      S.failClient(O, "TLS client expected ServerHello")
      return
    S.acceptServerHello(H, O)
  of tcsAwaitEncryptedExtensions:
    if H.messageType != thtEncryptedExtensions:
      S.failClient(O, "TLS client expected EncryptedExtensions")
      return
    S.acceptEncryptedExtensions(H, O)
  of tcsAwaitCertificate:
    if H.messageType != thtCertificate:
      S.failClient(O, "TLS client expected Certificate")
      return
    S.acceptCertificate(H, O)
  of tcsAwaitCertificateVerify:
    if H.messageType != thtCertificateVerify:
      S.failClient(O, "TLS client expected CertificateVerify")
      return
    S.acceptCertificateVerify(H, O)
  of tcsAwaitServerFinished:
    if H.messageType != thtFinished:
      S.failClient(O, "TLS client expected Finished")
      return
    S.acceptServerFinished(H, O)
  of tcsConnected:
    if H.messageType == thtKeyUpdate and H.body.len == 1 and H.body[0] == 1'u8:
      O.outbound.add(S.connection.encodeTls13KeyUpdate())
    elif H.messageType != thtKeyUpdate and
        H.messageType != thtNewSessionTicket:
      S.failClient(O, "TLS post-handshake message is unsupported")
  else:
    S.failClient(O, "TLS handshake message arrived in invalid client state")

proc feedTls13Client*(S: var Tls13ClientSession,
    A: openArray[byte]): Tls13ClientOutput {.role: orchestrator,
    tag: {tagTls, tagTransport, tagCryptoBoundary}.} =
  ## S/A: client session and arbitrary next transport bytes.
  var
    step: Tls13FeedStep = S.connection.feedTls13One(A)
    i: int = 0
  while true:
    i = 0
    while i < step.events.len:
      case step.events[i].kind
      of tekError:
        S.failClient(result, step.events[i].err)
        return
      of tekClosed:
        result.closed = true
        if S.state != tcsConnected:
          S.state = tcsClosed
        return
      of tekAlert:
        S.state = tcsFailed
        result.err = "TLS peer sent alert " & $step.events[i].alertDescription
        return
      of tekApplicationData:
        if S.state != tcsConnected:
          S.failClient(result,
            "TLS application data arrived before handshake completion")
          return
        result.applicationData.add(step.events[i].data)
      of tekHandshake:
        S.acceptClientHandshake(step.events[i].handshake, result)
        if S.state == tcsFailed:
          return
      i = i + 1
    if not step.progressed:
      return
    step = S.connection.feedTls13One([])

proc encodeTls13ClientApplication*(S: var Tls13ClientSession,
    A: openArray[byte]): ByteSeq {.role: dataWriter,
    tag: {tagTls, tagTransport, tagCryptoBoundary}.} =
  ## S/A: connected client session and application bytes.
  if S.state != tcsConnected:
    raise newException(IOError, "TLS client session is not connected")
  result = S.connection.encodeTls13Application(A)

proc encodeTls13ClientKeyUpdate*(S: var Tls13ClientSession,
    requestPeerUpdate: bool = false): ByteSeq {.role: dataWriter,
    tag: {tagTls, tagTransport, tagCryptoBoundary}.} =
  ## S/requestPeerUpdate: connected client and peer-update request flag.
  if S.state != tcsConnected:
    raise newException(IOError, "TLS client session is not connected")
  result = S.connection.encodeTls13KeyUpdate(requestPeerUpdate)

proc closeTls13Client*(S: var Tls13ClientSession): ByteSeq {.
    role: dataWriter, tag: {tagTls, tagTransport, tagCryptoBoundary}.} =
  ## S: connected client session to close cleanly.
  if S.state != tcsConnected:
    raise newException(IOError, "TLS client session is not connected")
  result = S.connection.encodeTls13CloseNotify()
  S.connection.clearTls13ConnectionSecrets()
  S.state = tcsClosed
