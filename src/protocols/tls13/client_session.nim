## -----------------------------------------------------------------------
## TLS 1.3 Client Session <- event-driven controlled-profile client engine
## -----------------------------------------------------------------------

import tyr/certs/[oid, x509, chain]
import tyr/helpers/random
import tyr/hashes/sha256
import tyr/kems/x25519
import tyr/certs/rsa
import tyr/signatures/ecdsa_p256

import ../types
import ./[types, codec, connection, hello, key_schedule, transcript,
  handshake_messages, alerts]
import runePragmas

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

  ## How the client decides whether to believe the server.
  ##
  ##   pinnedRootCertificateDer   exactly one self-issued root, and the
  ##                              server must send exactly one certificate
  ##                              directly under it. No intermediates, no
  ##                              path building, nothing to get wrong.
  ##
  ##   trustedRootsDer            a set of anchors, and the server may send
  ##                              a leaf plus the intermediates that lead to
  ##                              one of them. This is what talking to a
  ##                              server you did not provision requires.
  ##
  ## Set one or the other. Setting both is a configuration that cannot mean
  ## two things at once, so it is refused rather than silently ranked.
  Tls13ClientConfig* {.role: configurator.} = object
    pinnedRootCertificateDer*: ByteSeq
    trustedRootsDer*: seq[ByteSeq]
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
      tag: "tls|transport|cryptoBoundary".} = object
    state*: Tls13ClientSessionState
    config: Tls13ClientConfig
    connection: Tls13Connection
    transcript: Tls13Transcript
    rootCertificate: X509Certificate
    trustAnchors: TrustStore
    pinned: bool
    peerCertificate*: X509Certificate
    x25519SecretKey: ByteSeq
    handshakeSecrets: Tls13HandshakeSecrets
    applicationSecrets: Tls13ApplicationSecrets
    selectedAlpn*: string

proc random32(): array[32, byte] {.role: dataFetcher,
    tag: "tls|cryptoBoundary".} =
  var
    A: ByteSeq = cryptoRandomBytes(32)
    i: int = 0
  defer:
    secureClearBytes(A)
  while i < result.len:
    result[i] = A[i]
    i = i + 1

proc offeredAlpn(S: Tls13ClientSession, selected: string): bool {.role: parser,
    tag: "tls|validation".} =
  var i: int = 0
  while i < S.config.alpn.len:
    if S.config.alpn[i] == selected:
      return true
    i = i + 1

proc failClient(S: var Tls13ClientSession, O: var Tls13ClientOutput,
    e: string) {.role: actor,
    tag: "tls|validation|cryptoBoundary".} =
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
    role: truthBuilder, tag: "tls|transport".} =
  ## C: pinned root or trust anchors, expected identity, ALPN list, time, and
  ## optional test seed.
  var
    R: X509ReadResult
    added: string = ""
    i: int = 0
  if C.x25519Seed.len notin {0, 32}:
    raise newException(ValueError, "TLS client X25519 seed must be empty or 32 bytes")
  if C.pinnedRootCertificateDer.len > 0 and C.trustedRootsDer.len > 0:
    raise newException(ValueError,
      "TLS client takes a pinned root or a trust store, not both")
  if C.pinnedRootCertificateDer.len == 0 and C.trustedRootsDer.len == 0:
    raise newException(ValueError,
      "TLS client needs a pinned root or at least one trust anchor")
  result.state = tcsStart
  result.config = C
  result.connection = initTls13Connection()
  result.transcript = initTls13Transcript()
  result.trustAnchors = initTrustStore()
  result.pinned = C.pinnedRootCertificateDer.len > 0
  if result.pinned:
    R = parseX509CertificateDer(C.pinnedRootCertificateDer)
    if not R.ok:
      raise newException(ValueError, "TLS pinned root is invalid: " & R.err)
    result.rootCertificate = R.certificate
    return
  ## Every anchor is checked here rather than at handshake time, so a bad
  ## trust store is a setup error the caller sees immediately instead of a
  ## connection failure they have to trace back.
  while i < C.trustedRootsDer.len:
    R = parseX509CertificateDer(C.trustedRootsDer[i])
    if not R.ok:
      raise newException(ValueError, "TLS trust anchor is invalid: " & R.err)
    added = result.trustAnchors.addTrustedRoot(R.certificate)
    if added.len > 0:
      raise newException(ValueError, "TLS trust anchor is unusable: " & added)
    i = i + 1

proc startTls13Client*(S: var Tls13ClientSession): ByteSeq {.
    role: dataWriter, tag: "tls|transport|cryptoBoundary".} =
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
    tag: "tls|validation|cryptoBoundary".} =
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
    tag: "tls|validation".} =
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
    tag: "tls|validation|cryptoBoundary".} =
  ## The pinned profile takes exactly one certificate under exactly one root.
  ## The trust-store profile takes a leaf plus whatever intermediates lead to
  ## an anchor, which is what a server nobody provisioned actually sends.
  var
    R = decodeTls13Certificate(H.body)
    leaf: X509ReadResult
    parsed: X509ReadResult
    intermediates: seq[X509Certificate] = @[]
    policy: tuple[ok: bool, err: string]
    chain: ChainVerifyResult
    i: int = 1
  if not R.ok or R.message.requestContext.len != 0 or
      R.message.entries.len == 0:
    S.failClient(O, if R.err.len > 0: R.err else:
      "TLS server sent no certificate")
    return
  if S.pinned and R.message.entries.len != 1:
    S.failClient(O, "TLS controlled profile requires one server certificate")
    return
  if R.message.entries.len > maxChainDepth:
    S.failClient(O, "TLS server certificate chain is too long")
    return
  leaf = parseX509CertificateDer(R.message.entries[0].certificateDer)
  if not leaf.ok:
    S.failClient(O, leaf.err)
    return
  if S.pinned:
    policy = verifyPinnedServerCertificate(leaf.certificate,
      S.rootCertificate, S.config.nowUnix, S.config.serverName)
    if not policy.ok:
      S.failClient(O, policy.err)
      return
  else:
    while i < R.message.entries.len:
      parsed = parseX509CertificateDer(R.message.entries[i].certificateDer)
      if not parsed.ok:
        S.failClient(O, parsed.err)
        return
      intermediates.add(parsed.certificate)
      i = i + 1
    chain = verifyCertificateChain(leaf.certificate, intermediates,
      S.trustAnchors, S.config.nowUnix, S.config.serverName)
    if not chain.ok:
      S.failClient(O, chain.err)
      return
  S.peerCertificate = leaf.certificate
  S.transcript.appendTls13Transcript(H.encoded)
  S.state = tcsAwaitCertificateVerify

proc acceptCertificateVerify(S: var Tls13ClientSession, H: Tls13Handshake,
    O: var Tls13ClientOutput) {.role: actor,
    tag: "tls|validation|cryptoBoundary".} =
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
    tag: "tls|validation|cryptoBoundary".} =
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
    tag: "tls|validation".} =
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
    tag: "tls|transport|cryptoBoundary".} =
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
    tag: "tls|transport|cryptoBoundary".} =
  ## S/A: connected client session and application bytes.
  if S.state != tcsConnected:
    raise newException(IOError, "TLS client session is not connected")
  result = S.connection.encodeTls13Application(A)

proc encodeTls13ClientKeyUpdate*(S: var Tls13ClientSession,
    requestPeerUpdate: bool = false): ByteSeq {.role: dataWriter,
    tag: "tls|transport|cryptoBoundary".} =
  ## S/requestPeerUpdate: connected client and peer-update request flag.
  if S.state != tcsConnected:
    raise newException(IOError, "TLS client session is not connected")
  result = S.connection.encodeTls13KeyUpdate(requestPeerUpdate)

proc closeTls13Client*(S: var Tls13ClientSession): ByteSeq {.
    role: dataWriter, tag: "tls|transport|cryptoBoundary".} =
  ## S: connected client session to close cleanly.
  if S.state != tcsConnected:
    raise newException(IOError, "TLS client session is not connected")
  result = S.connection.encodeTls13CloseNotify()
  S.connection.clearTls13ConnectionSecrets()
  S.state = tcsClosed
