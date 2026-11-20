## -----------------------------------------------------------------------
## TLS 1.3 Server Session <- event-driven controlled-profile server flight
## -----------------------------------------------------------------------

import std/strutils
import tyr/certs/[oid, x509, verify]
import tyr/signatures/ed25519
import tyr/helpers/random
import tyr/hashes/sha256
import tyr/kems/x25519
import tyr/helpers/secure_memory
import tyr/certs/rsa
import tyr/helpers/bigint
import tyr/signatures/ecdsa_p256

import ../types
import ./[types, codec, connection, hello, key_schedule, transcript,
  handshake_messages, alerts, session_failure]
import ../byte_codec
import runePragmas

type
  Tls13ServerSessionState* = enum
    tssAwaitClientHello,
    tssAwaitClientFinished,
    tssConnected,
    tssClosed,
    tssFailed

  Tls13ServerKeyKind* {.role: configurator.} = enum
    tskEd25519, tskRsa, tskEcdsaP256

  Tls13ServerIdentity* {.role: configurator.} = object
    ## One certificate the server may show, and the names it is shown for.
    ##
    ##   names                a browser asks for a name (SNI); this identity
    ##                        answers when the name matches one of these:
    ##                        "example.com", or "*.example.com" (one label)
    ##   certificateChainDer  leaf first, then the chain
    ##   the three keys       exactly the one that fits the leaf, as in
    ##                        Tls13ServerConfig
    names*: seq[string]
    certificateChainDer*: seq[ByteSeq]
    ed25519SecretKey*: ByteSeq
    rsaPrivateKeyDer*: ByteSeq
    ecdsaPrivateScalar*: ByteSeq

  Tls13ServerConfig* {.role: configurator.} = object
    ## The four fields below are the DEFAULT certificate: shown when the
    ## browser names nothing or a name no identity answers for.
    ## `identities` adds more certificates, picked by the name asked for:
    ##
    ##   ClientHello "a.example.com" -> identities[k] whose names match,
    ##                                   the first one in list order
    ##   ClientHello "other.net"     -> the default certificate
    ##   ClientHello (no name)       -> the default certificate
    certificateChainDer*: seq[ByteSeq]
    ed25519SecretKey*: ByteSeq   ## used when the leaf carries an Ed25519 key
    rsaPrivateKeyDer*: ByteSeq   ## PKCS#1 or PKCS#8 DER for an RSA leaf
    ecdsaPrivateScalar*: ByteSeq ## 32-byte P-256 scalar for an EC leaf
    alpn*: seq[string]
    identities*: seq[Tls13ServerIdentity]

  Tls13ReadyIdentity {.role: memory,
      expectedCount: [1, 512], lifeCycle: lcSession.} = object
    ## A Tls13ServerIdentity after its key was proved to fit its leaf.
    ## One session holds the default and every named one (at most 512).
    names: seq[string]
    chain: seq[ByteSeq]
    keyKind: Tls13ServerKeyKind
    ed25519SecretKey: ByteSeq
    rsaKey: RsaPrivateKey
    ecdsaScalar: BigInt

  Tls13ServerOutput* {.role: truthState.} = object
    outbound*: seq[ByteSeq]
    applicationData*: seq[ByteSeq]
    connected*: bool
    closed*: bool
    err*: string

  Tls13ServerSession* {.role: memory,
      tag: "tls|transport|cryptoBoundary".} = object
    state*: Tls13ServerSessionState
    config: Tls13ServerConfig
    connection: Tls13Connection
    transcript: Tls13Transcript
    x25519SecretKey: ByteSeq
    handshakeSecrets: Tls13HandshakeSecrets
    applicationSecrets: Tls13ApplicationSecrets
    selectedAlpn*: string
    requestedServerName*: string
    ready: seq[Tls13ReadyIdentity]   ## [0] = the default, then `identities`
    chosen: int                      ## index into `ready`, set by the ClientHello

proc readyIdentity(C: Tls13ServerIdentity): Tls13ReadyIdentity {.
    role: truthBuilder, tag: "tls|transport|cryptoBoundary".} =
  ## C: one certificate and its key -> the same, checked: the key belongs to
  ## the leaf (proved here, before any session can use it).
  var
    R: X509ReadResult = default(X509ReadResult)
    leaf: X509Certificate = default(X509Certificate)
    publicKey: ByteSeq = @[]
    i: int = 0
    rsaParsed: RsaPrivateKeyResult = default(RsaPrivateKeyResult)
    ecParsed: P256PublicKeyResult = default(P256PublicKeyResult)
    derived: P256AffinePoint = default(P256AffinePoint)
    scalar: BigInt = default(BigInt)
  if C.certificateChainDer.len == 0:
    raise newException(ValueError, "TLS server certificate chain is empty")
  while i < C.names.len:
    if C.names[i].len == 0 or C.names[i].len > 253 or ' ' in C.names[i]:
      raise newException(ValueError, "TLS server identity name is invalid")
    i = i + 1
  i = 0
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
  result.names = C.names
  result.chain = C.certificateChainDer
  result.ed25519SecretKey = C.ed25519SecretKey

proc initTls13ServerSession*(C: Tls13ServerConfig): Tls13ServerSession {.
    role: truthBuilder, tag: "tls|transport".} =
  ## C: the default certificate and key, more named certificates, and the
  ## supported ALPN identifiers. Every key is checked against its leaf here,
  ## so a mismatched pair fails at start-up and not on a visitor's first
  ## handshake.
  var
    D: Tls13ServerIdentity = Tls13ServerIdentity(
      certificateChainDer: C.certificateChainDer,
      ed25519SecretKey: C.ed25519SecretKey,
      rsaPrivateKeyDer: C.rsaPrivateKeyDer,
      ecdsaPrivateScalar: C.ecdsaPrivateScalar)
    i: int = 0
  if C.identities.len > 511:
    raise newException(ValueError, "TLS server holds at most 512 certificates")
  result.ready.add(readyIdentity(D))
  while i < C.identities.len:
    result.ready.add(readyIdentity(C.identities[i]))
    i = i + 1
  result.chosen = 0
  result.state = tssAwaitClientHello
  result.config = C
  result.connection = initTls13Connection()
  result.transcript = initTls13Transcript()

proc answersTo(I: Tls13ReadyIdentity, host: string): bool {.role: parser,
    tag: "tls|validation".} =
  ## I/host: an identity and the lowercase name the browser asked for ->
  ## whether one of the identity's names matches it ("*.x.org" = one label).
  var
    i: int = 0
  while i < I.names.len:
    if matchDnsPattern(I.names[i], host):
      return true
    i = i + 1

proc pickIdentity(S: Tls13ServerSession, host: string): int {.role: parser,
    tag: "tls|validation".} =
  ## S/host: a session and the name from the ClientHello ("" = none) -> the
  ## index of the first named identity that answers to it, else 0 (default).
  var
    i: int = 1
    h: string = host.toLowerAscii()
  if h.len == 0:
    return 0
  while i < S.ready.len:
    if S.ready[i].answersTo(h):
      return i
    i = i + 1
  result = 0

proc chooseAlpn(offered, supported: openArray[string]): string {.role: parser,
    tag: "tls|validation".} =
  ## offered/supported: the first of OUR protocols the client also offered.
  result = ""
  for s in supported:
    if s in offered:
      return s

proc schemeForKeyKind(k: Tls13ServerKeyKind): uint16 {.role: helper,
    tag: "tls".} =
  ## k: server key kind whose TLS signature scheme code is returned.
  case k
  of tskEd25519:
    result = tls13SignatureEd25519
  of tskRsa:
    result = tls13SignatureRsaPssRsaeSha256
  of tskEcdsaP256:
    result = tls13SignatureEcdsaSecp256r1Sha256

proc clientOffered(offered: openArray[uint16], scheme: uint16): bool {.
    role: parser, tag: "tls|validation".} =
  ## offered/scheme: client's signature_algorithms list and one scheme code.
  var i: int = 0
  while i < offered.len:
    if offered[i] == scheme:
      return true
    i = i + 1

proc failServer(S: var Tls13ServerSession, O: var Tls13ServerOutput,
    e: string) {.role: actor,
    tag: "tls|validation|cryptoBoundary".} =
  S.state = tssFailed
  O.err = e
  failTls13Handshake(S.connection, O.outbound, S.x25519SecretKey,
    S.handshakeSecrets, S.applicationSecrets, e)

proc random32(): array[32, byte] {.role: dataFetcher,
    tag: "tls|cryptoBoundary".} =
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
    role: orchestrator, tag: "tls|cryptoBoundary".} =
  var
    kp: X25519TyrKeypair = default(X25519TyrKeypair)
    SH: Tls13ServerHello = default(Tls13ServerHello)
    serverHelloBody, serverHelloMessage, ee, cert, cv, finished: ByteSeq = @[]
    shared: ByteSeq = @[]
    helloHash, transcriptHash: Sha256Digest = default(Sha256Digest)
    certificateMessage: Tls13CertificateMessage =
      default(Tls13CertificateMessage)
    signature: ByteSeq = @[]
    serverHandshakeKeys, clientHandshakeKeys: Tls13TrafficKeys =
      default(Tls13TrafficKeys)
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
  S.chosen = S.pickIdentity(H.serverName)
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
  while i < S.ready[S.chosen].chain.len:
    certificateMessage.entries.add(Tls13CertificateEntry(
      certificateDer: S.ready[S.chosen].chain[i]))
    i = i + 1
  cert = encodeTls13Certificate(certificateMessage)
  S.transcript.appendTls13Transcript(cert)
  O.outbound.add(S.connection.encodeTls13Protected(tctHandshake, cert))
  transcriptHash = S.transcript.tls13TranscriptHash()
  scheme = schemeForKeyKind(S.ready[S.chosen].keyKind)
  # RFC 8446 4.4.3: only sign with a scheme the client advertised.
  if H.signatureSchemes.len > 0 and not clientOffered(H.signatureSchemes, scheme):
    S.failServer(O,
      "TLS client does not accept the server certificate's signature scheme")
    return
  case S.ready[S.chosen].keyKind
  of tskEd25519:
    signature = signTls13CertificateVerify(S.ready[S.chosen].ed25519SecretKey,
      true, transcriptHash)
  of tskRsa:
    signature = signTls13CertificateVerifyRsaPss(S.ready[S.chosen].rsaKey, true,
      transcriptHash)
  of tskEcdsaP256:
    signature = signTls13CertificateVerifyEcdsaP256(S.ready[S.chosen].ecdsaScalar,
      true, transcriptHash)
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
    tag: "tls|validation|cryptoBoundary".} =
  var
    transcriptHash: Sha256Digest = S.transcript.tls13TranscriptHash()
    expected: Tls13Secret = tls13FinishedVerifyData(
      S.handshakeSecrets.clientHandshakeTraffic, transcriptHash)
  if H.messageType != thtFinished or
      not constantTimeEqual(H.body, expected):
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

## ╭⟢ one event at a time
##
## The feed loop used to be five deep: a loop over steps, a loop over the
## events in a step, a case on the event kind, a case on the session state,
## and a test inside that. Each layer below is one of those, pulled out. The
## bool every one returns means "the caller must stop" -- a failure, a close,
## or an alert -- so the loop that remains has nothing in it but the walk.

proc acceptServerClientHello(S: var Tls13ServerSession, H: Tls13Handshake,
    O: var Tls13ServerOutput): bool {.inline, role: orchestrator,
    tag: "tls|cryptoBoundary".} =
  ## S/H/O: session awaiting a ClientHello, the message, and the output.
  var
    clientHello: Tls13ClientHelloResult = default(Tls13ClientHelloResult)
  if H.messageType != thtClientHello:
    S.failServer(O, "TLS server expected ClientHello")
    return true
  clientHello = decodeTls13ClientHello(H.body)
  if not clientHello.ok:
    S.failServer(O, clientHello.err)
    return true
  try:
    S.emitServerFlight(clientHello.hello, H.encoded, O)
  except CatchableError as e:
    S.failServer(O, e.msg)
  result = S.state == tssFailed

proc acceptServerPostHandshake(S: var Tls13ServerSession, H: Tls13Handshake,
    O: var Tls13ServerOutput): bool {.inline, role: orchestrator,
    tag: "tls|cryptoBoundary".} =
  ## S/H/O: connected session and a message arriving after the handshake.
  ## Only a KeyUpdate is allowed here, and only the "please update" form of
  ## it is answered; anything else ends the session rather than being
  ## ignored, so a peer cannot keep sending things this side does not read.
  if H.messageType != thtKeyUpdate:
    S.failServer(O, "TLS post-handshake message is unsupported")
    return true
  if H.body.len == 1 and H.body[0] == 1'u8:
    O.outbound.add(S.connection.encodeTls13KeyUpdate())

proc acceptServerHandshake(S: var Tls13ServerSession, H: Tls13Handshake,
    O: var Tls13ServerOutput): bool {.inline, role: orchestrator,
    tag: "tls|cryptoBoundary".} =
  ## S/H/O: which handshake message is allowed depends on the state.
  case S.state
  of tssAwaitClientHello:
    result = acceptServerClientHello(S, H, O)
  of tssAwaitClientFinished:
    S.acceptClientFinished(H, O)
    result = S.state == tssFailed
  of tssConnected:
    result = acceptServerPostHandshake(S, H, O)
  else:
    S.failServer(O, "TLS handshake message arrived in invalid server state")
    result = true

proc acceptServerEvent(S: var Tls13ServerSession, E: Tls13Event,
    O: var Tls13ServerOutput): bool {.inline, role: orchestrator,
    tag: "tls|cryptoBoundary".} =
  ## S/E/O: one decoded event. True when the caller must stop reading.
  case E.kind
  of tekError:
    S.failServer(O, E.err)
    result = true
  of tekClosed:
    O.closed = true
    if S.state != tssConnected:
      S.state = tssClosed
    result = true
  of tekAlert:
    S.state = tssFailed
    O.err = "TLS peer sent alert " & $E.alertDescription
    result = true
  of tekApplicationData:
    if S.state != tssConnected:
      S.failServer(O,
        "TLS application data arrived before handshake completion")
      return true
    O.applicationData.add(E.data)
  of tekHandshake:
    result = acceptServerHandshake(S, E.handshake, O)

proc acceptServerEvents(S: var Tls13ServerSession, E: seq[Tls13Event],
    O: var Tls13ServerOutput): bool {.role: actor,
    tag: "tls|transport|cryptoBoundary".} =
  ## S/E/O: act on each event of one feed step; true once one ends the feed.
  result = false
  for e in E:
    if acceptServerEvent(S, e, O):
      return true

proc feedTls13Server*(S: var Tls13ServerSession,
    A: openArray[byte]): Tls13ServerOutput {.role: orchestrator,
    tag: "tls|transport|cryptoBoundary".} =
  ## S/A: server session and arbitrary next transport bytes.
  var
    step: Tls13FeedStep = S.connection.feedTls13One(A)
  while true:
    if acceptServerEvents(S, step.events, result):
      return
    if not step.progressed:
      return
    step = S.connection.feedTls13One([])

proc encodeTls13ServerApplication*(S: var Tls13ServerSession,
    A: openArray[byte]): ByteSeq {.role: dataWriter,
    tag: "tls|transport|cryptoBoundary".} =
  ## S/A: connected server session and application bytes.
  if S.state != tssConnected:
    raise newException(IOError, "TLS server session is not connected")
  result = S.connection.encodeTls13Application(A)

proc encodeTls13ServerKeyUpdate*(S: var Tls13ServerSession,
    requestPeerUpdate: bool = false): ByteSeq {.role: dataWriter,
    tag: "tls|transport|cryptoBoundary".} =
  ## S/requestPeerUpdate: connected server and peer-update request flag.
  if S.state != tssConnected:
    raise newException(IOError, "TLS server session is not connected")
  result = S.connection.encodeTls13KeyUpdate(requestPeerUpdate)

proc closeTls13Server*(S: var Tls13ServerSession): ByteSeq {.
    role: dataWriter, tag: "tls|transport|cryptoBoundary".} =
  ## S: connected server session to close cleanly.
  if S.state != tssConnected:
    raise newException(IOError, "TLS server session is not connected")
  result = S.connection.encodeTls13CloseNotify()
  S.connection.clearTls13ConnectionSecrets()
  S.state = tssClosed
