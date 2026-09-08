## -----------------------------------------------------------------------
## TLS 1.3 Controlled Handshake <- in-memory Ed25519/X25519 state machine
## -----------------------------------------------------------------------

import tyr/certs/[x509, verify]
import tyr/hashes/sha256
import tyr/kems/x25519

import ../types
import ./[types, codec, hello, key_schedule, transcript, handshake_messages]
import bifrostPragmas

type
  Tls13HandshakeState* = enum
    thsStart,
    thsClientHello,
    thsServerHello,
    thsServerFlight,
    thsClientFinished,
    thsConnected,
    thsFailed

  Tls13ControlledConfig* = object
    serverCertificateDer*: ByteSeq
    pinnedRootCertificateDer*: ByteSeq
    serverEd25519SecretKey*: ByteSeq
    serverName*: string
    alpn*: string
    nowUnix*: int64
    clientX25519Seed*: ByteSeq
    serverX25519Seed*: ByteSeq

  Tls13ControlledResult* = object
    ok*: bool
    clientState*: Tls13HandshakeState
    serverState*: Tls13HandshakeState
    clientWriteKeys*: Tls13TrafficKeys
    clientReadKeys*: Tls13TrafficKeys
    serverWriteKeys*: Tls13TrafficKeys
    serverReadKeys*: Tls13TrafficKeys
    selectedAlpn*: string
    peerCertificate*: X509Certificate
    err*: string

proc failHandshake(R: var Tls13ControlledResult, e: string) {.
    role: actor, metaTags: {tagTls, tagValidation}.} =
  R.clientState = thsFailed
  R.serverState = thsFailed
  R.err = e

proc wrapHandshake(t: Tls13HandshakeType, body: ByteSeq): ByteSeq {.
    role: dataWriter, metaTags: {tagTls, tagWrite}.} =
  result = encodeTls13Handshake(Tls13Handshake(messageType: t, body: body))

proc runControlledTls13Handshake*(C: Tls13ControlledConfig):
    Tls13ControlledResult {.role: metaOrchestrator,
    metaTags: {tagTls, tagOrchestrator, tagCryptoBoundary}.} =
  ## C: deterministic controlled-profile credentials, identity, and X25519 seeds.
  var
    clientKp, serverKp: X25519TyrKeypair
    clientHello: Tls13ClientHello
    serverHello: Tls13ServerHello
    clientHelloBody, serverHelloBody: ByteSeq = @[]
    clientHelloMsg, serverHelloMsg: ByteSeq = @[]
    eeMsg, certMsg, cvMsg, serverFinishedMsg, clientFinishedMsg: ByteSeq = @[]
    sharedClient, sharedServer: ByteSeq = @[]
    clientTranscript, serverTranscript: Tls13Transcript
    helloHash, beforeCvHash, beforeServerFinishedHash, afterServerFinishedHash,
      beforeClientFinishedHash: Sha256Digest
    Hc, Hs: Tls13HandshakeSecrets
    Ac, As: Tls13ApplicationSecrets
    certParsed, rootParsed: X509ReadResult
    certPolicy: X509VerifyResult
    certFlight: Tls13CertificateMessage
    certDecoded: tuple[ok: bool, message: Tls13CertificateMessage, err: string]
    cvDecoded: tuple[ok: bool, signature: ByteSeq, scheme: uint16, err: string]
    eeDecoded: tuple[ok: bool, alpn, err: string]
    parsed: Tls13HandshakeResult
    signature, serverVerify, clientVerify: ByteSeq = @[]
    i: int = 0
  result.clientState = thsStart
  result.serverState = thsStart
  if C.clientX25519Seed.len != 32 or C.serverX25519Seed.len != 32:
    result.failHandshake("controlled TLS X25519 seeds must be 32 bytes")
    return
  clientKp = x25519TyrKeypairFromSeed(C.clientX25519Seed)
  serverKp = x25519TyrKeypairFromSeed(C.serverX25519Seed)
  clientTranscript = initTls13Transcript()
  serverTranscript = initTls13Transcript()
  clientHello.serverName = C.serverName
  if C.alpn.len > 0:
    clientHello.alpn = @[C.alpn]
  clientHello.x25519PublicKey = clientKp.publicKey
  while i < 32:
    clientHello.random[i] = byte(i)
    serverHello.random[i] = byte(255 - i)
    i = i + 1
  clientHelloBody = encodeTls13ClientHello(clientHello)
  clientHelloMsg = wrapHandshake(thtClientHello, clientHelloBody)
  clientTranscript.appendTls13Transcript(clientHelloMsg)
  serverTranscript.appendTls13Transcript(clientHelloMsg)
  result.clientState = thsClientHello
  result.serverState = thsClientHello
  if not decodeTls13ClientHello(clientHelloBody).ok:
    result.failHandshake("server rejected controlled ClientHello")
    return
  serverHello.x25519PublicKey = serverKp.publicKey
  serverHelloBody = encodeTls13ServerHello(serverHello)
  serverHelloMsg = wrapHandshake(thtServerHello, serverHelloBody)
  clientTranscript.appendTls13Transcript(serverHelloMsg)
  serverTranscript.appendTls13Transcript(serverHelloMsg)
  result.clientState = thsServerHello
  result.serverState = thsServerHello
  sharedClient = x25519TyrShared(clientKp.secretKey, serverKp.publicKey)
  sharedServer = x25519TyrShared(serverKp.secretKey, clientKp.publicKey)
  if sharedClient != sharedServer:
    result.failHandshake("controlled TLS X25519 shared secrets differ")
    return
  helloHash = clientTranscript.tls13TranscriptHash()
  Hc = buildTls13HandshakeSecrets([], sharedClient, helloHash)
  Hs = buildTls13HandshakeSecrets([], sharedServer, helloHash)
  eeMsg = encodeTls13EncryptedExtensions(C.alpn)
  serverTranscript.appendTls13Transcript(eeMsg)
  parsed = decodeTls13Handshake(eeMsg)
  eeDecoded = decodeTls13EncryptedExtensions(parsed.message.body)
  if not parsed.ok or not eeDecoded.ok or eeDecoded.alpn != C.alpn:
    result.failHandshake("client rejected EncryptedExtensions")
    return
  clientTranscript.appendTls13Transcript(eeMsg)
  certFlight.entries = @[Tls13CertificateEntry(
    certificateDer: C.serverCertificateDer)]
  certMsg = encodeTls13Certificate(certFlight)
  serverTranscript.appendTls13Transcript(certMsg)
  parsed = decodeTls13Handshake(certMsg)
  certDecoded = decodeTls13Certificate(parsed.message.body)
  if not parsed.ok or not certDecoded.ok or certDecoded.message.entries.len != 1:
    result.failHandshake("client rejected Certificate message")
    return
  clientTranscript.appendTls13Transcript(certMsg)
  certParsed = parseX509CertificateDer(certDecoded.message.entries[0].certificateDer)
  rootParsed = parseX509CertificateDer(C.pinnedRootCertificateDer)
  if not certParsed.ok or not rootParsed.ok:
    result.failHandshake("client could not parse controlled certificate chain")
    return
  certPolicy = verifyPinnedEd25519ServerCertificate(certParsed.certificate,
    rootParsed.certificate, C.nowUnix, C.serverName)
  if not certPolicy.ok:
    result.failHandshake(certPolicy.err)
    return
  beforeCvHash = serverTranscript.tls13TranscriptHash()
  signature = signTls13CertificateVerify(C.serverEd25519SecretKey, true,
    beforeCvHash)
  cvMsg = encodeTls13CertificateVerify(signature)
  serverTranscript.appendTls13Transcript(cvMsg)
  parsed = decodeTls13Handshake(cvMsg)
  cvDecoded = decodeTls13CertificateVerify(parsed.message.body)
  beforeCvHash = clientTranscript.tls13TranscriptHash()
  if not parsed.ok or not cvDecoded.ok or not verifyTls13CertificateVerify(
      certParsed.certificate.publicKey, cvDecoded.signature, true, beforeCvHash):
    result.failHandshake("client rejected server CertificateVerify")
    return
  clientTranscript.appendTls13Transcript(cvMsg)
  beforeServerFinishedHash = serverTranscript.tls13TranscriptHash()
  serverVerify = @(tls13FinishedVerifyData(Hs.serverHandshakeTraffic,
    beforeServerFinishedHash))
  serverFinishedMsg = encodeTls13Finished(serverVerify)
  serverTranscript.appendTls13Transcript(serverFinishedMsg)
  parsed = decodeTls13Handshake(serverFinishedMsg)
  beforeServerFinishedHash = clientTranscript.tls13TranscriptHash()
  if not parsed.ok or not constantTimeFinishedEqual(parsed.message.body,
      tls13FinishedVerifyData(Hc.serverHandshakeTraffic,
      beforeServerFinishedHash)):
    result.failHandshake("client rejected server Finished")
    return
  clientTranscript.appendTls13Transcript(serverFinishedMsg)
  afterServerFinishedHash = clientTranscript.tls13TranscriptHash()
  Ac = buildTls13ApplicationSecrets(Hc.handshakeSecret,
    afterServerFinishedHash)
  As = buildTls13ApplicationSecrets(Hs.handshakeSecret,
    afterServerFinishedHash)
  result.clientState = thsServerFlight
  result.serverState = thsServerFlight
  beforeClientFinishedHash = clientTranscript.tls13TranscriptHash()
  clientVerify = @(tls13FinishedVerifyData(Hc.clientHandshakeTraffic,
    beforeClientFinishedHash))
  clientFinishedMsg = encodeTls13Finished(clientVerify)
  clientTranscript.appendTls13Transcript(clientFinishedMsg)
  parsed = decodeTls13Handshake(clientFinishedMsg)
  beforeClientFinishedHash = serverTranscript.tls13TranscriptHash()
  if not parsed.ok or not constantTimeFinishedEqual(parsed.message.body,
      tls13FinishedVerifyData(Hs.clientHandshakeTraffic,
      beforeClientFinishedHash)):
    result.failHandshake("server rejected client Finished")
    return
  serverTranscript.appendTls13Transcript(clientFinishedMsg)
  result.clientState = thsClientFinished
  result.serverState = thsClientFinished
  result.clientWriteKeys = deriveTls13TrafficKeys(Ac.clientApplicationTraffic)
  result.clientReadKeys = deriveTls13TrafficKeys(Ac.serverApplicationTraffic)
  result.serverWriteKeys = deriveTls13TrafficKeys(As.serverApplicationTraffic)
  result.serverReadKeys = deriveTls13TrafficKeys(As.clientApplicationTraffic)
  result.selectedAlpn = eeDecoded.alpn
  result.peerCertificate = certParsed.certificate
  result.clientState = thsConnected
  result.serverState = thsConnected
  result.ok = result.clientWriteKeys.key == result.serverReadKeys.key and
    result.clientReadKeys.key == result.serverWriteKeys.key
  if not result.ok:
    result.failHandshake("controlled TLS application traffic keys differ")
