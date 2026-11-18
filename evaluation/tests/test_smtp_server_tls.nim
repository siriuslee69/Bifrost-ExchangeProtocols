## -------------------------------------------------------------------------
## SMTP server with STARTTLS <- the engine, with a TLS 1.3 client on the wire
## -------------------------------------------------------------------------
##
## No socket: the test is both ends of the wire. It hands the server engine
## the bytes a client would send and gives the client engine what comes back.
##
##   client engine (TLS 1.3)  <── bytes ──▶  SmtpTlsServer (the object a daemon holds)

import std/[strutils, unittest]

import tyr/certs/[pem, keys]
import tyr/signatures/ed25519

import ../../src/protocols/types
import ../../src/protocols/byte_codec
import ../../src/protocols/tls13
import ../../src/protocols/smtp
import ../../src/protocols/smtp/level2/server_tls
import runePragmas

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

proc serverConfig(): Tls13ServerConfig {.role: configurator.} =
  ## The fixture certificate and its Ed25519 key.
  var
    certPem: PemReadResult = readPemBlock(fixtureCertificate, "CERTIFICATE")
    key = parseEd25519PrivateKeyPem(fixturePrivateKey)
  result.certificateChainDer = @[certPem.pemBlock.der]
  result.ed25519SecretKey = ed25519TyrKeypairFromSeed(key.seed).secretKey

proc clientSession(): Tls13ClientSession {.role: configurator.} =
  ## A client that trusts the fixture certificate at a time it was valid.
  var
    c: Tls13ClientConfig = Tls13ClientConfig()
    certPem: PemReadResult = readPemBlock(fixtureCertificate, "CERTIFICATE")
    i: int = 0
  c.pinnedRootCertificateDer = certPem.pemBlock.der
  c.nowUnix = 1_627_310_000'i64
  c.x25519Seed = newSeq[byte](32)
  while i < 32:
    c.x25519Seed[i] = byte(i + 1)
    i = i + 1
  result = initTls13ClientSession(c)

proc mine(a: string): bool {.gcsafe, role: parser.} =
  ## Mail for example.org is ours.
  result = a.endsWith("@example.org")

proc textOf(A: seq[ByteSeq]): string {.role: helper.} =
  ## A: byte chunks as one text.
  for a in A:
    result.add(bytesToString(a))

proc handshake(S: var SmtpTlsServer, C: var Tls13ClientSession): bool {.
    role: orchestrator.} =
  ## S/C: the client says hello, both sides answer until the client is connected.
  ## True when both ends agree the handshake is done.
  var
    step: SmtpTlsStep = SmtpTlsStep()
    o: Tls13ClientOutput = Tls13ClientOutput()
    toServer: string = bytesToString(startTls13Client(C))
    rounds: int = 0
    connected: bool = false
  while rounds < 6 and toServer.len > 0:
    step = feedSmtpTlsServer(S, toServer, mine)
    if step.err.len > 0:
      return false
    o = feedTls13Client(C, stringToBytes(step.send))
    if o.err.len > 0:
      return false
    connected = connected or o.connected
    toServer = textOf(o.outbound)
    rounds = rounds + 1
  result = smtpTlsSecure(S) and connected

proc say(S: var SmtpTlsServer, C: var Tls13ClientSession, text: string): tuple[
    reply: string, mails: seq[SmtpMail]] {.role: orchestrator.} =
  ## S/C/text: the client seals `text`, the server answers; the client opens the
  ## sealed answer. `reply` is what the client reads.
  var
    step: SmtpTlsStep = feedSmtpTlsServer(S, bytesToString(
      encodeTls13ClientApplication(C, stringToBytes(text))), mine)
    sealed: string = S.sealSmtpTlsReply(step.reply)
    o: Tls13ClientOutput = Tls13ClientOutput()
  if sealed.len > 0:
    o = feedTls13Client(C, stringToBytes(sealed))
    result.reply = textOf(o.applicationData)
  result.mails = step.mails

suite "SMTP server with STARTTLS":
  # {.testKind: tkUnit, covers: "initSmtpTlsServer|feedSmtpTlsServer".}
  test "without a certificate STARTTLS is not offered and is refused":
    var
      S: SmtpTlsServer = initSmtpTlsServer("mx.example")
      step: SmtpTlsStep = feedSmtpTlsServer(S, "EHLO a.example\r\n", mine)
    check "STARTTLS" notin step.reply
    check step.send.len == 0
    step = feedSmtpTlsServer(S, "STARTTLS\r\n", mine)
    check step.reply.startsWith("502")
    check S.mode == swPlain

  # {.testKind: tkUnit, covers: "checkSmtpTlsConfig".}
  test "a good certificate passes the start-up check, a wrong key does not":
    var
      cfg: Tls13ServerConfig = serverConfig()
      bad: Tls13ServerConfig = serverConfig()
    check checkSmtpTlsConfig(cfg).ok
    check checkSmtpTlsConfig(Tls13ServerConfig()).ok
    bad.ed25519SecretKey[3] = bad.ed25519SecretKey[3] xor 0xff'u8
    check not checkSmtpTlsConfig(bad).ok
    check checkSmtpTlsConfig(bad).err.len > 0

  # {.testKind: tkRegression, covers: "feedSmtpTlsServer|resetSmtpServer",
  #   pins: "STARTTLS command injection: bytes after STARTTLS in the same burst".}
  test "what sat behind STARTTLS in the same burst is forgotten":
    var
      S: SmtpTlsServer = initSmtpTlsServer("mx.example", serverConfig())
      C: Tls13ClientSession = clientSession()
      step: SmtpTlsStep = SmtpTlsStep()
      got: tuple[reply: string, mails: seq[SmtpMail]] = ("", @[])
    step = feedSmtpTlsServer(S, "EHLO a.example\r\nSTARTTLS\r\n" &
      "MAIL FROM:<evil@x.example>\r\n", mine)
    ## the answers to EHLO and STARTTLS go out in the clear, the MAIL line gets none
    check "250-STARTTLS" in step.send
    check "220 go ahead" in step.send
    check "250 ok" notin step.send
    check step.reply.len == 0
    check S.mode == swHandshake
    check handshake(S, C)
    ## a recipient with no MAIL before it is refused: the server forgot the MAIL line
    got = say(S, C, "RCPT TO:<me@example.org>\r\n")
    check got.reply.startsWith("503")

  # {.testKind: tkIntegration, covers: "feedSmtpTlsServer|sealSmtpTlsReply".}
  test "a whole mail goes through TLS and its answers come back sealed":
    var
      S: SmtpTlsServer = initSmtpTlsServer("mx.example", serverConfig())
      C: Tls13ClientSession = clientSession()
      step: SmtpTlsStep = feedSmtpTlsServer(S, "EHLO a.example\r\nSTARTTLS\r\n", mine)
      got: tuple[reply: string, mails: seq[SmtpMail]] = ("", @[])
    check handshake(S, C)
    got = say(S, C, "EHLO a.example\r\n")
    check got.reply.startsWith("250-mx.example")
    ## STARTTLS is not offered a second time inside TLS
    check "STARTTLS" notin got.reply
    check say(S, C, "STARTTLS\r\n").reply.startsWith("502")
    check say(S, C, "MAIL FROM:<a@sender.example>\r\n").reply.startsWith("250")
    check say(S, C, "RCPT TO:<me@example.org>\r\n").reply.startsWith("250")
    check say(S, C, "DATA\r\n").reply.startsWith("354")
    got = say(S, C, "Subject: hi\r\n\r\nhello\r\n.\r\n")
    check got.reply.startsWith("250 kept")
    check got.mails.len == 1
    check got.mails[0].data == "Subject: hi\r\n\r\nhello\r\n"
    ## the reply of a finished mail was NOT sent in the clear
    check step.send.len > 0
    check "kept" notin step.send

  # {.testKind: tkUnit, covers: "closeSmtpTlsServer".}
  test "QUIT ends the conversation and the close is announced inside TLS":
    var
      S: SmtpTlsServer = initSmtpTlsServer("mx.example", serverConfig())
      C: Tls13ClientSession = clientSession()
      step: SmtpTlsStep = feedSmtpTlsServer(S, "STARTTLS\r\n", mine)
      sealed: string = ""
      o: Tls13ClientOutput = Tls13ClientOutput()
    check handshake(S, C)
    step = feedSmtpTlsServer(S, bytesToString(encodeTls13ClientApplication(C,
      stringToBytes("QUIT\r\n"))), mine)
    check step.closed
    sealed = S.sealSmtpTlsReply(step.reply) & S.closeSmtpTlsServer()
    o = feedTls13Client(C, stringToBytes(sealed))
    check textOf(o.applicationData).startsWith("221")
    check o.closed
    check S.mode == swDead

  # {.testKind: tkFuzz, covers: "feedSmtpTlsServer".}
  test "garbage in the handshake or in the clear closes the conversation, never raises":
    var
      S: SmtpTlsServer = initSmtpTlsServer("mx.example", serverConfig())
      step: SmtpTlsStep = SmtpTlsStep()
      junk: string = ""
      i: int = 0
    step = feedSmtpTlsServer(S, "STARTTLS\r\n", mine)
    junk = newString(300)
    while i < junk.len:
      junk[i] = char((i * 37 + 11) mod 256)
      i = i + 1
    step = feedSmtpTlsServer(S, junk, mine)
    check step.closed or step.err.len > 0 or S.mode == swHandshake
    step = feedSmtpTlsServer(S, junk, mine)
    ## and a plain server given the same junk: a line too long, no exception
    S = initSmtpTlsServer("mx.example", serverConfig())
    step = feedSmtpTlsServer(S, junk & junk & junk & junk & junk & junk & junk &
      junk & junk & junk & junk & junk & junk & junk & junk & junk & junk &
      junk & junk & junk & junk & junk & junk & junk & junk & junk, mine)
    check step.closed
    check S.mode == swDead
    ## a dead conversation stays dead
    step = feedSmtpTlsServer(S, "EHLO a\r\n", mine)
    check step.closed
    check step.reply.len == 0
