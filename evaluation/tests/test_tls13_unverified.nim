## -----------------------------------------------------------------------
## TLS 1.3 without identity checks <- encryption against listeners, nothing more
## -----------------------------------------------------------------------
##
## `acceptAnyCertificate` exists for opportunistic mail transfer: most mail
## servers present certificates that do not match their name, and a hard check
## would lose the mail. What it must still do, and what these tests pin:
##
##   still checked      the server proves it holds the key of the certificate it sent
##   (CertificateVerify, Finished): a flipped byte in the encrypted flight is refused
##   NOT checked        chain, name, dates (a MITM at the very start can read everything)
##   visible            tls13PeerVerified says false, so a log line can say "unverified"
##   never by accident  refused together with a root or a trust store

import std/[unittest, times, base64, os]
import protocols/tls13
import ../../src/protocols/types
import runePragmas

type
  Outcome = tuple[ok: bool, err: string, verified: bool]

proc rd(p: string): ByteSeq {.role: dataFetcher.} =
  var
    s: string = readFile(p)
    i: int = 0
  result = newSeq[byte](s.len)
  while i < s.len:
    result[i] = byte(s[i])
    i = i + 1

proc rsaServer(): Tls13ServerConfig {.role: configurator.} =
  result.certificateChainDer = @[rd("evaluation/tests/fixtures/webpki/rleaf.der")]
  result.rsaPrivateKeyDer = rd("evaluation/tests/fixtures/webpki/rleaf.pk8")

proc anyClient(): Tls13ClientConfig {.role: configurator.} =
  result.acceptAnyCertificate = true
  result.serverName = "mail.elsewhere.example"
  result.nowUnix = getTime().toUnix()

proc handshake(srvCfg: Tls13ServerConfig, cliCfg: Tls13ClientConfig,
    flipLastByte: bool = false): Outcome {.role: orchestrator.} =
  ## Both engines, in memory, until both are connected (or one refuses).
  ## flipLastByte: change the last byte of the server's first flight in flight.
  var
    srv: Tls13ServerSession = initTls13ServerSession(srvCfg)
    cli: Tls13ClientSession = initTls13ClientSession(cliCfg)
    toServer: ByteSeq = startTls13Client(cli)
    toClient: ByteSeq = @[]
    sOut: Tls13ServerOutput = Tls13ServerOutput()
    cOut: Tls13ClientOutput = Tls13ClientOutput()
    srvUp: bool = false
    cliUp: bool = false
    rounds: int = 0
  while rounds < 12 and not (srvUp and cliUp):
    rounds = rounds + 1
    toClient = @[]
    if toServer.len > 0:
      sOut = feedTls13Server(srv, toServer)
      if sOut.err.len > 0:
        return (false, "server: " & sOut.err, false)
      srvUp = srvUp or sOut.connected
      for b in sOut.outbound:
        toClient.add(b)
    toServer = @[]
    if flipLastByte and toClient.len > 0:
      toClient[toClient.high] = toClient[toClient.high] xor 1'u8
    if toClient.len > 0:
      cOut = feedTls13Client(cli, toClient)
      if cOut.err.len > 0:
        return (false, "client: " & cOut.err, false)
      cliUp = cliUp or cOut.connected
      for b in cOut.outbound:
        toServer.add(b)
  result = (ok: srvUp and cliUp, err: "", verified: tls13PeerVerified(cli))

suite "TLS 1.3 acceptAnyCertificate":
  # {.testKind: tkIntegration, covers: "initTls13ClientSession".}
  test "a server under an unknown root is accepted, and the session says it is unverified":
    var
      r: Outcome = handshake(rsaServer(), anyClient())
    check r.ok
    check not r.verified

  # {.testKind: tkIntegration, covers: "initTls13ClientSession".}
  test "the same server is REFUSED by a client that checks (wrong root)":
    var
      c: Tls13ClientConfig = Tls13ClientConfig()
      r: Outcome = (ok: true, err: "", verified: false)
    c.pinnedRootCertificateDer = rd("evaluation/tests/fixtures/webpki/eroot.der")
    c.serverName = "mail.fjord.example"
    c.nowUnix = getTime().toUnix()
    r = handshake(rsaServer(), c)
    check not r.ok
    check r.err.len > 0

  # {.testKind: tkEdgeCase, covers: "initTls13ClientSession".}
  test "acceptAnyCertificate together with a root or a trust store is refused":
    var
      c: Tls13ClientConfig = anyClient()
    c.pinnedRootCertificateDer = rd("evaluation/tests/fixtures/webpki/rroot.der")
    expect ValueError:
      discard initTls13ClientSession(c)
    c = anyClient()
    c.trustedRootsDer = @[rd("evaluation/tests/fixtures/webpki/rroot.der")]
    expect ValueError:
      discard initTls13ClientSession(c)

  # {.testKind: tkEdgeCase, covers: "initTls13ClientSession".}
  test "no identity setting at all is still refused (acceptAny is never the default)":
    var
      c: Tls13ClientConfig = Tls13ClientConfig()
    expect ValueError:
      discard initTls13ClientSession(c)

  # {.testKind: tkFuzz, covers: "feedTls13Client",
  #   pins: "an unverified session must still be tamper-proof once it has started".}
  test "a flipped byte in the encrypted server flight is refused even without identity checks":
    var
      r: Outcome = handshake(rsaServer(), anyClient(), flipLastByte = true)
    check not r.ok
    check r.err.len > 0

proc pemOf(der: ByteSeq): string {.role: helper.} =
  ## der: one certificate as the armoured text a CA bundle holds.
  var
    raw: string = newString(der.len)
    i: int = 0
  while i < der.len:
    raw[i] = char(der[i])
    i = i + 1
  result = "-----BEGIN CERTIFICATE-----\n" & encodeMime(raw, lineLen = 64, newLine = "\n") &
    "\n-----END CERTIFICATE-----\n"

suite "tls13RootsFromPem (a CA bundle becomes trust anchors)":
  # {.testKind: tkIntegration, covers: "tls13RootsFromPem".}
  test "a bundle's root verifies a server: the checked path works end to end":
    var
      r: tuple[ok: bool, roots: seq[ByteSeq], skipped: int, err: string] =
        tls13RootsFromPem(pemOf(rd("evaluation/tests/fixtures/webpki/rroot.der")))
      c: Tls13ClientConfig = Tls13ClientConfig()
      o: Outcome = (ok: false, err: "", verified: false)
    check r.ok
    check r.roots.len == 1 and r.skipped == 0
    c.trustedRootsDer = r.roots
    c.serverName = "mail.fjord.example"
    c.nowUnix = getTime().toUnix()
    o = handshake(rsaServer(), c)
    check o.ok
    check o.verified

  # {.testKind: tkEdgeCase, covers: "tls13RootsFromPem".}
  test "a block that is not a certificate is skipped and counted, the rest is kept":
    var
      junk: string = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
      r: tuple[ok: bool, roots: seq[ByteSeq], skipped: int, err: string] =
        tls13RootsFromPem(junk & pemOf(rd("evaluation/tests/fixtures/webpki/rroot.der")))
    check r.ok
    check r.roots.len == 1
    check r.skipped == 1

  # {.testKind: tkEdgeCase, covers: "tls13RootsFromPem".}
  test "text with no usable certificate is refused":
    check not tls13RootsFromPem("").ok
    check not tls13RootsFromPem("hello").ok
    check not tls13RootsFromPem("-----BEGIN CERTIFICATE-----\nAAAA\n").ok

  # {.testKind: tkIntegration, covers: "tls13RootsFromPem".}
  test "this machine's own CA bundle loads (skipped when the machine has none)":
    var
      path: string = "/etc/ssl/certs/ca-certificates.crt"
      r: tuple[ok: bool, roots: seq[ByteSeq], skipped: int, err: string] =
        (ok: true, roots: @[], skipped: 0, err: "")
    if fileExists(path):
      r = tls13RootsFromPem(readFile(path))
      check r.ok
      check r.roots.len > 50
      check r.skipped < r.roots.len
