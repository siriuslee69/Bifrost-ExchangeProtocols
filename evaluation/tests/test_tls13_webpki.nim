## Verifies that the TLS 1.3 engine completes real handshakes with the RSA and
## ECDSA P-256 certificates public CAs actually issue, not only the pinned
## Ed25519 profile. Fixtures under tests/fixtures/webpki were produced with
## OpenSSL; regenerate them with tools/gen_webpki_fixtures.sh.

import std/[strutils, times]
import protocols/tls13
import ../../src/protocols/types
import ../../src/analysis_pragmas

proc rd(p: string): ByteSeq =
  let s = readFile(p)
  result = newSeq[byte](s.len)
  for i, c in s: result[i] = byte(c)
proc fromHex(s: string): ByteSeq =
  let t = s.strip()
  result = newSeq[byte](t.len div 2)
  for i in 0 ..< result.len: result[i] = byte(parseHexInt(t[i*2 .. i*2+1]))

var fails = 0
proc chk(name: string, cond: bool) =
  if not cond:
    echo "FAIL ", name
    fails.inc
  else:
    echo "  ok  ", name

## Drive a complete handshake between the two session engines.
proc handshake(srvCfg: Tls13ServerConfig, cliCfg: Tls13ClientConfig):
    tuple[ok: bool, err: string, echoed: string] {.role: orchestrator.} =
  var
    srv = initTls13ServerSession(srvCfg)
    cli = initTls13ClientSession(cliCfg)
    toServer: ByteSeq = startTls13Client(cli)
    sOut: Tls13ServerOutput
    cOut: Tls13ClientOutput
    srvUp, cliUp: bool = false
    rounds = 0
  while rounds < 12:
    rounds.inc
    if toServer.len > 0:
      sOut = feedTls13Server(srv, toServer)
      if sOut.err.len > 0: return (false, "server: " & sOut.err, "")
      if sOut.connected: srvUp = true
    var toClient: ByteSeq = @[]
    for b in sOut.outbound: toClient.add(b)
    sOut.outbound = @[]
    toServer = @[]
    if toClient.len > 0:
      cOut = feedTls13Client(cli, toClient)
      if cOut.err.len > 0: return (false, "client: " & cOut.err, "")
      if cOut.connected: cliUp = true
      for b in cOut.outbound: toServer.add(b)
      cOut.outbound = @[]
    if srvUp and cliUp:
      let msg = "MAIL FROM:<a@b.example>"
      var appBytes = newSeq[byte](msg.len)
      for i, c in msg: appBytes[i] = byte(c)
      let wire = encodeTls13ClientApplication(cli, appBytes)
      let got = feedTls13Server(srv, wire)
      if got.err.len > 0: return (false, "app: " & got.err, "")
      if got.applicationData.len == 0: return (false, "no app data", "")
      var s = ""
      for v in got.applicationData[0]: s.add(char(v))
      return (true, "", s)
    if toServer.len == 0 and toClient.len == 0: break
  result = (false, "handshake did not converge", "")

let nowU = getTime().toUnix()

# --- RSA server certificate ---
var rsaSrv: Tls13ServerConfig
rsaSrv.certificateChainDer = @[rd("evaluation/tests/fixtures/webpki/rleaf.der")]
rsaSrv.rsaPrivateKeyDer = rd("evaluation/tests/fixtures/webpki/rleaf.pk8")
var rsaCli: Tls13ClientConfig
rsaCli.pinnedRootCertificateDer = rd("evaluation/tests/fixtures/webpki/rroot.der")
rsaCli.serverName = "mail.fjord.example"
rsaCli.nowUnix = nowU
let r1 = handshake(rsaSrv, rsaCli)
chk("TLS 1.3 handshake with an RSA-2048 certificate", r1.ok)
if not r1.ok: echo "   err: ", r1.err
else: chk("RSA session carries application data", r1.echoed == "MAIL FROM:<a@b.example>")

# --- ECDSA P-256 server certificate ---
var ecSrv: Tls13ServerConfig
ecSrv.certificateChainDer = @[rd("evaluation/tests/fixtures/webpki/eleaf.der")]
ecSrv.ecdsaPrivateScalar = fromHex(readFile("evaluation/tests/fixtures/webpki/eleaf.scalar.hex"))
var ecCli: Tls13ClientConfig
ecCli.pinnedRootCertificateDer = rd("evaluation/tests/fixtures/webpki/eroot.der")
ecCli.serverName = "mail.fjord.example"
ecCli.nowUnix = nowU
let r2 = handshake(ecSrv, ecCli)
chk("TLS 1.3 handshake with an ECDSA P-256 certificate", r2.ok)
if not r2.ok: echo "   err: ", r2.err
else: chk("ECDSA session carries application data", r2.echoed == "MAIL FROM:<a@b.example>")

# --- negative: wrong private key must be refused at config time ---
var badSrv: Tls13ServerConfig
badSrv.certificateChainDer = @[rd("evaluation/tests/fixtures/webpki/rleaf.der")]
badSrv.rsaPrivateKeyDer = rd("evaluation/tests/fixtures/webpki/rleaf.pk8")
badSrv.rsaPrivateKeyDer[80] = badSrv.rsaPrivateKeyDer[80] xor 0xff'u8
var threw = false
try: discard initTls13ServerSession(badSrv)
except CatchableError: threw = true
chk("reject an RSA key that does not match the leaf", threw)

# --- negative: hostname mismatch must fail the handshake ---
var wrongHost = rsaCli
wrongHost.serverName = "evil.example"
chk("reject a hostname the certificate does not cover",
    not handshake(rsaSrv, wrongHost).ok)

# --- negative: wrong pinned root must fail ---
var wrongRoot = rsaCli
wrongRoot.pinnedRootCertificateDer = rd("evaluation/tests/fixtures/webpki/eroot.der")
chk("reject a certificate not issued by the pinned root",
    not handshake(rsaSrv, wrongRoot).ok)

# --- ALPN: silence from the client is not a failure ---
#
# RFC 7301: a client that sends no ALPN extension gets no ALPN back and
# the connection proceeds normally. Only an offered list we share nothing
# with is a real failure. Getting this wrong breaks every client that
# does not bother with ALPN, `openssl s_client` among them.
var alpnSrv = ecSrv
alpnSrv.alpn = @["http/1.1"]

var noAlpnCli = ecCli
noAlpnCli.alpn = @[]
chk("a client offering no ALPN still completes the handshake",
    handshake(alpnSrv, noAlpnCli).ok)

var matchAlpnCli = ecCli
matchAlpnCli.alpn = @["h2", "http/1.1"]
chk("a client offering an overlapping ALPN list connects",
    handshake(alpnSrv, matchAlpnCli).ok)

var noOverlapCli = ecCli
noOverlapCli.alpn = @["h2"]
chk("a client whose ALPN list shares nothing is refused",
    not handshake(alpnSrv, noOverlapCli).ok)

# --- trust store: a real path through an intermediate ----------------------
#
# Every case above pins one root and takes exactly one certificate under it.
# That is the easy half of certificate validation and the only half that had
# ever run. A server nobody provisioned sends a leaf plus the intermediates
# that lead to an anchor, and the client has to walk them.
var chainSrv: Tls13ServerConfig
chainSrv.certificateChainDer = @[rd("evaluation/tests/fixtures/webpki/cleaf.der"),
                                 rd("evaluation/tests/fixtures/webpki/cint.der")]
chainSrv.rsaPrivateKeyDer = rd("evaluation/tests/fixtures/webpki/cleaf.pk8")

var chainCli: Tls13ClientConfig
chainCli.trustedRootsDer = @[rd("evaluation/tests/fixtures/webpki/croot.der")]
chainCli.serverName = "mail.fjord.example"
chainCli.nowUnix = nowU
let r3 = handshake(chainSrv, chainCli)
chk("TLS 1.3 handshake across root -> intermediate -> leaf", r3.ok)
if not r3.ok: echo "   err: ", r3.err
else: chk("chained session carries application data",
          r3.echoed == "MAIL FROM:<a@b.example>")

# Without the intermediate there is no path to the anchor, even though the
# anchor itself is trusted and the leaf is genuine.
var noIntSrv = chainSrv
noIntSrv.certificateChainDer = @[rd("evaluation/tests/fixtures/webpki/cleaf.der")]
chk("reject a leaf whose issuer was not supplied",
    not handshake(noIntSrv, chainCli).ok)

# A trust store that does not contain the root the chain leads to.
var wrongAnchor = chainCli
wrongAnchor.trustedRootsDer = @[rd("evaluation/tests/fixtures/webpki/rroot.der")]
chk("reject a chain that leads to an untrusted anchor",
    not handshake(chainSrv, wrongAnchor).ok)

# The hostname check applies to the chained profile too.
var chainWrongHost = chainCli
chainWrongHost.serverName = "evil.example"
chk("reject a chained certificate that does not cover the hostname",
    not handshake(chainSrv, chainWrongHost).ok)

# The pinned profile must keep refusing extra certificates: pinning means
# one hop, and accepting a bundle would quietly turn it into path building.
var pinnedWithExtra = rsaCli
chk("a pinned client refuses a multi-certificate chain",
    not handshake(chainSrv, pinnedWithExtra).ok)

# Two anchors configured, one of which is the right one.
var twoAnchors = chainCli
twoAnchors.trustedRootsDer = @[rd("evaluation/tests/fixtures/webpki/rroot.der"),
                               rd("evaluation/tests/fixtures/webpki/croot.der")]
chk("a trust store with several anchors finds the right one",
    handshake(chainSrv, twoAnchors).ok)

# A chain that is cryptographically perfect but violates a constraint one of
# its own certificates carries. dint1 says pathlen:0; dint2 sits below it.
var depthSrv: Tls13ServerConfig
depthSrv.certificateChainDer = @[rd("evaluation/tests/fixtures/webpki/dleaf.der"),
                                 rd("evaluation/tests/fixtures/webpki/dint2.der"),
                                 rd("evaluation/tests/fixtures/webpki/dint1.der")]
depthSrv.rsaPrivateKeyDer = rd("evaluation/tests/fixtures/webpki/dleaf.pk8")

var depthCli: Tls13ClientConfig
depthCli.trustedRootsDer = @[rd("evaluation/tests/fixtures/webpki/droot.der")]
depthCli.serverName = "mail.fjord.example"
depthCli.nowUnix = nowU
chk("reject a chain that exceeds an intermediate path length constraint",
    not handshake(depthSrv, depthCli).ok)

# --- configuration errors are refused at setup, not at handshake time ------
var bothModes: Tls13ClientConfig
bothModes.pinnedRootCertificateDer = rd("evaluation/tests/fixtures/webpki/rroot.der")
bothModes.trustedRootsDer = @[rd("evaluation/tests/fixtures/webpki/croot.der")]
bothModes.nowUnix = nowU
var bothThrew = false
try: discard initTls13ClientSession(bothModes)
except CatchableError: bothThrew = true
chk("refuse a client configured with both a pin and a trust store", bothThrew)

var neither: Tls13ClientConfig
neither.nowUnix = nowU
var neitherThrew = false
try: discard initTls13ClientSession(neither)
except CatchableError: neitherThrew = true
chk("refuse a client with no way to judge the server", neitherThrew)

var notACa: Tls13ClientConfig
notACa.trustedRootsDer = @[rd("evaluation/tests/fixtures/webpki/rleaf.der")]
notACa.nowUnix = nowU
var notACaThrew = false
try: discard initTls13ClientSession(notACa)
except CatchableError: notACaThrew = true
chk("refuse a trust anchor that is not a CA", notACaThrew)

echo "TLS RSA/ECDSA failures: ", fails
