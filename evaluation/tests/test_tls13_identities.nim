## -------------------------------------------------------------------------
## TLS 1.3 Identities <- one server, several certificates, picked by name
## -------------------------------------------------------------------------
##
## A hosting server answers for many domains. The browser says which one it
## wants inside the ClientHello (the "server name", SNI), and the server must
## show the certificate of THAT domain:
##
##   browser asks for        server shows          why
##   ----------------------  --------------------  ---------------------------
##   beta.example            beta's certificate    the name is in beta's list
##   www.beta.example        beta's certificate    the same list
##   x.wild.example          wild's certificate    "*.wild.example" = one label
##   a.b.wild.example        the default (alpha)   two labels: no match
##   unknown.net / nothing   the default (alpha)   nobody holds that name
##
## Each test connects as a browser would (asking for a name) and reads which
## certificate came back. The three certificates and their keys are throwaway
## Ed25519 pairs made with `openssl` for these tests only; they protect nothing.

import std/unittest

import tyr/certs/[pem, keys, x509]
import tyr/signatures/ed25519

import ../../src/protocols/types
import ../../src/protocols/tls13
import runePragmas

const
  testNow = 1_795_200_000'i64
    ## 2026-11-20, inside the three certificates' life (they last 100 years).
  alphaCert = """-----BEGIN CERTIFICATE-----
MIIBYTCCAROgAwIBAgIUOh/hWEZEJ9OVpsYAwShOMcxr64EwBQYDK2VwMBgxFjAU
BgNVBAMMDWFscGhhLmV4YW1wbGUwIBcNMjYxMTIwMTI0NTMyWhgPMjEyNjEwMjcx
MjQ1MzJaMBgxFjAUBgNVBAMMDWFscGhhLmV4YW1wbGUwKjAFBgMrZXADIQAunJv2
4W6qhptQXQQLKeJsjzdFXhb/Fstx6Gi3x6Xu5aNtMGswHQYDVR0OBBYEFE9OwKaE
kmGLhqo+55Gom5bco51gMB8GA1UdIwQYMBaAFE9OwKaEkmGLhqo+55Gom5bco51g
MA8GA1UdEwEB/wQFMAMBAf8wGAYDVR0RBBEwD4INYWxwaGEuZXhhbXBsZTAFBgMr
ZXADQQAyPyBn1EOsyU2+QHK0gt+UBqqLoKoUS93/DMEWt3MQwfIataqvj7eZ1gZh
HWUlyUtKE2fB9ABmtAHzlT9JcT8C
-----END CERTIFICATE-----"""
  alphaKey = """-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKAfzsrIziKARNvFNvJefQrm306Rb86hLYanCjz6JS8q
-----END PRIVATE KEY-----"""
  betaCert = """-----BEGIN CERTIFICATE-----
MIIBcDCCASKgAwIBAgIUCDTeRFZH5cYv9sBlrLLb2SdugJkwBQYDK2VwMBcxFTAT
BgNVBAMMDGJldGEuZXhhbXBsZTAgFw0yNjExMjAxMjQ1MzJaGA8yMTI2MTAyNzEy
NDUzMlowFzEVMBMGA1UEAwwMYmV0YS5leGFtcGxlMCowBQYDK2VwAyEAdfMv7rgk
rE38TQUZwMywcbyRgQhj1O6Pm8pmRYxoGx2jfjB8MB0GA1UdDgQWBBQXG2zN1x0J
7J71VVFq3XQVILN2ezAfBgNVHSMEGDAWgBQXG2zN1x0J7J71VVFq3XQVILN2ezAP
BgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDGJldGEuZXhhbXBsZYIQd3d3LmJl
dGEuZXhhbXBsZTAFBgMrZXADQQCAk5IZVI0vLGj5InO9GIVzgouqRzUxJOVX2wJw
1n+MhonfJ7/FEK5bGqKmR5cvR0D37eJ2pPTwDXQHOigjBoUF
-----END CERTIFICATE-----"""
  betaKey = """-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJkP/HTBScsO3GsPR0WzaOafGdiWPWmyVrFLyekc58NV
-----END PRIVATE KEY-----"""
  wildCert = """-----BEGIN CERTIFICATE-----
MIIBZDCCARagAwIBAgIUProTP12TBeJ+3DvNWkWY6P/YYuEwBQYDK2VwMBkxFzAV
BgNVBAMMDioud2lsZC5leGFtcGxlMCAXDTI2MTEyMDEyNDUzMloYDzIxMjYxMDI3
MTI0NTMyWjAZMRcwFQYDVQQDDA4qLndpbGQuZXhhbXBsZTAqMAUGAytlcAMhAFBg
zKTMA2hX3agSMzKzULVRdoYK9z0n0ZeJALxn0qnno24wbDAdBgNVHQ4EFgQUTArM
wpBSoYeBo/fnSOi2FrrfKSwwHwYDVR0jBBgwFoAUTArMwpBSoYeBo/fnSOi2Frrf
KSwwDwYDVR0TAQH/BAUwAwEB/zAZBgNVHREEEjAQgg4qLndpbGQuZXhhbXBsZTAF
BgMrZXADQQAjMTKgWgJAVdthACvV1lAt3QnM2+sdrdcxNrGL3Hym5LUlFKgFOwNk
cGQGggk/0Pk0WBAK4f4wxq9/+8gg1qcC
-----END CERTIFICATE-----"""
  wildKey = """-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAnhfd+j3LNx9L38w9FGvyFP9Jo1KS16s8QC/Qj+OvgE
-----END PRIVATE KEY-----"""

type
  Who = enum
    wNobody, wAlpha, wBeta, wWild
      ## Which of the three certificates a browser was shown.

proc joinAll(P: seq[ByteSeq]): ByteSeq {.role: helper.} =
  ## P: pieces -> all of them back to back.
  var
    i: int = 0
  while i < P.len:
    result.add(P[i])
    i = i + 1

proc identityOf(certPem, keyPem: string; names: seq[string]): Tls13ServerIdentity {.
    role: truthBuilder.} =
  ## certPem/keyPem/names: PEM texts and the names -> a server identity.
  var
    c: PemReadResult = readPemBlock(certPem, "CERTIFICATE")
    k = parseEd25519PrivateKeyPem(keyPem)
  result.names = names
  result.certificateChainDer = @[c.pemBlock.der]
  result.ed25519SecretKey = ed25519TyrKeypairFromSeed(k.seed).secretKey

proc leafKeyOf(certPem: string): ByteSeq {.role: parser.} =
  ## certPem -> the public key inside the certificate (it tells them apart).
  result = parseX509CertificateDer(
    readPemBlock(certPem, "CERTIFICATE").pemBlock.der).certificate.publicKey

proc whichOf(shown: ByteSeq): Who {.role: parser.} =
  ## shown: a public key -> which fixture certificate holds it.
  if shown == leafKeyOf(alphaCert):
    result = wAlpha
  elif shown == leafKeyOf(betaCert):
    result = wBeta
  elif shown == leafKeyOf(wildCert):
    result = wWild
  else:
    result = wNobody

proc serverConfig(order: seq[Tls13ServerIdentity] = @[]): Tls13ServerConfig {.
    role: truthBuilder.} =
  ## order: the named identities, in the order the server checks them (empty =
  ## beta then wild) -> a config whose DEFAULT certificate is alpha.
  var
    a: Tls13ServerIdentity = identityOf(alphaCert, alphaKey, @["alpha.example"])
  result.certificateChainDer = a.certificateChainDer
  result.ed25519SecretKey = a.ed25519SecretKey
  result.alpn = @["http/1.1"]
  if order.len > 0:
    result.identities = order
  else:
    result.identities = @[
      identityOf(betaCert, betaKey, @["beta.example", "www.beta.example"]),
      identityOf(wildCert, wildKey, @["*.wild.example"])]

proc shownFor(sc: Tls13ServerConfig; name: string): Who {.role: orchestrator.} =
  ## sc/name: a server config and the name the browser asks for ("" = none)
  ## -> which certificate the server showed (wNobody = the handshake failed).
  var
    cc: Tls13ClientConfig = default(Tls13ClientConfig)
    client: Tls13ClientSession = default(Tls13ClientSession)
    server: Tls13ServerSession = initTls13ServerSession(sc)
    co: Tls13ClientOutput = default(Tls13ClientOutput)
    so: Tls13ServerOutput = default(Tls13ServerOutput)
    i: int = 0
  cc.acceptAnyCertificate = true
  cc.serverName = name
  cc.alpn = @["http/1.1"]
  cc.nowUnix = testNow
  cc.x25519Seed = newSeq[byte](32)
  while i < cc.x25519Seed.len:
    cc.x25519Seed[i] = byte(i + 1)
    i = i + 1
  client = initTls13ClientSession(cc)
  so = server.feedTls13Server(client.startTls13Client())
  co = client.feedTls13Client(joinAll(so.outbound))
  if not co.connected:
    return wNobody
  result = whichOf(client.peerCertificate.publicKey)

suite "TLS 1.3 server identities":
  # {.testKind: tkIntegration, covers: "initTls13ServerSession|pickIdentity".}
  test "each name gets the certificate whose list holds it":
    var
      sc: Tls13ServerConfig = serverConfig()
    check sc.shownFor("beta.example") == wBeta
    check sc.shownFor("www.beta.example") == wBeta
    check sc.shownFor("x.wild.example") == wWild
    check sc.shownFor("alpha.example") == wAlpha

  # {.testKind: tkEdgeCase, covers: "pickIdentity".}
  test "an unknown name, no name, or two labels under a wildcard get the default":
    var
      sc: Tls13ServerConfig = serverConfig()
    check sc.shownFor("unknown.net") == wAlpha
    check sc.shownFor("") == wAlpha
    check sc.shownFor("a.b.wild.example") == wAlpha
    check sc.shownFor("wild.example") == wAlpha

  # {.testKind: tkEdgeCase, covers: "pickIdentity".}
  test "capital letters in the name do not matter":
    var
      sc: Tls13ServerConfig = serverConfig()
    check sc.shownFor("BETA.Example") == wBeta
    check sc.shownFor("X.WILD.example") == wWild

  # {.testKind: tkEdgeCase, covers: "pickIdentity".}
  test "when two identities answer to a name, the first in the list wins":
    var
      b: Tls13ServerIdentity = identityOf(betaCert, betaKey, @["x.wild.example"])
      w: Tls13ServerIdentity = identityOf(wildCert, wildKey, @["*.wild.example"])
    check serverConfig(@[b, w]).shownFor("x.wild.example") == wBeta
    check serverConfig(@[w, b]).shownFor("x.wild.example") == wWild

  # {.testKind: tkEdgeCase, covers: "initTls13ServerSession".}
  test "a server with no named identity behaves as before":
    var
      sc: Tls13ServerConfig = serverConfig()
    sc.identities = @[]
    check sc.shownFor("beta.example") == wAlpha
    check sc.shownFor("") == wAlpha

  # {.testKind: tkEdgeCase, covers: "readyIdentity".}
  test "a key that does not belong to its certificate is refused at start":
    var
      sc: Tls13ServerConfig = serverConfig()
      session: Tls13ServerSession = default(Tls13ServerSession)
    sc.identities = @[identityOf(betaCert, wildKey, @["beta.example"])]
    expect ValueError:
      session = initTls13ServerSession(sc)

  # {.testKind: tkEdgeCase, covers: "readyIdentity".}
  test "an empty name, a name with a space, and 512 identities are refused":
    var
      sc: Tls13ServerConfig = serverConfig()
      session: Tls13ServerSession = default(Tls13ServerSession)
      i: int = 0
    sc.identities = @[identityOf(betaCert, betaKey, @[""])]
    expect ValueError:
      session = initTls13ServerSession(sc)
    sc.identities = @[identityOf(betaCert, betaKey, @["a b.example"])]
    expect ValueError:
      session = initTls13ServerSession(sc)
    sc.identities = @[]
    while i < 512:
      sc.identities.add(identityOf(betaCert, betaKey, @["beta.example"]))
      i = i + 1
    expect ValueError:
      session = initTls13ServerSession(sc)
