## -------------------------------------------------------------------------
## Server config from PEM <- the text a CA hands out becomes a server config
## -------------------------------------------------------------------------
##
## The fixtures are DER files (evaluation/tests/fixtures/webpki). Each test
## wraps them in PEM armour first, the way a CA's files look, then asks
## `tls13ServerConfigFromPem` for a config.

import std/[base64, strutils, unittest]

import ../../src/protocols/types
import ../../src/protocols/tls13
import ../../src/protocols/tls13/server_config_pem
import runePragmas

const
  fixtures = "evaluation/tests/fixtures/webpki/"
  ed25519Certificate = """-----BEGIN CERTIFICATE-----
MIIBPDCB76ADAgECAhQkqENccCvOQyI4iKFuuOKwl860bTAFBgMrZXAwFDESMBAG
A1UEAwwJbG9jYWxob3N0MB4XDTIxMDcyNjE0MjcwN1oXDTIxMDgyNTE0MjcwN1ow
FDESMBAGA1UEAwwJbG9jYWxob3N0MCowBQYDK2VwAyEA1KMGmAZealfgakBuCx/E
n69fo072qm90eM40ulGex0ajUzBRMB0GA1UdDgQWBBTHKWv5l/SxnkkYJhh5r3Pv
ESAh1DAfBgNVHSMEGDAWgBTHKWv5l/SxnkkYJhh5r3PvESAh1DAPBgNVHRMBAf8E
BTADAQH/MAUGAytlcANBAF/vSBfOHAdRl29sWDTkuqy1dCuSf7j7jKE/Be8Fk7xs
WteXJmIa0HlRAZjxNfWbsSGLnTYbsGTbxKx3QU9H9g0=
-----END CERTIFICATE-----"""
  ed25519Key = """-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAjtEwCECqbot5RZxSmiNDWcPp+Xc9Y9WJcUhti3JgSP
-----END PRIVATE KEY-----"""

proc fileBytes(name: string): ByteSeq {.role: dataFetcher.} =
  ## name: a fixture file as bytes.
  var
    s: string = readFile(fixtures & name)
  for c in s:
    result.add(byte(c))

proc armour(label: string, A: openArray[byte]): string {.role: helper.} =
  ## label/A: the bytes as a PEM block, 64 characters to a line.
  var
    raw: string = newString(A.len)
    b64: string = ""
    i: int = 0
  while i < A.len:
    raw[i] = char(A[i])
    i = i + 1
  b64 = encode(raw)
  result = "-----BEGIN " & label & "-----\n"
  i = 0
  while i < b64.len:
    result.add(b64[i ..< min(i + 64, b64.len)] & "\n")
    i = i + 64
  result.add("-----END " & label & "-----\n")

proc scalarOfEc(): ByteSeq {.role: dataFetcher.} =
  ## the P-256 secret scalar of the EC fixture (hex file -> 32 bytes).
  var
    t: string = readFile(fixtures & "eleaf.scalar.hex").strip()
    i: int = 0
  while i + 1 < t.len:
    result.add(byte(parseHexInt(t[i .. i + 1])))
    i = i + 2

proc sec1Of(scalar: ByteSeq): ByteSeq {.role: helper.} =
  ## scalar: a minimal SEC1 ECPrivateKey: SEQUENCE { 1, OCTET STRING scalar }.
  result = @[0x30'u8, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20]
  result.add(scalar)

proc pkcs8Of(scalar: ByteSeq): ByteSeq {.role: helper.} =
  ## scalar: the same key wrapped as PKCS#8 (algorithm: P-256).
  var
    inner: ByteSeq = sec1Of(scalar)
  result = @[0x30'u8, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x04, 0x27]
  result.add(inner)

suite "TLS server config from PEM":
  # {.testKind: tkUnit, covers: "tls13ServerConfigFromPem".}
  test "an Ed25519 certificate and key":
    var
      got = tls13ServerConfigFromPem(ed25519Certificate, ed25519Key)
    check got.ok
    check got.cfg.certificateChainDer.len == 1
    check got.cfg.ed25519SecretKey.len == 64

  # {.testKind: tkUnit, covers: "tls13ServerConfigFromPem".}
  test "an RSA certificate with its key, as PKCS#8 and as PKCS#1 text":
    var
      cert: string = armour("CERTIFICATE", fileBytes("rleaf.der"))
      key: ByteSeq = fileBytes("rleaf.pk8")
    check tls13ServerConfigFromPem(cert, armour("PRIVATE KEY", key)).ok
    ## the same bytes under the other label: the session reads either form
    check tls13ServerConfigFromPem(cert, armour("RSA PRIVATE KEY", key)).ok

  # {.testKind: tkUnit, covers: "tls13ServerConfigFromPem".}
  test "a P-256 certificate with its key, as PKCS#8 and as SEC1 text":
    var
      cert: string = armour("CERTIFICATE", fileBytes("eleaf.der"))
      got = tls13ServerConfigFromPem(cert, armour("PRIVATE KEY",
        pkcs8Of(scalarOfEc())))
    check got.ok
    check got.cfg.ecdsaPrivateScalar == scalarOfEc()
    got = tls13ServerConfigFromPem(cert, armour("EC PRIVATE KEY",
      sec1Of(scalarOfEc())))
    check got.ok

  # {.testKind: tkUnit, covers: "tls13ServerConfigFromPem".}
  test "a chain keeps every certificate, in order":
    var
      chain: string = armour("CERTIFICATE", fileBytes("rleaf.der")) & "\n" &
        armour("CERTIFICATE", fileBytes("rroot.der"))
      got = tls13ServerConfigFromPem(chain, armour("PRIVATE KEY",
        fileBytes("rleaf.pk8")))
    check got.ok
    check got.cfg.certificateChainDer.len == 2
    check got.cfg.certificateChainDer[0] == fileBytes("rleaf.der")
    check got.cfg.certificateChainDer[1] == fileBytes("rroot.der")

  # {.testKind: tkEdgeCase, covers: "tls13ServerConfigFromPem".}
  test "what cannot be used is refused with a reason, never raised":
    var
      cert: string = armour("CERTIFICATE", fileBytes("rleaf.der"))
      many: string = ""
      i: int = 0
      got = tls13ServerConfigFromPem(cert, ed25519Key)
    ## a key that belongs to another certificate
    check not got.ok
    check got.err.len > 0
    ## a key with a password
    got = tls13ServerConfigFromPem(cert, armour("ENCRYPTED PRIVATE KEY",
      fileBytes("rleaf.pk8")))
    check not got.ok
    check "password" in got.err
    ## no certificate, text that is no PEM, a certificate block that is no certificate
    check not tls13ServerConfigFromPem("", ed25519Key).ok
    check not tls13ServerConfigFromPem("hello", ed25519Key).ok
    check not tls13ServerConfigFromPem(ed25519Certificate, "hello").ok
    check not tls13ServerConfigFromPem(armour("CERTIFICATE", @[byte 1, 2, 3]),
      ed25519Key).ok
    ## a certificate block with no end line
    check not tls13ServerConfigFromPem("-----BEGIN CERTIFICATE-----\nAAAA\n",
      ed25519Key).ok
    ## too long a chain
    while i < tlsMaxChainCertificates + 1:
      many.add(armour("CERTIFICATE", fileBytes("rleaf.der")))
      i = i + 1
    got = tls13ServerConfigFromPem(many, armour("PRIVATE KEY", fileBytes("rleaf.pk8")))
    check not got.ok
    check "more than" in got.err
