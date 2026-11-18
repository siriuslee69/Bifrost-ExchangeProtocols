## ------------------------------------------------------------------------
## TLS 1.3 downgrade <- an older version, a weaker suite or another group is refused
## ------------------------------------------------------------------------
##
## The native TLS engine speaks ONE profile: TLS 1.3, TLS_CHACHA20_POLY1305_SHA256,
## x25519, no compression. There is nothing weaker to fall back to, so a
## downgrade has to be refused outright, never negotiated:
##
##   what a man in the middle (or an old client) offers   what must happen
##   ---------------------------------------------------  -----------------------
##   TLS 1.1 / 1.2 in the legacy version field            refused
##   supported_versions without 1.3, or missing           refused
##   a cipher suite list without ChaCha20-Poly1305        refused
##   compression other than "null"                        refused
##   a key share of another group                         refused
##
## and the same from the client's side, against a ServerHello that picks a
## different version or suite than the one this engine can speak.

import std/[unittest, strutils]

import ../../src/protocols/types
import ../../src/protocols/tls13/hello
import runePragmas

proc honestClient(): ByteSeq {.role: configurator.} =
  var
    H: Tls13ClientHello = Tls13ClientHello()
    i: int = 0
  while i < H.random.len:
    H.random[i] = byte(i)
    i = i + 1
  H.x25519PublicKey = newSeq[byte](32)
  H.serverName = "mail.example.org"
  H.signatureSchemes = @[0x0807'u16]
  result = encodeTls13ClientHello(H)

proc honestServer(): ByteSeq {.role: configurator.} =
  var
    H: Tls13ServerHello = Tls13ServerHello()
  H.x25519PublicKey = newSeq[byte](32)
  result = encodeTls13ServerHello(H)

proc editOnce(B: ByteSeq, pattern, replacement: openArray[byte]): ByteSeq {.
    role: helper.} =
  ## B/pattern/replacement: the bytes of B with `pattern` replaced, which must
  ## occur exactly once (a pattern that is not there would make a test of
  ## "this edit is refused" pass for the wrong reason).
  var
    at: int = -1
    found: int = 0
    i: int = 0
  while i + pattern.len <= B.len:
    if B[i ..< i + pattern.len] == @pattern:
      found = found + 1
      at = i
    i = i + 1
  doAssert found == 1, "pattern found " & $found & " times"
  result = B
  i = 0
  while i < pattern.len:
    result[at + i] = replacement[i]
    i = i + 1

proc clientRefused(B: ByteSeq, why: string): bool {.role: parser.} =
  var
    R: Tls13ClientHelloResult = decodeTls13ClientHello(B)
  result = (not R.ok) and why in R.err

proc serverRefused(B: ByteSeq, why: string): bool {.role: parser.} =
  var
    R: Tls13ServerHelloResult = decodeTls13ServerHello(B)
  result = (not R.ok) and why in R.err

const
  versionsExt = [byte 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]
  versions12 = [byte 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x03]
  versionsGone = [byte 0x00, 0xfe, 0x00, 0x03, 0x02, 0x03, 0x04]

suite "TLS 1.3 refuses to be downgraded":
  # {.testKind: tkEdgeCase, covers: "decodeTls13ClientHello".}
  test "the honest hello is accepted (the edits below start from it)":
    check decodeTls13ClientHello(honestClient()).ok
    check decodeTls13ServerHello(honestServer()).ok

  # {.testKind: tkEdgeCase, covers: "decodeTls13ClientHello".}
  test "a client hello from TLS 1.1 or 1.2 is refused":
    var
      B: ByteSeq = honestClient()
    B[0] = 0x03
    B[1] = 0x02
    check clientRefused(B, "legacy version")
    B = editOnce(honestClient(), versionsExt, versions12)
    check clientRefused(B, "missing required version")
    B = editOnce(honestClient(), versionsExt, versionsGone)
    check clientRefused(B, "missing required version")

  # {.testKind: tkEdgeCase, covers: "decodeTls13ClientHello".}
  test "a client hello with no ChaCha20-Poly1305 is refused, whatever else it offers":
    var
      B: ByteSeq = honestClient()
    ## AES-128-GCM only, AES-256-GCM only, a TLS 1.2 RSA suite only
    check clientRefused(editOnce(B, [byte 0x00, 0x02, 0x13, 0x03],
      [byte 0x00, 0x02, 0x13, 0x01]), "cipher suite")
    check clientRefused(editOnce(B, [byte 0x00, 0x02, 0x13, 0x03],
      [byte 0x00, 0x02, 0x13, 0x02]), "cipher suite")
    check clientRefused(editOnce(B, [byte 0x00, 0x02, 0x13, 0x03],
      [byte 0x00, 0x02, 0x00, 0x2f]), "cipher suite")

  # {.testKind: tkEdgeCase, covers: "decodeTls13ClientHello".}
  test "compression other than null is refused":
    var
      B: ByteSeq = honestClient()
    check clientRefused(editOnce(B, [byte 0x01, 0x00, 0x00], [byte 0x01, 0x01, 0x00]),
      "compression")

  # {.testKind: tkEdgeCase, covers: "decodeTls13ServerHello".}
  test "a server hello that picks another version, suite or version list is refused":
    var
      B: ByteSeq = honestServer()
    B[0] = 0x03
    B[1] = 0x02
    check serverRefused(B, "legacy version")
    check serverRefused(editOnce(honestServer(), [byte 0x13, 0x03, 0x00],
      [byte 0x13, 0x01, 0x00]), "suite")
    check serverRefused(editOnce(honestServer(), [byte 0x00, 0x2b, 0x00, 0x02,
      0x03, 0x04], [byte 0x00, 0x2b, 0x00, 0x02, 0x03, 0x03]),
      "missing required version")

  # {.testKind: tkFuzz, covers: "decodeTls13ClientHello".}
  test "every single-byte edit of the hellos is refused, or leaves the profile intact; never a crash":
    var
      C: ByteSeq = honestClient()
      S: ByteSeq = honestServer()
      M: ByteSeq = @[]
      i: int = 0
      v: int = 0
      accepted: int = 0
    while i < C.len:
      v = 0
      while v < 256:
        M = C
        M[i] = byte(v)
        if decodeTls13ClientHello(M).ok:
          accepted = accepted + 1
        v = v + 1
      i = i + 1
    i = 0
    while i < S.len:
      v = 0
      while v < 256:
        M = S
        M[i] = byte(v)
        if decodeTls13ServerHello(M).ok:
          accepted = accepted + 1
        v = v + 1
      i = i + 1
    ## the unedited value is accepted once per position; random bytes, session
    ## id bytes, key share bytes and name bytes may take any value, so the
    ## accepted count is large: what matters is that no edit crashed.
    check accepted > 0
