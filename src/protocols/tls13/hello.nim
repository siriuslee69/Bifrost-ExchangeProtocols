## ----------------------------------------------------------------------
## TLS 1.3 Hello <- narrow interoperable ClientHello and ServerHello codec
## ----------------------------------------------------------------------

import std/strutils

import ../types
import ./codec
import runePragmas

const
  tls13Version* = 0x0304'u16
  tls13LegacyHelloVersion* = 0x0303'u16
  tls13SuiteChaCha20Poly1305Sha256* = 0x1303'u16
  tls13GroupX25519* = 0x001d'u16
  tls13SignatureEd25519* = 0x0807'u16
  tls13SignatureRsaPssRsaeSha256* = 0x0804'u16
  tls13SignatureEcdsaSecp256r1Sha256* = 0x0403'u16
  tls13SupportedSignatureSchemes* = [
    tls13SignatureEd25519, tls13SignatureRsaPssRsaeSha256,
    tls13SignatureEcdsaSecp256r1Sha256
  ] ## schemes this profile can produce and verify, in preference order
  extServerName = 0'u16
  extSupportedGroups = 10'u16
  extSignatureAlgorithms = 13'u16
  extAlpn = 16'u16
  extSupportedVersions = 43'u16
  extKeyShare = 51'u16

type
  Tls13ClientHello* {.role: truthState, tag: "tls|packet".} = object
    random*: array[32, byte]
    legacySessionId*: ByteSeq
    serverName*: string
    alpn*: seq[string]
    x25519PublicKey*: ByteSeq
    signatureSchemes*: seq[uint16] # schemes the client offered, in its order

  Tls13ServerHello* {.role: truthState, tag: "tls|packet".} = object
    random*: array[32, byte]
    legacySessionId*: ByteSeq
    x25519PublicKey*: ByteSeq

  Tls13ClientHelloResult* {.role: truthState, tag: "tls|parsing".} = object
    ok*: bool
    hello*: Tls13ClientHello
    err*: string

  Tls13ServerHelloResult* {.role: truthState, tag: "tls|parsing".} = object
    ok*: bool
    hello*: Tls13ServerHello
    err*: string

proc addU16(A: var ByteSeq, v: uint16) {.role: dataWriter,
    tag: "tls|write".} =
  A.add(byte(v shr 8))
  A.add(byte(v))

proc readU16(A: openArray[byte], o: int, v: var uint16): bool {.role: parser,
    tag: "tls|read".} =
  if o < 0 or o > A.len - 2:
    return false
  v = (uint16(A[o]) shl 8) or uint16(A[o + 1])
  result = true

proc addVector16(A: var ByteSeq, B: openArray[byte]) {.
    role: dataWriter, tag: "tls|write".} =
  if B.len > 65535:
    raise newException(ValueError, "TLS vector exceeds uint16 length")
  addU16(A, uint16(B.len))
  A.add(B)

proc addExtension(A: var ByteSeq, kind: uint16, B: openArray[byte]) {.
    role: dataWriter, tag: "tls|write".} =
  addU16(A, kind)
  addVector16(A, B)

proc addAscii(A: var ByteSeq, s: string) {.role: dataWriter,
    tag: "tls|write".} =
  var i: int = 0
  while i < s.len:
    A.add(byte(ord(s[i])))
    i = i + 1

proc validHelloHost(s: string): bool {.role: parser,
    tag: "tls|validation".} =
  var i: int = 0
  if s.len == 0 or s.len > 253:
    return false
  while i < s.len:
    if not ((s[i] >= 'a' and s[i] <= 'z') or (s[i] >= 'A' and s[i] <= 'Z') or
        (s[i] >= '0' and s[i] <= '9') or s[i] in {'.', '-'}):
      return false
    i = i + 1
  result = true

proc collectVectorU16(A: openArray[byte], start, n: int): seq[uint16] {.
    role: parser, tag: "tls|read".} =
  ## A/start/n: source bytes, vector body offset, and vector byte length.
  ## Returns the decoded u16 list, or an empty list when the vector is
  ## malformed, so callers fail closed.
  var
    o: int = start
    v: uint16 = 0
  if n < 0 or (n mod 2) != 0 or start < 0 or start > A.len or n > A.len - start:
    return @[]
  while o < start + n:
    if not readU16(A, o, v):
      return @[]
    result.add(v)
    o = o + 2

proc anySupportedScheme(offered: openArray[uint16]): bool {.role: parser,
    tag: "tls|validation".} =
  ## offered: signature schemes advertised by the peer.
  var i, j: int = 0
  while i < offered.len:
    j = 0
    while j < tls13SupportedSignatureSchemes.len:
      if offered[i] == tls13SupportedSignatureSchemes[j]:
        return true
      j = j + 1
    i = i + 1

proc vectorContainsU16(A: openArray[byte], start, n: int,
    wanted: uint16): bool {.role: parser, tag: "tls|read".} =
  var
    o: int = start
    v: uint16 = 0
  if n < 0 or (n mod 2) != 0 or start < 0 or start > A.len or n > A.len - start:
    return false
  while o < start + n:
    if not readU16(A, o, v):
      return false
    if v == wanted:
      return true
    o = o + 2

proc parseClientKeyShares(A: openArray[byte], start, finish: int,
    key: var ByteSeq): string {.role: parser,
    tag: "tls|read|validation".} =
  var
    o: int = start
    group, n: uint16 = 0
  while o < finish:
    if not readU16(A, o, group) or not readU16(A, o + 2, n) or
        o + 4 + int(n) > finish:
      return "TLS client key_share entry is invalid"
    if group == tls13GroupX25519:
      if key.len > 0:
        return "TLS X25519 key_share is duplicated"
      if n != 32:
        return "TLS X25519 key_share is invalid"
      key = @A[o + 4 ..< o + 4 + int(n)]
    o = o + 4 + int(n)
  if o != finish or key.len != 32:
    return "TLS ClientHello has no usable X25519 key_share"
  result = ""

proc buildClientExtensions(H: Tls13ClientHello): ByteSeq {.
    role: truthBuilder, tag: "tls|write".} =
  var
    E, V, N: ByteSeq = @[]
    i: int = 0
  V = @[byte 2, 0x03, 0x04]
  addExtension(E, extSupportedVersions, V)
  V = @[]
  addU16(V, 2'u16)
  addU16(V, tls13GroupX25519)
  addExtension(E, extSupportedGroups, V)
  V = @[]
  addU16(V, uint16(2 * tls13SupportedSignatureSchemes.len))
  i = 0
  while i < tls13SupportedSignatureSchemes.len:
    addU16(V, tls13SupportedSignatureSchemes[i])
    i = i + 1
  addExtension(E, extSignatureAlgorithms, V)
  if H.serverName.len > 0:
    if not validHelloHost(H.serverName):
      raise newException(ValueError, "TLS SNI hostname is invalid")
    N = @[byte 0]
    addU16(N, uint16(H.serverName.len))
    addAscii(N, H.serverName.toLowerAscii())
    V = @[]
    addVector16(V, N)
    addExtension(E, extServerName, V)
  if H.alpn.len > 0:
    N = @[]
    i = 0
    while i < H.alpn.len:
      if H.alpn[i].len == 0 or H.alpn[i].len > 255:
        raise newException(ValueError, "TLS ALPN identifier length is invalid")
      N.add(byte(H.alpn[i].len))
      addAscii(N, H.alpn[i])
      i = i + 1
    V = @[]
    addVector16(V, N)
    addExtension(E, extAlpn, V)
  if H.x25519PublicKey.len != 32:
    raise newException(ValueError, "TLS X25519 ClientHello key share must be 32 bytes")
  N = @[]
  addU16(N, tls13GroupX25519)
  addVector16(N, H.x25519PublicKey)
  V = @[]
  addVector16(V, N)
  addExtension(E, extKeyShare, V)
  result = E

proc encodeTls13ClientHello*(H: Tls13ClientHello): ByteSeq {.role: dataWriter,
    tag: "tls|write|packet".} =
  ## H: narrow TLS 1.3 client hello profile.
  var
    E: ByteSeq = buildClientExtensions(H)
    i: int = 0
  if H.legacySessionId.len > 32:
    raise newException(ValueError, "TLS legacy session id exceeds 32 bytes")
  addU16(result, tls13LegacyHelloVersion)
  while i < H.random.len:
    result.add(H.random[i])
    i = i + 1
  result.add(byte(H.legacySessionId.len))
  result.add(H.legacySessionId)
  addU16(result, 2'u16)
  addU16(result, tls13SuiteChaCha20Poly1305Sha256)
  result.add(1'u8)
  result.add(0'u8)
  addVector16(result, E)

proc buildServerExtensions(H: Tls13ServerHello): ByteSeq {.
    role: truthBuilder, tag: "tls|write".} =
  var V: ByteSeq = @[byte 0x03, 0x04]
  addExtension(result, extSupportedVersions, V)
  if H.x25519PublicKey.len != 32:
    raise newException(ValueError, "TLS X25519 ServerHello key share must be 32 bytes")
  V = @[]
  addU16(V, tls13GroupX25519)
  addVector16(V, H.x25519PublicKey)
  addExtension(result, extKeyShare, V)

proc encodeTls13ServerHello*(H: Tls13ServerHello): ByteSeq {.role: dataWriter,
    tag: "tls|write|packet".} =
  ## H: narrow TLS 1.3 server hello profile.
  var
    E: ByteSeq = buildServerExtensions(H)
    i: int = 0
  if H.legacySessionId.len > 32:
    raise newException(ValueError, "TLS legacy session id exceeds 32 bytes")
  addU16(result, tls13LegacyHelloVersion)
  while i < H.random.len:
    result.add(H.random[i])
    i = i + 1
  result.add(byte(H.legacySessionId.len))
  result.add(H.legacySessionId)
  addU16(result, tls13SuiteChaCha20Poly1305Sha256)
  result.add(0'u8)
  addVector16(result, E)

## ╭⟢ one extension at a time
##
## The extension walk used to hold every extension's parsing inside one
## `case` inside the loop, which put the innermost checks four and five
## deep. Each extension is now its own step, returning the error string it
## would have returned in place -- empty meaning "this one was fine".

proc readHelloText(A: openArray[byte], at, n: int): string {.inline,
    role: parser, tag: "tls|read".} =
  ## A/at/n: `n` bytes read out as text. Used for the two extensions that
  ## carry names rather than numbers.
  var
    i: int = 0
  result = newString(n)
  while i < n:
    result[i] = char(A[at + i])
    i = i + 1

proc parseVersionsExt(A: openArray[byte], dataStart: int, n: uint16,
    server: bool, versionOk: var bool): string {.inline, role: parser,
    tag: "tls|read|validation".} =
  ## A/dataStart/n/server/versionOk: the one extension that says TLS 1.3.
  var
    x: uint16 = 0
    vectorLen: int = 0
  if server:
    versionOk = n == 2 and readU16(A, dataStart, x) and x == tls13Version
    return
  vectorLen = if n > 0: int(A[dataStart]) else: -1
  versionOk = vectorLen >= 2 and vectorLen + 1 == int(n) and
    vectorContainsU16(A, dataStart + 1, vectorLen, tls13Version)

proc parseKeyShareExt(A: openArray[byte], dataStart, dataEnd: int,
    server: bool, key: var ByteSeq): string {.inline, role: parser,
    tag: "tls|read|validation".} =
  ## A/dataStart/dataEnd/server/key: the peer's X25519 share.
  var
    x, n: uint16 = 0
  if not server:
    if not readU16(A, dataStart, x) or dataStart + 2 + int(x) != dataEnd:
      return "TLS client key_share vector is invalid"
    return parseClientKeyShares(A, dataStart + 2, dataEnd, key)
  if not readU16(A, dataStart, x) or x != tls13GroupX25519 or
      not readU16(A, dataStart + 2, n) or n != 32 or dataStart + 4 + 32 != dataEnd:
    return "TLS X25519 key_share is invalid"
  key = @A[dataStart + 4 ..< dataEnd]

proc parseGroupsExt(A: openArray[byte], dataStart: int,
    n: uint16): string {.inline, role: parser,
    tag: "tls|read|validation".} =
  ## A/dataStart/n: the group list must name the one group this profile has.
  var
    x: uint16 = 0
  if not readU16(A, dataStart, x) or int(x) != int(n) - 2 or
      not vectorContainsU16(A, dataStart + 2, int(x), tls13GroupX25519):
    return "TLS supported_groups does not contain the controlled X25519 profile"

proc parseSignaturesExt(A: openArray[byte], dataStart: int, n: uint16,
    sigSchemes: var seq[uint16]): string {.inline, role: parser,
    tag: "tls|read|validation".} =
  ## A/dataStart/n/sigSchemes: the signature schemes the peer will accept.
  var
    x: uint16 = 0
    schemes: seq[uint16] = @[]
  if not readU16(A, dataStart, x) or int(x) != int(n) - 2:
    return "TLS signature_algorithms extension is malformed"
  schemes = collectVectorU16(A, dataStart + 2, int(x))
  if schemes.len == 0:
    return "TLS signature_algorithms list is empty"
  if not anySupportedScheme(schemes):
    return "TLS signature_algorithms offers no scheme this profile supports"
  sigSchemes = schemes

proc parseSniExt(A: openArray[byte], dataStart, dataEnd: int,
    serverName: var string): string {.inline, role: parser,
    tag: "tls|read|validation".} =
  ## A/dataStart/dataEnd/serverName: exactly one host name, and only the
  ## host_name type. A second entry or another type is refused rather than
  ## skipped, so two names can never disagree about who is being asked for.
  var
    x, n: uint16 = 0
    nameLen: int = 0
    name: string = ""
  if not readU16(A, dataStart, x):
    return "TLS SNI list is incomplete"
  if dataStart + 2 + int(x) != dataEnd or dataStart + 5 > dataEnd or
      A[dataStart + 2] != 0'u8 or not readU16(A, dataStart + 3, n):
    return "TLS SNI entry is invalid"
  nameLen = int(n)
  if dataStart + 5 + nameLen != dataEnd:
    return "TLS SNI hostname length is invalid"
  name = readHelloText(A, dataStart + 5, nameLen)
  if not validHelloHost(name):
    return "TLS SNI hostname is invalid"
  serverName = name.toLowerAscii()

proc parseAlpnExt(A: openArray[byte], dataStart, dataEnd: int,
    alpn: var seq[string]): string {.inline, role: parser,
    tag: "tls|read|validation".} =
  ## A/dataStart/dataEnd/alpn: the protocol names the peer offers, in order.
  var
    x: uint16 = 0
    p: int = 0
    nameLen: int = 0
  if not readU16(A, dataStart, x) or dataStart + 2 + int(x) != dataEnd:
    return "TLS ALPN list length is invalid"
  p = dataStart + 2
  while p < dataEnd:
    nameLen = int(A[p])
    p = p + 1
    if nameLen == 0 or p + nameLen > dataEnd:
      return "TLS ALPN identifier is invalid"
    alpn.add(readHelloText(A, p, nameLen))
    p = p + nameLen

proc parseExtensions(A: openArray[byte], start, finish: int,
    server: bool, key: var ByteSeq, versionOk: var bool,
    serverName: var string, alpn: var seq[string],
    sigSchemes: var seq[uint16]): string {.role: parser,
    tag: "tls|read|validation".} =
  ## A/start/finish/server: the extension vector and which side sent it.
  ## key/versionOk/serverName/alpn/sigSchemes: what the walk fills in.
  var
    o: int = start
    dataStart, dataEnd: int = 0
    kind, n: uint16 = 0
    seenVersion, seenKey, seenSni, seenAlpn: bool = false
    seenGroups, seenSignatures: bool = false
    seenKinds: seq[uint16] = @[]
  while o < finish:
    if not readU16(A, o, kind) or not readU16(A, o + 2, n):
      return "TLS extension header is incomplete"
    dataStart = o + 4
    dataEnd = dataStart + int(n)
    if dataEnd > finish:
      return "TLS extension exceeds extension vector"
    ## Every extension may appear once. A repeat is refused rather than
    ## letting the last copy win, which is how a peer would otherwise hide
    ## one value behind another.
    if kind in seenKinds:
      return "TLS extension is duplicated"
    seenKinds.add(kind)
    case kind
    of extSupportedVersions:
      seenVersion = true
      result = parseVersionsExt(A, dataStart, n, server, versionOk)
    of extKeyShare:
      seenKey = true
      result = parseKeyShareExt(A, dataStart, dataEnd, server, key)
    of extSupportedGroups:
      if server:
        return "TLS supported_groups extension is invalid or duplicated"
      seenGroups = true
      result = parseGroupsExt(A, dataStart, n)
    of extSignatureAlgorithms:
      if server:
        return "TLS signature_algorithms extension is invalid or duplicated"
      seenSignatures = true
      result = parseSignaturesExt(A, dataStart, n, sigSchemes)
    of extServerName:
      if server:
        return "TLS server_name extension is invalid or duplicated"
      seenSni = true
      result = parseSniExt(A, dataStart, dataEnd, serverName)
    of extAlpn:
      if server:
        return "TLS ALPN extension is invalid or duplicated"
      seenAlpn = true
      result = parseAlpnExt(A, dataStart, dataEnd, alpn)
    else:
      discard
    if result.len > 0:
      return
    o = dataEnd
  discard seenSni
  discard seenAlpn
  if not seenVersion or not versionOk or not seenKey:
    return "TLS hello is missing required version or key share"
  if not server and (not seenGroups or not seenSignatures):
    return "TLS ClientHello is missing required groups or signature algorithms"
  result = ""

proc decodeTls13ClientHello*(A: openArray[byte]): Tls13ClientHelloResult {.
    role: parser, tag: "tls|read|validation".} =
  ## A: ClientHello body without handshake header.
  var
    o, sidLen, suitesLen, compLen, extLen, i: int = 0
    v: uint16 = 0
    versionOk: bool = false
  if A.len < 42 or not readU16(A, 0, v) or v != tls13LegacyHelloVersion:
    result.err = "TLS ClientHello legacy version or length is invalid"
    return
  o = 2
  while i < 32:
    result.hello.random[i] = A[o + i]
    i = i + 1
  o = o + 32
  sidLen = int(A[o])
  o = o + 1
  if sidLen > 32 or o + sidLen + 2 > A.len:
    result.err = "TLS ClientHello session id is invalid"
    return
  result.hello.legacySessionId = @A[o ..< o + sidLen]
  o = o + sidLen
  if not readU16(A, o, v):
    result.err = "TLS ClientHello cipher suites are incomplete"
    return
  suitesLen = int(v)
  o = o + 2
  if suitesLen < 2 or (suitesLen mod 2) != 0 or o + suitesLen + 1 > A.len or
      not vectorContainsU16(A, o, suitesLen,
      tls13SuiteChaCha20Poly1305Sha256):
    result.err = "TLS ClientHello cipher suite is unsupported"
    return
  o = o + suitesLen
  compLen = int(A[o])
  o = o + 1
  if compLen < 1 or o + compLen + 2 > A.len or
      not validateTls13LegacyCompression(A.toOpenArray(o, o + compLen - 1)):
    result.err = "TLS ClientHello must offer null legacy compression"
    return
  o = o + compLen
  if not readU16(A, o, v):
    result.err = "TLS ClientHello extensions are incomplete"
    return
  extLen = int(v)
  o = o + 2
  if o + extLen != A.len:
    result.err = "TLS ClientHello extension length is invalid"
    return
  result.err = parseExtensions(A, o, A.len, false,
    result.hello.x25519PublicKey, versionOk, result.hello.serverName,
    result.hello.alpn, result.hello.signatureSchemes)
  result.ok = result.err.len == 0

proc decodeTls13ServerHello*(A: openArray[byte]): Tls13ServerHelloResult {.
    role: parser, tag: "tls|read|validation".} =
  ## A: ServerHello body without handshake header.
  var
    o, sidLen, extLen, i: int = 0
    v: uint16 = 0
    versionOk: bool = false
    ignoredName: string = ""
    ignoredAlpn: seq[string] = @[]
    ignoredSchemes: seq[uint16] = @[]
  if A.len < 40 or not readU16(A, 0, v) or v != tls13LegacyHelloVersion:
    result.err = "TLS ServerHello legacy version or length is invalid"
    return
  o = 2
  while i < 32:
    result.hello.random[i] = A[o + i]
    i = i + 1
  o = o + 32
  sidLen = int(A[o])
  o = o + 1
  if sidLen > 32 or o + sidLen + 5 > A.len:
    result.err = "TLS ServerHello session id is invalid"
    return
  result.hello.legacySessionId = @A[o ..< o + sidLen]
  o = o + sidLen
  if not readU16(A, o, v) or v != tls13SuiteChaCha20Poly1305Sha256 or
      A[o + 2] != 0'u8 or not readU16(A, o + 3, v):
    result.err = "TLS ServerHello suite or legacy compression is invalid"
    return
  extLen = int(v)
  o = o + 5
  if o + extLen != A.len:
    result.err = "TLS ServerHello extension length is invalid"
    return
  result.err = parseExtensions(A, o, A.len, true,
    result.hello.x25519PublicKey, versionOk, ignoredName, ignoredAlpn,
    ignoredSchemes)
  result.ok = result.err.len == 0
