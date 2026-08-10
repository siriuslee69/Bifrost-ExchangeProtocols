## -------------------------------------------------------------------------
## AME Handshake Wire <- strict certificate and initial-handshake codecs
## -------------------------------------------------------------------------

from ../../types import ByteSeq
import ../types
import ./handshake
import ../level0/bytes
import ../level1/exchange_paths
import ../level1/suites
import ../../../analysis_pragmas

const
  ameHandshakeWireVersion = 3'u16
  ameIdentityMagic = [uint8('A'), uint8('M'), uint8('I'), uint8('1')]
  ameClientHelloMagic = [uint8('A'), uint8('M'), uint8('C'), uint8('1')]
  ameServerHelloMagic = [uint8('A'), uint8('M'), uint8('S'), uint8('1')]
  ameClientFinishMagic = [uint8('A'), uint8('M'), uint8('F'), uint8('1')]
  ameHandshakeTextMax = 4096'u32
  ameHandshakeFieldMax = 16_777_216'u32
  ameIdentityKeyMax = 1_048_576'u32
  ameSignatureProofMax = 1_048_576'u32

proc requireHandshakeBytes(A: openArray[uint8], cursor, count: int) {.
    role: parser, tag: {tagParsing, tagValidation}.} =
  ## A/cursor/count: bounded source window required by a handshake decoder.
  if cursor < 0 or count < 0 or cursor > A.len - count:
    raise newException(ValueError, "AME handshake wire value is truncated")

proc readHandshakeU8(A: openArray[uint8], cursor: var int): uint8 {.
    role: parser, tag: {tagParsing}.} =
  ## A/cursor: consume one byte.
  requireHandshakeBytes(A, cursor, 1)
  result = A[cursor]
  cursor = cursor + 1

proc readHandshakeU16(A: openArray[uint8], cursor: var int): uint16 {.
    role: parser, tag: {tagParsing}.} =
  ## A/cursor: consume one little-endian u16.
  requireHandshakeBytes(A, cursor, 2)
  result = uint16(A[cursor]) or (uint16(A[cursor + 1]) shl 8)
  cursor = cursor + 2

proc readHandshakeU32(A: openArray[uint8], cursor: var int): uint32 {.
    role: parser, tag: {tagParsing}.} =
  ## A/cursor: consume one little-endian u32.
  requireHandshakeBytes(A, cursor, 4)
  result = uint32(A[cursor]) or (uint32(A[cursor + 1]) shl 8) or
    (uint32(A[cursor + 2]) shl 16) or (uint32(A[cursor + 3]) shl 24)
  cursor = cursor + 4

proc readHandshakeU64(A: openArray[uint8], cursor: var int): uint64 {.
    role: parser, tag: {tagParsing}.} =
  ## A/cursor: consume one little-endian u64.
  var
    i: int = 0
  requireHandshakeBytes(A, cursor, 8)
  while i < 8:
    result = result or (uint64(A[cursor + i]) shl (8 * i))
    i = i + 1
  cursor = cursor + 8

proc appendHandshakeField(A: var ByteSeq, B: openArray[uint8]) {.
    role: stateController, tag: {tagCodecBoundary, tagWrite}.} =
  ## A/B: append one bounded length-framed wire field.
  if uint64(B.len) > uint64(ameHandshakeFieldMax):
    raise newException(ValueError, "AME handshake field exceeds its limit")
  appendAmeU32(A, uint32(B.len))
  appendAmeBytes(A, B)

proc readHandshakeField(A: openArray[uint8], cursor: var int,
    maximum: uint32 = ameHandshakeFieldMax): ByteSeq {.role: parser,
    tag: {tagCodecBoundary, tagParsing}.} =
  ## A/cursor/maximum: consume one bounded length-framed field.
  var
    count: int = 0
  count = checkedAmeWireLen(readHandshakeU32(A, cursor), maximum,
    "AME handshake field")
  requireHandshakeBytes(A, cursor, count)
  if count > 0:
    result = @A[cursor ..< cursor + count]
  cursor = cursor + count

proc appendHandshakeString(A: var ByteSeq, s: string) {.
    role: stateController, tag: {tagCodecBoundary, tagWrite}.} =
  ## A/s: append one bounded UTF-8 identity field.
  var
    B: ByteSeq = @[]
    i: int = 0
  if uint64(s.len) > uint64(ameHandshakeTextMax):
    raise newException(ValueError, "AME handshake text exceeds its limit")
  B.setLen(s.len)
  while i < s.len:
    B[i] = uint8(ord(s[i]))
    i = i + 1
  appendHandshakeField(A, B)

proc readHandshakeString(A: openArray[uint8], cursor: var int): string {.
    role: parser, tag: {tagCodecBoundary, tagParsing}.} =
  ## A/cursor: consume one bounded identity field.
  var
    B: ByteSeq = @[]
    i: int = 0
  B = readHandshakeField(A, cursor, ameHandshakeTextMax)
  result.setLen(B.len)
  while i < B.len:
    result[i] = char(B[i])
    i = i + 1

proc requireHandshakeHeader(A: openArray[uint8], magic: array[4, uint8],
    cursor: var int) {.role: parser,
    tag: {tagCodecBoundary, tagParsing, tagValidation}.} =
  ## A/magic/cursor: validate one top-level handshake record header.
  if A.len < 6 or A[0 .. 3] != magic:
    raise newException(ValueError, "AME handshake wire identity mismatch")
  cursor = 4
  if readHandshakeU16(A, cursor) != ameHandshakeWireVersion:
    raise newException(ValueError, "AME handshake wire version mismatch")

proc signatureAlgorithmFromByte(v: uint8): AmeSignatureAlgorithm {.
    role: parser, tag: {tagParsing, tagValidation}.} =
  ## v: stable Bifrost signature algorithm identifier.
  if int(v) < ord(low(AmeSignatureAlgorithm)) or
      int(v) > ord(high(AmeSignatureAlgorithm)):
    raise newException(ValueError, "AME certificate algorithm is invalid")
  result = AmeSignatureAlgorithm(v)

proc appendHandshakeProofs(A: var ByteSeq, P: openArray[ByteSeq]) {.
    role: stateController, tag: {tagCodecBoundary, tagWrite}.} =
  ## A/P: append one bounded ordered proof stack.
  var
    i: int = 0
  if P.len == 0 or P.len > ameMaxAlgorithmSlots:
    raise newException(ValueError, "AME handshake proof count is invalid")
  A.add(uint8(P.len))
  while i < P.len:
    appendHandshakeField(A, P[i])
    i = i + 1

proc readHandshakeProofs(A: openArray[uint8], cursor: var int): seq[ByteSeq] {.
    role: parser, tag: {tagCodecBoundary, tagParsing}.} =
  ## A/cursor: consume one bounded ordered proof stack.
  var
    count: int = int(readHandshakeU8(A, cursor))
  if count == 0 or count > ameMaxAlgorithmSlots:
    raise newException(ValueError, "AME handshake proof count is invalid")
  while result.len < count:
    result.add(readHandshakeField(A, cursor, ameSignatureProofMax))

proc appendIdentitySigningKeys(A: var ByteSeq,
    K: openArray[AmeIdentitySigningKey]) {.role: stateController,
    tag: {tagCodecBoundary, tagWrite}.} =
  ## A/K: append one bounded ordered identity public-key stack.
  var
    i: int = 0
  if K.len == 0 or K.len > ameMaxAlgorithmSlots:
    raise newException(ValueError, "AME certificate signing-key count is invalid")
  A.add(uint8(K.len))
  while i < K.len:
    if K[i].publicKey.len == 0:
      raise newException(ValueError, "AME certificate signing key is empty")
    A.add(uint8(ord(K[i].algorithm)))
    appendHandshakeField(A, K[i].publicKey)
    i = i + 1

proc readIdentitySigningKeys(A: openArray[uint8], cursor: var int):
    seq[AmeIdentitySigningKey] {.role: parser,
    tag: {tagCodecBoundary, tagParsing}.} =
  ## A/cursor: consume one bounded ordered identity public-key stack.
  var
    count: int = int(readHandshakeU8(A, cursor))
    key: AmeIdentitySigningKey
  if count == 0 or count > ameMaxAlgorithmSlots:
    raise newException(ValueError, "AME certificate signing-key count is invalid")
  while result.len < count:
    key.algorithm = signatureAlgorithmFromByte(readHandshakeU8(A, cursor))
    key.publicKey = readHandshakeField(A, cursor, ameIdentityKeyMax)
    if key.publicKey.len == 0:
      raise newException(ValueError, "AME certificate signing key is empty")
    result.add(key)

proc encodeAmeIdentityCertificate*(c: AmeIdentityCertificate): ByteSeq {.
    role: stateController, tag: {tagAppApi, tagCodecBoundary, tagWrite}.} =
  ## c: authority certificate or unsigned direct-pinning identity descriptor.
  var
    certificateShape: bool = c.authority.len > 0 and
      c.authoritySignature.len > 0 and c.validFromUnix >= 0 and
      c.validUntilUnix > c.validFromUnix
    pinnedShape: bool = c.authority.len == 0 and
      c.authoritySignature.len == 0 and c.validFromUnix == 0 and
      c.validUntilUnix == high(int64)
  if c.subject.len == 0 or c.signingKeys.len == 0 or
      not (certificateShape or pinnedShape):
    raise newException(ValueError, "AME certificate is incomplete")
  appendAmeBytes(result, ameIdentityMagic)
  appendAmeU16(result, ameHandshakeWireVersion)
  appendHandshakeString(result, c.authority)
  appendHandshakeString(result, c.subject)
  appendIdentitySigningKeys(result, c.signingKeys)
  appendAmeU64(result, cast[uint64](c.validFromUnix))
  appendAmeU64(result, cast[uint64](c.validUntilUnix))
  appendHandshakeField(result, c.authoritySignature)

proc decodeAmeIdentityCertificate*(A: openArray[uint8]):
    AmeIdentityCertificate {.role: parser,
    tag: {tagAppApi, tagCodecBoundary, tagParsing}.} =
  ## A: complete bounded ACT1 certificate or pinned identity descriptor bytes.
  var
    cursor: int = 0
    certificateShape: bool = false
    pinnedShape: bool = false
  requireHandshakeHeader(A, ameIdentityMagic, cursor)
  result.authority = readHandshakeString(A, cursor)
  result.subject = readHandshakeString(A, cursor)
  result.signingKeys = readIdentitySigningKeys(A, cursor)
  result.validFromUnix = cast[int64](readHandshakeU64(A, cursor))
  result.validUntilUnix = cast[int64](readHandshakeU64(A, cursor))
  result.authoritySignature = readHandshakeField(A, cursor,
    ameSignatureProofMax)
  certificateShape = result.authority.len > 0 and
    result.authoritySignature.len > 0 and result.validFromUnix >= 0 and
    result.validUntilUnix > result.validFromUnix
  pinnedShape = result.authority.len == 0 and
    result.authoritySignature.len == 0 and result.validFromUnix == 0 and
    result.validUntilUnix == high(int64)
  if cursor != A.len or result.subject.len == 0 or
      result.signingKeys.len == 0 or
      not (certificateShape or pinnedShape):
    raise newException(ValueError, "AME certificate wire value is invalid")

proc encodeAmeClientHello*(h: AmeClientHello): ByteSeq {.role: stateController,
    tag: {tagAppApi, tagCodecBoundary, tagWrite}.} =
  ## h: authenticated client hello and exact AME KEM offer.
  var
    layout: ByteSeq = @[]
    tier: ByteSeq = @[]
    certificate: ByteSeq = @[]
    offer: ByteSeq = @[]
  if h.sessionId == 0'u64 or h.nonce.len != ameHandshakeNonceLen or
      h.proofs.len == 0:
    raise newException(ValueError, "AME client hello is incomplete")
  layout = encodeAmeSuiteLayout(h.layout)
  tier = encodeAmeMaskTier(h.initialTier)
  certificate = encodeAmeIdentityCertificate(h.certificate)
  offer = encodeAmeExchangeOffer(h.offer)
  appendAmeBytes(result, ameClientHelloMagic)
  appendAmeU16(result, ameHandshakeWireVersion)
  appendAmeU64(result, h.sessionId)
  appendHandshakeField(result, h.nonce)
  appendHandshakeField(result, layout)
  appendHandshakeField(result, tier)
  appendHandshakeField(result, certificate)
  appendHandshakeField(result, offer)
  appendHandshakeProofs(result, h.proofs)

proc decodeAmeClientHello*(A: openArray[uint8]): AmeClientHello {.
    role: parser, tag: {tagAppApi, tagCodecBoundary, tagParsing}.} =
  ## A: complete bounded ACH1 client hello bytes.
  var
    B: ByteSeq = @[]
    cursor: int = 0
  requireHandshakeHeader(A, ameClientHelloMagic, cursor)
  result.sessionId = readHandshakeU64(A, cursor)
  result.nonce = readHandshakeField(A, cursor, ameHandshakeNonceLen.uint32)
  B = readHandshakeField(A, cursor)
  result.layout = decodeAmeSuiteLayout(B)
  B = readHandshakeField(A, cursor)
  result.initialTier = decodeAmeMaskTier(result.layout, B)
  B = readHandshakeField(A, cursor)
  result.certificate = decodeAmeIdentityCertificate(B)
  B = readHandshakeField(A, cursor)
  result.offer = decodeAmeExchangeOffer(result.layout.kems, B)
  result.proofs = readHandshakeProofs(A, cursor)
  if cursor != A.len or result.sessionId == 0'u64 or
      result.nonce.len != ameHandshakeNonceLen or result.proofs.len == 0:
    raise newException(ValueError, "AME client hello wire value is invalid")

proc encodeAmeServerHello*(h: AmeServerHello): ByteSeq {.role: stateController,
    tag: {tagAppApi, tagCodecBoundary, tagWrite}.} =
  ## h: authenticated server hello and exact AME KEM reply.
  var
    certificate: ByteSeq = @[]
    reply: ByteSeq = @[]
  if h.nonce.len != ameHandshakeNonceLen or h.proofs.len == 0:
    raise newException(ValueError, "AME server hello is incomplete")
  certificate = encodeAmeIdentityCertificate(h.certificate)
  reply = encodeAmeExchangeReply(h.reply)
  appendAmeBytes(result, ameServerHelloMagic)
  appendAmeU16(result, ameHandshakeWireVersion)
  appendHandshakeField(result, h.nonce)
  appendHandshakeField(result, certificate)
  appendHandshakeField(result, reply)
  appendHandshakeProofs(result, h.proofs)

proc decodeAmeServerHello*(L: AmeSuiteLayout,
    A: openArray[uint8]): AmeServerHello {.
    role: parser, tag: {tagAppApi, tagCodecBoundary, tagParsing}.} =
  ## L/A: immutable negotiated layout and complete bounded server hello bytes.
  var
    B: ByteSeq = @[]
    cursor: int = 0
  requireHandshakeHeader(A, ameServerHelloMagic, cursor)
  result.nonce = readHandshakeField(A, cursor, ameHandshakeNonceLen.uint32)
  B = readHandshakeField(A, cursor)
  result.certificate = decodeAmeIdentityCertificate(B)
  B = readHandshakeField(A, cursor)
  result.reply = decodeAmeExchangeReply(L.kems, B)
  result.proofs = readHandshakeProofs(A, cursor)
  if cursor != A.len or result.nonce.len != ameHandshakeNonceLen or
      result.proofs.len == 0:
    raise newException(ValueError, "AME server hello wire value is invalid")

proc encodeAmeClientFinish*(f: AmeClientFinish): ByteSeq {.role: stateController,
    tag: {tagAppApi, tagCodecBoundary, tagWrite}.} =
  ## f: client transcript confirmation.
  if f.requestId == 0'u32 or f.transcriptHash.len == 0 or f.proofs.len == 0:
    raise newException(ValueError, "AME client finish is incomplete")
  appendAmeBytes(result, ameClientFinishMagic)
  appendAmeU16(result, ameHandshakeWireVersion)
  appendAmeU32(result, f.requestId)
  appendHandshakeField(result, f.transcriptHash)
  appendHandshakeProofs(result, f.proofs)

proc decodeAmeClientFinish*(A: openArray[uint8]): AmeClientFinish {.
    role: parser, tag: {tagAppApi, tagCodecBoundary, tagParsing}.} =
  ## A: complete bounded ACF1 client finish bytes.
  var
    cursor: int = 0
  requireHandshakeHeader(A, ameClientFinishMagic, cursor)
  result.requestId = readHandshakeU32(A, cursor)
  result.transcriptHash = readHandshakeField(A, cursor)
  result.proofs = readHandshakeProofs(A, cursor)
  if cursor != A.len or result.requestId == 0'u32 or
      result.transcriptHash.len == 0 or result.proofs.len == 0:
    raise newException(ValueError, "AME client finish wire value is invalid")
