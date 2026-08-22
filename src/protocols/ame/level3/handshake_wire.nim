## -------------------------------------------------------------------------
## AME Handshake Wire <- the four handshake records, byte for byte
## -------------------------------------------------------------------------
##
## Each record begins with three letters and one version byte, so the first
## four bytes read as a name:
##
##   "AMC1"  client hello        "AMS1"  server hello
##   "AMR1"  hello retry         "AMF1"  client finish
##
## Fixed-size fields carry no length. The nonce is always 32 bytes, so
## writing "32" in front of it every time would say nothing. Variable fields
## carry a length in front, u16 where the field is small by construction and
## u32 only where a post-quantum key can genuinely run to megabytes.
##
## Client hello (AMC1)
##   +---+---+---+---+-------------------+------------------------------+
##   | A | M | C | 1 |    session id     |   nonce (32 bytes, fixed)    |
##   +---+---+---+---+-------------------+------------------------------+
##     0   1   2   3    4..11               12..43
##
##   +--------+---------+--------+--------+--------+---------+
##   | u16 len| layout  | u16 len|  tier  | u16 len| cookie  |  then u32+offer
##   +--------+---------+--------+--------+--------+---------+
##
## Hello retry (AMR1)
##   "AMR" | ver | session id u64 | u16 len | cookie
##
## Server hello (AMS1)
##   "AMS" | ver | nonce (32) | u32 len | KEM reply
##         | tagLen u8 | padding u8 | tag (tagLen bytes) | u32 len | sealed
##
## Client finish (AMF1)
##   "AMF" | ver | tagLen u8 | padding u8 | tag | u32 len | sealed block
##
## The two bytes after the KEM reply are the epoch's tunables: how long every
## tag will be, and whether payloads get padded to whole blocks. The responder
## chooses them and the client either adopts them or gives up. They travel in
## the clear because the client needs them to open the block that follows, and
## they are bound into that block's tag, so editing one in flight only breaks
## the handshake.
##
## The sealed block in the last two is ciphertext. It holds the certificate
## and the proofs; nothing outside it says who either side is.

from ../../types import ByteSeq
import ../types
import ./handshake
import ../level0/bytes
import ../level1/exchange_paths
import ../level1/suites
import ../level1/padding
import ../../../analysis_pragmas

const
  ameHandshakeWireVersion = 1'u8
  ameClientHelloMagic = [uint8('A'), uint8('M'), uint8('C')]
  ameHelloRetryMagic = [uint8('A'), uint8('M'), uint8('R')]
  ameServerHelloMagic = [uint8('A'), uint8('M'), uint8('S')]
  ameClientFinishMagic = [uint8('A'), uint8('M'), uint8('F')]
  ameHandshakeSmallMax = 65_535'u32
  ameHandshakeFieldMax = 16_777_216'u32
  ameCookieMax = 255'u32

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

proc readFixed(A: openArray[uint8], cursor: var int, n: int): ByteSeq {.
    role: parser, tag: {tagParsing}.} =
  ## A/cursor/n: consume a field whose size the format already fixes.
  requireHandshakeBytes(A, cursor, n)
  if n > 0:
    result = @A[cursor ..< cursor + n]
  cursor = cursor + n

proc appendSmallField(A: var ByteSeq, B: openArray[uint8]) {.
    role: stateController, tag: {tagCodecBoundary, tagWrite}.} =
  ## A/B: append one field whose length fits a u16 by construction.
  if uint64(B.len) > uint64(ameHandshakeSmallMax):
    raise newException(ValueError, "AME handshake field exceeds its limit")
  appendAmeU16(A, uint16(B.len))
  appendAmeBytes(A, B)

proc readSmallField(A: openArray[uint8], cursor: var int,
    maximum: uint32 = ameHandshakeSmallMax): ByteSeq {.role: parser,
    tag: {tagCodecBoundary, tagParsing}.} =
  ## A/cursor/maximum: consume one bounded u16-framed field.
  var
    count: int = 0
  count = checkedAmeWireLen(uint32(readHandshakeU16(A, cursor)), maximum,
    "AME handshake field")
  result = readFixed(A, cursor, count)

proc appendLargeField(A: var ByteSeq, B: openArray[uint8]) {.
    role: stateController, tag: {tagCodecBoundary, tagWrite}.} =
  ## A/B: append one field that a post-quantum key may legitimately fill.
  if uint64(B.len) > uint64(ameHandshakeFieldMax):
    raise newException(ValueError, "AME handshake field exceeds its limit")
  appendAmeU32(A, uint32(B.len))
  appendAmeBytes(A, B)

proc readLargeField(A: openArray[uint8], cursor: var int,
    maximum: uint32 = ameHandshakeFieldMax): ByteSeq {.role: parser,
    tag: {tagCodecBoundary, tagParsing}.} =
  ## A/cursor/maximum: consume one bounded u32-framed field.
  var
    count: int = 0
  count = checkedAmeWireLen(readHandshakeU32(A, cursor), maximum,
    "AME handshake field")
  result = readFixed(A, cursor, count)

proc requireHandshakeHeader(A: openArray[uint8], magic: array[3, uint8],
    cursor: var int) {.role: parser,
    tag: {tagCodecBoundary, tagParsing, tagValidation}.} =
  ## A/magic/cursor: validate one top-level handshake record header.
  if A.len < 4 or A[0 .. 2] != magic:
    raise newException(ValueError, "AME handshake wire identity mismatch")
  if A[3] != ameHandshakeWireVersion:
    raise newException(ValueError, "AME handshake wire version mismatch")
  cursor = 4

proc appendRecordHeader(A: var ByteSeq, magic: array[3, uint8]) {.
    role: stateController, tag: {tagCodecBoundary, tagWrite}.} =
  ## A/magic: three letters and one version byte.
  appendAmeBytes(A, magic)
  A.add(ameHandshakeWireVersion)

proc encodeAmeClientHello*(h: AmeClientHello): ByteSeq {.role: stateController,
    tag: {tagAppApi, tagCodecBoundary, tagWrite}.} =
  ## h: client hello and exact AME KEM offer. Carries no identity.
  if h.sessionId == 0'u64 or h.nonce.len != ameHandshakeNonceLen:
    raise newException(ValueError, "AME client hello is incomplete")
  if uint64(h.cookie.len) > uint64(ameCookieMax):
    raise newException(ValueError, "AME client hello cookie is too large")
  appendRecordHeader(result, ameClientHelloMagic)
  appendAmeU64(result, h.sessionId)
  appendAmeBytes(result, h.nonce)
  appendSmallField(result, encodeAmeSuiteLayout(h.layout))
  appendSmallField(result, encodeAmeMaskTier(h.initialTier))
  appendSmallField(result, h.cookie)
  appendLargeField(result, encodeAmeExchangeOffer(h.offer))

proc decodeAmeClientHello*(A: openArray[uint8]): AmeClientHello {.
    role: parser, tag: {tagAppApi, tagCodecBoundary, tagParsing}.} =
  ## A: complete bounded AMC1 client hello bytes.
  var
    B: ByteSeq = @[]
    cursor: int = 0
  requireHandshakeHeader(A, ameClientHelloMagic, cursor)
  result.sessionId = readHandshakeU64(A, cursor)
  result.nonce = readFixed(A, cursor, ameHandshakeNonceLen)
  B = readSmallField(A, cursor)
  result.layout = decodeAmeSuiteLayout(B)
  B = readSmallField(A, cursor)
  result.initialTier = decodeAmeMaskTier(result.layout, B)
  result.cookie = readSmallField(A, cursor, ameCookieMax)
  B = readLargeField(A, cursor)
  result.offer = decodeAmeExchangeOffer(result.layout.kems, B)
  if cursor != A.len or result.sessionId == 0'u64:
    raise newException(ValueError, "AME client hello wire value is invalid")

proc encodeAmeHelloRetry*(r: AmeHelloRetry): ByteSeq {.role: stateController,
    tag: {tagAppApi, tagCodecBoundary, tagWrite}.} =
  ## r: the server's request that the client prove its return address.
  if r.sessionId == 0'u64 or r.cookie.len == 0 or
      uint64(r.cookie.len) > uint64(ameCookieMax):
    raise newException(ValueError, "AME hello retry is incomplete")
  appendRecordHeader(result, ameHelloRetryMagic)
  appendAmeU64(result, r.sessionId)
  appendSmallField(result, r.cookie)

proc decodeAmeHelloRetry*(A: openArray[uint8]): AmeHelloRetry {.role: parser,
    tag: {tagAppApi, tagCodecBoundary, tagParsing}.} =
  ## A: complete bounded AMR1 hello retry bytes.
  var
    cursor: int = 0
  requireHandshakeHeader(A, ameHelloRetryMagic, cursor)
  result.sessionId = readHandshakeU64(A, cursor)
  result.cookie = readSmallField(A, cursor, ameCookieMax)
  if cursor != A.len or result.sessionId == 0'u64 or result.cookie.len == 0:
    raise newException(ValueError, "AME hello retry wire value is invalid")

proc encodeAmeServerHello*(h: AmeServerHello): ByteSeq {.role: stateController,
    tag: {tagAppApi, tagCodecBoundary, tagWrite}.} =
  ## h: server nonce and KEM answer in the clear, identity sealed after them.
  if h.nonce.len != ameHandshakeNonceLen or
      h.authTag.len != int(ord(h.params.authTagLen)) or h.sealed.len == 0:
    raise newException(ValueError, "AME server hello is incomplete")
  appendRecordHeader(result, ameServerHelloMagic)
  appendAmeBytes(result, h.nonce)
  appendLargeField(result, encodeAmeExchangeReply(h.reply))
  result.add(uint8(ord(h.params.authTagLen)))
  result.add(uint8(ord(h.params.padding)))
  appendAmeBytes(result, h.authTag)
  appendLargeField(result, h.sealed)

proc decodeAmeServerHello*(L: AmeSuiteLayout,
    A: openArray[uint8]): AmeServerHello {.
    role: parser, tag: {tagAppApi, tagCodecBoundary, tagParsing}.} =
  ## L/A: negotiated layout and complete bounded AMS1 server hello bytes.
  var
    B: ByteSeq = @[]
    cursor: int = 0
  requireHandshakeHeader(A, ameServerHelloMagic, cursor)
  result.nonce = readFixed(A, cursor, ameHandshakeNonceLen)
  B = readLargeField(A, cursor)
  result.reply = decodeAmeExchangeReply(L.kems, B)
  result.params.authTagLen = ameAuthTagLenFromId(readHandshakeU8(A, cursor))
  result.params.padding = amePaddingPolicyFromId(readHandshakeU8(A, cursor))
  result.authTag = readFixed(A, cursor, int(ord(result.params.authTagLen)))
  result.sealed = readLargeField(A, cursor)
  if cursor != A.len or result.sealed.len == 0:
    raise newException(ValueError, "AME server hello wire value is invalid")

proc encodeAmeClientFinish*(f: AmeClientFinish): ByteSeq {.
    role: stateController, tag: {tagAppApi, tagCodecBoundary, tagWrite}.} =
  ## f: the client's sealed identity and transcript confirmation.
  if f.authTag.len != int(ord(f.params.authTagLen)) or f.sealed.len == 0:
    raise newException(ValueError, "AME client finish is incomplete")
  appendRecordHeader(result, ameClientFinishMagic)
  result.add(uint8(ord(f.params.authTagLen)))
  result.add(uint8(ord(f.params.padding)))
  appendAmeBytes(result, f.authTag)
  appendLargeField(result, f.sealed)

proc decodeAmeClientFinish*(A: openArray[uint8]): AmeClientFinish {.
    role: parser, tag: {tagAppApi, tagCodecBoundary, tagParsing}.} =
  ## A: complete bounded AMF1 client finish bytes.
  var
    cursor: int = 0
  requireHandshakeHeader(A, ameClientFinishMagic, cursor)
  result.params.authTagLen = ameAuthTagLenFromId(readHandshakeU8(A, cursor))
  result.params.padding = amePaddingPolicyFromId(readHandshakeU8(A, cursor))
  result.authTag = readFixed(A, cursor, int(ord(result.params.authTagLen)))
  result.sealed = readLargeField(A, cursor)
  if cursor != A.len or result.sealed.len == 0:
    raise newException(ValueError, "AME client finish wire value is invalid")
