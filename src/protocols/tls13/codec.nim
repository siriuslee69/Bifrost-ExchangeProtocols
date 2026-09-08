## ----------------------------------------------------------------
## TLS 1.3 Codec <- strict bounded record and handshake wire parser
## ----------------------------------------------------------------

import ../types
import ./types
import bifrostPragmas

const
  tls13RecordHeaderLen* = 5
  tls13HandshakeHeaderLen* = 4

proc appendU16Be(A: var ByteSeq, v: uint16) {.role: dataWriter,
    metaTags: {tagTls, tagWrite}.} =
  ## A/v: destination and big-endian integer.
  A.add(byte(v shr 8))
  A.add(byte(v))

proc appendU24Be(A: var ByteSeq, v: uint32) {.role: dataWriter,
    metaTags: {tagTls, tagWrite}.} =
  ## A/v: destination and 24-bit big-endian integer.
  A.add(byte(v shr 16))
  A.add(byte(v shr 8))
  A.add(byte(v))

proc readU16Be(A: openArray[byte], o: int): uint16 {.role: parser,
    metaTags: {tagTls, tagRead}.} =
  ## A/o: source and first integer byte.
  if o < 0 or o > A.len - 2:
    raise newException(ValueError, "TLS uint16 is incomplete")
  result = (uint16(A[o]) shl 8) or uint16(A[o + 1])

proc readU24Be(A: openArray[byte], o: int): uint32 {.role: parser,
    metaTags: {tagTls, tagRead}.} =
  ## A/o: source and first integer byte.
  if o < 0 or o > A.len - 3:
    raise newException(ValueError, "TLS uint24 is incomplete")
  result = (uint32(A[o]) shl 16) or (uint32(A[o + 1]) shl 8) or
    uint32(A[o + 2])

proc parseContentType(v: byte, t: var Tls13ContentType): bool {.role: parser,
    metaTags: {tagTls, tagValidation}.} =
  ## v/t: wire value and parsed content type.
  case v
  of 20'u8: t = tctChangeCipherSpec
  of 21'u8: t = tctAlert
  of 22'u8: t = tctHandshake
  of 23'u8: t = tctApplicationData
  else: return false
  result = true

proc parseHandshakeType(v: byte, t: var Tls13HandshakeType): bool {.
    role: parser, metaTags: {tagTls, tagValidation}.} =
  ## v/t: wire value and parsed handshake type.
  case v
  of 1'u8: t = thtClientHello
  of 2'u8: t = thtServerHello
  of 4'u8: t = thtNewSessionTicket
  of 8'u8: t = thtEncryptedExtensions
  of 11'u8: t = thtCertificate
  of 13'u8: t = thtCertificateRequest
  of 15'u8: t = thtCertificateVerify
  of 20'u8: t = thtFinished
  of 24'u8: t = thtKeyUpdate
  of 254'u8: t = thtMessageHash
  else: return false
  result = true

proc copySpan(A: openArray[byte], o, n: int): ByteSeq {.role: helper,
    metaTags: {tagTls, tagRead}.} =
  ## A/o/n: source, offset, and bounded byte count.
  var i: int = 0
  if o < 0 or n < 0 or o > A.len or n > A.len - o:
    raise newException(ValueError, "TLS byte span is out of bounds")
  result = newSeq[byte](n)
  while i < n:
    result[i] = A[o + i]
    i = i + 1

proc encodeTls13Record*(r: Tls13Record): ByteSeq {.role: dataWriter,
    metaTags: {tagTls, tagWrite, tagPacket}.} =
  ## r: bounded plaintext or ciphertext record.
  var maxLen: int = tls13PlaintextLimit
  if r.contentType == tctApplicationData:
    maxLen = tls13CiphertextLimit
  if r.legacyVersion != tls13LegacyRecordVersion:
    raise newException(ValueError, "TLS record legacy version must be 0x0303")
  if r.fragment.len > maxLen:
    raise newException(ValueError, "TLS record fragment exceeds maximum")
  result.add(byte(ord(r.contentType)))
  appendU16Be(result, r.legacyVersion)
  appendU16Be(result, uint16(r.fragment.len))
  result.add(r.fragment)

proc decodeTls13Record*(A: openArray[byte]): Tls13RecordResult {.role: parser,
    metaTags: {tagTls, tagRead, tagValidation}.} =
  ## A: stream bytes beginning at a TLS record boundary.
  var
    n, version: uint16 = 0
    t: Tls13ContentType
    maxLen: int = tls13PlaintextLimit
  if A.len < tls13RecordHeaderLen:
    result.needMore = true
    result.err = "need TLS record header"
    return
  if not parseContentType(A[0], t):
    result.err = "TLS record content type is invalid"
    return
  version = readU16Be(A, 1)
  if version notin {0x0301'u16, tls13LegacyRecordVersion}:
    result.err = "TLS record legacy version is invalid"
    return
  n = readU16Be(A, 3)
  if t == tctApplicationData:
    maxLen = tls13CiphertextLimit
  if int(n) > maxLen:
    result.err = "TLS record fragment exceeds maximum"
    return
  if A.len < tls13RecordHeaderLen + int(n):
    result.needMore = true
    result.err = "need complete TLS record fragment"
    return
  result.record.contentType = t
  result.record.legacyVersion = version
  result.record.fragment = copySpan(A, tls13RecordHeaderLen, int(n))
  result.consumed = tls13RecordHeaderLen + int(n)
  result.ok = true

proc encodeTls13Handshake*(h: Tls13Handshake,
    maxBytes: int = tls13DefaultHandshakeLimit): ByteSeq {.role: dataWriter,
    metaTags: {tagTls, tagWrite, tagPacket}.} =
  ## h/maxBytes: handshake message and caller resource bound.
  if maxBytes < 0 or h.body.len > maxBytes or h.body.len > 0x00ff_ffff:
    raise newException(ValueError, "TLS handshake body exceeds maximum")
  result.add(byte(ord(h.messageType)))
  appendU24Be(result, uint32(h.body.len))
  result.add(h.body)

proc decodeTls13Handshake*(A: openArray[byte],
    maxBytes: int = tls13DefaultHandshakeLimit): Tls13HandshakeResult {.
    role: parser, metaTags: {tagTls, tagRead, tagValidation}.} =
  ## A/maxBytes: buffered handshake bytes and caller resource bound.
  var
    n: uint32 = 0
    t: Tls13HandshakeType
  if maxBytes < 0:
    result.err = "TLS handshake maximum is invalid"
    return
  if A.len < tls13HandshakeHeaderLen:
    result.needMore = true
    result.err = "need TLS handshake header"
    return
  if not parseHandshakeType(A[0], t):
    result.err = "TLS handshake type is unsupported"
    return
  n = readU24Be(A, 1)
  if n > uint32(maxBytes):
    result.err = "TLS handshake body exceeds maximum"
    return
  if A.len < tls13HandshakeHeaderLen + int(n):
    result.needMore = true
    result.err = "need complete TLS handshake body"
    return
  result.message.messageType = t
  result.message.body = copySpan(A, tls13HandshakeHeaderLen, int(n))
  result.consumed = tls13HandshakeHeaderLen + int(n)
  result.message.encoded = copySpan(A, 0, result.consumed)
  result.ok = true

proc validateTls13LegacyCompression*(A: openArray[byte]): bool {.role: parser,
    metaTags: {tagTls, tagValidation}.} =
  ## A: ClientHello legacy compression vector; TLS 1.3 requires exactly null.
  result = A.len == 1 and A[0] == 0'u8
