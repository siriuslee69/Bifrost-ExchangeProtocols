## -------------------------------------------------------------------
## TLS 1.3 Handshake Messages <- controlled certificate-flight codecs
## -------------------------------------------------------------------

import ../types
import ./[types, codec, hello]
import ../../analysis_pragmas

type
  Tls13CertificateEntry* = object
    certificateDer*: ByteSeq

  Tls13CertificateMessage* = object
    requestContext*: ByteSeq
    entries*: seq[Tls13CertificateEntry]

proc addU16(A: var ByteSeq, v: uint16) {.role: stateController,
    tag: {tagTls, tagWrite}.} =
  A.add(byte(v shr 8))
  A.add(byte(v))

proc addU24(A: var ByteSeq, v: int) {.role: stateController,
    tag: {tagTls, tagWrite}.} =
  if v < 0 or v > 0x00ff_ffff:
    raise newException(ValueError, "TLS uint24 value is invalid")
  A.add(byte(v shr 16))
  A.add(byte(v shr 8))
  A.add(byte(v))

proc readU16(A: openArray[byte], o: int, v: var int): bool {.role: parser,
    tag: {tagTls, tagRead}.} =
  if o < 0 or o > A.len - 2:
    return false
  v = (int(A[o]) shl 8) or int(A[o + 1])
  result = true

proc readU24(A: openArray[byte], o: int, v: var int): bool {.role: parser,
    tag: {tagTls, tagRead}.} =
  if o < 0 or o > A.len - 3:
    return false
  v = (int(A[o]) shl 16) or (int(A[o + 1]) shl 8) or int(A[o + 2])
  result = true

proc encodeTls13EncryptedExtensions*(alpn: string = ""): ByteSeq {.
    role: dataWriter, tag: {tagTls, tagWrite}.} =
  ## alpn: selected protocol or empty when none was negotiated.
  var
    extensions, body, value, list: ByteSeq = @[]
    i: int = 0
  if alpn.len > 0:
    if alpn.len > 255:
      raise newException(ValueError, "TLS selected ALPN is too long")
    list.add(byte(alpn.len))
    while i < alpn.len:
      list.add(byte(ord(alpn[i])))
      i = i + 1
    addU16(value, uint16(list.len))
    value.add(list)
    addU16(extensions, 16'u16)
    addU16(extensions, uint16(value.len))
    extensions.add(value)
  addU16(body, uint16(extensions.len))
  body.add(extensions)
  result = encodeTls13Handshake(Tls13Handshake(
    messageType: thtEncryptedExtensions, body: body))

proc decodeTls13EncryptedExtensions*(A: openArray[byte]): tuple[
    ok: bool, alpn, err: string] {.role: parser,
    tag: {tagTls, tagRead, tagValidation}.} =
  ## A: EncryptedExtensions body without handshake header.
  var
    total, kind, n, listLen, nameLen, o: int = 0
  if not readU16(A, 0, total) or total != A.len - 2:
    result.err = "TLS EncryptedExtensions length is invalid"
    return
  o = 2
  while o < A.len:
    if not readU16(A, o, kind) or not readU16(A, o + 2, n) or
        o + 4 + n > A.len:
      result.err = "TLS encrypted extension is incomplete"
      return
    if kind == 16:
      if result.alpn.len > 0 or not readU16(A, o + 4, listLen) or
          listLen != n - 2 or listLen < 2:
        result.err = "TLS ALPN selection is invalid or duplicated"
        return
      nameLen = int(A[o + 6])
      if nameLen != listLen - 1:
        result.err = "TLS ALPN selected name length is invalid"
        return
      result.alpn = newString(nameLen)
      for i in 0 ..< nameLen:
        result.alpn[i] = char(A[o + 7 + i])
    o = o + 4 + n
  result.ok = true

proc encodeTls13Certificate*(C: Tls13CertificateMessage): ByteSeq {.
    role: dataWriter, tag: {tagTls, tagWrite}.} =
  ## C: certificate request context and bounded DER chain.
  var
    list, body: ByteSeq = @[]
    i: int = 0
  if C.requestContext.len > 255 or C.entries.len == 0:
    raise newException(ValueError, "TLS certificate context or chain is invalid")
  while i < C.entries.len:
    if C.entries[i].certificateDer.len == 0:
      raise newException(ValueError, "TLS certificate entry is empty")
    addU24(list, C.entries[i].certificateDer.len)
    list.add(C.entries[i].certificateDer)
    addU16(list, 0'u16)
    i = i + 1
  body.add(byte(C.requestContext.len))
  body.add(C.requestContext)
  addU24(body, list.len)
  body.add(list)
  result = encodeTls13Handshake(Tls13Handshake(
    messageType: thtCertificate, body: body))

proc decodeTls13Certificate*(A: openArray[byte], maxChainBytes: int =
    tls13DefaultHandshakeLimit): tuple[ok: bool,
    message: Tls13CertificateMessage, err: string] {.role: parser,
    tag: {tagTls, tagRead, tagValidation}.} =
  ## A/maxChainBytes: Certificate body and total DER resource bound.
  var
    contextLen, listLen, certLen, extLen, o, endList, totalDer: int = 0
    entry: Tls13CertificateEntry
  if A.len < 4:
    result.err = "TLS Certificate body is incomplete"
    return
  contextLen = int(A[0])
  if 1 + contextLen + 3 > A.len:
    result.err = "TLS Certificate request context is incomplete"
    return
  result.message.requestContext = @A[1 ..< 1 + contextLen]
  o = 1 + contextLen
  if not readU24(A, o, listLen):
    result.err = "TLS certificate_list length is incomplete"
    return
  o = o + 3
  endList = o + listLen
  if listLen == 0 or endList != A.len:
    result.err = "TLS certificate_list length is invalid"
    return
  while o < endList:
    if not readU24(A, o, certLen) or certLen <= 0:
      result.err = "TLS certificate entry length is invalid"
      return
    o = o + 3
    if o + certLen + 2 > endList:
      result.err = "TLS certificate entry is incomplete"
      return
    totalDer = totalDer + certLen
    if maxChainBytes < 0 or totalDer > maxChainBytes:
      result.err = "TLS certificate chain exceeds maximum"
      return
    entry.certificateDer = @A[o ..< o + certLen]
    o = o + certLen
    if not readU16(A, o, extLen) or o + 2 + extLen > endList:
      result.err = "TLS certificate entry extensions are invalid"
      return
    o = o + 2 + extLen
    result.message.entries.add(entry)
  result.ok = result.message.entries.len > 0

proc encodeTls13CertificateVerify*(signature: openArray[byte],
    scheme: uint16 = tls13SignatureEd25519): ByteSeq {.
    role: dataWriter, tag: {tagTls, tagWrite}.} =
  ## signature/scheme: CertificateVerify signature and its algorithm code.
  var body: ByteSeq = @[]
  if scheme == tls13SignatureEd25519 and signature.len != 64:
    raise newException(ValueError, "TLS Ed25519 signature must be 64 bytes")
  if signature.len == 0 or signature.len > 65535:
    raise newException(ValueError, "TLS CertificateVerify signature length is invalid")
  addU16(body, scheme)
  addU16(body, uint16(signature.len))
  body.add(signature)
  result = encodeTls13Handshake(Tls13Handshake(
    messageType: thtCertificateVerify, body: body))

proc decodeTls13CertificateVerify*(A: openArray[byte]): tuple[
    ok: bool, signature: ByteSeq, scheme: uint16, err: string] {.role: parser,
    tag: {tagTls, tagRead, tagValidation}.} =
  ## A: CertificateVerify body without handshake header.
  ## The scheme is returned so the caller can bind it to the certificate's
  ## key type; accepting a signature without that check would let a peer
  ## pick an algorithm the certificate was never issued for.
  var
    alg, n: int = 0
    known: bool = false
    i: int = 0
  if A.len < 4 or not readU16(A, 0, alg) or not readU16(A, 2, n) or
      A.len != 4 + n or n == 0:
    result.err = "TLS CertificateVerify body is invalid"
    return
  while i < tls13SupportedSignatureSchemes.len:
    if uint16(alg) == tls13SupportedSignatureSchemes[i]:
      known = true
    i = i + 1
  if not known:
    result.err = "TLS CertificateVerify uses an unsupported signature scheme"
    return
  if uint16(alg) == tls13SignatureEd25519 and n != 64:
    result.err = "TLS Ed25519 CertificateVerify signature must be 64 bytes"
    return
  result.scheme = uint16(alg)
  result.signature = @A[4 .. ^1]
  result.ok = true

proc encodeTls13Finished*(verifyData: openArray[byte]): ByteSeq {.
    role: dataWriter, tag: {tagTls, tagWrite}.} =
  ## verifyData: SHA-256 Finished verify_data.
  if verifyData.len != 32:
    raise newException(ValueError, "TLS Finished verify_data must be 32 bytes")
  result = encodeTls13Handshake(Tls13Handshake(
    messageType: thtFinished, body: @verifyData))
