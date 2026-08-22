## ----------------------------------------------------------------------
## TLS 1.3 Records <- ChaCha20-Poly1305 record seal/open and nonce state
## ----------------------------------------------------------------------

import tyr/ciphers/chacha20
import tyr/macs/poly1305
import tyr/helpers/secure_memory

import ../types
import ./types
import ../../analysis_pragmas

type
  Tls13AeadSeal = object
    ciphertext: ByteSeq
    tag: array[tls13AeadTagLen, byte]

  Tls13AeadOpen = object
    ok: bool
    plaintext: ByteSeq

proc appendLe64(A: var ByteSeq, v: uint64) {.role: stateController,
    tag: {tagTls, tagCryptoBoundary}.} =
  ## A/v: Poly1305 input and little-endian RFC 8439 length.
  var i: int = 0
  while i < 8:
    A.add(byte(v shr (i * 8)))
    i = i + 1

proc appendPadded16(A: var ByteSeq, B: openArray[byte]) {.
    role: stateController, tag: {tagTls, tagCryptoBoundary}.} =
  ## A/B: Poly1305 input and one RFC 8439 field.
  var n: int = 0
  A.add(B)
  n = (16 - (B.len mod 16)) mod 16
  while n > 0:
    A.add(0'u8)
    n = n - 1

proc buildPoly1305Input(aad, ciphertext: openArray[byte]): ByteSeq {.
    role: truthBuilder, tag: {tagTls, tagCryptoBoundary}.} =
  ## aad/ciphertext: authenticated RFC 8439 fields.
  appendPadded16(result, aad)
  appendPadded16(result, ciphertext)
  appendLe64(result, uint64(aad.len))
  appendLe64(result, uint64(ciphertext.len))

proc constantTimeTagEqual(A, B: openArray[byte]): bool {.role: helper,
    tag: {tagTls, tagCryptoBoundary}.} =
  ## A/B: fixed-size authentication tags.
  var
    diff: uint = if A.len == B.len: 0'u else: 1'u
    i: int = 0
    b: byte = 0
  while i < A.len:
    b = if i < B.len: B[i] else: 0'u8
    diff = diff or uint(A[i] xor b)
    i = i + 1
  result = diff == 0'u

proc derivePoly1305Key(key, nonce: openArray[byte]):
    array[poly1305KeyBytes, byte] {.role: truthBuilder,
    tag: {tagTls, tagCryptoBoundary}.} =
  ## key/nonce: ChaCha20 traffic key and per-record nonce.
  var
    keyBlock: array[chacha20BlockSize, byte]
    i: int = 0
  defer:
    secureClearBytes(keyBlock)
  keyBlock = chacha20Block(key, nonce, 0'u32)
  while i < result.len:
    result[i] = keyBlock[i]
    i = i + 1

proc sealTls13Aead(key, nonce, plaintext, aad: openArray[byte]):
    Tls13AeadSeal {.role: encryptor,
    tag: {tagTls, tagCryptoBoundary}.} =
  ## key/nonce/plaintext/aad: private TLS RFC 8439 composition inputs.
  var
    oneTimeKey: array[poly1305KeyBytes, byte]
    macInput: ByteSeq = @[]
  defer:
    secureClearBytes(oneTimeKey)
    secureClearBytes(macInput)
  oneTimeKey = derivePoly1305Key(key, nonce)
  result.ciphertext = chacha20Xor(key, nonce, 1'u32, plaintext)
  macInput = buildPoly1305Input(aad, result.ciphertext)
  result.tag = poly1305Mac(oneTimeKey, macInput)

proc openTls13Aead(key, nonce, ciphertext, tag,
    aad: openArray[byte]): Tls13AeadOpen {.role: decryptor,
    tag: {tagTls, tagCryptoBoundary}.} =
  ## key/nonce/ciphertext/tag/aad: private TLS RFC 8439 composition inputs.
  var
    oneTimeKey: array[poly1305KeyBytes, byte]
    expected: array[poly1305TagBytes, byte]
    macInput: ByteSeq = @[]
  defer:
    secureClearBytes(oneTimeKey)
    secureClearBytes(expected)
    secureClearBytes(macInput)
  if tag.len != tls13AeadTagLen:
    return
  oneTimeKey = derivePoly1305Key(key, nonce)
  macInput = buildPoly1305Input(aad, ciphertext)
  expected = poly1305Mac(oneTimeKey, macInput)
  if not constantTimeTagEqual(expected, tag):
    return
  result.plaintext = chacha20Xor(key, nonce, 1'u32, ciphertext)
  result.ok = true

proc recordNonce(T: Tls13TrafficKeys): array[tls13AeadIvLen, byte] {.
    role: truthBuilder, tag: {tagTls, tagCryptoBoundary}.} =
  ## T: traffic IV and sequence number.
  var i: int = 0
  result = T.iv
  while i < 8:
    result[result.len - 1 - i] = result[result.len - 1 - i] xor
      byte(T.sequence shr (i * 8))
    i = i + 1

proc recordAad(n: int): ByteSeq {.role: truthBuilder,
    tag: {tagTls, tagCryptoBoundary}.} =
  ## n: complete TLSCiphertext fragment length.
  if n < tls13AeadTagLen or n > tls13CiphertextLimit:
    raise newException(ValueError, "TLS ciphertext length is invalid")
  result = @[byte(ord(tctApplicationData)), byte 0x03, 0x03,
    byte(n shr 8), byte(n)]

proc parseInnerPlaintext(A: openArray[byte]): Tls13OpenResult {.role: parser,
    tag: {tagTls, tagCryptoBoundary, tagValidation}.} =
  ## A: authenticated TLSInnerPlaintext bytes.
  var
    i: int = A.len - 1
    t: byte = 0
  while i >= 0 and A[i] == 0'u8:
    i = i - 1
  if i < 0:
    result.err = "TLS inner plaintext has no content type"
    return
  t = A[i]
  case t
  of 21'u8: result.contentType = tctAlert
  of 22'u8: result.contentType = tctHandshake
  of 23'u8: result.contentType = tctApplicationData
  else:
    result.err = "TLS inner plaintext content type is invalid"
    return
  if i > 0:
    result.content = newSeq[byte](i)
    while result.content.len > 0 and i > 0:
      i = i - 1
      result.content[i] = A[i]
  result.ok = true

proc sealTls13Record*(T: var Tls13TrafficKeys, t: Tls13ContentType,
    content: openArray[byte], paddingLen: int = 0): Tls13Record {.
    role: encryptor, tag: {tagTls, tagCryptoBoundary, tagPacket}.} =
  ## T/t/content/paddingLen: write keys, inner type, plaintext, and zero padding.
  var
    inner, aad: ByteSeq = @[]
    nonce: array[tls13AeadIvLen, byte]
    sealed: Tls13AeadSeal
  if t notin {tctAlert, tctHandshake, tctApplicationData}:
    raise newException(ValueError, "TLS inner content type is invalid")
  if paddingLen < 0 or content.len + 1 + paddingLen > tls13PlaintextLimit:
    raise newException(ValueError, "TLS inner plaintext exceeds maximum")
  if T.sequence == uint64.high:
    raise newException(ValueError, "TLS record sequence is exhausted")
  inner.add(content)
  inner.add(byte(ord(t)))
  inner.setLen(inner.len + paddingLen)
  nonce = recordNonce(T)
  aad = recordAad(inner.len + tls13AeadTagLen)
  sealed = sealTls13Aead(T.key, nonce, inner, aad)
  result.contentType = tctApplicationData
  result.legacyVersion = tls13LegacyRecordVersion
  result.fragment = sealed.ciphertext
  result.fragment.add(sealed.tag)
  T.sequence = T.sequence + 1'u64

proc openTls13Record*(T: var Tls13TrafficKeys,
    r: Tls13Record): Tls13OpenResult {.role: decryptor,
    tag: {tagTls, tagCryptoBoundary, tagPacket}.} =
  ## T/r: read keys and received TLSCiphertext record.
  var
    nonce: array[tls13AeadIvLen, byte]
    aad, ciphertext: ByteSeq = @[]
    tag: array[tls13AeadTagLen, byte]
    opened: Tls13AeadOpen
    n, i: int = 0
  if r.contentType != tctApplicationData or
      r.legacyVersion != tls13LegacyRecordVersion:
    result.err = "TLS encrypted record header is invalid"
    return
  if r.fragment.len < tls13AeadTagLen or
      r.fragment.len > tls13CiphertextLimit:
    result.err = "TLS encrypted record length is invalid"
    return
  if T.sequence == uint64.high:
    result.err = "TLS record sequence is exhausted"
    return
  n = r.fragment.len - tls13AeadTagLen
  ciphertext = newSeq[byte](n)
  while i < n:
    ciphertext[i] = r.fragment[i]
    i = i + 1
  i = 0
  while i < tag.len:
    tag[i] = r.fragment[n + i]
    i = i + 1
  nonce = recordNonce(T)
  aad = recordAad(r.fragment.len)
  opened = openTls13Aead(T.key, nonce, ciphertext, tag, aad)
  if not opened.ok:
    result.err = "TLS record authentication failed"
    return
  result = parseInnerPlaintext(opened.plaintext)
  if result.ok:
    T.sequence = T.sequence + 1'u64
