## -------------------------------------------------------------------------
## GGAEAD <- compact Gimli stream encryption plus GimliHMAC authentication
## -------------------------------------------------------------------------

import tyr/ciphers/gimli_sponge as tyr_gimli
import tyr/macs/hmac as tyr_hmac

import ../types as core_types
import ../ame/level0/bytes
import ../fomke/types as fomke_types
import ../fomke/level0/gb3hkdf
import ../preparation/types
import ../preparation/gimli_batch
import ./types
import ../../analysis_pragmas

proc ggKeySlice(K: openArray[uint8], offset: int): ByteSeq {.role: parser,
    tag: {tagCryptoBoundary, tagGgAead}.} =
  ## K/offset: complete GGAEAD material and one 32-byte subkey offset.
  var
    i: int = 0
  if K.len != ggAeadKeyMaterialBytes or offset < 0 or
      offset > K.len - gb3BlockBytes:
    raise newException(ValueError,
      "GGAEAD key material must contain two 32-byte keys")
  result.setLen(gb3BlockBytes)
  while i < gb3BlockBytes:
    result[i] = K[offset + i]
    i = i + 1

proc appendGgField(A: var ByteSeq, B: openArray[uint8]) {.
    role: stateController, tag: {tagGgAead}.} =
  ## A/B: destination and one length-framed authenticated field.
  if uint64(B.len) > uint64(high(uint32)):
    raise newException(ValueError, "GGAEAD field exceeds u32")
  appendAmeU32(A, uint32(B.len))
  appendAmeBytes(A, B)

proc buildGgAuthInput(nonce, aad, ciphertext: openArray[uint8]): ByteSeq {.
    role: truthBuilder, tag: {tagCryptoBoundary, tagGgAead}.} =
  ## nonce/aad/ciphertext: canonical encrypt-then-authenticate fields.
  appendAmeLabel(result, "BIFROST-GGAEAD-v1")
  appendAmeU16(result, 1'u16)
  appendGgField(result, aad)
  appendGgField(result, nonce)
  appendGgField(result, ciphertext)

proc deriveGgAeadKeyMaterial*(rootKey, context: openArray[uint8],
    c: Gb3KdfConfig = initGb3KdfConfig()): ByteSeq {.role: truthBuilder,
    tag: {tagAppApi, tagCryptoBoundary, tagGgAead, tagKdf}.} =
  ## rootKey/context/c: compact root, purpose binding, and GB3HKDF policy.
  var
    info: ByteSeq = @[]
  defer:
    secureClearAmeBytes(info)
  appendAmeLabel(info, "BIFROST-GGAEAD-KEYS-v1")
  appendGgField(info, context)
  result = deriveGb3Hkdf(rootKey, @[], info, ggAeadKeyMaterialBytes, c)

proc prepareGgGimliStreams*(K, N: openArray[ByteSeq],
    outputBytes: int): seq[PreparedStream] {.role: truthBuilder,
    tag: {tagAppApi, tagCryptoBoundary, tagGgAead}.} =
  ## K/N/outputBytes: GGAEAD message materials, nonces, and prefetched bytes.
  var
    keys: seq[ByteSeq] = @[]
    streams: seq[ByteSeq] = @[]
    key: ByteSeq = @[]
    i: int = 0
  defer:
    i = 0
    while i < keys.len:
      secureClearAmeBytes(keys[i])
      i = i + 1
  if K.len != N.len:
    raise newException(ValueError,
      "GGAEAD prepared key and nonce counts differ")
  keys.setLen(K.len)
  result.setLen(K.len)
  while i < K.len:
    key = ggKeySlice(K[i], 0)
    keys[i] = move(key)
    i = i + 1
  streams = prepareGimliStreams(keys, N, outputBytes)
  i = 0
  while i < result.len:
    result[i].key = @keys[i]
    result[i].nonce = @N[i]
    result[i].bytes = move(streams[i])
    i = i + 1
  i = 0

proc ggPreparedStreamMatches(K, nonce: openArray[uint8],
    P: PreparedStream): bool {.role: parser,
    tag: {tagCryptoBoundary, tagGgAead, tagValidation}.} =
  ## K/nonce/P: GGAEAD Gimli subkey and nonce matched to prepared metadata.
  var
    key: ByteSeq = @[]
  if K.len != ggAeadKeyMaterialBytes or nonce.len != ggAeadNonceBytes:
    return
  key = ggKeySlice(K, 0)
  result = P.key.len == key.len and P.nonce.len == nonce.len and
    constantTimeEqualAme(P.key, key) and constantTimeEqualAme(P.nonce, nonce)
  secureClearAmeBytes(key)

proc sealGgAead*(K, nonce, plaintext: openArray[uint8],
    aad: openArray[uint8] = []): GgAeadCiphertext {.role: encryptor,
    tag: {tagAppApi, tagCryptoBoundary, tagGgAead}.} =
  ## K/nonce/plaintext/aad: two keys, unique nonce, payload, and binding bytes.
  var
    cipherKey: ByteSeq = @[]
    macKey: ByteSeq = @[]
    authInput: ByteSeq = @[]
  defer:
    secureClearAmeBytes(cipherKey)
    secureClearAmeBytes(macKey)
    secureClearAmeBytes(authInput)
  if K.len != ggAeadKeyMaterialBytes:
    raise newException(ValueError, "GGAEAD key material must be 64 bytes")
  if nonce.len != ggAeadNonceBytes:
    raise newException(ValueError, "GGAEAD nonce must be 24 bytes")
  cipherKey = ggKeySlice(K, 0)
  macKey = ggKeySlice(K, gb3BlockBytes)
  result.ciphertext = tyr_gimli.gimliStreamXor(cipherKey, nonce, plaintext)
  authInput = buildGgAuthInput(nonce, aad, result.ciphertext)
  result.authTag = tyr_hmac.gimliCustomHmac(macKey, authInput,
    ggAeadTagBytes)

proc sealGgAeadPrepared*(K, nonce, plaintext: openArray[uint8],
    P: PreparedStream,
    aad: openArray[uint8] = []): GgAeadCiphertext {.role: encryptor,
    tag: {tagAppApi, tagCryptoBoundary, tagGgAead}.} =
  ## K/nonce/plaintext/P/aad: one message with a bound prefetched stream.
  var
    macKey: ByteSeq = @[]
    authInput: ByteSeq = @[]
    i: int = 0
  defer:
    secureClearAmeBytes(macKey)
    secureClearAmeBytes(authInput)
  if K.len != ggAeadKeyMaterialBytes:
    raise newException(ValueError, "GGAEAD key material must be 64 bytes")
  if nonce.len != ggAeadNonceBytes:
    raise newException(ValueError, "GGAEAD nonce must be 24 bytes")
  if P.bytes.len < plaintext.len:
    raise newException(ValueError, "GGAEAD prepared Gimli stream is too short")
  if not ggPreparedStreamMatches(K, nonce, P):
    raise newException(ValueError, "GGAEAD prepared Gimli stream binding differs")
  result.ciphertext.setLen(plaintext.len)
  while i < plaintext.len:
    result.ciphertext[i] = plaintext[i] xor P.bytes[i]
    i = i + 1
  macKey = ggKeySlice(K, gb3BlockBytes)
  authInput = buildGgAuthInput(nonce, aad, result.ciphertext)
  result.authTag = tyr_hmac.gimliCustomHmac(macKey, authInput,
    ggAeadTagBytes)

proc openGgAead*(K, nonce: openArray[uint8], sealed: GgAeadCiphertext,
    aad: openArray[uint8] = []): tuple[ok: bool, payload: ByteSeq] {.
    role: decryptor,
    tag: {tagAppApi, tagCryptoBoundary, tagGgAead}.} =
  ## K/nonce/sealed/aad: two keys, nonce, detached envelope, and binding bytes.
  var
    cipherKey: ByteSeq = @[]
    macKey: ByteSeq = @[]
    authInput: ByteSeq = @[]
    expected: ByteSeq = @[]
  defer:
    secureClearAmeBytes(cipherKey)
    secureClearAmeBytes(macKey)
    secureClearAmeBytes(authInput)
    secureClearAmeBytes(expected)
  if K.len != ggAeadKeyMaterialBytes or nonce.len != ggAeadNonceBytes or
      sealed.authTag.len != ggAeadTagBytes:
    return
  macKey = ggKeySlice(K, gb3BlockBytes)
  authInput = buildGgAuthInput(nonce, aad, sealed.ciphertext)
  expected = tyr_hmac.gimliCustomHmac(macKey, authInput, ggAeadTagBytes)
  result.ok = constantTimeEqualAme(expected, sealed.authTag)
  if result.ok:
    cipherKey = ggKeySlice(K, 0)
    result.payload = tyr_gimli.gimliStreamXor(cipherKey, nonce,
      sealed.ciphertext)

proc openGgAeadPrepared*(K, nonce: openArray[uint8],
    sealed: GgAeadCiphertext, P: PreparedStream,
    aad: openArray[uint8] = []): tuple[ok: bool, payload: ByteSeq] {.
    role: decryptor,
    tag: {tagAppApi, tagCryptoBoundary, tagGgAead}.} =
  ## K/nonce/sealed/P/aad: authenticated message and bound prefetched bytes.
  var
    macKey: ByteSeq = @[]
    authInput: ByteSeq = @[]
    expected: ByteSeq = @[]
    i: int = 0
  defer:
    secureClearAmeBytes(macKey)
    secureClearAmeBytes(authInput)
    secureClearAmeBytes(expected)
  if K.len != ggAeadKeyMaterialBytes or nonce.len != ggAeadNonceBytes or
      sealed.authTag.len != ggAeadTagBytes or
      P.bytes.len < sealed.ciphertext.len or
      not ggPreparedStreamMatches(K, nonce, P):
    return
  macKey = ggKeySlice(K, gb3BlockBytes)
  authInput = buildGgAuthInput(nonce, aad, sealed.ciphertext)
  expected = tyr_hmac.gimliCustomHmac(macKey, authInput, ggAeadTagBytes)
  result.ok = constantTimeEqualAme(expected, sealed.authTag)
  if result.ok:
    result.payload.setLen(sealed.ciphertext.len)
    while i < sealed.ciphertext.len:
      result.payload[i] = sealed.ciphertext[i] xor P.bytes[i]
      i = i + 1
