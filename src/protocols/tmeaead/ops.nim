## -------------------------------------------------------------------------
## TMEAEAD <- XChaCha20, AES-CTR, Gimli, and XOR-combined authentication
## -------------------------------------------------------------------------

import protocols/custom_crypto/aes_ctr as tyr_aes
import protocols/custom_crypto/blake3 as tyr_blake3
import protocols/custom_crypto/gimli_sponge as tyr_gimli
import protocols/custom_crypto/poly1305 as tyr_poly
import protocols/custom_crypto/xchacha20 as tyr_xchacha

import ../types as core_types
import ../ame/level0/bytes
import ../fomke/types as fomke_types
import ../fomke/level0/gb3hkdf
import ../preparation/types
import ../preparation/gimli_batch
import ../preparation/xchacha_streams
import ./types
import ../../analysis_pragmas

proc tmeKeySlice(K: openArray[uint8], offset: int): ByteSeq {.role: parser,
    tag: {tagCryptoBoundary, tagTmeAead}.} =
  ## K/offset: complete TMEAEAD material and one 32-byte subkey offset.
  var
    i: int = 0
  if K.len != tmeAeadKeyMaterialBytes or offset < 0 or
      offset > K.len - gb3BlockBytes:
    raise newException(ValueError,
      "TMEAEAD key material must contain five 32-byte keys")
  result.setLen(gb3BlockBytes)
  while i < gb3BlockBytes:
    result[i] = K[offset + i]
    i = i + 1

proc appendTmeField(A: var ByteSeq, B: openArray[uint8]) {.
    role: stateController, tag: {tagTmeAead}.} =
  ## A/B: destination and one length-framed authenticated field.
  if uint64(B.len) > uint64(high(uint32)):
    raise newException(ValueError, "TMEAEAD field exceeds u32")
  appendAmeU32(A, uint32(B.len))
  appendAmeBytes(A, B)

proc buildTmeAuthInput(nonce, aad, ciphertext: openArray[uint8]): ByteSeq {.
    role: truthBuilder, tag: {tagCryptoBoundary, tagTmeAead}.} =
  ## nonce/aad/ciphertext: canonical encrypt-then-authenticate fields.
  appendAmeLabel(result, "BIFROST-TMEAEAD-v1")
  appendAmeU16(result, 1'u16)
  appendTmeField(result, aad)
  appendTmeField(result, nonce)
  appendTmeField(result, ciphertext)

proc deriveTmeAesNonce(key, nonce, aad: openArray[uint8]): ByteSeq {.
    role: truthBuilder, tag: {tagCryptoBoundary, tagTmeAead}.} =
  ## key/nonce/aad: AES key and message binding used for its 16-byte counter.
  var
    material: ByteSeq = @[]
  appendAmeLabel(material, "TMEAEAD-AES-NONCE-v1")
  appendTmeField(material, nonce)
  appendTmeField(material, aad)
  result = tyr_blake3.blake3KeyedHash(key, material, 16)

proc deriveTmePolyKey(root, nonce: openArray[uint8]): ByteSeq {.
    role: truthBuilder, tag: {tagCryptoBoundary, tagTmeAead}.} =
  ## root/nonce: independent root and unique message nonce for one Poly1305 key.
  var
    material: ByteSeq = @[]
  appendAmeLabel(material, "TMEAEAD-POLY1305-ONE-TIME-v1")
  appendTmeField(material, nonce)
  result = tyr_blake3.blake3KeyedHash(root, material, gb3BlockBytes)

proc computeTmeTag(gimliKey, polyRoot, nonce, authInput: openArray[uint8]):
    ByteSeq {.role: truthBuilder,
    tag: {tagCryptoBoundary, tagTmeAead}.} =
  ## gimliKey/polyRoot/nonce/authInput: independent MAC inputs and packet bytes.
  var
    polyKey: ByteSeq = @[]
    gimliTag: ByteSeq = @[]
    polyTag: ByteSeq = @[]
    polyMaterial: ByteSeq = @[]
    polyExpanded: ByteSeq = @[]
  polyKey = deriveTmePolyKey(polyRoot, nonce)
  gimliTag = tyr_gimli.gimliTag(gimliKey, nonce, authInput, tmeAeadTagBytes)
  polyTag = tyr_poly.poly1305Tag(polyKey, authInput)
  appendAmeLabel(polyMaterial, "TMEAEAD-POLY1305-EXPAND-v1")
  appendTmeField(polyMaterial, polyTag)
  polyExpanded = tyr_blake3.blake3KeyedHash(polyKey, polyMaterial,
    tmeAeadTagBytes)
  result = xorAmeOverlay(gimliTag, polyExpanded)
  secureClearAmeBytes(polyKey)
  secureClearAmeBytes(gimliTag)
  secureClearAmeBytes(polyTag)
  secureClearAmeBytes(polyMaterial)
  secureClearAmeBytes(polyExpanded)

proc tmeAesBackend(inputBytes: int): tyr_aes.AesCtrBackend {.
    role: configurator, tag: {tagCryptoBoundary, tagTmeAead}.} =
  ## inputBytes: payload size mapped to a backend without unused wide tails.
  when defined(avx2):
    if inputBytes >= 32 and (inputBytes mod 32) == 0:
      return tyr_aes.acbAvx2
  when defined(sse2):
    if inputBytes >= 16:
      return tyr_aes.acbSse2
  when defined(neon) or defined(arm64) or defined(aarch64):
    if inputBytes >= 16:
      return tyr_aes.acbNeon
  result = tyr_aes.acbScalar

proc tmeAesSimdWidth*(inputBytes: int): int {.role: configurator,
    tag: {tagAppApi, tagCryptoBoundary, tagTmeAead}.} =
  ## inputBytes: selected online AES-CTR XOR width for this payload size.
  case tmeAesBackend(inputBytes)
  of tyr_aes.acbAvx2:
    result = 32
  of tyr_aes.acbSse2, tyr_aes.acbNeon:
    result = 16
  else:
    result = 1

proc cryptTmePayload(K, nonce, aad, input: openArray[uint8]): ByteSeq {.
    role: orchestrator, tag: {tagCryptoBoundary, tagTmeAead}.} =
  ## K/nonce/aad/input: five-key material, nonce, binding, and payload bytes.
  var
    xKey: ByteSeq = @[]
    aesKey: ByteSeq = @[]
    gimliKey: ByteSeq = @[]
    aesNonce: ByteSeq = @[]
  if nonce.len != tmeAeadNonceBytes:
    raise newException(ValueError, "TMEAEAD nonce must be 24 bytes")
  xKey = tmeKeySlice(K, 0)
  aesKey = tmeKeySlice(K, 32)
  gimliKey = tmeKeySlice(K, 64)
  aesNonce = deriveTmeAesNonce(aesKey, nonce, aad)
  result = tyr_xchacha.xchacha20Xor(xKey, nonce, input)
  result = tyr_aes.aesCtrXor(aesKey, aesNonce, result,
    tmeAesBackend(result.len))
  result = tyr_gimli.gimliStreamXor(gimliKey, nonce, result)
  secureClearAmeBytes(xKey)
  secureClearAmeBytes(aesKey)
  secureClearAmeBytes(gimliKey)
  secureClearAmeBytes(aesNonce)

proc cryptTmePayloadPrepared(K, nonce, aad, input,
    gimliStream, xChaChaStream: openArray[uint8]): ByteSeq {.role: orchestrator,
    tag: {tagCryptoBoundary, tagTmeAead}.} =
  ## K/nonce/aad/input/streams: prefetched XChaCha/Gimli and online AES.
  var
    aesKey: ByteSeq = @[]
    aesNonce: ByteSeq = @[]
    i: int = 0
  if nonce.len != tmeAeadNonceBytes:
    raise newException(ValueError, "TMEAEAD nonce must be 24 bytes")
  if gimliStream.len < input.len:
    raise newException(ValueError, "TMEAEAD prepared Gimli stream is too short")
  if xChaChaStream.len < input.len:
    raise newException(ValueError,
      "TMEAEAD prepared XChaCha stream is too short")
  aesKey = tmeKeySlice(K, 32)
  aesNonce = deriveTmeAesNonce(aesKey, nonce, aad)
  result.setLen(input.len)
  while i < input.len:
    result[i] = input[i] xor xChaChaStream[i]
    i = i + 1
  result = tyr_aes.aesCtrXor(aesKey, aesNonce, result,
    tmeAesBackend(result.len))
  i = 0
  while i < result.len:
    result[i] = result[i] xor gimliStream[i]
    i = i + 1
  secureClearAmeBytes(aesKey)
  secureClearAmeBytes(aesNonce)

proc prepareTmeGimliStreams*(K, N: openArray[ByteSeq],
    outputBytes: int): seq[PreparedStream] {.role: truthBuilder,
    tag: {tagAppApi, tagCryptoBoundary, tagTmeAead}.} =
  ## K/N/outputBytes: TME message materials, nonces, and bytes to precompute.
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
      "TMEAEAD prepared key and nonce counts differ")
  keys.setLen(K.len)
  result.setLen(K.len)
  while i < K.len:
    key = tmeKeySlice(K[i], 64)
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

proc prepareTmeXChaChaStreams*(K, N: openArray[ByteSeq],
    outputBytes: int): seq[PreparedStream] {.role: truthBuilder,
    tag: {tagAppApi, tagCryptoBoundary, tagTmeAead}.} =
  ## K/N/outputBytes: TME message materials, nonces, and XChaCha bytes.
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
      "TMEAEAD prepared key and nonce counts differ")
  keys.setLen(K.len)
  result.setLen(K.len)
  while i < K.len:
    key = tmeKeySlice(K[i], 0)
    keys[i] = move(key)
    i = i + 1
  streams = prepareXChaChaStreamRows(keys, N, outputBytes)
  i = 0
  while i < result.len:
    result[i].key = @keys[i]
    result[i].nonce = @N[i]
    result[i].bytes = move(streams[i])
    i = i + 1
  i = 0

proc tmeGimliPreparedStreamMatches(K, nonce: openArray[uint8],
    P: PreparedStream): bool {.role: parser,
    tag: {tagCryptoBoundary, tagTmeAead, tagValidation}.} =
  ## K/nonce/P: TME Gimli subkey and nonce matched to prepared stream metadata.
  var
    key: ByteSeq = @[]
  if K.len != tmeAeadKeyMaterialBytes or nonce.len != tmeAeadNonceBytes:
    return
  key = tmeKeySlice(K, 64)
  result = P.key.len == key.len and P.nonce.len == nonce.len and
    constantTimeEqualAme(P.key, key) and constantTimeEqualAme(P.nonce, nonce)
  secureClearAmeBytes(key)

proc tmeXChaChaPreparedStreamMatches(K, nonce: openArray[uint8],
    P: PreparedStream): bool {.role: parser,
    tag: {tagCryptoBoundary, tagTmeAead, tagValidation}.} =
  ## K/nonce/P: TME XChaCha subkey and nonce matched to prepared metadata.
  var
    key: ByteSeq = @[]
  if K.len != tmeAeadKeyMaterialBytes or nonce.len != tmeAeadNonceBytes:
    return
  key = tmeKeySlice(K, 0)
  result = P.key.len == key.len and P.nonce.len == nonce.len and
    constantTimeEqualAme(P.key, key) and constantTimeEqualAme(P.nonce, nonce)
  secureClearAmeBytes(key)

proc deriveTmeAeadKeyMaterial*(rootKey, context: openArray[uint8],
    c: Gb3KdfConfig = initGb3KdfConfig()): ByteSeq {.role: truthBuilder,
    tag: {tagAppApi, tagCryptoBoundary, tagKdf, tagTmeAead}.} =
  ## rootKey/context/c: compact root, purpose binding, and GB3HKDF policy.
  result = deriveGb3Hkdf(rootKey, @[], context, tmeAeadKeyMaterialBytes, c)

proc cryptTmeAead*(K, nonce, input: openArray[uint8],
    aad: openArray[uint8] = []): ByteSeq {.role: encryptor,
    tag: {tagAppApi, tagCryptoBoundary, tagTmeAead}.} =
  ## K/nonce/input/aad: stream-only transform. Same call encrypts and decrypts.
  ## Does not compute or check the authentication tag.
  if K.len != tmeAeadKeyMaterialBytes:
    raise newException(ValueError, "TMEAEAD key material must be 160 bytes")
  result = cryptTmePayload(K, nonce, aad, input)

proc tagTmeAead*(K, nonce, ciphertext: openArray[uint8],
    aad: openArray[uint8] = []): ByteSeq {.role: truthBuilder,
    tag: {tagAppApi, tagCryptoBoundary, tagTmeAead}.} =
  ## K/nonce/ciphertext/aad: MAC-only over an already-transformed payload.
  ## Use with the HMAC/integrity key path when callers only need a tag.
  var
    gimliMacKey: ByteSeq = @[]
    polyRoot: ByteSeq = @[]
    authInput: ByteSeq = @[]
  if K.len != tmeAeadKeyMaterialBytes:
    raise newException(ValueError, "TMEAEAD key material must be 160 bytes")
  if nonce.len != tmeAeadNonceBytes:
    raise newException(ValueError, "TMEAEAD nonce must be 24 bytes")
  gimliMacKey = tmeKeySlice(K, 96)
  polyRoot = tmeKeySlice(K, 128)
  authInput = buildTmeAuthInput(nonce, aad, ciphertext)
  result = computeTmeTag(gimliMacKey, polyRoot, nonce, authInput)
  secureClearAmeBytes(gimliMacKey)
  secureClearAmeBytes(polyRoot)
  secureClearAmeBytes(authInput)

proc verifyTmeAeadTag*(K, nonce, ciphertext, authTag: openArray[uint8],
    aad: openArray[uint8] = []): bool {.role: parser,
    tag: {tagAppApi, tagCryptoBoundary, tagTmeAead, tagValidation}.} =
  ## K/nonce/ciphertext/authTag/aad: tag check without decrypting payload bytes.
  var
    expected: ByteSeq = @[]
  if K.len != tmeAeadKeyMaterialBytes or nonce.len != tmeAeadNonceBytes or
      authTag.len != tmeAeadTagBytes:
    return false
  expected = tagTmeAead(K, nonce, ciphertext, aad)
  result = constantTimeEqualAme(expected, authTag)
  secureClearAmeBytes(expected)

proc hmacTmeAead*(rootKey, message: openArray[uint8],
    context: openArray[uint8] = []): ByteSeq {.role: truthBuilder,
    tag: {tagAppApi, tagCryptoBoundary, tagTmeAead}.} =
  ## rootKey/message/context: keyed TME MAC without encrypting payload bytes.
  ## Expands rootKey through the TME key domain bound to context, derives one
  ## deterministic 24-byte nonce from that domain, then returns tagTmeAead over
  ## message. Use for integrity trees that only need authentication.
  var
    keyMaterial: ByteSeq = @[]
    keyInfo: ByteSeq = @[]
    nonceMaterial: ByteSeq = @[]
    nonce: ByteSeq = @[]
    aad: ByteSeq = @[]
  appendAmeLabel(keyInfo, "BIFROST-TME-HMAC-v1")
  appendTmeField(keyInfo, context)
  keyMaterial = deriveTmeAeadKeyMaterial(rootKey, keyInfo)
  appendAmeLabel(nonceMaterial, "BIFROST-TME-HMAC-NONCE-v1")
  appendTmeField(nonceMaterial, context)
  appendTmeField(nonceMaterial, rootKey)
  nonce = tyr_blake3.blake3KeyedHash(keyMaterial.toOpenArray(0, 31),
    nonceMaterial, tmeAeadNonceBytes)
  appendAmeLabel(aad, "BIFROST-TME-HMAC-AAD-v1")
  appendTmeField(aad, context)
  result = tagTmeAead(keyMaterial, nonce, message, aad)
  secureClearAmeBytes(keyMaterial)
  secureClearAmeBytes(keyInfo)
  secureClearAmeBytes(nonceMaterial)
  secureClearAmeBytes(nonce)
  secureClearAmeBytes(aad)

proc verifyHmacTmeAead*(rootKey, message, authTag: openArray[uint8],
    context: openArray[uint8] = []): bool {.role: parser,
    tag: {tagAppApi, tagCryptoBoundary, tagTmeAead, tagValidation}.} =
  ## rootKey/message/authTag/context: check hmacTmeAead without decryption.
  var
    expected: ByteSeq = @[]
  if authTag.len != tmeAeadTagBytes:
    return false
  expected = hmacTmeAead(rootKey, message, context)
  result = constantTimeEqualAme(expected, authTag)
  secureClearAmeBytes(expected)

proc sealTmeAead*(K, nonce, plaintext: openArray[uint8],
    aad: openArray[uint8] = []): TmeAeadCiphertext {.role: encryptor,
    tag: {tagAppApi, tagCryptoBoundary, tagTmeAead}.} =
  ## K/nonce/plaintext/aad: five keys, unique nonce, payload, and binding bytes.
  if K.len != tmeAeadKeyMaterialBytes:
    raise newException(ValueError, "TMEAEAD key material must be 160 bytes")
  result.ciphertext = cryptTmeAead(K, nonce, plaintext, aad)
  result.authTag = tagTmeAead(K, nonce, result.ciphertext, aad)

proc sealTmeAeadPrepared*(K, nonce, plaintext: openArray[uint8],
    G: PreparedStream, X: PreparedStream,
    aad: openArray[uint8] = []): TmeAeadCiphertext {.role: encryptor,
    tag: {tagAppApi, tagCryptoBoundary, tagTmeAead}.} =
  ## K/nonce/plaintext/G/X/aad: one message with both bound streams.
  var
    gimliMacKey: ByteSeq = @[]
    polyRoot: ByteSeq = @[]
    authInput: ByteSeq = @[]
  if K.len != tmeAeadKeyMaterialBytes:
    raise newException(ValueError, "TMEAEAD key material must be 160 bytes")
  if not tmeGimliPreparedStreamMatches(K, nonce, G):
    raise newException(ValueError, "TMEAEAD prepared Gimli stream binding differs")
  if not tmeXChaChaPreparedStreamMatches(K, nonce, X):
    raise newException(ValueError,
      "TMEAEAD prepared XChaCha stream binding differs")
  result.ciphertext = cryptTmePayloadPrepared(K, nonce, aad, plaintext,
    G.bytes, X.bytes)
  gimliMacKey = tmeKeySlice(K, 96)
  polyRoot = tmeKeySlice(K, 128)
  authInput = buildTmeAuthInput(nonce, aad, result.ciphertext)
  result.authTag = computeTmeTag(gimliMacKey, polyRoot, nonce, authInput)
  secureClearAmeBytes(gimliMacKey)
  secureClearAmeBytes(polyRoot)
  secureClearAmeBytes(authInput)

proc openTmeAead*(K, nonce: openArray[uint8], sealed: TmeAeadCiphertext,
    aad: openArray[uint8] = []): tuple[ok: bool, payload: ByteSeq] {.
    role: decryptor,
    tag: {tagAppApi, tagCryptoBoundary, tagTmeAead}.} =
  ## K/nonce/sealed/aad: five keys, nonce, detached envelope, and binding bytes.
  if K.len != tmeAeadKeyMaterialBytes or nonce.len != tmeAeadNonceBytes or
      sealed.authTag.len != tmeAeadTagBytes:
    return
  result.ok = verifyTmeAeadTag(K, nonce, sealed.ciphertext, sealed.authTag, aad)
  if result.ok:
    result.payload = cryptTmeAead(K, nonce, sealed.ciphertext, aad)

proc openTmeAeadPrepared*(K, nonce: openArray[uint8],
    sealed: TmeAeadCiphertext, G: PreparedStream,
    X: PreparedStream,
    aad: openArray[uint8] = []): tuple[ok: bool, payload: ByteSeq] {.
    role: decryptor,
    tag: {tagAppApi, tagCryptoBoundary, tagTmeAead}.} =
  ## K/nonce/sealed/G/X/aad: authenticated message and bound stream bytes.
  var
    gimliMacKey: ByteSeq = @[]
    polyRoot: ByteSeq = @[]
    authInput: ByteSeq = @[]
    expected: ByteSeq = @[]
  if K.len != tmeAeadKeyMaterialBytes or nonce.len != tmeAeadNonceBytes or
      sealed.authTag.len != tmeAeadTagBytes or
      G.bytes.len < sealed.ciphertext.len or
      X.bytes.len < sealed.ciphertext.len or
      not tmeGimliPreparedStreamMatches(K, nonce, G) or
      not tmeXChaChaPreparedStreamMatches(K, nonce, X):
    return
  gimliMacKey = tmeKeySlice(K, 96)
  polyRoot = tmeKeySlice(K, 128)
  authInput = buildTmeAuthInput(nonce, aad, sealed.ciphertext)
  expected = computeTmeTag(gimliMacKey, polyRoot, nonce, authInput)
  result.ok = constantTimeEqualAme(expected, sealed.authTag)
  if result.ok:
    result.payload = cryptTmePayloadPrepared(K, nonce, aad,
      sealed.ciphertext, G.bytes, X.bytes)
  secureClearAmeBytes(gimliMacKey)
  secureClearAmeBytes(polyRoot)
  secureClearAmeBytes(authInput)
  secureClearAmeBytes(expected)
