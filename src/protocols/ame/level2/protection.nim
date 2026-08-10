## -------------------------------------------------------------------------
## AME Protection <- immutable layout and tier-selected protection layers
## -------------------------------------------------------------------------

import protocols/wrapper/basic_api as tyr_basic
import protocols/wrapper/helpers/algorithms as tyr_alg
import protocols/custom_crypto/blake3 as tyr_blake3

import ../../types
import ../types
import ../level0/bytes
import ../level1/exchange_paths
import ../level1/suites
import ../level1/derivation
import ../../../analysis_pragmas

proc nonceLen(a: AmeCipherAlgorithm): int {.role: helper.} =
  ## a: exact cipher whose native nonce size is returned.
  case a
  of acaXChaCha20, acaGimli: result = 24
  of acaAesCtr: result = 16
  of acaChaCha20: result = 12

proc ameProtectionNonceLen*(L: AmeSuiteLayout,
    t: AmeMaskTier): int {.role: parser.} =
  ## L/t: layout and tier whose selected cipher nonce lengths are summed.
  var i: int = 0
  validateAmeTier(L, t)
  while i < int(L.ciphers.length):
    if algorithmSlotSelected(t.masks.cipher, i):
      result = result + nonceLen(L.ciphers.algorithms[i])
    i = i + 1

proc randomAmeNonce*(L: AmeSuiteLayout,
    t: AmeMaskTier): ByteSeq {.role: dataFetcher.} =
  ## L/t: immutable layout and tier determining nonce bytes.
  result = tyr_basic.cryptoRand(tyr_alg.raSystem, ameProtectionNonceLen(L, t))

proc nonceSlice(A: openArray[byte], offset: int,
    a: AmeCipherAlgorithm): ByteSeq {.role: parser.} =
  ## A/offset/a: nonce prefix, current offset, and cipher slot.
  var
    n: int = nonceLen(a)
    i: int = 0
  if offset < 0 or offset > A.len - n:
    raise newException(ValueError, "AME nonce prefix is too short")
  result = newSeq[byte](n)
  while i < n:
    result[i] = A[offset + i]
    i = i + 1

proc requireProtection(L: AmeSuiteLayout, t: AmeMaskTier,
    E: AmeExchangeState) {.
    role: parser.} =
  ## L/t/E: immutable layout, active tier, and exchange state to validate.
  validateAmeTier(L, t)
  if not kemLayoutsEquivalent(L.kems, E.algorithms):
    raise newException(ValueError, "AME protection layout mismatch")
  if (t.masks.kem and not E.activeMask) != 0'u8:
    raise newException(ValueError, "AME protection tier lacks a KEM secret")

proc cryptPayload(L: AmeSuiteLayout, t: AmeMaskTier, E: AmeExchangeState,
    nonce, msg, keyContext: openArray[byte]): ByteSeq {.role: orchestrator.} =
  ## L/t/E/nonce/msg/keyContext: tier, state, input, and channel binding.
  var
    key: ByteSeq = @[]
    n: ByteSeq = @[]
    label: string = ""
    offset: int = 0
    i: int = 0
  requireProtection(L, t, E)
  if nonce.len != ameProtectionNonceLen(L, t):
    raise newException(ValueError, "AME nonce length mismatch")
  result = @msg
  while i < int(L.ciphers.length):
    if algorithmSlotSelected(t.masks.cipher, i):
      label = "cipher:" & $uint8(ord(L.ciphers.algorithms[i])) & ":" & $i
      key = deriveAmeLayerKey(E, L, t, label, context = keyContext)
      n = nonceSlice(nonce, offset, L.ciphers.algorithms[i])
      result = tyr_basic.symEnc(toTyrCipher(L.ciphers.algorithms[i]), key, n,
        result)
      offset = offset + n.len
    i = i + 1

proc nativeMacLen(a: AmeMacAlgorithm, wanted: int): int {.role: helper.} =
  ## a/wanted: MAC primitive and requested common tag length.
  if a == amaPoly1305:
    return 16
  if a == amaSha3 and wanted <= 28:
    return 28
  result = wanted

proc normalizeMac(A: openArray[byte], wanted: int): ByteSeq {.role: helper.} =
  ## A/wanted: native tag expanded or compressed into the common tag length.
  var
    seed: ByteSeq = @[]
  if A.len == wanted:
    return @A
  appendAmeLabel(seed, "AME-MAC-NORMALIZE-v1")
  appendAmeU32(seed, uint32(A.len))
  appendAmeBytes(seed, A)
  result = tyr_blake3.blake3Hash(seed, wanted)

proc authenticateAme*(L: AmeSuiteLayout, t: AmeMaskTier, E: AmeExchangeState,
    data: openArray[byte], authTagLen: int = ameProtectionAuthTagLen,
    keyContext: openArray[byte] = []): ByteSeq {.
    role: orchestrator.} =
  ## L/t/E/data/authTagLen/keyContext: MAC inputs and channel binding.
  var
    key: ByteSeq = @[]
    raw: ByteSeq = @[]
    tag: ByteSeq = @[]
    label: string = ""
    i: int = 0
  requireProtection(L, t, E)
  if authTagLen <= 0:
    raise newException(ValueError, "AME authentication tag length is invalid")
  result = newSeq[byte](authTagLen)
  while i < int(L.macs.length):
    if algorithmSlotSelected(t.masks.mac, i):
      label = "mac:" & $uint8(ord(L.macs.algorithms[i])) & ":" & $i
      key = deriveAmeLayerKey(E, L, t, label, context = keyContext)
      raw = tyr_basic.hmacCreate(toTyrMac(L.macs.algorithms[i]), key, @data,
        nativeMacLen(L.macs.algorithms[i], authTagLen))
      tag = normalizeMac(raw, authTagLen)
      xorAmeInto(result, tag)
    i = i + 1

proc authInput(L: AmeSuiteLayout, t: AmeMaskTier, nonce, aad,
    cipher: openArray[byte]): ByteSeq {.role: truthBuilder.} =
  ## L/t/nonce/aad/cipher: canonical authenticated fields.
  appendAmeLabel(result, "AME-PROTECTED-TIER-v2")
  appendAmeBytes(result, encodeAmeSuiteLayout(L))
  appendAmeBytes(result, encodeAmeMaskTier(t))
  appendAmeU32(result, uint32(aad.len))
  appendAmeBytes(result, aad)
  appendAmeU32(result, uint32(nonce.len))
  appendAmeBytes(result, nonce)
  appendAmeU32(result, uint32(cipher.len))
  appendAmeBytes(result, cipher)

proc protectAmeMessageWithNonce*(L: AmeSuiteLayout, t: AmeMaskTier,
    E: AmeExchangeState,
    nonce, msg: openArray[byte], aad: openArray[byte] = [],
    keyContext: openArray[byte] = []):
    AmeProtectedMessage {.role: orchestrator.} =
  ## L/t/E/nonce/msg/aad: exact persisted-message inputs. Callers that store a
  ## nonce beside ciphertext use this entrypoint to replay the same nonce at
  ## open time.
  result.payload = cryptPayload(L, t, E, nonce, msg, keyContext)
  result.authTag = authenticateAme(L, t, E,
    authInput(L, t, nonce, aad, result.payload), keyContext = keyContext)

proc protectAmeMessage*(L: AmeSuiteLayout, t: AmeMaskTier,
    E: AmeExchangeState,
    msg: openArray[byte], aad: openArray[byte] = [],
    keyContext: openArray[byte] = []): tuple[
    message: AmeProtectedMessage, nonce: ByteSeq] {.role: orchestrator.} =
  ## L/t/E/msg/aad: tier-selected protection with a fresh random nonce.
  result.nonce = randomAmeNonce(L, t)
  result.message = protectAmeMessageWithNonce(L, t, E, result.nonce, msg, aad,
    keyContext)

proc openAmeMessage*(L: AmeSuiteLayout, t: AmeMaskTier, E: AmeExchangeState,
    nonce: openArray[byte], message: AmeProtectedMessage,
    aad: openArray[byte] = [], keyContext: openArray[byte] = []): tuple[
    ok: bool, payload: ByteSeq] {.
    role: orchestrator.} =
  ## L/t/E/nonce/message/aad: exact authenticated open inputs.
  ## The received tag length is never trusted. A caller that recomputed the
  ## expected tag at `message.authTag.len` would let a sender truncate the tag
  ## to one byte and forge a message with probability 1/256, so the full
  ## `ameProtectionAuthTagLen` is required before any comparison happens.
  var
    expected: ByteSeq = @[]
  if message.authTag.len != ameProtectionAuthTagLen:
    return
  expected = authenticateAme(L, t, E,
    authInput(L, t, nonce, aad, message.payload), ameProtectionAuthTagLen,
    keyContext)
  if not constantTimeEqualAme(expected, message.authTag):
    return
  result.payload = cryptPayload(L, t, E, nonce, message.payload, keyContext)
  result.ok = true
