## -------------------------------------------------------------------------
## AME Protection <- at-rest sealing keyed straight from the exchange
## -------------------------------------------------------------------------
##
## This is NOT the path a frame takes. Live traffic is protected once, by the
## message ratchet (see protocols/fomke). This module exists for the other
## case: bytes that have to sit still somewhere -- a package on disk, a blob
## handed to a repair layer -- where there is no ratchet position to derive
## from and the nonce must therefore be stored beside the ciphertext.
##
##   live frame      plaintext -> ratchet step -> ciphertext + tag
##   package at rest plaintext -> random nonce  -> ciphertext + tag + nonce
##
## Both use the SAME slot construction from level1/tier_aead: every
## switched-on cipher XORed in turn, every switched-on authenticator XORed
## into one tag. Only where the key material comes from differs.
##
## The key block that construction wants looks like this:
##
##   [ nonce ][ cipher key 0 ][ cipher key 1 ][ mac key 0 ][ mac key 1 ]
##
## so this file derives the key part from the exchange and puts the caller's
## nonce in front of it.

import tyr/helpers/random as tyr_random

import tyr/helpers/tiers as tyr_alg

import ../../types
import ../types
import ../level0/bytes
import ../level1/exchange_paths
import ../level1/suites
import ../level1/derivation
import ../level1/tier_aead
import bifrostPragmas

export ameTierNonceLen, ameCipherNonceLen

proc ameProtectionNonceLen*(L: AmeSuiteLayout,
    t: AmeMaskTier): int {.role: parser.} =
  ## L/t: how many nonce bytes this tier needs in total. One switched-on
  ## cipher contributes its own nonce size; two contribute both, end to end.
  result = ameTierNonceLen(L, t)

proc randomAmeNonce*(L: AmeSuiteLayout,
    t: AmeMaskTier): ByteSeq {.role: dataFetcher.} =
  ## L/t: fresh nonce of exactly the size this tier needs.
  result = tyr_random.cryptoRand(tyr_alg.raSystem, ameProtectionNonceLen(L, t))

proc requireProtection(L: AmeSuiteLayout, t: AmeMaskTier,
    E: AmeExchangeState) {.role: parser.} =
  ## L/t/E: immutable layout, active tier, and exchange state to validate.
  validateAmeTier(L, t)
  if not kemLayoutsEquivalent(L.kems, E.algorithms):
    raise newException(ValueError, "AME protection layout mismatch")
  if (t.masks.kem and not E.activeMask) != 0'u8:
    raise newException(ValueError, "AME protection tier lacks a KEM secret")

proc buildAtRestMaterial(L: AmeSuiteLayout, t: AmeMaskTier,
    E: AmeExchangeState, nonce, keyContext: openArray[byte]): ByteSeq {.
    role: truthBuilder, metaTags: {tagCryptoBoundary}.} =
  ## L/t/E/nonce/keyContext: caller's nonce followed by one key per
  ## switched-on slot, derived from the exchange and bound to `keyContext`.
  var
    i: int = 0
    slot: int = 0
    key: ByteSeq = @[]
    label: string = ""
  requireProtection(L, t, E)
  if nonce.len != ameTierNonceLen(L, t):
    raise newException(ValueError, "AME nonce length mismatch")
  appendAmeBytes(result, nonce)
  while i < int(L.ciphers.length):
    if algorithmSlotSelected(t.masks.cipher, i):
      label = "cipher:" & $uint8(ord(L.ciphers.algorithms[i])) & ":" & $i
      key = deriveAmeLayerKey(E, L, t, label, ameProtectionKeyLen, keyContext)
      appendAmeBytes(result, key)
      secureClearAmeBytes(key)
    i = i + 1
  while slot < int(L.macs.length):
    if algorithmSlotSelected(t.masks.mac, slot):
      label = "mac:" & $uint8(ord(L.macs.algorithms[slot])) & ":" & $slot
      key = deriveAmeLayerKey(E, L, t, label, ameProtectionKeyLen, keyContext)
      appendAmeBytes(result, key)
      secureClearAmeBytes(key)
    slot = slot + 1

proc buildStoredMaterial(L: AmeSuiteLayout, t: AmeMaskTier,
    rootKey, context, nonce: openArray[byte]): ByteSeq {.role: truthBuilder,
    metaTags: {tagCryptoBoundary}.} =
  ## L/t/rootKey/context/nonce: the same key block as `buildAtRestMaterial`,
  ## derived from a caller-owned key instead of from a KEM exchange.
  var
    keys: ByteSeq = @[]
  validateAmeTier(L, t)
  if nonce.len != ameTierNonceLen(L, t):
    raise newException(ValueError, "AME nonce length mismatch")
  keys = deriveAmeStorageKey(L, t, rootKey, context,
    ameTierKeyMaterialLen(L, t) - nonce.len)
  appendAmeBytes(result, nonce)
  appendAmeBytes(result, keys)
  secureClearAmeBytes(keys)

proc sealAmeStored*(L: AmeSuiteLayout, t: AmeMaskTier,
    rootKey, context, nonce, msg: openArray[byte],
    aad: openArray[byte] = [],
    tagLen: AmeAuthTagLen = aatl32): AmeProtectedMessage {.
    role: orchestrator, metaTags: {tagAppApi, tagCryptoBoundary}.} =
  ## L/t/rootKey/context/nonce/msg/aad/tagLen: seal bytes that have to sit
  ## still under a key the caller already holds -- a checkpoint on disk, a
  ## blob in a store. No exchange state is involved, so this works before a
  ## session exists and after one is gone.
  var
    material: ByteSeq = buildStoredMaterial(L, t, rootKey, context, nonce)
    sealed: tuple[ciphertext: ByteSeq, authTag: ByteSeq]
  try:
    sealed = sealAmeTier(L, t, material, msg, aad, tagLen)
    result.payload = sealed.ciphertext
    result.authTag = sealed.authTag
  finally:
    secureClearAmeBytes(material)

proc openAmeStored*(L: AmeSuiteLayout, t: AmeMaskTier,
    rootKey, context, nonce: openArray[byte], message: AmeProtectedMessage,
    aad: openArray[byte] = [],
    tagLen: AmeAuthTagLen = aatl32): tuple[ok: bool, payload: ByteSeq] {.
    role: orchestrator, metaTags: {tagAppApi, tagCryptoBoundary}.} =
  ## L/t/rootKey/context/nonce/message/aad/tagLen: the exact open. A wrong
  ## nonce length or tag length is a plain "no", not an error, so a caller
  ## trying several stored blobs can move past one that does not fit.
  var
    material: ByteSeq = @[]
  if nonce.len != ameTierNonceLen(L, t) or
      message.authTag.len != int(ord(tagLen)):
    return
  material = buildStoredMaterial(L, t, rootKey, context, nonce)
  try:
    result = openAmeTier(L, t, material, message.payload, message.authTag,
      aad, tagLen)
  finally:
    secureClearAmeBytes(material)

proc protectAmeMessageWithNonce*(L: AmeSuiteLayout, t: AmeMaskTier,
    E: AmeExchangeState,
    nonce, msg: openArray[byte], aad: openArray[byte] = [],
    keyContext: openArray[byte] = [],
    tagLen: AmeAuthTagLen = aatl32):
    AmeProtectedMessage {.role: orchestrator.} =
  ## L/t/E/nonce/msg/aad/keyContext/tagLen: exact at-rest inputs. Callers that
  ## store a nonce beside the ciphertext replay it here at open time.
  var
    material: ByteSeq = buildAtRestMaterial(L, t, E, nonce, keyContext)
    sealed: tuple[ciphertext: ByteSeq, authTag: ByteSeq]
  try:
    sealed = sealAmeTier(L, t, material, msg, aad, tagLen)
    result.payload = sealed.ciphertext
    result.authTag = sealed.authTag
  finally:
    secureClearAmeBytes(material)

proc protectAmeMessage*(L: AmeSuiteLayout, t: AmeMaskTier,
    E: AmeExchangeState,
    msg: openArray[byte], aad: openArray[byte] = [],
    keyContext: openArray[byte] = [],
    tagLen: AmeAuthTagLen = aatl32): tuple[
    message: AmeProtectedMessage, nonce: ByteSeq] {.role: orchestrator.} =
  ## L/t/E/msg/aad/keyContext/tagLen: at-rest sealing with a fresh nonce.
  result.nonce = randomAmeNonce(L, t)
  result.message = protectAmeMessageWithNonce(L, t, E, result.nonce, msg, aad,
    keyContext, tagLen)

proc openAmeMessage*(L: AmeSuiteLayout, t: AmeMaskTier, E: AmeExchangeState,
    nonce: openArray[byte], message: AmeProtectedMessage,
    aad: openArray[byte] = [], keyContext: openArray[byte] = [],
    tagLen: AmeAuthTagLen = aatl32): tuple[
    ok: bool, payload: ByteSeq] {.
    role: orchestrator.} =
  ## L/t/E/nonce/message/aad/keyContext/tagLen: exact authenticated open.
  ## `tagLen` is what THIS side agreed, never what the stored blob claims for
  ## itself, so a shortened tag is refused instead of being checked at its own
  ## easier length.
  var
    material: ByteSeq = @[]
  ## Opening with the wrong tier is a failure, not an error: a caller trying
  ## each of its epochs in turn must get a plain "no" it can move past.
  if nonce.len != ameTierNonceLen(L, t) or
      message.authTag.len != int(ord(tagLen)):
    return
  material = buildAtRestMaterial(L, t, E, nonce, keyContext)
  try:
    result = openAmeTier(L, t, material, message.payload, message.authTag,
      aad, tagLen)
  finally:
    secureClearAmeBytes(material)
