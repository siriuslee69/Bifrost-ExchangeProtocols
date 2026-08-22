## -------------------------------------------------------------------------
## AME Tier AEAD <- one plaintext -> many ciphers XORed, many MACs XORed
## -------------------------------------------------------------------------
##
## This file holds the only place in Bifrost where a payload is turned into
## ciphertext plus a tag. Both the message ratchet (FOMKE) and the at-rest
## package sealer call it, so there is exactly one construction to read and
## exactly one to get right.
##
## What a "slot" is
## ----------------
## A layout lists up to eight ciphers and up to eight authenticators, in a
## fixed order. A tier is a pair of bit patterns saying which of those are
## switched on right now. Slot 0 is the highest bit.
##
##   layout ciphers : [ XChaCha20 | Gimli   | AES-CTR | ... ]
##   tier mask      :   1           1         0
##                      ^           ^         ^
##                      on          on        off
##
## How the payload is protected
## ----------------------------
##
##   plaintext
##      |
##      +--> XOR with keystream of slot 0  --> intermediate
##                                              |
##                                              +--> XOR with keystream of slot 1 --> ciphertext
##
## Each switched-on cipher gets its own key and its own slice of the nonce.
## Undoing this is the same walk again, because XOR is its own inverse. An
## attacker has to break EVERY switched-on cipher, not the weakest one.
##
##   ciphertext (+ the header fields it belongs to)
##      |
##      +--> MAC slot 0 --> tag A --+
##      +--> MAC slot 1 --> tag B --+--> XOR --> the one tag on the wire
##
## Every switched-on authenticator sees the same input. Their outputs are
## XORed into one tag of the agreed length. Forging needs every one of them.
##
## Order: the payload is encrypted first, then the tag is taken over the
## CIPHERTEXT. A receiver therefore checks the tag before it decrypts
## anything, and never touches attacker-chosen plaintext.

import ./symmetric
import ./suites
import ./exchange_paths

import ../../types
import ../types
import ../level0/bytes
import ../../../analysis_pragmas

proc ameCipherNonceLen*(a: AmeCipherAlgorithm): int {.role: helper,
    tag: {tagCryptoBoundary}.} =
  ## a: cipher slot whose native nonce size in bytes is returned.
  case a
  of acaXChaCha20, acaGimli: result = 24
  of acaAesCtr: result = 16
  of acaChaCha20: result = 12

proc ameTierNonceLen*(L: AmeSuiteLayout, t: AmeMaskTier): int {.role: parser,
    tag: {tagCryptoBoundary}.} =
  ## L/t: layout and tier whose switched-on cipher nonce sizes are summed.
  ## Two switched-on ciphers need two nonces, laid end to end.
  var
    i: int = 0
  validateAmeTier(L, t)
  while i < int(L.ciphers.length):
    if algorithmSlotSelected(t.masks.cipher, i):
      result = result + ameCipherNonceLen(L.ciphers.algorithms[i])
    i = i + 1

proc ameTierCipherSlots*(L: AmeSuiteLayout, t: AmeMaskTier): int {.
    role: parser.} =
  ## L/t: how many cipher slots this tier switches on.
  var
    i: int = 0
  while i < int(L.ciphers.length):
    if algorithmSlotSelected(t.masks.cipher, i):
      result = result + 1
    i = i + 1

proc ameTierMacSlots*(L: AmeSuiteLayout, t: AmeMaskTier): int {.role: parser.} =
  ## L/t: how many authenticator slots this tier switches on.
  var
    i: int = 0
  while i < int(L.macs.length):
    if algorithmSlotSelected(t.masks.mac, i):
      result = result + 1
    i = i + 1

proc ameTierKeyMaterialLen*(L: AmeSuiteLayout, t: AmeMaskTier): int {.
    role: parser, tag: {tagCryptoBoundary}.} =
  ## L/t: total bytes one message needs -- nonce first, then one key per
  ## switched-on cipher slot, then one key per switched-on authenticator slot.
  ##
  ##   [ nonce bytes ][ cipher key 0 ][ cipher key 1 ][ mac key 0 ][ mac key 1 ]
  ##
  ## Callers derive this as ONE block and slice it, rather than making a
  ## separate derivation call per slot.
  result = ameTierNonceLen(L, t) +
    ameProtectionKeyLen * (ameTierCipherSlots(L, t) + ameTierMacSlots(L, t))

proc keySlice(A: openArray[byte], offset, n: int): ByteSeq {.role: parser.} =
  ## A/offset/n: bounded window of derived key material.
  var
    i: int = 0
  if offset < 0 or n < 0 or offset > A.len - n:
    raise newException(ValueError, "AME tier key material is too short")
  result = newSeq[byte](n)
  while i < n:
    result[i] = A[offset + i]
    i = i + 1

proc nativeMacLen(a: AmeMacAlgorithm, wanted: int): int {.role: helper.} =
  ## a/wanted: authenticator primitive and the tag length the session agreed.
  ## Poly1305 only ever emits 16 bytes; SHA3 refuses to go under 28.
  if a == amaPoly1305:
    return 16
  if a == amaSha3 and wanted <= 28:
    return 28
  result = wanted

proc normalizeMac(A: openArray[byte], wanted: int): ByteSeq {.role: helper,
    tag: {tagCryptoBoundary}.} =
  ## A/wanted: native tag stretched or squeezed to the agreed tag length, so
  ## authenticators of different natural widths can still be XORed together.
  var
    seed: ByteSeq = @[]
  if A.len == wanted:
    return @A
  appendAmeLabel(seed, "AME-MAC-NORMALIZE-v1")
  appendAmeU32(seed, uint32(A.len))
  appendAmeBytes(seed, A)
  result = blake3AmeHash(seed, wanted)

proc ameTierAuthInput*(L: AmeSuiteLayout, t: AmeMaskTier, tagLen: AmeAuthTagLen,
    nonce, aad, cipher: openArray[byte]): ByteSeq {.role: truthBuilder,
    tag: {tagCryptoBoundary}.} =
  ## L/t/tagLen/nonce/aad/cipher: every field the tag commits to.
  ##
  ##   "AME-TIER-AEAD-v1" | layout | tier | tagLen
  ##                      | len(aad)   | aad
  ##                      | len(nonce) | nonce
  ##                      | len(ct)    | ct
  ##
  ## The layout and tier are inside, so a peer cannot talk this side down to
  ## a weaker slot selection. The tag length is inside, so it cannot be
  ## shortened. Every variable field carries its length in front, so two
  ## different field splits can never produce the same bytes.
  appendAmeLabel(result, "AME-TIER-AEAD-v1")
  appendAmeBytes(result, encodeAmeSuiteLayout(L))
  appendAmeBytes(result, encodeAmeMaskTier(t))
  result.add(uint8(ord(tagLen)))
  appendAmeU32(result, uint32(aad.len))
  appendAmeBytes(result, aad)
  appendAmeU32(result, uint32(nonce.len))
  appendAmeBytes(result, nonce)
  appendAmeU32(result, uint32(cipher.len))
  appendAmeBytes(result, cipher)

proc ameTierCrypt*(L: AmeSuiteLayout, t: AmeMaskTier,
    material, msg: openArray[byte]): ByteSeq {.role: encryptor,
    tag: {tagCryptoBoundary}.} =
  ## L/t/material/msg: tier selection, one message's derived key block, and
  ## the bytes to transform. Running it twice on the same material returns
  ## the original, because every step is an XOR.
  var
    nonceOffset: int = 0
    keyOffset: int = 0
    n: int = 0
    key: ByteSeq = @[]
    nonce: ByteSeq = @[]
    i: int = 0
  validateAmeTier(L, t)
  keyOffset = ameTierNonceLen(L, t)
  if material.len != ameTierKeyMaterialLen(L, t):
    raise newException(ValueError, "AME tier key material length mismatch")
  result = @msg
  while i < int(L.ciphers.length):
    if algorithmSlotSelected(t.masks.cipher, i):
      n = ameCipherNonceLen(L.ciphers.algorithms[i])
      nonce = keySlice(material, nonceOffset, n)
      key = keySlice(material, keyOffset, ameProtectionKeyLen)
      result = ameCipherXor(L.ciphers.algorithms[i], key, nonce, result)
      secureClearAmeBytes(key)
      secureClearAmeBytes(nonce)
      nonceOffset = nonceOffset + n
      keyOffset = keyOffset + ameProtectionKeyLen
    i = i + 1

proc ameTierTag*(L: AmeSuiteLayout, t: AmeMaskTier, material,
    data: openArray[byte], tagLen: AmeAuthTagLen): ByteSeq {.
    role: orchestrator, tag: {tagCryptoBoundary}.} =
  ## L/t/material/data/tagLen: tier selection, the same derived key block,
  ## the authenticated input, and the agreed tag length. Every switched-on
  ## authenticator runs over `data`; the results are XORed into one tag.
  var
    keyOffset: int = 0
    key: ByteSeq = @[]
    raw: ByteSeq = @[]
    normalized: ByteSeq = @[]
    i: int = 0
  validateAmeTier(L, t)
  keyOffset = ameTierNonceLen(L, t) +
    ameProtectionKeyLen * ameTierCipherSlots(L, t)
  if material.len != ameTierKeyMaterialLen(L, t):
    raise newException(ValueError, "AME tier key material length mismatch")
  result = newSeq[byte](int(ord(tagLen)))
  while i < int(L.macs.length):
    if algorithmSlotSelected(t.masks.mac, i):
      key = keySlice(material, keyOffset, ameProtectionKeyLen)
      raw = ameMacTag(L.macs.algorithms[i], key, data,
        nativeMacLen(L.macs.algorithms[i], int(ord(tagLen))))
      normalized = normalizeMac(raw, int(ord(tagLen)))
      xorAmeInto(result, normalized)
      secureClearAmeBytes(key)
      secureClearAmeBytes(raw)
      secureClearAmeBytes(normalized)
      keyOffset = keyOffset + ameProtectionKeyLen
    i = i + 1

proc ameTierNonce*(L: AmeSuiteLayout, t: AmeMaskTier,
    material: openArray[byte]): ByteSeq {.role: parser,
    tag: {tagCryptoBoundary}.} =
  ## L/t/material: the nonce slice sitting at the front of the key block.
  ## It never travels on the wire -- both sides derive the same block from
  ## the same ratchet step, so both already hold it.
  result = keySlice(material, 0, ameTierNonceLen(L, t))

proc sealAmeTier*(L: AmeSuiteLayout, t: AmeMaskTier, material,
    msg, aad: openArray[byte], tagLen: AmeAuthTagLen): tuple[
    ciphertext: ByteSeq, authTag: ByteSeq] {.role: encryptor,
    tag: {tagAppApi, tagCryptoBoundary}.} =
  ## L/t/material/msg/aad/tagLen: encrypt first, then authenticate the
  ## ciphertext together with the header fields the caller passes as `aad`.
  var
    nonce: ByteSeq = ameTierNonce(L, t, material)
    authInput: ByteSeq = @[]
  result.ciphertext = ameTierCrypt(L, t, material, msg)
  authInput = ameTierAuthInput(L, t, tagLen, nonce, aad, result.ciphertext)
  result.authTag = ameTierTag(L, t, material, authInput, tagLen)
  secureClearAmeBytes(nonce)
  secureClearAmeBytes(authInput)

proc openAmeTier*(L: AmeSuiteLayout, t: AmeMaskTier, material,
    ciphertext, authTag, aad: openArray[byte], tagLen: AmeAuthTagLen): tuple[
    ok: bool, payload: ByteSeq] {.role: decryptor,
    tag: {tagAppApi, tagCryptoBoundary}.} =
  ## L/t/material/ciphertext/authTag/aad/tagLen: check the tag first, and
  ## only decrypt once it matched. `tagLen` is what THIS side agreed, never
  ## what the message claims for itself -- otherwise a sender could shrink
  ## its tag to one byte and guess it once in 256 tries.
  var
    nonce: ByteSeq = @[]
    authInput: ByteSeq = @[]
    expected: ByteSeq = @[]
  if authTag.len != int(ord(tagLen)):
    return
  nonce = ameTierNonce(L, t, material)
  authInput = ameTierAuthInput(L, t, tagLen, nonce, aad, ciphertext)
  expected = ameTierTag(L, t, material, authInput, tagLen)
  secureClearAmeBytes(authInput)
  if not constantTimeEqualAme(expected, authTag):
    secureClearAmeBytes(nonce)
    secureClearAmeBytes(expected)
    return
  secureClearAmeBytes(expected)
  result.payload = ameTierCrypt(L, t, material, ciphertext)
  result.ok = true
  secureClearAmeBytes(nonce)
