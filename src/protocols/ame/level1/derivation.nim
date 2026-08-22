## -------------------------------------------------------------------------
## AME Derivation <- selected KEM secrets and tier-selected KDF overlays
## -------------------------------------------------------------------------

import ./symmetric




import ../../types
import ../types
import ../level0/bytes
import ./exchange_paths
import ./suites
import ../../../analysis_pragmas

proc deriveKdfLayer(a: AmeKdfAlgorithm, seed: openArray[byte],
    outLen: int): ByteSeq {.role: helper.} =
  ## a/seed/outLen: selected KDF primitive, bound seed, and output length.
  var
    layerSeed: ByteSeq = @[]
  appendAmeLabel(layerSeed, "AME-KDF-LAYER-v1")
  layerSeed.add(uint8(ord(a)))
  appendAmeU32(layerSeed, uint32(seed.len))
  appendAmeBytes(layerSeed, seed)
  result = ameKdfBytes(a, layerSeed, outLen)

proc deriveAmeKey*(S: AmeExchangeState, L: AmeSuiteLayout, t: AmeMaskTier,
    outLen: int, context: openArray[byte] = []): ByteSeq {.role: truthBuilder.} =
  ## S/L/t: established KEM state, immutable layout, and active mask tier.
  ## outLen/context: requested key length and transcript/domain context.
  var
    seed: ByteSeq = @[]
    layoutBytes: ByteSeq = @[]
    layer: ByteSeq = @[]
    i: int = 0
  if outLen <= 0:
    raise newException(ValueError, "AME key length must be positive")
  validateAmeTier(L, t)
  if not kemLayoutsEquivalent(S.algorithms, L.kems):
    raise newException(ValueError, "AME KDF layout and exchange state differ")
  if (t.masks.kem and not S.activeMask) != 0'u8:
    raise newException(ValueError, "AME tier selected an unavailable KEM secret")
  layoutBytes = encodeAmeSuiteLayout(L)
  appendAmeLabel(seed, "AME-MASK-TIER-KEY-v2")
  appendAmeU32(seed, uint32(layoutBytes.len))
  appendAmeBytes(seed, layoutBytes)
  appendAmeBytes(seed, encodeAmeMaskTier(t))
  appendAmeU32(seed, uint32(context.len))
  appendAmeBytes(seed, context)
  appendAmeBytes(seed, buildAmeExchangeSeed(S, t.masks.kem))
  result = newSeq[uint8](outLen)
  while i < int(L.kdfs.length):
    if algorithmSlotSelected(t.masks.kdf, i):
      layer = deriveKdfLayer(L.kdfs.algorithms[i], seed, outLen)
      xorAmeInto(result, layer)
    i = i + 1

proc deriveAmeStorageKey*(L: AmeSuiteLayout, t: AmeMaskTier,
    rootKey, context: openArray[byte], outLen: int): ByteSeq {.
    role: truthBuilder.} =
  ## L/t: the slot selection this material is for, bound into the seed so a
  ## key derived for one selection is useless under another.
  ## rootKey/context/outLen: a caller-owned secret, what it is being used
  ## for, and how many bytes to produce.
  ##
  ## The counterpart to `deriveAmeKey` for bytes that never came from a KEM
  ## exchange -- a passphrase-derived storage key, a key handed over out of
  ## band. Every switched-on KDF slot runs and the results are XORed, exactly
  ## as they are for session keys, so breaking one KDF is not enough.
  var
    seed: ByteSeq = @[]
    layoutBytes: ByteSeq = @[]
    layer: ByteSeq = @[]
    i: int = 0
  if outLen <= 0:
    raise newException(ValueError, "AME key length must be positive")
  if rootKey.len < ameProtectionKeyLen:
    raise newException(ValueError,
      "AME storage root key must contain at least 32 bytes")
  validateAmeTier(L, t)
  layoutBytes = encodeAmeSuiteLayout(L)
  appendAmeLabel(seed, "AME-STORAGE-KEY-v1")
  appendAmeU32(seed, uint32(layoutBytes.len))
  appendAmeBytes(seed, layoutBytes)
  appendAmeBytes(seed, encodeAmeMaskTier(t))
  appendAmeU32(seed, uint32(rootKey.len))
  appendAmeBytes(seed, rootKey)
  appendAmeU32(seed, uint32(context.len))
  appendAmeBytes(seed, context)
  result = newSeq[uint8](outLen)
  while i < int(L.kdfs.length):
    if algorithmSlotSelected(t.masks.kdf, i):
      layer = deriveKdfLayer(L.kdfs.algorithms[i], seed, outLen)
      xorAmeInto(result, layer)
      secureClearAmeBytes(layer)
    i = i + 1
  secureClearAmeBytes(seed)

proc deriveAmeLayerKey*(S: AmeExchangeState, L: AmeSuiteLayout,
    t: AmeMaskTier, label: string,
    outLen: int = ameProtectionKeyLen,
    context: openArray[byte] = []): ByteSeq {.
    role: truthBuilder.} =
  ## S/L/t/label/outLen/context: exact tier and external channel binding.
  var
    C: ByteSeq = @[]
  appendAmeLabel(C, label)
  appendAmeU32(C, uint32(context.len))
  appendAmeBytes(C, context)
  result = deriveAmeKey(S, L, t, outLen, C)

proc deriveAmeMasterKey*(S: AmeExchangeState, L: AmeSuiteLayout,
    t: AmeMaskTier, outLen: int = ameProtectionKeyLen,
    context: openArray[byte] = []): ByteSeq {.
    role: wrapper.} =
  ## S/L/t/outLen/context: exact master-key derivation inputs.
  result = deriveAmeLayerKey(S, L, t, "master", outLen, context)
