## -------------------------------------------------------------------------
## AME Derivation <- selected KEM secrets and tier-selected KDF overlays
## -------------------------------------------------------------------------

import protocols/custom_crypto/blake3 as tyr_blake3
import protocols/custom_crypto/gimli_sponge as tyr_gimli
import protocols/custom_crypto/sha3 as tyr_sha3
import protocols/custom_crypto/argon2 as tyr_argon2

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
  case a
  of akfaBlake3:
    result = tyr_blake3.blake3Hash(layerSeed, outLen)
  of akfaSha3Shake256:
    result = tyr_sha3.shake256Tyr(layerSeed, outLen)
  of akfaGimliXof:
    result = tyr_gimli.gimliXof(@[], @[], layerSeed, outLen)
  of akfaArgon2id:
    var salt: ByteSeq = tyr_blake3.blake3Hash(layerSeed, 16)
    result = tyr_argon2.argon2idTyrHash(layerSeed, salt, 3, 65_536, 1,
      outLen)

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
