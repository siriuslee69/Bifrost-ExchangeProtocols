## -------------------------------------------------------------------------
## FOMKE Tests <- GB3HKDF, AEAD presets, ratchets, and AME upgrades
## -------------------------------------------------------------------------

import std/[os, unittest]

import tyr/ciphers/xchacha20 as tyr_xchacha

import ../src/protocols/types
import ../src/protocols/config
import ../src/protocols/ame/types
import ../src/protocols/ame/level1/exchange_paths
import ../src/protocols/ame/level1/suites
import ../src/protocols/ame/level1/tier_aead
import ../src/protocols/ame/level1/presets
import ../src/protocols/ame/level2/protection
import ../src/protocols/ame/level1/path_triggers
import ../src/protocols/ame/level2/session
import ../src/protocols/fomke/types
import ../src/protocols/fomke/level0/gb3hkdf
import ../src/protocols/preparation/types
import ../src/protocols/preparation/gimli_batch
import ../src/protocols/preparation/xchacha_streams
import ../src/protocols/fomke/level0/protocols
import ../src/protocols/fomke/level1/chain
import ../src/protocols/fomke/level2/wire
import ../src/protocols/fomke/level2/state_codec
import ../src/protocols/fomke/level2/state_store

const
  fomkeKems: AmeKemAlgorithms = [akaX25519, akaKyber768, akaFireSaber]

proc fomkeLayout(): AmeSuiteLayout =
  result = defaultAmeLayout(fomkeKems)

proc fomkeTier(id: uint32, kemMask: uint8): AmeMaskTier =
  var L: AmeSuiteLayout = fomkeLayout()
  result = initAmeMaskTier(L, id, initAmeTierMasks(kemMask,
    occupiedAmeMask(L.ciphers.length), occupiedAmeMask(L.macs.length),
    occupiedAmeMask(L.hashes.length), occupiedAmeMask(L.signatures.length),
    occupiedAmeMask(L.kdfs.length)))

proc fomkeInitialTier(): AmeMaskTier =
  result = fomkeTier(1'u32, 0b10000000'u8)

proc initialExchangeState(): AmeExchangeState =
  var
    request: AmeExchangeRequest
  result = initAmeExchangeState(fomkeKems)
  request = initAmeExchangeRequest(fomkeKems,
    fomkeTier(1'u32, 0b10000000'u8), 0b10000000'u8)
  applyAmeExchange(result, request,
    [@[byte 1, 3, 3, 7, 9, 11, 13, 17, 19, 23, 29, 31]])

proc upgradedExchangeState(swapped: bool = false): AmeExchangeState =
  var
    request: AmeExchangeRequest
    first: ByteSeq = @[byte 41, 42, 43, 44, 45, 46]
    second: ByteSeq = @[byte 51, 52, 53, 54, 55, 56]
  result = initialExchangeState()
  request = initAmeExchangeRequest(fomkeKems,
    fomkeTier(3'u32, 0b11100000'u8), 0b01100000'u8)
  if swapped:
    applyAmeExchange(result, request, [second, first])
  else:
    applyAmeExchange(result, request, [first, second])

proc fomkeAmeAuth(role: AmeEndpointRole = aerInitiator): AmeAuthPackage =
  var
    state: AmeExchangeState = initialExchangeState()
    layout: AmeSuiteLayout = fomkeLayout()
    tier: AmeMaskTier = fomkeTier(1'u32, 0b10000000'u8)
  ## The role has to be settled BEFORE the session is built, because the
  ## session starts its ratchet immediately and the role decides which lane
  ## it sends on.
  result = initAmeAuthPackage(layout, tier, state, endpointRole = role)

proc fomkeUpgradeSession(role: AmeEndpointRole = aerInitiator): AmeSession =
  var
    auth: AmeAuthPackage = fomkeAmeAuth(role)
    target: AmeMaskTier = fomkeTier(2'u32, 0b11000000'u8)
    path: AmeTierPath = initAmeTierPath(auth.current.layout,
      [auth.current.tier, target])
  result = initAmeSession(auth, path, peerTrustRequired = false)

proc installSignaturePeers(A, B: var AmeSession) =
  var
    aKeys = generateAmeSigningKeys(A.auth.current.layout,
      fullAmeMaskTier(A.auth.current.layout))
    bKeys = generateAmeSigningKeys(B.auth.current.layout,
      fullAmeMaskTier(B.auth.current.layout))
  A.auth.localSignatureSecretKeys = aKeys.secretKeys
  A.auth.peerSignaturePublicKeys = bKeys.publicKeys
  B.auth.localSignatureSecretKeys = bKeys.secretKeys
  B.auth.peerSignaturePublicKeys = aKeys.publicKeys

suite "Gimli prepared backend":
  test "compiled lane width matches the selected target profile":
    when defined(avx2):
      check gimliPreparedBatchWidth() == 8
    elif defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
      check gimliPreparedBatchWidth() == 4
    else:
      check gimliPreparedBatchWidth() == 1
    when defined(bifrostTyrXChaChaBatch):
      check preparedXChaChaWidth() == gimliPreparedBatchWidth()
    else:
      check preparedXChaChaWidth() == 1
    ## The AES-CTR slot used to pick its own vector width here. It now hands
    ## Tyr `acbAuto` and lets the cipher choose, so there is no Bifrost-side
    ## width left to assert.

  test "XChaCha batches match scalar streams across block boundaries":
    var
      keys: seq[ByteSeq] = @[]
      nonces: seq[ByteSeq] = @[]
      streams: seq[ByteSeq] = @[]
      expected: ByteSeq = @[]
      lengths: array[7, int] = [0, 1, 31, 63, 64, 65, 257]
      i: int = 0
      j: int = 0
    while i < 13:
      keys.add(deriveGb3Hkdf(@[byte 101 + uint8(i)], @[], @[byte 102],
        gb3BlockBytes))
      nonces.add(deriveGb3Hkdf(@[byte 111 + uint8(i)], @[], @[byte 112],
        ameCipherNonceLen(acaXChaCha20)))
      i = i + 1
    while j < lengths.len:
      streams = prepareXChaChaStreamRows(keys, nonces, lengths[j])
      i = 0
      while i < streams.len:
        expected = tyr_xchacha.xchacha20Stream(keys[i], nonces[i], lengths[j])
        check streams[i] == expected
        i = i + 1
      j = j + 1

suite "GB3HKDF":
  test "sequential derivation is deterministic and block selectable":
    var
      input: ByteSeq = @[byte 1, 2, 3, 4, 5]
      info: ByteSeq = @[byte 9, 8, 7]
      base: ByteSeq = @[]
      again: ByteSeq = @[]
      later: ByteSeq = @[]
      moreRounds: ByteSeq = @[]
    base = deriveGb3Hkdf(input, @[byte 6], info, 96,
      initGb3KdfConfig(rounds = 2'u32))
    again = deriveGb3Hkdf(input, @[byte 6], info, 96,
      initGb3KdfConfig(rounds = 2'u32))
    later = deriveGb3Hkdf(input, @[byte 6], info, 96,
      initGb3KdfConfig(rounds = 2'u32, blockIndex = 7'u64))
    moreRounds = deriveGb3Hkdf(input, @[byte 6], info, 96,
      initGb3KdfConfig(rounds = 3'u32))
    check base.len == 96
    check base == again
    check base != later
    check base != moreRounds

  test "memory-mixed mode is deterministic and distinct":
    var
      config: Gb3KdfConfig
      first: ByteSeq = @[]
      second: ByteSeq = @[]
      sequential: ByteSeq = @[]
    config = initGb3KdfConfig(rounds = 2'u32, blockIndex = 3'u64,
      mode = gb3MemoryMixed, memoryBlocks = 16'u32)
    first = deriveGb3Hkdf(@[byte 4, 5, 6], @[], @[byte 7], 80, config)
    second = deriveGb3Hkdf(@[byte 4, 5, 6], @[], @[byte 7], 80, config)
    sequential = deriveGb3Hkdf(@[byte 4, 5, 6], @[], @[byte 7], 80,
      initGb3KdfConfig(rounds = 2'u32, blockIndex = 3'u64))
    check first == second
    check first != sequential

  test "multiple secret order and work bounds are enforced":
    var
      first: ByteSeq = @[]
      reversed: ByteSeq = @[]
      secrets: seq[ByteSeq] = @[@[byte 1, 2], @[byte 3, 4]]
      reverseSecrets: seq[ByteSeq] = @[@[byte 3, 4], @[byte 1, 2]]
    first = deriveGb3HkdfInputs(@[byte 9, 9], secrets, @[byte 1], 64)
    reversed = deriveGb3HkdfInputs(@[byte 9, 9], reverseSecrets,
      @[byte 1], 64)
    check first != reversed
    expect ValueError:
      discard initGb3KdfConfig(rounds = 0'u32)
    expect ValueError:
      discard initGb3KdfConfig(mode = gb3MemoryMixed, memoryBlocks = 7'u32)
    expect ValueError:
      discard deriveGb3Hkdf(@[byte 1], @[], @[], gb3MaxOutputBytes + 1)

suite "AEAD presets":
  ## TMEAEAD and GGAEAD used to be two hand-built constructions with their own
  ## code. They are now two slot selections over the one construction in
  ## tier_aead, and these tests are what "the same suite" means: the same
  ## primitives, in the same order, all of them mattering.
  test "the TMEAEAD preset selects three ciphers and two authenticators":
    var
      L: AmeSuiteLayout = tmeAeadAmeLayout(fomkeKems)
      t: AmeMaskTier = presetAmeTier(L)
    check L.ciphers.length == 3'u8
    check L.ciphers.algorithms[0] == acaXChaCha20
    check L.ciphers.algorithms[1] == acaAesCtr
    check L.ciphers.algorithms[2] == acaGimli
    check L.macs.length == 2'u8
    check L.macs.algorithms[0] == amaGimli
    check L.macs.algorithms[1] == amaPoly1305
    check ameTierCipherSlots(L, t) == 3
    check ameTierMacSlots(L, t) == 2
    ## 24 bytes of XChaCha nonce, 16 of AES counter, 24 of Gimli, then one
    ## 32-byte key for each of the five slots. The old code carried exactly
    ## those five keys in a 160-byte block.
    check ameTierNonceLen(L, t) == 64
    check ameTierKeyMaterialLen(L, t) == 64 + 5 * 32

  test "the GGAEAD preset selects one cipher and one authenticator":
    var
      L: AmeSuiteLayout = ggAeadAmeLayout(fomkeKems)
      t: AmeMaskTier = presetAmeTier(L)
    check L.ciphers.length == 1'u8
    check L.ciphers.algorithms[0] == acaGimli
    check L.macs.length == 1'u8
    check L.macs.algorithms[0] == amaGimli
    check ameTierNonceLen(L, t) == 24
    check ameTierKeyMaterialLen(L, t) == 24 + 2 * 32

  test "a preset roundtrips and refuses a changed AAD":
    var
      L: AmeSuiteLayout = tmeAeadAmeLayout(fomkeKems)
      t: AmeMaskTier = presetAmeTier(L)
      material: ByteSeq = deriveGb3Hkdf(@[byte 1, 2, 3, 4], @[], @[byte 5],
        ameTierKeyMaterialLen(L, t))
      plaintext: ByteSeq = @[byte 4, 8, 15, 16, 23, 42]
      sealed: tuple[ciphertext: ByteSeq, authTag: ByteSeq]
      opened: tuple[ok: bool, payload: ByteSeq]
    sealed = sealAmeTier(L, t, material, plaintext, @[byte 11], aatl32)
    check sealed.ciphertext.len == plaintext.len
    check sealed.ciphertext != plaintext
    check sealed.authTag.len == 32
    opened = openAmeTier(L, t, material, sealed.ciphertext, sealed.authTag,
      @[byte 11], aatl32)
    check opened.ok
    check opened.payload == plaintext
    opened = openAmeTier(L, t, material, sealed.ciphertext, sealed.authTag,
      @[byte 12], aatl32)
    check not opened.ok

  test "every cipher slot in the preset changes the ciphertext":
    var
      L: AmeSuiteLayout = tmeAeadAmeLayout(fomkeKems)
      full: AmeMaskTier = presetAmeTier(L)
      plaintext: ByteSeq = @[byte 1, 2, 3, 4, 5, 6, 7, 8]
      whole: ByteSeq = @[]
      partial: ByteSeq = @[]
      narrow: AmeMaskTier
      material: ByteSeq = @[]
      i: int = 0
    material = deriveGb3Hkdf(@[byte 9, 9, 9, 9], @[], @[byte 1],
      ameTierKeyMaterialLen(L, full))
    whole = ameTierCrypt(L, full, material, plaintext)
    ## Drop one cipher slot at a time. If the dropped one had contributed
    ## nothing, the bytes would be unchanged -- which is exactly the failure
    ## a chain of XORs has to be checked against.
    while i < 3:
      narrow = initAmeMaskTier(L, 1'u32, initAmeTierMasks(
        full.masks.kem, full.masks.cipher and not slotMask(i),
        full.masks.mac, full.masks.hash, full.masks.signature,
        full.masks.kdf))
      partial = ameTierCrypt(L, narrow, deriveGb3Hkdf(@[byte 9, 9, 9, 9],
        @[], @[byte 1], ameTierKeyMaterialLen(L, narrow)), plaintext)
      check partial != whole
      i = i + 1

  test "one preset cannot open what the other sealed":
    var
      wide: AmeSuiteLayout = tmeAeadAmeLayout(fomkeKems)
      compact: AmeSuiteLayout = ggAeadAmeLayout(fomkeKems)
      wideTier: AmeMaskTier = presetAmeTier(wide)
      compactTier: AmeMaskTier = presetAmeTier(compact)
      sealed: tuple[ciphertext: ByteSeq, authTag: ByteSeq]
      opened: tuple[ok: bool, payload: ByteSeq]
    sealed = sealAmeTier(wide, wideTier,
      deriveGb3Hkdf(@[byte 7, 7, 7, 7], @[], @[byte 2],
      ameTierKeyMaterialLen(wide, wideTier)), @[byte 5, 5, 5], @[], aatl32)
    opened = openAmeTier(compact, compactTier,
      deriveGb3Hkdf(@[byte 7, 7, 7, 7], @[], @[byte 2],
      ameTierKeyMaterialLen(compact, compactTier)), sealed.ciphertext,
      sealed.authTag, @[], aatl32)
    check not opened.ok

  test "a preset keys an at-rest blob straight from a storage key":
    var
      L: AmeSuiteLayout = ggAeadAmeLayout(fomkeKems)
      t: AmeMaskTier = presetAmeTier(L)
      storageKey: ByteSeq = deriveGb3Hkdf(@[byte 3, 1, 4, 1], @[], @[], 32)
      nonce: ByteSeq = randomAmeNonce(L, t)
      sealed: AmeProtectedMessage
      opened: tuple[ok: bool, payload: ByteSeq]
    sealed = sealAmeStored(L, t, storageKey, @[byte 1], nonce,
      @[byte 6, 6, 6], @[byte 2], aatl32)
    opened = openAmeStored(L, t, storageKey, @[byte 1], nonce, sealed,
      @[byte 2], aatl32)
    check opened.ok
    check opened.payload == @[byte 6, 6, 6]
    ## A different purpose string is a different key, so the same blob does
    ## not open under it.
    opened = openAmeStored(L, t, storageKey, @[byte 9], nonce, sealed,
      @[byte 2], aatl32)
    check not opened.ok
    expect ValueError:
      discard sealAmeStored(L, t, @[byte 1, 2, 3], @[byte 1], nonce,
        @[byte 6], @[], aatl32)

suite "FOMKE":
  test "initial AME secret becomes independent directional chains":
    var
      secrets: seq[ByteSeq] = @[@[byte 1, 2, 3, 4]]
      alice: FomkeState
    alice = initFomke(secrets, fomkeKems, fomkeLayout(), fomkeInitialTier(),
      frInitiator, @[byte 9])
    check secrets.len == 0
    check alice.epoch == 1'u32
    check alice.lane1.chainKey.len == fomkeChainKeyBytes
    check alice.lane2.chainKey.len == fomkeChainKeyBytes
    check alice.lane1.chainKey != alice.lane2.chainKey
    check outboundFomkeLane(alice.role) == flLane1
    check inboundFomkeLane(alice.role) == flLane2

  test "asynchronous directions progress without a shared counter race":
    var
      state: AmeExchangeState = initialExchangeState()
      alice: FomkeState = initFomkeFromAme(state, fomkeLayout(), fomkeInitialTier(), frInitiator,
        @[byte 7, 7])
      bob: FomkeState = initFomkeFromAme(state, fomkeLayout(), fomkeInitialTier(), frResponder,
        @[byte 7, 7])
      a0: FomkeMessage
      a1: FomkeMessage
      a2: FomkeMessage
      b0: FomkeMessage
      opened: FomkeOpenResult
    a0 = sealFomkeMessage(alice, @[byte 10])
    a1 = sealFomkeMessage(alice, @[byte 11])
    a2 = sealFomkeMessage(alice, @[byte 12])
    opened = openFomkeMessage(bob, a2)
    check opened.ok
    check opened.payload == @[byte 12]
    check bob.skipped.len == 2
    opened = openFomkeMessage(bob, a0)
    check opened.ok
    opened = openFomkeMessage(bob, a1)
    check opened.ok
    check bob.skipped.len == 0
    opened = openFomkeMessage(bob, a1)
    check not opened.ok
    b0 = sealFomkeMessage(bob, @[byte 21, 22])
    opened = openFomkeMessage(alice, b0)
    check opened.ok
    check opened.payload == @[byte 21, 22]
    check alice.lane1.nextIndex == 3'u64
    check alice.lane2.nextIndex == 1'u64
    check bob.lane1.nextIndex == 3'u64
    check bob.lane2.nextIndex == 1'u64

  test "failed authentication does not consume receive state":
    var
      state: AmeExchangeState = initialExchangeState()
      alice: FomkeState = initFomkeFromAme(state, fomkeLayout(), fomkeInitialTier(), frInitiator)
      bob: FomkeState = initFomkeFromAme(state, fomkeLayout(), fomkeInitialTier(), frResponder)
      message: FomkeMessage = sealFomkeMessage(alice, @[byte 5, 6])
      tampered: FomkeMessage = message
      opened: FomkeOpenResult
    tampered.authTag[0] = tampered.authTag[0] xor 1'u8
    opened = openFomkeMessage(bob, tampered)
    check not opened.ok
    check bob.lane1.nextIndex == 0'u64
    opened = openFomkeMessage(bob, message)
    check opened.ok
    check bob.lane1.nextIndex == 1'u64

  test "prepared slots preserve exact wire output and ratchet state":
    var
      exchange: AmeExchangeState = initialExchangeState()
      preparedState: FomkeState = initFomkeFromAme(exchange, fomkeLayout(),
        fomkeInitialTier(), frInitiator)
      normalState: FomkeState = initFomkeFromAme(exchange, fomkeLayout(),
        fomkeInitialTier(), frInitiator)
      cache: FomkeSendCache = prepareFomkeSendCache(preparedState, 9)
      clonedCache: FomkeSendCache = cloneFomkeSendCache(cache)
      payload: ByteSeq = @[]
      prepared: FomkeMessage
      normal: FomkeMessage
      materialLen: int = ameTierKeyMaterialLen(fomkeLayout(),
        fomkeInitialTier())
      i: int = 0
    check preparedState.lane1.nextIndex == 0'u64
    check fomkePreparedMessages(cache) == 9
    clearFomkeSendCache(clonedCache)
    check fomkePreparedMessages(cache) == 9
    check fomkePreparedSecretBytes(cache) ==
      fomkeChainKeyBytes + 9 * (materialLen + fomkeChainKeyBytes)
    while i < 9:
      payload = @[byte i + 1, byte i + 2, byte i + 3]
      prepared = sealFomkeMessagePrepared(preparedState, cache, payload,
        @[byte 5])
      normal = sealFomkeMessage(normalState, payload, @[byte 5])
      check prepared.epoch == normal.epoch
      check prepared.index == normal.index
      check prepared.senderLane == normal.senderLane
      check prepared.tagLen == normal.tagLen
      check prepared.authTag == normal.authTag
      check prepared.ciphertext == normal.ciphertext
      i = i + 1
    check fomkePreparedMessages(cache) == 0
    check preparedState.lane1.nextIndex == normalState.lane1.nextIndex
    check preparedState.lane1.chainKey == normalState.lane1.chainKey

  test "prepared slots fall back safely after live state changes":
    var
      exchange: AmeExchangeState = initialExchangeState()
      preparedState: FomkeState = initFomkeFromAme(exchange, fomkeLayout(),
        fomkeInitialTier(), frInitiator)
      normalState: FomkeState = initFomkeFromAme(exchange, fomkeLayout(),
        fomkeInitialTier(), frInitiator)
      stale: FomkeSendCache = prepareFomkeSendCache(preparedState, 8)
      prepared: FomkeMessage
      normal: FomkeMessage
    ## Sealing outside the cache moves the live chain past what the cache
    ## holds. The next prepared send must notice and fall back rather than
    ## reuse a key the chain has already spent.
    prepared = sealFomkeMessage(preparedState, @[byte 1])
    normal = sealFomkeMessage(normalState, @[byte 1])
    check prepared.ciphertext == normal.ciphertext
    prepared = sealFomkeMessagePrepared(preparedState, stale, @[byte 2])
    normal = sealFomkeMessage(normalState, @[byte 2])
    check prepared.ciphertext == normal.ciphertext
    check prepared.authTag == normal.authTag
    check fomkePreparedMessages(stale) == 0

  test "the ratchet keeps one-time keys compact and survives a checkpoint":
    var
      state: AmeExchangeState = initialExchangeState()
      alice: FomkeState = initFomkeFromAme(state, fomkeLayout(),
        fomkeInitialTier(), frInitiator)
      bob: FomkeState = initFomkeFromAme(state, fomkeLayout(),
        fomkeInitialTier(), frResponder)
      first: FomkeMessage = sealFomkeMessage(alice, @[byte 1])
      second: FomkeMessage = sealFomkeMessage(alice, @[byte 2])
      opened: FomkeOpenResult
      restored: FomkeState
    discard first
    opened = openFomkeMessage(bob, second)
    check opened.ok
    check opened.payload == @[byte 2]
    check bob.skipped.len == 1
    check bob.skipped[0].keyMaterial.len == fomkeMessageKeyBytes
    restored = decodeFomkeState(encodeFomkeState(bob))
    check restored.skipped[0].keyMaterial.len == fomkeMessageKeyBytes
    check restored.tagLen == bob.tagLen
    check restored.tier == bob.tier

  test "AME bitmask upgrade is exact ordered and atomic":
    var
      initial: AmeExchangeState = initialExchangeState()
      candidate: AmeExchangeState = upgradedExchangeState()
      request: AmeExchangeRequest = initAmeExchangeRequest(fomkeKems,
        fomkeTier(3'u32, 0b11100000'u8), 0b01100000'u8)
      alice: FomkeState = initFomkeFromAme(initial, fomkeLayout(), fomkeInitialTier(), frInitiator)
      bob: FomkeState = initFomkeFromAme(initial, fomkeLayout(), fomkeInitialTier(), frResponder)
      message: FomkeMessage
      opened: FomkeOpenResult
      aliceCommit: FomkeUpgradeCommit
      bobCommit: FomkeUpgradeCommit
      decoded: FomkeUpgradeCommit
    message = sealFomkeMessage(alice, @[byte 1])
    opened = openFomkeMessage(bob, message)
    check opened.ok
    message = sealFomkeMessage(bob, @[byte 2])
    opened = openFomkeMessage(alice, message)
    check opened.ok
    aliceCommit = prepareFomkeUpgrade(alice, 44'u32, 2'u32, request,
      candidate)
    bobCommit = prepareFomkeUpgrade(bob, 44'u32, 2'u32, request, candidate)
    check fomkeUpgradeCommitsEqual(aliceCommit, bobCommit)
    decoded = decodeFomkeUpgradeCommit(encodeFomkeUpgradeCommit(aliceCommit))
    check fomkeUpgradeCommitsEqual(decoded, bobCommit)
    expect ValueError:
      discard sealFomkeMessage(alice, @[byte 3])
    confirmFomkeUpgrade(alice, bobCommit)
    confirmFomkeUpgrade(bob, decoded)
    check alice.epoch == 2'u32
    check bob.epoch == 2'u32
    check alice.lane1.nextIndex == 0'u64
    check alice.lane2.nextIndex == 0'u64
    message = sealFomkeMessage(alice, @[byte 9, 9])
    opened = openFomkeMessage(bob, message)
    check opened.ok
    check opened.payload == @[byte 9, 9]

  test "secret order and lane-counter races reject upgrade confirmation":
    var
      initial: AmeExchangeState = initialExchangeState()
      correct: AmeExchangeState = upgradedExchangeState()
      swapped: AmeExchangeState = upgradedExchangeState(true)
      request: AmeExchangeRequest = initAmeExchangeRequest(fomkeKems,
        fomkeTier(3'u32, 0b11100000'u8), 0b01100000'u8)
      alice: FomkeState = initFomkeFromAme(initial, fomkeLayout(), fomkeInitialTier(), frInitiator)
      bob: FomkeState = initFomkeFromAme(initial, fomkeLayout(), fomkeInitialTier(), frResponder)
      aliceCommit: FomkeUpgradeCommit
      bobCommit: FomkeUpgradeCommit
    discard sealFomkeMessage(alice, @[byte 1])
    aliceCommit = prepareFomkeUpgrade(alice, 91'u32, 2'u32, request, correct)
    bobCommit = prepareFomkeUpgrade(bob, 91'u32, 2'u32, request, swapped)
    check not fomkeUpgradeCommitsEqual(aliceCommit, bobCommit)
    expect ValueError:
      confirmFomkeUpgrade(alice, bobCommit)

  test "KEM upgrade rejects unresolved skipped messages":
    var
      initial: AmeExchangeState = initialExchangeState()
      candidate: AmeExchangeState = upgradedExchangeState()
      request: AmeExchangeRequest = initAmeExchangeRequest(fomkeKems,
        fomkeTier(3'u32, 0b11100000'u8), 0b01100000'u8)
      alice: FomkeState = initFomkeFromAme(initial, fomkeLayout(), fomkeInitialTier(), frInitiator)
      bob: FomkeState = initFomkeFromAme(initial, fomkeLayout(), fomkeInitialTier(), frResponder)
      first: FomkeMessage = sealFomkeMessage(alice, @[byte 1])
      second: FomkeMessage = sealFomkeMessage(alice, @[byte 2])
      opened: FomkeOpenResult
    discard first
    opened = openFomkeMessage(bob, second)
    check opened.ok
    check bob.skipped.len == 1
    expect ValueError:
      discard prepareFomkeUpgrade(bob, 12'u32, 2'u32, request, candidate)

  test "message wire and descriptor are strict":
    var
      state: AmeExchangeState = initialExchangeState()
      alice: FomkeState = initFomkeFromAme(state, fomkeLayout(), fomkeInitialTier(), frInitiator)
      message: FomkeMessage = sealFomkeMessage(alice, @[byte 7, 8, 9])
      encoded: ByteSeq = encodeFomkeMessage(message)
      decoded: FomkeMessage = decodeFomkeMessage(encoded, message.tagLen)
      descriptor: ProtocolDescriptor = initFomkeDescriptor()
      damaged: ByteSeq = @[]
    check decoded.epoch == message.epoch
    check decoded.index == message.index
    check decoded.senderLane == message.senderLane
    check decoded.tagLen == message.tagLen
    check decoded.ciphertext == message.ciphertext
    ## Thirteen bytes of header, then the tag, then the ciphertext. No magic,
    ## no version, no length field, no tag-length byte.
    check encoded.len == fomkeWireLen(3, message.tagLen)
    check encoded.len == fomkeHeaderLen + int(ord(message.tagLen)) + 3
    check descriptor.protocolId == "bifrost.fomke"
    ## Epoch zero is not a real epoch, so it is refused rather than treated
    ## as one.
    damaged = encoded
    damaged[0] = 0'u8
    damaged[1] = 0'u8
    damaged[2] = 0'u8
    damaged[3] = 0'u8
    expect ValueError:
      discard decodeFomkeMessage(damaged, message.tagLen)
    ## An unknown sender lane is refused too.
    damaged = encoded
    damaged[12] = 9'u8
    expect ValueError:
      discard decodeFomkeMessage(damaged, message.tagLen)
    ## Too short to hold a tag at the agreed length.
    damaged = encoded
    damaged.setLen(fomkeHeaderLen + int(ord(message.tagLen)) - 1)
    expect ValueError:
      discard decodeFomkeMessage(damaged, message.tagLen)
    ## The caller's tag length decides the split, so asking for a longer tag
    ## than the sender used moves the boundary and yields other bytes -- it
    ## is the tag check that refuses this, never the decoder.
    check decodeFomkeMessage(encoded, aatl16).ciphertext !=
      message.ciphertext

  test "state codec preserves directional and skipped ratchet state":
    var
      exchange: AmeExchangeState = initialExchangeState()
      alice: FomkeState = initFomkeFromAme(exchange, fomkeLayout(), fomkeInitialTier(), frInitiator)
      bob: FomkeState = initFomkeFromAme(exchange, fomkeLayout(), fomkeInitialTier(), frResponder)
      first: FomkeMessage = sealFomkeMessage(alice, @[byte 1])
      second: FomkeMessage = sealFomkeMessage(alice, @[byte 2])
      encoded: ByteSeq = @[]
      decoded: FomkeState
      opened: FomkeOpenResult
    discard first
    opened = openFomkeMessage(bob, second)
    check opened.ok
    check bob.skipped.len == 1
    encoded = encodeFomkeState(bob)
    decoded = decodeFomkeState(encoded)
    check decoded.role == bob.role
    check decoded.epoch == bob.epoch
    check decoded.lane1.nextIndex == bob.lane1.nextIndex
    check decoded.lane1.chainKey == bob.lane1.chainKey
    check decoded.lane2.chainKey == bob.lane2.chainKey
    check decoded.skipped.len == 1
    check decoded.skipped[0].index == 0'u64
    encoded[^1] = encoded[^1] xor 1'u8
    expect ValueError:
      discard decodeFomkeState(encoded)

  test "a checkpoint from another format version is refused":
    var
      exchange: AmeExchangeState = initialExchangeState()
      state: FomkeState = initFomkeFromAme(exchange, fomkeLayout(),
        fomkeInitialTier(), frInitiator)
      wrongVersion: ByteSeq = encodeFomkeState(state)
    ## There is no compatibility shim. A checkpoint written by a different
    ## format is refused outright rather than guessed at, because guessing
    ## which fields are missing is how a decoder ends up reading key material
    ## out of the wrong offsets.
    wrongVersion[3] = 9'u8
    expect ValueError:
      discard decodeFomkeState(wrongVersion)

  test "durable checkpoints advance before publish and reject rollback":
    var
      exchange: AmeExchangeState = initialExchangeState()
      alice: FomkeState = initFomkeFromAme(exchange, fomkeLayout(), fomkeInitialTier(), frInitiator)
      bob: FomkeState = initFomkeFromAme(exchange, fomkeLayout(), fomkeInitialTier(), frResponder)
      storageKey: ByteSeq = newSeq[byte](32)
      context: ByteSeq = @[byte 7, 7, 9, 9]
      aliceBase: string = getTempDir() / "bifrost-fomke-alice-state"
      bobBase: string = getTempDir() / "bifrost-fomke-bob-state"
      aliceCounter: uint64 = 0'u64
      bobCounter: uint64 = 0'u64
      durable: FomkeDurableMessage
      opened: FomkeDurableOpen
      loaded: FomkeCheckpoint
      fallback: FomkeCheckpoint
      rejected: FomkeCheckpoint
      i: int = 0
    while i < storageKey.len:
      storageKey[i] = uint8(i + 1)
      i = i + 1
    defer:
      for path in [aliceBase & ".0", aliceBase & ".1",
          aliceBase & ".0.next", aliceBase & ".1.next",
          bobBase & ".0", bobBase & ".1", bobBase & ".0.next",
          bobBase & ".1.next"]:
        if fileExists(path):
          removeFile(path)
    durable = sealFomkeMessageDurable(alice, aliceBase, storageKey,
      aliceCounter, @[byte 10, 11], context)
    check durable.ok
    check aliceCounter == 1'u64
    check alice.lane1.nextIndex == 1'u64
    loaded = loadFomkeCheckpoint(aliceBase, storageKey, 1'u64, context,
      fomkeLayout(), fomkeInitialTier())
    check loaded.ok
    check loaded.counter == 1'u64
    check loaded.state.lane1.nextIndex == 1'u64
    opened = openFomkeMessageDurable(bob, bobBase, storageKey, bobCounter,
      durable.message, context)
    check opened.ok
    check opened.payload == @[byte 10, 11]
    check bobCounter == 1'u64
    durable = sealFomkeMessageDurable(alice, aliceBase, storageKey,
      aliceCounter, @[byte 12], context)
    check durable.ok
    check aliceCounter == 2'u64
    writeFile(aliceBase & ".0", "damaged-newest-slot")
    fallback = loadFomkeCheckpoint(aliceBase, storageKey, 1'u64, context,
      fomkeLayout(), fomkeInitialTier())
    check fallback.ok
    check fallback.counter == 1'u64
    rejected = loadFomkeCheckpoint(aliceBase, storageKey, 2'u64, context,
      fomkeLayout(), fomkeInitialTier())
    check not rejected.ok
    check rejected.err == "FOMKE checkpoint rollback detected"

suite "AME with FOMKE":
  test "TCP and DAC data use the forward-only inner message layer":
    var
      tcpSender: AmeSession = initAmeSession(fomkeAmeAuth(aerInitiator),
        peerTrustRequired = false)
      tcpReceiver: AmeSession = initAmeSession(fomkeAmeAuth(aerResponder),
        peerTrustRequired = false)
      dacSender: AmeSession = initAmeSession(fomkeAmeAuth(aerInitiator),
        peerTrustRequired = false)
      dacReceiver: AmeSession = initAmeSession(fomkeAmeAuth(aerResponder),
        peerTrustRequired = false)
      frame: ByteSeq = @[]
      opened: AmeOpenResult
    check not tcpSender.fomkePregenerationEnabled
    check fomkePreparedMessages(tcpSender.fomkeSendCache) == 0
    frame = sealAmeTcpFrame(tcpSender, @[byte 7, 8, 9])
    opened = openAmeTcpFrame(tcpReceiver, frame)
    check opened.ok
    check opened.packet.payload == @[byte 7, 8, 9]
    check tcpSender.fomke.lane1.nextIndex == 1'u64
    check tcpReceiver.fomke.lane1.nextIndex == 1'u64
    frame = sealAmeDacFrame(dacSender, @[byte 10, 11])
    opened = openAmeDacFrame(dacReceiver, frame)
    check opened.ok
    check opened.packet.payload == @[byte 10, 11]

  test "DAC preserves bounded FOMKE out-of-order delivery":
    var
      sender: AmeSession = initAmeSession(fomkeAmeAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(fomkeAmeAuth(aerResponder),
        peerTrustRequired = false)
      first: ByteSeq = @[]
      second: ByteSeq = @[]
      third: ByteSeq = @[]
      opened: AmeOpenResult
    first = sealAmeDacFrame(sender, @[byte 1])
    second = sealAmeDacFrame(sender, @[byte 2])
    third = sealAmeDacFrame(sender, @[byte 3])
    opened = openAmeDacFrame(receiver, third)
    check opened.ok
    check opened.packet.payload == @[byte 3]
    opened = openAmeDacFrame(receiver, first)
    check opened.ok
    opened = openAmeDacFrame(receiver, second)
    check opened.ok
    opened = openAmeDacFrame(receiver, first)
    check not opened.ok

  test "AME prepares future send slots and can turn them off":
    var
      sender: AmeSession = initAmeSession(fomkeAmeAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(fomkeAmeAuth(aerResponder),
        peerTrustRequired = false)
      frame: ByteSeq = @[]
      opened: AmeOpenResult
    ## Preparing ahead is OFF by default, because a filled cache holds the
    ## keys for messages that have not been sent yet.
    check not sender.fomkePregenerationEnabled
    check fomkePreparedMessages(sender.fomkeSendCache) == 0
    setAmeFomkePregeneration(sender, true, 8)
    check fomkePreparedMessages(sender.fomkeSendCache) == 8
    frame = sealAmeTcpFrame(sender, @[byte 21, 34, 55])
    opened = openAmeTcpFrame(receiver, frame)
    check fomkePreparedMessages(sender.fomkeSendCache) == 7
    check opened.ok
    check opened.packet.payload == @[byte 21, 34, 55]
    setAmeFomkePregeneration(sender, false)
    check not sender.fomkePregenerationEnabled
    check fomkePreparedMessages(sender.fomkeSendCache) == 0

  test "AME installs prepared slots and rejects an asynchronously stale cache":
    var
      sender: AmeSession = initAmeSession(fomkeAmeAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(fomkeAmeAuth(aerResponder),
        peerTrustRequired = false)
      snapshot: FomkeState
      stale: FomkeSendCache
      frame: ByteSeq = @[]
      opened: AmeOpenResult
    snapshot = snapshotAmeFomkeSendState(sender)
    stale = prepareFomkeSendCache(snapshot, 8)
    clearFomkeState(snapshot)
    prepareAmeFomkeSendCache(sender, 8)
    check fomkePreparedMessages(sender.fomkeSendCache) == 8
    frame = sealAmeDacFrame(sender, @[byte 8, 13, 21])
    check fomkePreparedMessages(sender.fomkeSendCache) == 7
    opened = openAmeDacFrame(receiver, frame)
    check opened.ok
    check opened.packet.payload == @[byte 8, 13, 21]
    check not installAmeFomkeSendCache(sender, stale)
    check fomkePreparedMessages(stale) == 0

  test "authenticated AME exchange automatically commits the FOMKE epoch":
    var
      client: AmeSession = fomkeUpgradeSession(aerInitiator)
      server: AmeSession = fomkeUpgradeSession(aerResponder)
      request: AmeExchangeRequest = initAmeExchangeRequest(fomkeKems,
        fomkeTier(2'u32, 0b11000000'u8), 0b01000000'u8)
      dataFrame: ByteSeq = @[]
      offerFrame: ByteSeq = @[]
      replyFrame: ByteSeq = @[]
      readyFrame: ByteSeq = @[]
      opened: AmeOpenResult
    installSignaturePeers(client, server)
    dataFrame = sealAmeTcpFrame(client, @[byte 1])
    opened = openAmeTcpFrame(server, dataFrame)
    check opened.ok
    prepareAmeFomkeSendCache(client, 8)
    prepareAmeFomkeSendCache(server, 8)
    offerFrame = beginAmeTcpExchangeFrame(client, request)
    replyFrame = answerAmeTcpExchangeFrame(server, offerFrame)
    check server.fomke.pending.active
    check fomkePreparedMessages(server.fomkeSendCache) == 0
    readyFrame = finishAmeTcpExchangeFrame(client, replyFrame)
    check fomkePreparedMessages(client.fomkeSendCache) == 8
    check client.auth.current.epochId == 2'u32
    check client.fomke.epoch == 2'u32
    confirmAmeTcpExchangeFrame(server, readyFrame)
    check fomkePreparedMessages(server.fomkeSendCache) == 8
    check server.auth.current.epochId == 2'u32
    check server.fomke.epoch == 2'u32
    check client.fomke.lane1.chainKey == server.fomke.lane1.chainKey
    check client.fomke.lane2.chainKey == server.fomke.lane2.chainKey
    dataFrame = sealAmeTcpFrame(client, @[byte 9, 9])
    check fomkePreparedMessages(client.fomkeSendCache) == 7
    opened = openAmeTcpFrame(server, dataFrame)
    check opened.ok
    check opened.packet.payload == @[byte 9, 9]

  test "unsynchronized lane counters reject automatic AME upgrade":
    var
      client: AmeSession = fomkeUpgradeSession(aerInitiator)
      server: AmeSession = fomkeUpgradeSession(aerResponder)
      request: AmeExchangeRequest = initAmeExchangeRequest(fomkeKems,
        fomkeTier(2'u32, 0b11000000'u8), 0b01000000'u8)
      offer: AmeExchangeOffer
      reply: AmeExchangeReply
      clientCommit: FomkeUpgradeCommit
    installSignaturePeers(client, server)
    discard sealFomkeMessage(client.fomke, @[byte 1])
    offer = beginAmeSessionExchange(client, request)
    reply = answerAmeSessionExchange(server, offer)
    finishAmeSessionExchange(client, reply)
    clientCommit = client.fomke.pending.commit
    check not fomkeUpgradeCommitsEqual(clientCommit,
      server.fomke.pending.commit)
    expect ValueError:
      confirmAmeSessionExchange(server, offer.requestId,
        server.pendingIncoming.candidate.epochId, request.targetTier,
        clientCommit)

  test "runtime config decides whether new sessions prepare ahead":
    var
      previous: BifrostConfig = currentBifrostConfig()
      configured: BifrostConfig = previous
      eager: AmeSession
      lazy: AmeSession
    configured.fomkePregeneration = true
    applyBifrostConfig(configured)
    eager = initAmeSession(fomkeAmeAuth(aerInitiator),
      peerTrustRequired = false)
    check eager.fomkePregenerationEnabled
    check fomkePreparedMessages(eager.fomkeSendCache) ==
      configured.fomkePregenerationMessages
    configured.fomkePregeneration = false
    applyBifrostConfig(configured)
    lazy = initAmeSession(fomkeAmeAuth(aerResponder),
      peerTrustRequired = false)
    check not lazy.fomkePregenerationEnabled
    check fomkePreparedMessages(lazy.fomkeSendCache) == 0
    clearAmeSession(eager)
    clearAmeSession(lazy)
    applyBifrostConfig(previous)

  test "connection teardown erases FOMKE and AME secret state":
    var
      connection: AmeSession = initAmeSession(fomkeAmeAuth(aerInitiator),
        peerTrustRequired = false)
    prepareAmeFomkeSendCache(connection, 8)
    discard sealAmeDacFrame(connection, @[byte 1])
    clearAmeSession(connection)
    check connection.fomke.lane1.chainKey.len == 0
    check connection.fomkeRetiring.lane1.chainKey.len == 0
    check fomkePreparedMessages(connection.fomkeSendCache) == 0
    check connection.auth.current.exchange.activeMask == 0'u8
