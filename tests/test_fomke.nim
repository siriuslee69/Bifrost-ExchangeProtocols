## -------------------------------------------------------------------------
## FOMKE Tests <- GB3HKDF, TMEAEAD, GGAEAD, ratchets, and AME upgrades
## -------------------------------------------------------------------------

import std/[os, unittest]

import tyr/ciphers/xchacha20 as tyr_xchacha

import ../src/protocols/types
import ../src/protocols/config
import ../src/protocols/ame/types
import ../src/protocols/ame/level1/exchange_paths
import ../src/protocols/ame/level1/suites
import ../src/protocols/ame/level1/path_triggers
import ../src/protocols/ame/types
import ../src/protocols/ame/level2/session
import ../src/protocols/fomke/types
import ../src/protocols/fomke/level0/gb3hkdf
import ../src/protocols/preparation/types
import ../src/protocols/preparation/gimli_batch
import ../src/protocols/preparation/xchacha_streams
import ../src/protocols/tmeaead
import ../src/protocols/ggaead
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

proc fomkeAmeAuth(): AmeAuthPackage =
  var
    state: AmeExchangeState = initialExchangeState()
    layout: AmeSuiteLayout = fomkeLayout()
    tier: AmeMaskTier = fomkeTier(1'u32, 0b10000000'u8)
  result = initAmeAuthPackage(layout, tier, state)

proc fomkeUpgradeSession(): AmeSession =
  var
    auth: AmeAuthPackage = fomkeAmeAuth()
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
  A.auth.endpointRole = aerInitiator
  B.auth.endpointRole = aerResponder

proc installTrafficPeers(A, B: var AmeSession) =
  A.auth.endpointRole = aerInitiator
  B.auth.endpointRole = aerResponder

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
    when defined(avx2):
      check tmeAesSimdWidth(32) == 32
      check tmeAesSimdWidth(16) == 16
      check tmeAesSimdWidth(48) == 16
    elif defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
      check tmeAesSimdWidth(32) == 16
      check tmeAesSimdWidth(16) == 16
    else:
      check tmeAesSimdWidth(32) == 1
    check tmeAesSimdWidth(8) == 1

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
        tmeAeadNonceBytes))
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

suite "TMEAEAD":
  test "five-key composite roundtrips and binds AAD":
    var
      key: ByteSeq = @[]
      nonce: ByteSeq = @[]
      plaintext: ByteSeq = @[byte 4, 8, 15, 16, 23, 42]
      sealed: TmeAeadCiphertext
      opened: tuple[ok: bool, payload: ByteSeq]
    key = deriveTmeAeadKeyMaterial(@[byte 1, 2, 3, 4],
      @[byte 5, 6, 7])
    nonce = deriveGb3Hkdf(@[byte 8, 9], @[], @[byte 10],
      tmeAeadNonceBytes)
    sealed = sealTmeAead(key, nonce, plaintext, @[byte 11])
    opened = openTmeAead(key, nonce, sealed, @[byte 11])
    check key.len == tmeAeadKeyMaterialBytes
    check sealed.authTag.len == tmeAeadTagBytes
    check opened.ok
    check opened.payload == plaintext
    opened = openTmeAead(key, nonce, sealed, @[byte 12])
    check not opened.ok

  test "ciphertext tag nonce and key tampering fail closed":
    var
      key: ByteSeq = deriveTmeAeadKeyMaterial(@[byte 1, 2, 3], @[byte 4])
      wrongKey: ByteSeq = deriveTmeAeadKeyMaterial(@[byte 1, 2, 4], @[byte 4])
      nonce: ByteSeq = newSeq[byte](tmeAeadNonceBytes)
      sealed: TmeAeadCiphertext
      changed: TmeAeadCiphertext
      opened: tuple[ok: bool, payload: ByteSeq]
    sealed = sealTmeAead(key, nonce, @[byte 9, 8, 7])
    changed = sealed
    changed.ciphertext[^1] = changed.ciphertext[^1] xor 1'u8
    opened = openTmeAead(key, nonce, changed)
    check not opened.ok
    changed = sealed
    changed.authTag[0] = changed.authTag[0] xor 1'u8
    opened = openTmeAead(key, nonce, changed)
    check not opened.ok
    nonce[0] = 1'u8
    opened = openTmeAead(key, nonce, sealed)
    check not opened.ok
    nonce[0] = 0'u8
    opened = openTmeAead(wrongKey, nonce, sealed)
    check not opened.ok

  test "prepared short-message streams match normal sealing exactly":
    var
      keys: seq[ByteSeq] = @[]
      nonces: seq[ByteSeq] = @[]
      gimliStreams: seq[PreparedStream] = @[]
      xChaChaStreams: seq[PreparedStream] = @[]
      key: ByteSeq = @[]
      nonce: ByteSeq = @[]
      plaintext: ByteSeq = @[byte 3, 1, 4, 1, 5, 9, 2, 6]
      normal: TmeAeadCiphertext
      prepared: TmeAeadCiphertext
      opened: tuple[ok: bool, payload: ByteSeq]
      i: int = 0
    while i < 13:
      key = deriveTmeAeadKeyMaterial(@[byte 40 + uint8(i), 2, 3],
        @[byte 7, uint8(i)])
      nonce = deriveGb3Hkdf(@[byte 80 + uint8(i)], @[], @[byte 9],
        tmeAeadNonceBytes)
      keys.add(key)
      nonces.add(nonce)
      i = i + 1
    gimliStreams = prepareTmeGimliStreams(keys, nonces, 32)
    xChaChaStreams = prepareTmeXChaChaStreams(keys, nonces, 32)
    check gimliStreams.len == 13
    check xChaChaStreams.len == 13
    i = 0
    while i < gimliStreams.len:
      normal = sealTmeAead(keys[i], nonces[i], plaintext, @[byte 11, 12])
      prepared = sealTmeAeadPrepared(keys[i], nonces[i], plaintext,
        gimliStreams[i], xChaChaStreams[i], @[byte 11, 12])
      check prepared.ciphertext == normal.ciphertext
      check prepared.authTag == normal.authTag
      opened = openTmeAeadPrepared(keys[i], nonces[i], prepared,
        gimliStreams[i], xChaChaStreams[i], @[byte 11, 12])
      check opened.ok
      check opened.payload == plaintext
      i = i + 1
    expect ValueError:
      discard sealTmeAeadPrepared(keys[0], nonces[0], plaintext,
        gimliStreams[1], xChaChaStreams[0], @[byte 11, 12])
    expect ValueError:
      discard sealTmeAeadPrepared(keys[0], nonces[0], plaintext,
        gimliStreams[0], xChaChaStreams[1], @[byte 11, 12])

suite "GGAEAD":
  test "Gimli stream and GimliHMAC match the fixed construction vector":
    var
      key: ByteSeq = @[]
      nonce: ByteSeq = newSeq[byte](ggAeadNonceBytes)
      plaintext: ByteSeq = @[byte 4, 8, 15, 16, 23, 42]
      sealed: GgAeadCiphertext
      opened: tuple[ok: bool, payload: ByteSeq]
    key = deriveGgAeadKeyMaterial(@[byte 1, 2, 3, 4], @[byte 5, 6, 7])
    sealed = sealGgAead(key, nonce, plaintext, @[byte 11])
    check key.len == ggAeadKeyMaterialBytes
    check sealed.ciphertext == @[byte 76, 142, 173, 3, 135, 251]
    check sealed.authTag == @[byte 129, 254, 238, 242, 124, 248, 81, 146,
      181, 116, 66, 13, 184, 138, 254, 131, 45, 92, 141, 26, 141, 132, 79,
      83, 92, 136, 51, 220, 59, 176, 251, 168]
    opened = openGgAead(key, nonce, sealed, @[byte 11])
    check opened.ok
    check opened.payload == plaintext

  test "ciphertext tag nonce AAD and key tampering fail closed":
    var
      key: ByteSeq = deriveGgAeadKeyMaterial(@[byte 1, 2, 3], @[byte 4])
      wrongKey: ByteSeq = deriveGgAeadKeyMaterial(@[byte 1, 2, 4], @[byte 4])
      nonce: ByteSeq = newSeq[byte](ggAeadNonceBytes)
      sealed: GgAeadCiphertext = sealGgAead(key, nonce, @[byte 9, 8, 7],
        @[byte 6])
      changed: GgAeadCiphertext
      opened: tuple[ok: bool, payload: ByteSeq]
    changed = sealed
    changed.ciphertext[^1] = changed.ciphertext[^1] xor 1'u8
    check not openGgAead(key, nonce, changed, @[byte 6]).ok
    changed = sealed
    changed.authTag[0] = changed.authTag[0] xor 1'u8
    check not openGgAead(key, nonce, changed, @[byte 6]).ok
    nonce[0] = 1'u8
    check not openGgAead(key, nonce, sealed, @[byte 6]).ok
    nonce[0] = 0'u8
    check not openGgAead(key, nonce, sealed, @[byte 7]).ok
    opened = openGgAead(wrongKey, nonce, sealed, @[byte 6])
    check not opened.ok

  test "prepared short-message streams match normal sealing exactly":
    var
      keys: seq[ByteSeq] = @[]
      nonces: seq[ByteSeq] = @[]
      streams: seq[PreparedStream] = @[]
      key: ByteSeq = @[]
      nonce: ByteSeq = @[]
      plaintext: ByteSeq = @[byte 2, 7, 1, 8, 2, 8, 1, 8]
      normal: GgAeadCiphertext
      prepared: GgAeadCiphertext
      opened: tuple[ok: bool, payload: ByteSeq]
      i: int = 0
    while i < 13:
      key = deriveGgAeadKeyMaterial(@[byte 30 + uint8(i), 4, 5],
        @[byte 6, uint8(i)])
      nonce = deriveGb3Hkdf(@[byte 70 + uint8(i)], @[], @[byte 8],
        ggAeadNonceBytes)
      keys.add(key)
      nonces.add(nonce)
      i = i + 1
    streams = prepareGgGimliStreams(keys, nonces, 32)
    check streams.len == 13
    i = 0
    while i < streams.len:
      normal = sealGgAead(keys[i], nonces[i], plaintext, @[byte 13, 14])
      prepared = sealGgAeadPrepared(keys[i], nonces[i], plaintext,
        streams[i], @[byte 13, 14])
      check prepared.ciphertext == normal.ciphertext
      check prepared.authTag == normal.authTag
      opened = openGgAeadPrepared(keys[i], nonces[i], prepared,
        streams[i], @[byte 13, 14])
      check opened.ok
      check opened.payload == plaintext
      i = i + 1
    expect ValueError:
      discard sealGgAeadPrepared(keys[0], nonces[0], plaintext,
        streams[1], @[byte 13, 14])

suite "FOMKE":
  test "initial AME secret becomes independent directional chains":
    var
      secret: ByteSeq = @[byte 1, 2, 3, 4]
      alice: FomkeState
    alice = initFomke(secret, fomkeKems, 0, frInitiator, @[byte 9])
    check secret.len == 0
    check alice.epoch == 1'u32
    check alice.lane1.chainKey.len == fomkeChainKeyBytes
    check alice.lane2.chainKey.len == fomkeChainKeyBytes
    check alice.lane1.chainKey != alice.lane2.chainKey
    check outboundFomkeLane(alice.role) == flLane1
    check inboundFomkeLane(alice.role) == flLane2

  test "asynchronous directions progress without a shared counter race":
    var
      state: AmeExchangeState = initialExchangeState()
      alice: FomkeState = initFomkeFromAme(state, 0, frInitiator,
        @[byte 7, 7])
      bob: FomkeState = initFomkeFromAme(state, 0, frResponder,
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
      alice: FomkeState = initFomkeFromAme(state, 0, frInitiator)
      bob: FomkeState = initFomkeFromAme(state, 0, frResponder)
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

  test "prepared TMEAEAD slots preserve exact wire output and ratchet state":
    var
      exchange: AmeExchangeState = initialExchangeState()
      preparedState: FomkeState = initFomkeFromAme(exchange, 0, frInitiator)
      normalState: FomkeState = initFomkeFromAme(exchange, 0, frInitiator)
      cache: FomkeSendCache = prepareFomkeSendCache(preparedState, 9, 32)
      clonedCache: FomkeSendCache = cloneFomkeSendCache(cache)
      payload: ByteSeq = @[]
      prepared: FomkeMessage
      normal: FomkeMessage
      i: int = 0
    check preparedState.lane1.nextIndex == 0'u64
    check fomkePreparedMessages(cache) == 9
    clearFomkeSendCache(clonedCache)
    check fomkePreparedMessages(cache) == 9
    check fomkePreparedSecretBytes(cache) ==
      fomkeChainKeyBytes + 9 * (tmeAeadKeyMaterialBytes +
      fomkeAeadNonceBytes + gb3BlockBytes + fomkeAeadNonceBytes + 32 +
      gb3BlockBytes + fomkeAeadNonceBytes + 32 + fomkeChainKeyBytes)
    while i < 9:
      payload = @[byte i + 1, byte i + 2, byte i + 3]
      prepared = sealFomkeMessagePrepared(preparedState, cache, payload,
        @[byte 5])
      normal = sealFomkeMessage(normalState, payload, @[byte 5])
      check prepared.epoch == normal.epoch
      check prepared.index == normal.index
      check prepared.senderLane == normal.senderLane
      check prepared.nonce == normal.nonce
      check prepared.authTag == normal.authTag
      check prepared.ciphertext == normal.ciphertext
      i = i + 1
    check fomkePreparedMessages(cache) == 0
    check preparedState.lane1.nextIndex == normalState.lane1.nextIndex
    check preparedState.lane1.chainKey == normalState.lane1.chainKey

  test "prepared GGAEAD slots fall back safely after live state changes":
    var
      exchange: AmeExchangeState = initialExchangeState()
      preparedState: FomkeState = initFomkeFromAme(exchange, 0, frInitiator,
        messageCipher = fmcGgAead)
      normalState: FomkeState = initFomkeFromAme(exchange, 0, frInitiator,
        messageCipher = fmcGgAead)
      stale: FomkeSendCache = prepareFomkeSendCache(preparedState, 8, 8)
      oversized: FomkeSendCache
      prepared: FomkeMessage
      normal: FomkeMessage
    prepared = sealFomkeMessage(preparedState, @[byte 1])
    normal = sealFomkeMessage(normalState, @[byte 1])
    check prepared.ciphertext == normal.ciphertext
    prepared = sealFomkeMessagePrepared(preparedState, stale, @[byte 2])
    normal = sealFomkeMessage(normalState, @[byte 2])
    check prepared.ciphertext == normal.ciphertext
    check prepared.authTag == normal.authTag
    check fomkePreparedMessages(stale) == 0
    oversized = prepareFomkeSendCache(preparedState, 8, 2)
    prepared = sealFomkeMessagePrepared(preparedState, oversized,
      @[byte 3, 4, 5])
    normal = sealFomkeMessage(normalState, @[byte 3, 4, 5])
    check prepared.ciphertext == normal.ciphertext
    check prepared.authTag == normal.authTag
    check fomkePreparedMessages(oversized) == 0

  test "GGAEAD ratchets compact one-time keys and persists its selector":
    var
      state: AmeExchangeState = initialExchangeState()
      alice: FomkeState = initFomkeFromAme(state, 0, frInitiator,
        messageCipher = fmcGgAead)
      bob: FomkeState = initFomkeFromAme(state, 0, frResponder,
        messageCipher = fmcGgAead)
      first: FomkeMessage = sealFomkeMessage(alice, @[byte 1])
      second: FomkeMessage = sealFomkeMessage(alice, @[byte 2])
      opened: FomkeOpenResult
      restored: FomkeState
    discard first
    opened = openFomkeMessage(bob, second)
    check opened.ok
    check opened.payload == @[byte 2]
    check bob.messageCipher == fmcGgAead
    check bob.skipped.len == 1
    check bob.skipped[0].keyMaterial.len == ggAeadKeyMaterialBytes
    restored = decodeFomkeState(encodeFomkeState(bob))
    check restored.messageCipher == fmcGgAead
    check restored.skipped[0].keyMaterial.len == ggAeadKeyMaterialBytes

  test "AME bitmask upgrade is exact ordered and atomic":
    var
      initial: AmeExchangeState = initialExchangeState()
      candidate: AmeExchangeState = upgradedExchangeState()
      request: AmeExchangeRequest = initAmeExchangeRequest(fomkeKems,
        fomkeTier(3'u32, 0b11100000'u8), 0b01100000'u8)
      alice: FomkeState = initFomkeFromAme(initial, 0, frInitiator)
      bob: FomkeState = initFomkeFromAme(initial, 0, frResponder)
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
      alice: FomkeState = initFomkeFromAme(initial, 0, frInitiator)
      bob: FomkeState = initFomkeFromAme(initial, 0, frResponder)
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
      alice: FomkeState = initFomkeFromAme(initial, 0, frInitiator)
      bob: FomkeState = initFomkeFromAme(initial, 0, frResponder)
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
      alice: FomkeState = initFomkeFromAme(state, 0, frInitiator)
      message: FomkeMessage = sealFomkeMessage(alice, @[byte 7, 8, 9])
      encoded: ByteSeq = encodeFomkeMessage(message)
      decoded: FomkeMessage = decodeFomkeMessage(encoded)
      descriptor: ProtocolDescriptor = initFomkeDescriptor()
    check decoded.epoch == message.epoch
    check decoded.index == message.index
    check decoded.senderLane == message.senderLane
    check decoded.ciphertext == message.ciphertext
    check encoded.len == fomkeWireLen(3)
    check descriptor.protocolId == "bifrost.fomke"
    encoded[0] = 0'u8
    expect ValueError:
      discard decodeFomkeMessage(encoded)

  test "state codec preserves directional and skipped ratchet state":
    var
      exchange: AmeExchangeState = initialExchangeState()
      alice: FomkeState = initFomkeFromAme(exchange, 0, frInitiator)
      bob: FomkeState = initFomkeFromAme(exchange, 0, frResponder)
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

  test "version-1 checkpoints decode with the TMEAEAD default":
    var
      exchange: AmeExchangeState = initialExchangeState()
      state: FomkeState = initFomkeFromAme(exchange, 0, frInitiator)
      legacy: ByteSeq = encodeFomkeState(state)
      decoded: FomkeState
    legacy[4] = 1'u8
    legacy[5] = 0'u8
    legacy.delete(7)
    decoded = decodeFomkeState(legacy)
    check decoded.messageCipher == fmcTmeAead
    check decoded.lane1.chainKey == state.lane1.chainKey
    check decoded.lane2.chainKey == state.lane2.chainKey

  test "durable checkpoints advance before publish and reject rollback":
    var
      exchange: AmeExchangeState = initialExchangeState()
      alice: FomkeState = initFomkeFromAme(exchange, 0, frInitiator)
      bob: FomkeState = initFomkeFromAme(exchange, 0, frResponder)
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
    loaded = loadFomkeCheckpoint(aliceBase, storageKey, 1'u64, context)
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
    fallback = loadFomkeCheckpoint(aliceBase, storageKey, 1'u64, context)
    check fallback.ok
    check fallback.counter == 1'u64
    rejected = loadFomkeCheckpoint(aliceBase, storageKey, 2'u64, context)
    check not rejected.ok
    check rejected.err == "FOMKE checkpoint rollback detected"

suite "AME with FOMKE":
  test "TCP and DAC data use the forward-only inner message layer":
    var
      tcpSender: AmeSession = initAmeSession(fomkeAmeAuth(),
        peerTrustRequired = false)
      tcpReceiver: AmeSession = initAmeSession(fomkeAmeAuth(),
        peerTrustRequired = false)
      dacSender: AmeSession = initAmeSession(fomkeAmeAuth(),
        peerTrustRequired = false)
      dacReceiver: AmeSession = initAmeSession(fomkeAmeAuth(),
        peerTrustRequired = false)
      frame: ByteSeq = @[]
      opened: AmeOpenResult
    installTrafficPeers(tcpSender, tcpReceiver)
    installTrafficPeers(dacSender, dacReceiver)
    enableAmeFomke(tcpSender, frInitiator, 0, @[byte 1, 2])
    enableAmeFomke(tcpReceiver, frResponder, 0, @[byte 1, 2])
    check not tcpSender.fomkePregenerationEnabled
    check fomkePreparedMessages(tcpSender.fomkeSendCache) == 0
    frame = sealAmeTcpFrame(tcpSender, @[byte 7, 8, 9])
    opened = openAmeTcpFrame(tcpReceiver, frame)
    check opened.ok
    check opened.packet.payload == @[byte 7, 8, 9]
    check tcpSender.fomke.lane1.nextIndex == 1'u64
    check tcpReceiver.fomke.lane1.nextIndex == 1'u64
    enableAmeFomke(dacSender, frInitiator, 0, @[byte 3, 4])
    enableAmeFomke(dacReceiver, frResponder, 0, @[byte 3, 4])
    frame = sealAmeDacFrame(dacSender, @[byte 10, 11])
    opened = openAmeDacFrame(dacReceiver, frame)
    check opened.ok
    check opened.packet.payload == @[byte 10, 11]

  test "DAC preserves bounded FOMKE out-of-order delivery":
    var
      sender: AmeSession = initAmeSession(fomkeAmeAuth(),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(fomkeAmeAuth(),
        peerTrustRequired = false)
      first: ByteSeq = @[]
      second: ByteSeq = @[]
      third: ByteSeq = @[]
      opened: AmeOpenResult
    installTrafficPeers(sender, receiver)
    enableAmeFomke(sender, frInitiator, 0)
    enableAmeFomke(receiver, frResponder, 0)
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

  test "AME selects compact GGAEAD for forward-only message encryption":
    var
      sender: AmeSession = initAmeSession(fomkeAmeAuth(),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(fomkeAmeAuth(),
        peerTrustRequired = false)
      frame: ByteSeq = @[]
      opened: AmeOpenResult
    installTrafficPeers(sender, receiver)
    enableAmeFomke(sender, frInitiator, 0, messageCipher = fmcGgAead)
    enableAmeFomke(receiver, frResponder, 0, messageCipher = fmcGgAead)
    check sender.fomkePregenerationEnabled
    check fomkePreparedMessages(sender.fomkeSendCache) == 8
    frame = sealAmeTcpFrame(sender, @[byte 21, 34, 55])
    opened = openAmeTcpFrame(receiver, frame)
    check sender.fomke.messageCipher == fmcGgAead
    check receiver.fomke.messageCipher == fmcGgAead
    check fomkePreparedMessages(sender.fomkeSendCache) == 7
    check opened.ok
    check opened.packet.payload == @[byte 21, 34, 55]
    setAmeFomkePregeneration(sender, false)
    check not sender.fomkePregenerationEnabled
    check fomkePreparedMessages(sender.fomkeSendCache) == 0

  test "AME installs prepared slots and rejects an asynchronously stale cache":
    var
      sender: AmeSession = initAmeSession(fomkeAmeAuth(),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(fomkeAmeAuth(),
        peerTrustRequired = false)
      snapshot: FomkeState
      stale: FomkeSendCache
      frame: ByteSeq = @[]
      opened: AmeOpenResult
    installTrafficPeers(sender, receiver)
    enableAmeFomke(sender, frInitiator, 0, messageCipher = fmcGgAead)
    enableAmeFomke(receiver, frResponder, 0, messageCipher = fmcGgAead)
    snapshot = snapshotAmeFomkeSendState(sender)
    stale = prepareFomkeSendCache(snapshot, 8, 32)
    clearFomkeState(snapshot)
    prepareAmeFomkeSendCache(sender, 8, 32)
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
      client: AmeSession = fomkeUpgradeSession()
      server: AmeSession = fomkeUpgradeSession()
      request: AmeExchangeRequest = initAmeExchangeRequest(fomkeKems,
        fomkeTier(2'u32, 0b11000000'u8), 0b01000000'u8)
      dataFrame: ByteSeq = @[]
      offerFrame: ByteSeq = @[]
      replyFrame: ByteSeq = @[]
      readyFrame: ByteSeq = @[]
      opened: AmeOpenResult
    installSignaturePeers(client, server)
    enableAmeFomke(client, frInitiator, 0, @[byte 5])
    enableAmeFomke(server, frResponder, 0, @[byte 5])
    dataFrame = sealAmeTcpFrame(client, @[byte 1])
    opened = openAmeTcpFrame(server, dataFrame)
    check opened.ok
    prepareAmeFomkeSendCache(client, 8, 32)
    prepareAmeFomkeSendCache(server, 8, 32)
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
      client: AmeSession = fomkeUpgradeSession()
      server: AmeSession = fomkeUpgradeSession()
      request: AmeExchangeRequest = initAmeExchangeRequest(fomkeKems,
        fomkeTier(2'u32, 0b11000000'u8), 0b01000000'u8)
      offer: AmeExchangeOffer
      reply: AmeExchangeReply
      clientCommit: FomkeUpgradeCommit
    installSignaturePeers(client, server)
    enableAmeFomke(client, frInitiator, 0)
    enableAmeFomke(server, frResponder, 0)
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

  test "runtime config can invert both cipher pregeneration defaults":
    var
      previous: BifrostConfig = currentBifrostConfig()
      configured: BifrostConfig = previous
      tme: AmeSession = initAmeSession(fomkeAmeAuth(),
        peerTrustRequired = false)
      gg: AmeSession = initAmeSession(fomkeAmeAuth(),
        peerTrustRequired = false)
    configured.tmeAeadPregeneration = true
    configured.ggAeadPregeneration = false
    applyBifrostConfig(configured)
    enableAmeFomke(tme, frInitiator, 0)
    enableAmeFomke(gg, frInitiator, 0, messageCipher = fmcGgAead)
    check tme.fomkePregenerationEnabled
    check fomkePreparedMessages(tme.fomkeSendCache) ==
      configured.fomkePregenerationMessages
    check not gg.fomkePregenerationEnabled
    check fomkePreparedMessages(gg.fomkeSendCache) == 0
    clearAmeSession(tme)
    clearAmeSession(gg)
    applyBifrostConfig(previous)

  test "connection teardown erases FOMKE and AME secret state":
    var
      connection: AmeSession = initAmeSession(fomkeAmeAuth(),
        peerTrustRequired = false)
    enableAmeFomke(connection, frInitiator, 0)
    prepareAmeFomkeSendCache(connection, 8, 32)
    discard sealAmeDacFrame(connection, @[byte 1])
    clearAmeSession(connection)
    check not connection.fomkeEnabled
    check connection.fomke.lane1.chainKey.len == 0
    check fomkePreparedMessages(connection.fomkeSendCache) == 0
    check connection.auth.current.exchange.activeMask == 0'u8
