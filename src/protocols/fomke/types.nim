## -------------------------------------------------------------------------
## FOMKE Types <- forward-only message keys, GB3HKDF, TMEAEAD, and GGAEAD
## -------------------------------------------------------------------------

import ../types
import ../ame/types
import ../tmeaead/types as tme_types
import ../ggaead/types as gg_types
import ../preparation/types as preparation_types
import ../../analysis_pragmas

const
  gb3BlockBytes* = 32
  gb3DefaultRounds* = 3'u32
  gb3DefaultMemoryBlocks* = 64'u32
  gb3MaxRounds* = 1_000_000'u32
  gb3MaxMemoryBlocks* = 65_536'u32
  gb3MaxOutputBytes* = 1_048_576
  gb3MaxWorkBlocks* = 16_777_216'u64
  fomkeAeadNonceBytes* = 24
  fomkeAeadTagBytes* = 32
  fomkeChainKeyBytes* = 64
  fomkeMaxMessageKeyBytes* = tmeAeadKeyMaterialBytes
  fomkeMessageKeyBytes* = fomkeMaxMessageKeyBytes
  fomkeDefaultMaxSkip* = 64'u32
  fomkeMaxSkipLimit* = 4_096'u32
  fomkeDefaultPreparedMessages* = 8
  fomkeDefaultPreparedPayloadBytes* = 256
  fomkeMaxPreparedMessages* = 4_096
  fomkeMaxPreparedStreamBytes* = 16_777_216
  fomkeMagic* = [uint8('F'), uint8('O'), uint8('M'), uint8('1')]
  fomkeFormatVersion* = 1'u16
  fomkeHeaderLen* = 27
  fomkeMaxCiphertextBytes* = 16_777_216'u32
  fomkeMaxStateBytes* = 2_097_152'u32
  fomkeCheckpointKeyMinBytes* = 32

type
  Gb3KdfMode* = enum
    gb3Sequential = 0x00'u8,
    gb3MemoryMixed = 0x01'u8

  Gb3KdfConfig* {.role: configurator, tag: {tagFomke, tagKdf,
      tagTypes}.} = object
    rounds*: uint32
    blockIndex*: uint64
    mode*: Gb3KdfMode
    memoryBlocks*: uint32

  FomkeMessageCipher* = enum
    fmcTmeAead = 0x01'u8,
    fmcGgAead = 0x02'u8

  FomkeRole* = enum
    frInitiator = 0x01'u8,
    frResponder = 0x02'u8

  FomkeLane* = enum
    flLane1 = 0x01'u8,
    flLane2 = 0x02'u8

  FomkeChainState* {.role: truthState, tag: {tagCryptoBoundary, tagFomke,
      tagTypes}.} = object
    chainKey*: ByteSeq
    nextIndex*: uint64

  FomkeSkippedKey* {.role: truthState, tag: {tagCryptoBoundary, tagFomke,
      tagTypes}.} = object
    epoch*: uint32
    index*: uint64
    lane*: FomkeLane
    keyMaterial*: ByteSeq

  FomkeUpgradeCommit* {.role: truthState, tag: {tagExchange, tagFomke,
      tagTypes}.} = object
    requestId*: uint32
    baseEpoch*: uint32
    targetEpoch*: uint32
    targetTier*: AmeMaskTier
    exchangeMask*: uint8
    lane1Index*: uint64
    lane2Index*: uint64
    generations*: array[ameMaxAlgorithmSlots, uint32]
    confirmationTag*: ByteSeq

  FomkePendingUpgrade* {.role: truthState, tag: {tagCryptoBoundary,
      tagExchange, tagFomke, tagTypes}.} = object
    active*: bool
    commit*: FomkeUpgradeCommit
    candidateLane1*: FomkeChainState
    candidateLane2*: FomkeChainState

  FomkePreparedSendEntry* {.role: memory, tag: {tagCryptoBoundary, tagFomke,
      tagTypes}.} = object
    epoch*: uint32
    index*: uint64
    lane*: FomkeLane
    messageCipher*: FomkeMessageCipher
    keyMaterial*: ByteSeq
    nonce*: ByteSeq
    gimli*: PreparedStream
    xchacha*: PreparedStream
    nextChainKey*: ByteSeq

  FomkeSendCache* {.role: memory, tag: {tagCryptoBoundary, tagFomke,
      tagTypes}.} = object
    epoch*: uint32
    lane*: FomkeLane
    messageCipher*: FomkeMessageCipher
    nextIndex*: uint64
    chainKey*: ByteSeq
    payloadBytes*: int
    nextEntry*: int
    entries*: seq[FomkePreparedSendEntry]

  FomkeState* {.role: truthState, tag: {tagCryptoBoundary, tagFomke,
      tagTypes}.} = object
    role*: FomkeRole
    messageCipher*: FomkeMessageCipher
    epoch*: uint32
    algorithms*: AmeKemAlgorithms
    lane1*: FomkeChainState
    lane2*: FomkeChainState
    skipped*: seq[FomkeSkippedKey]
    maxSkip*: uint32
    kdf*: Gb3KdfConfig
    pending*: FomkePendingUpgrade

  FomkeMessage* {.role: truthState, tag: {tagFomke, tagPacket,
      tagTypes}.} = object
    epoch*: uint32
    index*: uint64
    senderLane*: FomkeLane
    nonce*: ByteSeq
    authTag*: ByteSeq
    ciphertext*: ByteSeq

  FomkeOpenResult* {.role: truthState, tag: {tagFomke, tagTypes}.} = object
    ok*: bool
    payload*: ByteSeq
    err*: string

  FomkeCheckpoint* {.role: truthState, tag: {tagCryptoBoundary, tagFomke,
      tagTypes}.} = object
    ok*: bool
    state*: FomkeState
    counter*: uint64
    err*: string

  FomkeDurableMessage* {.role: truthState, tag: {tagCryptoBoundary, tagFomke,
      tagTypes}.} = object
    ok*: bool
    message*: FomkeMessage
    checkpointCounter*: uint64
    err*: string

  FomkeDurableOpen* {.role: truthState, tag: {tagCryptoBoundary, tagFomke,
      tagTypes}.} = object
    ok*: bool
    payload*: ByteSeq
    checkpointCounter*: uint64
    err*: string

proc fomkeMessageKeyBytesFor*(a: FomkeMessageCipher): int {.role: helper,
    tag: {tagAppApi, tagCryptoBoundary, tagFomke}.} =
  ## a: message cipher whose one-time ratchet key size is required.
  case a
  of fmcTmeAead:
    result = tmeAeadKeyMaterialBytes
  of fmcGgAead:
    result = ggAeadKeyMaterialBytes
