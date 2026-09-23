## -------------------------------------------------------------------------
## FOMKE Types <- forward-only message keys over the AME slot layout
## -------------------------------------------------------------------------
##
## FOMKE is the only thing that protects a payload once the handshake is
## finished. There is no second wrapper around it and none inside it.
##
##   one AME frame
##   +---------------------------+-------------------------------------+
##   | AME header (26 bytes)     | FOMKE envelope                      |
##   | plain, but authenticated  | header + tag + ciphertext           |
##   +---------------------------+-------------------------------------+
##
## Every message gets its own key, taken one step further down a chain that
## cannot be walked backwards. Sending message 5 destroys the state that
## produced messages 1..4, so a machine seized afterwards cannot read them.
##
## The actual encryption is the AME slot construction (see level1/tier_aead):
## the payload is XORed through every switched-on cipher, and the tag is the
## XOR of every switched-on authenticator. FOMKE supplies the key material
## for that; it does not carry a cipher choice of its own.

import ../types
import ../ame/types
import runePragmas

const
  gb3BlockBytes* = 32
  gb3DefaultRounds* = 3'u32
  gb3DefaultMemoryBlocks* = 64'u32
  gb3MaxRounds* = 1_000_000'u32
  gb3MaxMemoryBlocks* = 65_536'u32
  gb3MaxOutputBytes* = 1_048_576
  gb3MaxWorkBlocks* = 16_777_216'u64

  fomkeChainKeyBytes* = 64
  fomkeNextSecretBytes* = 32
    ## The "next secret" (NS). Born next to the two lane keys and never used
    ## for a message. Its only job is to be carried into the NEXT epoch:
    ##
    ##   ISS ──GB3HKDF──▶ [ LK1 (64) | LK2 (64) | NS (32) ]
    ##                                            │
    ##   rotation:  NS + fresh KEM secrets ──GB3HKDF──▶ [ LK1' | LK2' | NS' ]
    ##
    ## It is a one-way image of the epoch's secret, so holding it opens no
    ## message of this epoch -- but the next epoch cannot be derived without
    ## it. There is no root key: nothing else outlives the derivation.
  fomkeMessageKeyBytes* = 32
    ## What one ratchet step hands out. It is not the encryption key itself:
    ## it is the seed the per-message key block is expanded from, so its size
    ## does not change when the layout switches more cipher slots on.
  fomkeMinReorderWindow* = 4'u32
  fomkeDefaultReorderWindow* = 16'u32
  fomkeDefaultReorderCeiling* = 64'u32
  fomkeMaxReorderWindow* = 4_096'u32
  fomkeReorderRelaxRuns* = 64'u32
    ## How far out of order messages are allowed to arrive.
    ##
    ## Datagrams do not always turn up in the order they were sent. When
    ## message 7 arrives before message 5, this side runs its key chain
    ## forward to 7 and KEEPS the keys it stepped over, so that 5 still opens
    ## when it turns up a moment later. Those kept keys are the cost:
    ##
    ##   window of  4  ->  at most  4 kept keys  ->  about 256 bytes
    ##   window of 16  ->  at most 16 kept keys  ->  about   1 kilobyte
    ##   window of 64  ->  at most 64 kept keys  ->  about   4 kilobytes
    ##
    ## The window is also what a FORGED message can make this side do. A
    ## message claiming a position N ahead costs N key derivations before its
    ## tag can be checked and it is thrown away, so a wide window is a wide
    ## amplifier: one cheap packet in, N derivations out.
    ##
    ## So the window is not a fixed setting. It starts narrow and is widened
    ## only by reordering that a VERIFIED message has proved:
    ##
    ##   starts at   fomkeDefaultReorderWindow  (16)
    ##   grows to    FomkeState.reorderCeiling       as reordering is proved
    ##   shrinks to  fomkeMinReorderWindow       (4) on a path that behaves
    ##
    ## Widening happens on the copy of the state that is kept only once the
    ## tag verifies, so a forger cannot widen their own amplifier. An honest
    ## peer on a badly reordering path widens it within a few messages.
    ##
    ## `fomkeReorderRelaxRuns` is how many messages must arrive in order
    ## before the window halves back down one step. `fomkeMaxReorderWindow`
    ## is the hard limit on any ceiling a caller may ask for.
  fomkeDefaultPreparedMessages* = 8
  fomkeMaxPreparedMessages* = 4_096

  fomkeProtocolVersion* = 2'u8
    ## The envelope format's number. It is NOT a wire field -- nothing on the
    ## wire states it, because an AME frame's own version already fixes what
    ## its body looks like. This exists so the protocol registry can name the
    ## format, and it moved to 2 when the envelope lost its magic, its length
    ## field and its tag-length byte.
  fomkeHeaderLen* = 13
    ##  offset size field
    ##  ------ ---- --------------------------------------------------
    ##       0    4 epoch          (which KEM generation this belongs to)
    ##       4    8 message index  (position in the chain)
    ##      12    1 sender lane    (1 = initiator sends, 2 = responder)
    ##  ------ ---- --------------------------------------------------
    ##      13      tag, then ciphertext
    ##
    ## Thirteen bytes, and nothing here that the receiver could work out for
    ## itself. Four fields a reader might expect are gone on purpose:
    ##
    ##   no magic or version  This envelope only ever travels as the body of
    ##                        an AME frame, whose packet kind already says
    ##                        what the body is.
    ##   no nonce             Both sides derive it from the same ratchet
    ##                        step, so sending it repeats what they hold.
    ##   no ciphertext length The frame delimits the envelope; the
    ##                        ciphertext is whatever follows the tag.
    ##   no tag length        The receiver uses the length its own epoch
    ##                        agreed. A field here would have been a number
    ##                        an attacker could edit and a receiver would
    ##                        refuse anyway.
  fomkeMaxCiphertextBytes* = 16_777_216'u32
  fomkeMaxStateBytes* = 2_097_152'u32
  fomkeCheckpointKeyMinBytes* = 32

type
  Gb3KdfMode* = enum
    gb3Sequential = 0x00'u8,
    gb3MemoryMixed = 0x01'u8

  Gb3KdfConfig* {.role: configurator, tag: "fomke|kdf|types".} = object
    rounds*: uint32
    blockIndex*: uint64
    mode*: Gb3KdfMode
    memoryBlocks*: uint32

  FomkeRole* = enum
    frInitiator = 0x01'u8,
    frResponder = 0x02'u8

  ## Two chains run at once, one per direction, so neither side can replay
  ## its own traffic back at the other.
  FomkeLane* = enum
    flLane1 = 0x01'u8,
    flLane2 = 0x02'u8

  FomkeChainState* {.role: truthState, tag: "cryptoBoundary|fomke|types".} = object
    chainKey*: ByteSeq
    nextIndex*: uint64

  FomkeSkippedKey* {.role: truthState, tag: "cryptoBoundary|fomke|types".} = object
    epoch*: uint32
    index*: uint64
    lane*: FomkeLane
    keyMaterial*: ByteSeq

  FomkeUpgradeCommit* {.role: truthState, tag: "exchange|fomke|types".} = object
    requestId*: uint32
    baseEpoch*: uint32
    targetEpoch*: uint32
    targetTier*: AmeMaskTier
    exchangeMask*: uint8
    lane1Index*: uint64
    lane2Index*: uint64
    generations*: array[ameMaxAlgorithmSlots, uint32]
    confirmationTag*: ByteSeq

  FomkePendingUpgrade* {.role: truthState, tag: "cryptoBoundary|exchange|fomke|types".} = object
    active*: bool
    commit*: FomkeUpgradeCommit
    candidateLane1*: FomkeChainState
    candidateLane2*: FomkeChainState
    candidateNextSecret*: ByteSeq
      ## The NS the new epoch will carry, taken up together with the lanes.

  ## One message's worth of work done ahead of time. `material` is the whole
  ## derived key block for that message: nonce first, then one key per
  ## switched-on cipher slot, then one per switched-on authenticator slot.
  FomkePreparedSendEntry* {.role: memory, tag: "cryptoBoundary|fomke|types".} = object
    epoch*: uint32
    index*: uint64
    lane*: FomkeLane
    material*: ByteSeq
    nextChainKey*: ByteSeq

  FomkeSendCache* {.role: memory, tag: "cryptoBoundary|fomke|types".} = object
    epoch*: uint32
    lane*: FomkeLane
    nextIndex*: uint64
    chainKey*: ByteSeq
    nextEntry*: int
    entries*: seq[FomkePreparedSendEntry]

  FomkeState* {.role: truthState, tag: "cryptoBoundary|fomke|types".} = object
    role*: FomkeRole
    epoch*: uint32
    algorithms*: AmeKemAlgorithms
    layout*: AmeSuiteLayout
      ## Which ciphers and authenticators exist, in a fixed order.
    tier*: AmeMaskTier
      ## Which of those slots are switched on right now.
    tagLen*: AmeAuthTagLen
      ## How many tag bytes this session agreed to carry. A tag that arrives
      ## at any other length is refused before it is even compared.
    lane1*: FomkeChainState
    lane2*: FomkeChainState
    nextSecret*: ByteSeq
      ## NS -- see `fomkeNextSecretBytes`. Replaced at every rotation.
    skipped*: seq[FomkeSkippedKey]
    reorderWindow*: uint32
      ## How far ahead of the next expected position a message may sit and
      ## still be opened. Moves on its own as the path is measured.
    reorderCeiling*: uint32
      ## The widest `reorderWindow` may ever become on this session. Fixed
      ## when the ratchet is built and never moved afterwards.
    orderedRun*: uint32
      ## Messages that have arrived in order since the window last moved.
    kdf*: Gb3KdfConfig
    pending*: FomkePendingUpgrade

  FomkeMessage* {.role: truthState, tag: "fomke|packet|types".} = object
    epoch*: uint32
    index*: uint64
    senderLane*: FomkeLane
    tagLen*: AmeAuthTagLen
    authTag*: ByteSeq
    ciphertext*: ByteSeq

  FomkeOpenResult* {.role: truthState, tag: "fomke|types".} = object
    ok*: bool
    payload*: ByteSeq
    err*: string

  FomkeCheckpoint* {.role: truthState, tag: "cryptoBoundary|fomke|types".} = object
    ok*: bool
    state*: FomkeState
    counter*: uint64
    err*: string

  FomkeDurableMessage* {.role: truthState, tag: "cryptoBoundary|fomke|types".} = object
    ok*: bool
    message*: FomkeMessage
    checkpointCounter*: uint64
    err*: string

  FomkeDurableOpen* {.role: truthState, tag: "cryptoBoundary|fomke|types".} = object
    ok*: bool
    payload*: ByteSeq
    checkpointCounter*: uint64
    err*: string
