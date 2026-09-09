## -------------------------------------------------------------------------
## AME Types <- immutable algorithm layouts, mask tiers, and exchange state
## -------------------------------------------------------------------------

import ../types
import ../transport/types as transport_types
import ../dac/types as dac_types
import runePragmas

const
  ameMagic* = [uint8('A'), uint8('M'), uint8('E')]
    ## Three letters, not four. The version is the byte that follows, so the
    ## first four bytes of every AME frame read as "AME" plus one number.
  ameFormatVersion* = 4'u8
  ameFrameHeaderLen* = 26
  ameMaxAlgorithmSlots* = 8
  ameProtectionKeyLen* = 32
  ameProtectionAuthTagLen* = 32
    ## The tag length AME uses when nothing selects another. Kept as a
    ## constant because several sizing helpers still name it directly; the
    ## per-session value lives in `AmeRuntimeParams.authTagLen`.

  ## Byte 5 of every frame header holds two things at once. The low three
  ## bits name the message class, which has eight values and needs no more
  ## room than that. The five bits above it are flags about the frame itself.
  ##
  ##   bit  7   6   5   4   3   2   1   0
  ##        |   |   |   |   |   +---+---+-- message class (0..7)
  ##        |   |   |   |   +-------------- payload is padded
  ##        +---+---+---+------------------ unused, must be zero
  ##
  ## Unused bits are refused rather than ignored, so a flag added later can
  ## never be silently dropped by an older peer that would not honour it.
  ameFrameClassMask* = 0x07'u8
  ameFrameFlagPadded* = 0x08'u8
    ## The frame body was padded to whole blocks before it was sealed. The
    ## receiver strips the padding after the tag checked out, never before.
  ameFrameKnownFlags* = ameFrameFlagPadded

type
  AmePacketKind* = enum
    ampkUnknown = 0x00'u8,
    ampkAgreementProposal = 0x01'u8,
    ampkAgreementAccept = 0x02'u8,
    ampkAgreementReject = 0x03'u8,
    ampkExchangeKeys = 0x04'u8,
    ampkExchangeEnvelopes = 0x05'u8,
    ampkEpochReady = 0x06'u8,
    ampkLaneData = 0x07'u8,
    ampkProblem = 0x08'u8,
    ampkPing = 0x09'u8,
    ampkPong = 0x0A'u8,
    ampkDacControl = 0x0B'u8,
    ampkClientHello = 0x0C'u8,
    ampkHelloRetry = 0x0D'u8,
    ampkServerHello = 0x0E'u8,
    ampkClientFinish = 0x0F'u8

  AmeMessageClass* = enum
    amcStatus = 0x00'u8,
    amcTelemetry = 0x01'u8,
    amcControl = 0x02'u8,
    amcProfile = 0x03'u8,
    amcUserdata = 0x04'u8,
    amcSecret = 0x05'u8,
    amcArchive = 0x06'u8,
    amcRecovery = 0x07'u8

  ## How many bytes of authentication tag every protected message carries.
  ## The three values are the only ones expressible, so an out-of-range
  ## length cannot be built, stored or decoded into existence.
  ##
  ##   aatl32   256-bit authentication. The default, and what to keep on a
  ##            link that can afford it.
  ##   aatl24   192-bit. Eight bytes back per message.
  ##   aatl16   128-bit. The conventional floor, and worth it when the
  ##            payload is a handful of bytes and the tag dominates.
  ##
  ## This is a SESSION parameter, never a wire-supplied one. The receiver
  ## checks the arriving tag against the length its own session agreed; if it
  ## trusted the length field in the message instead, a sender could truncate
  ## the tag to one byte and forge with probability 1/256.
  AmeAuthTagLen* = enum
    aatl16 = 16'u8,
    aatl24 = 24'u8,
    aatl32 = 32'u8

  ## Whether a payload is rounded up to whole blocks before it is encrypted,
  ## so its exact length stops being visible on the wire. The wire value IS
  ## the block size, which is why `apadNone` is zero.
  ##
  ##   apadNone     no padding. The ciphertext is exactly as long as the
  ##                plaintext, and every observer learns that length.
  ##   apadBlock64  round up to a multiple of 64 bytes. Costs 1 to 64 bytes
  ##                per message and is REQUIRED whenever the payload was
  ##                compressed first -- see level1/padding.nim for why.
  AmePaddingPolicy* = enum
    apadNone = 0'u8,
    apadBlock64 = 64'u8

  ## Knobs AME exposes for something above it to tune per connection. They
  ## are part of the epoch, so both endpoints hold the same values and a
  ## change takes effect at the next tier rotation rather than mid-flight.
  AmeRuntimeParams* {.role: configurator.} = object
    authTagLen*: AmeAuthTagLen
    padding*: AmePaddingPolicy

  AmeKemAlgorithm* = enum
    akaFireSaber = 0x01'u8,
    akaNtruHps4096821 = 0x02'u8,
    akaKyber1024 = 0x03'u8,
    akaFrodo1344Aes = 0x04'u8,
    akaMcEliece8192 = 0x05'u8,
    akaSaber = 0x06'u8,
    akaNtruHps2048677 = 0x07'u8,
    akaKyber768 = 0x08'u8,
    akaFrodo976Aes = 0x09'u8,
    akaMcEliece6960 = 0x0A'u8,
    akaLightSaber = 0x0B'u8,
    akaNtruHps2048509 = 0x0C'u8,
    akaFrodo640Aes = 0x0D'u8,
    akaMcEliece6688 = 0x0E'u8,
    akaX25519 = 0x0F'u8

  AmeCipherAlgorithm* = enum
    acaXChaCha20 = 0x01'u8,
    acaGimli = 0x02'u8,
    acaAesCtr = 0x03'u8,
    acaChaCha20 = 0x04'u8

  AmeMacAlgorithm* = enum
    amaBlake3 = 0x01'u8,
    amaGimli = 0x02'u8,
    amaPoly1305 = 0x03'u8,
    amaSha3 = 0x04'u8

  AmeHashAlgorithm* = enum
    ahaBlake3 = 0x01'u8,
    ahaSha3 = 0x02'u8,
    ahaShake256 = 0x03'u8,
    ahaGimliXof = 0x04'u8

  ## Ed448 used to sit at 0x02. It existed only as a liboqs algorithm, so
  ## keeping it would have forced every AME build to link liboqs. The slots
  ## below are renumbered contiguously rather than leaving a hole, because
  ## the layout decoder range-checks ids and a hole would let an undefined
  ## value through.
  AmeSignatureAlgorithm* = enum
    asaEd25519 = 0x01'u8,
    asaDilithium44 = 0x02'u8,
    asaDilithium65 = 0x03'u8,
    asaDilithium87 = 0x04'u8,
    asaFalcon512 = 0x05'u8,
    asaFalcon1024 = 0x06'u8,
    asaSphincsShake128f = 0x07'u8,
    asaEd25519Falcon512Hybrid = 0x08'u8,
    asaEd25519Falcon1024Hybrid = 0x09'u8

  AmeKdfAlgorithm* = enum
    akfaBlake3 = 0x01'u8,
    akfaSha3Shake256 = 0x02'u8,
    akfaGimliXof = 0x03'u8,
    akfaArgon2id = 0x04'u8

  AmeKemAlgorithms* {.role: configurator.} = object
    length*: uint8
    algorithms*: array[ameMaxAlgorithmSlots, AmeKemAlgorithm]

  AmeCipherAlgorithms* {.role: configurator.} = object
    length*: uint8
    algorithms*: array[ameMaxAlgorithmSlots, AmeCipherAlgorithm]

  AmeMacAlgorithms* {.role: configurator.} = object
    length*: uint8
    algorithms*: array[ameMaxAlgorithmSlots, AmeMacAlgorithm]

  AmeHashAlgorithms* {.role: configurator.} = object
    length*: uint8
    algorithms*: array[ameMaxAlgorithmSlots, AmeHashAlgorithm]

  AmeSignatureAlgorithms* {.role: configurator.} = object
    length*: uint8
    algorithms*: array[ameMaxAlgorithmSlots, AmeSignatureAlgorithm]

  AmeKdfAlgorithms* {.role: configurator.} = object
    length*: uint8
    algorithms*: array[ameMaxAlgorithmSlots, AmeKdfAlgorithm]

  AmeSuiteLayout* {.role: configurator.} = object
    kems*: AmeKemAlgorithms
    ciphers*: AmeCipherAlgorithms
    macs*: AmeMacAlgorithms
    hashes*: AmeHashAlgorithms
    signatures*: AmeSignatureAlgorithms
    kdfs*: AmeKdfAlgorithms

  AmeTierMasks* {.role: configurator.} = object
    kem*: uint8
    cipher*: uint8
    mac*: uint8
    hash*: uint8
    signature*: uint8
    kdf*: uint8

  AmeMaskTier* {.role: truthState.} = object
    tierId*: uint32
    masks*: AmeTierMasks

  AmeAgreementProposal* {.role: truthState.} = object
    proposalId*: uint32
    layout*: AmeSuiteLayout
    initialTier*: AmeMaskTier

  AmeAgreementDecision* {.role: truthState.} = object
    proposalId*: uint32
    accepted*: bool
    selectionHash*: ByteSeq
    reason*: string

  AmeExchangeRequest* {.role: truthState.} = object
    targetTier*: AmeMaskTier
    exchangeMask*: uint8
    params*: AmeRuntimeParams
      ## Tunables the initiator wants the next epoch to use. The responder
      ## adopts them, so both sides rotate onto the same values instead of
      ## each following its own observer.

  AmeKemEnvelope* {.role: truthState.} = object
    ciphertext*: ByteSeq
    senderPublicKey*: ByteSeq

  AmeExchangeKeys* {.role: truthState.} = object
    request*: AmeExchangeRequest
    publicKeys*: seq[ByteSeq]
    secretKeys*: seq[ByteSeq]

  AmeExchangeResult* {.role: truthState.} = object
    request*: AmeExchangeRequest
    envelopes*: seq[AmeKemEnvelope]
    sharedSecrets*: seq[ByteSeq]

  AmeExchangeOffer* {.role: truthState.} = object
    requestId*: uint32
    baseEpochId*: uint32
    request*: AmeExchangeRequest
    publicKeys*: seq[ByteSeq]
    signatures*: seq[ByteSeq]

  AmeExchangeReply* {.role: truthState.} = object
    requestId*: uint32
    baseEpochId*: uint32
    request*: AmeExchangeRequest
    envelopes*: seq[AmeKemEnvelope]
    signatures*: seq[ByteSeq]

  AmeExchangeState* {.role: truthState.} = object
    algorithms*: AmeKemAlgorithms
    activeMask*: uint8
    generation*: array[ameMaxAlgorithmSlots, uint32]
    sharedSecrets*: array[ameMaxAlgorithmSlots, ByteSeq]

  AmeProtectedMessage* {.role: truthState.} = object
    payload*: ByteSeq
    authTag*: ByteSeq

  AmeFrameHeader* {.role: truthState.} = object
    magic*: array[3, uint8]
    formatVersion*: uint8
    packetKind*: AmePacketKind
    messageClass*: AmeMessageClass
    flags*: uint8
      ## Shares one wire byte with `messageClass`; see `ameFrameFlagPadded`.
    sessionId*: uint64
    rootLaneId*: uint32
    laneId*: uint32
    sequence*: uint32

  AmeDecodedFrame* {.role: truthState.} = object
    header*: AmeFrameHeader
    payload*: ByteSeq

  AmeIdentitySigningKey* {.role: truthState.} = object
    algorithm*: AmeSignatureAlgorithm
    publicKey*: ByteSeq

  ## The signing side of an authority. One keypair per occupied slot, in the
  ## same order the public stack lists them, so slot `i` of `signingKeys`
  ## always pairs with slot `i` of `secretKeys`.
  AmeAuthorityRoot* {.role: configurator.} = object
    authority*: string
    signingKeys*: seq[AmeIdentitySigningKey]
      ## The authority's public keys, one per slot. A certificate must carry
      ## one valid proof for every slot listed here -- an authority that signs
      ## with two algorithms cannot be forged by breaking only one of them.

  AmeAuthenticationMode* = enum
    am1c = 0, am1s = 1, am1m = 2
      ## AM1R describes relay topology, so it is not an authentication mode.

  AmePeerTrustResult* {.role: truthState.} = object
    ok*: bool
    mode*: AmeAuthenticationMode
    authority*: string
    algorithms*: seq[AmeSignatureAlgorithm]
    subjectKeyId*: string
    serial*: uint64
    err*: string

# ---- session / connection state (session state) ----

const
  ameSessionProtocolLongName* = "Adaptive Message Encryption"
  defaultAmeInboxCapacity* = 64
  defaultAmeMaxFrameBytes* = 16_777_216
  ameBytesPerMiB* = 1_048_576'u64
  ameSessionProtocolId* = "bifrost.ame.session"
  ameHandshakeNonceLen* = 32
  ameCertificateVersion* = 2'u8

type
  AmeCompressionAlgorithm* = enum
    aczNone = 0x00'u8,
    aczEirRle = 0x01'u8

  AmeCompressionPolicy* {.role: configurator.} = object
    algorithm*: AmeCompressionAlgorithm
    padding*: AmePaddingPolicy
      ## Padding applied after compressing and before encrypting. Switching
      ## compression on forces this on too, whatever it was set to: a
      ## compressed payload whose length still shows is the exact thing that
      ## has been used to read secrets out of other protocols.
    maxPlaintextBytes*: uint32
    maxEncodedBytes*: uint32
    maxExpansionRatio*: uint16

  AmeCarrier* = enum
    acrTcp,
    acrDac

  AmeEndpointRole* = enum
    aerInitiator,
    aerResponder

  AmeTrafficDirection* = enum
    atdInitiatorToResponder,
    atdResponderToInitiator

  AmePathTriggerKind* = enum
    aptManual = 0x00'u8,
    aptTransferredMiB = 0x01'u8,
    aptElapsedMs = 0x02'u8

  AmePathTrigger* {.role: configurator.} = object
    kind*: AmePathTriggerKind
    threshold*: uint64
    enabled*: bool
    fired*: bool

  AmeTierPath* {.role: truthState.} = object
    layout*: AmeSuiteLayout
    tierCount*: uint8
    tiers*: array[ameMaxAlgorithmSlots, AmeMaskTier]
    triggers*: array[ameMaxAlgorithmSlots, AmePathTrigger]
    transferredBytes*: uint64
    elapsedMs*: uint64
    dueMask*: uint8
    currentTierId*: uint32
    inFlightTierId*: uint32

  AmeTierStep* {.role: truthState.} = object
    available*: bool
    targetTier*: AmeMaskTier
    exchangeMask*: uint8
    request*: AmeExchangeRequest

  AmeEpochKeySet* {.role: truthState.} = object
    epochId*: uint32
    layout*: AmeSuiteLayout
    tier*: AmeMaskTier
    exchange*: AmeExchangeState
    transcriptSalt*: ByteSeq
    params*: AmeRuntimeParams
      ## The tunables THIS epoch was created with. They live per epoch, not
      ## per session, because a retiring epoch must keep opening frames that
      ## were sealed under its own values while the new epoch uses the new
      ## ones. Bound into every tag, so both endpoints must agree.

  AmeAuthPackage* {.role: truthState.} = object
    current*: AmeEpochKeySet
    retiring*: AmeEpochKeySet
    retiringFramesLeft*: int
    sessionId*: uint64
    endpointRole*: AmeEndpointRole
    authenticationMode*: AmeAuthenticationMode
    exchangeAuthenticationKey*: ByteSeq
      ## Session-derived AM1M proof key; never the provisioned PSK.
    localSignatureSecretKeys*: seq[ByteSeq]
    peerSignaturePublicKeys*: seq[ByteSeq]

  AmePendingExchange* {.role: truthState.} = object
    active*: bool
    offer*: AmeExchangeOffer
    secretKeys*: seq[ByteSeq]

  AmePendingIncomingExchange* {.role: truthState.} = object
    active*: bool
    requestId*: uint32
    request*: AmeExchangeRequest
    candidate*: AmeEpochKeySet

  AmeReplayWindow* {.role: truthState.} = object
    initialized*: bool
    highest*: uint32
    bitmap*: uint64

  AmePacket* {.role: truthState.} = object
    payload*: ByteSeq
    carrier*: AmeCarrier
    remoteDac*: dac_types.DacAddress
    remoteTcp*: transport_types.TcpAddress
    sessionId*: uint64
    rootLaneId*: uint32
    laneId*: uint32
    ameSequence*: uint32
    dacSequence*: uint32

  AmeOpenResult* {.role: truthState.} = object
    ok*: bool
    packet*: AmePacket
    err*: string

  AmeSessionInfo* {.role: truthState.} = object
    layoutBytes*: int
    tierId*: uint32
    tierMasks*: AmeTierMasks
    activeKemMask*: uint8
    epochId*: uint32
    sessionId*: uint64
    laneId*: uint32
    pending*: int
    capacity*: int
    transferredBytes*: uint64
    peerTrustRequired*: bool
    peerTrusted*: bool
    peerAuthority*: string
