## -------------------------------------------------------------------------
## DAC Types <- Data Adaptive Connection shared transport records
## -------------------------------------------------------------------------

import ../types
import runePragmas

const

  dacCarriedAscii* = """
DAC does not frame anything itself. Every message it sends travels as the
body of an AME frame, and its KIND is the first byte of that body:

  +------------- one AME frame -------------+
  | AME header | FOMKE | tag | ciphertext   |
  +------------------------------|----------+
                                 |
                    +------------v-------------+
                    | DacKind u8 | DAC body    |
                    +--------------------------+

So the kind is recovered only after the tag has checked out. There is no
unauthenticated DAC framing and no way for a stranger to present a kind:
DAC decides parameters, AME carries the words.

What DAC still owns, above that line:

  +----------------------+                    +----------------------+
  | package scheduler    | -- Manifest/Chunks | package receive map  |
  | parity builder       | -- ParityShard --> | group repair actor   |
  | repair actor         | <- Ack/RepairHint  | gap/receipt builder  |
  | commit writer        | -- PackageCommit-> | digest/commit actor  |
  +----------------------+                    +----------------------+
"""

  dacSenderReceiverAscii* = """
+----------------------+                          +----------------------+
| DAC Sender           |                          | DAC Receiver         |
+----------------------+                          +----------------------+
| package scheduler    | -- Manifest/Chunks ----> | package receive map  |
| parity builder       | -- ParityShard -------->| group repair actor   |
| repair actor         | <- Ack/RepairHint ------ | gap/receipt builder  |
| commit writer        | -- PackageCommit ------> | digest/commit actor  |
+----------------------+                          +----------------------+

Neither side asks the other to behave differently. Each one decides its own
encoding from what it can see locally:

  the sender picks    chunk size, repair mode, parity width, repair timer
  the receiver picks  ACK batch size, ACK deadline, receipt encoding

An ACK states which sequences arrived. A repair hint states which chunks are
still missing. Both are facts about the speaker, never instructions for the
listener -- so the two loops control disjoint things and cannot fight.
"""

type
  ## DacAddress: public DAC endpoint. It lives here rather than beside the
  ## socket helpers so a module can name a DAC peer without compiling the
  ## datagram transport, which carries sockets and a peer registry.
  DacAddress* {.role: truthState.} = object
    host*: string
    port*: uint16

  ## DacMessageKind: the nine words DAC can say.
  ##
  ## Every one of them except `dmkUnknown` has a branch in `feedDacMessage`.
  ## That is the whole list and there is nothing else to look up: if a kind is
  ## in this enum, the loop acts on it.
  ##
  ## Four kinds used to sit here that the loop had no branch for -- a path
  ## probe, a path-switch request and its ack, and a realtime pose packet.
  ## They had encoders, decoders and fuzz tests, and a caller could seal one
  ## and watch the peer ignore it. See `dac/README.md`, "Four words DAC used
  ## to have", for why each one went.
  DacMessageKind* = enum
    dmkUnknown = 0x00'u8,
    dmkPathStats = 0x01'u8,
    dmkPackageManifest = 0x02'u8,
    dmkPackageChunk = 0x03'u8,
    dmkParityShard = 0x04'u8,
    dmkAckRange = 0x05'u8,
    dmkRepairHint = 0x06'u8,
    dmkRepairChunk = 0x07'u8,
    dmkPackageCommit = 0x08'u8

  ## DacPathLane: horizontal path condition profile.
  DacPathLane* = enum
    dplCleanPath = 0x00'u8,
    dplMobilePath = 0x01'u8,
    dplThinPath = 0x02'u8,
    dplLossyPath = 0x03'u8,
    dplBlockedUdpPath = 0x04'u8,
    dplRecoveryPath = 0x05'u8,
    dplSuperCleanPath = 0x06'u8

  ## DacTransferClass: vertical transfer meaning.
  DacTransferClass* = enum
    dtcStatus = 0x00'u8,
    dtcControl = 0x01'u8,
    dtcUserData = 0x02'u8,
    dtcArchive = 0x03'u8,
    dtcRecovery = 0x04'u8,
    dtcRealtime = 0x05'u8

  ## DacRepairMode: package repair strategy.
  DacRepairMode* = enum
    drmNone = 0x00'u8,
    drmXor = 0x01'u8,
    drmReedSolomon = 0x02'u8,
    drmTcpExact = 0x03'u8

  ## DacAckMode: receiver answer strategy.
  DacAckMode* = enum
    damSilent = 0x00'u8,
    damNackOnly = 0x01'u8,
    damBatch = 0x02'u8,
    damExplicit = 0x03'u8,
    damVerified = 0x04'u8

  ## DacTaggedMessage: one thing the link wants to say -- a kind and a body,
  ## and nothing else.
  ##
  ## It used to stamp a sequence here too, for the DAC header to carry. The
  ## AME frame has its own sequence and its own replay window over it, so a
  ## second counter was two numbers that always agreed and one of them was
  ## never read.
  DacTaggedMessage* {.role: truthState.} = object
    kind*: DacMessageKind
    body*: ByteSeq

  ## DacScenarioDefaults: default transport policy values for one condition.
  DacScenarioDefaults* {.role: configurator.} = object
    pathLane*: DacPathLane
    transferClass*: DacTransferClass
    repairMode*: DacRepairMode
    ackMode*: DacAckMode
    chunkBytes*: uint16
    dataShards*: uint16
    parityShards*: uint16
    ackBatchChunks*: uint16
    ackMaxDelayMs*: uint16
    repairWaitMs*: uint16
    repairRounds*: uint8

  ## DacAckRangeEntry: one contiguous sequence receipt.
  DacAckRangeEntry* {.role: truthState.} = object
    startSeq*: uint32
    count*: uint16

  ## DacAckRange: receiver ACK body in one of two shapes.
  ## ranges: contiguous runs of arrivals; empty in bitmap mode.
  ## gapMap: one bit per sequence, set where a sequence is missing; empty in
  ## run mode. Exactly one of the two is populated.
  DacAckRange* {.role: truthState.} = object
    ackBase*: uint32
    commitCount*: uint8
    ranges*: seq[DacAckRangeEntry]
    gapMap*: ByteSeq

  ## DacPathStats: receiver path report.
  DacPathStats* {.role: truthState.} = object
    lossPpm*: uint32
    rttMs*: uint16
    jitterMs*: uint16
    reorderDepth*: uint16
    mtuHint*: uint16
    queueMs*: uint16
    creditHint*: uint16

  ## DacReceiveBudget: receiver-advertised sender limits.
  DacReceiveBudget* {.role: truthState.} = object
    maxBytes*: uint32
    maxPackages*: uint16
    maxGroups*: uint16
    maxBurst*: uint16
    ackBudget*: uint16
    repairBytes*: uint32
    holdMs*: uint16

  ## DacCommitStatus: package receiver status.
  DacCommitStatus* = enum
    dcsRejected = 0x00'u8,
    dcsCommitted = 0x01'u8,
    dcsCommittedWithRepair = 0x02'u8,
    dcsExpired = 0x03'u8

  ## DacPackageCommit: package digest and assembly status.
  DacPackageCommit* {.role: truthState.} = object
    packageId*: uint64
    digest*: array[32, uint8]
    dataCount*: uint16
    repairCount*: uint16
    status*: DacCommitStatus

  ## DacPackageManifest: sender package declaration and receiver plan input.
  DacPackageManifest* {.role: truthState.} = object
    packageId*: uint64
    transferClass*: DacTransferClass
    chunkBytes*: uint16
    dataCount*: uint16
    parityCount*: uint16
    groupSize*: uint16
    repairMode*: DacRepairMode
    digest*: array[32, uint8]
    totalLen*: uint64
    nameLen*: uint8

  ## DacPackageChunk: original data shard.
  DacPackageChunk* {.role: truthState.} = object
    packageId*: uint64
    groupId*: uint32
    chunkId*: uint16
    offset*: uint32
    payload*: ByteSeq

  ## DacParityShard: FEC/ECC parity data for a repair group.
  DacParityShard* {.role: truthState.} = object
    packageId*: uint64
    groupId*: uint32
    shardId*: uint16
    repairMode*: DacRepairMode
    payload*: ByteSeq

  ## DacRepairReason: receiver reason for repair.
  DacRepairReason* = enum
    drrMissing = 0x00'u8,
    drrCorrupt = 0x01'u8,
    drrDecodeFailed = 0x02'u8,
    drrTimeout = 0x03'u8

  ## DacRepairHint: missing or corrupt shard report.
  DacRepairHint* {.role: truthState.} = object
    packageId*: uint64
    groupId*: uint32
    missingCount*: uint16
    corruptCount*: uint16
    wantedCount*: uint16
    gapMap*: ByteSeq
    repairMode*: DacRepairMode
    reason*: DacRepairReason

  ## DacRepairSource: sender repair source.
  DacRepairSource* = enum
    drsUdpExtraParity = 0x00'u8,
    drsTcpExactChunk = 0x01'u8,
    drsTcpFullFallback = 0x02'u8

  ## DacRepairChunk: repair payload from sender to receiver.
  DacRepairChunk* {.role: truthState.} = object
    packageId*: uint64
    groupId*: uint32
    chunkId*: uint16
    source*: DacRepairSource
    payload*: ByteSeq

  ## DacPathSwitchReason: why a side decided to change its own lane.
  ##
  ## This never travels. It is the word `recommendDacPathFromStats` hands back
  ## with its suggestion, so a caller reading `DacPathRecommendation.reason`
  ## can see WHY the loop wants to move rather than only where to.
  ##
  ## There used to be a `DacPathSwitch` message carrying it, asking a peer to
  ## move with you. That is the one shape this protocol refuses: a message is
  ## a fact about the speaker, never an instruction for the listener. See
  ## `dac/README.md`.
  DacPathSwitchReason* = enum
    dpsrLoss = 0x00'u8,
    dpsrMetered = 0x01'u8,
    dpsrUdpBlocked = 0x02'u8,
    dpsrAddressChanged = 0x03'u8,
    dpsrReceiverPressure = 0x04'u8,
    dpsrBatterySaver = 0x05'u8

proc dacMessage*(k: DacMessageKind, body: ByteSeq): DacTaggedMessage {.
    role: configurator.} =
  ## k: which of the nine words this is.
  ## body: the bytes that say it.
  ##
  ## There is nothing else to put on a DAC message, which is the point. The
  ## link used to build these through a helper that took the link itself and
  ## then discarded it -- left over from when a link stamped its own identity
  ## into a DAC header that no longer exists.
  result.kind = k
  result.body = body
