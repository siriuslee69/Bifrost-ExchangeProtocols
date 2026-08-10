## -------------------------------------------------------------------------
## DAC Types <- Data Adaptive Connection shared transport records
## -------------------------------------------------------------------------

import ../types
import ../../analysis_pragmas

const
  dacMagic* = [uint8('D'), uint8('A'), uint8('C')]
  dacFormatVersion* = 1'u8
  dacBaseHeaderLen* = 27
  dacExtendedHeaderLen* = 29
  dacSuperCleanMaxBodyLen* = 16_777_216'u32

  dacBaseFrameAscii* = """
+-------------------------- Common DAC1 Envelope --------------------------+
| DAC1 prefix = 3-byte magic DAC + 1-byte format version.                  |
| Default paths use BodyLen as u16. SuperCleanPath uses BodyLen as u32.    |
+-------+-----+------+-------+----------+----------+--------+--------+---------+---------+
| Magic | Ver | Kind | Flags | Session  | Lane     | Epoch  | Seq    | BodyLen | Body... |
+-------+-----+------+-------+----------+----------+--------+--------+---------+---------+
| DAC   | u8  | u8   | u16   | u64      | u32      | u16    | u32    | u16     | n bytes |
+-------+-----+------+-------+----------+----------+--------+--------+---------+---------+

SuperCleanPath extended envelope:
+-------+-----+------+-------+----------+----------+--------+--------+---------+---------+
| Magic | Ver | Kind | Flags | Session  | Lane     | Epoch  | Seq    | BodyLen | Body... |
+-------+-----+------+-------+----------+----------+--------+--------+---------+---------+
| DAC   | u8  | u8   | u16   | u64      | u32      | u16    | u32    | u32     | n bytes |
+-------+-----+------+-------+----------+----------+--------+--------+---------+---------+

Body layering:
+---------------- DAC transport ----------------+---------------- AME message ----------------+
| DAC parses Kind/Flags/Session/Lane/BodyLen     | Body can contain AME1 root/child bytes.     |
| DAC repairs, ACKs, reorders, and reassembles.  | AME parses, verifies, decrypts afterwards.  |
+-----------------------------------------------+---------------------------------------------+
"""

  dacSenderReceiverAscii* = """
+----------------------+                          +----------------------+
| DAC Sender           |                          | DAC Receiver         |
+----------------------+                          +----------------------+
| path lane selector   | -- PathProbe/Stats ----> | path truth state     |
| receive budget cache | <- ReceiveBudget ------- | memory/budget actor  |
| package scheduler    | -- Manifest/Chunks ----> | package receive map  |
| repair actor         | <- Ack/RepairHint ------ | gap/repair builder   |
| commit writer        | -- PackageCommit ------> | digest/commit actor  |
+----------------------+                          +----------------------+
"""

type
  ## DacMessageKind: data adaptive transport message kind.
  DacMessageKind* = enum
    dmkUnknown = 0x00'u8,
    dmkPathProbe = 0x01'u8,
    dmkPathStats = 0x02'u8,
    dmkReceiveBudget = 0x03'u8,
    dmkPackageManifest = 0x04'u8,
    dmkPackageChunk = 0x05'u8,
    dmkParityShard = 0x06'u8,
    dmkAckRange = 0x07'u8,
    dmkRepairHint = 0x08'u8,
    dmkRepairChunk = 0x09'u8,
    dmkPackageCommit = 0x0A'u8,
    dmkPathSwitchRequest = 0x0B'u8,
    dmkPathSwitchAck = 0x0C'u8,
    dmkDriftPayload = 0x0D'u8

  ## DacPathLane: horizontal path condition profile.
  DacPathLane* = enum
    dplCleanPath = 0x00'u8,
    dplMobilePath = 0x01'u8,
    dplThinPath = 0x02'u8,
    dplLossyPath = 0x03'u8,
    dplBlockedUdpPath = 0x04'u8,
    dplRecoveryPath = 0x05'u8,
    dplSuperCleanPath = 0x06'u8

  ## DacBodyLenMode: body length field width selected by the path profile.
  DacBodyLenMode* = enum
    dblU16 = 0x00'u8,
    dblU32 = 0x01'u8

  ## DacTransferClass: vertical transfer meaning.
  DacTransferClass* = enum
    dtcStatus = 0x00'u8,
    dtcControl = 0x01'u8,
    dtcUserData = 0x02'u8,
    dtcArchive = 0x03'u8,
    dtcRecovery = 0x04'u8,
    dtcRealtime = 0x05'u8

  ## DacDriftScalar: compact scalar type for realtime pose drift bodies.
  DacDriftScalar* = float32

  ## DacDriftVector3: realtime 3D vector.
  DacDriftVector3* {.role: truthState.} = object
    x*: DacDriftScalar
    y*: DacDriftScalar
    z*: DacDriftScalar

  ## DacDriftPose: compact position and rotation body.
  DacDriftPose* {.role: truthState.} = object
    position*: DacDriftVector3
    rotation*: DacDriftVector3

  ## DacDriftPayloadKind: realtime drift body kind.
  DacDriftPayloadKind* = enum
    ddpkSnapshot,
    ddpkDelta

  ## DacDriftPacket: salvaged realtime pose body carried by DAC, then AME if
  ## encrypted. It has no separate legacy frame and no local Gimli tag.
  DacDriftPacket* {.role: truthState.} = object
    kind*: DacDriftPayloadKind
    tick*: uint32
    pose*: DacDriftPose

  ## DacRepairMode: package repair strategy.
  DacRepairMode* = enum
    drmNone = 0x00'u8,
    drmXor = 0x01'u8,
    drmReedSolomon = 0x02'u8,
    drmFountain = 0x03'u8,
    drmTcpExact = 0x04'u8

  ## DacAckMode: receiver answer strategy.
  DacAckMode* = enum
    damSilent = 0x00'u8,
    damNackOnly = 0x01'u8,
    damBatch = 0x02'u8,
    damExplicit = 0x03'u8,
    damAudited = 0x04'u8

  ## DacFrameFlags: common DAC frame flags.
  DacFrameFlags* {.role: configurator.} = object
    needsAck*: bool
    isRepair*: bool
    isParity*: bool
    endOfGroup*: bool
    endOfPackage*: bool
    pathProbe*: bool
    creditBound*: bool
    tcpRepairAllowed*: bool
    extendedBodyLen*: bool

  ## DacFrameHeader: fixed DAC frame prefix.
  DacFrameHeader* {.role: truthState.} = object
    magic*: array[3, uint8]
    formatVersion*: uint8
    messageKind*: DacMessageKind
    flags*: uint16
    sessionId*: uint64
    laneId*: uint32
    epochId*: uint16
    sequence*: uint32
    bodyLenMode*: DacBodyLenMode
    bodyLen*: uint32

  ## DacDecodedFrame: parsed DAC envelope and body bytes.
  DacDecodedFrame* {.role: truthState.} = object
    header*: DacFrameHeader
    flags*: DacFrameFlags
    payload*: ByteSeq

  ## DacScenarioDefaults: default transport policy values for one condition.
  DacScenarioDefaults* {.role: configurator.} = object
    pathLane*: DacPathLane
    bodyLenMode*: DacBodyLenMode
    transferClass*: DacTransferClass
    repairMode*: DacRepairMode
    ackMode*: DacAckMode
    maxBodyLen*: uint32
    chunkBytes*: uint16
    dataShards*: uint16
    parityShards*: uint16
    ackBatchChunks*: uint16
    ackMaxDelayMs*: uint16
    ackRangeCount*: uint8
    gapBits*: uint16
    repairWaitMs*: uint16
    repairRounds*: uint8
    activeGroups*: uint8
    useTcpRepair*: bool
    compressManifest*: bool
    orderedStream*: bool

  ## DacSenderState: sender-side truth state for pacing and repair.
  DacSenderState* {.role: truthState.} = object
    sessionId*: uint64
    laneId*: uint32
    pathLane*: DacPathLane
    nextSequence*: uint32
    outstandingPackages*: uint16
    creditBytes*: uint32
    activeGroups*: uint8

  ## DacReceiverState: receiver-side truth state for package assembly.
  DacReceiverState* {.role: truthState.} = object
    sessionId*: uint64
    laneId*: uint32
    pathLane*: DacPathLane
    receiveWindowStart*: uint32
    receiveWindowSpan*: uint16
    bufferedBytes*: uint32
    openPackages*: uint16
    repairHintsSent*: uint16

  ## DacAntiOraclePolicy: receiver-side masking/delay policy for repeated bad
  ## request probes.
  DacAntiOraclePolicy* {.role: configurator.} = object
    badWindowSec*: uint32
    maskAfterBadCount*: uint16
    maskAfterUniqueKeys*: uint8
    delayAfterBadCount*: uint16
    delayAfterUniqueKeys*: uint8
    minDelayMs*: uint16
    maxDelayMs*: uint16
    protectForSec*: uint32
    protectSessions*: uint16
    maxTrackedClients*: uint16
    maxTrackedRequestsPerClient*: uint8
    maxTrackedKeysPerRequest*: uint8
    maxTrackedErrorsPerRequest*: uint8
    genericErrorReply*: string

  ## DacAntiOracleRequestState: one suspicious request fingerprint observed
  ## from one client.
  DacAntiOracleRequestState* {.role: truthState.} = object
    requestFingerprint*: string
    badCount*: uint16
    lastBadUnix*: int64
    keyFingerprints*: seq[string]
    errorFingerprints*: seq[string]

  ## DacAntiOracleClientState: one client's bad-message/oracle-defense memory.
  DacAntiOracleClientState* {.role: truthState.} = object
    clientFingerprint*: string
    lastSeenUnix*: int64
    lastSessionFingerprint*: string
    protectedUntilUnix*: int64
    protectedSessionsLeft*: uint16
    badMessageCount*: uint32
    maskedReplyCount*: uint32
    delayCounter*: uint32
    requests*: seq[DacAntiOracleRequestState]

  ## DacAntiOracleTracker: top-level receiver cache keyed by client
  ## fingerprint.
  DacAntiOracleTracker* {.role: truthState.} = object
    policy*: DacAntiOraclePolicy
    clients*: seq[DacAntiOracleClientState]

  ## DacAntiOracleDecision: one caller-facing decision after observing a
  ## message from a tracked client.
  DacAntiOracleDecision* {.role: truthState.} = object
    protectionActive*: bool
    protectionTriggered*: bool
    maskReply*: bool
    replyText*: string
    delayMs*: uint16
    badCount*: uint16
    uniqueKeyCount*: uint8
    uniqueErrorCount*: uint8

  ## DacAckRangeEntry: one contiguous sequence receipt.
  DacAckRangeEntry* {.role: truthState.} = object
    startSeq*: uint32
    count*: uint16

  ## DacAckRange: receiver ACK body.
  DacAckRange* {.role: truthState.} = object
    ackBase*: uint32
    gapBits*: uint8
    commitCount*: uint8
    ranges*: seq[DacAckRangeEntry]

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

  ## DacPathProbe: sender probe and receiver echo schema.
  DacPathProbe* {.role: truthState.} = object
    probeId*: uint32
    pathLane*: DacPathLane
    udpPort*: uint16
    tcpPort*: uint16
    nonce*: array[9, uint8]

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

  ## DacPathSwitchReason: reason for horizontal path lane switch.
  DacPathSwitchReason* = enum
    dpsrLoss = 0x00'u8,
    dpsrMetered = 0x01'u8,
    dpsrUdpBlocked = 0x02'u8,
    dpsrAddressChanged = 0x03'u8,
    dpsrReceiverPressure = 0x04'u8,
    dpsrBatterySaver = 0x05'u8

  ## DacPathSwitch: request or ACK body for path epoch transition.
  DacPathSwitch* {.role: truthState.} = object
    oldEpoch*: uint16
    newEpoch*: uint16
    oldPath*: DacPathLane
    newPath*: DacPathLane
    reason*: DacPathSwitchReason
