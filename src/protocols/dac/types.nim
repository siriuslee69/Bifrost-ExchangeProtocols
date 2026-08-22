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

  ## DacMessageKind: data adaptive transport message kind.
  DacMessageKind* = enum
    dmkUnknown = 0x00'u8,
    dmkPathProbe = 0x01'u8,
    dmkPathStats = 0x02'u8,
    dmkPackageManifest = 0x03'u8,
    dmkPackageChunk = 0x04'u8,
    dmkParityShard = 0x05'u8,
    dmkAckRange = 0x06'u8,
    dmkRepairHint = 0x07'u8,
    dmkRepairChunk = 0x08'u8,
    dmkPackageCommit = 0x09'u8,
    dmkPathSwitchRequest = 0x0A'u8,
    dmkPathSwitchAck = 0x0B'u8,
    dmkDriftPayload = 0x0C'u8

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
    drmTcpExact = 0x03'u8

  ## DacAckMode: receiver answer strategy.
  DacAckMode* = enum
    damSilent = 0x00'u8,
    damNackOnly = 0x01'u8,
    damBatch = 0x02'u8,
    damExplicit = 0x03'u8,
    damVerified = 0x04'u8

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

  ## DacTaggedMessage: one thing the link wants to say, before any framing has
  ## decided how to carry it. The kind and the body are DAC's business; whether
  ## that ends up as a bare DAC1 frame or as authenticated bytes inside an AME
  ## frame is the carrier's. The sequence is stamped here rather than at render
  ## time so the order the link chose survives whichever framing is used.
  DacTaggedMessage* {.role: truthState.} = object
    kind*: DacMessageKind
    sequence*: uint32
    flags*: DacFrameFlags
    body*: ByteSeq

  ## DacFrameIdentity: the routing fields of a frame, read without copying the
  ## body. A dispatcher holding many peers has to know which link a datagram
  ## belongs to before it is willing to spend an allocation on it, so this
  ## reads the fixed prefix and stops. `ok` false means the bytes are not a
  ## usable DAC frame; it never raises, because deciding to drop a datagram
  ## must be the cheapest thing the dispatcher can do.
  DacFrameIdentity* {.role: truthState.} = object
    ok*: bool
    messageKind*: DacMessageKind
    sessionId*: uint64
    laneId*: uint32
    epochId*: uint16
    sequence*: uint32
    bodyLen*: uint32
    headerLen*: int

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
    repairWaitMs*: uint16
    repairRounds*: uint8

    ## The four below are DECLARED BUT NOT CONSULTED. Every scenario
    ## constructor sets them, nothing anywhere reads them back, and none of
    ## them reaches the wire. They are recorded intent, not behaviour:
    ##
    ##   activeGroups      no receiver bounds its in-flight repair groups
    ##   useTcpRepair      exact chunk repair is always available, flag or not
    ##   compressManifest  manifests are never compressed
    ##   orderedStream     no path reorders or refuses to reorder on this
    ##
    ## Setting one changes nothing. They are kept because they name work that
    ## was agreed and not built; treat a value here as a note to a future
    ## implementer rather than as a knob.
    activeGroups*: uint8
    useTcpRepair*: bool
    compressManifest*: bool
    orderedStream*: bool

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
