# DAC: Data Adaptive Connection

`DAC` is the transport-side companion to `AME`.

## Package Repair From The Top

```text
planDacPackage
  +-> Manifest: package size, chunk size, BLAKE3 digest
  +-> Chunks:   unordered pieces of the package
  +-> Repair:   XOR recovery bytes + Eir parity check

initDacPackageReceiver
  +-> accept chunks in any order
  +-> repairGroup when exactly one group chunk is absent
  +-> buildDacRepairHint when several chunks are absent
  +-> acceptDacRepairChunk for exact fallback data
  +-> finishDacPackage checks length + digest and emits a commit
```

Repair never means "trust repaired bytes." The final digest must match. When
DAC carries an AME secure package, AME authentication is a second independent
check after package repair.

```text
+-------------------------------+----------------------------------------------+
| AME                          | verifies and encrypts message lanes          |
| DAC                           | adapts delivery to path conditions           |
+-------------------------------+----------------------------------------------+
```

## Sender Receiver Shape

```text
+----------------------+                          +----------------------+
| DAC Sender           |                          | DAC Receiver         |
+----------------------+                          +----------------------+
| path lane selector   | -- PathProbe ----------> | probe echo actor     |
| path truth cache     | <- PathStats ----------- | path stats actor     |
| receive budget cache | <- ReceiveBudget ------- | memory budget actor  |
| package scheduler    | -- Manifest/Chunks ----> | package receive map  |
| parity/repair writer | -- Parity/RepairChunk -> | gap repair builder   |
| ack/repair reader    | <- Ack/RepairHint ------ | gap repair builder   |
| commit receipt cache | <- PackageCommit ------- | digest/commit actor  |
+----------------------+                          +----------------------+
```

## Base Frame

Common `DAC1` envelope. The first four bytes are `DAC` magic plus one
format-version byte. Normal path lanes keep `BodyLen` as `u16`; the
same-room/server-rack `SuperCleanPath` uses the extended envelope with
`BodyLen` as `u32`.

```text
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
```

## AME + DAC Layering

DAC owns delivery. AME owns message verification and encryption. That means a
receiver parses DAC first, uses the DAC `Kind` and `Flags` to ACK, repair,
reorder, or reassemble the body, and only then hands the delivered bytes to AME.

For encrypted application data, the DAC body normally contains an `AME2` frame,
or a package/chunk schema whose payload is a slice of AME secure-package bytes.
After DAC delivery is complete, AME parses that body, verifies it, decrypts it,
and yields the actual application message.

```text
+---------------- DAC1 -----------------+---------------- AME2 ----------------+
| path lane, repair, ACK, package order  | root/child lane, crypto, message     |
| BodyLen says how many bytes to deliver | parse only after DAC has delivered   |
+---------------------------------------+--------------------------------------+
| DAC Body: AME2 frame bytes or chunks that reassemble an AME secure package   |
+------------------------------------------------------------------------------+
```

## Sender Receiver Messages

Every DAC message is carried by a `DAC1` header. `Kind` says which body follows.
Some bodies travel sender to receiver, some receiver to sender, and some are
runtime memory views built from messages that already arrived.

```text
+----------------------+--------------------+--------------------------------+
| Message/body         | Usual direction    | Plain meaning                  |
+----------------------+--------------------+--------------------------------+
| PathProbe            | Sender -> Receiver | Can this path/lane work?       |
| PathStats            | Receiver -> Sender | This path currently looks like |
| ReceiveBudget        | Receiver -> Sender | You may send up to this much   |
| PackageManifest      | Sender -> Receiver | A package is about to arrive   |
| PackageChunk         | Sender -> Receiver | Original data bytes            |
| ParityShard          | Sender -> Receiver | Extra repair/ECC bytes         |
| AckRange             | Receiver -> Sender | I received these sequences     |
| RepairHint           | Receiver -> Sender | I need these missing bytes     |
| RepairChunk          | Sender -> Receiver | Here are the requested bytes   |
| PackageCommit        | Receiver -> Sender | Package verified/finished      |
| PathSwitch           | Either direction   | Move to another path lane      |
| DriftPayload         | Sender -> Receiver | Realtime pose snapshot/delta   |
+----------------------+--------------------+--------------------------------+
```

Concrete transfer:

```text
1. Sender -> Receiver: PathProbe {probeId=9, pathLane=SuperCleanPath}
2. Receiver -> Sender: PathStats + ReceiveBudget
3. Sender -> Receiver: PackageManifest {packageId=7001, totalLen=131072}
4. Sender -> Receiver: PackageChunk seq=10..13 carrying secure-package bytes
5. Receiver -> Sender: AckRange {ranges=[10..13]}
6. Receiver -> Sender: PackageCommit {status=Committed}
7. AME authenticates/decrypts the delivered package; Eir then decompresses it.
```

Compact realtime transfer:

```text
1. AME protects DacDriftPacket when the lane requires encryption/auth.
2. DAC carries it as Kind=DriftPayload on a low-latency path lane.
3. Receiver parses DAC first, opens AME if present, then decodes DacDriftPacket.
```

## Anti-Oracle Guard

`level0/anti_oracle.nim` adds a receiver-side helper for the case where one
client keeps replaying the same request shape with different keys or auth
material in order to learn from the server's error differences.

The helper keeps small per-client/per-request memory:
- bad message count
- unique key fingerprints seen for the same request
- unique internal error fingerprints seen for the same request
- client-wide delay protection state

Caller flow:

```text
1. Fingerprint raw request/key bytes with fingerprintDacAntiOracle(...).
2. peekDacAntiOracleDecision(...) before processing if the client might already
   be under delay protection.
3. recordDacAntiOracleBadMessage(...) after a reject.
4. If maskReply is true, send replyText instead of the specific internal error.
5. If delayMs > 0, sleep for that many ms or call enforceDacAntiOracleDelay(...).
6. recordDacAntiOracleAcceptedMessage(...) after a valid request to clear that
   request bucket.
7. triggerDacAntiOracleProtection(...) can force protection manually.
```

Default policy:
- collapse replies after `2` bad attempts across `2` different keys for the
  same request fingerprint
- activate client-wide delay after `6` bad attempts across `4` different keys
- delay range `3..11 ms`
- persistence `60` days plus a carry budget of `64` later session changes

The tracker is plain DAC state, not a socket daemon. That means higher-level
repos can persist `DacAntiOracleTracker` however they want if the delay memory
must survive restarts.

## Torii and Geist Fit

`dac://` is the stable public endpoint shape for higher-level repos that want
DAC as a network carrier without owning the raw UDP details.

- Geist uses DAC carrying AME frames for peer fetch/sync/server traffic.
- Torii should treat public Bifrost routes as opaque DAC/AME datagram relays.
- When Torii exposes a Bifrost-backed service on `dac://host:port`, the
  application protocol inside that carrier stays Bifrost/Geist-owned; Torii
  should not rewrite DAC sequence, lane, or session metadata.

The runnable `examples/ame_dac_echo.nim` file is the minimal reference for that
carrier contract.

## ASCII Object Examples

The following boxes are readable versions of the DAC schemas in `types.nim`.
Numbers are concrete example values, not fixed protocol constants.

### DacFrameHeader

The DAC header wraps every body. It is parsed before the body.
`encodeDacFrame` and `decodeDacFrame` enforce magic, version, known kind,
known flags, exact body length, and the SuperClean `u32` body limit.

```text
+----------------------------- DAC1 Header ------------------------------+
| Magic=DAC | Ver=1 | Kind=PackageChunk | Flags=CreditBound+ExtendedLen |
| Session=42 | Lane=5 | Epoch=2 | Seq=10 | BodyLenMode=u32 | BodyLen=70000 |
+------------------------------------------------------------------------+
```

### DacFrameFlags

Flags tell the receiver how to treat the body.

```text
+-------------------+-------+--------------------------------------------+
| Flag              | Value | Meaning in this example                    |
+-------------------+-------+--------------------------------------------+
| NeedsAck          | no    | receiver may batch ACK                     |
| IsRepair          | no    | this is not repair data                    |
| IsParity          | no    | this is original data                      |
| EndOfGroup        | no    | more chunks may follow in the group        |
| EndOfPackage      | no    | package is not complete yet                |
| PathProbe         | no    | ordinary package data                      |
| CreditBound       | yes   | sender is obeying receiver budget          |
| TcpRepairAllowed  | yes   | receiver may ask for exact TCP repair      |
| ExtendedBodyLen   | yes   | BodyLen is u32                             |
+-------------------+-------+--------------------------------------------+
```

### DacScenarioDefaults

Defaults are the chosen behavior for one path condition.

```text
+--------------------------- SuperClean Defaults ------------------------+
| Path=SuperCleanPath | BodyLenMode=u32 | Transfer=UserData              |
| Repair=None | ACK=Batch | MaxBodyLen=16777216 | ChunkBytes=32768       |
| DataShards=64 | ParityShards=0 | AckBatch=256 | AckDelay=25ms          |
| AckRanges=2 | GapBits=16 | RepairWait=25ms | ActiveGroups=8           |
+------------------------------------------------------------------------+
```

### DacSenderState

Sender state is memory, not a wire message. It is what the sender currently
believes it can send.

```text
+----------------------------- Sender State -----------------------------+
| Session=42 | Lane=5 | Path=SuperCleanPath | NextSeq=14                 |
| OutstandingPackages=1 | CreditBytes=393216 | ActiveGroups=2            |
+------------------------------------------------------------------------+
```

### DacReceiverState

Receiver state is memory, not a wire message. It tracks the receive window and
how much package data is buffered.

```text
+---------------------------- Receiver State ----------------------------+
| Session=42 | Lane=5 | Path=SuperCleanPath | WindowStart=10             |
| WindowSpan=512 | BufferedBytes=98304 | OpenPackages=1 | HintsSent=0     |
+------------------------------------------------------------------------+
```

### DacAntiOracleDecision

The anti-oracle decision is caller-facing memory, not a wire message. It says
whether the current reject should be masked and whether the client currently
owes a random delay.

```text
+-------------------------- Anti Oracle Decision ------------------------+
| ProtectionActive=yes | ProtectionTriggered=no | MaskReply=yes          |
| Reply="dac: request rejected" | DelayMs=7                              |
| BadCount=4 | UniqueKeys=3 | UniqueErrors=2                            |
+------------------------------------------------------------------------+
```

### PathProbe

PathProbe asks whether a path lane is usable.
The nonce is caller-supplied and must not be all zero; replayable default probes
are rejected by the constructor.

```text
+------------------------------ PathProbe -------------------------------+
| ProbeId=9 | Path=SuperCleanPath | UdpPort=48373 | TcpPort=48371        |
| Nonce=00 01 02 03 04 05 06 07 08                                  |
+------------------------------------------------------------------------+
```

### PathStats

PathStats reports what the receiver sees on the path.

```text
+------------------------------ PathStats -------------------------------+
| LossPpm=120 | RttMs=1 | JitterMs=0 | ReorderDepth=0 | MtuHint=9000     |
| QueueMs=1 | CreditHint=512                                             |
+------------------------------------------------------------------------+
```

### ReceiveBudget

ReceiveBudget is a wire message from receiver to sender. It says how much the
sender may send before waiting for more credit.
`dacBudgetAllowsBulk` requires all bulk-relevant limits to be nonzero,
including burst, ACK, repair, and hold fields.

```text
+----------------------------- ReceiveBudget ----------------------------+
| MaxBytes=524288 | MaxPackages=8 | MaxGroups=32 | MaxBurst=65535        |
| AckBudget=256 | RepairBytes=65536 | HoldMs=100                         |
+------------------------------------------------------------------------+
```

### Budget Cache

The budget cache is sender memory built from the latest `ReceiveBudget`
messages. It is not sent directly.

```text
+----------------------------- Budget Cache -----------------------------+
| PeerSession=42 | Lane=5 | Source=ReceiveBudget seq=3                  |
| CreditLeft=393216 | MaxBurst=65535 | AckBudget=256 | HoldUntil=+100ms  |
| Sender rule: stop bulk data when CreditLeft reaches 0                  |
+------------------------------------------------------------------------+
```

### PackageManifest

PackageManifest declares the package before chunks arrive. In encrypted flows,
the package payload usually reassembles into authenticated AME package bytes.
Constructors require a nonzero 32-byte package digest. `DataCount` is the
package chunk count, while `GroupSize` remains the repair-group shard width.

```text
+---------------------------- PackageManifest ---------------------------+
| PackageId=7001 | Class=UserData | ChunkBytes=32768                    |
| DataCount=4 | ParityCount=0 | GroupSize=4 | Repair=None               |
| Digest=ab cd ef ... 32 bytes ... 90 | TotalLen=131072 | NameLen=8      |
+------------------------------------------------------------------------+
```

### PackageChunk

PackageChunk carries original data bytes.

```text
+----------------------------- PackageChunk -----------------------------+
| PackageId=7001 | GroupId=1 | ChunkId=0 | Offset=0                     |
| PayloadLen=32768 | Payload=secure package bytes [0..32767]            |
+------------------------------------------------------------------------+
```

### DacDriftPacket

DacDriftPacket is a compact realtime body for pose snapshots and deltas. It is
not a standalone protocol frame and has no local authTag; DAC carries it, and
AME protects it when encryption or verification is required.

```text
+--------------------------- DriftPayload Body ---------------------------+
| Kind=Delta | Tick=90125                                                 |
| Position=(x=12.500, y=0.000, z=-3.250)                                  |
| Rotation=(x=0.000, y=1.570, z=0.000)                                    |
+------+-------+------+------+------+------+------+------+
| Kind | Tick  | PosX | PosY | PosZ | RotX | RotY | RotZ |
| u8   | u32   | f32  | f32  | f32  | f32  | f32  | f32  |
+------+-------+------+------+------+------+------+------+
| BodyLen=29 | TransferClass=Realtime | DAC Kind=DriftPayload             |
+--------------------------------------------------------------------------+
```

### ParityShard

ParityShard carries ECC/FEC bytes. Clean paths may not need it; lossy paths do.

```text
+----------------------------- ParityShard ------------------------------+
| PackageId=8002 | GroupId=3 | ShardId=17 | Repair=ReedSolomon          |
| PayloadLen=768 | Payload=parity bytes for missing/corrupt chunks       |
+------------------------------------------------------------------------+
```

### Package Receive Map

The package receive map is receiver memory built from `PackageManifest`,
`PackageChunk`, `ParityShard`, and `RepairChunk`. It is not sent directly.

```text
+--------------------------- Package Receive Map ------------------------+
| PackageId=7001 | TotalLen=131072 | Digest=ab cd ef ... pending check  |
| Group 1: Chunk0=ok | Chunk1=ok | Chunk2=missing | Chunk3=ok           |
| Parity: none | BytesBuffered=98304 | NextAction=send RepairHint        |
+------------------------------------------------------------------------+
```

### AckRange

AckRange says which DAC sequence numbers arrived.

```text
+------------------------------- AckRange -------------------------------+
| AckBase=10 | GapBits=0 | CommitCount=0                                |
| Ranges: [StartSeq=10, Count=4]  -> received seq 10,11,12,13            |
+------------------------------------------------------------------------+
```

### RepairHint

RepairHint asks for missing or corrupt data.

```text
+------------------------------ RepairHint ------------------------------+
| PackageId=7001 | GroupId=1 | Missing=1 | Corrupt=0 | Wanted=1         |
| GapMap=00000100 | Repair=TcpExact | Reason=Missing                    |
+------------------------------------------------------------------------+
```

### RepairChunk

RepairChunk answers a RepairHint.

```text
+------------------------------ RepairChunk -----------------------------+
| PackageId=7001 | GroupId=1 | ChunkId=2 | Source=TcpExactChunk         |
| PayloadLen=32768 | Payload=secure package bytes [65536..98303]        |
+------------------------------------------------------------------------+
```

### PackageCommit

PackageCommit is the receiver's final package receipt.

```text
+----------------------------- PackageCommit ----------------------------+
| PackageId=7001 | Digest=ab cd ef ... 32 bytes ... 90                  |
| DataCount=4 | RepairCount=1 | Status=CommittedWithRepair              |
+------------------------------------------------------------------------+
```

### PathSwitch

PathSwitch moves the session to a new horizontal path lane and starts a new
path epoch.

```text
+------------------------------ PathSwitch ------------------------------+
| OldEpoch=2 | NewEpoch=3 | OldPath=SuperCleanPath | NewPath=CleanPath  |
| Reason=AddressChanged                                                   |
+------------------------------------------------------------------------+
```

## Path Profiles

- `SuperCleanPath`: same-room or same-rack servers, `u32` `BodyLen`, up to
  16 MiB per DAC body by default, no repair unless the receiver asks.
- `CleanPath`: LAN/Wi-Fi defaults with small `u16` frames and light parity.
- `MobilePath`, `ThinPath`, and `LossyPath`: progressively smaller chunks,
  stronger repair, and tighter ACK cadence for metered or unstable links.
- `BlockedUdpPath`: stream-style fallback when UDP-like delivery is unavailable.
- `RecoveryPath`: audited, repair-heavy defaults for critical weak recovery.

## Module Split

```text
+----------------------------+------------------------------------------------+
| Module                     | Responsibility                                 |
+----------------------------+------------------------------------------------+
| types.nim                  | shared enums, defaults, frame and message schemas |
| level0/transport.nim       | DAC address and socket helpers                 |
| level0/framing.nim         | frame flag packing and renderer names         |
| level0/body_codec.nim      | shared little-endian body codec helpers       |
| level0/sender_receiver.nim | sender and receiver truth-state initializers  |
| level0/defaults.nim        | path defaults for repair and ACK behavior     |
| level0/path_stats.nim      | receiver path metrics                         |
| level0/receive_budget.nim  | receiver memory/credit budget                 |
| level0/ack_range.nim       | compact ACK ranges                            |
| level0/package_commit.nim  | digest-verified package commit                |
| level0/protocols.nim       | protocol descriptor                           |
| level1/path_probe.nim      | reachability probing                          |
| level1/package_manifest.nim| package declaration                           |
| level1/package_chunk.nim   | original data chunks                          |
| level1/parity_shard.nim    | parity/FEC shards                             |
| level1/repair_hint.nim     | receiver repair requests                      |
| level1/repair_chunk.nim    | exact repair chunks or extra parity           |
| level1/path_switch.nim     | horizontal path-lane epoch changes            |
| level1/drift_payload.nim   | compact realtime drift packet body            |
+----------------------------+------------------------------------------------+
```
