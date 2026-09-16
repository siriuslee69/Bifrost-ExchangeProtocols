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
| package scheduler    | -- Manifest/Chunks ----> | package receive map  |
| parity/repair writer | -- Parity/RepairChunk -> | gap repair builder   |
| ack/repair reader    | <- Ack/RepairHint ------ | gap repair builder   |
| commit receipt cache | <- PackageCommit ------- | digest/commit actor  |
| path truth cache     | <- PathStats ----------- | path stats actor     |
+----------------------+                          +----------------------+
```

## No Frame Of Its Own

DAC used to have a `DAC1` envelope: magic, version, kind, flags, session,
lane, epoch, sequence and a body length — 27 bytes of it. **It is gone.**

Every message DAC sends is the body of an AME frame, and its kind is the first
byte of that body:

```text
  +------------- one AME frame -------------+
  | AME header | FOMKE | tag | ciphertext   |
  +------------------------------|----------+
                                 |
                    +------------v-------------+
                    | DacKind u8 | DAC body    |
                    +--------------------------+
```

The kind is recovered only after the tag has checked out, so a stranger cannot
present one. Before, the kind sat in a header nobody had authenticated, and a
bare frame from an unknown address could claim a slot in the link table.

Every field of that envelope was restating something:

| field | why it is gone |
|---|---|
| Magic, Ver | the AME header already names the frame and its version |
| Kind | now the first byte of the sealed body, so it is authenticated |
| Flags | never read by a peer; the loop set them for nobody |
| Session, Lane, Seq | the AME header carries all three, and binds them |
| Epoch | AME epochs are the only epochs; DAC never had its own |
| BodyLen | the carrier delimits the frame, and the tag covers the length |

## AME + DAC Layering

**AME carries. DAC decides.** A receiver authenticates and opens an AME frame
first, reads the kind from the front of the plaintext, and only then does DAC
see anything at all. There is no branch in which DAC believes a kind it has not
already checked a tag over.

```text
+---------------- AME ------------------+---------------- DAC ----------------+
| session, lane, sequence, replay        | chunking, parity, ACK pacing,       |
| the tag over header AND body           | repair timing, path choice          |
| recovers the kind, then hands it over  | acts only on what AME handed it     |
+---------------------------------------+-------------------------------------+
```

The one place DAC **is** the outer layer is a stored package: AME seals the
whole thing once, and DAC then cuts the sealed blob into chunks and adds parity
on top. Encrypt, authenticate, then add repair data — which is what lets a
relay holding no key rebuild a lost chunk.

## Sender Receiver Messages

Every DAC message is carried by an AME frame. The kind, sealed with the body,
says which body follows.
Some bodies travel sender to receiver, some receiver to sender, and some are
runtime memory views built from messages that already arrived.

```text
+----------------------+--------------------+--------------------------------+
| Message/body         | Usual direction    | Plain meaning                  |
+----------------------+--------------------+--------------------------------+
| PathStats            | Receiver -> Sender | This path currently looks like |
| PackageManifest      | Sender -> Receiver | A package is about to arrive   |
| PackageChunk         | Sender -> Receiver | Original data bytes            |
| ParityShard          | Sender -> Receiver | Extra repair/ECC bytes         |
| AckRange             | Receiver -> Sender | I received these sequences     |
| RepairHint           | Receiver -> Sender | I need these missing bytes     |
| RepairChunk          | Sender -> Receiver | Here are the requested bytes   |
| PackageCommit        | Receiver -> Sender | Package verified/finished      |
+----------------------+--------------------+--------------------------------+
```

Eight words, and `feedDacMessage` has a branch for every one of them. There
is no ninth row to look up and no kind that arrives and is quietly ignored.

Concrete transfer:

```text
1. Sender -> Receiver: PackageManifest {packageId=7001, totalLen=131072}
2. Sender -> Receiver: PackageChunk  the package's pieces, in shuffled order
3. Sender -> Receiver: ParityShard   spare maths for each repair group
4. Receiver -> Sender: AckRange {ranges=[0..33]}
5. Receiver -> Sender: PackageCommit {status=Committed}
6. Receiver -> Sender: PathStats    what this delivery actually looked like
7. AME authenticates/decrypts the delivered package; Eir then decompresses it.
```

Nothing precedes step 1. A DAC message can only travel inside an AME frame,
so a session already exists by the time DAC has anything to say — which is
also why there is no longer a reachability probe: reaching the peer is a
precondition for asking whether you can reach it.

## Four words DAC used to have ꒰ঌ ໒꒱

Four message kinds were defined, encoded, decoded and fuzz-tested, and
`feedDacMessage` had a branch for none of them. A caller could build one,
seal it through AME, send it, and watch the peer answer `dlkIgnored`. They
are gone. Each one is written down here rather than just deleted, because
"why is this not here" is a harder question than "what is this".

**PathProbe** — *"can I reach you on UDP port X or TCP port Y?"*

Answered by the fact that it was asked. A probe can only travel inside a
sealed AME frame, which means a session already exists, which means the peer
is already reachable. The question's own precondition is its answer. What
remains of the job is covered:

```text
  can I reach this peer at all?     the handshake completes, or it does not
  is this path any good?            PathStats, measured, once per package
  is something badly wrong?         recommendDacPathFromFailures(retries,
                                    authFailures) walks the lane down
  UDP does not work here            dplBlockedUdpPath, chosen by config
```

**PathSwitchRequest / PathSwitchAck** — *"let us both move to lane B at epoch N."*

This one is not merely redundant, it is the one shape this protocol refuses.
Every DAC message is a **fact about the speaker**; a switch request is an
**instruction for the listener**, and it hands a peer a lever on your
parameters — `newPath` is arbitrary, so one message could drop you from the
clean lane to recovery in a single step. The measured path cannot do that:

```text
  PathStats arrives  ->  recommendDacPathFromStats  ->  ONE step, my lane only
```

`DacPathSwitchReason` survives, because the *vocabulary* was useful even
though the message was not: it is what a recommendation hands back so a caller
can see why the loop wants to move.

**DriftPayload** — a 29-byte position-and-rotation packet for a realtime pose
stream. Its own doc comment called it "salvaged". Nothing in Bifrost is about
poses; an application that wants to send one sends it as payload bytes like
anything else.

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

### DacTaggedMessage

One thing the link wants to say. A kind and a body, and nothing else — the AME
carrier seals both together, so the kind is authenticated rather than declared.

```text
+--------------------------- DacTaggedMessage ---------------------------+
| Kind=PackageChunk | Body = 70000 bytes of encoded chunk                |
+------------------------------------------------------------------------+
                                  |
                    sealed into one AME frame, kind 0x0B
                                  v
+------------------------------------------------------------------------+
| AME header 26 B | FOMKE 13 B | tag | enc: [DacKind u8][70000 bytes]     |
+------------------------------------------------------------------------+
```

There is no `DacFrameHeader` and no `DacFrameFlags` any more. The flags said
things like `NeedsAck`, `IsRepair` and `ExtendedBodyLen`; no peer ever read
them, and the length they described belonged to a field the carrier now
delimits. The sequence went the same way — the AME header carries one, with a
replay window over it, so a second counter was two numbers that always agreed.

### DacScenarioDefaults

Defaults are the chosen behavior for one path condition. Nearly every field
here is read by something -- a value that changed nothing would be a note to a
future implementer wearing the costume of a knob, which is worse than no note.

One exception, stated rather than hidden: `ackMode` is set per profile and
nothing acts on it. The ACK cadence is INFERRED -- the receiver watches what
arrives and picks its own batch size and deadline, which is the whole design
of `level1/ack_policy.nim`. A declared mode is the thing that design rejected.
It is read only to check that a non-silent profile also set a batch size.
Either the loop should honour it or it should go; it predates the framing
removal and is not fallout from it.

BlockedUdpPath has no defaults at all. It is a signal that UDP does not work
on this path, and the answer is the TCP carrier, so asking for its parameters
raises rather than returning a datagram policy that cannot be used.

```text
+--------------------------- SuperClean Defaults ------------------------+
| PathLane=SuperCleanPath | TransferClass=UserData                       |
| RepairMode=None | AckMode=Batch                                        |
| ChunkBytes=32768 | DataShards=64 | ParityShards=0                      |
| AckBatchChunks=256 | AckMaxDelayMs=25 | RepairWaitMs=25 | Rounds=1     |
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

### PathStats

PathStats reports what the receiver saw on the path. It is sent once, when a
package finishes, because that is the moment every number in it is settled
rather than guessed.

```text
+------------------------------ PathStats -------------------------------+
| LossPpm=120 | RttMs=0 | JitterMs=3 | ReorderDepth=0 | MtuHint=1200     |
| QueueMs=48 | CreditHint=13977                                          |
+------------------------------------------------------------------------+
```

**A zero means "I did not measure this".** Not "I measured zero". The only
exception is `LossPpm`, where a receiver that lost nothing really does mean
it, and which every receiver can always fill in. A rule in the lane policy
whose input is zero is skipped rather than believed.

That convention is not decoration. Here is what each field is, and which of
them Bifrost's own receiver can honestly produce:

```text
  field         who can know it                        filled in?
  -----------   ------------------------------------   ----------
  LossPpm       chunks repaired / chunks expected       yes
  MtuHint       the chunk size that GOT THROUGH, read   yes
                off the sender's manifest
  JitterMs      how much the gap between arrivals        yes
                kept changing
  QueueMs       how long this side has been holding      yes
                an unfinished package
  CreditHint    chunks of room left on top of what       yes, floored at 1
                is already held                         so 0 stays free to
                                                        mean "not measured"
  RttMs         only a side that SENT something and      only when this link
                was answered                            has sent
  ReorderDepth  nobody, on this wire -- see below        no, always 0
```

`MtuHint` is the sender's chunk size, not the receiver's. Reporting your own
configuration back at a peer is a statement about your plans and about nothing
else; the size that arrived is a fact about the path.

`ReorderDepth` is left at zero deliberately. A DAC sender shuffles a package's
chunks on purpose, so that an observer cannot read the shape of a file out of
the order its pieces cross the wire:

```text
  the package          0   1   2   3  ...  33
  what the sender      19  4   27  2  ...  8      <- Fisher-Yates, every send
  emits
  what arrives on a    19  4   27  2  ...  8      <- identical: the wire did
  FLAWLESS wire                                      nothing at all
```

Measured against chunk ids, that flawless delivery reports a reorder depth of
31 and the lossy-lane rule fires on it. The number is real; it is a
measurement of the sender's shuffling and not of the path. Measuring it
properly needs the carrier's send counter — AME stamps a monotonic sequence on
every frame, and an inversion in THAT is the network's doing — which means
handing the sequence down into the loop. Until then the field stays zero and
the rule that reads it stays quiet.

#### What a report does when it lands

Nothing, directly. A report is a fact about the speaker, never an instruction
for the listener. The listener runs it through `recommendDacPathFromStats` and
moves its **own** lane at most one step:

```text
  SuperClean  <-  Clean  <-  Mobile  <-  Thin  <-  Lossy  <-  Recovery
      5           4          3          2         1           0
                   \________/
                    one step per report, in whichever direction the
                    numbers point, and never while this side has a
                    package in flight
```

One step per report means a peer cannot drive the other end anywhere in a
hurry, however it lies. It also means a genuinely bad path takes as many
packages to reach the right lane as there are steps between here and there —
which is the trade that bounds the damage.
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

AckRange says which chunk ids arrived.

```text
+------------------------------- AckRange -------------------------------+
| AckBase=10 | GapBits=0 | CommitCount=0                                |
| Ranges: [StartSeq=10, Count=4]  -> received chunk 10,11,12,13          |
+------------------------------------------------------------------------+
```

#### Receipts and the shuffle ʕ•́ᴥ•̀ʔっ♡

The receiver batches its receipts instead of answering every chunk, and it
picks the batch size itself by watching what arrives. The whole scheme rests
on one assumption that is worth stating out loud, because DAC breaks it on
purpose:

> a hole in the middle of the batch means something was lost

That is true of a stream that arrives in the order it was sent. A DAC sender
does not send in order — it shuffles (see `level1/scramble.nim`) — so a hole
usually means "not sent yet" and fills itself in a moment later. Two things
follow, and the loop has to get both right:

**The window must be anchored to the package, not to the first arrival.**
The manifest says how many chunks there are, so the batch opens at chunk 0
and spans the whole package:

```text
  base                                              window
   |  0  1  2  3  4  5  6  7  8  ...                   |
      .  .  X  .  .  .  .  .  .            first arrival is chunk 2
      ^
      base stays at 0, so chunks 0 and 1 are still welcome when they land
```

Letting the first arrival set the base puts most of a shuffled package below
it, where arrivals are refused and never reported. And when the batch closes,
the base may only advance over chunks that actually **arrived**:

```text
      0  1  2  3  4  5  6  7  8
      X  X  X  .  X  X  .  X  X        X = arrived,  . = still missing
      \_____/
       settled  ->  base moves 3; 4, 5, 7 and 8 stay in the window
```

Sliding the whole span instead leaves chunks 3 and 6 permanently below the
base. They then appear in no receipt ever again, and the sender spends repair
rounds on chunks it already delivered.

**A hole must not move the levers.** The batch size and deadline shrink on
loss and creep back when things are clean. Fed on phantom holes they collapse:

```text
  34 chunks, flawless wire, every one delivered
                            before        after
  receipts sent             6             1
  batch size                64 -> 2       64 (untouched)
  deadline                  100ms -> 5ms  100ms (untouched)
  chunks the sender was     14 of 33      33 of 33
  told had arrived
  parity re-sent for        20            0
  chunks already held
```

So where the sender shuffles, holes are ignored and the levers move on
evidence the receiver actually has: the stall timer. When nothing has arrived
for a while and chunks are still missing, that silence is real loss — the
levers halve, and the batch is flushed on the spot so the sender knows exactly
what it still owes before it spends a repair round.

`DacAckPolicy.holesMeanLoss` is the switch, and `initDacLink` sets it from
this side's own scramble policy: a link that shuffles assumes its peer does
too. That is the safe direction to be wrong in — the worst case is that loss
is caught by the stall timer a beat later instead of instantly.


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

## Path Profiles

- `SuperCleanPath`: same-room or same-rack servers, up to
  16 MiB per DAC body by default, no repair unless the receiver asks.
- `CleanPath`: LAN/Wi-Fi defaults with small `u16` frames and light parity.
- `MobilePath`, `ThinPath`, and `LossyPath`: progressively smaller chunks,
  stronger repair, and tighter ACK cadence for metered or unstable links.
- `BlockedUdpPath`: stream-style fallback when UDP-like delivery is unavailable.
- `RecoveryPath`: audited, repair-heavy defaults for critical weak recovery.

## Module Split

```text
+-----------------------------+-----------------------------------------------+
| Module                      | Responsibility                                |
+-----------------------------+-----------------------------------------------+
| types.nim                   | shared enums, defaults, message schemas       |
| build.nim                   | is the adaptive layer in this build at all    |
| level0/transport.nim        | DAC address and socket helpers                |
| level0/wire_helpers.nim     | little-endian readers/writers and kind names  |
| level0/body_codec.nim       | shared body codec helpers                     |
| level0/defaults.nim         | the path profile table, as data               |
| level0/path_stats.nim       | the receiver's path report, on the wire       |
| level0/ack_range.nim        | compact ACK ranges and bitmaps                |
| level0/package_commit.nim   | digest-verified package commit                |
| level0/protocols.nim        | protocol descriptor                           |
| level1/package_manifest.nim | package declaration                           |
| level1/package_chunk.nim    | original data chunks                          |
| level1/parity_shard.nim     | parity/FEC shards                             |
| level1/repair_hint.nim      | receiver repair requests                      |
| level1/repair_chunk.nim     | exact repair chunks or extra parity           |
| level1/ack_policy.nim       | WHEN to send a receipt, and the repair timer  |
| level1/path_meter.nim       | what the receiver measures as chunks land     |
| level1/path_policy.nim      | turning a report into at most one lane step   |
| level1/scramble.nim         | send delay and chunk-order shuffling          |
| level2/package_transfer.nim | planning, receiving, repairing one package    |
| level3/link.nim             | the loop: one connection's whole state        |
| level3/link_table.nim       | many connections, bounded                     |
+-----------------------------+-----------------------------------------------+
```

These 22 files, and every one of them is reachable from `level3/link.nim`.
There used to be three more -- `path_probe`, `path_switch` and
`drift_payload` -- holding codecs for kinds the loop had no branch for. See
*Four words DAC used to have* above.

Reading order, if you want the whole thing:

```text
  types.nim                     what the shapes are
  level0/defaults.nim           the twelve profiles, as one table
  level1/package_manifest.nim   what a package announces about itself
  level2/package_transfer.nim   cutting one up, and putting it back together
  level3/link.nim               the loop that decides when to do any of it
```
