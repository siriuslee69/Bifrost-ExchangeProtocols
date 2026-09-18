# Progress

Commit Message: Make every exchange stand on the ones before it

Features (Planned):
- 83 triple-nesting sites remain, all at depth 3 (a loop plus two tests).
  Every site deeper than that is gone. Mostly BFX2, the HTTP request parser
  and the CHUNKYAEAD worker pool.
- 32 routine families Otter reads as one routine with a knob: the five
  `initAme*Algorithms`, the five `carriers` frame wrappers, the four
  `requireAme*Built` guards, the three hash entry points. These want
  generics rather than the data table the DAC presets took.
- The biggest single family is the five `sealAme{Tcp,Dac}Frame` /
  `{begin,answer,finish,confirm}Ame{Tcp,Dac}ExchangeFrame` pairs in
  `ame/level2/session.nim` -- 63 lines, and the pairs differ ONLY in
  `acrTcp` vs `acrDac`. It is left alone on purpose: `level2/carriers.nim`
  already dispatches over exactly those pairs, so collapsing them makes its
  five wrappers trivial too, and the `when acrX in ameCarriersBuilt` guards
  live in that wrapper layer. Doing it properly means moving
  `ameCarriersBuilt` down to a level0 module so `session.nim` can guard
  directly and the wrapper layer can go -- about 98 lines across both
  families, but it touches the slim-build facade that `testDacFlag` and
  `testMinimalAme` pin by compile-failure probe. Worth doing; not worth
  doing halfway.
- Three families Otter lists are better left as they are, so they will keep
  showing up: `outbound`/`inboundAmeDirection` plus `fomkeRoleFor` (the
  third returns a different type, and merging the other two swaps two named
  calls for one bool flag), the three `init*TransportDescriptor`
  configurators (merging invents a public enum to save five lines), and the
  three `httpConnection*` predicates (one line each already).
- 4 oversized files: `http/level1/request_parser.nim`, `bfx2/reader.nim`,
  `tools/run_tls13_openssl_interop.nim`, `tools/generate_bfx2_vectors.nim`.
- 21 unused public routines, and none of them are deletable as they stand:

    6  converters (`toAmeKemAlgorithms` and siblings). Nim calls these
       implicitly, so no tool that looks for call sites can see them.
       Deleting one breaks every `AmeKemAlgorithms = [...]` literal.
    5  accessors reached by method-call syntax (`pending`, `inboxCapacity`,
       `info`, `start`, `connectAmeDacClient`) that the tool misses.
    5  the TLS socket server front end. Complete, and needs a loopback
       socket test rather than a unit test.
    5  `relayAsyncStreams`, `pinLocalhostDacPeer`, `sweepDacRepair`,
       `ameDacSendDelayMs`, `encodeTls13ServerKeyUpdate` -- real features
       wanting a socket or a built-up link to exercise.

Features (Done):
- A KEM slot holds everything it has ever agreed, not the last thing it
  agreed. `stackAmeSecret` folds the fresh shared secret into the slot's
  accumulated stack -- previous hashed, then hashed together with the new KEM
  output -- so recovering ONE exchange is no longer enough to read the epoch it
  belongs to. Each rotation adds a term and none ever removes one. Forward
  secrecy is unchanged: the old stack is erased as the new one is built and the
  new one is a one-way image of it.
- The provisioned AM1M secret reaches the key schedule. It used to prove who
  was speaking and go nowhere near a traffic key, so a broken KEM took the
  whole session and the out-of-band secret did nothing. `exchangeBinder` is
  derived from it and the finished transcript, under its own label, and mixed
  into every slot's stack on every exchange. AM1C and AM1S carry an empty
  binder -- they have no such secret, and inventing one would look like
  protection while resting on public values.
- `requestTier` re-exchanges every KEM slot the current tier already uses,
  unless told otherwise. It used to default to rekeying NOTHING, which was
  backwards: a rotation with no new KEM still changes every traffic key, so it
  looks like it did the work and did not. The expensive, honest thing happens
  when nobody says otherwise; `rekeyMask = 0` asks for the cheap one by name.
  Triggered rotations -- bytes moved, time elapsed -- do the same, for the same
  reason: the trigger firing is what says fresh key material is wanted.
- The cost is real and worth knowing before it surprises someone. An exchange
  carries a public key and a ciphertext per slot: one or two kilobytes for
  X25519, Saber, Kyber and NTRU, and HUNDREDS of kilobytes for Classic
  McEliece. A layout using McEliece re-ships that on every rotation now. The
  `rekeyMask` knob is per rotation, so a thin link can name a smaller one
  without deciding anything for the whole session.
- `ameStackDepth` reports how deep the SHALLOWEST chosen slot is, because an
  attacker picks the slot to work on. Asking for the tier already in force is
  the ordinary way to deepen without changing anything else.
- `ame/level1/secret_stack.nim` owns the whole life of those bytes -- what
  goes in (`applyAmeExchange`), what comes back out for a key to be built from
  (`buildAmeExchangeSeed`), and how deep it is. Those two used to sit in
  different files, which is how the meaning of a field can change on one side
  without the other noticing.
- A soak: `nimble soak`. Separate processes on separate loopback addresses,
  real UDP, real handshakes, induced loss, peer churn and a payload that
  carries its own name so the receiver can verify it without sharing memory
  with the sender. `docs/soak.md` is the whole story; it found three faults no
  unit test could have.
- A finished package no longer leaves its receipt asking to be sent. The ACK
  window slides over arrivals only and never past a hole -- right, and the
  window belonged to ONE package while the package ended without it. Every
  delivery repaired from parity, which is the normal case under loss, left a
  batch that asked to go out every deadline for the life of the process: ten
  sealed datagrams a second per link to a peer that had stopped listening, and
  each one refreshed `lastSeenMs` so the slot never looked quiet and was never
  reclaimed. `endDacIncoming` ends both together, with one last receipt for
  `damVerified` only -- that one carries the commit count a lost commit
  message would otherwise take with it. Same run, same settings: 2,878
  packages frozen at two minutes, to 17,159 and still climbing; 70 MB verified
  to 414 MB; 22 slots reclaimed to 319.
- FOMKE no longer dies on a lossy path. A held key whose message can no longer
  arrive is erased, the cache is capped by the ceiling rather than by the
  window that moves, and a full cache gives up its oldest key instead of
  refusing. Same run, same settings: 170 packages and everything dead after
  ten seconds -> 1,114 packages and still climbing after forty-five.
- `applyLinkStep` gives up held keys when a package ends. That is the moment
  it becomes knowable that nothing outstanding can still be useful, and the
  relay is the only thing that knows it. It also unblocks rekeying, which
  refuses to run while any skipped key is outstanding.
- `openDacListener` takes a receive-buffer size, and `setUdpReceiveBuffer`
  explains why a server needs one. The default queue is 208 KB here, which is
  generous for one conversation and small for a listener carrying forty-eight
  peers: a run lost 2,787 datagrams to socket-buffer overflow in 72 seconds,
  in BURSTS, which is the one shape of loss the ratchet cannot absorb. With 4
  MB the same run lost 2, and did a third more work.
- A DAC sender gives up. `dacSenderGaveUp` is the half of the sentence the
  receiver already spoke: rounds spent, twice the repair wait passed, nothing
  acknowledged. Without it one reply to a peer that had gone pinned a relay
  slot for the life of the process -- a soak filled all sixty-four in two
  minutes and then refused every new peer.
- AM1M works end to end on both endpoints, over the core API and the real
  TCP driver. One `AmeAuthentication` drives all three modes.
- AM1M mixes a binder from the provisioned secret into the handshake key
  schedule, and rotates epochs with a session-derived MAC key.
- A default-constructed authentication fails closed, with a test saying so.
- `discardFomkeSkipped` / `discardAmeSessionSkipped`: the way out of a
  session that can neither receive across a gap nor rekey.
- Pragmas come from the shared `Rune-Pragmas` repo; tags are strings.
- 542 of 542 evaluation routines declare a `testKind`.
- The twelve `*DacDefaults` presets are one enum plus one data table.
- `AmeSession.pathLane` is read, and the wall against link conditions
  moving a protection parameter is tested.
- Every site nested deeper than triple is gone: 26 -> 0.
- Unused public routines 47 -> 21; coverage 199 untested -> 148.
- Tests and benchmarks live under `evaluation/`.
- The FOMKE reorder window is measured, not configured, and it is what bounds
  the derive-before-you-check amplifier a forged datagram can aim at a peer.
- One retiring epoch, kept for stored packages and replaced by the next
  rotation rather than by a count of unrelated live traffic.
- Header protection: the frame counter is masked on the wire, so a relay no
  longer leaks that traffic in and traffic out are the same conversation.
- Session id rotation, three frames, changing only the wire label and no key.
- A blind UDP forwarder for the VPS: address mapping, NAS keepalive, a tiny
  overflow buffer, and no key material anywhere in it.
- The five ACK modes are real behaviour, not a table nobody read. One payload
  on one flawless wire now gets five measurably different answers.
- DacMessageKind is nine words and the loop has a branch for all but
  `dmkUnknown`. There is no list to keep in step with the enum any more.
- `ame/level2/session.nim` split in two at the obvious question: `session.nim`
  is WHAT a connection knows, `framing.nim` is WHAT one message looks like.
- The adaptive loop adapts in the right direction. A clean link stays clean;
  a lossy one walks down one step per package and settles. It used to reach
  the recovery lane in four packages on a flawless LAN.
- The receipt tells the sender what actually arrived. A flawless 34-chunk
  delivery now acknowledges all 34 in one receipt, where it used to report 14
  in six receipts and re-send parity for 20 chunks already delivered.
- A finished package reaches the caller even when its receipt cannot be
  sealed, and a send that cannot be sealed leaves the link usable.
- A fresh clone builds. `Rune-Pragmas` is a submodule, and the pinned
  `Tyr-Crypto` is at Tyr `main` 1585636, the first Tyr commit that imports
  `runePragmas` instead of the `metaPragmas` that no longer exists. Both
  verified by hiding the sibling checkouts and compiling against the
  submodules alone.

Features (In Progress):
- Nothing. Everything above is complete and every suite passes.

Notes:
- A twenty-five minute run with every fix in: 472,051 packages verified byte
  for byte, 11.40 GB, 16.95 million datagrams, 8,993 handshakes, 7,695 slots
  reclaimed, zero mismatches, zero escaped exceptions, zero FOMKE window
  refusals. 315 packages and 7.6 MB a second of sealed, ratcheted, chunked,
  verified traffic; the same run before the socket queue was sized managed 227
  and 5.5 MB. Server memory grew 584 KB in its first interval and 32 KB in its
  last, while serving five hundred more handshakes in that last one -- a curve
  flattening, not a line rising.
- The soak reaches a part of the code nothing else did. `sweepAmeDacRelay`
  had never been called by anything before it; the reclamation rule itself
  turned out to be right, and what was wrong was that a link could stay
  active forever so the rule never got a chance to fire.
- Three things the soak found and did NOT fix, all design decisions rather
  than bugs, all written up in `docs/soak.md`:

    a peer that leaves POLITELY still costs a slot for the whole idle
      window. `releaseAmeDacPeer` frees the slot on the side that calls it and
      nothing crosses the wire, so a server sizing its table by peer count
      sizes it wrong: slots needed is live peers PLUS live peers times
      idleMs over the seconds between reconnects. 48 peers reconnecting every
      30 seconds with a 20-second idle window need 80 slots, not 48.

    a reclaimed slot is SILENT. The peer is never told, so it cannot tell
      "my session is gone" from "the path got worse", and all it can do is
      wait out its own timeout once per package. Dropping in silence is the
      right default -- replying to a datagram from an address with no session
      is a reflection vector -- but the usual answer is a stateless reset
      token, and Bifrost has none.
    one socket cannot carry both a handshake and live traffic, because
      `ameDacServerHandshake` consumes and discards whatever it is not
      waiting for. Any real server must split the ports, as the soak server
      does, or grow a demultiplexer that reads the frame kind first.
- The idle window and the client package timeout are COUPLED and nothing in
  the code says so. A sender that has spent its repair rounds goes quiet while
  still believing it is connected, so an `idleMs` shorter than that silence
  reclaims live peers. With the defaults that is roughly four seconds; the
  soak defaults to fifteen.
- `Rune-Pragmas` is now a real submodule (`submodules/Rune-Pragmas`), not
  just a sibling path. 126 of 134 files under `src/` import `runePragmas`,
  so before this the repository compiled only on a machine that happened to
  have the sibling checkout. `config.nims` picks sibling first and submodule
  second with `elif`, never both: Nim takes the LAST matching `--path`, so
  adding both would silently reverse the intended preference.
- `webui` is deliberately NOT a package requirement. Only the desktop client
  imports it; `requireWebui` checks for it inside the two tasks that need it.
- autopush now follows Proto-RepoTemplate verbatim in shape: message via
  `--file`, stale-lock refusal, `agents/PROGRESS.md` as the source. It read a
  path removed in the restructure, so every autopush had been committing
  "No specific commit message given." `captureCommand` stands in for the
  template's `captureGit` -- same job, and a second one would be a duplicate.
- Two traps worth not re-learning. Otter's "written and never read" list
  does not scan `evaluation/`, so a field a test asserts on shows up as
  dead -- `AmeSession.lastErr` nearly got deleted on the tool's word. And
  its unused-public list cannot see `converter` calls, which are implicit;
  six of the seven names still on that list are converters.
- `dacMaxBodyLenForMode` reports what the length FIELD can express, not what
  a profile will send. The super-clean preset caps itself far below it.
  Confusing the two is how a body larger than policy would look encodable.
- A session-level FOMKE skip only arises on the datagram carrier. The TCP
  carrier requires an exact sequence, so a gap there is refused outright.
- SETTLED (was an open question): the retiring-epoch grace window. Measured
  by instrumenting the guard and running every suite plus the examples:
  `retireAmeFomke` ran 22 times, the guard was entered 0 times, the old
  ratchet was used 0 times. Not a gap in the tests -- three deliberate rules
  each make the situation impossible:

    TCP   an exact sequence is required, so holding a frame back is a gap
          and is refused outright
    DAC   FOMKE refuses a KEM upgrade while a receive-side skip is
          outstanding, so a held frame BEFORE the rotation blocks it
    DAC   FOMKE refuses to seal while an upgrade is pending, so a held
          frame cannot be made AFTER the rotation message either

  So the FOMKE half is gone: `fomkeRetiring`, `fomkeRetiringFramesLeft`,
  `retireAmeFomke`, `ameRetiringGraceFrames`, `consumeRetiringGrace`, and the
  second-attempt branch in `openFrameBody`. It was the expensive half -- a
  whole `FomkeState` copy including its skipped-key cache.

  `auth.retiring` STAYS. It is reached, just not by frames: by
  `openAmeSecurePackage`, which derives keys straight from the epoch with no
  ratchet involved. A stored package has no sequence and no sender waiting to
  re-send it, so losing those keys loses the bytes.

  Its lifetime is now one rotation instead of a hundred received frames. The
  frame counter was a real bug: it measured live traffic and then erased keys
  that live traffic has nothing to do with, so a busy session destroyed a
  stored package's keys in a second while an idle one kept them for days.
  Pinned by "live traffic does not expire the retiring epoch" (150 frames,
  past the old threshold on purpose).

  STILL OPEN, one level up: one spare epoch is not a promise. A package that
  sits through TWO rotations is unopenable. A package meant to outlive its
  session needs to carry its own key material rather than rely on session
  state. Worth deciding before the relay work, since the relay is exactly the
  path that makes packages outlive sessions.
- FOMKE's `maxSkip` is now an adaptive `reorderWindow`, and the rename is the
  smaller half of the change. The window bounds two costs, not one:

    RAM  parked keys, 32 bytes each (`fomkeMessageKeyBytes`)
    CPU  a message claiming N positions ahead costs N derivations BEFORE its
         tag is checked -- one cheap forged packet in, N derivations out

  The CPU half was the real exposure and nothing bounded it but a fixed 64.
  `openDecoded` authenticates before it looks at the sequence (deliberately:
  a forged wild sequence must not push the replay window forward), so no
  cheap filter runs first.

  Now: starts at 16, widens to twice a proved jump, narrows by half after 64
  in-order messages, floor 4, ceiling 64 (`fomkeDefaultReorderCeiling`). The
  ceiling equals the OLD fixed value on purpose, so the worst case is not
  regressed while the typical case is 4x cheaper.

  The security property that makes it work: widening happens inside
  `acquireFomkeInboundKey`, which runs on the `pending` clone that
  `openFomkeMessage` keeps only once the tag verifies. A forger cannot widen
  the window they are measured by. Pinned by "a forged message cannot widen
  the reorder window".

  `FomkeState` gained `reorderWindow`/`reorderCeiling`/`orderedRun`, so the
  checkpoint format moved to `fomkeStateVersion = 2`.
- `fomkeReorderWindow(S)` is public so a transport reporting path statistics
  can read the measured depth instead of measuring it again.
  `DacPathStats.reorderDepth` is the obvious consumer: it is a wire field
  with no production caller today (`initDacPathStats` is called only from
  tests and its own decoder). Not wired up -- FOMKE must not import DAC, and
  DAC can be compiled out entirely.
- `nim-check.sh` false-positives on a `var` whose initializer WRAPS onto the
  next line: it reads the continuation as a declaration with no default. It
  fires on every edit of `session.nim` (10 sites), `test_ame_session.nim`
  (24) and others. The values are all correctly initialized. Worth fixing in
  the hook rather than reshaping correct code around it.
- The Android instrumented tests cannot be compiled here: gradle wants
  `androidx.tracing:tracing:1.1.0` and it is not in the offline cache. The
  JVM unit tests run and pass. Set `ANDROID_HOME` to the repo's
  `.android-sdk` before any gradle task.
- Header protection lives in `ame/level1/header_protection.nim` and is NOT
  optional. Both ends must produce the same mask and there is nothing to
  negotiate, so it cannot depend on a primitive `-d:bifrostSymmetric=` may
  have left out of one of the two builds. BLAKE3 is the only primitive always
  compiled, so it is the only honest choice. `blake3AmeMac` refuses to emit
  fewer than 16 bytes -- correctly, it cannot know this caller wants a mask
  and not a tag -- so 16 are drawn and 4 are used.

  Two traps to not re-learn:

    the epoch-ready frame is sealed as the FIRST frame of an epoch the
      RECEIVER has not committed to, so it is masked with a key
      `auth.current` cannot produce. `recvHeaderKey(S, useCandidate)` derives
      it from `pendingIncoming.candidate` instead.
    `refreshAmeHeaderKeys` must be called wherever `auth.current` changes --
      three places today. A stale pair fails loudly (every frame refuses),
      which is the right way for a missed call to show up.
- Session id rotation keeps TWO ids apart, and collapsing them would be a
  silent disaster:

    auth.sessionId   the cryptographic identity, in every derived key, never
                     rotated
    sessionId        the header label, for routing and demux, rotated

  Rotating the label re-derives nothing. If they were one field, a rotation
  would change every traffic key and the session would go deaf.
- The session-id grace window IS reachable, unlike the epoch one that was just
  deleted, and for a reason worth keeping straight: it bounds frames already
  in the air, which is what a frame count is actually a good clock for, and
  DAC datagrams genuinely reorder past the assign message. It holds one
  integer, not a second set of keys.
- `src/protocols/relay/udp_forward.nim` is the VPS side and holds no key by
  design -- the VPS is the weakest CPU in the picture and authenticating there
  would cost a key derivation per datagram AND let the relay read everything.
  It is pure logic: no sockets, time passed in, same split as the DAC link
  modules.

  `ame/level3/dac_relay.nim` was NOT deleted. It is the authenticating
  endpoint relay, a different job from the blind forwarder, and it has its own
  suite. Worth a decision, not a guess.
- A test caught a real bug in the forwarder worth remembering: keepalive
  pacing keyed on "have we heard from the NAS" instead of "have we poked it"
  makes a DOWN NAS look permanently overdue, so the relay pokes on every
  single tick -- a poke storm from the weakest machine at the worst moment.
  `nasPoked` is a separate flag from `nasStarted` for exactly that reason.
- DECIDED: a package outlives exactly ONE rotation and is then discarded.
  Keeping more epochs alive is keeping more key material alive, and the point
  of rotating is that old keys stop existing. What changed is that the case is
  now LEGIBLE: `restoreAmeSecurePackage` sets `expired` and reports the epoch
  the package named, separately from a package whose bytes do not check out.
  Those two want opposite responses -- discard the first without a second
  thought, look into the second -- and one error string for both was hiding a
  real problem behind a routine one. `ameSecurePackageEpoch` reads the epoch
  off stored bytes with no key, so a caller can sort a pile before trying any.
- DECIDED and DONE: the bare, unauthenticated DAC1 framing is deleted.
  DacFrameHeader, DacDecodedFrame, DacFrameIdentity, the whole encode/decode/
  peek codec, the frame-flag pack pair, renderDacFrame(s), feedDacFrame,
  routeDacFrame and dacFrameOpensLink. Roughly 400 lines.

  The invariant that now holds, and that any future change must keep:

    DAC manages AME's parameters from what it observes.
    DAC may set a message KIND in an AME frame for repair/ack/request.
    DAC never sends a message without AME.
    AME needs no unauthenticated channel -- the first handshake included,
      which is sealed by signature or authority.

  It had no production caller. AmeDacRelay drops any datagram from an address
  holding no session, so a slot has always come from the handshake and never
  from a frame. The doc comment claiming it was for "a path probe before a
  session exists" described an intention nothing implemented.

  Import direction is worth stating because it is easy to get backwards:
  AME imports DAC. DAC never imports AME. That is what lets
  -d:bifrostDac=off delete the adaptive layer and leave a working wire.
- OPEN: the relay keepalive PAYLOAD is the caller's to supply. The relay holds
  no keys so it cannot produce anything the NAS would accept as authentic;
  what it sends must be something the NAS will answer or ignore cheaply from
  an unauthenticated source. Not yet decided what that datagram should be.
- `evaluation/tests/test_attack_surface.nim` is written from the attacker's
  chair: every test names WHAT THEY HOLD, WHAT THEY TRY, and HOW FAR THEY GET.
  The third one is the point -- it asserts on the specific error, because the
  check that refused an attack is the check that must never be weakened. If
  one of those strings changes, a layer of defence moved.

  Two findings from writing it, both worth keeping:

    a replay is stopped by the RATCHET, not the replay window. Using a
      message key destroys it, so the second copy finds no key. The window is
      the backstop behind that. If that assertion ever starts reading "AME
      replay rejected" instead, the ratchet stopped consuming its keys and
      forward secrecy went with it.
    a reused relay tag CAN misdeliver an answer to the wrong client. The
      relay is not a security boundary -- the bytes were sealed for somebody
      else and do not open -- but the test says so out loud rather than
      implying the relay prevents it. `clientIdleMs` is the lever.
- RECORDED LIMITATION, not a bug: an observer who can watch BOTH sides of the
  relay pairs the flows trivially, because the relay forwards bytes unchanged.
  Header protection and id rotation defeat an observer on ONE side. Nothing
  short of the relay re-encrypting would defeat both, and that would cost the
  relay its keylessness. There is a test that fails if this ever silently
  changes.
- Repair geometry differs sharply by preset and a test written against the
  wrong one looks like a protocol bug. Measured, not assumed:

    dscCleanLan    18 KB -> 16 chunks, ONE group, ONE XOR shard
                   budget: one lost chunk, full stop
    dscHeavyLoss   18 KB -> 36 chunks, THREE groups of 12, SIX Reed-Solomon
                   shards each; budget six per group, independently

  Two of the loss tests were written assuming several groups on a clean LAN
  and failed. The protocol was right and the tests were wrong.
- The 16 routines Otter lists as PLACEHOLDERS were checked one by one and are
  false positives: zero-value initializers (`initDacRepairTimer`,
  `initTls13SocketSession`), `noreturn` raisers for excluded primitives
  (`raiseExcludedSym` and siblings), and the `-d:ssl`-absent branch of
  `buildTlsContext` which raises by design. Nothing unfinished is hiding
  behind that count; Otter reads "short body returning a constant" as a stub.
- Sweep after the framing deletion. Three things it had orphaned, all found by
  asking Otter for readers rather than by reasoning about it:

    DacTaggedMessage.flags   NEVER READ ANYWHERE. I had claimed the loop still
                             set them "for its own use" -- it set them for
                             nobody. Gone, with DacFrameFlags and dacLinkFlags.
    DacTaggedMessage.sequence  written by tagDacBody, read nowhere. The AME
                             header carries a sequence and the replay window
                             runs over THAT one, so this was a second counter
                             that always agreed and nobody consulted. Gone,
                             with DacLink.nextSequence.
    bodyLenMode, maxBodyLen  plus DacBodyLenMode and dacSuperCleanMaxBodyLen.
                             They configured the width of a length field that
                             no longer exists, and were read only by the
                             validation that checked them against each other.

  Otter CONFIG dead fields 35 -> 27.
- The module `dac/level0/framing.nim` is now `wire_helpers.nim`. It holds
  little-endian readers/writers and two name lookups, and frames nothing;
  keeping the old name would have been the same kind of stale signpost the
  deletion was about. Eight importers, all updated.
- KNOWN and NOT swept: DacScenarioDefaults.ackMode. Set per profile, asserted
  by one test, and acted on by nothing -- the ACK cadence is INFERRED by
  level1/ack_policy.nim, which is precisely the design a declared mode
  rejects. It is read only to check a non-silent profile also set a batch
  size. It predates the framing removal, so deleting it is a separate
  decision, not fallout. Said out loud in dac/README.md rather than left for
  somebody to rediscover.
- What the DAC deletion cost in tests, and what replaced it. Nothing was
  dropped without its invariant being rehomed or explicitly retired:

    test_dac_link          carries DacTaggedMessage through the hostile pipe
                           instead of bytes. Loss, reordering and duplication
                           never cared about framing.
    test_dac_link_table    `admitAndFeed` stands in for `routeDacFrame`, doing
                           what AmeDacRelay does: admit from the session, then
                           feed the loop. Capacity, eviction, sweep and close
                           coverage is unchanged.
    test_wire_fuzz         fuzzes BODIES now, which is the input that still
                           exists -- what a peer WITH the keys can send.
    "a frame for another session is dropped"  -> moved to AME, where the
                           binding now lives. test_attack_surface covers it.
    "rubbish from an unknown address consumes no slot" -> retired. A stranger
                           cannot present a frame at all; the relay drops the
                           datagram before parsing. test_attack_surface's
                           "a flood from many addresses cannot exhaust the
                           relay" is the equivalent.
- `dacMagic`, `dacFormatVersion`, `dacBaseHeaderLen`, `dacExtendedHeaderLen`,
  `dacBaseFrameAscii` and the three `dac*BodyLenMode*` helpers went with the
  frame -- they described a header that no longer exists. `DacTaggedMessage`
  stays, carrying a kind and a body and nothing else. `DacFrameFlags` did NOT
  stay: an earlier note here claimed the loop still set flags "for its own
  use", and the sweep proved nothing ever read them.
- THE BIG ONE, and the shape of it is worth more than the fix: **a number
  nobody measured was being read as a measurement.** `measureDacPath` filled
  three of `DacPathStats`' seven fields and left four at zero. One of those
  four is `creditHint`, and `targetDacPathFromStats` opens with
  `creditHint <= 32` meaning "the receiver is out of buffer" -- the FIRST
  rule, so it fired before loss, MTU or round trip were even looked at.

  Every report DAC generated therefore said "I am drowning", and every link
  walked itself down the lane ladder one package at a time:

    clean -> mobile -> thin -> lossy -> recovery, in four packages, on a
    wire that had dropped nothing, with the reason given as "receiver
    pressure" on a receiver that was idle

  Measured, not reasoned about: two DacLinks, a perfect pipe, five packages.
  The existing tests never caught it because every one of them hand-builds a
  fully-populated `DacPathStats` -- none had ever used the report DAC itself
  produces.

  Fixed on both sides. The receiver now measures what it honestly can
  (`level1/path_meter.nim` plus `dacReceiveCreditChunks`), and the policy
  skips any rule whose input is zero. `mtuHint` is now the chunk size that
  GOT THROUGH, read off the sender's manifest, instead of this side's own
  configured chunk size -- which was a statement about this side's plans and
  about nothing else. `rttMs` is reported only when this link has sent
  something and been answered.
- The same shape appeared twice more, which is why it is worth naming: **a
  number that describes the SPEAKER'S OWN behaviour is not a measurement of
  the path.**

    reorderDepth   chunk order says what the sender's shuffle did. On a
                   flawless 34-chunk delivery it reads 31, which alone puts
                   the link over `dacShouldEnterLossyPath`. Left at zero on
                   purpose now; the honest measurement needs the CARRIER's
                   send counter (AME's monotonic sequence), because an
                   inversion in THAT is the network's doing. Worth wiring the
                   day the rule is wanted, not before.
    ACK holes      same cause. See below -- it was doing real damage.
- The ACK batch was being fed chunk ids by a shuffling sender, and it is
  written for a stream that arrives in the order it was sent. Measured on a
  perfect wire, 34 chunks, nothing dropped:

                              before        after
    receipts sent             6             1
    batch size                64 -> 2       64 (untouched)
    deadline                  100ms -> 5ms  100ms (untouched)
    sender told arrived       14 of 33      33 of 33
    parity re-sent for        20            0
    chunks already held

  Three separate bugs, all from the same assumption:

    1. the base floated to the FIRST arrival, so with a shuffle most of the
       package landed below it and `observeDacArrival` refused it. The
       function documents that contract -- "the caller answers by closing the
       batch and offering it again" -- and `feedDacChunk` was discarding the
       answer. Now the batch opens at chunk 0 with the manifest's chunk count
       as its window, and the refusal is honoured.
    2. closing slid the base by the whole SPAN, past sequences that had never
       arrived, putting them permanently out of reach. Now it slides by the
       arrived PREFIX only, so a hole keeps the window open over it.
    3. holes halved the levers. Now `holesMeanLoss` (set from this side's own
       scramble policy) decides whether they are evidence at all, and where
       they are not, the verdict comes from the stall timer instead -- which
       also flushes the batch on the spot, so the sender knows what it still
       owes before it spends a repair round.
- Two bugs at the AME/DAC seam, both about confusing "what arrived" with
  "what I could say about it":

    a finished package was DISCARDED when its commit could not be sealed.
      `applyLinkStep` sealed first and bailed on failure, so a payload that
      was parsed, repaired and digest-checked was thrown away to report that
      the receipt did not go out -- and since `finishDacIncoming` had already
      closed the receive, it was gone for good. The caller got `adrDropped`:
      the one answer that means nothing arrived. Now the event is decided
      from the link's own outcome first and the seal error rides alongside.
    a send that could not be sealed WEDGED the link. `beginDacPackage` claims
      the one outgoing slot before anything is sealed; nothing released it but
      a commit, which needs a peer that received something. Every later send
      answered "DAC link already has a package in flight", forever.
      `abandonDacPackage` is the way out, and `sendAmeDacPackage` rolls back
      and drops any half-sealed datagrams, so a send happens whole or not at
      all.
- A lane move used to rebuild the ACK policy under an open receive, throwing
  away where the batch was and what it had counted. The new lane seeds the
  NEXT receive; `openDacIncoming` calls `initDacAckPolicy` with the current
  defaults anyway.
- `test_dac_link`'s harness had a blind spot worth remembering: it watched for
  `dlkPackageComplete` only while feeding messages, never on the receiver's
  own tick. A package that finishes by rebuilding a group from parity already
  in hand completes ON the tick, so the run burned every remaining tick and
  reported failure for a payload sitting complete in the receiver. The loop
  reports the event; a harness has to read it.
- `AmeDacControlOpen` names the tuple `openAmeDacControl` returns. The same
  four fields were spelled out longhand at four call sites, and the wrapped
  spelling is one of the `nim-check.sh` false positives noted above.
- STILL OPEN, unchanged: `DacScenarioDefaults.ackMode` (set per profile, acted
  on by nothing); the relay keepalive payload; `dmkPathProbe`,
  `dmkPathSwitchRequest`, `dmkPathSwitchAck` and `dmkDriftPayload` are
  exported codecs with no branch in `feedDacMessage` -- a caller can build and
  seal one and the peer will answer `dlkIgnored`. Said out loud in
  `dac/README.md` under Module Split rather than left to be discovered.
- `docs/repo_structure.md` and `CONTRIBUTING.md` described a `.iron/` tree
  that does not exist and that the conventions forbid recreating. Corrected to
  `agents/`. The nimble file still has `findIronOverrideFile` looking for
  `.iron/.local.gitmodules.toml` -- dead, since nobody may create that
  directory, but it is build machinery and deleting it was not this task.
- DELETED, and each one for its own reason. `dmkPathProbe`,
  `dmkPathSwitchRequest`, `dmkPathSwitchAck` and `dmkDriftPayload` had bodies,
  encoders, decoders, fuzz tests and umbrella exports -- and no branch in
  `feedDacMessage`. A caller could build one, seal it and watch the peer
  answer `dlkIgnored`, which is worse than the feature being absent.

    PathProbe    "can I reach you on UDP port X?" -- and it could only travel
                 inside a sealed AME frame, so a session already existed and
                 the peer was already reachable. The question's precondition
                 was its answer. What is left of the job: the handshake
                 completes or it does not; PathStats measures quality;
                 recommendDacPathFromFailures walks the lane down on retries
                 and auth failures; dplBlockedUdpPath is chosen by config.
    PathSwitch   not merely redundant -- it is the one shape this protocol
                 refuses. Every DAC message is a fact about the SPEAKER; a
                 switch request is an instruction for the LISTENER, and
                 `newPath` is arbitrary, so one message could drop a peer from
                 clean to recovery in a single step. `feedDacPathStats` moves
                 a lane ONE step and only its own. `DacPathSwitchReason` stays
                 -- the vocabulary was useful, the message was not.
    DriftPayload a 29-byte pose packet whose own doc comment called it
                 "salvaged". Nothing in Bifrost is about poses.

  Kind bytes renumbered densely, 0x00..0x08. `dacMessageKindFromId` went from
  a 22-line case that listed every id a second time to a bounds check and a
  cast, so it cannot drift from the enum -- which it already had, once.
  `dacLinkHandlesKind` is now `k != dmkUnknown`.
- ackMode was a five-word vocabulary the loop ignored: every profile batched
  by count and deadline, so the table promised a metered link sent only NACKs
  and the recovery lane verified, and neither was true. Now each word does
  something the others measurably do not:

    damSilent    emits nothing at all. The sender learns a package landed from
                 the commit and from nowhere else.
    damNackOnly  emits only on a hole it can trust -- which, with a shuffling
                 sender, means the stall flush and not a mid-package gap. On a
                 clean 34-chunk delivery it sends ZERO receipts.
    damBatch     unchanged: count or deadline.
    damExplicit  one receipt per chunk.
    damVerified  batch pacing, plus the running commit count in every receipt.

  `damVerified` earns its keep in one specific way, and it is why the commit
  count stopped being a hardcoded zero: a PackageCommit is one datagram and
  can die like any other, so a receiver that reports "I have committed N" lets
  the sender release its package even when the commit never arrived.
  `DacOutgoing.peerCommitsAtStart` snapshots the last count seen; a DIFFERENT
  number coming back means the peer committed something, and with one package
  in flight that something is this one. Every other mode reports a fixed zero,
  so the comparison never fires for them -- that self-disabling is the guard,
  and there is a test pinning it.
- `ame/level2/session.nim` was 1796 lines and is now two files that answer two
  different questions:

    session.nim  1796 -> 932   WHAT a connection knows: the epoch, its keys,
                               the exchange that replaces them, the ratchet,
                               the settings
    framing.nim         953    WHAT one message looks like: seal, open, the
                               header protection wiring, replay, control
                               frames, and the AME/DAC seam

  The cut was verified before it was made: nothing in the first half
  referenced anything in the second. `framing.nim` re-exports `session`, so a
  module that seals frames imports one file and gets both halves, and
  `carriers.nim` exports framing upward for the umbrella. Two things had to
  move with the framing: the private `AmeSendRollback` type (only sealing ever
  undoes itself) and `readU32`. One private had to be exported --
  `restoreConfiguredAmeFomkeCache` -- because the exchange is genuinely split
  across the seam: the STATE half lives in session, the FRAME half in framing.
- `DacLink` carried `sessionId`, `laneId` and `epochId`, all written and never
  read -- the last of the "identity stamped into every frame" fields the DAC
  header deletion orphaned, and `epochId` was specifically the path-epoch
  counter PathSwitch would have incremented. Gone, which simplifies two public
  signatures a long way:

    initDacLink(sessionId, laneId, d, seed, epochId, policy, limits)
      -> initDacLink(d, seed, policy, limits)
    admitDacLink(T, key, sessionId, laneId, nowMs, epochId)
      -> admitDacLink(T, key, nowMs)

  WHO a link belongs to is the table's question, answered by the address it
  was admitted on; WHAT authenticates is the AME session beside it. A field
  that LOOKS like a binding and enforces nothing is worse than no field.
  `tagDacBody(S, kind, body)` -- which took the link only to `discard` it --
  became `dacMessage(kind, body)` in types.nim.
- The `.iron` machinery is out of the nimble file: `findIronOverrideFile`,
  `parseironOverrides`, `unquoteValue` and the overrides parameter threaded
  through `resolveDepSrc`. It read `.iron/.local.gitmodules.toml`, a file in a
  directory the conventions forbid recreating, so the TOML reader behind it
  was ~50 lines nothing could ever reach. Sibling checkouts do the same job
  with no file to write, and `resolveDepSrc` now says its three-step search
  out loud. 43 lines lighter, and `std/tables` came off the import line.
- dplSuperCleanPath is CONFIGURATION ONLY and that is correct, not a gap.
  Promotion needs `mtuHint >= 4096`, and the hint a receiver reports is the
  chunk size that actually got through -- a sender on the clean lane sends
  1200-byte chunks, so 1200 is all anyone can observe. You do not discover a
  32 KB path by only ever sending small pieces down it. Adaptation can still
  walk DOWN from it the moment the path disagrees. Written down in README.md
  under "The top lane is chosen, never discovered".
- Where the AME/DAC seam is now explained, for the next person who asks:

    README.md                     "The nine words DAC can say" -- the whole
                                  vocabulary as a table, byte by byte
                                  "How one word gets from DAC to the wire and
                                  back" -- four files, one job each, both
                                  directions
                                  "What DAC is allowed to change, and what it
                                  is not"
    ame/level2/framing.nim        the module header draws one frame and the
                                  seam, in the file that implements it
    dac/README.md                 "Four words DAC used to have"
    README.md "The numbered folders"  what level0..level3 actually mean
    ame/README.md "What is in this folder"  four questions, and which file
                                  answers each
- `ame/level3/handshake.nim` was 1835 lines and is now six files. It was
  already sectioned by `╭⟢` banners, and every cut landed exactly on one --
  which is the tell that the file had been several files for a while:

    handshake.nim             1835 -> 797   the four steps, and the four
                                            calls a caller makes
    handshake_identity.nim           793    who someone is, and whether you
                                            believe them
    handshake_transcript.nim         240    the running record both sides
                                            sign, and the AM1M proofs over it
    handshake_records.nim            108    the SHAPE of the four messages
    handshake_cookie.nim             144    proving you can receive where you
                                            claim to be
    (handshake_wire.nim              283    unchanged -- those four as bytes)

  Two things this fixed beyond the size:

    the three `AmeAuthentication` constructors were 1500 lines apart. PSK sat
      near the top with the PSK proofs; pinned and certificate sat at the very
      bottom under a banner saying "three authentication inputs" that held
      two of them. All three are together now, in identity, where the choice
      is one glance.
    `handshake_wire.nim` imported the whole 1000-line handshake to learn what
      a client hello contains. It imports `handshake_records.nim` now, which
      is 108 lines of types and nothing else.
- `ameCookieValid` and `issueAmeCookie` took an `AmeClientHello` and read two
  fields of it. They now take those two fields, which is what makes
  `handshake_cookie.nim` readable on its own: a cookie is about an ADDRESS,
  and it needs to know nothing about what a hello is.

    ameCookieValid(secret, peerId, nowUnix, hello)
      -> ameCookieValid(secret, peerId, nowUnix, sessionId, cookie)

  A comment at the test site claimed the cookie was bound to the hello's
  nonce and had to be replayed with it. It never was -- `cookieSubject`
  covers the address, the timestamp and the session id, deliberately NOT the
  nonce, so a client may retry with fresh key material without paying for a
  second round trip. The comment and the line it justified are gone, and
  there is a new check that a cookie cannot be carried to another session.
- NOT split further, on purpose: the certificate's byte form stays inside
  `handshake_identity.nim` rather than becoming a `_wire` file of its own.
  The whole point of that encoding is that there is ONE canonical form, used
  both as the thing the authority signs and as the thing that travels sealed.
  Putting the bytes in a different file from the signing is how a second form
  gets introduced by accident, which is the trap the design exists to avoid.
- Each of the five new files re-exports what it sits on, so one `import
  ./handshake` still gives a caller everything. The split is for reading.
