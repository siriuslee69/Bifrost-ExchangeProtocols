# Progress

Commit Message: Sweep the fields the deleted DAC framing left behind

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
- A fresh clone builds. `Rune-Pragmas` is a submodule, and the pinned
  `Tyr-Crypto` is at Tyr `main` 1585636, the first Tyr commit that imports
  `runePragmas` instead of the `metaPragmas` that no longer exists. Both
  verified by hiding the sibling checkouts and compiling against the
  submodules alone.

Features (In Progress):
- Nothing. Everything above is complete and every suite passes.

Notes:
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
-  is now . It holds little-endian
  readers/writers and two name lookups and frames nothing; keeping the old
  name would have been the same kind of stale signpost the deletion was
  about. Eight importers, all updated.
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
  frame -- they described a header that no longer exists. `DacFrameFlags` and
  `DacTaggedMessage` STAY: the loop still sets flags for its own use, even
  though they never travel, because only the kind and the body are sealed.
