# Progress

Commit Message: Measure the reorder window instead of fixing it, and drop the ratchet nothing drove

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
- 514 of 514 evaluation routines declare a `testKind`.
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
