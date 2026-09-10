# Progress

Commit Message: Collapse the DAC and FOMKE enum decoders onto two generics

Features (Planned):
- 85 triple-nesting sites remain, all at depth 3 (a loop plus two tests).
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
- 510 of 510 evaluation routines declare a `testKind`.
- The twelve `*DacDefaults` presets are one enum plus one data table.
- `AmeSession.pathLane` is read, and the wall against link conditions
  moving a protection parameter is tested.
- Every site nested deeper than triple is gone: 26 -> 0.
- Unused public routines 47 -> 21; coverage 199 untested -> 148.
- Tests and benchmarks live under `evaluation/`.

Features (In Progress):
- The pinned `submodules/Tyr-Crypto` still imports `metaPragmas`, which no
  longer exists anywhere. Tyr's move onto `runePragmas` sits unpushed on
  Tyr's `nightly`. Until Tyr promotes and pushes that, a standalone clone of
  Bifrost builds only against a sibling `Tyr-Crypto` checkout, not against
  its own submodule. Nothing here can fix it; the pin bump is one commit
  once Tyr's `main` carries the migration.

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
- The Android instrumented tests cannot be compiled here: gradle wants
  `androidx.tracing:tracing:1.1.0` and it is not in the offline cache. The
  JVM unit tests run and pass. Set `ANDROID_HOME` to the repo's
  `.android-sdk` before any gradle task.
