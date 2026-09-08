# Progress

Commit Message: Collapse the DAC scenario presets, and declare every test's kind

Features (Planned):
- 112 triple-nesting and 26 deeper sites, all in TLS 1.3, HTTP, CHUNKYAEAD and
  BFX2. None in AME, FOMKE or DAC.
- 33 remaining routine families Otter reads as one routine with a knob:
  `initAme*Algorithms` (5), the `carriers` frame wrappers (5), the
  `requireAme*Built` guards (4), the three hash entry points.
- 5 oversized files: `http/level1/request_parser.nim`, `bfx2/reader.nim`,
  `tls13/server_session.nim`, `http/level0/target_ops.nim`,
  `http/level1/chunked_ops.nim`.
- 47 unused public routines. Bifrost is a library and most exports exist for a
  consumer, so this needs deciding per symbol rather than in bulk. Geist is the
  only intended consumer; it currently imports the umbrella and calls nothing
  from this list.

Features (Done):
- AM1M works end to end, on both endpoints, over the core API and the real TCP
  driver. One `AmeAuthentication` drives all three modes; the old
  `trustMode`/`root`/`expectedPeer` triple is gone.
- AM1M mixes a binder from the provisioned secret into the handshake key
  schedule, and rotates epochs with a session-derived MAC key.
- `discardFomkeSkipped` / `discardAmeSessionSkipped`: the way out of a session
  that can neither receive across a gap nor rekey.
- Pragmas back on the shared contract: `meta/metaPragmas.nim` is the template
  verbatim with only the `MetaTag` list changed, `tag:` renamed to `metaTags:`
  at 605 sites, the two invented roles mapped onto template roles, `.iron/`
  deleted.
- 487 of 487 evaluation routines declare a `testKind`, up from 12. They could
  not before: the pragma did not exist in the file this repo was using.
- Every routine in `src/` declares a role.
- The twelve `*DacDefaults` presets are one enum plus one data table that
  mirrors the ASCII table documenting them.
- `AmeSession.pathLane` is read: `ameSessionPathDefaults` turns it into the
  full parameter set, and `planAmeSecurePackage` takes a session so chunking
  and parity come from the path the session is on.
- The NixOS module documented `defaultAecInboxCapacity`, a key the parser
  refuses; a test now pins the module's keys to what the parser accepts.
- Tests and benchmarks moved under `evaluation/`.
- Android client renamed off the retired AEC layer; its dead `AEC1` reference
  wire deleted.

Features (In Progress):
- Nothing. Everything above is complete and the full suite passes.

Notes:
- Last big change: the pragma migration. The definitions lived in
  `.iron/meta/metaPragmas.nim` and had drifted from the template, which is why
  475 tests could not declare a kind and why 605 `metaTags` uses were invisible
  to Otter's charts. Moving them made Otter read the tree properly for the
  first time, which is where the FAMILIES, STATE and EMBEDDED CODE findings
  came from — they were always true, just unreadable.
- The one thing that bit during it: `src/analysis_pragmas.nim` looks like a
  pointless facade and is not. Tyr ships a module called `metaPragmas` too, and
  Bifrost compiles Tyr's sources, so both `meta` directories are on the Nim
  path at once. Flattening the imports made files pick up Tyr's `MetaTag` list
  and fail on `tagCryptoBoundary`. The shim names a path instead of a module.
  It now says so at the top.
- Second lesson worth keeping: Otter's "written and never read" list does not
  scan `evaluation/`. `AmeSession.lastErr` is on that list and a test asserts
  on it. Check before deleting.
- The Android instrumented tests cannot be compiled here: gradle wants
  `androidx.tracing:tracing:1.1.0` and it is not in the offline cache. The JVM
  unit tests run and pass. Set `ANDROID_HOME` to the repo's `.android-sdk`
  before any gradle task.
