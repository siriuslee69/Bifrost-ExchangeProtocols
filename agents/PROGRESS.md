# Progress

Commit Message: Finish the unified authentication path and give FOMKE a way out of a stuck skip cache

Features (Planned):
- Repo-wide convention debt: 17 placeholders without the `ph_` prefix, 78
  routines with no role pragma, 112 triple-nesting sites, 67 unused public
  routines. All in TLS 1.3 / HTTP / BFX2 / DAC, none in the AME or FOMKE
  paths reworked here.
- Move `tests/` under `evaluation/tests/` and `tools/bench_protocols.nim`
  under `evaluation/benchmarks/`, as CONVENTIONS.md requires.
- Only 8 of 483 evaluation routines declare a `testKind`.

Features (Done):
- AM1M (shared-secret) handshake works end to end, on both endpoints, over
  the core API and over the real TCP driver.
- One `AmeAuthentication` object now drives every step in all three modes.
  The old `trustMode` / `root` / `expectedPeer` triple is gone from the
  policies and the drivers.
- AM1M mixes a binder derived from the provisioned secret into the handshake
  key schedule, so breaking every KEM slot is not enough to open a block.
- AM1M sessions rotate epochs using a session-derived MAC key, because they
  hold no signature keys to sign an offer or a reply with.
- `AmePeerTrustResult.mode` and `AmeAuthPackage.authenticationMode` are set
  from the mode that actually ran, instead of always reading `am1c`.
- Responders refuse a hello naming a mode they do not run, before key work.
- Both drivers put the configured mode into the hello they build.
- `discardFomkeSkipped` / `discardAmeSessionSkipped` let a caller give up on
  messages that will never arrive, which is the only way out of a session
  that can neither receive across a gap nor rekey.
- `config.nims` points at Tyr's `meta/`, so a plain `nim c` builds again.
- Android client renamed off the retired AEC layer; its dead `AEC1` reference
  wire and that wire's tests are gone.
- Root `audit.md` and `findings.md` removed; both described the retired AEC
  layer and neither was linked from anywhere.

Features (In Progress):
- Nothing. The work above is complete and the full suite passes.

Notes:
- Last big problem: the AM1M client read the server's identity block before
  it had been opened (`finishAmeHandshakeCore` used `identityBlock` about 17
  lines above the line that assigned it). Every AM1M handshake therefore
  failed with "PSK transcript proof is invalid", and no test caught it
  because the only AM1M tests exercised the proof helper on its own. Two
  further holes sat behind it: the responder never produced a shared-secret
  proof at all, and there was no responder-side accept path for the mode.
- How it was fixed: the block is opened first and judged second, the two
  sealed-block shapes are built and read by one function each per side, and
  three new tests run a complete AM1M handshake — one over the core API, one
  checking wrong-secret / wrong-name / mode-mismatch all fail closed, and one
  over a real TCP socket. It worked; the whole suite is green.
- The Android instrumented tests cannot be compiled here: gradle needs
  `androidx.tracing:tracing:1.1.0`, which is not in the offline cache. The
  JVM unit tests do run and pass. Set `ANDROID_HOME` to the repo's
  `.android-sdk` before calling any gradle task.
