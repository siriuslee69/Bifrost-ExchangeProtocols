# Contributing

This repo owns transport and wire contracts. Changes here should stay small,
deterministic, and protocol-focused.

## Scope

```text
+----------------------+-----------------------------------------------+
| Keep here            | Do not keep here                              |
+----------------------+-----------------------------------------------+
| AME wire/protection  | app-specific field meaning                    |
| DAC framing/defaults | downstream routing policy                     |
| AME carrier binding  | repo-local business rules                     |
| BFX2 envelopes       | consumer-specific schema ranges               |
+----------------------+-----------------------------------------------+
```

## Layout

```text
Bifrost-ExchangeProtocols
├── .iron/
├── docs/
├── examples/
├── src/
│   ├── protocols/
│   │   ├── ame/
│   │   ├── dac/
│   │   ├── fomke/
│   │   └── bfx2/
│   └── clients/android/
├── evaluation/tests/
└── tools/
```

## Local Setup

1. Initialize the checked-in submodules:
   `git submodule update --init submodules/Fylgia-Utils submodules/Tyr-Crypto submodules/SIMD-Nexus submodules/Eir-CompressionAndECC`.
2. Use sibling repos only through `.iron/.local.gitmodules.toml` when you need
   local development overrides.
3. Put machine-specific Android SDK/NDK paths in the environment or
   `local.properties`.
4. Install OpenSSL development libraries before running `nimble testTls`, or
   let the task fall back to `nix-build nix/tls-check.nix --no-out-link`
   when Nix is available.

## Commands

```text
+---------------------------+---------------------------------------------+
| Command                   | Purpose                                     |
+---------------------------+---------------------------------------------+
| nimble test               | full Nim test suite                         |
| nimble testDac            | DAC-only tests                              |
| nimble benchmarks         | release-mode protocol microbench harness    |
| nimble vectors            | regenerate committed BFX2 vectors           |
| nimble examples           | run all Nim examples                        |
| nimble androidTest        | Android JVM tests                           |
| nimble androidDebug       | Android debug APK build                     |
| nimble testTls            | TLS transport/AME TCP checks; uses host OpenSSL or Nix fallback |
| nimble buildLib           | shared-library build                        |
| nix-build nix/module-check.nix --no-out-link | NixOS module merge/replace/conflict checks |
| nix flake check path:$PWD | package + TLS + module checks in Nix        |
+---------------------------+---------------------------------------------+
```

Bifrost is a library package. `nimble buildLib` is the supported build path;
the default `nimble build` command is not a supported artifact path here.

## Change Rules

1. Keep wire layouts explicit.
2. Add tests when bytes, validation, or negotiation behavior changes.
3. Update README and `docs/` when production assumptions change.
4. Do not commit local `.iron/.local*` overrides.
5. Do not ship debug-only Android demo shortcuts as release behavior.


## The Pragma Module, And Why It Is Not Called `metaPragmas`

Every Nim repository in this workspace copies the same pragma file from
`Proto-RepoTemplate`, changing only its `MetaTag` list. More than twenty of
them do. That is fine until two of them are compiled together — and they are,
constantly, because these repos are put on the Nim path as **sources**, not as
installed packages:

```text
  nim c ... --path:Bifrost/src --path:Tyr/src --path:Tyr/meta ...
                                                    |
                     Tyr's files say `import metaPragmas` and need Tyr's tags
                     Bifrost's files say the same and need Bifrost's
```

**Both need to win, and only one can.** Nim resolves a module name by
searching the `--path` entries, and the **last one wins**:

```text
  --path:A --path:B     import collide  ->  B's copy
  --path:B --path:A     import collide  ->  A's copy
```

So reordering is not a fix. Whichever repo loses compiles against a `MetaTag`
enum belonging to someone else, and fails on the first tag that list has never
heard of — with an error pointing at a file several imports away from the
cause. The symptom looks like this, and it is baffling until you know:

```text
  src/protocols/ame/level1/padding.nim(84, 33)
    Error: undeclared identifier: 'tagCryptoBoundary'
```

### The rule

> **Name the pragma module after the repository, not after the template.**

```text
  meta/bifrostPragmas.nim      <- ours
  meta/tyrPragmas.nim          <- Tyr's, when it adopts this
  meta/                        <- on the Nim path, safe because the name is ours
  import bifrostPragmas        <- flat, from any depth, in every file
```

Three things fall out of it, all good:

1. **No collision is possible.** Two distinct names cannot capture each other,
   whatever order the paths land in.
2. **Imports are flat.** `import bifrostPragmas` works from `src/`, from
   `evaluation/tests/`, from `tools/` — no `../../../`. Moving a file no
   longer breaks its pragma import, which is a real class of breakage: it
   happened here when the tests moved under `evaluation/`.
3. **No shim.** The older answer was a `src/analysis_pragmas.nim` that reached
   the real file by relative path and re-exported it. It worked, but it looked
   like a pointless facade, and it was deleted once by someone who thought it
   was one.

Otter does not care about the filename. It reads `role:` and `metaTags:`
annotations out of the source text and never looks for a module by name, so
renaming costs nothing in any chart.

### Two other ways, and why not

| Approach | Why not |
|---|---|
| Order the paths so ours is last | Cannot work. Every repo in the build needs its own list at the same time. |
| Relative import everywhere, `import ../../meta/metaPragmas` | Correct, and what Otter itself does. But the depth is baked into every file, so moving a file breaks it. |
| One shared module for everybody, with each repo defining only `MetaTag` | The pragma templates are typed against `MetaTags`. Making them `untyped` to allow a local enum would mean a misspelled tag compiles silently instead of failing — a real safety property traded for tidiness. |

`evaluation/tests/test_task_contract.nim` pins all of this: no file may import
the shared name, the module must be named for this repository, and `meta` must
be on the path.

## Release Gate

```text
AME/DAC change
   |
   v
update evaluation/tests/vectors/docs
   |
   v
run nimble test
   |
   v
if performance-sensitive path changed -> run nimble benchmarks
   |
   v
if TLS/transport touched -> run nimble testTls (host OpenSSL or automatic Nix fallback)
   |
   v
if Nix module/config surface touched -> run nix-build nix/module-check.nix --no-out-link
   |
   v
if Android touched -> run nimble androidTest + nimble androidDebug
   |
   v
check README + docs/production_readiness.md
   |
   v
ready to review
```

## Android Note

The Android LAN client is a protocol harness, not the source of truth for AME,
DAC, or AME session semantics.

- Android TLS requires provisioned `bifrost_tls_identity.p12` and
  `bifrost_tls_password.txt`; do not commit demo private keys.
- Android AME secret bundles must stay behind `AmeSecretStore`; do not add
  new plaintext preference, log, or UI paths for `secret=*` bundle lines.
- Bundled demo AME seed path is debug-only.
- Release builds must use real certificate provisioning and real AME shared
  secrets before those lanes are re-enabled.
- Use the repo-local `./gradlew` or `nimble android*` tasks on Linux/NixOS so
  the wrapper can pick a working host `aapt2` and purge stale foreign-host
  `build/intermediates/cxx` state before NDK configure.
