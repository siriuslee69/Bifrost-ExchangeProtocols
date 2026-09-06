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
