# Tests

## Matrix

```text
+---------------------------+----------------------------------------------+
| Command                   | Coverage                                      |
+---------------------------+----------------------------------------------+
| nimble test               | full Nim suite                               |
| nimble testFomke          | GB3HKDF, TMEAEAD, FOMKE, and AME session composition |
| nimble testChunkyAead    | CHUNKYAEAD chunk encryption, authentication, and hash tree |
| nimble testDac            | DAC defaults, wire body codecs, drift payload, anti-oracle |
| nimble testTls            | TLS-enabled transport + AME TCP endpoint coverage; uses host OpenSSL or Nix fallback |
| nimble benchmarks         | release-mode protocol microbenchmark harness |
| nimble vectors            | explicit BFX2 deterministic vector regeneration |
| nimble examples           | runnable AME examples                    |
| nimble androidTest        | Android JVM tests + instrumented test APK assembly |
| nimble androidDebug       | Android debug APK build                      |
| nimble androidConnectedTest| Android device/instrumented tests           |
+---------------------------+----------------------------------------------+
```

Nix / packaging:
- `nix-build nix/module-check.nix --no-out-link`
  -> NixOS module merge/replace/conflict contract
- `nix flake check path:$PWD`
  -> package build plus flake-wired TLS transport/AME TCP check and module contract check

Prerequisites:
- `nimble testTls` uses direct host OpenSSL build libraries when they are
  available; otherwise it falls back to
  `nix-build nix/tls-check.nix --no-out-link` when `nix-build` is installed.
- `nimble androidTest` / `nimble androidDebug` need the local Android SDK/NDK
  paths configured or the repo wrapper environment that provides them.
- `nimble androidConnectedTest` additionally needs a connected device or
  emulator; `nimble androidTest` deliberately stops at JVM execution plus
  headless `assembleDebugAndroidTest` so it validates the full instrumented
  test APK without requiring a device in CI.

Connected Android verification:
- On June 11, 2026, `./gradlew :androidApp:connectedDebugAndroidTest --rerun-tasks`
  passed on `bifrost-x86_64(AVD) - 16` against `emulator-5554`.
- The authoritative result XML is
  `src/clients/android/app/build/outputs/androidTest-results/connected/debug/TEST-bifrost-x86_64(AVD) - 16-_androidApp-.xml`
  with `tests="9"` and `failures="0"`.

## Current Suite

```text
AME
  -> immutable layout and mask-tier encoding
  -> malformed and bounded exchange parsing
  -> atomic tier transitions and KEM slot add/rekey roundtrips
  -> external verified-trust handoff
  -> protected payload open/seal
  -> authority root construction rejects incomplete pinning material
  -> certificate path refuses unsigned pinned descriptors
  -> zero session id refused by policy instead of raising
  -> responder state without verified trust cannot accept a finish

DAC
  -> defaults validation
  -> frame header encode/decode
  -> typed body encode/decode and manifest/ACK validation
  -> anti-oracle state
  -> drift payload encode/decode

Transport
  -> IPv4/IPv6 address parse/format
  -> TCP length-prefixed loopback echo
  -> TCP framed receive timeouts surface as `TcpFrameResult.err` instead of throwing
  -> `-d:ssl` TCP/TLS framed roundtrip with CA-backed hostname verification
  -> `-d:ssl` hostname mismatch rejection when peer verification stays enabled
  -> `-d:ssl` verification-disabled client mode skips hostname validation but still completes the TLS handshake
  -> UDP datagram loopback echo
  -> hostname clients reaching IPv6-only TCP and UDP listeners
  -> `::` TCP/UDP wildcard listeners accept IPv4 loopback peers
  -> raw-close stale localhost DAC peer state cannot poison a later reused socket fd
  -> pure stream-frame decode for complete, oversized, and partial buffers

AME
  -> TCP carrier open/seal
  -> DAC carrier metadata binding
  -> full-width epoch and detached nonce/AAD binding
  -> authenticated Offer -> Reply -> EpochReady over TCP and DAC
  -> responder candidate epoch before confirmation
  -> bounded retiring epoch and DAC replay window
  -> SuperClean extended frames and normal-path rejection
  -> durable trigger cancellation and completion
  -> receive timeout errors without malformed-frame exceptions
  -> simultaneous rekey converges on one epoch instead of splitting it
  -> outgoing exchange refused while a peer candidate epoch is pending
  -> truncated authentication tags rejected at every length
  -> authority certificate validity and signature verification
  -> signed client/server hello and final transcript proof
  -> first-epoch equality after the initial KEM handshake
  -> bounded Eir compression and decompression-bomb rejection
  -> package loss, XOR recovery, Eir verification, exact repair, and commit

FOMKE
  -> sequential, indexed-block, multi-input, and memory-mixed GB3HKDF
  -> TMEAEAD roundtrip plus key, nonce, AAD, ciphertext, and tag tamper rejection
  -> independent asynchronous lane chains and bounded out-of-order receive
  -> transactional authentication failure and replay rejection
  -> exact mask-order KEM upgrades and lane-counter race rejection
  -> automatic authenticated AME Offer -> Reply -> EpochReady composition

Android
  -> AME public descriptor parsing and compact discovery beacon roundtrip
  -> AME secret summary redaction
  -> AME secret bundle export requires explicit debug/provisioning approval
```

## Rule

If a change touches:

- wire bytes
- framing lengths
- negotiation decisions
- trust validation
- example message flow

then update the matching tests or vectors in the same change.

Vector rule
  -> `nimble test` validates committed vector files without regenerating them
  -> run `nimble vectors` only when you intentionally accept a wire-format change

Cache rule
  -> nimble tasks compile into per-target `nimcache/` subdirectories
  -> do not point all Nim targets at one shared object cache

Config
  -> default config.toml parse/apply
  -> userconfig-style key spelling
  -> sanitizer rejection for unsafe values

NixOS module
  -> global config generation
  -> profile merge vs replace behavior
  -> `configFile` / `settings` conflict assertions
  -> disabled profiles omitted
  -> external config-file passthrough
