# Tests

## Matrix

```text
+---------------------------+----------------------------------------------+
| Command                   | Coverage                                      |
+---------------------------+----------------------------------------------+
| nimble test               | full Nim suite                               |
| nimble testFomke          | GB3HKDF, standalone AEADs, the FOMKE ratchet, its forward-secrecy properties, and AME session composition |
| nimble testChunkyAead    | CHUNKYAEAD chunk encryption, authentication, and hash tree |
| nimble testDac            | DAC defaults, wire codecs, ACK pacing, repair, scramble, link loop, link table, fuzz |
| nimble testDacFlag        | -d:bifrostDac=off keeps the wire and refuses the adaptive layer |
| nimble testFuzz           | every wire decoder under mutated frames: DAC, AME, BFX2, TLS 1.3 |
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
  -> at-rest seal/open, and the wrong tier failing rather than raising
  -> authority root construction rejects incomplete pinning material
  -> zero session id refused by policy instead of raising

AME handshake (private identities)
  -> neither certificate appears anywhere on the wire in the clear
  -> both sides derive the same epoch, transcript salt, and working ratchet
  -> ONE broken authority algorithm is not enough to forge a certificate
  -> a dropped authority proof is refused, not judged on what remains
  -> a revoked serial is refused, and the same subject can be reissued
  -> validity window, and a clock too far outside it refusing to judge
  -> a pinned identity expires like any other
  -> reciprocal pins authenticate; the wrong pin and a mixed-up trust mode fail
  -> tampering with the nonce, the sealed block, or the tag all fail closed
  -> an unsupported layout or tier is refused before any key work
  -> the finish erases the handshake secrets it consumed
  -> the cookie verifies only for the address, hello, and window it was minted for
  -> handshake records ride AME frames and refuse to arrive out of order

AME authentication modes (AM1C / AM1S / AM1M)
  -> the mode byte is carried in the hello and bound into the transcript
  -> a complete AM1M handshake runs with no certificate on either side
  -> the AM1M proof binds the provisioned name, the transcript, AND the
     direction, so the two proofs of one handshake are not interchangeable
  -> the wrong shared secret cannot open the sealed block at all, because
     the binder went into the key schedule and not just into a proof
  -> the right secret under the wrong name is refused
  -> a responder refuses a hello naming a mode it does not run
  -> AM1M rotates an epoch with a tag, having no signature keys to sign with
  -> a tampered rotation proof is refused rather than ignored
  -> the same, over a real TCP socket, through the driver

FOMKE forward secrecy
  -> the state that sent a message cannot open it again afterwards
  -> a captured chain key opens nothing that came before it
  -> the chain key is replaced, not extended, on every step
  -> an epoch change destroys every key from the epoch before it
  -> a failed open leaves the ratchet exactly where it was
  -> a gap past the skip budget is refused, not absorbed
  -> messages that never arrive can be given up on, and a rekey then runs
  -> a full skip cache stops receiving, and giving up starts it again
  -> a message given up on stays shut even if it does turn up later
  -> every switched-on KEM slot feeds the root, not just the first
  -> a tier naming a KEM slot with no secret is refused
  -> preparing ahead is bounded, and its cost in held key bytes is countable
  -> the nonce never repeats and never travels

MITM, loss, and repair
  -> no run of the plaintext survives anywhere into the frame, checked by
     scanning the wire for every four-byte window of the secret
  -> an observer may read the header fields, and nothing past them
  -> the same secret sent twice gives two unrelated blobs
  -> a captured frame opens for nobody who lacks the exchange secret
  -> changing ANY single byte of a frame, header included, breaks it
  -> a captured frame cannot be replayed or reflected at its sender
  -> a forged body under an honest header is refused
  -> padded traffic: the blob is longer than the secret, and a range of
     message sizes is one width on the wire
  -> no KEM secret, transcript salt, or signing key appears in the four
     handshake records
  -> a MITM offering his own certificate for the same subject is refused
  -> a sealed package leaks nothing through its chunks or its parity
  -> a relay holding no key rebuilds a lost chunk from XOR parity
  -> Reed-Solomon rebuilds a full parity budget of losses, from shards that
     made a real encode/decode round trip
  -> one loss past the budget is refused and the receiver is left untouched
  -> a damaged chunk is caught by the package digest and by the tag
  -> a dropped datagram does not stop the ones behind it
  -> the stream carrier refuses a gap instead of papering over it
  -> a dropped rotation commit stalls the rotation instead of splitting it

DAC
  -> defaults validation
  -> frame header encode/decode
  -> typed body encode/decode and manifest/ACK validation
  -> ACK receipts in run and bitmap form, and the encoder picking the shorter
  -> batch pacing: count bound, deadline bound, and a gap closing at once
  -> levers halve on loss and walk back only after a clean streak
  -> repair wait tracks measured ACK latency and never drops below the profile
  -> repair-group geometry, including the short final group
  -> XOR rebuilds one loss; Reed-Solomon rebuilds its whole parity budget
  -> one loss past the budget is refused with a reason, not guessed
  -> parity shards survive the wire and a partial parity set still repairs
  -> send delay and chunk-order scrambling stay a permutation of the package
  -> the link loop carries a package end to end and commits it
  -> loss inside the parity budget repairs with no round trip
  -> loss past it recovers through exact repair; reordering and duplication too
  -> a link that cannot finish reports failure instead of hanging forever
  -> the repair-round budget is spent, not looped
  -> drift payload encode/decode

AME DAC relay
  -> a peer with a session gets a slot; one without is dropped unparsed
  -> releasing or sweeping a peer erases its session with its slot
  -> a full relay refuses a new peer rather than evicting a live one
  -> a whole package crosses the relay, sealed the entire way
  -> every datagram is authenticated: a one-bit change to any of them is
     refused, and the count of refusals equals the count sent
  -> rubbish from an admitted peer is dropped, never raised
  -> a package survives one-in-four loss, repairing over the sealed lane
  -> a secure package crosses the relay and restores its plaintext
  -> the relay path carries no package seal, because it needs none
  -> a package that leaves through a file still carries its own seal
  -> every kind that opens a link is a kind the loop acts on
  -> a path probe no longer takes a slot the loop cannot use
  -> a completed package reports what this side measured
  -> a peer's report moves this side's lane, one step at a time
  -> a report cannot move a lane out from under a package in flight

AME DAC endpoint
  -> a package crosses two real loopback UDP sockets and commits
  -> a receive timeout is quiet, not an error
  -> a datagram from an unknown address is dropped, not admitted

DAC link table
  -> two peers get two links; one address on two carriers is two links
  -> a returning peer routes back to the link it already had
  -> rubbish, and valid frames that open nothing, consume no slot
  -> capacity is a hard number and the surplus is refused
  -> a flood cannot displace a peer that is mid-transfer
  -> an idle link's slot is reused only after its quiet window passes
  -> two tables carry a whole package between two peers
  -> each peer draws its own scramble stream from one table seed

Wire fuzz
  -> every DAC decoder survives thousands of mutated frames without a Defect
  -> the link loop never raises on arbitrary bytes, and still completes a real
     package interleaved with rubbish
  -> the header peek refuses exactly what the full decoder refuses, and never
     leaves a field set on a refusal
  -> a hostile peer cannot make the link table raise or exceed its capacity
  -> AME frame headers, frames, and protected bodies, including a mutation at
     either depth of the nested pair
  -> BFX2 envelopes with and without checksums, and value packets
  -> TLS 1.3 records and handshake messages, including a mutation at either
     depth of a record wrapping a handshake
  -> TLS 1.3 ClientHello, ServerHello, EncryptedExtensions, Certificate, and
     CertificateVerify
  -> a certificate chain past the caller's bound is refused, not truncated

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
  -> package loss, XOR recovery, exact repair, and commit
  -> a DAC datagram is exactly one AME frame, with no outer header
  -> the epoch lives only in the protected body, and tampering is caught
  -> an epoch past 65535 rides DAC, which the old u16 field refused
  -> a payload past 65535 needs no widened framing on any path lane
  -> a DAC control message round-trips with its kind authenticated
  -> the DAC kind sits inside the ciphertext, so an ACK and a repair hint are
     indistinguishable on the wire
  -> every single-bit change to a DAC control frame is refused
  -> a replayed DAC control message is refused

FOMKE
  -> sequential, indexed-block, multi-input, and memory-mixed GB3HKDF
  -> the TMEAEAD and GGAEAD presets, and that every slot they name matters
  -> payload padding: block rounding, malformed filler, and epoch agreement
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
