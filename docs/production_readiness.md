# Production Readiness

## Cryptographic Agreement

AME2 uses an exact canonical immutable layout plus an initial mask tier. A peer
either supports both values byte for byte or rejects them. There is no strength
range, clamping, fallback, or implicit algorithm insertion.

The layout and active tier are bound into hashing, signatures, key derivation,
encryption-layer keys, MAC-layer keys, and agreement decisions.

## Rekey Safety

Each transition binds a request id, base epoch, target tier, and independent KEM
exchange mask. Newly active KEM slots must be exchanged, selected active slots
may be rotated, and unselected established secrets remain. Old replies cannot
be applied after the base epoch changes.

AME protected body carries offers, replies, and epoch-ready confirmation as authenticated AME
control frames. The responder does not promote a candidate epoch until it
authenticates the confirmation. Retiring keys expire after bounded authenticated
progress, TCP stays ordered, and DAC uses a 64-packet replay window.

## Resource Limits

- At most eight slots per algorithm family.
- KEM ids use one byte.
- Other algorithm ids use four bits and canonical zero padding.
- Masks cannot address unoccupied slots.
- Frame and transport size limits remain configurable.
- Wire lengths are checked before host-integer conversion or allocation.
- Normal DAC paths use u16 bodies; SuperClean paths use bounded u32 bodies.

## Validation

- `nimble test` runs AME mask-tier tests and unaffected transport/DAC/BFX tests.
- `nimble testTls` uses host OpenSSL build libraries or the automatic
  `nix-build nix/tls-check.nix --no-out-link` fallback.
- `nix-build nix/module-check.nix --no-out-link` checks Nix module rules.
- `nimble releaseHygiene` checks generated and local artifacts.

## Initial Authority Trust

The initial handshake pins an `AmeAuthorityRoot`, validates certificate
signatures and validity periods, verifies peer ownership proofs, binds the exact
AME layout, initial tier, and KEM exchange into the transcript, and requires a final client
transcript signature before the server releases the first epoch.

Revocation-list distribution remains deployment policy. Handshake verification
accepts a caller-supplied `revokedSubjects` list and fails closed on a match.

## Package Delivery

Secure packages compress before encryption, authenticate before decompression,
and enforce absolute encoded/plaintext limits plus an expansion-ratio limit.
DAC can recover one missing group chunk with XOR, validates that recovery using
Eir parity, requests exact chunks for wider loss, and verifies the complete
BLAKE3 digest before issuing a commit.
