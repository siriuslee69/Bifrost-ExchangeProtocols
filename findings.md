# Bifrost Audit Findings

Date: 2026-05-30

This file reflects the current repo state. Earlier AME/DAC observations from
early May are superseded by the fixes already present in the codebase and by
`docs/production_readiness.md`.

## Current Summary

```text
Area                 | State
---------------------+------------------------------------------------------------
AME core             | canonical profile validation and AAD coverage are present
DAC core             | DAC1 framing, typed body codecs, and validation are present
AEC core             | authenticated rekeys, authority handshake, bounded Eir
                    | compression, DAC package repair, and carrier tests exist
NixOS module         | profile merge/replace semantics and config conflicts are
                    | verified instead of documented only by prose
Android TLS harness  | provisioned identity; no bundled repo secret
Android AEC demo     | debug-only; release builds fail closed
Android build path   | wrapper auto-picks `aapt2` and cleans stale CXX state
```

## Findings

1. The core Nim protocol layers are no longer the main production blocker.
   The earlier high-risk gaps are covered by the current tests.
2. The DAC wire completeness gap is closed.
   Shared DAC body helpers now provide canonical encode/decode coverage for
   actual body bytes, plus reserved-byte, enum/id, ACK-range, and manifest
   repair-semantics validation.
3. Package recovery is protocol-state-owned.
   `dac/level2/package_transfer.nim` plans chunks, performs one-loss XOR/Eir
   recovery, builds exact repair requests, and verifies digest commits.
4. Socket scheduling remains application-owned.
   Bifrost exposes deterministic protocol state; applications choose their
   event loop, retry timing, persistence, and peer discovery policy.
5. The AEC detached-envelope API gap is closed.
   `AecProtectedEnvelope` is exported, preserves caller nonce after AME
   normalization, binds caller AAD, and rejects mismatched AAD before
   decrypting.
6. The Android harness and repo-hygiene gaps are closed.
   There is no trust-all TLS verification or bundled repo private key, demo
   shortcuts are debug-only, the wrapper handles `aapt2` and stale foreign-host
   depfiles, the repo ships the expected docs/license/contributing files, and
   `.iron` layout/path handling are aligned with the current template.
7. Remaining AEC work is above the protocol/runtime layer.
   Multi-peer orchestration, app-specific discovery/routing policy, and
   persistence strategies still belong in consuming repos rather than inside
   this protocol library.

## Verification

- `nimble test`
- `nimble testDac`
- `nimble androidTest`
- `nimble androidDebug`
- DAC drift payload encode/decode keeps the fixed 29-byte layout and rejects
  wrong length or unknown kind values.
- Top-level exports include the AME and DAC modules that currently exist.
