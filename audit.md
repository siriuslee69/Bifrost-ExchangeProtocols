# Bifrost Audit

Date: 2026-06-07

Scope:
- Audited the current `Bifrost-ExchangeProtocols` worktree as-is.
- Focused on the Nim build/test surface and the newly added AEC/BFX2 paths.
- Ran the repo test surface from both the existing workspace cache and a fresh cache.

## Remediation Status

- Fixed on 2026-06-07.
- `config.nims` no longer forces a single shared repo-wide `nimcache/` for plain `nim` builds.
- `bifrost_exchange_protocols.nimble` now assigns per-target cache subdirectories for nimble-driven builds and leaves vector regeneration in the explicit `vectors` task only.
- Verification after the fix:
  - `nimble test` exited successfully.
  - `nimble vectors` exited successfully.
  - `git diff -- tests/vectors/bfx2 tests/vectors/bfx2_external` was empty after regeneration.

## Original Findings

These findings describe the pre-fix state observed during the audit run.

### High: the standard Nim build/test path is cache-sensitive and not hermetic

Evidence:
- `config.nims:5` forces all plain `nim` builds into the shared `./nimcache` directory.
- `bifrost_exchange_protocols.nimble:139-144` forces all nimble-driven builds into that same shared `./nimcache` directory.
- During this audit, `nimble test` from the pre-existing workspace cache produced an AEC autopilot failure, but the same suite passed after `nimcache/` was moved aside and rebuilt from scratch.

Impact:
- Local test results can be polluted by stale cross-target objects.
- Failures become harder to trust because a cache reset can change the outcome without any source change.
- Concurrent or background Nim builds are especially risky because they all target the same object cache.

Recommendation:
- Use a per-target or per-task cache path instead of a single repo-wide cache.
- At minimum, make `nimble test` clear or isolate its cache before compiling the suite.

### High: `nimble test` rewrites the golden BFX2 fixtures before asserting that they are stable

Evidence:
- `bifrost_exchange_protocols.nimble:183-184` runs `tools/generate_bfx2_vectors.nim` at the start of the main test task.
- `tools/generate_bfx2_vectors.nim:15-17` and `tools/generate_bfx2_vectors.nim:47-89` unconditionally overwrite the committed files under `tests/vectors/`.
- The “stable vector” assertions in `tests/test_bfx2_wire.nim:75-91` and `tests/test_bfx2_external_bridge.nim:80-104` then read those freshly rewritten files.

Impact:
- The default regression command can silently normalize wire-format drift before checking it.
- A change to the encoder and the generator can pass together, even if the committed wire contract changed unintentionally.
- The vector tests only act as real compatibility guards when fixture regeneration is reviewed separately, or skipped during normal test runs.

Recommendation:
- Remove vector regeneration from the default `test` task.
- Keep regeneration as an explicit `vectors` or release-maintenance step, then review fixture diffs intentionally.

## Verification

- The pre-existing workspace cache produced inconsistent `nimble test` behavior.
- After moving `nimcache/` aside and rebuilding clean, `nimble test` completed successfully.
- Isolated clean-cache runs also passed for:
  - `tests/test_aec_autopilot.nim`
  - `tests/test_aec_channel.nim`
  - `tests/test_aec_dac_channel.nim`
  - `tests/test_aec_dac_peer_pool.nim`
  - `tests/test_aec_two_clients.nim`

No additional confirmed runtime regression was found in the current Nim test surface beyond the build/test issues above.
