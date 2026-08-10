# Progress

## Current commit message
Harden AME epoch transitions, tag verification, and seal length bounds

## Features to implement (total)
- Migrate downstream consumers to `AmeSuiteLayout`, `AmeMaskTier`, and `AmeTierPath`

## Features already implemented
- AME fixes ordered KEM, cipher, MAC, hash, signature, and KDF slots per session
- Stable mask tiers select active slots without replacing or reordering algorithms
- Handshakes bind the immutable layout and exact initial tier
- Epoch upgrades authenticate target tier masks and independent KEM exchange masks
- Identity certificates and direct pins bind complete ordered signing-key stacks
- Initial KEM offers, replies, and transcript finishes require every signature
  selected by the initial tier
- In-session KEM offers and replies require every signature selected by the
  target tier before encapsulation, decapsulation, or epoch mutation
- AME traffic keys are transcript-, session-, epoch-, and direction-bound
- Tier transitions are monotonic and authorized by the union of current and
  target signature masks
- Handshake session IDs flow directly into live sessions and cannot be replaced
- Consumptive handshake finish APIs erase retained KEM and shared-secret state
- Bifrost omits Tyr's SPHINCS+ Haraka compatibility alias because it currently
  executes the SHAKE implementation rather than an independent Haraka scheme
- Newly activated KEM slots require exchange; selected slots may rekey
- Unselected established KEM secrets survive atomic non-KEM mask rotations
- FOMKE upgrade commits bind the AME target tier
- AME DAC headers derive their epoch from the protected AME epoch
- DAC data and control receivers reject outer/inner epoch mismatches
- BFX2 v2 checksums include payload bytes when enabled
- BFX2 rejects oversized envelopes, packets, collections, and nesting
- TMEAEAD exposes stream-only, tag-only, verify-only, and keyed HMAC APIs
- BFX2 vectors were regenerated for the v2 envelope format
- Only one AME epoch transition may be in flight in either direction; a
  simultaneous start is resolved by endpoint role instead of splitting the epoch
- AME open requires the full authentication tag length before comparing
- AME responder handshake state carries its verified peer trust rather than
  re-asserting it at accept time
- `AmeAuthorityRoot` has a validating constructor and empty roots are refused
- Every AME seal path bounds the envelope length before narrowing it to u32
- AME sends roll back through a small counter record instead of copying the
  whole session, and erase the superseded FOMKE ratchet copy

## Features in progress
- none

## Last big change or problem
- Reviewed the AME protocol end to end for logic and edge-case defects. Four
  confirmed issues were found and fixed, each with a regression test:
  1. Simultaneous rekey. Both endpoints could start an epoch transition at the
     same time and rotate to the same epoch id from different KEM secrets, with
     no error raised anywhere. Reproduced with a probe that showed the two
     endpoints holding different slot-1 secrets at epoch 2, which breaks the
     session permanently once the 100-frame retiring grace runs out. Fixed with
     an in-flight guard plus a role-based tie-break; verified the same probe now
     converges on one key set.
  2. Truncated tag forgery. `openAmeMessage` recomputed the expected tag at
     whatever length arrived, so a one-byte tag was accepted 1 time in 256.
     Measured before the fix (1/256) and after (0/256). AME's own wire paths
     already pinned 32 bytes, so the exposure was to direct API callers.
  3. Signature work ahead of cheap guards in `answerAmeSessionExchange`, which
     let replayed offers force repeated post-quantum verifications.
  4. Missing envelope length bounds in `sealAmeDacFrame` and `sealControlFrame`.
     `sealAmeTcpFrame` had the check; the other two narrowed to u32 unchecked.
- One flaw was introduced and caught by its own new test: the peer-trust guard
  in `acceptAmeHandshakeCore` sat below a `var` block that built the transcript
  first, so an unverified state raised instead of returning an error. The guard
  now runs before any transcript work.
- Not changed, documented instead: a tier transition whose target selects the
  same KEM slots as the current tier produces an exchange mask of zero. Keys
  still change, but no new KEM runs, so forward secrecy does not advance. This
  is deliberate and `rekeyMask` is the intended control.
  and signed every initial and later KEM transaction according to its tier mask.
  Receiver-side checks happen before KEM processing or candidate mutation. The
  AME handshake wire version is now 3 and the certificate subject version is 2.
  AME now also derives directional transcript-bound traffic keys, prevents frame
  reflection and tier downgrade, carries signed session IDs, and exposes
  consumptive handshake cleanup. Focused AME/FOMKE tests, both public examples,
  the shared-library build, and the full `nimble test` matrix pass.
