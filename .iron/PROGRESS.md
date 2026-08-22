# Progress

## Current commit message
AME and FOMKE become one layer: compact framing, private handshake, real hybrids

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
- `-d:bifrostKems=` compiles only the named KEM families, `-d:bifrostCarriers=`
  only the named transports; with no flag the full library is built as before
- One KEM entry point serves a constant (settled while compiling, no branch)
  and a value off the wire (one `case`); an excluded family is a compile error
  in the first shape and a refusal in the second
- A layout naming a family this build lacks is refused when it is built and
  when a peer's bytes are decoded, before any key material exists
- The session core opens no socket, so a carrier's network stack only enters
  the build when that carrier does
- `-d:bifrostSigs=` and `-d:bifrostSymmetric=` gate signature families and
  symmetric primitives the same way, with the same runtime/constant/flag shapes
- AME no longer reaches Tyr's `signatures/registry`, so it no longer binds
  liboqs at all; Ed448 is gone from the wire and the slot ids are renumbered
- Hybrid signature slots declare BOTH families they need, so the build check
  is a set comparison rather than a single family lookup
- BLAKE3 is always compiled: AME normalizes MAC tags and derives Argon2's
  salt with it, so no flag combination may remove it
- Every layout constructor refuses a slot this build cannot execute, and the
  default layout is assembled from what the build carries

- FOMKE is the ONLY payload protection: one ciphertext, one tag, per frame
- The slot construction (cipher XOR chain + XOR-combined tag) lives in one
  file, `ame/level1/tier_aead.nim`, used by the ratchet and the at-rest sealer
- The FOMKE root absorbs every KEM secret the tier selects, so a hybrid
  exchange is a hybrid in fact; a tier naming a slot with no secret is refused
- Every magic is three letters plus one version byte; AME header 36 -> 34 B,
  FOMKE envelope 83 -> 22 + tag, total frame overhead 187 -> 88 B
- The FOMKE nonce is derived on both sides and never travels; its length field
  is gone; the tag-length byte is checked against the session, not obeyed
- A session always has a working ratchet: `initAmeSession` starts it from the
  finished exchange and the transcript, so role and lane cannot disagree
- A bounded retiring-ratchet window keeps frames already in flight openable
  across an epoch change, then erases those keys
- Handshake identities are sealed from the server hello onward: no certificate
  appears on the wire in the clear
- Authority certificates are signed by the authority's whole algorithm stack;
  a certificate with fewer proofs than the pinned root has slots is refused
- Certificates carry a serial, so revocation names the certificate and the
  same subject can be reissued
- Pinned identities have real validity windows, and a clock too far outside a
  certificate's window refuses to judge rather than guessing
- A stateless retry cookie sits in front of all key work, bound to the sender's
  address, the hello it was minted for, and a 30-second window
- Handshake records travel as ordinary AME frames (kinds 0x0C..0x0F) carrying
  their step in the sequence field, with a TCP driver for both sides
- Compression is off by default on the sealed path; the package sealer honours
  the session's negotiated tag length instead of hardcoding 32

- AME exposes its first runtime parameter: the authentication tag length,
  16, 24 or 32 bytes, as an enum whose only values are those three
- Tag length lives per EPOCH, not per session, so a retiring epoch keeps
  opening frames sealed under its old value while the new one uses the new
- The length is bound into the authenticated input, so a peer that shortened
  its own tags fails verification instead of being believed
- `setAmeAuthTagLen` stages rather than applies: the value rides in the next
  exchange request, the responder adopts it, and both rotate together
- The arriving tag is measured against the epoch's agreed length, never
  against the length the message claims for itself

- Reed-Solomon is real: Eir gained systematic GF(256) erasure coding over
  whole shards, backed by a Cauchy matrix, so any k of k+m shards rebuild
  the rest and no loss pattern is unlucky
- SIMD-Nexus gained the GF(256) primitive underneath it: one coefficient
  becomes two 16-entry tables, then AVX2/SSSE3/NEON shuffle 32 or 16 lanes
  per instruction, with a scalar fallback checked at every buffer length
- The SSE2 paths in SIMD-Nexus byte streams were gated on `defined(sse2)`,
  which nothing in the workspace ever sets, so every one of them silently
  ran the scalar branch; they now gate on the architecture
- `drmReedSolomon` rebuilds its whole parity budget in a DAC repair group,
  data or parity shards alike; `drmXor` still repairs exactly one loss
- A repair that cannot succeed reports why instead of returning false, and
  `drmFountain` is refused explicitly rather than silently doing nothing
- The ACK wire carries a gap bitmap as well as arrival runs, and the encoder
  measures both and sends the shorter; `gapBits` used to announce a bitmap
  width for a bitmap that was never written or parsed
- `damBatch` does something: a batch closes on frame count, on a deadline, or
  at once when a gap appears, whichever comes first
- Both ACK levers are inferred from arrivals alone, never requested. Loss
  halves them in one step; a clean streak walks them back a quarter at a time,
  so one bad patch cannot make the cadence flap
- The sender's repair wait comes from the ACK latency it measures itself,
  floored by the profile, so a batching receiver is never mistaken for loss
  and no hold time has to be advertised or believed

- DAC has a loop that runs it. Before this, every message kind except
  `dmkPackageChunk` was encoded by nobody: no ACK, no parity shard, no repair
  hint and no manifest had ever left the process. `level3/link.nim` owns no
  socket, so the same loop runs over UDP, over a test pipe, or in one process
- The loop is tested against a pipe that drops one frame in three, reverses
  delivery order and duplicates everything, all at once, and still commits
- A package that cannot complete now reports `dlkPackageFailed` instead of
  going quiet; both repair budgets are bounded and spent, never looped
- Only a DROP in the missing count counts as progress. Parity that merely
  arrives does not: a sender topping up parity the receiver cannot use was
  refreshing the receiver's timer forever, so it never escalated to asking
  for exact chunks. That one distinction fixed three failing loss scenarios
- The sender's parity timer and the receiver's request timer are separate,
  because a link that only receives still has to be able to ask
- `-d:bifrostDac=off` removes the adaptive layer, and reaching for it is a
  compile error rather than a silent inclusion. It is not a size lever: Nim
  emits nothing for a proc nothing calls, so an unused layer already costs
  nothing. Eir stays required either way, since AME's RLE compression uses it
- A fuzz harness walks structured mutations of real frames through all
  thirteen DAC decoders and the link loop. Arbitrary bytes must yield a value
  or a CatchableError, never a Defect. It found one wrong assertion in its own
  first run; the decoders themselves held

- One process now holds many peers. `level3/link_table.nim` keys a DacLink by
  host, port and carrier, so one address reached two ways is two links
- The table is the one structure in DAC a peer can push on, so every path that
  adds to it is bounded. Capacity is a fixed array, never grown
- A datagram is identified from its header prefix by `peekDacFrameIdentity`,
  which allocates nothing and raises nothing, so rubbish from an unknown
  address is dropped before a slot is even considered. A fuzz property checks
  it accepts exactly what the full decoder accepts, and never leaves a field
  set on a refusal
- A stranger may only open a link with a frame that STARTS something: a
  manifest or a path probe. A chunk or an ACK refers to state a new link does
  not have and would be ignored anyway, so it never costs a slot
- Under pressure only links that finished both directions and then went quiet
  are reclaimed. A live conversation is never evicted for a stranger; the
  stranger is refused and the refusal counted. Tested with a 200-peer flood
  against a 4-slot table holding one mid-transfer peer
- Each link mixes the peer key into the table seed, so a peer knowing its own
  address learns nothing about another link's delays or chunk order
- Linear scan, not a hash map: at a few dozen slots it compares faster than it
  hashes, and there is no key an attacker can pick to force collisions

- The fuzz harness now covers every decoder in the library, not just DAC.
  AME frame headers, frames and protected bodies; BFX2 envelopes and value
  packets; TLS 1.3 records, handshake framing, ClientHello, ServerHello,
  EncryptedExtensions, Certificate and CertificateVerify
- Nested decoders are fuzzed as the pair they arrive as -- an AME frame around
  a protected body, a TLS record around a handshake message -- so a mutation
  can land in either length field
- The mutator moved to `tests/fuzz_support.nim` so both harnesses share one
  implementation, and it was checked against a deliberate out-of-bounds read
  to confirm it still reports a Defect with the seed and round to reproduce it

- AME is the only framing now. A DAC datagram is one AME frame; the 27-byte
  DAC header is gone. Measured on a 1024-byte payload, framing overhead went
  from 131 bytes to 104
- Every field in that header was already beside it. Session and lane were in
  the AME header, the epoch was the protected body's epoch in a narrower
  field, and the sequence advanced in lockstep with the AME sequence because
  both were incremented on the same line
- Removing it removed failure modes, not just bytes. There is no outer epoch
  to disagree with the protected one, one replay window instead of two, and
  no `u16` ceiling: a session past 65,535 epochs can use DAC now, and a
  payload past 65,535 bytes needs no widened framing on any path lane
- DAC control messages are authenticated. They travel as `ampkDacControl` AME
  frames with the KIND AS THE FIRST BYTE OF THE PROTECTED PLAINTEXT, so it is
  encrypted as well as authenticated: an ACK and a repair hint are
  indistinguishable on the wire, and a rewritten kind fails verification.
  Before this they rode bare and anyone could forge a receipt
- The link loop no longer produces bytes. It emits `DacTaggedMessage`, and the
  carrier decides the framing: `renderDacFrame` for a bare DAC1 probe before a
  session exists, or the AME carrier for anything on a live session. DAC
  decides WHAT to say; AME decides how it is protected
- The FOMKE inner AAD label moved to v2, having dropped the DAC sequence it
  bound alongside the identical AME one

- The pieces are assembled. Until now the link loop, the peer table and the
  authenticated control lane had ZERO callers outside tests: three finished
  parts that never touched each other. `ame/level3/dac_relay.nim` is the join
- A peer enters the relay only by holding an AME session the handshake gave
  it. A datagram from any other address is dropped before it is parsed, so the
  relay never has to guess whether a stranger deserves memory, and the link
  loop only ever sees message kinds that authenticated
- Sessions sit in an array parallel to the table's slots, so the slot index IS
  the session index. A released or swept peer has its session erased before
  its slot is freed, so a slot is never handed on with the old keys beside it
- The relay owns no socket, for the same reason the loop does not. It is
  driven identically by a real socket, a test pipe, or one process
- `secure_package` reaches the relay instead of making the caller hand-drive a
  plan and a receiver. The example now runs the real path end to end: authority
  handshake, admission, sealed package, one datagram in five dropped, parity
  repair, restored plaintext
- The two seals were deliberately NOT merged. The package seal is what lets
  bytes sit in a file or cross an untrusted courier; the datagram seal is what
  stops a forged receipt on the live lane. Merging them would make package
  integrity depend on the transport that happened to carry it
- Fixed a hole introduced with the link table: `dmkPathProbe` was allowed to
  admit a new peer, but the loop has no branch for it, so a probe took a slot
  and was then ignored. Measured: 40 probes from 40 addresses filled a 4-slot
  table completely, which is the exact flood the admission rule exists to
  stop. `dacLinkHandlesKind` now sits beside the admission rule and a test
  asserts every kind that opens a link is a kind the loop acts on

- One seal per path, not two. Over the relay a secure package is COMPRESSED
  ONLY: the transport already authenticates it end to end, since every
  datagram is sealed, the manifest carrying the BLAKE3 digest is sealed, and
  the receiver checks the assembled bytes against that digest. The relay entry
  point takes no key material at all, which is the clearest statement of it.
  `planAmeSecurePackage` keeps its AEAD, because bytes leaving through a file
  or an untrusted courier have no transport to inherit integrity from
- The stack finally holds a socket. `ame/level3/dac_endpoint.nim` is the one
  file that does, so it is the only one that has to be trusted about blocking,
  timeouts and partial reads. A timeout is `adrNone`, not an error; a failed
  send is counted, not raised, so one unreachable peer cannot end the loop for
  everyone else. A package now crosses two real loopback UDP sockets in tests
- Path reports work, and they are facts rather than requests. On commit a link
  states the loss and round trip IT measured; the peer may move its own lane
  on the strength of that, ONE STEP at a time and only between packages. The
  other side learns the new parameters from the next authenticated manifest,
  so nothing is negotiated
- `dacDefaultsForPath` was missing: the path policy recommended a LANE and
  nothing could turn that into the parameters a link sends with

## Next, agreed but not yet built
- Three DAC message kinds are still decoded and then ignored. `dmkPathProbe`
  measures a round trip the ACK latency already measures. `dmkPathSwitchRequest`
  and `dmkPathSwitchAck` are a NEGOTIATION, which contradicts the no-requests
  rule outright and is unnecessary now that a path report moves only the
  reporter's own lane and the manifest carries the result. They should
  probably be cut like `receive_budget` and `drmFountain` were, but that is a
  wire decision to make deliberately
- `dmkDriftPayload` is a separate feature with codecs and tests and no
  consumer anywhere
- A DAC handshake driver to match `handshake_tcp.nim`. The records and their
  framing are carrier-agnostic already; only the datagram retry/timeout loop
  is missing
- External analysis of GB3HKDF and the XOR-combined multi-MAC tag. This is
  the largest standing risk in the repo and no amount of layering fixes it
- External review of the hand-written TLS 1.3 stack. Fuzzing shows the
  decoders do not crash; it says nothing about whether the state machine is
  correct, and that is still the largest hand-written surface in the repo

## Features in progress
- none

## Removed as dead weight
- `receive_budget.nim` and `DacReceiveBudget`: encoded and decoded but never
  sent, and it asked the peer to behave differently, which this design does not
- `sender_receiver.nim`, `DacSenderState` and `DacReceiverState`: constructors
  with no consumers, overlapping the new `DacAckPolicy` / `DacRepairTimer`
- `drmFountain`: no implementation, no profile selected it. `drmTcpExact`
  moves from 0x04 to 0x03, and every message kind after `dmkPathStats` shifts
  down one now that `dmkReceiveBudget` is gone
- `anti_oracle.nim`: 517 lines of per-client fingerprint tracking replaced by
  `level1/scramble.nim`, which is eight bytes of sender-local state
- Eir's `ecc_ldpc_bitflip_simd.nim` and `llbvc/codec_simd.nim`: SSE2 and AVX2
  entry points whose bodies just called the scalar one. `EccAlgorithm` loses
  `eccLdpcBitFlipSse2` and `eccLdpcBitFlipAvx2` with them

## Oracle defence, rebuilt small
- An attacker who probes learns from how long a reply took and what order
  chunks arrived in. Both are closed by the sender alone
- A per-package delay is drawn from a sender-local splitmix64 seed; the proc
  returns milliseconds and never sleeps, so an async sender is not blocked
- Chunk send order is a Fisher-Yates shuffle. Chunks already name their own id
  and offset, so a shuffled package reassembles exactly like an ordered one
  and nothing on the wire changes
- There is no per-client memory at all. The old tracker kept fingerprints,
  bad-message counts and error sets per client, which is a table an attacker
  can grow on purpose

## Last big change or problem
- Reworked AME and FOMKE into ONE layer of payload protection, gave the
  handshake privacy and a transport, and compacted every frame.

  **1. The double encryption is gone.** A frame used to be sealed twice: an
  outer epoch AEAD around an inner FOMKE envelope that had already sealed the
  same bytes. FOMKE is now the only payload protection, and it uses the
  construction the outer layer used to — every switched-on cipher slot XORed
  over the payload in turn, every switched-on authenticator XORed into one
  tag. That code now lives in exactly one file, `ame/level1/tier_aead.nim`,
  called by both the live ratchet and the at-rest package sealer.

  **2. Framing compacted.** Every magic is three letters plus a version byte.
  The AME header went 36 -> 34 bytes. The FOMKE envelope went 27 + 24 nonce +
  32 tag -> 22 + tag: the nonce is derived on both sides and no longer
  travels, its length field is gone with it, and the tag length is one byte
  that is *checked* against the session's agreed value rather than obeyed.
  Total per-frame overhead: 187 -> 88 bytes, measured.

  **3. A real flaw found and fixed while doing it.** `initFomke` derived its
  root from ONE KEM slot's shared secret. A tier naming Kyber *and* X25519 was
  therefore a hybrid in name only — breaking the single contributing algorithm
  was enough. The root now absorbs every secret for every slot the tier
  switches on, and a tier naming a slot with no secret is refused. Covered by
  "every switched-on KEM slot feeds the root, not just the first".

  **4. The handshake hides who is talking.** The client hello names nobody.
  The server encapsulates, derives a temporary key from the KEM answer plus
  the transcript, and its certificate travels sealed under it; the client's
  does the same in the finish. An observer sees two nonces and some key
  material. Verified by a test that scans every record's bytes for the subject
  name and finds none.

  **5. Authority certificates are hybrid.** They were signed by ONE algorithm
  while leaf identities were stacks, so one Ed25519 break forged certificates
  for a whole deployment. An authority now signs with its whole stack, and a
  certificate carrying fewer proofs than the pinned root has slots is refused
  outright rather than judged on what remains.

  **6. The handshake finally has a transport.** The record codecs had no
  callers anywhere outside tests — the handshake had never crossed a wire, and
  every integrator had to invent framing, where getting it wrong is a security
  bug. Records now ride ordinary AME frames with packet kinds 0x0C..0x0F,
  carrying their step in the sequence field, plus a TCP driver that runs both
  sides to completion including the cookie retry.

  **7. Hardening, all in one pass.** A stateless retry cookie in front of all
  key work; certificate serials so revocation names the certificate rather
  than burning the subject's name; real validity windows on pinned identities;
  a clock too far outside a certificate's window refusing to judge rather than
  guessing; compression off by default on the sealed path (it leaked plaintext
  length); the package sealer honouring the session's negotiated tag length
  instead of hardcoding 32.

- **Two ordering bugs were introduced and caught by their own tests**, both
  worth recording because they are the same shape:
  1. The responder staged its ratchet upgrade inside
     `answerAmeSessionExchange`, which froze the lane counters *before* it had
     sealed its own reply. The two endpoints then staged at different
     positions and every rotation failed. Staging moved after that send, into
     `stageAmeSessionFomkeUpgrade`.
  2. The sealed identity block wrote the certificate body length-framed and
     read it back raw. Caught immediately by the first handshake test.

- **Not changed, recorded instead:** the DAC relay computes repair parity over
  *plaintext* chunks and seals each piece separately, while the file path
  seals once and computes parity over *ciphertext*. Both are correct, and the
  live path cannot use the file path's ordering: each datagram is sealed with
  its own ratchet key, so two sealed datagrams XORed together are not a sealed
  datagram. Sealing per datagram and erasure-coding across datagrams cannot
  both be the outer layer. Written out in full in `docs/production_readiness.md`
  under "One Seal Per Path". If bit-level correction is ever wanted, it MUST
  go on the file path's side of the tag — correcting bits underneath an
  authenticator is dead code.

- **Standing risk, unchanged:** the primitives are homemade. GB3HKDF, the
  XOR-combined multi-MAC tag, and the standalone TMEAEAD/GGAEAD constructions
  have no external analysis. The constructions around them are careful, but
  layering discipline cannot rescue a weak primitive.

- 413 tests pass, plus the build-flag, DAC-flag, fuzz, TLS, examples,
  benchmark and hygiene tasks.
