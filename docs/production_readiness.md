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
DAC repairs a group from its parity shards: `drmXor` carries one shard and
rebuilds exactly one loss, `drmReedSolomon` carries `parityCount` shards and
rebuilds any `parityCount` losses across the group, data or parity alike. Loss
past the budget is reported with a reason rather than guessed at. Wider loss
falls back to exact chunk repair, and the complete BLAKE3 digest is verified
before a commit is issued.

Neither endpoint asks the other to change behaviour. The sender picks chunk
size, repair mode and parity width; the receiver picks its ACK batch size and
deadline from what it observes arriving, and the sender derives its repair
timer from the ACK latency it actually measures. An ACK states which sequences
arrived; a repair hint states which chunks are missing. Both are facts about
the speaker, so the two control loops touch disjoint parameters.

A path report is the same shape. On commit, a link states the loss and round
trip IT measured. The peer may move its own lane on the strength of that, one
step at a time, and only between packages -- a report never moves a lane out
from under a transfer in flight, and it is never an instruction. The receiving
side learns the sender's new parameters from the next manifest, which is
authenticated, so nothing has to be negotiated.

## The Link Loop

`dac/level3/link.nim` is what actually runs the transport. It owns no socket:
`beginDacPackage` returns frames to transmit, `feedDacFrame` turns arriving
bytes into events and reply frames, and `tickDacLink` acts on elapsed time. The
same loop therefore runs over UDP, over a test pipe, or inside one process.

One package is in flight per direction. Both repair timers are bounded, and a
package that cannot complete raises `dlkPackageFailed` rather than waiting
forever, so a caller always learns the outcome.

Two failure modes are load-bearing and tested rather than assumed:

- A malformed or foreign frame is reported, never raised. A peer cannot end
  the loop by sending rubbish.
- Only a drop in the missing count counts as progress. Parity that merely
  arrives does not, or a sender topping up parity the receiver cannot use
  would refresh the receiver's timer forever and it would never escalate to
  asking for exact chunks.

## One Framing

A DAC datagram is one AME frame. It used to be two headers:

```text
  before   [DAC1 27B][AME2 36B][epoch|nonce|tag|ciphertext]
  after             [AME2 36B][epoch|nonce|tag|ciphertext]
```

Every field in that DAC header was already beside it or derivable. Session and
lane were in the AME header. The epoch was the protected body's epoch restated
in a narrower field. The sequence advanced in lockstep with the AME sequence,
because both were incremented on the same line. Measured on a 1024-byte
payload, framing overhead went from 131 bytes to 104.

Removing it removed failure modes, not just bytes:

- Two identities can disagree. The receiver had to cross-check the outer epoch
  against the protected one and reject a mismatch; there is now one epoch and
  nothing to reconcile.
- Two replay windows tracked two sequences that were always equal. One window
  remains.
- The outer epoch was a `u16`. An AME epoch is a `u32`, so a session past
  65,535 epochs could not use the DAC carrier at all. It can now.
- Payloads over 65,535 bytes needed the SuperClean "extended body length"
  framing to widen the outer header. The AME length is `u32` natively, so no
  path lane needs widening.

DAC control messages -- manifests, chunks, parity, receipts, repair hints --
now travel as `ampkDacControl` AME frames. **The message kind is the first byte
of the protected plaintext**, so it is encrypted as well as authenticated: an
observer cannot tell an ACK from a repair hint by looking, and a peer that
rewrites one fails verification rather than being believed. Before this, DAC
control traffic rode bare and anyone could forge a receipt.

`renderDacFrame` still produces the old bare DAC1 frame. That path is for a
path probe sent before a session exists, and for tests. Nothing on a live
session should use it, and it is documented as unauthenticated.

## The Assembled Path

`ame/level3/dac_relay.nim` joins the three pieces that previously existed
separately: the link loop, the peer table, and the session that authenticates
every datagram.

```text
   datagram + peer address
             |
   find the peer's slot          <- no slot, no session: DROPPED unparsed
             |
   openAmeDacControl()           <- authenticate, decrypt, recover the kind
             |
   feedDacMessage(link, kind)    <- the loop only ever sees trusted kinds
             |
   sealAmeDacControl() per reply <- every answer authenticated on the way out
```

The admission rule here is stronger than the bare table's. That one had to
guess from a frame whether a stranger deserved a slot. This one does not
guess: a peer gets a slot when the handshake gave it an AME session, and a
datagram from any other address is dropped before it is parsed. Sessions live
in an array parallel to the table's slots, so the slot index is the session
index -- one bound, one lookup, and no second structure a peer can grow. A
released or swept peer has its session erased before its slot is freed, so a
slot is never handed to a new peer with the previous peer's keys beside it.

The relay owns no socket, for the same reason the link loop does not: it turns
datagrams into events and events into datagrams, so it is driven identically
by a real socket, a test pipe, or one process talking to itself.

`examples/secure_authority_package.nim` runs the whole path end to end --
authority handshake, relay admission, a sealed package, one datagram in five
dropped, parity repair, restored plaintext -- without touching a chunk by
hand.

## One Seal Per Path

A package is sealed once, and which seal depends on how it travels:

- **Over the relay** (`sendAmeSecurePackage`): compression only, no
  package-level AEAD. The transport already authenticates the whole package
  end to end -- every datagram is sealed under the epoch, the manifest
  carrying the package's BLAKE3 digest is itself a sealed message, and
  `finishDacPackage` checks the assembled bytes against that digest before
  committing. An attacker can forge none of the three, so a second AEAD over
  the same bytes buys nothing and costs a full pass over the payload.
- **Through a file or an untrusted courier** (`planAmeSecurePackage`): the
  package-level AEAD, bound to the package id, epoch, and compression
  algorithm. There is no transport to inherit integrity from, so the package
  carries its own, and `restoreAmeSecurePackage` verifies it however the bytes
  arrived.

The relay entry point takes no key material at all, which is the clearest
statement of the split: on that path the keys are the session's, not the
package's.

## The Socket

`ame/level3/dac_endpoint.nim` is the one file in the stack that holds a
socket, so it is the only one that has to be trusted about blocking, timeouts
and partial reads. It adds nothing to the protocol: `pumpAmeDacEndpoint` reads
one datagram into the relay and transmits the replies, `tickAmeDacEndpoint`
runs the clock so ACK deadlines and repair timers fire on a quiet link.

A receive timeout returns `adrNone`, not an error -- a datagram loop spends
most of its life waiting. A send that fails is counted rather than raised, so
one unreachable peer cannot end the loop for every other peer.

`tests/test_ame_dac_endpoint.nim` runs a package across two loopback UDP
sockets, which is the first time a DAC package has crossed a real socket.

## Many Peers, Bounded Memory

`dac/level3/link_table.nim` holds one `DacLink` per conversation, keyed by
host, port and carrier, so one process serves many peers. The table is the one
structure in DAC that a peer can push on, so every path that adds to it is
bounded:

- Capacity is a fixed array allocated once. It is never grown.
- An arriving datagram is identified from its fixed header prefix by
  `peekDacFrameIdentity`, which allocates nothing and raises nothing. Rubbish
  from an unknown address is dropped before a slot is considered.
- A peer with no slot is admitted only by a frame that starts a conversation --
  a manifest or a path probe. A chunk, ACK or repair hint from a stranger
  refers to state that does not exist and the link would ignore it anyway, so
  spending a slot on one is refused.
- Under pressure the table reclaims only links that finished in both
  directions and then stayed quiet for the idle window. A live conversation is
  never evicted to make room for a stranger; the stranger is refused and the
  refusal counted.

Each link derives its scramble stream by mixing the peer key into the table
seed, so a peer that knows its own address learns nothing about another link's
send delays or chunk order.

The table is a linear scan rather than a hash map. At a few dozen slots that
compares faster than it hashes, and there is no key an attacker can choose to
force collisions with.

## Parser Hardening

Two harnesses walk structured mutations of real encodings through every
decoder in the library. The contract is that arbitrary bytes yield either a
value or a `CatchableError` -- never an `IndexDefect`, a `RangeDefect`, or an
overflow. Seeds are deterministic, so a failure reproduces exactly, and the
harness is checked against a deliberate out-of-bounds read to confirm it still
reports one.

- `tests/test_wire_fuzz.nim`: every DAC body decoder, the frame envelope, the
  header peek, the link loop, and the link table.
- `tests/test_wire_fuzz_protocols.nim`: AME frame headers, frames and
  protected bodies; BFX2 envelopes and value packets; TLS 1.3 records,
  handshake framing, ClientHello, ServerHello, EncryptedExtensions,
  Certificate and CertificateVerify.

Nested decoders are fuzzed as the pair they arrive as -- an AME frame carrying
a protected body, a TLS record carrying a handshake message -- so a mutation
can land in either length field.

This establishes that the decoders do not crash on hostile input. It is not a
substitute for external review of the TLS 1.3 implementation, which remains
the largest hand-written attack surface in the repository.
