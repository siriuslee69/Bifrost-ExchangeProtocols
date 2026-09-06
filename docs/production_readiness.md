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

The handshake settles identity in private. The client hello names nobody; the
server's certificate and the client's both travel inside sealed blocks keyed
from the KEM answer plus the transcript so far. An observer sees two nonces
and some key material and never learns who is talking to whom.

Before the server releases the first epoch it checks, in this order:

1. **Shape and policy**, on fields the hello already carries — no key work, so
   a flood of nonsense costs almost nothing.
2. **The cookie**, if required: a tag the server computes from the sender's
   address with its own secret, keeping no per-client state. A peer that
   cannot receive at the address it claimed never gets a valid one, so
   encapsulation and signature work only ever run for a peer really there.
3. **Every authority proof** — one per slot the pinned root lists, not just
   the first. A certificate carrying fewer proofs than the root has slots is
   refused outright, so an attacker cannot drop the post-quantum half of a
   hybrid authority and be judged on the classical half alone.
4. **The certificate serial** against the deployment's revocation list.
5. **The validity window**, and whether the local clock is close enough to
   that window to be worth trusting at all. A clock a year out of step is
   refused as unusable rather than allowed to guess.
6. **The peer's own proof** over the transcript, and the transcript hash.

Revocation names the certificate, not the holder: a serial can be revoked and
the same subject issued a fresh certificate. Revocation-list *distribution*
remains deployment policy; verification accepts a caller-supplied
`revokedSerials` list and fails closed on a match.

The wall clock is a caller parameter. A library that silently reads an unset
system clock and judges certificates against it is worse than one that makes
the caller say where the time came from.

### The three modes, and what each one requires

Steps 3 to 6 above describe AM1C, the certificate mode. The other two replace
those steps and nothing else — the four records, their order and their sizes
are the same in all three.

| | Replaces steps 3-6 with | Provisioned in advance |
|---|---|---|
| AM1C | authority proofs, serial, validity, transcript proof | the authority's public keys |
| AM1S | validity and an exact key match, then transcript proof | the peer's own public key |
| AM1M | a name match and one tag over the transcript | a shared secret |

Three properties hold across all three, and are what make the choice safe to
make per deployment rather than per protocol:

1. **The mode is bound, not merely stated.** It travels as one byte in the
   hello and is inside the transcript both sides rebuild independently. A
   responder refuses a hello naming a mode it does not run, before any key
   work, rather than mirroring the client's choice back.
2. **Failure is closed in every direction.** A wrong pin, a wrong secret, a
   wrong name, or a mode this side does not run all end in no epoch and a
   dropped connection. None of them fall through to a weaker check.
3. **AM1M contributes key material, not just a verdict.** A binder derived
   from the shared secret goes into the handshake key schedule beside the KEM
   results, so an attacker who breaks every KEM slot still cannot open the
   sealed blocks. The provisioned secret itself never enters the derivation.

AM1M sessions hold no signature keys, so the offers and replies that rotate an
epoch are proved with a tag under a session-derived key instead of a signature
stack. That key comes from the finished transcript and is never the
provisioned secret, so it differs in every session.

## Package Delivery

Secure packages compress before encryption, authenticate before decompression,
and enforce absolute encoded/plaintext limits plus an expansion-ratio limit.

Compressing before encrypting leaks the plaintext's compressibility through
the ciphertext length, so compression is off unless a caller names it, and
naming it switches padding on with it — the envelope is rounded up to whole
64-byte blocks before sealing, filler count in the last byte. The padding
decision is taken from the policy, never from whether compression actually
helped: deciding it from the outcome would make the presence of padding a
signal about the plaintext. Padding blunts the leak into 64-byte steps rather
than deleting it, and that limit is worth stating plainly — a payload that
compresses from 4 KiB to 100 bytes still lands in a different block count than
one that does not compress at all. Compression remains unsafe on any payload
that mixes a secret with attacker-supplied text, padded or not.
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

## One Layer Of Encryption

A frame used to be encrypted twice. The session sealed the payload with an
epoch AEAD, and inside that ciphertext sat a FOMKE envelope that had already
sealed the same bytes with a per-message key. Two ciphertexts, two tags, two
nonces, and one of them entirely redundant.

```text
  before   [AME 36][epoch|nonceLen|tagLen|len][nonce 24][tag 32]
                     [FOM 27][nonce 24][tag 32][ciphertext]     = 187 B

  after    [AME 34][FOM 22][tag 32][ciphertext]                 =  88 B

  then     [AME 26][FOMKE 13][tag 32][ciphertext]              =  71 B
```

FOMKE is now the only payload protection, and it uses the construction the
outer layer used to: every cipher slot the tier switches on is XORed over the
payload in turn, and every authenticator slot contributes to one combined tag.
That code lives in exactly one place, `ame/level1/tier_aead.nim`, and both the
live ratchet and the at-rest package sealer call it.

What went away, besides bytes:

- **A second construction to review.** The two layers derived keys
  differently, framed their authenticated input differently, and had separate
  tag-length handling. There is now one of each.
- **A wire nonce.** Both sides derive it from the same ratchet step, so
  sending it repeated something the receiver already held: 24 bytes per
  message, and one fewer field an attacker could influence.
- **A nonce-length field.** Nothing left to describe.
- **A mode where the ratchet is off.** A session either has a working ratchet
  or does not exist. `initAmeSession` starts it from the finished exchange and
  the handshake transcript, so the endpoint role and the ratchet direction
  cannot disagree — there is no separate switch to set wrongly.

What stayed:

- **Header authentication.** The AME header is still in the clear, because a
  receiver must read it before it knows which keys to reach for. Every byte of
  it still goes into the tag, so a header edited in flight makes the body fail
  to open.
- **A retiring grace window.** After an epoch turns, frames already in flight
  carry the previous epoch. The pre-upgrade ratchet is kept for a bounded
  number of frames and erased at zero, so old keys do not outlive the handful
  of packets they exist for.
## One Framing

A DAC datagram is one AME frame. It used to be two headers:

```text
  before   [DAC1 27B][AME2 36B][epoch|nonce|tag|ciphertext]
  after             [AME  26B][FOMKE 13B|tag|ciphertext]
```

Every field in that DAC header was already beside it or derivable. Session and
lane were in the AME header. The epoch was the protected body's epoch restated
in a narrower field. The sequence advanced in lockstep with the AME sequence,
because both were incremented on the same line. Measured on a 1024-byte
payload, framing overhead went from 131 bytes to 115 -- and, once the double
encryption went with it, from 214 bytes to 115.

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

## One Seal Per Path, And Where The Repair Data Sits

A package is sealed once. Which seal, and where the repair data goes relative
to it, depends on how the package travels. Both orderings below are correct;
which one applies is *forced* by where the sealing happens.

```text
through a file or an untrusted courier   (planAmeSecurePackage)
  seal the whole package once, THEN cut it up and add parity
    -> parity is computed over CIPHERTEXT, and sits OUTSIDE the tag
    -> a repair layer rebuilds lost pieces with no key at all
    -> one tag, checked once, on bytes already put back together

over the live relay                       (sendAmeSecurePackage)
  cut the package up, compute parity, THEN seal each piece separately
    -> parity is computed over PLAINTEXT, and sits INSIDE the tags
    -> only an endpoint can repair, because only an endpoint can decrypt
```

The live path cannot use the first ordering. Each datagram is sealed with its
own ratchet key, so two sealed datagrams XORed together are not a sealed
datagram — parity across them would be meaningless. Sealing per datagram and
erasure-coding across datagrams cannot both be the outer layer.

That is safe on the live path because the loss being repaired is a **whole
missing datagram**, not a flipped bit. A datagram that arrives damaged fails
its own tag and is dropped, which looks exactly like one that never came. A
piece rebuilt from parity is then checked twice over: the manifest carrying
the package's BLAKE3 digest is itself a sealed message, and `finishDacPackage`
compares the reassembled bytes against that digest before committing. Nothing
an attacker supplies is ever handed up.

**If bit-level correction is ever wanted** instead of whole-piece recovery, it
must go on the file path's side of the tag. Correcting bits underneath an
authenticator is dead code: the tag rejects the message before the correction
would ever run.

The relay entry point takes no key material at all, which is the clearest
statement of the split: on that path the keys are the session's, not the
package's.

### Compression

Compression is off by default on both paths. Compressing before encrypting
leaks: the ciphertext is as long as the compressed input, so its length says
how well the plaintext compressed — and if an attacker can get their own text
placed beside a secret, a shorter result means the two matched. Callers ask
for it by name, with `compressedAmeCompressionPolicy()`, and should only do so
when no part of the payload is attacker-influenced.
## The Socket

`ame/level3/dac_endpoint.nim` is the one file in the stack that holds a
socket, so it is the only one that has to be trusted about blocking, timeouts
and partial reads. It adds nothing to the protocol: `pumpAmeDacEndpoint` reads
one datagram into the relay and transmits the replies, `tickAmeDacEndpoint`
runs the clock so ACK deadlines and repair timers fire on a quiet link.

A receive timeout returns `adrNone`, not an error -- a datagram loop spends
most of its life waiting. A send that fails is counted rather than raised, so
one unreachable peer cannot end the loop for every other peer.

`evaluation/tests/test_ame_dac_endpoint.nim` runs a package across two loopback UDP
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

- `evaluation/tests/test_wire_fuzz.nim`: every DAC body decoder, the frame envelope, the
  header peek, the link loop, and the link table.
- `evaluation/tests/test_wire_fuzz_protocols.nim`: AME frame headers, frames and
  protected bodies; BFX2 envelopes and value packets; TLS 1.3 records,
  handshake framing, ClientHello, ServerHello, EncryptedExtensions,
  Certificate and CertificateVerify.

Nested decoders are fuzzed as the pair they arrive as -- an AME frame carrying
a protected body, a TLS record carrying a handshake message -- so a mutation
can land in either length field.

This establishes that the decoders do not crash on hostile input. It is not a
substitute for external review of the TLS 1.3 implementation, which remains
the largest hand-written attack surface in the repository.
