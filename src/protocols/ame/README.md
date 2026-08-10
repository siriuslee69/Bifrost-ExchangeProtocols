# AME2 Mask Tiers

AME separates immutable algorithm placement from active epoch selections.
There is no in-session algorithm replacement, reordering, or negotiation shim.

## Layout

`AmeSuiteLayout` fixes six ordered slot families for the whole session:

```text
KEM | cipher | MAC | hash | signature | KDF
```

- Each family contains `1..8` slots.
- KEM identifiers use stable one-byte values.
- Other algorithm identifiers use stable four-bit values packed two per byte.
- Repeated KEM identifiers create independent slots, keypairs, and secrets.
- Slot order never changes after the handshake.
- Canonical layout bytes contain algorithm IDs only, never active masks.

## Tiers

`AmeMaskTier` contains a stable positive `tierId` and `AmeTierMasks`:

```text
tierId u32
KEM mask | cipher mask | MAC mask | hash mask | signature mask | KDF mask
```

Every mask is MSB-first:

```text
bit 7 -> slot 0
bit 6 -> slot 1
...
bit 0 -> slot 7
```

Every mask must select at least one occupied slot. Active duplicate hash or KDF
algorithms are rejected because equal XOR layers could cancel each other.

## Tier Path

`AmeTierPath` stores up to eight ordered `AmeMaskTier` values. Tier IDs must be
unique and remain stable. Manual, elapsed-time, and successful-transfer triggers
select a target tier; they do not alter the immutable layout.

```nim
const kems: AmeKemAlgorithms = [akaX25519, akaFireSaber, akaFireSaber]

var
  layout = defaultAmeLayout(kems)
  initial = initAmeMaskTier(layout, 10'u32,
    initAmeTierMasks(0b10000000'u8, 0b10000000'u8, 0b10000000'u8,
      0b10000000'u8, 0b10000000'u8, 0b10000000'u8))
  stronger = fullAmeMaskTier(layout, 20'u32)
  path = initAmeTierPath(layout, [initial, stronger])

path.setCurrentAmeTier(initial)
path.setTrigger(1, 200'u64)
```

Transferred bytes are counted only after a successful transport write. A failed
transition returns its tier to the due queue.

## Handshake

Every identity certificate or direct pin contains one public signing key for
every signature slot in the immutable layout. The local identity contains the
matching private keys. The initial tier's signature mask selects the exact
proof stack required from both peers.

The client hello identity proofs and transcript bind all values:

```text
immutable layout bytes
initial tier id and six masks
initial KEM offer
```

For example, a `11000000` signature mask over `[Ed25519, Falcon-512]` requires
both signatures. A missing, reordered, or invalid proof rejects the hello before
the responder encapsulates a KEM secret.

The completed handshake stores its signed `sessionId`, endpoint role, and
transcript hash in the authentication package. Live sessions cannot replace the
signed ID. Traffic keys are derived separately for:

```text
initiator -> responder
responder -> initiator
```

Both directions include the authenticated transcript, session ID, and epoch.
An endpoint therefore cannot accept its own reflected frame.

The initial exchange mask must equal the initial tier's KEM mask, so every KEM
secret required by epoch 1 exists before protection begins. The responder accepts
only a byte-identical supported layout and validates all initial masks.

## Epoch Transition

An `AmeExchangeRequest` carries:

```text
target tier id and six masks
KEM exchange mask
```

The request does not carry algorithm IDs. Both peers use the immutable layout
bound by the handshake.

```text
receiver -> Offer(request id, base epoch, target tier, exchange mask, public keys)
sender   -> Reply(request id, base epoch, target tier, exchange mask, envelopes)
receiver -> EpochReady(request id, candidate epoch, target tier, optional FOMKE commit)
both     -> atomically promote the authenticated candidate epoch
```

Validation rules:

- Every newly activated KEM slot must occur in the exchange mask.
- Exchange bits must be contained in the target tier's KEM mask.
- Already selected KEM slots may occur in the exchange mask to rekey them.
- Established secrets in unselected exchange slots remain stored unchanged.
- Key derivation uses only KEM slots selected by the target tier.
- Cipher, MAC, hash, signature, and KDF masks rotate together with the epoch.
- Offer public keys are signed by every signature slot selected by the union of
  the current and target tiers. The responder verifies the complete stack before
  encapsulation or candidate-epoch mutation.
- Reply envelopes use that same current-plus-target signature stack. The
  initiator verifies it before decapsulation or epoch rotation.
- The responder keeps the candidate separate until EpochReady authenticates its
  epoch, tier, and optional FOMKE confirmation.

A transition may use an empty exchange mask when only non-KEM masks change and
all target KEM secrets already exist.

Transitions never move backward in the ordered tier path. Their proof stack uses
the union of the current and target signature masks, so a weaker target cannot
authorize removal of a stronger current signature by itself. The complete signed
offer and reply are hashed into the next epoch's transcript salt.

## Key Derivation

The KDF input binds:

```text
canonical immutable layout
canonical active tier
selected KEM mask
slot index and stable algorithm id
slot generation
length-framed shared secret
caller transcript or context
```

Only tier-selected KDF layers run. Their outputs are XOR-combined.

## Peer Trust

AME accepts authority certificates, reciprocal pinned identities, or a verified
`AmePeerTrustResult` supplied by a caller-owned provisioning layer. A session
with required trust fails closed until that evidence is present.
