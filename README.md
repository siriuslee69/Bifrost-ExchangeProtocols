# Bifrost Exchange Protocols

Nim protocol library for transport, BFX2, DAC, AME2, and FOMKE.

## Names And Abbreviations

Every protocol name in this repo is an abbreviation. Spelled out once, here:

```text
+----------+----------------------------------------+----------------------------------+
| Short    | Full name                              | One-line job                     |
+----------+----------------------------------------+----------------------------------+
| DAC      | Data Adaptive Connection               | delivery: chunks, ACK, repair    |
| AME      | Adaptive Message Encryption            | suite/KEM/protect + live session |
| FOMKE    | Forward-Only Message Key Extension     | one fresh key per message        |
| GB3HKDF  | Gimli BLAKE3 Hash Key Derivation Func. | turns one secret into many keys  |
| TMEAEAD  | Too Much Encryption AEAD               | layered heavy message cipher     |
| GGAEAD   | Gimli Gimli AEAD                       | compact IoT/game message cipher  |
| BFX2     | Bifrost Exchange format 2              | tagged binary envelopes          |
+----------+----------------------------------------+----------------------------------+
```

Supporting terms used throughout:

- `KEM` (Key Encapsulation Mechanism): a public-key exchange that leaves both
  peers holding the same secret bytes.
- `AEAD` (Authenticated Encryption with Associated Data): encryption that also
  proves nobody changed the message, and can bind extra public bytes (the
  "associated data", `AAD`) into that proof.
- `KDF` (Key Derivation Function): a one-way function that stretches one secret
  into any number of independent keys.
- `Epoch`: a numbered key generation. A new KEM exchange starts a new epoch.
- `Lane`: one direction of traffic. Lane 1 is initiator to responder, lane 2 is
  responder to initiator.

## Read This First

```text
+---------------- Application ----------------+
| plaintext file, message, archive, or record  |
+----------------------|-----------------------+
                       v
+---------------- AME security ----------------+
| authority trust -> layout + mask-tier epoch  |
| -> optional compression -> protect / open    |
| -> optional FOMKE per-message ratchet        |
+----------------------|-----------------------+
                       v
+---------------- DAC1 delivery ---------------+
| manifest -> chunks -> parity -> repair       |
| -> digest check -> commit receipt             |
+----------------------------------------------+
```

AME owns both the crypto toolkit and the live session (epochs, triggers,
handshake, TCP/DAC carriers, replay). DAC only delivers opaque body bytes.

Two axes matter:

```text
OWNERSHIP (API)
  app  ->  AmeSession  ->  AME protect/open  ->  optional FOMKE
                     \->  DAC / TCP stream

WIRE (bytes, outer to inner)
  [stream 4 | DAC1 27/29]
    -> AME2 header 36
      -> protected body 12 + nonce + tag + ciphertext
        -> [optional FOM1 83 + app]
```

See [Wire Formats: Low-Level View](#wire-formats-low-level-view) for exact bytes.

```text
+----------------------------- DAC1 frame ------------------------------------+
| DAC header (delivery: session, lane, path-epoch, sequence)                  |
|  +------------------------- AME2 frame -----------------------------------+ |
|  | AME header (session, lane tree, sequence, kind, class)                 | |
|  |  +---------------- protected body ------------------------------------+| |
|  |  | epoch + nonceLen + tagLen + payLen | nonce | tag | ciphertext      || |
|  |  |   after AME open -> optional FOM1 (per-message key) -> app bytes   || |
|  |  +--------------------------------------------------------------------+| |
|  +------------------------------------------------------------------------+ |
+-----------------------------------------------------------------------------+
```

## Quick Start

```nim
import bifrost_exchange_protocols

const myKems: AmeKemAlgorithms = [
  akaFireSaber,
  akaFireSaber,
  akaX25519
]

var
  layout = defaultAmeLayout(myKems)
  initial = initAmeMaskTier(layout, 10'u32,
    initAmeTierMasks(0b10000000'u8, 0b10000000'u8, 0b10000000'u8,
      0b10000000'u8, 0b10000000'u8, 0b10000000'u8))
  stronger = fullAmeMaskTier(layout, 20'u32)
  path = initAmeTierPath(layout, [initial, stronger])

path.setCurrentAmeTier(initial)
path.setTrigger(1, 200'u64)
```

Run the example and tests:

```text
nimble exampleAmeExactPath
nimble exampleSecurePackage
nimble test
```

## Native TLS 1.3

Bifrost now exports a transport-neutral TLS 1.3 client and server engine. The
first profile is deliberately narrow:

```text
TLS version       TLS 1.3 only
Key exchange      X25519
Record cipher     ChaCha20 + one-time Poly1305
Hash and KDF      SHA-256 + HMAC/HKDF-SHA-256
Certificate key   Ed25519
Client trust      caller-supplied pinned Ed25519 root
Identity          DNS or IP Subject Alternative Name
Application       caller-owned bytes, such as HTTP/1.1
Compression       none at the TLS record layer
```

The engine does not own a socket:

```text
TCP / AsyncSocket / memory test
             |
             v
 feedTls13Client / feedTls13Server
             |
             +-> outbound TLS records
             +-> authenticated application bytes
             +-> connected / closed / error state
```

Server setup:

```nim
import bifrost_exchange_protocols

var config = Tls13ServerConfig(
  certificateChainDer: @[leafCertificateDer],
  ed25519SecretKey: serverSecretKey,
  alpn: @["http/1.1"]
)
var server = initTls13ServerSession(config)

# Pass each arbitrary TCP fragment to the engine.
var output = server.feedTls13Server(networkBytes)
for record in output.outbound:
  sendToPeer(record)
for plaintext in output.applicationData:
  handleAuthenticatedBytes(plaintext)
```

Client setup:

```nim
var config = Tls13ClientConfig(
  pinnedRootCertificateDer: rootCertificateDer,
  serverName: "service.example",
  alpn: @["http/1.1"],
  nowUnix: currentUnixTime
)
var client = initTls13ClientSession(config)

sendToPeer(client.startTls13Client())
var output = client.feedTls13Client(networkBytes)
```

Both directions support fragmented and coalesced records, encrypted alerts,
`close_notify`, and post-handshake `KeyUpdate`. Handshake and copied schedule
secrets are cleared after traffic-key promotion.

This profile is not a general public-Web TLS client. It currently rejects
multi-certificate chains and certificates using RSA or ECDSA. It also omits
HelloRetryRequest, client certificates, session resumption, and 0-RTT. Keep the
OpenSSL transport wrapper available until the native profile receives broader
interoperability, fuzzing, and independent security review.

## Initial Trust

```text
Authority
  +-> signs Client certificate
  +-> signs Server certificate

Client                         Server
  |-- signed Hello + KEM keys -->| verify authority + client proof
  |<-- signed Hello + KEM reply -| create shared candidate secrets
  |-- signed transcript Finish ->| verify the complete conversation
  +========== equal AME epoch ===+
```

An epoch is returned only after the authority signature, validity period, peer
key proof, exact AME layout and initial tier, KEM exchange, and final transcript
proof all pass.

## Secure Packages

```text
Sender
  plaintext -> bounded Eir compression -> AME protect -> DAC chunks
            -> XOR recovery bytes + Eir parity check

Receiver
  chunks -> local one-loss recovery -> exact repair fallback
         -> BLAKE3 digest -> AME open -> bounded Eir decode -> plaintext
```

```nim
var plan = planAmeSecurePackage(senderAuth, packageId, plaintext,
  cleanLanDacDefaults())
var incoming = initDacPackageReceiver(plan.package.manifest)

for chunk in plan.package.chunks:
  incoming.acceptDacPackageChunk(chunk)

var result = finishAmeSecurePackage(receiverAuth, incoming, plan.compression)
```

Applications transmit the manifest, chunks, repair hints, repair chunks, and
commit with their own socket or event loop. Protocol state stays deterministic
and can be tested without a live network.

## AME2

AME2 exchanges exact ordered algorithm paths rather than security tiers.

| Family | Identifier | Slots | Selection |
|---|---:|---:|---:|
| KEM | 8 bit | 8 | exchange mask |
| Cipher | 4 bit | 8 | active mask |
| MAC/HMAC | 4 bit | 8 | active mask |
| Hash | 4 bit | 8 | active mask |
| Signature | 4 bit | 8 | active mask |
| KDF | 4 bit | 8 | active mask |

Repeated KEM entries are independent. Selecting an inactive slot adds it;
selecting an active slot rekeys it. Other active slots remain.

Exact suite proposals are accepted or rejected without substitution.

### One Transition At A Time

Only one epoch transition may be in flight, counting both directions. If both
endpoints start one at the same moment, roles break the tie:

```text
  initiator A                       responder B
  ------------                      ------------
  begin  -> offer A  -------------> B drops its own offer, answers A
  offer B <------------------------ begin  -> offer B
  reject offer B (A keeps its own)

  result: both endpoints follow A's transition, one epoch, one key set
```

Without the tie-break both sides would rotate to the same epoch number from
different key material, and every later frame would fail to authenticate.
`beginAmeSessionExchange` therefore refuses to start while a peer candidate
epoch is pending, and `answerAmeSessionExchange` refuses an offer while the
local endpoint is the initiator with its own exchange outstanding.

### Rekeying Versus Rotating

A tier change always rotates the epoch and always changes every traffic key,
because each epoch mixes in a fresh transcript salt. It only runs a new KEM for
the slots named by the exchange mask:

```text
  current kem 1000_0000 -> target kem 1100_0000   exchange mask 0100_0000
      new KEM on slot 1, forward secrecy advances

  current kem 1000_0000 -> target kem 1000_0000   exchange mask 0000_0000
      keys change, but no new KEM: forward secrecy does NOT advance
```

Pass `rekeyMask` to `requestAmeTier` to force fresh key agreement on slots that
are already active.

## FOMKE

FOMKE (Forward-Only Message Key Extension) adds one fresh key per message on
top of one exact AME KEM result. "Forward-only" means keys can only be derived
forward, never backward: after a key is used, it and everything that could
recreate it are erased. Stealing today's state therefore never decrypts
yesterday's messages.

### How The FOMKE Algorithm Works

Step 1 - root. One shared secret from one active AME KEM slot goes through
GB3HKDF together with the epoch number, the exact encoded AME algorithm path,
and the chosen slot. The result is a 64-byte root. The shared secret copy is
erased.

Step 2 - lane split. The root is derived into two independent 64-byte chain
keys, one per direction, by including the lane number in the derivation. Then
the root itself is erased. Lane 1 always carries initiator-to-responder
traffic, lane 2 the reverse, so both sides agree on the mapping without
negotiation.

Step 3 - the chain. Each send advances the sender's outbound lane one step.
One GB3HKDF call turns the current chain key `CK(i)` into the next chain key
plus two one-time message key blocks; the sender keeps the block for its lane
and erases the other:

```text
lane 1 (initiator -> responder)          lane 2 (responder -> initiator)

CK1(0) --GB3HKDF--> CK1(1) + MK1(0)      CK2(0) --GB3HKDF--> CK2(1) + MK2(0)
   X erased            |                    X erased            |
                       v                                        v
CK1(1) --GB3HKDF--> CK1(2) + MK1(1)      seal message index 0 on lane 2
   X erased            |
                       v
              seal message index 1 on lane 1
```

Every derivation input includes a version label (`FOMKE-CHAIN-BLOCK-v1` or the
GGAEAD variant), the lane, the epoch, and the index, so no two positions in
any chain can ever produce the same bytes. The message key block `MK` is 160
bytes for TMEAEAD or 64 bytes for GGAEAD (see below). The chain key is 64
bytes at every step.

Step 4 - nonce. The 24-byte nonce is not random. It is derived by GB3HKDF from
the message key block itself plus epoch, index, and lane. Because the key is
used exactly once, the deterministic nonce is also used exactly once, and a
broken random generator cannot cause nonce reuse.

Step 5 - seal. The plaintext is encrypted with TMEAEAD or GGAEAD under the
one-time key and nonce. The authenticated associated data is a version label
plus epoch, index, lane, and the caller's own binding bytes - inside the AME session that
binding is the carrier, session, all three lane ids, and both sequence
numbers. After sealing, the message key is erased. The wire bytes are the FOM1
envelope shown in the wire-format section.

Step 6 - open (transactional). The receiver never mutates its live state on a
bad message. It clones the state, advances the clone's inbound lane up to the
received index, verifies the authentication tag, and only then replaces the
live state with the clone. Verification happens before any decryption output
is released.

Out-of-order and replay handling:

```text
receive index 5, chain expects 3
  -> derive keys 3 and 4, park them in the skipped-key cache
  -> derive key 5, open the message

receive index 3 later     -> take key 3 from the cache, open, remove it
receive index 3 again     -> not in cache, not derivable backward -> rejected
receive index 3 + maxSkip -> gap too large -> rejected (default 64, cap 4096)
```

Step 7 - epoch upgrade. An AME tier transition prepares candidate chains for
epoch `n+1` next to the live epoch `n` chains. Data is paused; the FKU2 commit
(wire-format section) must match request id, epochs, target tier, KEM exchange
mask, slot generations, both lane counters, and a confirmation tag derived
from the candidate chains. Only then do the candidates atomically replace the
live chains. On any mismatch the candidates are erased and epoch `n` continues.

### The Building Blocks

`GB3HKDF` (Gimli BLAKE3 Hash Key Derivation Function) is the protocol name for
Bifrost's domain-separated, XOR-combined Gimli/BLAKE3 KDF. It is not RFC 5869
HKDF. Each round computes one Gimli sponge branch and one BLAKE3 branch over
the same length-framed input and XORs them, so an attacker must break both
hash constructions to learn the output. It supports configurable rounds
(default 3), indexed 32-byte output blocks, multiple ordered secret inputs,
and an optional bounded memory-mixed mode for password-style hardening.

`TMEAEAD` (Too Much Encryption AEAD) is the heavy default cipher. Its 160-byte
message key block is five independent 32-byte keys. XChaCha20, AES-CTR, and
Gimli streams are composed over the payload. A nonce-specific Poly1305 tag is
expanded and XOR-combined with an independent 32-byte Gimli tag.
Authentication is verified before decryption.

`GGAEAD` (Gimli Gimli AEAD) is the smaller IoT/game-oriented choice. Its
64-byte block is one 32-byte Gimli stream key and one independent 32-byte
GimliHMAC key. The 32-byte HMAC covers a domain-separated, length-framed AAD,
nonce, and ciphertext transcript. FOMKE therefore derives 64 message-key bytes
per step for GGAEAD instead of 160 for TMEAEAD.

Short-message senders may prepare a bounded sequence of future FOMKE slots.
Preparation derives each one-time message key and nonce without advancing the
live chain, then generates AAD-independent Gimli and TMEAEAD XChaCha streams in
parallel:

```text
ordinary x86 build       1 message  -> scalar
SSE2 / ARM NEON build    4 messages -> one 4-lane batch, scalar tail
AVX2 server build        8 messages -> one 8-lane batch, then 4, then scalar
```

No SIMD lane is filled and discarded. A partial tail runs through the narrower
backend. Prepared TMEAEAD only computes its AAD-bound AES counter stream and both
authentication branches on the send path. AES-CTR selects AVX2 for complete
32-byte groups, SSE2/NEON for complete 16-byte groups, and scalar code for a
short tail. GGAEAD only needs the prepared Gimli bytes XORed with the payload
before computing GimliHMAC. Authentication is never pre-accepted or skipped.

The ordinary x86 tasks do not define `sse2` or `avx2`, so their prepared backend
is scalar. `nimble testFomkeServerSimd` and `nimble benchmarksServerSimd` build
an AVX2 server profile and require an AVX2-capable host. AME sessions use TMEAEAD by
default. Pre-generation defaults are deliberately cipher-specific:

```toml
[fomke]
tmeAeadPregeneration = false
ggAeadPregeneration = true
fomkePregenerationMessages = 8
fomkePregenerationPayloadBytes = 256
```

TMEAEAD therefore keeps future composite key and stream material out of memory
unless the user opts in. GGAEAD favors low-latency game/IoT traffic by default.
The setting is copied into each session by `enableAmeFomke`; it can be
overridden and securely cleared per connection:

```nim
enableAmeFomke(server, frResponder, 0, messageCipher = fmcGgAead)
setAmeFomkePregeneration(server, false)
```

`buildAmeFomkeSendCache` performs a synchronous deep-copy and build. For worker
threads, call `snapshotAmeFomkeSendState` under the connection lock, run
`prepareFomkeSendCache` on that detached state, erase the snapshot, then call
`installAmeFomkeSendCache` under the lock. Installation rejects and erases a
cache if the live epoch, direction, cipher, chain key, next index, or configured
policy changed. `ameFomkeSendCacheNeedsRefill` reports the half-empty threshold
for a caller-owned worker/synchronization loop. Losing an uninstalled cache
wastes work but does not advance the live ratchet.

The default 8-message, 256-byte cache contains 7,040 secret bytes for TMEAEAD or
3,776 for GGAEAD, plus sequence/object allocation overhead. Each prepared stream
is bound to its exact cipher subkey and nonce before use. Cache dimensions are
bounded to 4,096 messages and 16 MiB of prepared stream bytes. KEM upgrades,
connection teardown, and explicit cache clearing erase all stored keys, nonces,
chain snapshots, and stream bytes.

```nim
var alice = initFomkeFromAme(aliceExchange, 0, frInitiator)
var bob = initFomkeFromAme(bobExchange, 0, frResponder)

var message = sealFomkeMessage(alice, @[byte 1, 2, 3])
var opened = openFomkeMessage(bob, message)
doAssert opened.ok
```

AME sessions default to TMEAEAD. Select GGAEAD when enabling its forward-only inner
message layer on both peers:

```nim
enableAmeFomke(sender, frInitiator, 0, messageCipher = fmcGgAead)
enableAmeFomke(receiver, frResponder, 0, messageCipher = fmcGgAead)
```

The selected cipher is stored in FOMKE checkpoints and domain-separates chain
blocks, nonces, message AAD, and KEM-upgrade confirmations. It is connection
configuration, not an unauthenticated per-packet switch, so both peers must use
the same value. Version-1 checkpoints decode as TMEAEAD.

`enableAmeFomke` places FOMKE inside authenticated AME data frames. Later AME
KEM exchanges automatically prepare a FOMKE candidate. `EpochReady` commits it
only when request id, epochs, exact MSB-first mask, slot generations, both lane
counters, and the candidate confirmation tag agree. Data is paused while the
candidate is pending.

FOMKE, GB3HKDF, TMEAEAD, and GGAEAD are Bifrost-specific constructions. Keep
protocol versions domain-separated and obtain independent cryptographic review
before using them as a substitute for a standardized, reviewed secure-messaging
protocol.

CHUNKYAEAD is Bifrost's chunked file construction. It preserves the existing
`CHUNKY01` file format while owning its transform selection, fixed-width keys,
24-byte base nonce, threaded chunk processing, authentication, and BLAKE3/Gimli
tree hashing. Tyr supplies only the AES, XChaCha20, Gimli, and hash primitives.

## Layout

| Path | Purpose |
|---|---|
| `src/protocols/ame/` | Suite/KEM/protect, AME2 wire, session, handshake, secure package |
| `src/protocols/fomke/` | GB3HKDF, directional ratchets, upgrade commits, and FOM1 wire |
| `src/protocols/tmeaead/` | Bifrost five-key TMEAEAD construction |
| `src/protocols/ggaead/` | Bifrost compact GGAEAD construction |
| `src/protocols/preparation/` | Shared future-message stream preparation backends |
| `src/protocols/chunkyaead/` | Chunked file encryption and tree hashing |
| `src/protocols/dac/` | Framing, ACK, repair, path control, drift payloads |
| `src/protocols/transport/` | TCP, UDP, TLS, stream framing, bounded async stream I/O and relay helpers |
| `src/protocols/tls13/` | Pure-Nim TLS 1.3 records, handshake, and client/server sessions |
| `src/protocols/bfx2/` | Tagged binary envelopes |
| `tests/` | Unit and protocol tests |

## Tasks

| Task | Command |
|---|---|
| Build library | `nimble buildLib` |
| Run tests | `nimble test` |
| Run examples | `nimble examples` |
| Run benchmarks | `nimble benchmarks` |
| Run AVX2 server benchmarks | `nimble benchmarksServerSimd` |
| Test native TLS | `nimble testNativeTls` |
| Test FOMKE | `nimble testFomke` |
| Test CHUNKYAEAD | `nimble testChunkyAead` |
| Test FOMKE AVX2 server profile | `nimble testFomkeServerSimd` |
| Test native TLS against OpenSSL | `nimble testNativeTlsInterop` |
| Check generated files | `nimble releaseHygiene` |
| Remove generated files | `nimble cleanGenerated` |

## Wire Formats: Low-Level View

Four magic prefixes identify the framing layers after the AME fold:

```text
DAC1  -> transport and repair framing            (dac/level0/framing.nim)
AME2  -> routing header + protected body payload (ame/level2/wire.nim, session.nim)
FOM1  -> forward-only per-message envelope       (fomke/level2/wire.nim)
FKU2  -> tier-bound AME/FOMKE upgrade confirmation (fomke/level2/wire.nim)
```

Handshake records use separate magics and are **not** AME2-wrapped until epoch
keys exist:

```text
AMI1  -> identity certificate / pinned descriptor
AMC1  -> client hello (layout + initial tier + offer + proof)
AMS1  -> server hello (reply + proof)
AMF1  -> client finish (transcript + proof)
ASP1  -> secure package detached protect shape
```

All multi-byte integers below are little-endian. `u8/u16/u32/u64` are unsigned
integers of 1/2/4/8 bytes. Offsets start at 0 for that layer.
`LF(n)` means a length-framed field: `u32 len` + `n` bytes = **4 + n**.

### Two phases

```text
PHASE A — first key exchange (no epoch keys yet)
  [optional TCP stream 4+body]  ->  bare AMC1 / AMS1 / AMF1

PHASE B — after epoch exists
  [stream 4 | DAC1] -> AME2 -> protected body (AME protect) -> [optional FOM1]
```

### TCP/TLS stream frame

```text
offset 0        4
       +--------+------------------+
       | Len32  | Payload          |
       | 4 B    | Len bytes        |
       +--------+------------------+
Total = 4 + Len
```

### DAC1 Frame (Data Adaptive Connection)

Optional outermost delivery shell. Stage-blind: does not know handshake vs live
crypto. Adapts body length, chunks, ACK, and repair only.

```text
Base header = 27 B   (BodyLen = u16)
Extended    = 29 B   (BodyLen = u32, flag bit 8)

 0     3   4    5     7        15    19    21    25      27
+-----+---+---+----+---------+-----+-----+-----+-------+------+
|DAC  |Ver|Knd|Flgs| Session |Lane |Epch | Seq |BodyLn | Body |
| 3B  |1B |1B |2B  | 8B      |4B   |2B   |4B   |2or4B  | n    |
+-----+---+---+----+---------+-----+-----+-----+-------+------+
```

### AME2 Frame (Adaptive Message Encryption)

Fixed header is **36 B**. Format version is **2**. For live data and control,
the payload is one **protected body** (no separate AME protected body magic).

```text
offset   0      4     6      7       8         16       20        24      28      32        36
         +------+-----+------+-------+---------+--------+---------+-------+-------+---------+---------+
         | AME2 | Ver | Kind | Class | Session | RootLn | ParentLn| Lane  | Seq   | PayLen  | Payload |
         | 4B   | u16 | u8   | u8    | u64     | u32    | u32     | u32   | u32   | u32     | n bytes |
         +------+-----+------+-------+---------+--------+---------+-------+-------+---------+---------+
Total AME2 = 36 + PayLen
```

Kinds: `0x04` ExchangeKeys, `0x05` ExchangeEnvelopes, `0x06` EpochReady,
`0x07` LaneData, plus agreement/ping kinds.

### AME protected body (AME2 payload)

Epoch, nonce, tag, and ciphertext sit directly in the AME2 payload. Header is
**12 B** (no nested magic).

```text
offset   0       4        6        8        12       12+NL    12+NL+32
         +-------+--------+--------+--------+--------+--------+-------------+
         | Epoch | NonceLn| TagLen | PayLen | Nonce  | AuthTag| Ciphertext  |
         | u32   | u16    | u16    | u32    | NL     | 32     | n           |
         +-------+--------+--------+--------+--------+--------+-------------+

Total = 12 + NL + 32 + n
NL = sum of active cipher nonces (default tier: XChaCha20 only -> NL = 24)
Tag always 32 (ameProtectionAuthTagLen)
Ciphertext length = inner plaintext length (length-preserving)
```

Default protected-body overhead with NL=24: **12 + 24 + 32 = 68 B** before
inner bytes.

AAD label is `AME-AAD` plus carrier id, the full encoded AME2 header, and when
DAC-carried: `DAC1` plus DAC kind/flags/session/lane/epoch/seq.

### FOM1 Message (optional inner ratchet)

When FOMKE is enabled, AME ciphertext opens to one FOM1 envelope, not raw app
bytes.

```text
Header fixed = 27 B
FOM1 total   = 83 + P     (P = app plaintext length; nonce 24 + tag 32 fixed)
```

FOMKE AAD label: `AME-FOMKE-AAD-v1` plus carrier, session, lane tree, sequences.

### FKU2 Commit (FOMKE upgrade) - fixed **111 B**

Travels inside authenticated AME control frames (EpochReady body).

### Size cheat sheet (default tier, NL=24)

| Item | Bytes |
|---|---:|
| Stream header | 4 |
| DAC1 base / ext | 27 / 29 |
| AME2 header | 36 |
| Protected body fixed+nonce+tag | 68 |
| FOM1 fixed+nonce+tag | 83 |
| FKU2 | 111 |
| TCP data OH, no FOMKE | **4+36+68+P = 108+P** |
| TCP data OH, FOMKE | **4+36+68+83+P = 191+P** |
| DAC data OH, no FOMKE | **27+36+68+P = 131+P** |
| DAC data OH, FOMKE | **27+36+68+83+P = 214+P** |

Later tier/rekey control frames use the same AME2+protected-body shell; the
inner body is Offer, Reply, or tier-bound EpochReady (23 B, or 134 B with FKU2).

### Initial handshake bodies (bare)

```text
AMI1 cert  = variable (identity strings + PK + authority sig)
AMC1 hello = magic+ver+session + LF(nonce32) + LF(layout) + LF(initialTier) + LF(cert) + LF(offer) + LF(proof)
AMS1 hello = magic+ver + LF(nonce32) + LF(cert) + LF(reply) + LF(proof)
AMF1 finish= magic+ver + requestId + LF(transcriptHash) + LF(proof)
```

Offer/reply sizes grow with selected KEM public keys and ciphertexts
(FireSaber pk 1312 / ct 1472; X25519 pk 32 / sender pk 32).

## Issue Playbook

- A layout mismatch is rejected. Compare `encodeAmeSuiteLayout` output.
- A tier mismatch is rejected. Compare `encodeAmeMaskTier` output.
- A stale exchange is rejected. Check request id and base epoch id.
- A mask selecting an unoccupied slot is rejected.
- "AME cannot start an exchange while a peer candidate epoch is pending" means
  the peer's transition arrived first. Finish it, then start yours.
- "AME initiator keeps its own exchange during a simultaneous start" means both
  endpoints triggered at once. The responder yields; nothing is lost.
- A tier whose KEM mask equals the current one rotates the epoch without new
  key agreement. Pass `rekeyMask` when you want forward secrecy to advance.
- `AmeAuthorityRoot` must come from `initAmeAuthorityRoot`. A hand-filled root
  left at its defaults has an empty authority name and is refused.
- Data triggers count successful plaintext transfer bytes, not retry bytes.
- Tier changes and rekeys use authenticated Offer -> Reply -> EpochReady frames.
- FOMKE rekeys require matching lane counters and an empty skipped-key cache;
  deliver outstanding messages before starting an AME/FOMKE epoch transition.
- AVX2 tasks produce host-specific binaries. Use the ordinary tasks for x86
  clients or servers that may run on CPUs without AVX2.
- Peer trust is supplied by a caller-owned certificate or provisioning verifier.
- Initial authority trust uses `beginAmeHandshake`, `answerAmeHandshake`,
  `finishAmeHandshake`, and `acceptAmeHandshake`.
- Package repair uses XOR recovery for one loss and exact-chunk fallback for
  wider loss; Eir parity verifies recovered groups.
- Native TLS accepts only TLS 1.3, X25519, Ed25519, SHA-256, and
  `TLS_CHACHA20_POLY1305_SHA256`; unsupported suites fail closed.
- Native TLS client trust is pinned-root only. Public operating-system trust
  stores and RSA/ECDSA certificate paths remain unsupported.
- TLS record compression is intentionally absent. Compress HTTP content before
  encryption when the application negotiates a standard content encoding.

The benchmark task keeps its executable under `--out:build/tools/...`.
The default `nimble build` command is not a supported artifact path here; use
`nimble buildLib`.

`nix flake check path:$PWD` validates the package build, reproducible TLS
transport checks, and NixOS module rules.
# Direct LAN Messenger

Bifrost includes matching Android and Nim-WebUI desktop clients. They exchange
the same length-prefixed `BMSG` frames used by the automated transport test.

```text
desktop :48371  <---- local Wi-Fi / Ethernet ---->  Android :48371
```

Run the desktop client:

```sh
nimble desktop
```

Build it without launching the UI:

```sh
nimble desktopBuild
```

Build both Android APKs and run the physical host/phone exchange:

```sh
nimble androidLanTest
```

No router port forwarding is needed when both devices are on the same subnet.
The machine firewall must allow phone-to-host TCP. On NixOS, add these ports to
the active system configuration and rebuild:

```nix
networking.firewall.allowedTCPPorts = [ 48371 49371 ];
```

`48371` is the interactive messenger port. `49371` is isolated for the
instrumented physical-device test. The test first proves host-to-phone traffic,
then phone-to-host traffic, and fails with a firewall-specific message if only
the return path is blocked.
