# Bifrost Exchange Protocols

Nim protocol library for transport, BFX2, DAC, AME, and FOMKE.

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
- `Slot`: one position in the session's list of algorithms. A `tier` is a set of
  bit patterns saying which slots are switched on right now. Every switched-on
  cipher is applied in turn; every switched-on authenticator contributes to one
  combined tag.

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
  app  ->  AmeSession  ->  FOMKE ratchet  ->  DAC / TCP stream

WIRE (bytes, outer to inner)
  [stream 4 | DAC1 27/29]
    -> AME header 26
      -> FOMKE envelope 13 + tag + ciphertext
        -> app bytes
```

See [Wire Formats: Low-Level View](#wire-formats-low-level-view) for exact bytes.

```text
+----------------------------- DAC1 frame ------------------------------------+
| DAC header (delivery: session, lane, path-epoch, sequence)                  |
|  +-------------------------- AME frame ------------------------------------+|
|  | AME header (session, lane tree, sequence, kind, class)                  ||
|  |   plain to read, but every byte of it goes into the tag below           ||
|  |  +------------------ FOMKE envelope -----------------------------------+||
|  |  | epoch | index | lane | tag | ciphertext                            |||
|  |  |   opened once -> app bytes. There is no second layer either side.   |||
|  |  +---------------------------------------------------------------------+||
|  +-------------------------------------------------------------------------+|
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

## Small Builds

A device that speaks one KEM over one transport should not carry the code for
five other KEMs and a second network stack. Two build flags decide what enters
the binary. Nothing in your source changes between a full build and a slim one.

```text
nim c -d:bifrostKems=kyber,x25519 -d:bifrostCarriers=dac firmware.nim
```

```text
+---------------------------+-------------------------+---------------------+
| flag                      | accepted values         | default (no flag)   |
+---------------------------+-------------------------+---------------------+
| -d:bifrostKems=<list>     | x25519 kyber saber      | all six families    |
|                           | ntru frodo mceliece     |                     |
+---------------------------+-------------------------+---------------------+
| -d:bifrostSigs=<list>     | ed25519 dilithium       | all four families   |
|                           | falcon sphincs          |                     |
+---------------------------+-------------------------+---------------------+
| -d:bifrostSymmetric=      | blake3 sha3 gimli       | all seven           |
|   <list>                  | chacha20 aes poly1305   | primitives          |
|                           | argon2                  |                     |
+---------------------------+-------------------------+---------------------+
| -d:bifrostCarriers=<list> | tcp dac                 | both carriers       |
+---------------------------+-------------------------+---------------------+
```

Two notes on the lists. BLAKE3 is always compiled whatever you write, because
AME normalizes MAC tags and derives Argon2's salt with it. And the symmetric
flag names *primitives*, not slots, because one primitive serves several
families at once — dropping `sha3` removes a MAC slot, two hash slots and a
KDF slot in one move, since they are all the same code.

Hybrid signature slots need two families. `asaEd25519Falcon512Hybrid` exists
only when both `ed25519` and `falcon` are compiled; ask for it otherwise and
the error names exactly what is missing.

What comes out. A program that performs one two-slot AME KEM exchange and
generates its signing keys, built with `-d:release` on x86-64:

```text
  everything ...................................... 747 336 bytes
  + kems=kyber,x25519  carriers=dac ............... 506 432 bytes   (-32%)
  + sigs=ed25519  symmetric=blake3,chacha20 ....... 249 272 bytes   (-67%)
```

The flags do not change the wire. Every slot number keeps its meaning, so a
slim node and a full node still understand each other whenever they share an
algorithm. What changes is what the slim node can run: a slot it lacks is
refused the moment a layout naming it is built or decoded, before any key
material is touched. Naming a missing family as a constant does not even
compile, and the error says which flag to change.

One wire change did happen, once, and not because of a flag: **Ed448 is gone**.
It existed only as a liboqs algorithm, so keeping it would have forced every
AME build to link liboqs. The signature slot ids are renumbered contiguously
(Ed25519 is still 0x01, everything after it moved down by one). AME no longer
depends on liboqs at all.

Verify all three profiles at once:

```text
nimble testMinimalAme
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

The handshake settles two things at once: what keys both sides will use, and
who the other side is. It settles the second one **in private** — an observer
watching every byte never learns who is talking to whom.

```text
Authority
  +-> signs Client certificate   (with its WHOLE algorithm stack)
  +-> signs Server certificate

Client                                              Server
  |--- Hello: nonce, slot layout, KEM public keys ---->|
  |         (no identity here -- there is no key yet)  |
  |                                                    |
  |<-- Retry: "prove you can receive at that address" -|   optional
  |--- the same Hello again, carrying the cookie ----->|
  |                                                    |
  |<-- Server Hello: nonce, KEM answer, [sealed block]-|
  |         the sealed block holds the server's        |
  |         certificate and its proof                  |
  |                                                    |
  |--- Finish: [sealed block] ------------------------>|
  |         the client's certificate, its proof, and   |
  |         a hash of the whole conversation           |
  +================ equal AME epoch ===================+
```

**Def. 1 — sealed block.** Ciphertext under a key both sides work out from the
KEM answer plus everything said so far. It exists from the server hello
onwards. Nothing before it needs to be secret; nothing after it is not.

**Def. 2 — cookie.** A short tag the server computes from the sender's address
using a secret only the server holds. The server keeps no record of issuing
one: when the cookie comes back it simply recomputes the tag. Someone who
cannot receive at the address they claimed never gets a valid cookie, so the
expensive work — key encapsulation, signature checks — only ever runs for a
peer that is really there.

An epoch is returned only after all of this passes: every authority proof (one
per authority slot, not just the first), the certificate serial against the
revocation list, the validity window, the local clock being close enough to
that window to be worth trusting, the peer's own proof over the transcript,
the exact slot layout and initial tier, the KEM exchange, and the final
transcript hash.

### Three ways to decide whom to believe ꒰ঌ ໒꒱

The picture above shows AM1C, where an authority vouches for both sides. There
are three modes in total. **The four messages are identical in all three** —
same fields, same order, same sizes. Only the contents of the two sealed
blocks change, and only because the modes prove different things.

**Def. 3 — authentication mode.** The single choice of what a peer must show
before this side will believe it. It is made once, by building one
`AmeAuthentication`, and every step of the handshake reads that same object.

| | What you provision | What travels sealed | Needs a PKI |
|---|---|---|---|
| **AM1C** | an authority's public keys | certificate + one signature per slot | yes |
| **AM1S** | the peer's own public key | identity + one signature per slot | no |
| **AM1M** | a secret both sides hold | a name + one tag under that secret | no |

```nim
# AM1C -- an authority vouches for the peer
var auth = initAmeCertificateAuthentication(root)

# AM1S -- you were handed the peer's public key in advance
var auth = initAmePinnedAuthentication(pinnedPeerIdentity(theirKey))

# AM1M -- you were handed a shared secret in advance
var auth = initAmePskAuthentication("site-a", secretBytes)
```

That one object then goes to every call, and nothing else has to be told which
mode is running:

```nim
var server = answerAmeHandshake(hello, supportedPaths, auth, cert, key)
var client = finishAmeHandshake(state, serverHello, auth, cert, key, nowUnix)
var done   = acceptAmeHandshake(server.state, finish, auth, nowUnix)
```

`cert` and `key` are the certificate and signing key this side proves itself
with. **AM1M uses neither** — a device provisioned with a shared secret holds
no signing key at all — so both are left out there:

```nim
var server = answerAmeHandshake(hello, supportedPaths, auth)
var client = finishAmeHandshake(state, serverHello, auth)
var done   = acceptAmeHandshake(server.state, finish, auth)
```

#### What AM1M actually proves ʚ♡ɞ

Two separate things come out of the one provisioned secret, and it is worth
keeping them apart.

**1. A proof, so each side knows who the other is.** A tag over the
conversation so far. The two proofs are not interchangeable: a direction byte
sits inside the tagged bytes, so a responder's proof can never be replayed as
an initiator's.

```text
responder proves:  tag( secret, "responder" | name | everything said so far )
initiator proves:  tag( secret, "initiator" | name | hash of the whole exchange )
```

**2. A binder, so the keys depend on the secret too.** This is the part that
matters, and the part it is easy to leave out. The proof alone says who is
talking; it puts nothing into the keys. So AM1M also derives one *binder* from
the secret and drops it into the key schedule beside the KEM results:

```text
AM1C / AM1S :  keys <- [ KEM slot 0 | KEM slot 1 | ... ]
AM1M        :  keys <- [ KEM slot 0 | KEM slot 1 | ... | binder ]
```

Read the second row carefully. Someone who breaks **every** KEM slot still
cannot open an AM1M sealed block, because they are missing the last input. A
provisioned secret that only authenticated would not buy that.

The provisioned secret itself never enters the derivation — only the binder
computed from it — so a key block recovered later says nothing about a secret
that gets reused across many sessions.

#### Rotating an epoch without signature keys

Every so often a session throws its keys away and agrees new ones. The offer
and the reply that do this each have to be proved by whoever sent them, and
AM1M has no signing key to prove them with. It uses a tag instead, under a key
derived from the finished handshake:

```text
AM1C / AM1S  ->  one signature per active signature slot
AM1M         ->  one tag under the session's own exchange key
```

Both travel in the same field and cover the same bytes, so nothing downstream
has to know which one it is looking at. The exchange key is derived per
session and is never the provisioned secret.

#### What a mode mismatch does

The hello names the mode it wants, and that byte is covered by the transcript.
A responder running one mode **refuses** a hello asking for another, before it
does any key work:

```text
client asks for AM1C, responder runs AM1M
  -> "client asked for an authentication mode this side does not run"
```

This is checked rather than mirrored on purpose. A responder that simply
echoed the mode back would be letting the client choose which of its own
checks ran.

### What each side can and cannot do

| | Client hello | Server hello | Finish |
|---|---|---|---|
| Who sent it | not stated | sealed | sealed |
| Readable by an observer | yes | nonce + KEM answer only | nothing |
| Costs the server real work | no (cookie first) | yes | yes |
| Authenticated | no — it cannot be | yes | yes |

The client hello is deliberately unauthenticated. There is nothing to
authenticate it *with* yet, which is exactly why the cookie sits in front of
the work it would otherwise trigger.

### Revocation

A certificate carries a **serial**: a number naming that certificate, not its
holder. Revoking a serial takes one certificate out of use and leaves the
subject free to be issued another. Revoking by name instead would burn the
name forever.

```nim
var cert = issueAmeIdentityCertificate(authority, identity,
  serial = 11'u64, validFromUnix = 100'i64, validUntilUnix = 1000'i64)
var trust = verifyAmeIdentityCertificate(cert, root, nowUnix,
  revokedSerials = [7'u64, 9'u64])
```

### Running it over a socket

```nim
var auth = initAmeCertificateAuthentication(root)
var server = initAmeResponderPolicy(supportedPaths, auth, serverCert, serverKey)
var outcome = ameTcpServerHandshake(sock, server, remoteAddr, nowUnix)
if outcome.ok:
  discard sealAmeTcpFrame(outcome.connection, payload)
```

```nim
var client = initAmeInitiatorPolicy(layout, tier, auth, clientCert, clientKey)
var outcome = ameTcpClientHandshake(sock, client, sessionId = 1'u64,
  nowUnix = nowUnix)
```

The same policy objects drive the datagram carrier. Only the driver changes,
because `AmeResponderPolicy` and `AmeInitiatorPolicy` say what each side will
accept, not which socket carries it:

```nim
var done = ameDacServerHandshake(sock, server, nowUnix)
if done.outcome.ok:
  sendDacFrameBytes(sock, done.remote,
    sealAmeDacFrame(done.outcome.connection, payload))
```

```nim
var outcome = ameDacClientHandshake(sock, peer, client, sessionId = 1'u64,
  nowUnix = nowUnix)
```

The DAC responder returns the address it ended up talking to rather than being
told one: on a datagram socket it learns who its peer is by listening. It also
retransmits nothing -- the initiator owns every timer -- so a responder holds
no per-peer state until a handshake actually completes.

Leave `requireCookie` on for DAC. Nothing proves a source address there, and a
responder without a cookie will do post-quantum key exchanges for packets that
never came from anyone.

`nowUnix` is supplied by the caller on purpose. A library that silently reads
an unset system clock and judges certificates against it is worse than one
that makes the caller say where the time came from.

## Secure Packages

```text
Sender
  plaintext -> optional compression -> AME seal (one tag)
            -> DAC chunks + parity over the SEALED bytes

Receiver
  chunks -> local one-loss recovery -> exact repair fallback
         -> BLAKE3 digest -> AME open -> bounded decode -> plaintext
```

Note the order: seal first, then cut up and add repair data. The repair layer
works on ciphertext and needs no key at all, and the one tag over the whole
package is checked once, at the end, on bytes already put back together.

Compression is **off** by default. Compressing before encrypting leaks: the
ciphertext is as long as the compressed input, so its length says how well the
plaintext compressed — and if an attacker can get their own text placed beside
a secret, a shorter result means the two matched. Ask for it by name, and only
when no part of the payload is attacker-influenced.

Switching compression on switches **padding** on with it, and there is no way
to ask for one without the other. Before encryption the envelope is rounded up
to a whole number of 64 bytes, and the last filler byte says how many filler
bytes there are:

```text
  compressed (5 bytes)             padded to one 64-byte block
  +---+---+---+---+---+            +---+---+---+---+---+-----------+----+
  | h | e | l | l | o |    -->     | h | e | l | l | o | 0 0 ... 0 | 59 |
  +---+---+---+---+---+            +---+---+---+---+---+-----------+----+
                                     \_____ 5 _____/ \____ 59 filler ___/
```

There is always filler — a 64-byte payload becomes 128 — so the last byte can
never be mistaken for real data. Padding blunts the length leak into 64-byte
steps; it does not delete it, and a payload that compresses from 4 KiB to 100
bytes still lands in a different block count than one that does not compress
at all. `paddedAmeCompressionPolicy()` gives padding without compression, for
a stored package whose size alone would say what it is.

```nim
var plan = planAmeSecurePackage(senderAuth, packageId, plaintext,
  cleanLanDacDefaults(), compressedAmeCompressionPolicy())
var incoming = initDacPackageReceiver(plan.package.manifest)

for chunk in plan.package.chunks:
  incoming.acceptDacPackageChunk(chunk)

var restored = finishAmeSecurePackage(receiverAuth, incoming, plan.compression)
```

Applications transmit the manifest, chunks, repair hints, repair chunks, and
commit with their own socket or event loop. Protocol state stays deterministic
and can be tested without a live network.
## AME

AME exchanges exact ordered algorithm paths rather than security tiers.

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

FOMKE (Forward-Only Message Key Extension) is **the** thing that protects a
payload once the handshake is done. There is no second wrapper around it and
none inside it: a frame is encrypted exactly once.

"Forward-only" means keys can only be derived forward, never backward. After a
key is used, it and everything that could recreate it are erased. Taking
today's state therefore never opens yesterday's messages. ʕ•́ᴥ•̀ʔっ♡

### How The FOMKE Algorithm Works

**Step 1 — root.** *Every* shared secret the exchange produced, for every KEM
slot the tier switches on, goes through GB3HKDF together with the epoch
number, the KEM path, the slot layout, the tier, and the handshake transcript.
The result is a 64-byte root; the secrets are erased.

Using every slot is the point. A tier that names Kyber *and* X25519 but
derived from one of them would be a hybrid in name only — breaking the single
contributing algorithm would be enough.

**Step 2 — lane split.** The root becomes two independent 64-byte chain keys,
one per direction, by including the lane number in the derivation. Then the
root itself is erased. Lane 1 always carries initiator-to-responder traffic,
lane 2 the reverse, so both sides agree without negotiating.

**Step 3 — the chain.** Each send advances the sender's outbound lane one
step. One GB3HKDF call turns the current chain key `CK(i)` into the next chain
key plus one 32-byte message key per direction; the sender keeps its own and
erases the other:

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

Every derivation input carries a version label, the lane, the epoch, and the
index, so no two positions in any chain can produce the same bytes.

**Step 4 — one expansion, sliced.** The 32-byte message key is expanded, in a
single GB3HKDF call, into the whole block the slot construction needs:

```text
[ nonce ][ key for cipher slot 0 ][ key for cipher slot 1 ][ mac keys... ]
```

The nonce sits at the front and **never travels**. Both sides derive the same
block from the same ratchet step, so sending it would repeat something the
receiver already holds. Because the message key is used exactly once, the
derived nonce is used exactly once, and a broken random generator cannot cause
nonce reuse.

**Step 5 — seal.** The payload is XORed through every switched-on cipher in
turn, and the tag is the XOR of every switched-on authenticator:

```text
plaintext --XOR slot 0--> --XOR slot 1--> ciphertext
                                             |
                        MAC slot 0 --> tag A +
                        MAC slot 1 --> tag B +--> XOR --> the one tag on wire
```

Undoing the ciphers is the same walk again, because XOR is its own inverse. An
attacker has to break **every** switched-on cipher, not the weakest one, and
forging needs every authenticator at once.

Encrypt first, then authenticate the ciphertext. A receiver therefore checks
the tag before it decrypts anything, and never touches attacker-chosen
plaintext. The tag covers a label, the layout, the tier, the tag length, the
message's epoch/index/lane, the caller's binding bytes (the whole AME header),
and the ciphertext.

This is the same construction the at-rest package sealer uses — one piece of
code, in `ame/level1/tier_aead.nim`, so there is exactly one thing to read and
exactly one to get right.

**Step 6 — open (transactional).** The receiver never mutates live state on a
bad message. It clones the state, advances the clone's inbound lane up to the
received index, verifies the tag, and only then swaps the clone in. A forged
message costs one derivation and changes nothing — it cannot burn ratchet
positions or fill the skipped-key cache.

Out-of-order and replay handling:

```text
receive index 5, chain expects 3
  -> derive keys 3 and 4, park them in the skipped-key cache
  -> derive key 5, open the message

receive index 3 later     -> take key 3 from the cache, open, remove it
receive index 3 again     -> not in cache, not derivable backward -> rejected
receive index 3 + maxSkip -> gap too large -> rejected (default 64, cap 4096)
```

**Step 7 — epoch upgrade.** An AME tier transition prepares candidate chains
for epoch `n+1` beside the live epoch `n` chains. The new root is derived from
**both** the current chain keys and the fresh KEM secrets: mixing the old keys
keeps out an attacker who only saw the new exchange, and mixing the new
secrets lets a session recover from a past compromise, because the attacker
never saw the new KEM result.

Data is paused; the FKU1 commit must match request id, epochs, target tier,
KEM exchange mask, slot generations, both lane counters, and a confirmation
tag derived from the candidate chains. Only then do the candidates atomically
replace the live chains, and the tier changes with them. On any mismatch the
candidates are erased and epoch `n` continues.


### When a message is not late but gone ⌜guide⌟

Steps 5 and 6 above hold on to the keys for messages that were jumped over, so
a datagram that turns up late still opens. Nothing takes those keys back out
of the cache except the message itself arriving. That is fine on a link where
everything eventually arrives, and it is a trap on one where it does not:

```text
  a message is lost for good
        |
        v
  its key stays in the cache forever
        |
        +--> after maxSkip of them, the cache is full
        |      -> the next gap is refused: "skipped-key cache is full"
        |
        +--> and a rekey refuses to run at all while any are outstanding
               -> "skipped messages must be resolved before a KEM upgrade"
```

Both rules are deliberate — a rekey with keys still outstanding would silently
strand them — but together they leave a lossy session with nowhere to go. So
there is one way out, and the caller has to ask for it by name:

```nim
if ameSessionSkippedMessages(connection) > 0:
  var gaveUp = discardAmeSessionSkipped(connection)
  echo "gave up on ", gaveUp, " message(s)"
```

This erases those keys. The messages behind them can never be opened
afterwards, even if the network does eventually deliver them — which is
exactly why nothing calls it for you. Only the caller knows whether a gap
means a slow path or a dead one.

### Preparing ahead, and what it costs ₊˚⊹♡

A sender may prepare a bounded run of future slots off the latency-sensitive
path. This is **off by default**, and the reason is worth stating plainly:

> A filled cache holds the key material for the next N messages in memory.
> Forward secrecy for messages already **sent** is unaffected. But a machine
> seized while the cache is full gives up the next N messages that had not
> gone out yet.

Turn it on when latency matters and the machine cannot be taken; leave it off
otherwise. `fomkePreparedSecretBytes` reports exactly how much secret material
a cache is holding, so the trade is countable rather than guessed at.

```nim
setAmeFomkePregeneration(connection, enabled = true, messageCount = 8)
```

### The Building Blocks

`GB3HKDF` (Gimli BLAKE3 Hash Key Derivation Function) is Bifrost's
domain-separated, XOR-combined Gimli/BLAKE3 KDF. It is not RFC 5869 HKDF. Each
round computes one Gimli sponge branch and one BLAKE3 branch over the same
length-framed input and XORs them, so an attacker must break both hash
constructions to learn the output. It supports configurable rounds (default
3), indexed 32-byte output blocks, multiple ordered secret inputs, and an
optional bounded memory-mixed mode for password-style hardening.

The ciphers and authenticators themselves come from the session's **slot
layout**, not from anything FOMKE chooses. Switching a second cipher on is a
layout decision, and it costs what the benchmark says it costs
(`fomke_seal_1slot` against `fomke_seal_2slot`).

`TMEAEAD` and `GGAEAD` are gone as separate code. They were two fixed AEAD
constructions, and the slot construction generalises both: run every
switched-on cipher over the payload in turn, XOR every switched-on
authenticator into one tag. What they used to be is now two named slot
selections in `ame/level1/presets.nim`:

| Preset | Ciphers | Authenticators |
|---|---|---|
| `tmeAeadAmeLayout` | XChaCha20, AES-CTR, Gimli | Gimli, Poly1305 |
| `ggAeadAmeLayout` | Gimli | Gimli |

`presetAmeTier(L)` switches on everything the preset layout holds. The bytes
are **not** the old formats — keys now come from one derivation over the whole
slot block, each cipher gets its own nonce slice, and the tag is whatever
length the session agreed. Nothing sealed by the old code opens under these,
and nothing should: the old formats are not in the library any more.
## Layout

| Path | Purpose |
|---|---|
| `src/protocols/ame/` | Suite/KEM/protect, AME wire, session, handshake, secure package |
| `src/protocols/fomke/` | GB3HKDF, directional ratchets, upgrade commits, and FOMKE envelope wire |
| `src/protocols/chunkyaead/` | Chunked file encryption and tree hashing |
| `src/protocols/dac/` | Framing, ACK, repair, path control, drift payloads |
| `src/protocols/transport/` | TCP, UDP, TLS, stream framing, bounded async stream I/O and relay helpers |
| `src/protocols/tls13/` | Pure-Nim TLS 1.3 records, handshake, and client/server sessions |
| `src/protocols/bfx2/` | Tagged binary envelopes |
| `evaluation/tests/` | Unit and protocol tests |
| `evaluation/benchmarks/` | Performance measurements |
| `evaluation/statistics/` | Repository and code statistics |

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

Every magic is **three letters plus one version byte**, so the first four
bytes of any layer read as a name and a number:

```text
DAC1  -> transport and repair framing              (dac/level0/framing.nim)
AME4  -> routing header, then one FOMKE envelope   (ame/level2/wire.nim)
FOMKE -> the message envelope: header, tag, ct     (fomke/level2/wire.nim)
FKU1  -> tier-bound AME/FOMKE upgrade confirmation (fomke/level2/wire.nim)
```

Handshake records travel as ordinary AME frames with a handshake packet kind,
because there are no session keys yet to protect them with:

```text
AMC1  -> client hello   (packet kind 0x0C)
AMR1  -> hello retry    (packet kind 0x0D)  -- the cookie challenge
AMS1  -> server hello   (packet kind 0x0E)
AMF1  -> client finish  (packet kind 0x0F)
ASP1  -> secure package, for bytes that sit still somewhere
```

All multi-byte integers below are little-endian. `u8/u16/u32/u64` are unsigned
integers of 1/2/4/8 bytes. Offsets start at 0 for that layer.

### One layer of encryption, not two

**Def. 3 — the frame body.** After the handshake, an AME frame's payload is
one FOMKE envelope. Nothing wraps that envelope and nothing sits inside it but
the application's own bytes. A frame is encrypted exactly once.

```text
PHASE A -- the handshake (no session keys yet)
  [stream 4 | DAC1] -> AME4 header (kind 0x0C..0x0F) -> AMC1/AMR1/AMS1/AMF1

PHASE B -- after the handshake
  [stream 4 | DAC1] -> AME4 header -> FOMKE envelope -> plaintext
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

Optional outermost delivery shell. Stage-blind: it does not know handshake
from live traffic. It adapts body length, chunks, ACK, and repair only.

```text
Base header = 27 B   (BodyLen = u16)
Extended    = 29 B   (BodyLen = u32, flag bit 8)

 0     3   4    5     7        15    19    21    25      27
+-----+---+---+----+---------+-----+-----+-----+-------+------+
|DAC  |Ver|Knd|Flgs| Session |Lane |Epch | Seq |BodyLn | Body |
| 3B  |1B |1B |2B  | 8B      |4B   |2B   |4B   |2or4B  | n    |
+-----+---+---+----+---------+-----+-----+-----+-------+------+
```

### AME Frame — fixed **26 B**

Magic is three bytes, `"AME"`; the version byte after it is **4**.

```text
offset  0     3    4     5      6        14      18     22      26
        +-----+----+-----+------+--------+-------+------+------+---------+
        | AME |Ver | Kind|Cls+Fl| Session|RootLn | Lane | Seq  | Payload |
        | 3B  |u8  | u8  | u8   | u64    |u32    | u32  | u32  | n bytes |
        +-----+----+-----+------+--------+-------+------+------+---------+
Total = 26 + n
```

Two fields that used to sit here are gone, both for the same reason — they
restated something the receiver already had:

- **No payload length.** The decoder required it to equal `frame.len - header`,
  which the caller already knew: a stream carrier delimits the frame with its
  own 4-byte prefix, a datagram carrier is delimited by the datagram. The tag
  still commits to the ciphertext length, which is where that belongs. A frame
  truncated in flight now fails on the tag rather than on a length field —
  the better of the two failures, since the check that catches it is the
  authenticated one.
- **No parent lane id.** It was set equal to the root lane id when a session
  was built and never changed after, so it carried a copy of the field four
  bytes to its left.


Byte 5 carries two fields, because neither needs a whole byte:

```text
bit  7   6   5   4   3   2   1   0
     |   |   |   |   |   +---+---+-- message class (eight values)
     |   |   |   |   +-------------- payload is padded
     +---+---+---+------------------ unused, refused unless zero
```

The header is in the clear — a receiver must read it before it knows which
keys to reach for. It is still **authenticated**: every byte above goes into
the tag over the payload, so a header edited in flight makes the body fail to
open. That covers the flags: clearing the padded bit does not get a receiver
to hand filler up as data, it gets a frame that will not open at all. An
unknown flag bit is refused rather than ignored, so a flag added later can
never be silently dropped by a peer that would not honour it.

Kinds: `0x04` ExchangeKeys, `0x05` ExchangeEnvelopes, `0x06` EpochReady,
`0x07` LaneData, `0x0B` DacControl, `0x0C..0x0F` the four handshake records.

### Padding

Off by default, and a property of the epoch rather than of one message, so
both endpoints hold the same value or the frame is refused. `setAmePadding(S,
apadBlock64)` stages it; it takes effect at the next tier rotation, riding in
the exchange request the way the tag length does. The responder names it for
the first epoch in its server hello.

When it is on, the payload is rounded up to whole 64 bytes before sealing —
same construction as the package path above, filler count in the last byte —
and the padded flag goes in the header. It costs **1 to 64 bytes on every
frame**, which is real money on a link carrying small messages, so it is
switched on when message sizes would say something (which command, who is
typing) rather than by default. `ameFrameOverheadBytes(S)` returns the
worst-case total per frame, for a caller sizing datagrams against an MTU.

### FOMKE Envelope — header **13 B**

```text
offset  0       4            12     13
        +-------+------------+------+--------+------------+
        | Epoch | Index      | Lane | AuthTag| Ciphertext |
        | u32   | u64        | u8   | T bytes| n bytes    |
        +-------+------------+------+--------+------------+
Total = 13 + T + n     (T is 16, 24 or 32; n equals the plaintext length)
```

Thirteen bytes, and every one of them is something the receiver cannot work
out for itself. Four fields a reader might expect are **absent**:

- **No magic and no version.** This envelope only ever travels as the body of
  an AME frame, and that frame's packet kind already says what the body is. A
  second name for the same thing cost four bytes on every message.
- **No nonce.** Both sides derive it from the same ratchet step, so sending it
  would only repeat something the receiver already holds. That is 24 bytes per
  message saved and one fewer field an attacker can influence.
- **No ciphertext length.** It is whatever follows the tag; the frame already
  delimits the envelope.
- **No tag length.** The receiver splits tag from ciphertext using the length
  its own epoch agreed, and would refuse any other value anyway. Removing the
  field removed a number an attacker could edit — and made the retiring-epoch
  case correct rather than lucky, since a frame in flight when the tag length
  changed is now decoded again with the old epoch's length instead of trusting
  a byte the sender wrote.

What the tag covers: a label, the slot layout, the tier, the tag length, the
message's epoch/index/lane, the caller's binding bytes (which include the
whole AME header), and the ciphertext. Encrypt first, then authenticate the
ciphertext — so a receiver checks the tag before it decrypts anything.

### FKU1 Commit (FOMKE upgrade) — fixed **108 B**

Travels inside an authenticated EpochReady frame.

### Size cheat sheet (default tier, 32-byte tag)

| Item | Bytes |
|---|---:|
| Stream header | 4 |
| DAC1 base / ext | 27 / 29 |
| AME header | 26 |
| FOMKE header + tag | 13 + 32 = 45 |
| FKU1 | 108 |
| **TCP data overhead** | **4 + 26 + 45 + P = 75 + P** |
| **DAC data overhead** | **27 + 26 + 45 + P = 98 + P** |

With a 16-byte tag the last two become **59 + P** and **82 + P**.

Where that number came from, in three steps:

| | AME header | envelope + tag | per frame |
|---|---:|---:|---:|
| two nested AEADs | 36 | 12 + 24 + 32, then 27 + 24 + 32 | **187** |
| one AEAD | 34 | 22 + 32 | **88** |
| nothing restated | 26 | 13 + 32 | **71** |

The first step removed a whole layer of encryption. The second removed six
fields that each repeated something the receiver already had — two lengths,
two names, a version and a tag length. Nothing was traded away for either:
every byte dropped was a byte a receiver either ignored or refused.

### Handshake records

```text
AMC1 hello  = "AMC" | ver | session u64 | nonce (32, fixed, no length field)
                    | u16+layout | u16+tier | u16+cookie | u32+offer
AMR1 retry  = "AMR" | ver | session u64 | u16+cookie
AMS1 hello  = "AMS" | ver | nonce (32) | u32+KEM reply
                    | tagLen u8 | padding u8 | tag | u32+sealed block
AMF1 finish = "AMF" | ver | tagLen u8 | padding u8 | tag | u32+sealed block
```

Fixed-size fields carry no length: the nonce is always 32 bytes, so writing
"32" in front of it every time would say nothing. Variable fields use `u16`
where the field is small by construction and `u32` only where a post-quantum
key can genuinely run to megabytes.

Those two bytes after the KEM reply are the first epoch's tunables — tag
length and padding policy. The **responder** picks them; the client adopts
them or gives up. They ride in the clear because the client needs them to open
the block that follows, and they are bound into that block's tag, so editing
one in flight breaks the handshake instead of downgrading it. When padding is
on, the sealed identity blocks are padded too: hiding *who* is connecting
while leaving the size of their certificate on the wire only does half the
job.

The **sealed block** in the last two is ciphertext. Opened, it holds one of
two shapes, decided by the mode byte in the hello. AM1C and AM1S look alike;
AM1M is the short one, because it carries no certificate at all:

```text
AM1C / AM1S
  server: certificate body | u32 count + authority proofs
                           | u32 count + proofs
  client: certificate body | u32 count + authority proofs
                           | u32+transcript hash | u32 count + proofs

AM1M
  server: u32+name | u32 count (always 1) + one tag
  client: u32+name | u32+transcript hash | u32 count (always 1) + one tag
```

Both shapes are padded under the same policy, so which mode is running is not
readable from the length of the block either.

The certificate body goes in raw rather than length-framed, because it is the
exact byte string the authority signed. Wrapping it in another length would
mean the bytes that verified and the bytes that were stored were not the same
thing.

Offer and reply sizes grow with the selected KEM public keys and ciphertexts
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
- **"FOMKE epoch or sender lane mismatch" right after setting up a session**
  almost always means the endpoint role was set *after* `initAmeSession`. The
  session starts its ratchet immediately and reads the role off the auth
  package, so the role has to be right in `initAmeAuthPackage` — assigning
  `auth.endpointRole` afterwards changes nothing about which lane it sends on.
- **"FOMKE KEM upgrade is pending"** when sealing means an upgrade was staged
  before this side finished sending. A responder must call
  `stageAmeSessionFomkeUpgrade` *after* its reply frame has been sealed; the
  carrier entry points already do this in the right order.
- **"FOMKE upgrade confirmation mismatch"** means the two endpoints staged at
  different lane positions. Deliver outstanding messages and empty the
  skipped-key cache before starting a transition.
- **"certificate proof count does not match the pinned root"** means the
  certificate carries fewer proofs than the authority has slots — usually a
  certificate issued by an older, single-algorithm authority. Reissue it.
- **"local clock is too far outside the identity validity window"** means this
  machine's clock is more than a day outside the certificate's window. Fix the
  clock; the library will not guess.
- **"AME handshake step number is wrong"** means a record arrived where a
  different one belonged. Records carry their step in the frame sequence, and
  a mis-ordered handshake is refused before it is parsed.
- Data triggers count successful plaintext transfer bytes, not retry bytes.
- Tier changes and rekeys use authenticated Offer -> Reply -> EpochReady frames.
- AVX2 tasks produce host-specific binaries. Use the ordinary tasks for x86
  clients or servers that may run on CPUs without AVX2.
- Peer trust is supplied by a caller-owned certificate or provisioning verifier.
- Initial authority trust uses `beginAmeHandshake`, `answerAmeHandshake`,
  `finishAmeHandshake`, and `acceptAmeHandshake`; over a socket, use
  `ameTcpClientHandshake` and `ameTcpServerHandshake`, which run the whole
  exchange including the cookie retry.
- Package repair uses XOR recovery for one loss and exact-chunk fallback for
  wider loss; Eir parity verifies recovered groups.
- Native TLS accepts only TLS 1.3, X25519, Ed25519, SHA-256, and
  `TLS_CHACHA20_POLY1305_SHA256`; unsupported suites fail closed.
- Native TLS client trust is pinned-root only. Public operating-system trust
  stores and RSA/ECDSA certificate paths remain unsupported.
- TLS record compression is intentionally absent. Compress HTTP content before
  encryption when the application negotiates a standard content encoding.

The benchmark task keeps its executable under `--out:build/benchmarks/...`.
The default `nimble build` command is not a supported artifact path here; use
`nimble buildLib`.

`nix flake check path:$PWD` validates the package build, reproducible TLS
transport checks, and NixOS module rules.

### Standing risks

- **The primitives are homemade.** GB3HKDF and the XOR-combined multi-MAC tag
  have no external analysis.
  The constructions *around* them are careful — domain separation everywhere,
  encrypt-then-MAC, transcript binding, constant-time comparison on secrets,
  transactional state, secrets wiped — but layering discipline cannot rescue a
  primitive that turns out to be weak. This is the thing to keep front of
  mind, above any specific item above.
- **Metadata is visible by design.** The AME header is authenticated but not
  encrypted: session id, lane ids, sequence and length are readable by anyone
  on the path. Identities are not, but traffic patterns are. Padding
  (`setAmePadding`) blurs the length into 64-byte steps; it does not hide the
  rest of the header, and it does not hide *when* a message was sent.
- **Preparing send slots ahead weakens forward secrecy for messages not yet
  sent.** It is off by default for that reason. See the FOMKE section.
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
