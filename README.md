# Bifrost Exchange Protocols

Nim protocol library for transport, BFX2, DAC, AME, and FOMKE.

## Installation

Clone, then init the submodules **one level deep**. Bifrost's pragma
definitions, crypto, error correction, and SIMD tables all live in other
repositories, pinned here as submodules. A plain `git clone` on its own
leaves `submodules/` empty and every source file then fails with
`cannot open file: runePragmas`.

**NixOS**

```text
git clone https://github.com/siriuslee69/Bifrost-ExchangeProtocols.git
cd Bifrost-ExchangeProtocols
git submodule update --init
nix-shell            # brings nim, gcc, libsodium, openssl
nimble test
```

**Windows 11**

```text
git clone https://github.com/siriuslee69/Bifrost-ExchangeProtocols.git
cd Bifrost-ExchangeProtocols
git submodule update --init
nimble test
```

**Why one level and not `--recursive`.** One level is all Bifrost needs, and
it is far cheaper. Recursing pulls the vendored C sources its dependencies
carry -- libsodium, liboqs, openssl, PQClean, lz4, zstd:

```text
git submodule update --init      6 repositories, ~157 MB
git clone --recursive            plus their vendored C sources, ~4.6 GB
```

Both work, and both pass the full suite, 96 suites and 525 checks, with no
sibling checkouts anywhere present. Take `--recursive` only when you actually
intend to build the native crypto libraries from source.

Windows needs Nim 1.6+ with a working `gcc` on `PATH` (the Nim installer's
MinGW is enough). `nimble testTls` additionally needs OpenSSL development
libraries; without them that one task stops with a message saying so, and
every other task still runs.

Already cloned without the submodules? Fix it in place with the same command:

```text
git submodule update --init
```

**The desktop client only.** `nimble desktop` needs one extra package that the
library itself does not:

```text
nimble install webui
```

**Where configuration lives.**

```text
config.toml                <- shipped defaults
userconfig.toml.template   <- copy to userconfig.toml for local overrides
```

Leave `config.toml` alone unless you are changing a protocol default. Local
and per-machine changes belong in `userconfig.toml`, which is gitignored.

Neither file is read on its own — nothing in the library loads a config at
startup. A program says which files it wants and in what order. Because
`parseBifrostConfigText` takes a starting config, the second file overrides
only the keys it mentions:

```nim
var cfg = loadBifrostConfigFile("config.toml")     # shipped defaults
if fileExists("userconfig.toml"):
  cfg = parseBifrostConfigText(readFile("userconfig.toml"), cfg)
applyBifrostConfig(cfg)                            # now the library uses it
```

Both entry points validate before returning: an out-of-range value or an
unknown key raises rather than being silently clamped or ignored. So a typo in
`userconfig.toml` stops the program at startup instead of quietly leaving a
protocol limit at its default.

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
+---------------- DAC delivery -----------------+
| manifest -> chunks -> parity -> repair       |
| -> digest check -> commit receipt             |
+----------------------------------------------+
```

AME owns both the crypto toolkit and the live session (epochs, triggers,
handshake, TCP/DAC carriers, replay). **DAC frames nothing itself** — it
decides parameters and AME carries the words.

### Which one is on the outside? ⌜guide⌟

This is the thing people get backwards, so it is worth stating twice, because
the answer is **different for a live frame and for a stored package**.

**A live frame — AME is outermost. There is no DAC header.**

```text
+------------------------------ one AME frame --------------------------------+
| AME header 26 B (session, lane, sequence, kind, class)                      |
|   in the clear, because a receiver must read it before it can pick keys;    |
|   every byte of it still goes into the tag below                            |
|  +-------------------- FOMKE envelope 13 B ---------------------------------+|
|  | epoch | index | lane | tag | ciphertext                                 ||
|  |   opened once -> app bytes. There is no second layer either side.        ||
|  +--------------------------------------------------------------------------+|
+-----------------------------------------------------------------------------+
```

A DAC message rides *inside* that ciphertext, its kind as the first byte:

```text
AME frame, kind = 0x0B DacControl        <- ampkDacControl
  -> sealed payload -> [ DacKind u8 | DAC body ]
```

So the kind is recovered only after the tag checks out. There is no
unauthenticated DAC framing and no way for a stranger to present a kind.

**A stored package — DAC is outermost, wrapping something AME already sealed.**

```text
plaintext
   |  AME seals it ONCE
   v
[ "ASP" | ver | epoch | nonce | tag | ciphertext ]      one sealed blob
   |  DAC cuts it up and adds parity
   v
[chunk][chunk][chunk][chunk]  +  [parity shards]        DAC framing, outside
```

Encrypt → authenticate → **then** add repair data. That ordering is the point:
a relay holding no key can rebuild a lost chunk from parity, and the one tag
over the whole blob is checked at the end, by the endpoint, on bytes that have
already been put back together.

Two axes, to keep the two apart:

```text
OWNERSHIP (API)
  app  ->  AmeSession  ->  FOMKE ratchet  ->  DAC / TCP stream

WIRE, live frame (outer to inner)
  [stream length prefix 4, TCP only]
    -> AME header 26
      -> FOMKE envelope 13 + tag + ciphertext
        -> app bytes, or [DacKind u8 | DAC body]

WIRE, stored package (outer to inner)
  DAC chunk + parity
    -> ASP envelope 15 + nonce + tag + ciphertext
      -> app bytes
```

Which layer does what:

| | decides | carries |
|---|---|---|
| **AME** | which algorithms, the identity, the AAD | yes — it is the envelope |
| **FOMKE** | the key for this one message | its 13-byte position marker |
| **DAC** | chunking, parity, ACK pacing, repair timing, path | no, for frames; yes, for packages |

See [Wire Formats: Low-Level View](#wire-formats-low-level-view) for exact bytes.

### The nine words DAC can say ୨୧

DAC never invents bytes on the wire. It has a **vocabulary** — nine words —
and AME is what speaks them. Here is the whole list, which is also the whole
of `DacMessageKind`:

| byte | word | who says it | what it means |
|---|---|---|---|
| `0x00` | Unknown | nobody | a first byte no word claims; the message is dropped |
| `0x01` | PathStats | receiver | "here is what I measured about this path" |
| `0x02` | PackageManifest | sender | "a package is coming: this many pieces, this big, this digest" |
| `0x03` | PackageChunk | sender | one piece of it |
| `0x04` | ParityShard | sender | spare maths, so a lost piece can be rebuilt without asking |
| `0x05` | AckRange | receiver | "these pieces arrived" |
| `0x06` | RepairHint | receiver | "these pieces did not; send them again" |
| `0x07` | RepairChunk | sender | a piece, sent again |
| `0x08` | PackageCommit | receiver | "it is all here and the digest matches" |

Eight real words and one non-word. **Every one of the eight has a branch in
`feedDacMessage`** — there is no list to cross-check and no kind that arrives
and is quietly ignored. If it is in the enum, the loop acts on it.

> There used to be four more: a path probe, a path-switch request and its ack,
> and a realtime pose packet. All four had encoders, decoders and fuzz tests,
> and none of them had a branch in the loop. See `src/protocols/dac/README.md`,
> *Four words DAC used to have*, for why each one went and what covers it now.

### How one word gets from DAC to the wire and back ❮💕❯

This is the seam. Four files, and each one does exactly one thing:

```text
  SENDING                                        module
  ------------------------------------------     ---------------------------
  1. the loop decides what to say                dac/level3/link.nim
       "ack, and here is the receipt body"
       -> DacTaggedMessage(kind, body)
                    |
  2. the relay finds this peer's session         ame/level3/dac_relay.nim
       one address -> one slot -> one session
                    |
  3. the seal puts the kind in FRONT of the      ame/level2/framing.nim
     body and encrypts the pair                    sealAmeDacControl()
       [ kind u8 | body ]  ->  AME frame
                    |
  4. the socket sends it                         ame/level3/dac_endpoint.nim


  RECEIVING                                      module
  ------------------------------------------     ---------------------------
  1. a datagram arrives from some address        ame/level3/dac_endpoint.nim
                    |
  2. no session for that address? DROPPED        ame/level3/dac_relay.nim
       nothing is parsed, nothing is allocated
                    |
  3. the tag is checked, the frame opened,       ame/level2/framing.nim
     and ONLY THEN is the kind read                openAmeDacControl()
       AME frame -> [ kind u8 | body ]
                    |
  4. the loop acts on a kind it can trust        dac/level3/link.nim
       feedDacMessage(link, kind, body)
```

Read step 3 twice, because it is the whole security argument:

```text
  the kind is INSIDE the encryption, not in a header

    an observer  cannot tell an ACK from a repair hint, because the byte
                 that says which one is encrypted with everything else
    a stranger   cannot present a kind at all, because a frame that does
                 not authenticate never reaches step 4
    a peer       cannot rewrite one, because the tag covers it
```

### What DAC is allowed to change, and what it is not ⟡

DAC sets AME's parameters. It does this by choosing a **lane**, and the lane
is a row of numbers:

```text
  a peer's PathStats arrives
        |
  recommendDacPathFromStats()   one step, never a jump
        |
  a new DacPathLane  ->  dacDefaultsFor()  ->  chunk size, parity width,
                                               ACK batch, ACK deadline,
                                               repair wait, repair rounds
```

Every one of those is about **how bytes are cut up and paced**. Not one of
them touches a key, an algorithm, a tag length or a padding policy. That wall
is deliberate and there is a test that fails if it is ever crossed: link
conditions must never be able to talk this side into weaker protection.

```text
  DAC may say            "send smaller pieces, send more parity, answer sooner"
  DAC may NEVER say      "use a weaker cipher, a shorter tag, no padding"
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

### Four ways to decide whom to believe ꒰ঌ ໒꒱

The picture above shows AM1A, where an authority vouches for both sides. There
are four modes in total. **The four messages carry the same fields in all
of them.** Two things change between modes: the contents of the two sealed
blocks, and, in the pre-shared modes, the client hello's KEM public keys,
which are sealed too.

**Def. 3 — authentication mode.** The single choice of what a peer must show
before this side will believe it. It is made once, by building one
`AmeAuthentication`, and every step of the handshake reads that same object.

The names follow one pattern: **AM1** + the letter of what is provisioned.

| | What you provision | What travels sealed | Hello keys | Needs a PKI |
|---|---|---|---|---|
| **AM1A** | an **A**uthority's public keys | certificate + one signature per slot | clear | yes |
| **AM1S** | the peer's own **S**ignature key | identity + one signature per slot | clear | no |
| **AM1P** | a **P**re-shared secret | a name + one tag under that secret | **sealed** | no |
| **AM1P+S** | both of the last two | name + tag, **then** identity + signatures | **sealed** | no |

```nim
# AM1A -- an authority vouches for the peer
var auth = initAmeCertificateAuthentication(root)

# AM1S -- you were handed the peer's public key in advance
var auth = initAmePinnedAuthentication(pinnedPeerIdentity(theirKey))

# AM1P -- you were handed a shared secret in advance
var auth = initAmePskAuthentication("site-a", secretBytes)

# AM1P+S -- a shared secret AND the peer's public key
var auth = initAmePskPinnedAuthentication("site-a", secretBytes,
  pinnedPeerIdentity(theirKey))
```

That one object then goes to every call, and nothing else has to be told which
mode is running:

```nim
var hello  = beginAmeHandshake(sessionId, layout, tier, a = auth)
var server = answerAmeHandshake(hello.hello, supportedPaths, auth, cert, key)
var client = finishAmeHandshake(hello, server.state.serverHello, auth, cert,
  key, nowUnix)
var done   = acceptAmeHandshake(server.state, client.finish, nowUnix)
```

`acceptAmeHandshake` takes no `auth`: it uses the one `answerAmeHandshake`
settled on, which it stored in `server.state`. That keeps the two halves of the
responder from ever running with different secrets.

`cert` and `key` are the certificate and signing key this side proves itself
with. **AM1P uses neither.** A device provisioned with a shared secret holds no
signing key at all, so both are left out:

```nim
var server = answerAmeHandshake(hello.hello, supportedPaths, auth)
var client = finishAmeHandshake(hello, server.state.serverHello, auth)
var done   = acceptAmeHandshake(server.state, client.finish)
```

#### Which mode protects against what

No single mode is best everywhere. The honest ranking depends on what you are
afraid of:

```text
mode     proof                          someone who STEALS it can ...
-------  -----------------------------  -----------------------------------
AM1A     "an authority vouched for me"  whatever the authority will sign
AM1S     "I own this pinned key"        pretend to be that one side
AM1P     "I know the shared secret"     pretend to be EITHER side
AM1P+S   both of the above              needs to steal BOTH

against a quantum computer:  AM1P  >  AM1S (post-quantum sigs)  >  AM1A
against a stolen device:     AM1S  >  AM1A  >  AM1P
for first contact:           AM1A  (the others need earlier setup)
```

**Def. 3a — AM1P+S.** Both proofs are required, and neither can stand in for
the other:

```text
shared secret stolen, signing key safe   -> still secure
signatures broken, shared secret safe    -> still secure
both lost                                -> broken
```

It costs one signature and one verification per side, once per handshake.
Rotations inside an AM1P+S session are signed, like in AM1S.

**Def. 3b — the sealed hello (AM1P, AM1P+S).** In the pre-shared modes the
KEM public keys never travel in the clear. They are sealed under a key taken
from the shared secret and a fresh random salt:

```text
key  = GB3HKDF( psk ‖ next secret?,  salt = 32 random bytes,
                info = "AME-AM1P-HELLO-v1" + name + every clear hello field )
seal = the session's own tier AEAD: every switched-on cipher, every
       switched-on MAC -- the same masks every later message uses
```

The fresh salt matters. The shared secret is the same for every hello, so
without it two hellos would be sealed with one keystream, and XORing the two
would reveal both. The seal's tag covers every clear field, including the mode
byte and the salt. A responder holding a different secret cannot even open
the hello, and refuses it before doing any KEM work:

```text
-> "client hello did not open under the shared secret"
```

#### What AM1P actually proves ʚ♡ɞ

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
talking; it puts nothing into the keys. So AM1P also derives one *binder* from
the secret and drops it into the key schedule beside the KEM results:

```text
AM1A / AM1S   :  keys <- [ KEM slot 0 | KEM slot 1 | ... ]
AM1P / AM1P+S :  keys <- [ KEM slot 0 | KEM slot 1 | ... | binder ]
```

Read the second row carefully. Someone who breaks **every** KEM slot still
cannot open an AM1P sealed block, because they are missing the last input. A
provisioned secret that only authenticated would not buy that.

The provisioned secret itself never enters the derivation — only the binder
computed from it — so a key block recovered later says nothing about a secret
that gets reused across many sessions.

#### The next secret: carrying one session into the next ⟡

**Def. 3c — next secret (NS).** 32 bytes the key schedule sets aside in every
epoch and never uses for a message (see [FOMKE](#fomke)). When a session ends,
both sides can keep a value derived from it. The next AM1P handshake with the
same peer can then take it as a second key, next to the shared secret:

```nim
# session 1 is running
var kept = ameNextHandshakeSecret(session)        # 32 bytes, same on both ends

# later, session 2
var auth = initAmePskAuthentication("site-a", secretBytes).withAmeNextSecret(kept)
```

With it, the hello seal, both proofs and the binder all take
`psk ‖ next secret` as their key. **A stolen shared secret alone no longer
opens the next hello.**

Both sides have to agree whether it was used. The hello carries a one-byte
flag for exactly that, in the clear and under the seal's tag. The responder
decides what it accepts:

```text
hello flag   responder holds   required   outcome
----------   ---------------   --------   -------------------------------------
set          yes               any        use it
set          no                any        refuse: nothing to match it with
clear        any               yes        refuse: no silent fallback
clear        yes               no         psk only -- and the flag SAYS so
clear        no                no         psk only
```

`withAmeNextSecret(kept, required = true)` is the setting that stops an
attacker from quietly pushing both sides back to psk-only by breaking one
handshake on purpose. Leave it off only while a peer may have lost its copy,
for example after a restore from backup.

#### Rotating an epoch without signature keys

Every so often a session throws its keys away and agrees new ones. The offer
and the reply that do this each have to be proved by whoever sent them, and
AM1P has no signing key to prove them with. It uses a tag instead, under a key
derived from the finished handshake:

```text
AM1A / AM1S / AM1P+S  ->  one signature per active signature slot
AM1P                  ->  one tag under the session's own exchange key
```

Both travel in the same field and cover the same bytes, so nothing downstream
has to know which one it is looking at. The exchange key is derived per
session and is never the provisioned secret.

#### What a mode mismatch does

The hello names the mode it wants, and that byte is covered by the transcript
(and, in the pre-shared modes, by the seal's tag). A responder running one mode
**refuses** a hello asking for another, before it does any key work:

```text
client asks for AM1A, responder runs AM1P
  -> "client asked for an authentication mode this side does not run"
```

This is checked rather than mirrored on purpose. A responder that simply
echoed the mode back would be letting the client choose which of its own
checks ran. The same rule is what makes a *downgrade* impossible: each side
decides its mode locally, and never takes "whatever the other one offers".

### What each side can and cannot do

| | Client hello | Server hello | Finish |
|---|---|---|---|
| Who sent it | not stated | sealed | sealed |
| Readable by an observer | AM1A/AM1S: yes. AM1P, AM1P+S: nonce, layout, salt -- the KEM keys are sealed | nonce + KEM answer only | nothing |
| Costs the server real work | no (cookie first) | yes | yes |
| Authenticated | AM1A/AM1S: no, it cannot be. AM1P, AM1P+S: yes, by the seal's tag | yes | yes |

In the certificate and pinned modes the client hello is unauthenticated. There is nothing to
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
  dacDefaultsFor(dscCleanLan), compressedAmeCompressionPolicy())
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
because each epoch mixes in a fresh transcript salt. Whether it runs a **new
KEM** is a separate question, and that is the one that matters:

```text
  keys change      every rotation, always, from the fresh transcript salt
  KEM runs again   only for the slots in the exchange mask
  stack deepens    only for the slots in the exchange mask
```

**The default re-exchanges everything that was already on.** If the last
exchange had all its algorithm bits set, all of them run again:

```nim
requestAmeTier(session, tierId)              # rekey everything that was on
requestAmeTier(session, tierId, 0)           # rekey nothing already active
requestAmeTier(session, tierId, 0b0100_0000) # rekey exactly slot 1
```

```text
  current kem 1000_0000 -> target kem 1100_0000   default -> mask 1100_0000
      both slots run a KEM; both stacks go one deeper

  current kem 1000_0000 -> target kem 1100_0000   mask 0  -> mask 0100_0000
      only the ADDED slot runs a KEM; slot 0's stack stays where it was

  current kem 1000_0000 -> target kem 1000_0000   mask 0  -> mask 0000_0000
      keys change and nothing else does
```

It used to default the other way, and that was backwards. A rotation with no
new KEM still changes every traffic key, so it **looks** like it did the work —
and it did not: an attacker holding the current KEM secrets keeps reading, and
no stack is deeper than it was. The expensive, honest thing happens when nobody
says otherwise; the cheap thing has to be asked for by name.

Asking for the tier already in force is allowed, and is the ordinary way to
deepen the stack without changing anything else about the connection.

**Triggered rotations do the same.** A rotation that fires because enough bytes
have moved, or enough time has passed, is exactly the moment fresh key material
is wanted — so it re-exchanges the established slots too, not only the slot the
next tier adds.

> 💸 **This costs real bytes, and one KEM family makes it expensive.** An
> exchange carries a public key and a ciphertext per slot. For X25519, Saber,
> Kyber and NTRU that is one or two kilobytes each — nothing. Classic McEliece
> public keys are **hundreds of kilobytes**, so a layout using one re-ships
> that on every rotation under this default. On a metered or thin link, name a
> smaller `rekeyMask`, or `0`, and accept that those slots stop getting deeper.
> The knob is per rotation; nothing is decided for the whole session.

### Every exchange stacks on the one before it ⟡

A KEM slot does not hold the secret it last agreed. It holds **everything it
has ever agreed**, folded together, so each exchange makes the next one harder
to unpick rather than simply replacing what came before.

**Def. — the stack.** What `AmeExchangeState.stackedSecrets[i]` holds for slot
`i`. Not a shared secret; the accumulated image of every shared secret that
slot has produced, with the provisioned secret underneath all of them.

```text
  first exchange   stack = H( binder, slot, algorithm, 1, secret1 )
  rotation         stack = H( H(stack), binder, slot, algorithm, 2, secret2 )
  rotation         stack = H( H(stack), binder, slot, algorithm, 3, secret3 )
```

`H` here is the tier's hash overlay — every switched-on hash slot, XORed
together — so breaking one hash primitive is not enough here either.

**Why it is built that way.** Before, a slot kept only its latest secret and a
rotation threw the old one away:

```text
  epoch 1   key = KDF( ... secret1 ... )
  epoch 2   key = KDF( ... secret2 ... )      secret1 gone, and irrelevant
```

An attacker who recovered `secret2` alone — a KEM broken ten years from now, a
bad random number, a flawed machine — read epoch 2, and every exchange before
it had protected nothing. Now the key hangs off the whole stack, and `secret2`
on its own reaches none of it:

```text
  to read epoch 3 you now need
    secret3   AND   secret2   AND   secret1   AND   the provisioned secret
```

Each rotation adds a term. None of them ever removes one.

**What it costs nothing of.** Forward secrecy is exactly what it was. The old
stack is erased the instant the new one is built, and the new one is a one-way
image of it, so a machine seized today still cannot read yesterday. What
changed is only what an attacker needs in order to read **tomorrow**.

**The provisioned secret finally does something.** In AM1P (and AM1P+S) both sides are
handed a secret out of band. It used to prove who was speaking and then go
nowhere near a traffic key, so a broken KEM took the whole session and the
secret the two sides had gone to the trouble of sharing beforehand did nothing
to stop it. It is now the `binder` in the diagram above — mixed into every
slot's stack, on the first exchange and on every rotation after it:

```nim
## Both sides reach the same binder, and it is not the provisioned secret.
check clientDone.auth.exchangeBinder == serverDone.auth.exchangeBinder
check clientDone.auth.exchangeBinder != secret
```

It is derived from the provisioned secret and the finished transcript, under
its own label — deliberately **not** the same bytes as
`exchangeAuthenticationKey`, which is the MAC key that tags offers and
replies. One secret doing two jobs is how a proof about one of them quietly
stops being a proof about the other.

AM1A and AM1S carry an empty binder. They are trusted through signatures, have
no secret shared beforehand, and inventing one would look like protection while
resting on values both sides already send in the clear.

**Stacking on purpose.** Ask for the tier already in force, as many times as
the traffic is worth. Every KEM slot that tier uses is re-exchanged, and every
one of their stacks goes one deeper:

```text
  for each rotation the server wants:

    requestAmeTier(session, session.auth.current.tier.tierId)
        ^ no mask needed: the default is everything that was already on

    beginAmeSessionExchange   ->  offer   ->  answerAmeSessionExchange
    finishAmeSessionExchange  <-  reply   <-
    confirmAmeSessionExchange <-> epoch-ready

    every slot the tier uses is now one deeper
```

One round trip per rotation. This is a two-party agreement — no side can
deepen the stack alone, because the whole point is that the new term comes
from a KEM both of them ran.

```nim
## What that bought, read back from the session itself.
echo ameSessionStackDepth(session)
```

It reports the **shallowest** slot the tier uses, because an attacker picks
which slot to work on and the defender does not. A tier running a slot six
exchanges deep beside one that has run once is one deep.

Which has a consequence worth knowing before it surprises you: **adding an
algorithm lowers the number.** Rotating onto a tier that brings in a new KEM
slot deepens every slot that was already on, and then puts a brand new slot
beside them at depth one -- so the session reads one. Nothing was lost; there
is simply a shallower place to aim at now. It comes back up by rotating again
on the tier now in force.

> ⚠️ Depth grows only with fresh key material. Passing `rekeyMask = 0` asks
> for the cheap rotation — new traffic keys, no new KEM — and that one deepens
> nothing, because re-hashing a value is something an attacker can do just as
> easily. It is there for callers who know what they are giving up, and it is
> not what you get by default.

## What DAC actually decides ꒰ঌ ໒꒱

DAC is two things wearing one name, and it is worth keeping them apart.

**Def. — the parameter setter.** Given what the link looks like, it says what
to send with. Pure arithmetic; no socket touches it:

```text
  DacPathStats          loss ppm, rtt, jitter, reorder depth,
                        mtu hint, queue ms, credit hint
        |               ZERO MEANS "NOT MEASURED", never "measured zero".
        |               Only loss ppm is exempt. A rule whose input is
        |               missing is skipped, not believed.
        |
  recommendDacPathFromStats     moves ONE step toward a target, never jumps
        |
  DacPathLane           clean · superClean · mobile · thin ·
                        lossy · blockedUdp · recovery
        |
  dacDefaultsFor(scenario)
        |
  DacScenarioDefaults   chunkBytes      how big a payload piece is
                        dataShards      how many pieces per repair group
                        parityShards    how much repair rides along
                        repairMode      none | xor | reedSolomon | tcpExact
                        ackBatchChunks  how many before an answer
                        ackMaxDelayMs   how long before one anyway
                        repairWaitMs    how long before rebuilding
                        repairRounds    how many attempts
```

**Def. — the transport.** The link loop, the chunking, the ACK bookkeeping and
the repair maths that act on those numbers. It has a socket and state.


### The scenario table

Twelve rows, one enum, one table. Several scenarios share a lane on purpose:
bad signal, heavy loss, jitter and an unstable path are all `dplLossyPath` and
want different amounts of parity.

```nim
var d = dacDefaultsFor(dscCleanLan)          # 1200-byte chunks, 32D + 1P
var e = dacDefaultsFor(dscHeavyLoss)         # 512-byte chunks, 12D + 6P
var f = dacDefaultsFor(dscWeakRecovery)      # fixes its own transfer class
```

Notice that heavy loss gets the **small** ACK batch, not the large one: every
un-acknowledged frame is retransmit state the sender cannot free yet. Long
deadlines are for battery radios, where what is being saved is a wake-up
rather than bandwidth.

### How a receiver answers — the five modes ꒰ঌ ໒꒱

`ackMode` is the sixth number in that row and it is not a size, it is a
**habit**. The two levers above say how big a receipt gets and how long it may
wait; the mode says whether a receipt is the right idea at all:

| mode | when it answers | what it is for |
|---|---|---|
| `damSilent` | never | an uplink byte costs more than a wasted parity shard |
| `damNackOnly` | only when something really is missing | a metered link, where silence is the message |
| `damBatch` | on the count or the deadline | the ordinary case |
| `damExplicit` | every single chunk | lowest latency, most receipts |
| `damVerified` | like batch, plus "I have committed N packages" | a barely-working path, where the commit itself may be lost |

The last one earns its keep in one specific way. A `PackageCommit` is one
datagram and it can die like any other; a `damVerified` receiver puts its
running commit count in **every** receipt, so the sender learns the package
landed even when the commit never arrived:

```text
  receiver commits package 1          its count goes 0 -> 1
        |
  every receipt from now on says 1
        |
  sender started this package when the count read 0
        -> the number MOVED -> the peer committed something
        -> with one package in flight, that something is this one
        -> release it
```

Every other mode reports a fixed zero, which a sender reads as *"this peer
does not report commits"* — never as *"this peer has committed nothing"*. That
distinction is the whole guard, and it is why the count is floored rather than
left to mean two things at once.

**One more thing that ends with the package.** The receipt does too, and it
used not to. The ACK window slides over arrivals only and never past a hole --
which is right, because a sequence pushed below the base could never be
reported again -- but the window belongs to ONE package, and the package used
to end without it:

```text
  base                    the package is complete, and yet
   |  X  .  X  X          pending = 2, so the batch is still due
         ^                -> a receipt every ackMaxDelayMs
         the hole that       -> the batch slides nowhere
         parity filled       -> so it happens again, and again
```

Every delivery repaired from parity ends that way, which under loss is most of
them. The link then sent about ten sealed receipts a second, for ever, to a
peer that had usually stopped listening -- and each one made the link look
alive, so its relay slot was never reclaimed.

One last receipt still goes out, for `damVerified` only: that mode carries its
commit count in every receipt, and that count is what a sender learns from
when the commit message itself is lost. The other four modes have just sent a
commit, which says everything a receipt could.

### The top lane is chosen, never discovered ⌜guide⌟

`dplSuperCleanPath` — 32 KB chunks, no repair at all — is **configuration
only**. Nothing measures its way into it, and that is correct rather than a
gap: promotion needs an MTU hint of 4096 or more, and the hint a receiver
reports is the chunk size that actually got through. A sender on the clean
lane sends 1200-byte chunks, so 1200 is all anyone can ever observe. You do
not discover a 32 KB path by only ever sending small pieces down it.

```nim
## Ask for it when you KNOW the two machines share a rack or a switch.
var d = dacDefaultsFor(dscSameRoom)      # dplSuperCleanPath
```

Adaptation can still walk *down* from it the moment the path disagrees.

### One sentence that costs more than it looks ⌜guide⌟

> A zero in a path report means "I did not measure this".

Everything above is arithmetic on numbers a peer sent. If a number nobody
measured reads as a measurement, the arithmetic is exactly as confident as if
it were real — and it will be wrong in whatever direction the unfilled field
happens to point. That is not hypothetical. `creditHint` went unfilled, the
first rule in the chain reads `creditHint <= 32` as "the receiver is out of
buffer", and so **every** report said so:

```text
  a flawless LAN, one package at a time

  clean  ->  mobile  ->  thin  ->  lossy  ->  recovery
     1          2         3         4          and stays there

  chunks 1200 -> 512 bytes, parity none -> six-way Reed-Solomon,
  ACK batch 64 -> 4, and the stated reason is "receiver pressure"
  on a receiver that has not been asked to do anything.
```

The same shape appears twice more in this protocol, so it is worth
recognising: **a number that describes the speaker's own behaviour is not a
measurement of the path.** DAC shuffles its chunks on purpose, which makes
chunk order say what the sender did, not what the wire did — so reorder depth
read off chunk ids is meaningless, and so is a hole in an ACK batch. Both are
handled in `src/protocols/dac/README.md`; both were getting it wrong.

### How AME reaches it ʚ♡ɞ

A session records which path profile it is running over, and hands back the
whole parameter set for it:

```nim
var d = ameSessionPathDefaults(connection)
var plan = planAmeSecurePackage(connection, packageId, payload)
```

The second call is the one to prefer. The older overload takes a
`DacScenarioDefaults` the caller has to keep in step with the session by hand,
and nothing checks that the two agree.

### The line this must not cross ₊˚⊹♡

> Chunk size, repair strength, ACK batching and timeouts follow the link.
> **Which algorithms are on, the tag length, and the padding policy do not.**

Loss is something an attacker on the path can cause at will. If padding
switched off on a "thin" profile, an attacker would induce loss and get
message lengths back — which is the exact thing padding exists to hide. The
same argument rules out stepping down a tier or shortening a tag.

So AME tier transitions fire on elapsed time, transferred MiB, or an explicit
call, and never on measured link conditions. There is a test that says so.

## FOMKE

FOMKE (Forward-Only Message Key Extension) is **the** thing that protects a
payload once the handshake is done. There is no second wrapper around it and
none inside it: a frame is encrypted exactly once.

"Forward-only" means keys can only be derived forward, never backward. After a
key is used, it and everything that could recreate it are erased. Taking
today's state therefore never opens yesterday's messages. ʕ•́ᴥ•̀ʔっ♡

### How The FOMKE Algorithm Works

**Step 1 — one derivation, three pieces.** *Every* shared secret the exchange
produced (the initial shared secret, ISS: one per KEM slot the tier switches
on) goes through **one** GB3HKDF call, together with the epoch number, the
KEM path, the slot layout, the tier, and the handshake transcript. Its 160
bytes of output are cut apart:

```text
every KEM secret (ISS) + transcript + layout + tier
                 │
              GB3HKDF  (one call, 160 bytes out)
                 │
┌──────────────────┬──────────────────┬───────────────────┐
│ LK1   bytes 0..63│ LK2  bytes 64..127│ NS  bytes 128..159│
└──────────────────┴──────────────────┴───────────────────┘
  lane 1 chain key   lane 2 chain key    next secret
```

The secrets and the 160-byte block are erased at once. **There is no root
key.** There used to be one: a 64-byte value derived first, then split
again. It bought nothing (the one call already separates the pieces by
position) and it was one more secret that had to exist for a moment.

Using every slot is the point. A tier that names Kyber *and* X25519 but
derived from one of them would be a hybrid in name only — breaking the single
contributing algorithm would be enough.

**Def. — lane key (LK).** One of the two chain keys. Lane 1 always carries
initiator-to-responder traffic, lane 2 the reverse, so both sides agree
without negotiating.

**Def. — next secret (NS).** 32 bytes that are never used for a message. They
have exactly two jobs:

```text
1. the next KEM rotation:   NS + fresh KEM secrets ──GB3HKDF──▶ LK1' | LK2' | NS'
2. the next handshake:      ameNextHandshakeSecret() = GB3HKDF(NS, "next handshake")
                            ──▶ withAmeNextSecret(...) on both sides
```

NS is a one-way image of the epoch's secret. Someone who steals it cannot
work back to any lane key, so it opens no message. It only matters together
with the NEXT KEM result, which that person does not have.

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
receive index 3 + window  -> gap too large -> rejected (window starts at 16)
```

**Def. — the reorder window.** How far ahead of the next expected position a
message may sit and still be opened. It is the one number that bounds both
costs of arriving out of order:

```text
  window of  4  ->  at most  4 parked keys  ->  about 256 bytes held
  window of 16  ->  at most 16 parked keys  ->  about   1 kilobyte held
  window of 64  ->  at most 64 parked keys  ->  about   4 kilobytes held
```

It bounds a second cost that is easier to miss. A message claiming a position
`N` ahead makes this side derive `N` keys **before** its tag can be checked:

```text
  one forged datagram in
        |
        v
  N key derivations                  <- paid before the tag is looked at
        |
        v
  tag fails, everything thrown away  <- paid for nothing
```

So a wide window is a wide amplifier: one cheap packet in, `N` derivations
out. This is why it is not a fixed setting. It starts at 16 and moves with
what the lane actually sees:

```text
  message sits exactly where expected   -> narrow, after 64 of them
  message sits out of position by N     -> widen to 2N, at once
```

Widening happens on the **copy** of the state that is kept only once the tag
verifies. A forged message is thrown away before its measurement is committed,
so nobody can walk the window up and then aim the full amplifier at this side.
An honest peer on a badly reordering path widens it within a few messages.

The ceiling is fixed when the ratchet is built and the window never grows
past it. It comes from `config.toml` (`fomkeReorderCeiling`, default 64,
allowed 4 .. 4096), so a very lossy or reordering link can be given more room
without a rebuild:

```toml
[fomke]
fomkeReorderCeiling = 64     # keys held per lane for late messages, 32 B each
```

Loss on a datagram link is usually handled below this layer anyway — DAC
rebuilds a missing frame from repair shards, or asks for it again — so the
window rarely needs to be wide.

**Step 7 — epoch upgrade.** An AME tier transition prepares candidate chains
for epoch `n+1` beside the live epoch `n` chains, again with ONE GB3HKDF call:

```text
NS(n) + fresh KEM secrets + the commit ──GB3HKDF──▶
    [ LK1(n+1) | LK2(n+1) | NS(n+1) | confirmation key ]
       64         64         32         32 bytes
```

Mixing the old NS keeps out an attacker who only saw the new exchange; mixing
the new secrets lets a session recover from a past compromise, because the
attacker never saw the new KEM result.

The live lane keys are **not** an input. They were once, and that tied the new
epoch to the exact position each lane had reached. The two sides only agree on
that position once every message in flight has landed. NS is fixed for the
whole epoch, so both sides always hold the same one.

Data is paused; the FKU1 commit must match request id, epochs, target tier,
KEM exchange mask, slot generations, both lane counters, and a confirmation
tag taken with the confirmation key above. Only then do the candidates
(both lanes AND the new NS) atomically replace the live ones, and the tier
changes with them. On any mismatch the candidates are erased and epoch `n`
continues.


### When a message is not late but gone ⌜guide⌟

Steps 5 and 6 above hold on to the keys for messages that were jumped over, so
a datagram that turns up late still opens. The message arriving is what takes
its key back out of the cache.

**Loss is not lateness, and that is the whole difficulty.** A lost datagram is
never re-sent by DAC. DAC re-sends the CHUNK, inside a **new frame at a new
position**, so the key for the old frame waits for something that will never
exist:

```text
  frames 100..130 sealed and sent
        |
        +--> 104 and 117 are lost on the path
        |      their keys are held, waiting
        |
        +--> DAC re-sends those two chunks as frames 131 and 132
               nothing will ever claim 104 or 117 again
```

Left alone, that cache fills with keys for messages that are not coming, and
a session on a 2% path used to stop receiving **permanently** within a few
hundred frames. Three rules now stop it, and all three run on their own:

```text
  too far behind    a held key whose message is further behind than
                    reorderCeiling is erased. Further behind than the widest
                    reordering this lane will ever agree to is not late.

  capped by the     the cache holds at most reorderCeiling keys -- the memory
  ceiling           bound the lane was built with -- not reorderWindow, which
                    moves, and used to shrink below what was already held.

  room is made,     a cache at its ceiling gives up its OLDEST key rather than
  never refused     refusing the message. Giving a key up costs one datagram
                    the carrier re-sends; refusing cost the whole session.
```

The bound that stops a stranger making this side derive without limit is
**untouched**: a message claiming a position further ahead than
`reorderWindow` is still refused before any key is derived.

On top of that, the DAC relay gives up whatever is still held **when a package
ends**. That is the moment it becomes knowable that nothing outstanding can
still be useful, and the relay is the only thing that knows it:

```text
  package completes or fails
        |
        v
  every chunk is either here or given up on
        |
        v
  so anything still held is waiting on nothing -- let it go
```

It matters for a second reason: a rekey refuses to run while any held key is
outstanding, so without this a long-lived lossy session could never rotate its
epoch.

**Asking by hand.** A caller that is not using the DAC relay -- or one that
simply knows a gap is dead -- still has the same door:

```nim
if ameSessionSkippedMessages(connection) > 0:
  var gaveUp = discardAmeSessionSkipped(connection)
  echo "gave up on ", gaveUp, " message(s)"
```

This erases those keys. The messages behind them can never be opened
afterwards, even if the network does eventually deliver them.

**The one refusal that remains.** A burst of losses **wider than
`reorderWindow`** is still refused, and a refusal advances nothing -- so every
message after it sits further ahead still, and that lane cannot recover. This
is the deliberate half: letting a gap that wide through is exactly the
amplifier a forged datagram wants.

It is rarer than it sounds, because bursts that wide are rarer than they
sound. A soak hit it steadily until the SOCKET QUEUE was sized -- the bursts
were the kernel emptying a full receive buffer, not the path losing runs of
datagrams -- and then stopped hitting it at all. See "The one socket setting a
server must not leave alone" further down. When it does happen the peer
recovers by building a new session, which is what DTLS does in the same
situation. Narrowing is also floored at the number of keys the lane is
holding, so a lane that has recently seen gaps no longer shrinks its way into
one.

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
## Relaying Through A VPS 🌊

The problem is reachability, not trust. A home NAS has no address the world
can reach; a small rented VPS does. So the VPS forwards:

```text
clients            a small VPS                a home NAS
(many, anywhere)   (weak CPU, public IP)      (strong, no public IP)
     |                    |                        |
     +---- datagram ----->|                        |
                          +---- same datagram ---->|
                          |<--- answer ------------+
     |<--- answer --------+
```

**Def. — the relay.** The VPS process. It holds no key, opens no frame, and
does not know a session id from a sequence number. It moves bytes.

### Why it must not authenticate ⌜guide⌟

Authenticating would mean running the exchange, holding keys, and paying a key
derivation per datagram **on the weakest machine in the picture**. It would
also mean the relay could read everything. Both are the wrong trade.

Cheap filtering that needs no secrets is welcome there — refusing an address
range, refusing an oversized datagram. Anything needing a key belongs on the
NAS.

### How an answer finds its way back

The relay gives each client a **tag**, and uses a different local socket
toward the NAS per tag. The NAS answers to whichever socket it was addressed
from, so the tag comes back with the answer and names the client:

```text
client A --> [ tag 1 ] --> NAS      NAS --> [ tag 1 ] --> client A
client B --> [ tag 2 ] --> NAS      NAS --> [ tag 2 ] --> client B
```

This is exactly what a home router does, and it is why **neither end has to
know the relay is there**. Nothing is added to the datagram, so the bytes the
NAS sees are the bytes the client sent, and the frame the client sealed is the
frame the NAS opens.

A late answer whose slot has already been released is **dropped**, never sent
to whoever holds the tag now. Guessing there would hand one client another
client's bytes, which is the single worst thing a relay can do.

### When the NAS goes away

A home line reboots, changes address, or drops off. While the NAS is silent,
datagrams for it go into a small buffer rather than into a hole:

```text
NAS answering    -> forward straight through, buffer stays empty
NAS silent       -> hold the most recent few, keep listening
buffer full      -> drop the OLDEST and count it
NAS returns      -> drain in order, then carry on
```

The buffer is **overflow protection, not a mailbox**: it covers a reboot, not
an outage. Everything in it is a datagram the real transport can ask for again
— DAC rebuilds a missing frame from repair shards or re-requests it — so
holding more would spend memory to save something already recoverable.

The relay follows the NAS to a new address when it reappears, because
insisting on the configured one means a relay that never recovers.

### The numbers, and why each one is a ceiling

| setting | default | what it bounds |
|---|---:|---|
| `udpForwardMaxClients` | 512 | slots a stranger can make the VPS allocate |
| `udpForwardClientIdleMs` | 120 000 | how long an unused slot holds its tag |
| `udpForwardNasKeepaliveMs` | 20 000 | how often the NAS is poked when quiet |
| `udpForwardNasSilentMs` | 60 000 | silence before the NAS counts as away |
| `udpForwardBufferDatagrams` | 64 | datagrams held for an absent NAS |
| `udpForwardBufferBytes` | 262 144 | and the same limit in bytes |

Anyone who can send a datagram gets a slot, so the table must have a top or a
stranger sending from many addresses grows it until the VPS runs out of
memory. When it is full the **newcomer is refused** — evicting somebody to
make room would let the stranger push out the clients really using the relay.

A nonsensical setting is an error rather than something quietly corrected,
because each one is a bound on memory a stranger can make the process spend.

### No sockets in the module

`src/protocols/relay/udp_forward.nim` is the decision-making half only. It
takes "a datagram arrived from here at this time" and answers "send these
bytes there"; the caller owns the sockets. That is the same split the DAC link
modules use, and it is what makes every rule above testable without a network.

```nim
var
  F: UdpForwarder = initUdpForwarder(initUdpAddress("10.0.0.2", 9000'u16))
  step: UdpForwardStep = fromClient(F, client, datagram, nowMs)
## step.send is what to put on the wire, in order. step.send[i].tag names the
## local socket to send from; step.send[i].peer is where it goes.
```

### The one socket setting a server must not leave alone ⟡

A UDP socket has one queue, and when it is full the kernel throws the next
datagram away silently — no error, no signal, nothing on the wire. The default
is 208 KB on Linux (`net.core.rmem_default`), which is generous for one
conversation and small for a listener carrying dozens of peers:

```nim
# 4 MB of kernel queue for this listener. The kernel may give less: Linux
# doubles the value for its own bookkeeping and caps it at net.core.rmem_max.
var sock = openDacListener(initDacAddress("0.0.0.0", 9000), 4 * 1024 * 1024)
```

It matters more than the raw loss rate suggests, because a full queue drops
everything until it drains — so the losses arrive in RUNS, and a run is the
one shape of loss the ratchet cannot absorb. Two places count them, and they
are the only two:

```text
  /proc/net/snmp   the RcvbufErrors column, for the whole machine
  /proc/net/udp    the last column, per socket
```

A soak measured this directly: 2,787 kernel drops in seventy-two seconds with
the default, 2 with four megabytes, and a third more work done.

## Layout

Three protocols do the work and the rest are tools they use or things that
happen to live here too:

| Path | Purpose |
|---|---|
| `src/protocols/ame/` | **Who you are talking to, and how a message is wrapped.** Algorithms, epochs, the handshake, framing, the carriers |
| `src/protocols/fomke/` | **A fresh key for every single message.** GB3HKDF, the two directional ratchets, the 13-byte envelope |
| `src/protocols/dac/` | **How bytes are cut up, paced and repaired.** Chunking, parity, receipts, path lanes |
| `src/protocols/relay/` | The blind VPS forwarder: address mapping, NAS keepalive, overflow buffer. Holds no key |
| `src/protocols/chunkyaead/` | Chunked file encryption and tree hashing |
| `src/protocols/transport/` | TCP, UDP, TLS, stream framing, bounded async stream I/O |
| `src/protocols/tls13/` | Pure-Nim TLS 1.3 records, handshake, and client/server sessions |
| `src/protocols/bfx2/` | Tagged binary envelopes |
| `evaluation/tests/` | Unit and protocol tests |
| `evaluation/benchmarks/` | Performance measurements |
| `evaluation/statistics/` | Repository and code statistics |

### The numbered folders ⌜guide⌟

Inside each protocol the folders are numbered, and the number means exactly
one thing: **what a file is allowed to import.**

```text
  types.nim   the shapes. Imports almost nothing.
  level0/     may use types.        the alphabet: read a number, write a number
  level1/     may use level0.       one idea each: one message body, one policy
  level2/     may use level1.       one whole job: a session, a package
  level3/     may use level2.       the loop that runs it all
```

So a file can only ever reach *downward*, and reading a folder in order takes
you from bytes to behaviour. If you want to know what something does, start at
`level3/` and read backwards; if you want to know how it is built, start at
`level0/` and read forwards.

The two files most people are looking for:

```text
  src/protocols/dac/level3/link.nim        the DAC loop -- every decision
  src/protocols/ame/level2/framing.nim     the seam -- every seal and open
```

Each protocol folder has its own `README.md` with a one-line-per-file table.

## Tasks

| Task | Command |
|---|---|
| Build library | `nimble buildLib` |
| Run tests | `nimble test` |
| Run examples | `nimble examples` |
| Run benchmarks | `nimble benchmarks` |
| Soak AME+DAC over real sockets | `nimble soak` |
| Run AVX2 server benchmarks | `nimble benchmarksServerSimd` |
| Test native TLS | `nimble testNativeTls` |
| Test FOMKE | `nimble testFomke` |
| Test CHUNKYAEAD | `nimble testChunkyAead` |
| Test FOMKE AVX2 server profile | `nimble testFomkeServerSimd` |
| Test native TLS against OpenSSL | `nimble testNativeTlsInterop` |
| Check generated files | `nimble releaseHygiene` |
| Remove generated files | `nimble cleanGenerated` |

`nimble soak` is the odd one out and is deliberately not part of `nimble
test`. It starts separate server and client PROCESSES on separate loopback
addresses, gives them real UDP sockets, drops datagrams on purpose and churns
peers, for as long as it is told to:

```sh
nimble soak                                   # two minutes, default shape
nimble soak --seconds=3600 --clients=4        # an hour, four client processes
nimble soak --loss=0 --churn=0 --peers=8      # throughput, nothing induced
```

It ends with `soak: every process finished clean` when no payload arrived
wrong and nothing escaped a loop. A twenty-five minute run verifies about
half a million packages and eleven gigabytes byte for byte.

`docs/soak.md` explains every switch, how to read a report line, and what the
soak has found so far -- four faults that no unit test could have reached, all
fixed, and three design gaps it deliberately did not.

## Wire Formats: Low-Level View

Every magic is **three letters plus one version byte**, so the first four
bytes of any layer read as a name and a number:

```text
DAC   -> chunking, parity, ACK pacing, repair    (dac/level*, no framing)
AME4  -> routing header, then one FOMKE envelope   (ame/level2/wire.nim)
FOMKE -> the message envelope: header, tag, ct     (fomke/level2/wire.nim)
FKU1  -> tier-bound AME/FOMKE upgrade confirmation (fomke/level2/wire.nim)
```

Handshake records travel as ordinary AME frames with a handshake packet kind,
because there are no session keys yet to protect them with:

```text
AMC2  -> client hello   (packet kind 0x0C)
AMR2  -> hello retry    (packet kind 0x0D)  -- the cookie challenge
AMS2  -> server hello   (packet kind 0x0E)
AMF2  -> client finish  (packet kind 0x0F)
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
  [stream 4] -> AME4 header (kind 0x0C..0x0F) -> AMC2/AMR2/AMS2/AMF2

PHASE B -- after the handshake
  [stream 4] -> AME4 header -> FOMKE envelope -> plaintext
```

### Which mask does which job ⌜guide⌟

A tier is six bit masks (KEM, cipher, MAC, hash, signature, KDF). Each one
switches slots on for **one** job and is never borrowed for another:

```text
mask        used for                                    where
----------  ------------------------------------------  -----------------------
KEM         which key exchanges run                     exchange_paths
cipher      the keystreams a payload is XORed through   tier_aead (ameTierCrypt)
MAC         THE tag on the wire -- one per frame        tier_aead (ameTierTag)
hash        transcript hash, secret stack, selection    suites (hashAmeTier)
            hash -- never a tag
signature   identity proofs and signed rotations        suites / handshake
KDF         header keys and storage keys                derivation
```

**There is one tag per frame, not two.** The cipher's authentication and the
"MAC on the wire" are the same thing here. The tag is taken over the
ciphertext AND the AME header (passed in as associated data), so the header
cannot be edited without breaking it:

```text
per-message key block (from ONE GB3HKDF call on the message key):
[ nonce | cipher key, slot 0 | cipher key, slot 1 | MAC key, slot 0 | MAC key, slot 1 ]
          └──────── cipher mask ────────────────┘   └──────── MAC mask ─────────┘

plaintext ─XOR cipher 0─XOR cipher 1─▶ ciphertext
tag = MAC0(input) XOR MAC1(input)     input = layout | tier | AME header | nonce | ciphertext
```

Every cipher slot and every MAC slot has its **own** 32-byte key from its own
position in the block, so no key is ever used by two algorithms. A second,
separate wire MAC would add bytes to every frame and protect nothing the one
tag does not already protect.

Three places use fixed BLAKE3 on purpose, outside the masks: header
protection (both ends must always agree, see above), the anti-flood cookie
(only the server ever checks it), and the AM1P proofs and binder (the shared
secret is the post-quantum anchor, and BLAKE3 is the one primitive every
build carries). Message keys always come from GB3HKDF, never from the KDF
mask.

### TCP/TLS stream frame

```text
offset 0        4
       +--------+------------------+
       | Len32  | Payload          |
       | 4 B    | Len bytes        |
       +--------+------------------+
Total = 4 + Len
```

### DAC message — no frame of its own

DAC had a 27-byte envelope of its own and it is **gone**. Every message it
sends is the body of an AME frame, and its kind is the first byte of that
body:

```text
  +------------- one AME frame -------------+
  | AME header | FOMKE | tag | ciphertext   |
  +------------------------------|----------+
                                 |
                    +------------v-------------+
                    | DacKind u8 | DAC body    |
                    +--------------------------+
```

The kind is recovered only after the tag checks out, so a stranger cannot
present one. Before this, the kind sat in a header nobody had authenticated
and a bare frame from an unknown address could claim a slot in the link table.

What went with the envelope, and why none of it is missed:

| field | why it is gone |
|---|---|
| Magic, Ver | the AME header already names the frame and its version |
| Kind | now the first byte of the sealed body, so it is authenticated |
| Flags | never read by a peer; the loop sets them for its own use |
| Session, Lane, Seq | the AME header carries all three, and binds them |
| Epoch | AME epochs are the only epochs; DAC never had its own |
| BodyLen | the carrier delimits the frame, and the tag covers the length |

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
`0x07` LaneData, `0x0B` DacControl, `0x0C..0x0F` the four handshake records,
`0x10` SessionIdRequest, `0x11` SessionIdAssign.

#### The one masked field: **Seq** at offset 22 ⌜guide⌟

Authenticated is not the same as private, and one field in that header is a
privacy problem on its own. The sequence counts up by one per frame, forever:

```text
watching one link              watching two links
-----------------              -------------------------------------------
how much you sent              "these two flows count up together, so they
when you were idle              are the same conversation"
when you restarted
```

The second column is what matters for a relay. The whole point of forwarding
through one is that traffic going in and traffic coming out should not
obviously be the same traffic, and a counter in the clear on both sides undoes
that by itself. So the four bytes at offset 22 are masked:

```text
offset 0          22        26        39            55
       +----------+---------+---------+-------------+-------------+
       | AME ...  |   Seq   | FOMKE   |  sample     | ciphertext  |
       |          | masked  | 13 B    |  16 B       |             |
       +----------+----|----+---------+------|------+-------------+
                       |                     |
                       |     BLAKE3-MAC(headerKey, sample) -> 4 B
                       |                     |
                       +<------- XOR --------+
```

The mask input is 16 bytes of the **authentication tag**, which is a different
unpredictable value on every frame — so the mask is too. If it were drawn from
the sequence instead, the same counter value would always produce the same
bytes and the counter would be back in the clear one step removed.

Reading it back is the same operation. XOR is its own inverse, and the sample
sits in the part of the frame the mask never touches, so a receiver can take
it before it has unmasked anything. There is no pair of routines to get the
wrong way round.

Three things worth being exact about:

- **This is not a second layer of encryption.** It hides one counter from
  someone *watching*. It buys nothing against someone *editing* — and needs
  to buy nothing, because the real sequence was always covered by the tag. A
  flipped bit here changes the sequence the receiver recovers, that number
  goes into the tag input, and the frame fails to open exactly as before.
- **The header key is per epoch and per direction**, derived once when the
  epoch is built — never per frame. Deriving it runs every switched-on KDF
  slot; masking a frame is one keyed BLAKE3 call over 16 bytes.
- **BLAKE3, not Gimli.** Both ends must produce the same mask or every frame
  fails, and there is no way to negotiate it, so it cannot depend on a
  primitive `-d:bifrostSymmetric=` might have left out of one of the two
  builds. BLAKE3 is the only primitive always compiled.

#### Rotating the session id ⌜guide⌟

With the counter masked, the session id becomes the last field that links a
conversation to itself — eight bytes, identical on every frame. So it rotates,
in three frames:

```text
requester                             responder
---------                             ---------
SessionIdRequest  ------------------>
                                      picks an id nothing else is using
                  <------------------ SessionIdAssign (new id inside)
adopts the new id                     adopts the new id
```

Both frames are sealed under the **old** id, because that is the only id both
sides share while the exchange is in flight. Each side switches only after the
assign frame is safely sealed or safely opened.

There are two session ids and the difference is the whole reason this is
cheap:

| | what it is | rotates? |
|---|---|---|
| `auth.sessionId` | the **cryptographic** identity, mixed into every derived key | never |
| `sessionId` | the **label** written into the header, for routing and demux | yes |

Rotating the label therefore re-derives nothing. Every traffic key, both
header keys, and any sealed package stay exactly as they were. The label is
still authenticated — it is part of the header, and the header is part of the
tag — so nobody can edit it in flight either.

The receiver answers to the previous id as well, for `ameSessionIdGraceFrames`
(100) arriving frames. That window exists for one carrier only:

```text
TCP   order is guaranteed, so every frame after the assign already carries
      the new id and the window never fires
DAC   datagrams reorder, so a frame sealed before the assign can easily
      land after it
```

What the window holds is one integer, not a second set of keys — forgetting it
early costs a dropped datagram the transport re-sends, never a lost secret.

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
  field removed a number an attacker could edit, and left exactly one place
  that decides where the tag ends: the epoch both sides negotiated.

  A frame sealed under the previous epoch has no second chance at a different
  split — it is refused, and the transport sends it again. A sealed *package*
  is the one thing that can outlive its epoch, and it carries its own tag
  length in its own header (`ASP`), so it never depended on this field.

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
AMC2 hello  = "AMC" | ver | session u64 | mode u8 | nonce (32, fixed)
                    | u16+layout | u16+tier | u16+cookie | ... tail
                      tail, AM1A / AM1S:    u32+offer            (clear)
                      tail, AM1P / AM1P+S:  flag u8 | salt (32) | tag (32)
                                            | u32+sealed offer   (sealed)
AMR2 retry  = "AMR" | ver | session u64 | u16+cookie
AMS2 hello  = "AMS" | ver | mode u8 | nonce (32) | u32+KEM reply
                    | tagLen u8 | padding u8 | tag | u32+sealed block
AMF2 finish = "AMF" | ver | tagLen u8 | padding u8 | tag | u32+sealed block
```

`ver` is 2 since the pre-shared hello got its seal. The mode byte reads
`0` AM1A, `1` AM1S, `2` AM1P, `3` AM1P+S, and it alone decides which hello
tail follows. The `flag` byte is `1` when the seal and the key schedule also
took a next secret, `0` otherwise.

Note the names: the three letters are the RECORD (C = client hello, S = server
hello, R = retry, F = finish). They are not the authentication mode —
"AMS2" is the server hello in every mode, AM1S is the pinned-key mode.

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

The **sealed block** in the last two is ciphertext. Opened, it holds up to
two halves, in a fixed order; each mode leaves out the halves it does not
use:

```text
server block                         AM1A/AM1S   AM1P   AM1P+S
  u32+name | u32 count (1) + tag         -        yes     yes
  certificate body                      yes        -      yes
  u32 count + authority proofs          yes        -      yes
  u32 count + signatures                yes        -      yes

client block                         AM1A/AM1S   AM1P   AM1P+S
  u32+name | u32 count (1) + tag         -        yes     yes
  certificate body                      yes        -      yes
  u32 count + authority proofs          yes        -      yes
  u32+transcript hash                   yes       yes     yes
  u32 count + signatures                yes        -      yes
```

All shapes are padded under the same policy, so which mode is running is not
readable from the length of the block either.

The certificate body goes in raw rather than length-framed, because it is the
exact byte string the authority signed. Wrapping it in another length would
mean the bytes that verified and the bytes that were stored were not the same
thing.

Offer and reply sizes grow with the selected KEM public keys and ciphertexts
(FireSaber pk 1312 / ct 1472; X25519 pk 32 / sender pk 32).

## Issue Playbook

- **"client hello did not open under the shared secret"** (AM1P, AM1P+S) means
  the two sides do not hold the same key for the hello seal. Check, in order:
  the same `pskId` and secret bytes on both ends; that both ends agree on the
  next secret (same `kept` bytes, or neither has one). A peer restored from a
  backup has an older next secret -- drop it on both sides with
  `withAmeNextSecret(@[])` and start over from psk-only.
- **"client used a next secret this side does not hold"** means the client
  kept one from an earlier session and the responder did not. Either give the
  responder the same bytes, or have the client drop its copy.
- **"client hello did not carry the required next secret"** means the
  responder was built with `required = true` and the client came without one.
  This is the setting doing its job; it is what stops a forced fallback. Turn
  it off only while you re-establish the next secret on a peer that lost it.
- Handshake records from before the key-schedule rework (`ver` byte 1, the
  old mode names AM1C / AM1M) are refused with "AME handshake wire version
  mismatch". Both ends must run the same build. So are FOMKE checkpoints
  written before the next secret existed ("FOMKE state version mismatch"):
  there is no conversion, rebuild the session with a fresh handshake.
- `fomkeReorderCeiling` outside 4 .. 4096 in `config.toml` refuses the whole
  config at load time. Raise it for links that reorder heavily, not for loss:
  a lost datagram's key is dropped once it falls further behind than the
  ceiling anyway.
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


### Findings the evaluation tools raise that are meant to be there ⌜guide⌟

`otter-gate.sh` reports a few things in this repository every time. They have
been looked at; they are the tool being careful rather than the code being
wrong. Written down so the next person does not chase them twice.

| What it says | Why it is fine |
|---|---|
| PLACEHOLDERS: `raiseExcludedKem` / `raiseExcludedSig` / `raiseExcludedSym` | "The body only refuses to work" is the whole job. These exist so a build without a KEM family refuses a layout naming it, loudly, at the point the layout is built. |
| PLACEHOLDERS: `buildTlsContext` | Only the `when not defined(ssl)` half is flagged. Raising is what a build without TLS should do. |
| PLACEHOLDERS: `defaultDacProbeCount`, `defaultAmeCompressionPolicy`, `initChunkedDecoder`, `initTls13SocketSession` | "Hands back the same answer whatever comes in" is what a default provider and a zero-argument constructor are for. |
| STATE: `AmeSession.lastErr`, `Tls13ClientOutput.connected` | Read by tests under `evaluation/`, which the tool does not scan for reads. Check a field there before believing it is dead — one of these was nearly deleted on the tool's word. |
| STATE: `DacGroupRepairReport.err` | Public API. `repairGroup` is documented as saying *why* it refused, and a consumer reads it even though nothing inside this repository does. |
| DEAD CODE: unused public | Bifrost is a library. Most of its exports exist for a consumer, and the tool can only see callers inside this tree. |
| SECRETS in `evaluation/` and `.android-sdk/` | Test vectors and a vendored NDK. Neither is a key of ours. |
| EMBEDDED CODE | Almost all of it is the vendored Android NDK's own Python. |

Two of these have a real lesson rather than a shrug:

- **Check `evaluation/` before deleting a "never read" field.** The tool does
  not look there, so its list is a list of candidates, not a verdict.
- **`stage: stDone` does not silence a placeholder finding.** It suppresses
  the other stage values only; a routine that legitimately just raises or just
  returns a constant will keep being listed.

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
