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

**One level, not `--recursive`.** One level is all Bifrost needs. Recursing
also pulls the vendored C sources of the dependencies (libsodium, liboqs,
openssl, PQClean, lz4, zstd):

```text
git submodule update --init      6 repositories, ~157 MB
git clone --recursive            plus their vendored C sources, ~4.6 GB
```

Both pass the full suite with no sibling checkouts present. Take
`--recursive` only to build the native crypto libraries from source.

Windows needs Nim 1.6+ with a working `gcc` on `PATH` (the Nim installer's
MinGW is enough). `nimble testTls` also needs the OpenSSL development
libraries; without them that one task stops with a message, and every other
task still runs.

Cloned without the submodules? The same command repairs it:

```text
git submodule update --init
```

**The desktop client only.** `nimble runWebui` needs one extra package:

```text
nimble install webui
```

**Where configuration lives.**

```text
config.toml                <- shipped defaults
userconfig.toml.template   <- copy to userconfig.toml for local overrides
```

`config.toml` stays unchanged unless a protocol default changes. Local
changes belong in `userconfig.toml`, which is gitignored.

The library reads no config file on its own. The program names the files and
their order. `parseBifrostConfigText` takes a starting config, so the second
file overrides only the keys it names:

```nim
var cfg = loadBifrostConfigFile("config.toml")     # shipped defaults
if fileExists("userconfig.toml"):
  cfg = parseBifrostConfigText(readFile("userconfig.toml"), cfg)
applyBifrostConfig(cfg)                            # now the library uses it
```

Both calls validate before they return. An out-of-range value or an unknown
key raises an error. A typo in `userconfig.toml` therefore stops the program
at startup.

```text
key                          default   free to change?
---------------------------  --------  ------------------------------------------
maxTcpFrameBytes             16 MiB    yes, downward
maxDacFrameBytes             16 MiB    yes, downward
defaultAmeInboxCapacity      64        yes
defaultTimeoutMs             4000      yes
peerTrustRequired            true      keep true on anything reachable
fomkePregeneration           false     see "Preparing ahead"
fomkePregenerationMessages   8         yes (1 .. 4096)
fomkeReorderCeiling          64        yes (4 .. 4096), see FOMKE
ameLayoutHex                 (hex)     only together with every endpoint
ameInitialTierHex            (hex)     only together with every endpoint
```

## Definitions ✦

Every term below keeps exactly this meaning for the whole document. No
synonyms are used. A term used in only one section is defined at the top of
that section, under **Definitions**. An abbreviation carries its definition
in brackets the first two times it is used after that.

**Protocol names**

- `DAC` := Data Adaptive Connection. Delivery: chunks, receipts, repair.
- `AME` := Adaptive Message Encryption. Algorithm slots, handshake, sessions.
- `FOMKE` := Forward-Only Message Key Extension. One fresh key per message.
- `GB3HKDF` := Gimli BLAKE3 Hash Key Derivation Function. Turns secret bytes
  into any number of key bytes.
- `BFX2` := Bifrost Exchange format 2. Tagged binary envelopes.

**Cryptographic terms**

- `KEM` := key encapsulation mechanism. A public-key exchange after which both
  endpoints hold the same secret bytes.
- `KEM exchange` := one run of every switched-on KEM, public keys one way and
  ciphertexts back.
- `KDF` := key derivation function. A one-way function from secret bytes to
  key bytes.
- `MAC` := message authentication code. The ALGORITHM that computes a tag.
- `tag` := the BYTES a MAC outputs. A changed byte in the covered input gives a
  different tag.
- `AEAD` := authenticated encryption with associated data. Encryption plus one
  tag over the ciphertext and over extra unencrypted bytes.
- `AAD` := associated data. The unencrypted bytes an AEAD tag also covers.
- `PSK` := pre-shared key. Secret bytes both endpoints received before the
  first handshake.

**Actions**

- `seal` := encrypt, then compute the tag over the ciphertext and the AAD.
- `open` := check the tag first; decrypt only if it matches.
- `unencrypted` := readable by anyone who sees the bytes. The opposite of
  sealed.
- `erase` := overwrite secret bytes in memory, then release them.
- `refuse` := stop with an error message; nothing changes.
- `discard` := throw bytes away with no error message.

**Roles and units**

- `endpoint` := one of the two programs in a conversation.
- `initiator` := the endpoint that sends the first handshake record.
- `responder` := the other endpoint.
- `frame` := one AME unit on the wire: header plus sealed body.
- `datagram` := one UDP packet.
- `message` := one payload a caller hands to FOMKE for one frame.
- `package` := a sealed blob meant to be stored or relayed, cut into chunks
  by DAC.
- `chunk` := one piece of a package.

**Session terms**

- `session` := the state two endpoints share after one handshake.
- `epoch` := one numbered key generation inside a session. Epoch 1 starts at
  the handshake.
- `rotation` := the switch from epoch n to epoch n+1.
- `lane` := one direction of traffic. Lane 1: initiator to responder. Lane 2:
  responder to initiator.
- `slot` := one position in a session's algorithm list.
- `layout` := the fixed, ordered algorithm list of a session: up to eight
  slots per family (KEM, cipher, MAC, hash, signature, KDF).
- `mask` := one byte per family; bit i set means slot i is switched on.
- `tier` := one mask per family, plus a tier id.

Example 1. A layout with ciphers `[XChaCha20, Gimli, AES-CTR]` and a cipher
mask `1100_0000` switches on XChaCha20 (slot 0) and Gimli (slot 1). AES-CTR
(slot 2) stays switched off.

## Read This First 🌊

**Definitions**

- `carrier` := the transport under AME: TCP (a byte stream) or DAC
  (datagrams).
- `DAC kind` := the first byte of a DAC word. It says which of nine DAC words
  follows.

```text
+---------------- Application ----------------+
| plaintext file, message, archive, or record  |
+----------------------|-----------------------+
                       v
+---------------- AME security ----------------+
| trust -> layout + tier -> epoch              |
| -> optional compression -> seal / open       |
| -> FOMKE per-message keys                    |
+----------------------|-----------------------+
                       v
+---------------- DAC delivery -----------------+
| manifest -> chunks -> parity -> repair        |
| -> digest check -> commit receipt             |
+----------------------------------------------+
```

AME (Adaptive Message Encryption) owns the crypto toolkit and the live
session (epochs (numbered key generations), triggers, handshake, carriers,
replay). **DAC (Data Adaptive
Connection) writes no frame of its own.** It decides parameters, and AME
carries its words.

### Which one is on the outside? ⌜guide⌟

The answer differs between a live frame and a stored package.

**A live frame: AME is outermost. There is no DAC header.**

```text
+------------------------------ one AME frame --------------------------------+
| AME header 26 B (session, lane, sequence, kind, class)                      |
|   unencrypted: a receiver must read it to pick its keys.                    |
|   every byte of it is covered by the tag below (it is the AAD)              |
|  +-------------------- FOMKE envelope 13 B ---------------------------------+|
|  | epoch | index | lane | tag | ciphertext                                 ||
|  |   opened once -> application bytes. There is no second layer.           ||
|  +--------------------------------------------------------------------------+|
+-----------------------------------------------------------------------------+
```

A DAC word travels INSIDE that ciphertext. Its DAC kind is the first byte:

```text
AME frame, kind = 0x0B DacControl        <- ampkDacControl
  -> sealed body -> [ DAC kind u8 | DAC body ]
```

The DAC kind is readable only after the tag matched. There is no unencrypted
DAC header, and an endpoint without the key cannot present a DAC kind.

**A stored package: DAC is outermost, around bytes AME already sealed.**

```text
plaintext
   |  AME seals it ONCE
   v
[ "ASP" | ver | epoch | nonce | tag | ciphertext ]      one sealed blob
   |  DAC cuts it into chunks and adds parity
   v
[chunk][chunk][chunk][chunk]  +  [parity shards]        DAC, outside
```

Seal, then add repair data. A relay without any key can rebuild a lost chunk
from parity. The one tag over the whole blob is checked at the end, by the
receiving endpoint, on the rebuilt bytes.

```text
OWNERSHIP (API)
  app  ->  AmeSession  ->  FOMKE  ->  DAC / TCP carrier

WIRE, live frame (outer to inner)
  [stream length prefix 4, TCP only]
    -> AME header 26
      -> FOMKE envelope 13 + tag + ciphertext
        -> application bytes, or [DAC kind u8 | DAC body]

WIRE, stored package (outer to inner)
  DAC chunk + parity
    -> ASP envelope 15 + nonce + tag + ciphertext
      -> application bytes
```

| | decides | writes bytes on the wire |
|---|---|---|
| **AME** | algorithms, identity, AAD (associated data) | yes, the frame |
| **FOMKE** | the key for one message | its 13-byte envelope header |
| **DAC** | chunk size, parity, receipt pacing, repair timing, path lane | no for frames; yes for packages |

See [Wire Formats: Low-Level View](#wire-formats-low-level-view) for exact bytes.

### The nine DAC words ୨୧

DAC writes no bytes itself. It has nine words, and AME carries them. The list
is the whole of `DacMessageKind`:

| byte | word | sent by | meaning |
|---|---|---|---|
| `0x00` | Unknown | nobody | a first byte no word claims; the frame is discarded |
| `0x01` | PathStats | receiver | "this is what I measured about the path" |
| `0x02` | PackageManifest | sender | "a package follows: this many chunks, this size, this digest" |
| `0x03` | PackageChunk | sender | one chunk |
| `0x04` | ParityShard | sender | repair data; rebuilds a lost chunk without a request |
| `0x05` | AckRange | receiver | "these chunks arrived" |
| `0x06` | RepairHint | receiver | "these chunks did not arrive; send them again" |
| `0x07` | RepairChunk | sender | one chunk, sent again |
| `0x08` | PackageCommit | receiver | "everything arrived and the digest matches" |

Each of the eight real words has a branch in `feedDacMessage`. No DAC kind
arrives and is ignored.

> Four more words existed: a path probe, a path-switch request and its ack,
> and a realtime pose packet. None had a branch in the loop. See
> `src/protocols/dac/README.md`, *Four words DAC used to have*.

### How one DAC word reaches the wire and comes back ❮💕❯

```text
  SENDING                                        module
  ------------------------------------------     ---------------------------
  1. the loop decides what to say                dac/level3/link.nim
       -> DacTaggedMessage(kind, body)
                    |
  2. the relay finds this endpoint's session     ame/level3/dac_relay.nim
       one address -> one slot -> one session
                    |
  3. the DAC kind goes in FRONT of the body,     ame/level2/framing.nim
     and the pair is sealed                        sealAmeDacControl()
       [ kind u8 | body ]  ->  AME frame
                    |
  4. the socket sends it                         ame/level3/dac_endpoint.nim


  RECEIVING                                      module
  ------------------------------------------     ---------------------------
  1. a datagram arrives from an address          ame/level3/dac_endpoint.nim
                    |
  2. no session for that address: discard        ame/level3/dac_relay.nim
       nothing is parsed, nothing is allocated
                    |
  3. the frame is opened, and ONLY THEN is the   ame/level2/framing.nim
     DAC kind read                                 openAmeDacControl()
       AME frame -> [ kind u8 | body ]
                    |
  4. the loop acts on a DAC kind it can trust    dac/level3/link.nim
       feedDacMessage(link, kind, body)
```

Step 3 is the security argument:

```text
  the DAC kind is INSIDE the ciphertext, not in a header

    an observer   cannot tell a receipt from a repair hint: the byte that
                  says which one is sealed with everything else
    an outsider   cannot present a DAC kind: a frame whose tag fails never
                  reaches step 4
    an endpoint   cannot rewrite one: the tag covers it
```

### What DAC may change, and what it may not ⟡

**Definitions**

- `path lane` := one row of DAC transport numbers (chunk size, parity width,
  receipt batch, receipt deadline, repair wait, repair rounds). Not the same
  thing as a traffic lane (lane 1 / lane 2).

```text
  a PathStats word arrives
        |
  recommendDacPathFromStats()   one step, never a jump
        |
  a new DacPathLane  ->  dacDefaultsFor()  ->  chunk size, parity width,
                                               receipt batch, receipt deadline,
                                               repair wait, repair rounds
```

Every number in a path lane is about **how bytes are cut and paced**. None
touches a key, an algorithm, a tag length or the padding policy. A test fails
if that line is ever crossed: link conditions must never lower protection.

```text
  DAC may say       "send smaller chunks, send more parity, answer sooner"
  DAC may NEVER say "use a weaker cipher, a shorter tag, no padding"
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

Run the examples and the tests:

```text
nimble exampleAmeExactPath
nimble exampleSecurePackage
nimble exampleFomke
nimble test
```

## Small Builds

**Definitions**

- `family` := one algorithm kind in a layout: KEM, cipher, MAC, hash,
  signature or KDF.
- `slim build` := a build compiled with fewer KEM, signature or symmetric
  families, or one carrier.

A device with one KEM (key encapsulation mechanism) and one carrier (TCP or
DAC) needs no
code for the others. Four build flags decide what enters the binary. The
source code stays the same between a full build and a slim build.

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

BLAKE3 is always compiled, whatever the list says: AME normalises MAC (message
authentication code) outputs and derives Argon2's salt with it. The symmetric
flag names *primitives*, not slots (positions in a layout). One primitive
serves several families:
removing `sha3` removes one MAC (message authentication code) slot, two hash
slots and one KDF (key
derivation function) slot at once.

Hybrid signature slots need two families. `asaEd25519Falcon512Hybrid` exists
only when `ed25519` and `falcon` are both compiled. The compile error names
what is missing.

Size of a program that runs one two-slot KEM (key encapsulation mechanism)
exchange and generates its
signing keys, `-d:release`, x86-64:

```text
  everything ...................................... 747 336 bytes
  + kems=kyber,x25519  carriers=dac ............... 506 432 bytes   (-32%)
  + sigs=ed25519  symmetric=blake3,chacha20 ....... 249 272 bytes   (-67%)
```

The flags do not change the wire. Every slot (position in a layout) number
keeps its meaning, so a
slim build and a full build understand each other wherever they share an
algorithm. A slim build refuses a layout (the ordered algorithm list) that
names a missing slot, when the
layout (the ordered algorithm list) is built or decoded, before any key
exists. Naming a missing family as
a constant does not compile, and the error names the flag.

One wire change happened once, for another reason: **Ed448 is gone.** It
existed only in liboqs, and keeping it forced every AME build to link liboqs.
The signature slot ids are renumbered without gaps (Ed25519 is still 0x01;
everything after it moved down by one). AME no longer depends on liboqs.

Check all slim profiles at once:

```text
nimble testMinimalAme
```

## Native TLS 1.3

**Definitions**

- `TLS` := Transport Layer Security, the standard encrypted stream protocol.
- `engine` := the TLS state machine without a socket: bytes in, bytes out.

Bifrost exports a TLS 1.3 client and server engine. The first profile is
narrow on purpose:

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

The engine owns no socket:

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

# Pass each TCP fragment to the engine, in any size.
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

Both directions handle fragmented and joined records, sealed alerts,
`close_notify`, and post-handshake `KeyUpdate`. Handshake secrets and copied
schedule secrets are erased once the traffic keys exist.

This profile is not a general web TLS client. It refuses multi-certificate
chains and RSA or ECDSA certificates. It has no HelloRetryRequest, no client
certificates, no session resumption and no 0-RTT. Keep the OpenSSL transport
wrapper until the native profile has broader interoperability tests, fuzzing
and an independent security review.

## Initial Trust 🐦‍🔥

**Definitions**

- `handshake` := the four records that start a session: client hello, hello
  retry (optional), server hello, client finish.
- `client hello` := record 1, initiator to responder: nonce, layout, tier,
  KEM public keys.
- `hello retry` := the responder's answer "send your hello again, with this
  cookie".
- `server hello` := record 2, responder to initiator: nonce, KEM answer, one
  sealed block.
- `client finish` := record 3, initiator to responder: one sealed block.
- `nonce` := 32 random bytes, fresh per record, never reused.
- `transcript` := every handshake field so far, in order, built the same way by
  both endpoints.
- `sealed block` := the sealed part of the server hello and of the client
  finish. It holds the identity proofs.
- `cookie` := a tag the responder computes over the initiator's address with a
  secret only the responder holds.
- `authority` := a key stack that signs certificates.
- `certificate` := subject name, public signing keys, validity window, serial,
  and one authority signature per authority slot.
- `pin` := a public signing key an endpoint received before the handshake.
- `authentication mode` := what an endpoint must show before the other one
  believes it. One of AM1A, AM1S, AM1P, AM1P+S.
- `AM1A` := mode "Authority": a certificate signed by a known authority.
- `AM1S` := mode "Signature": the other endpoint's pin.
- `AM1P` := mode "Pre-shared": a PSK and its name.
- `AM1P+S` := AM1P and AM1S at once; both must hold.
- `pre-shared mode` := AM1P or AM1P+S.
- `binder` := 32 bytes derived from the PSK that join the key schedule.
- `salt` := 32 random bytes in a pre-shared client hello, fresh per hello.
- `sealed hello` := a client hello whose KEM public keys are sealed (pre-shared
  modes only).
- `CS` := carried secret. 32 bytes a finished session hands to the NEXT
  handshake with the same endpoint. `CS = GB3HKDF(NS, "next handshake")`, see
  [FOMKE](#fomke) for NS. Code names: `ameNextHandshakeSecret` returns it,
  `withAmeNextSecret` takes it, the hello flag is `usesNextSecret`.

The handshake decides two things at once: which keys both endpoints use, and
who the other endpoint is. It decides the second one privately: an observer
of every byte never learns who talks to whom.

```text
Authority
  +-> signs initiator certificate   (with its WHOLE algorithm stack)
  +-> signs responder certificate

Initiator                                           Responder
  |--- client hello: nonce, layout, KEM public keys ->|
  |       (no identity: there is no key yet)          |
  |       (pre-shared modes: KEM keys sealed)         |
  |                                                   |
  |<-- hello retry: cookie ---------------------------|   optional
  |--- client hello again, with the cookie ---------->|
  |                                                   |
  |<-- server hello: nonce, KEM answer, sealed block -|
  |       sealed block: responder certificate + proof |
  |                                                   |
  |--- client finish: sealed block ------------------>|
  |       initiator certificate, proof, transcript hash|
  +=============== equal epoch 1 =====================+
```

A sealed block (the sealed part of the server hello and of the client finish)
is sealed under a key both endpoints derive from the KEM answer and the
transcript (every handshake field so far). It exists from the server hello
onwards.

The cookie (a tag over the initiator's address) needs no memory on the
responder: when the cookie comes back, the responder computes it again. An
initiator that cannot receive at its claimed address never gets a matching
cookie. The costly work, key encapsulation and signature checks, therefore
runs only for an endpoint that is really there.

An epoch (numbered key generation) is returned only after all of this holds:
every authority signature (one per authority slot, not only the first), the
certificate serial against the revocation list, the validity window, the local
clock near enough to that window, the other endpoint's proof over the
transcript, the exact layout and initial tier, the KEM exchange, and the final
transcript hash.

### Four authentication modes ꒰ঌ ໒꒱

The picture above shows AM1A (authority certificate). All four modes send the
same four records with the same fields. Two things differ: the content of the
two sealed blocks, and, in the pre-shared modes (AM1P, AM1P+S), the KEM public
keys of the client hello, which are sealed too.

The mode is chosen once, by building one `AmeAuthentication`. Every handshake
step reads that same object. The names follow one pattern: **AM1** + the
letter of what an endpoint holds in advance.

| mode | held in advance | content of the sealed blocks | client hello KEM keys | needs a PKI |
|---|---|---|---|---|
| **AM1A** | an **A**uthority's public keys | certificate + one signature per slot | unencrypted | yes |
| **AM1S** | the other endpoint's **S**ignature key (pin) | certificate + one signature per slot | unencrypted | no |
| **AM1P** | a **P**SK (pre-shared key) and its name | the name + one PSK (pre-shared key) tag | sealed | no |
| **AM1P+S** | both of the above | name + PSK tag, THEN certificate + signatures | sealed | no |

`PKI` := public key infrastructure, a set of authorities.

```nim
# AM1A -- an authority vouches for the other endpoint
var auth = initAmeCertificateAuthentication(root)

# AM1S -- the other endpoint's pin was handed over in advance
var auth = initAmePinnedAuthentication(pinnedPeerIdentity(theirKey))

# AM1P -- a PSK was handed over in advance
var auth = initAmePskAuthentication("site-a", pskBytes)

# AM1P+S -- a PSK AND the other endpoint's pin
var auth = initAmePskPinnedAuthentication("site-a", pskBytes,
  pinnedPeerIdentity(theirKey))
```

That one object goes to every call. No other call is told the mode:

```nim
var hello  = beginAmeHandshake(sessionId, layout, tier, a = auth)
var server = answerAmeHandshake(hello.hello, supportedPaths, auth, cert, key)
var client = finishAmeHandshake(hello, server.state.serverHello, auth, cert,
  key, nowUnix)
var done   = acceptAmeHandshake(server.state, client.finish, nowUnix)
```

`acceptAmeHandshake` takes no `auth`. It uses the `auth` that
`answerAmeHandshake` matched to the hello and stored in `server.state`. The
two responder steps can therefore never run with different secrets.

`cert` and `key` are this endpoint's own certificate and signing key. **AM1P
(PSK only) uses neither**; an endpoint with only a PSK (pre-shared key) holds
no signing key:

```nim
var server = answerAmeHandshake(hello.hello, supportedPaths, auth)
var client = finishAmeHandshake(hello, server.state.serverHello, auth)
var done   = acceptAmeHandshake(server.state, client.finish)
```

#### Which mode protects against what

```text
mode     proof                          someone who STEALS it can ...
-------  -----------------------------  -----------------------------------
AM1A     "an authority vouched for me"  whatever the authority will sign
AM1S     "I own this pinned key"        pretend to be that one endpoint
AM1P     "I know the PSK"               pretend to be EITHER endpoint
AM1P+S   both of the above              needs to steal BOTH

against a quantum computer:  AM1P  >  AM1S (post-quantum signatures)  >  AM1A
against a stolen device:     AM1S  >  AM1A  >  AM1P
for first contact:           AM1A  (the others need earlier setup)
```

AM1P+S (PSK and pin) needs both proofs. Neither replaces the other:

```text
PSK stolen, signing key safe             -> still secure
signatures broken, PSK safe              -> still secure
both lost                                -> broken
```

It costs one signature and one verification per endpoint, once per handshake.
Rotations (switches to the next epoch) inside an AM1P+S session are signed, as
in AM1S.

#### The sealed hello (pre-shared modes)

In the pre-shared modes the KEM public keys of the client hello are never
unencrypted. They are sealed under a key derived from the PSK and the salt:

```text
key  = GB3HKDF( PSK ‖ CS if present,  salt,
                "AME-AM1P-HELLO-v1" + PSK name + every unencrypted hello field )
seal = the session's own tier AEAD (encryption + one tag): every switched-on cipher, every
       switched-on MAC -- the same masks every later frame uses
```

The salt (32 random bytes, fresh per hello) is required. The PSK is the same
for every hello. Without the salt, two hellos would be sealed with one
keystream, and XOR of the two ciphertexts would reveal both. The tag of the
sealed hello covers every unencrypted field, including the mode byte and the
salt. A responder with a different PSK cannot open the hello, and refuses it
before any KEM work:

```text
-> "client hello did not open under the shared secret"
```

#### What AM1P proves ʚ♡ɞ

Two separate things come from the one PSK.

**1. A proof: each endpoint learns who the other one is.** A tag over the
transcript. A direction byte sits inside the tagged bytes, so the responder's
proof never passes as the initiator's.

```text
responder proves:  tag( PSK, "responder" | name | transcript so far )
initiator proves:  tag( PSK, "initiator" | name | hash of the whole transcript )
```

**2. The binder: the keys depend on the PSK too.** The proof says who talks;
it adds nothing to the keys. So AM1P also derives the binder (32 bytes from
the PSK) and adds it to the key schedule next to the KEM results:

```text
AM1A / AM1S   :  keys <- [ KEM slot 0 | KEM slot 1 | ... ]
AM1P / AM1P+S :  keys <- [ KEM slot 0 | KEM slot 1 | ... | binder ]
```

Row 2: an attacker who breaks **every** KEM slot still cannot open a
pre-shared sealed block, because the binder (the PSK's key-schedule input) is
missing. The PSK itself never enters the derivation; only the binder does. A
key block recovered later says nothing about a PSK that many sessions reuse.

#### The carried secret: from one session to the next ⟡

When a session ends, both endpoints can keep the CS (carried secret, 32 bytes
from the old session). The next pre-shared handshake with the same endpoint
takes it as a second key next to the PSK:

```nim
# session 1 is running
var kept = ameNextHandshakeSecret(session)        # the CS, equal on both endpoints

# later, session 2
var auth = initAmePskAuthentication("site-a", pskBytes).withAmeNextSecret(kept)
```

With it, the sealed hello, both proofs and the binder all take `PSK ‖ CS` (CS:
the carried secret) as their key. **A stolen PSK alone no longer opens the next
hello.**

Both endpoints must agree whether the CS was used. The client hello carries
one flag byte for that, unencrypted and covered by the tag of the sealed
hello. The responder decides what it accepts:

```text
hello flag   responder holds a CS   required   outcome
----------   --------------------   --------   ----------------------------------
1            yes                    any        use it
1            no                     any        refuse: nothing to match it with
0            any                    yes        refuse: no fallback without notice
0            yes                    no         PSK only -- and the flag shows it
0            no                     no         PSK only
```

`withAmeNextSecret(kept, required = true)` stops an attacker from forcing both
endpoints back to PSK only by breaking one handshake on purpose. Set it to
`false` only while an endpoint may have lost its CS, for example after a
restore from backup.

#### Rotating an epoch without signature keys

A rotation needs an offer and a reply, and each is proved by the endpoint that
sent it. AM1P has no signing key. It uses a tag instead, under a key derived
from the finished handshake:

```text
AM1A / AM1S / AM1P+S  ->  one signature per switched-on signature slot
AM1P                  ->  one tag under the session's own exchange key
```

Both forms travel in the same field and cover the same bytes. The exchange key
is derived per session and is never the PSK.

#### A mode mismatch

The client hello names its mode. The mode byte is covered by the transcript
and, in the pre-shared modes, by the tag of the sealed hello. A responder that
runs another mode **refuses** the hello before any key work:

```text
initiator asks for AM1A, responder runs AM1P
  -> "client asked for an authentication mode this side does not run"
```

The responder checks the mode; it does not copy it back. Copying would let the
initiator choose which checks the responder runs. The same rule prevents a
downgrade: each endpoint sets its mode locally and never takes the other
endpoint's choice.

### What each record shows

| | client hello | server hello | client finish |
|---|---|---|---|
| sender identity | not stated | sealed | sealed |
| unencrypted to an observer | AM1A/AM1S: everything. AM1P, AM1P+S: nonce, layout, tier, salt; the KEM keys are sealed | nonce + KEM answer | nothing |
| costs the responder real work | no (cookie first) | yes | yes |
| authenticated | AM1A/AM1S: no, nothing to authenticate it with yet. AM1P, AM1P+S: yes, by the tag of the sealed hello | yes | yes |

In AM1A and AM1S the client hello has no key to authenticate it with. The
cookie in front of the costly work exists for that reason.

### Revocation

**Definitions**

- `serial` := a number that names one certificate, not its holder.

Revoking a serial (certificate number) removes one certificate and leaves the
subject free to receive another one. Revoking by name would block the name for
ever.

```nim
var cert = issueAmeIdentityCertificate(authority, identity,
  serial = 11'u64, validFromUnix = 100'i64, validUntilUnix = 1000'i64)
var trust = verifyAmeIdentityCertificate(cert, root, nowUnix,
  revokedSerials = [7'u64, 9'u64])
```

### Running it over a socket

**Definitions**

- `policy` := `AmeResponderPolicy` or `AmeInitiatorPolicy`: what one endpoint
  accepts, independent of the carrier.

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

The same policy (what one endpoint accepts) drives the DAC carrier. Only the
driver changes:

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

The DAC responder returns the address it answered: on a datagram socket it
learns the other endpoint by listening. It sends nothing twice (the initiator
owns every timer), so a responder holds no state per endpoint until a
handshake completes.

Keep `requireCookie` on for DAC. Nothing proves a source address there, and a
responder without the cookie runs post-quantum KEM work for datagrams nobody
sent.

`nowUnix` comes from the caller on purpose. A library that reads an unset
system clock and judges certificates by it is worse than one that makes the
caller name the time source.

## Secure Packages

**Definitions**

- `ASP` := AME secure package: one sealed blob for bytes that are stored or
  relayed.
- `manifest` := the first DAC word of a package: chunk count, size, digest.
- `padding` := filler bytes that round a payload up to whole 64-byte blocks.

```text
Sender
  plaintext -> optional compression -> AME seal (one tag)
            -> DAC chunks + parity over the SEALED bytes

Receiver
  chunks -> local one-loss recovery -> exact repair fallback
         -> BLAKE3 digest -> AME open -> bounded decode -> plaintext
```

Seal first, then cut and add repair data. The repair layer works on
ciphertext and needs no key. The one tag over the whole ASP (secure package)
is checked once, at the end, on the rebuilt bytes.

Compression is **off** by default. Compression before sealing leaks: the
ciphertext is as long as the compressed input, so its length shows how well
the plaintext compressed. An attacker who can place their own text next to a
secret sees a shorter result when the two match. Switch compression on by
name, and only when no part of the payload is under an attacker's influence.

Compression on means padding (filler up to whole 64-byte blocks) on. Before
sealing, the envelope is rounded up to whole 64-byte blocks, and the last
filler byte counts the filler bytes:

```text
  compressed (5 bytes)             padded to one 64-byte block
  +---+---+---+---+---+            +---+---+---+---+---+-----------+----+
  | h | e | l | l | o |    -->     | h | e | l | l | o | 0 0 ... 0 | 59 |
  +---+---+---+---+---+            +---+---+---+---+---+-----------+----+
                                     \_____ 5 _____/ \____ 59 filler ___/
```

There is always filler (a 64-byte payload becomes 128), so the last byte is
never data. Padding (the filler) reduces the length leak to 64-byte steps; it
does not remove it. `paddedAmeCompressionPolicy()` gives padding without
compression, for a package whose size alone would reveal its content.

```nim
var plan = planAmeSecurePackage(senderAuth, packageId, plaintext,
  dacDefaultsFor(dscCleanLan), compressedAmeCompressionPolicy())
var incoming = initDacPackageReceiver(plan.package.manifest)

for chunk in plan.package.chunks:
  incoming.acceptDacPackageChunk(chunk)

var restored = finishAmeSecurePackage(receiverAuth, incoming, plan.compression)
```

The caller sends the manifest (chunk count, size, digest), chunks, repair
hints, repair chunks and commit with its own socket or event loop. Protocol
state is deterministic and testable without a network.

## AME

**Definitions**

- `exchange mask` := the KEM mask of one rotation: which KEM slots run a new
  KEM exchange.
- `rekeyMask` := the caller's name for the exchange mask of one rotation.
- `offer` := rotation record 1: the requester's KEM public keys and target
  tier.
- `reply` := rotation record 2: the KEM answer.
- `epoch-ready` := rotation record 3: the first frame of the new epoch.
- `transcript salt` := a hash of the handshake transcript, fixed per epoch,
  mixed into every traffic key.
- `stack` := per KEM slot, the one-way image of every KEM secret that slot has
  ever produced, with the binder underneath.
- `stack depth` := how many KEM exchanges a stack holds.

AME (Adaptive Message Encryption) exchanges exact, ordered algorithm lists,
not named security levels.

| family | identifier | slots | selection |
|---|---:|---:|---:|
| KEM | 8 bit | 8 | exchange mask |
| cipher | 4 bit | 8 | tier mask |
| MAC | 4 bit | 8 | tier mask |
| hash | 4 bit | 8 | tier mask |
| signature | 4 bit | 8 | tier mask |
| KDF | 4 bit | 8 | tier mask |

Repeated KEM entries are independent slots. Setting the bit of a
switched-off slot adds it; setting the bit of a switched-on slot runs it
again. Other switched-on slots stay on.

A layout offer is accepted exactly or refused. There is no substitution.

### One rotation at a time

Only one rotation (switch to the next epoch) may be in progress, counting
both directions. When both endpoints start one at the same moment, the roles
decide:

```text
  initiator A                       responder B
  ------------                      ------------
  begin  -> offer A  -------------> B discards its own offer, answers A
  offer B <------------------------ begin  -> offer B
  refuse offer B (A keeps its own)

  result: both endpoints follow A's rotation: one epoch, one key set
```

Without this rule both endpoints would reach the same epoch number with
different keys, and every later frame would fail its tag.
`beginAmeSessionExchange` refuses to start while a candidate epoch from the
other endpoint is pending. `answerAmeSessionExchange` refuses an offer while
the local endpoint is the initiator with its own offer outstanding.

### Rotation with and without a new KEM exchange

A tier change always rotates the epoch and always changes every traffic key,
because each epoch mixes in a new transcript salt (hash of the transcript).
Whether the rotation runs a **new KEM exchange** is a separate choice, and it
is the one that matters:

```text
  traffic keys change    every rotation, from the new transcript salt
  KEM runs again         only for the slots in the exchange mask
  stack grows            only for the slots in the exchange mask
```

**Default: every slot that was switched on runs again.**

```nim
requestAmeTier(session, tierId)              # new KEM for every switched-on slot
requestAmeTier(session, tierId, 0)           # no new KEM for switched-on slots
requestAmeTier(session, tierId, 0b0100_0000) # new KEM for slot 1 only
```

```text
  current kem 1000_0000 -> target kem 1100_0000   default -> mask 1100_0000
      both slots run a KEM; both stacks grow by one

  current kem 1000_0000 -> target kem 1100_0000   mask 0  -> mask 0100_0000
      only the ADDED slot runs a KEM; the stack of slot 0 stays as it was

  current kem 1000_0000 -> target kem 1000_0000   mask 0  -> mask 0000_0000
      traffic keys change, nothing else does
```

The default was once the other way round. A rotation without a new KEM
exchange still changes every traffic key, so it looks like work was done. It
was not: an attacker who holds the current KEM secrets keeps reading, and no
stack grows. The costly, real rotation now happens by default; the cheap one
must be asked for with `rekeyMask = 0`.

Asking for the tier already in force is allowed. It is the ordinary way to
grow the stacks without changing anything else.

**Triggered rotations do the same.** A rotation triggered by transferred bytes
or elapsed time runs a new KEM exchange for every switched-on slot too.

> 💸 **Cost.** A KEM exchange carries one public key and one ciphertext per
> slot. For X25519, Saber, Kyber and NTRU that is one or two kilobytes per
> slot. Classic McEliece public keys are **hundreds of kilobytes**, and the
> default sends them again on every rotation. On a metered or thin link, pass a
> smaller `rekeyMask`, or `0`, and accept that those stacks stop growing. The
> choice is per rotation.

### The stack: every KEM exchange builds on the one before ⟡

A KEM slot does not hold only its latest secret. It holds the stack (the
one-way image of all its secrets).

```text
  first exchange   stack = H( binder, slot, algorithm, 1, secret1 )
  rotation         stack = H( H(stack), binder, slot, algorithm, 2, secret2 )
  rotation         stack = H( H(stack), binder, slot, algorithm, 3, secret3 )
```

`H` := the tier's hash overlay: every switched-on hash slot, outputs XORed
together. Breaking one hash primitive is not enough.

Before the stack, a slot kept only its latest secret:

```text
  epoch 1   key = KDF( ... secret1 ... )
  epoch 2   key = KDF( ... secret2 ... )      secret1 erased, and irrelevant
```

An attacker with `secret2` alone read epoch 2. Now the key depends on the
whole stack (image of all secrets):

```text
  to read epoch 3 an attacker needs
    secret3   AND   secret2   AND   secret1   AND   the binder
```

Each rotation adds a term. No rotation removes one.

**Forward secrecy is unchanged.** The old stack is erased when the new one is
built, and the new one is a one-way image of the old one. A device seized
today still cannot read yesterday.

**The PSK joins every stack.** In the pre-shared modes both endpoints hold a
PSK. The binder derived from it enters every slot's stack, on the first KEM
exchange and on every rotation:

```nim
## Both endpoints hold the same binder, and it is not the PSK.
check clientDone.auth.exchangeBinder == serverDone.auth.exchangeBinder
check clientDone.auth.exchangeBinder != secret
```

The binder is derived from the PSK, the CS if present, and the finished
transcript, under its own label. It is NOT the same bytes as
`exchangeAuthenticationKey`, the MAC key that tags offers and replies in AM1P.
One secret with two jobs is how a proof about one job silently stops holding
for the other.

AM1A and AM1S have an empty binder. They have no PSK, and a binder built from
unencrypted values would protect nothing.

**Growing the stacks on purpose.** Ask for the tier already in force, as
often as the traffic is worth. Each switched-on KEM slot runs again, and each
stack grows by one:

```text
  for each rotation:

    requestAmeTier(session, session.auth.current.tier.tierId)
        ^ no mask needed: the default is every switched-on slot

    beginAmeSessionExchange   ->  offer   ->  answerAmeSessionExchange
    finishAmeSessionExchange  <-  reply   <-
    confirmAmeSessionExchange <-> epoch-ready

    every stack of the tier is now one deeper
```

One round trip per rotation. Neither endpoint can grow a stack alone: the new
term comes from a KEM exchange both endpoints ran.

```nim
## The stack depth, read from the session.
echo ameSessionStackDepth(session)
```

It reports the **smallest** stack depth (KEM exchanges per stack) among the
tier's slots, because an attacker chooses which slot to attack.

**Adding an algorithm lowers the number.** A rotation onto a tier with a new
KEM slot grows every existing stack and adds a new slot at depth 1, so the
session reads 1. Nothing is lost; there is a shallower target now. Rotating
again on the same tier raises it.

> ⚠️ Stack depth grows only with a new KEM exchange. `rekeyMask = 0` gives new
> traffic keys without a KEM exchange, and grows nothing: hashing a value
> again is as easy for an attacker as for an endpoint.

## What DAC decides ꒰ঌ ໒꒱

**Definitions**

- `parameter setter` := the part of DAC that maps path measurements to a path
  lane. Arithmetic only, no socket.
- `transport` := the part of DAC that acts on those numbers: the link loop,
  chunking, receipt bookkeeping, repair. It has a socket and state.
- `receipt` := an AckRange word: "these chunks arrived".
- `receipt mode` := when a receiver sends receipts (`ackMode`).
- `not measured` := the value 0 in a PathStats field (except loss ppm).

```text
  DacPathStats          loss ppm, rtt, jitter, reorder depth,
                        mtu hint, queue ms, credit hint
        |               0 MEANS "NOT MEASURED", never "measured 0".
        |               Only loss ppm is exempt. A rule whose input is
        |               not measured is skipped.
        |
  recommendDacPathFromStats     moves ONE step toward a target, never jumps
        |
  DacPathLane           clean · superClean · mobile · thin ·
                        lossy · blockedUdp · recovery
        |
  dacDefaultsFor(scenario)
        |
  DacScenarioDefaults   chunkBytes      size of one chunk
                        dataShards      chunks per repair group
                        parityShards    repair data per group
                        repairMode      none | xor | reedSolomon | tcpExact
                        ackBatchChunks  chunks per receipt
                        ackMaxDelayMs   longest wait before a receipt
                        repairWaitMs    wait before rebuilding
                        repairRounds    rebuild attempts
```

`rtt` := round-trip time. `mtu` := maximum transmission unit, the largest
datagram a path carries. `ppm` := parts per million.

### The scenario table

Twelve rows, one enum, one table. Several scenarios share one path lane on
purpose: bad signal, heavy loss, jitter and an unstable path are all
`dplLossyPath` and differ in parity.

```nim
var d = dacDefaultsFor(dscCleanLan)          # 1200-byte chunks, 32D + 1P
var e = dacDefaultsFor(dscHeavyLoss)         # 512-byte chunks, 12D + 6P
var f = dacDefaultsFor(dscWeakRecovery)      # fixes its own transfer class
```

Heavy loss gets the **small** receipt batch: every chunk without a receipt is
state the sender cannot release yet. Long deadlines are for battery radios,
where a wake-up costs more than bandwidth.

### Receipt modes ꒰ঌ ໒꒱

`ackMode` is the receipt mode (when a receiver sends receipts). It is a
behaviour, not a size:

| mode | sends a receipt | use |
|---|---|---|
| `damSilent` | never | a sent byte costs more than a wasted parity shard |
| `damNackOnly` | only when a chunk is really missing | a metered link |
| `damBatch` | on the count or the deadline | the ordinary case |
| `damExplicit` | for every chunk | lowest latency, most receipts |
| `damVerified` | like batch, plus "I have committed N packages" | a path so bad the commit itself may be lost |

A `PackageCommit` is one datagram and can be lost. A `damVerified` receiver
puts its commit count in **every** receipt (AckRange word), so the sender
learns the package arrived even when the commit is lost:

```text
  receiver commits package 1          its count goes 0 -> 1
        |
  every receipt from now on says 1
        |
  sender started this package when the count read 0
        -> the count CHANGED -> the receiver committed a package
        -> with one package in flight, that is this one
        -> release it
```

Every other mode reports 0, which a sender reads as "this receiver does not
report commits", never as "this receiver committed nothing".

**The receipt ends with the package.** The receipt window slides over arrived
chunks only and never past a hole: a position below the window base could
never be reported again. The window belongs to ONE package, and it once
outlived it:

```text
  base                    the package is complete, and yet
   |  X  .  X  X          pending = 2, so a receipt is still due
         ^                -> a receipt every ackMaxDelayMs
         the hole that       -> the window does not slide
         parity filled       -> so it repeats, for ever
```

Every delivery rebuilt from parity ended like that. The link sent about ten
sealed receipts per second to an endpoint that had stopped listening, and
each one made the link look alive, so its relay slot was never reclaimed.

One last receipt still goes out, in `damVerified` only: that mode's receipt
carries the commit count a sender needs when the commit word is lost. The
other four modes have just sent a commit.

### The top path lane is configured, never measured ⌜guide⌟

`dplSuperCleanPath` (32 KB chunks, no repair) is **configuration only**.
Promotion needs an mtu hint of 4096 or more, and a receiver reports the chunk
size that got through. On the clean path lane a sender sends 1200-byte
chunks, so 1200 is all a receiver ever sees. Small chunks never reveal a
32 KB path.

```nim
## Ask for it when both machines share a rack or a switch.
var d = dacDefaultsFor(dscSameRoom)      # dplSuperCleanPath
```

Adaptation still moves *down* from it as soon as the path disagrees.

### A zero means "not measured" ⌜guide⌟

Every rule above is arithmetic on numbers the other endpoint sent. A field
that was not measured but reads as a measurement makes the arithmetic wrong in
whichever direction that field points. This happened: `creditHint` was not
filled, the first rule reads `creditHint <= 32` as "the receiver is out of
buffer", and so **every** report said so:

```text
  a perfect LAN, one package at a time

  clean  ->  mobile  ->  thin  ->  lossy  ->  recovery
     1          2         3         4          and stays there

  chunks 1200 -> 512 bytes, parity none -> six-way Reed-Solomon,
  receipt batch 64 -> 4, reason given: "receiver pressure"
```

**A number that describes the sender's own behaviour is not a measurement of
the path.** DAC shuffles its chunks on purpose, so chunk order describes the
sender, not the wire. Reorder depth read from chunk ids means nothing, and
neither does a hole in a receipt batch. Both are handled in
`src/protocols/dac/README.md`.

### How AME reaches DAC ʚ♡ɞ

A session records its path lane and returns the whole parameter row:

```nim
var d = ameSessionPathDefaults(connection)
var plan = planAmeSecurePackage(connection, packageId, payload)
```

Prefer the second call. The older overload takes a `DacScenarioDefaults` the
caller must keep equal to the session's by hand, and nothing checks it.

### The line DAC must not cross ₊˚⊹♡

> Chunk size, repair strength, receipt batching and timeouts follow the link.
> **The switched-on algorithms, the tag length and the padding policy do not.**

An attacker on the path can cause loss at will. If padding switched off on a
"thin" path lane, the attacker would cause loss and read message lengths,
which is exactly what padding hides. The same holds for a lower tier or a
shorter tag.

So AME rotations trigger on elapsed time, transferred MiB, or an explicit
call, and never on measured link conditions. A test checks it.

## FOMKE

**Definitions**

- `ISS` := initial shared secret. Every KEM secret of one KEM exchange, one per
  switched-on KEM slot.
- `LK1(i)`, `LK2(i)` := lane key of lane 1 / lane 2 at step i, 64 bytes each.
  Code name: `chainKey`.
- `NS(n)` := next secret of epoch n, 32 bytes. Never used for a message.
- `MK(i)` := message key of message i on one lane, 32 bytes.
- `step` := one GB3HKDF call that turns LK(i) into LK(i+1) and MK(i).
- `key block` := the bytes one MK expands into: nonce, one key per switched-on
  cipher slot, one key per switched-on MAC slot.
- `held key` := an MK kept for a message that has not arrived yet, while later
  messages already did.
- `reorder cache` := the set of held keys of one session.
- `reorder window` := how far AHEAD of the next expected index a message may
  sit and still be opened. Moves with measured reordering.
- `reorder ceiling` := the largest reorder window, and the most held keys per
  lane. Fixed per session (`fomkeReorderCeiling`).
- `forward secrecy` := a device seized today cannot open earlier messages.

FOMKE (Forward-Only Message Key Extension) is **the** only protection of a
payload after the handshake. Nothing wraps it and nothing sits inside it: a
frame is sealed exactly once.

"Forward-only" means keys are derived forward, never backward. Once a key is
used, it and everything that could recreate it are erased. A device seized
today therefore opens no earlier message. ʕ•́ᴥ•̀ʔっ♡

### What exists, and when it is erased ⟡

This table is the whole memory story of FOMKE (forward-only message keys).
Every other step below only explains one row of it.

```text
value        size   created                      erased
-----------  -----  ---------------------------  ---------------------------------------
ISS          var.   KEM exchange                 right after the one GB3HKDF call
             (initial shared secret)
160-byte     160    that GB3HKDF call            right after LK1(0), LK2(0), NS(1) are
output                                           copied out of it (same call)
LK1(i)       64     step i-1 of lane 1           at step i of lane 1 (LK1(i+1) replaces it)
LK2(i)       64     step i-1 of lane 2           at step i of lane 2
MK(i)        32     step i                       sender: right after message i is sealed
                                                 receiver, message i arrives in order:
                                                   right after message i is opened
                                                 receiver, message i skipped (a later
                                                   message arrived first): kept as a held
                                                   key, see "held keys" below
NS(n)        32     start of epoch n             at the rotation to epoch n+1, when
                                                 NS(n+1) replaces it
key block    var.   from MK(i)                   right after message i is sealed / opened
```

Held keys (MKs of skipped messages) are erased at the FIRST of:

```text
  message i arrives          -> opened, then its held key is erased
  i falls more than the      -> erased: that message is lost, not late
    reorder ceiling behind
  the reorder cache is full  -> the OLDEST held key is erased to make room
  the package ends           -> the DAC relay erases what is still held
  the caller gives up        -> discardAmeSessionSkipped()
  rotation                   -> every held key of the old epoch is erased
```

So after the first derivation the session holds, at any moment: LK1 and LK2
(lane keys, 64 bytes each), NS (next secret, 32 bytes, for the whole epoch), and at most
`reorder ceiling` held keys per lane (32 bytes each). The lane keys do NOT
wait for late messages: a lane key always steps forward at once, and only the
MKs (message keys) of the skipped positions are kept.

### Step 1: one derivation, three pieces

Every KEM secret of the handshake (the ISS, initial shared secret) goes
through **one** GB3HKDF (Gimli BLAKE3 KDF) call, together with the epoch number, the KEM list,
the layout, the tier and the transcript. The 160 output bytes are cut into
three pieces by position:

```text
ISS + transcript + layout + tier + epoch
                 │
              GB3HKDF  (one call, 160 bytes out)
                 │
┌───────────────────┬────────────────────┬────────────────────┐
│ LK1(0) bytes 0..63│ LK2(0) bytes 64..127│ NS(1) bytes 128..159│
└───────────────────┴────────────────────┴────────────────────┘
  lane 1 key          lane 2 key            next secret
```

The ISS (the KEM secrets) is erased. LK1, LK2 (the lane keys) and NS are copied into the
session state and **kept** (see the table above); the 160-byte scratch copy
is erased. There is no root key. A root key, derived first and then split
again, added one more secret and no separation: the one call already
separates the pieces by position.

Every switched-on KEM slot enters the call. A tier that names Kyber AND X25519
but derived from one of them would be a hybrid in name only.

NS (next secret) has exactly two jobs:

```text
1. the next rotation:   NS(n) + new KEM secrets ──GB3HKDF──▶ LK1 | LK2 | NS(n+1)
2. the next session:    CS = GB3HKDF(NS, "next handshake")
                        ──▶ withAmeNextSecret(CS) on both endpoints
```

NS (the next secret) is a one-way image of the epoch's secret. An attacker who
steals it cannot compute any lane key from it, so it opens no message. It
matters only together with the NEXT KEM secrets, which that attacker does not
have.

### Step 2: the steps

Each sent message moves the sender's lane one step. One GB3HKDF (Gimli BLAKE3
KDF) call turns `LK(i)` into `LK(i+1)` and one 32-byte MK (message key) per
direction; the sender keeps the
MK of its own lane and erases the other:

```text
lane 1 (initiator -> responder)          lane 2 (responder -> initiator)

LK1(0) --GB3HKDF--> LK1(1) + MK1(0)      LK2(0) --GB3HKDF--> LK2(1) + MK2(0)
   X erased            |                    X erased            |
                       v                                        v
LK1(1) --GB3HKDF--> LK1(2) + MK1(1)      seal message 0 on lane 2
   X erased            |
                       v
              seal message 1 on lane 1
```

Every derivation input carries a version label, the lane, the epoch and the
index. No two positions in any lane produce the same bytes.

### Step 3: one key block per message

The 32-byte MK (message key) expands, in one GB3HKDF call, into the key block:

```text
[ nonce ][ key, cipher slot 0 ][ key, cipher slot 1 ][ MAC keys... ]
```

The nonce is at the front and **never travels**: both endpoints derive the
same key block from the same step. Each MK is used exactly once, so each nonce
is used exactly once, and a broken random generator cannot repeat a nonce.

### Step 4: seal

The payload is XORed through every switched-on cipher in turn. The tag is the
XOR of every switched-on MAC:

```text
plaintext --XOR slot 0--> --XOR slot 1--> ciphertext
                                             |
                        MAC slot 0 --> tag A +
                        MAC slot 1 --> tag B +--> XOR --> the one tag of the frame
```

Decryption is the same walk again (XOR is its own inverse). An attacker must
break **every** switched-on cipher; a forgery needs every switched-on MAC.

Seal = encrypt, then tag the ciphertext. A receiver checks the tag before it
decrypts, and never touches plaintext an attacker chose. The tag covers a
label, the layout, the tier, the tag length, the message's epoch, index and
lane, the AAD (the whole AME header), and the ciphertext.

The at-rest package sealer uses the same code (`ame/level1/tier_aead.nim`).

### Step 5: open, all or nothing

The receiver never changes its live state for a message that fails. It copies
the state, steps the copy's lane up to the received index, checks the tag, and
only then replaces the live state with the copy. A forged message costs one
derivation and changes nothing: it cannot advance a lane or fill the reorder
cache (the held message keys).

```text
receive index 5, lane expects 3
  -> derive MK(3) and MK(4), keep them as held keys
  -> derive MK(5), open message 5

receive index 3 later            -> take the held key MK(3), open, erase it
receive index 3 again            -> no held key, no way backward -> refused
receive index 3 + window + 1     -> too far ahead -> refused
```

### Step 6: the reorder window

The reorder window (how far ahead a message may sit) bounds two costs.

Memory:

```text
  ceiling  4  ->  at most  4 held keys per lane  ->  128 bytes
  ceiling 16  ->  at most 16 held keys per lane  ->  512 bytes
  ceiling 64  ->  at most 64 held keys per lane  ->  2 kilobytes
```

Work: a message that claims a position `N` ahead makes the receiver derive
`N` MKs **before** its tag can be checked:

```text
  one forged datagram in
        |
        v
  N derivations                      <- paid before the tag is checked
        |
        v
  tag fails, everything discarded    <- paid for nothing
```

A wide window is therefore a wide amplifier. The window starts at 16 and
follows what the lane measures:

```text
  message at exactly the expected index   -> narrow, after 64 of them
  message N positions out of order        -> widen to 2N, at once
```

Widening happens on the **copy** of the state, which is kept only when the tag
matches. A forged message cannot widen the window. An honest endpoint on a
reordering path widens it within a few messages.

The window never exceeds the reorder ceiling (largest window, most held keys).
The ceiling is fixed per session and comes from `config.toml`:

```toml
[fomke]
fomkeReorderCeiling = 64     # 4 .. 4096; held keys per lane, 32 B each
```

On a datagram link DAC usually repairs loss first (parity or a repair
request), so the window rarely needs to be wide.

### Step 7: rotation

A rotation prepares candidate lanes for epoch `n+1` next to the live lanes of
epoch `n`, again with ONE GB3HKDF call:

```text
NS(n) + new KEM secrets + the FKU1 commit ──GB3HKDF──▶
    [ LK1(0) | LK2(0) | NS(n+1) | confirmation key ]    of epoch n+1
       64       64       32        32 bytes
```

NS(n) keeps out an attacker who saw only the new KEM exchange. The new KEM
secrets let a session recover from an earlier compromise, because the
attacker never saw them.

The live lane keys are **not** an input. They were once, and that bound the
new epoch to the exact index each lane had reached, a value both endpoints
agree on only after every message in flight has arrived. NS(n) is constant for
the whole epoch, so both endpoints always hold the same one.

Data is paused. The FKU1 commit must match: request id, epochs, target tier,
exchange mask, slot generations, both lane indices, and a confirmation tag
computed with the confirmation key above. Only then do the candidates (both
lane keys AND NS(n+1)) replace the live values in one step, and the tier
changes with them. The old lane keys, NS(n) and every held key of epoch n are
erased. On any mismatch the candidates are erased and epoch `n` continues.

### Loss is not lateness ⌜guide⌟

Held keys exist so a late datagram still opens. The arriving message is what
removes its held key. A **lost** datagram never arrives: DAC sends the lost
CHUNK again inside a **new frame at a new index**, so the held key of the old
index waits for nothing:

```text
  frames 100..130 sealed and sent
        |
        +--> 104 and 117 are lost on the path
        |      their MKs are held keys now
        |
        +--> DAC sends those two chunks again as frames 131 and 132
               nothing ever claims 104 or 117 again
```

Without limits, the reorder cache fills with keys for messages that never
come; a session on a 2% loss path once stopped receiving **for good** within a
few hundred frames. Three rules run on their own:

```text
  too far behind    a held key more than the reorder ceiling behind the
                    lane is erased: that message is lost, not late.

  capped by the     the reorder cache holds at most the reorder ceiling of
  ceiling           keys per lane, not the reorder window, which moves.

  room is made,     a full reorder cache erases its OLDEST held key instead
  never refused     of refusing the message. Losing one key costs one
                    datagram the carrier sends again; refusing cost the
                    whole session.
```

The bound against an outsider is **unchanged**: a message further ahead than
the reorder window is still refused before any derivation.

The DAC relay erases every remaining held key **when a package ends**. From
that moment nothing outstanding can still arrive, and only the relay knows
that moment:

```text
  package completes or fails
        |
        v
  every chunk is either here or given up
        |
        v
  every remaining held key waits for nothing -- erase it
```

This matters twice: a rotation refuses to start while any held key exists, so
without this a long lossy session could never rotate.

**By hand.** A caller without the DAC relay, or one that knows a gap is lost:

```nim
if ameSessionSkippedMessages(connection) > 0:
  var gaveUp = discardAmeSessionSkipped(connection)
  echo "gave up on ", gaveUp, " message(s)"
```

Those held keys are erased. The messages behind them can never be opened
afterwards, even if the network delivers them later.

**The one refusal that remains.** A burst of losses **wider than the reorder
window** is refused, and a refusal advances nothing, so every later message
sits further ahead and the lane cannot recover. This is deliberate: letting a
gap that wide through is the amplifier a forged datagram wants.

It is rare. A soak hit it steadily until the SOCKET QUEUE was sized (the
bursts were the kernel emptying a full receive buffer, not path loss), then
never. See "The one socket setting a server must set" below. When it happens,
the endpoint builds a new session, as DTLS does. Narrowing never goes below
the number of held keys, so a lane with recent gaps does not narrow itself
into one.

### Preparing ahead, and what it costs ₊˚⊹♡

**Definitions**

- `send cache` := MKs and key blocks derived before their messages are sent.

A sender may prepare a bounded run of future key blocks off the latency path.
This is **off by default**:

> A full send cache (keys prepared in advance) holds the keys of the next N
> messages. Forward secrecy for messages already **sent** is unchanged. A
> device seized while the send cache is full gives up the next N messages
> that were not sent yet.

Switch it on when latency matters and the device cannot be seized.
`fomkePreparedSecretBytes` reports how many secret bytes a send cache holds.

```nim
setAmeFomkePregeneration(connection, enabled = true, messageCount = 8)
```

### The building blocks

`GB3HKDF` (Gimli BLAKE3 Hash Key Derivation Function) is Bifrost's own KDF. It
is not RFC 5869 HKDF. Each round computes one Gimli sponge branch and one
BLAKE3 branch over the same length-framed input and XORs them, so an attacker
must break both constructions. It supports configurable rounds (default 3),
indexed 32-byte output blocks, several ordered secret inputs, and an optional
bounded memory-mixed mode for password hardening.

The ciphers and MACs come from the session's **layout**, not from FOMKE.
Switching on a second cipher is a layout decision and costs what the benchmark
shows (`fomke_seal_1slot` against `fomke_seal_2slot`).

`TMEAEAD` and `GGAEAD` are no longer separate code. The slot construction
covers both: every switched-on cipher in turn, every switched-on MAC XORed into
one tag. They remain as two named layouts in `ame/level1/presets.nim`:

| preset | ciphers | MACs |
|---|---|---|
| `tmeAeadAmeLayout` | XChaCha20, AES-CTR, Gimli | Gimli, Poly1305 |
| `ggAeadAmeLayout` | Gimli | Gimli |

`presetAmeTier(L)` switches on every slot of the preset layout. The bytes are
**not** the old formats. Nothing sealed by the old code opens under these.

## Relaying through a VPS 🌊

**Definitions**

- `VPS` := virtual private server: a small rented machine with a public
  address.
- `NAS` := network-attached storage: here, a home machine with no public
  address.
- `relay` := the process on the VPS that forwards datagrams. It holds no key.
- `relay tag` := the number the relay gives one client; one local socket
  toward the NAS per relay tag.
- `overflow buffer` := datagrams the relay holds while the NAS is silent.

The problem is reachability, not trust. The NAS (home machine) has no public
address; the VPS (rented machine) has one. So the VPS (rented machine) forwards:

```text
clients            VPS                        NAS
(many, anywhere)   (weak CPU, public IP)      (strong, no public IP)
     |                    |                        |
     +---- datagram ----->|                        |
                          +---- same datagram ---->|
                          |<--- answer ------------+
     |<--- answer --------+
```

The relay holds no key, opens no frame, and does not tell a session id from a
sequence number. It moves bytes.

### Why the relay does not authenticate ⌜guide⌟

Authenticating would mean running the handshake, holding keys, and one key
derivation per datagram **on the weakest machine**. It would also let the
relay read everything.

Filtering without secrets is fine there: refusing an address range, refusing
an oversized datagram. Anything that needs a key belongs on the NAS.

### How an answer finds its way back

The relay gives each client a relay tag (one socket toward the NAS per
client). The NAS answers to the socket that sent to it, so the relay tag comes
back with the answer and names the client:

```text
client A --> [ relay tag 1 ] --> NAS      NAS --> [ relay tag 1 ] --> client A
client B --> [ relay tag 2 ] --> NAS      NAS --> [ relay tag 2 ] --> client B
```

A home router works the same way, and **neither endpoint needs to know the
relay exists**. Nothing is added to the datagram: the NAS receives the bytes
the client sent.

A late answer whose relay tag was already released is **discarded**, never
sent to the client that holds that relay tag now. Sending it would give one
client another client's bytes.

### When the NAS goes away

While the NAS is silent, datagrams for it go into the overflow buffer:

```text
NAS answering    -> forward at once, the overflow buffer stays empty
NAS silent       -> hold the most recent few, keep listening
buffer full      -> discard the OLDEST and count it
NAS returns      -> send the held datagrams in order, then carry on
```

The overflow buffer **covers a reboot, not an outage**. Every datagram in it
is one the carrier can recover (DAC repair or a repair request), so holding
more would spend memory on something already recoverable.

The relay follows the NAS to a new address when it reappears.

### The numbers, and why each one is a ceiling

| setting | default | bounds |
|---|---:|---|
| `udpForwardMaxClients` | 512 | relay tags an outsider can make the VPS allocate |
| `udpForwardClientIdleMs` | 120 000 | how long an unused relay tag stays reserved |
| `udpForwardNasKeepaliveMs` | 20 000 | how often a quiet NAS is contacted |
| `udpForwardNasSilentMs` | 60 000 | silence before the NAS counts as away |
| `udpForwardBufferDatagrams` | 64 | datagrams in the overflow buffer |
| `udpForwardBufferBytes` | 262 144 | the same limit in bytes |

Anyone who can send a datagram gets a relay tag, so the table has a top. When
it is full the **newcomer is refused**. Evicting an existing client would let
an outsider push out real clients.

A nonsensical setting is refused, not corrected: each one bounds memory an
outsider can make the process spend.

### No sockets in the module

`src/protocols/relay/udp_forward.nim` only decides. It takes "a datagram
arrived from here at this time" and returns "send these bytes there"; the
caller owns the sockets. Every rule above is testable without a network.

```nim
var
  F: UdpForwarder = initUdpForwarder(initUdpAddress("10.0.0.2", 9000'u16))
  step: UdpForwardStep = fromClient(F, client, datagram, nowMs)
## step.send lists what to send, in order. step.send[i].tag names the
## local socket to send from; step.send[i].peer is where it goes.
```

### The one socket setting a server must set ⟡

**Definitions**

- `receive queue` := the kernel's buffer of datagrams not yet read by the
  program.

A UDP socket has one receive queue (kernel buffer of unread datagrams). When
it is full, the kernel discards the next datagram without any signal. The
Linux default is 208 KB (`net.core.rmem_default`): enough for one
conversation, too small for a listener with dozens of endpoints.

```nim
# 4 MB of receive queue for this listener. Linux doubles the value for its
# own bookkeeping and caps it at net.core.rmem_max.
var sock = openDacListener(initDacAddress("0.0.0.0", 9000), 4 * 1024 * 1024)
```

A full receive queue (kernel buffer) discards everything until it drains, so
the losses arrive in RUNS, and a run is the one loss shape FOMKE cannot
absorb. Two places count them:

```text
  /proc/net/snmp   the RcvbufErrors column, whole machine
  /proc/net/udp    the last column, per socket
```

A soak measured it: 2,787 kernel discards in 72 seconds with the default, 2
with 4 MB, and one third more work done.

## Layout

**Definitions**

- `protocol folder` := one folder below `src/protocols/`.
- `level folder` := `level0/` to `level3/` inside a protocol folder; the
  number limits what a file may import.

| path | purpose |
|---|---|
| `src/protocols/ame/` | **Who the other endpoint is, and how a frame is sealed.** Algorithms, epochs, handshake, framing, carriers |
| `src/protocols/fomke/` | **One key per message.** GB3HKDF, the two lanes, the 13-byte envelope |
| `src/protocols/dac/` | **How bytes are cut, paced and repaired.** Chunks, parity, receipts, path lanes |
| `src/protocols/relay/` | The VPS relay: address mapping, NAS keepalive, overflow buffer. Holds no key |
| `src/protocols/chunkyaead/` | Chunked file encryption and tree hashing |
| `src/protocols/transport/` | TCP, UDP, TLS, stream framing, bounded async stream I/O |
| `src/protocols/tls13/` | Pure-Nim TLS 1.3 records, handshake, client and server sessions |
| `src/protocols/bfx2/` | Tagged binary envelopes |
| `evaluation/tests/` | Unit and protocol tests |
| `evaluation/benchmarks/` | Performance measurements |
| `evaluation/statistics/` | Repository and code statistics |

### The level folders ⌜guide⌟

The number of a level folder (`level0/` .. `level3/`) says what a file may
import:

```text
  types.nim   the shapes. Imports almost nothing.
  level0/     may use types.        read a number, write a number
  level1/     may use level0.       one idea each: one message body, one policy
  level2/     may use level1.       one whole job: a session, a package
  level3/     may use level2.       the loop that runs it all
```

A file only reaches *downward*. To learn what something does, start at
`level3/` and read backward; to learn how it is built, start at `level0/` and
read forward.

```text
  src/protocols/dac/level3/link.nim        the DAC loop -- every decision
  src/protocols/ame/level2/framing.nim     every seal and open of a frame
```

Each protocol folder has its own `README.md` with one line per file.

## Tasks

| task | command |
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
| Check the slim build profiles | `nimble testMinimalAme` |
| Check generated files | `nimble releaseHygiene` |
| Remove generated files | `nimble cleanGenerated` |

`nimble soak` is not part of `nimble test`. It starts separate server and
client PROCESSES on separate loopback addresses with real UDP sockets, loses
datagrams on purpose and replaces endpoints, for as long as it is told:

```sh
nimble soak                                   # two minutes, default shape
nimble soak --seconds=3600 --clients=4        # one hour, four client processes
nimble soak --loss=0 --churn=0 --peers=8      # throughput, nothing induced
```

It ends with `soak: every process finished clean` when no payload arrived
wrong and no error escaped a loop. `docs/soak.md` explains every switch, the
report lines, and what the soak has found.

## Wire Formats: Low-Level View

**Definitions**

- `magic` := the first three letters of a record, followed by one version
  byte.
- `u8/u16/u32/u64` := unsigned integers of 1/2/4/8 bytes, little-endian.
- `offset` := byte position, from 0, inside one layer.

Every magic (three letters + version byte) makes the first four bytes of a
layer read as a name and a number:

```text
DAC   -> chunking, parity, receipts, repair       (dac/level*, no framing)
AME4  -> routing header, then one FOMKE envelope   (ame/level2/wire.nim)
FOMKE -> the message envelope: header, tag, ct     (fomke/level2/wire.nim)
FKU1  -> rotation confirmation                     (fomke/level2/wire.nim)
```

Handshake records travel as ordinary AME frames with a handshake kind, because
there are no session keys yet:

```text
AMC2  -> client hello   (kind 0x0C)
AMR2  -> hello retry    (kind 0x0D)  -- the cookie
AMS2  -> server hello   (kind 0x0E)
AMF2  -> client finish  (kind 0x0F)
ASP1  -> secure package, for stored bytes
```

The three letters name the RECORD (C = client hello, S = server hello, R =
retry, F = finish). They are not authentication modes: AMS2 is the server
hello in every mode; AM1S is the pin mode.

### One layer of encryption

After the handshake, the body of an AME frame is one FOMKE envelope. Nothing
wraps it, and nothing is inside it but the application's bytes. A frame is
sealed exactly once.

```text
PHASE A -- the handshake (no session keys yet)
  [stream 4] -> AME4 header (kind 0x0C..0x0F) -> AMC2/AMR2/AMS2/AMF2

PHASE B -- after the handshake
  [stream 4] -> AME4 header -> FOMKE envelope -> plaintext
```

### Which mask does which job ⌜guide⌟

A tier (one mask per family) has six masks. Each mask switches slots on for
**one** job and is never used for another:

```text
mask        used for                                    where
----------  ------------------------------------------  -----------------------
KEM         which KEM exchanges run                     exchange_paths
cipher      the keystreams a payload is XORed through   tier_aead (ameTierCrypt)
MAC         THE tag of a frame -- one per frame         tier_aead (ameTierTag)
hash        transcript hash, stack, selection hash --   suites (hashAmeTier)
            never a tag
signature   identity proofs and signed rotations        suites / handshake
KDF         header keys and storage keys                derivation
```

**One tag per frame.** The tag of the cipher and the "MAC on the wire" are
the same tag. It covers the ciphertext AND the AME header (the AAD), so an
edited header fails the tag:

```text
key block (ONE GB3HKDF call on MK(i)):
[ nonce | cipher key, slot 0 | cipher key, slot 1 | MAC key, slot 0 | MAC key, slot 1 ]
          └────────── cipher mask ──────────────┘   └────────── MAC mask ───────┘

plaintext ─XOR cipher 0─XOR cipher 1─▶ ciphertext
tag = MAC0(input) XOR MAC1(input)     input = layout | tier | AME header | nonce | ciphertext
```

Every cipher slot and every MAC slot has its **own** 32-byte key from its own
position in the key block. No key is used by two algorithms. A second wire MAC
would add bytes to every frame and cover nothing the one tag does not.

Three places use fixed BLAKE3 on purpose, outside the masks: header
protection (both endpoints must always agree, see below), the cookie (only
the responder checks it), and the AM1P proofs and binder (the PSK is the
post-quantum anchor, and BLAKE3 is in every build). MKs always come from
GB3HKDF, never from the KDF mask.

### TCP stream frame

```text
offset 0        4
       +--------+------------------+
       | Len32  | Payload          |
       | 4 B    | Len bytes        |
       +--------+------------------+
Total = 4 + Len
```

### DAC word: no frame of its own

A DAC word is the body of an AME frame. Its DAC kind is the first byte of that
body:

```text
  +------------- one AME frame -------------+
  | AME header | FOMKE | tag | ciphertext   |
  +------------------------------|----------+
                                 |
                    +------------v-------------+
                    | DAC kind u8 | DAC body   |
                    +--------------------------+
```

The DAC kind is readable only after the tag matched. DAC once had its own
27-byte envelope with an unencrypted, unauthenticated DAC kind, and a frame
from an unknown address could claim a slot in the link table. That envelope is
gone:

| field | why it is gone |
|---|---|
| Magic, Ver | the AME header names the frame and its version |
| Kind | now the first byte of the sealed body, so it is authenticated |
| Flags | never read by the other endpoint |
| Session, Lane, Seq | the AME header carries all three, under the tag |
| Epoch | AME epochs are the only epochs |
| BodyLen | the carrier delimits the frame; the tag covers the length |

### AME frame: fixed **26 B** header

**Definitions**

- `Seq` := the frame counter of one lane, +1 per frame.
- `header key` := per epoch and per direction, the key that masks `Seq`.
- `session id label` := the `sessionId` field in the header. Rotates.
- `session identity` := `auth.sessionId`, mixed into every key. Never rotates.

Magic `"AME"`, version byte **4**.

```text
offset  0     3    4     5      6        14      18     22      26
        +-----+----+-----+------+--------+-------+------+------+---------+
        | AME |Ver | Kind|Cls+Fl| Session|RootLn | Lane | Seq  | Payload |
        | 3B  |u8  | u8  | u8   | u64    |u32    | u32  | u32  | n bytes |
        +-----+----+-----+------+--------+-------+------+------+---------+
Total = 26 + n
```

- **No payload length.** The carrier delimits the frame: TCP by its 4-byte
  prefix, DAC by the datagram. The tag covers the ciphertext length. A frame
  cut in transit fails its tag.
- **No parent lane id.** It always equalled the root lane id.

Byte 5 holds two fields:

```text
bit  7   6   5   4   3   2   1   0
     |   |   |   |   |   +---+---+-- message class (eight values)
     |   |   |   |   +-------------- payload is padded
     +---+---+---+------------------ unused, refused unless 0
```

The header is unencrypted: a receiver must read it to pick its keys. It is
**authenticated**: every byte is AAD (covered by the tag). Clearing the
padded bit does not make a receiver treat filler as data; the frame fails to
open. An unknown flag bit is refused, not ignored.

Kinds: `0x04` ExchangeKeys, `0x05` ExchangeEnvelopes, `0x06` EpochReady,
`0x07` LaneData, `0x0B` DacControl, `0x0C..0x0F` the four handshake records,
`0x10` SessionIdRequest, `0x11` SessionIdAssign.

#### The masked field: Seq at offset 22 ⌜guide⌟

Authenticated is not private. Seq (the frame counter) grows by one per frame:

```text
watching one link              watching two links
-----------------              -------------------------------------------
how much was sent              "these two flows count up together, so they
when it was idle                are the same conversation"
when it restarted
```

The second column defeats a relay: frames in and frames out would match by
counter. So the four bytes at offset 22 are masked with the header key
(per-epoch, per-direction masking key):

```text
offset 0          22        26        39            55
       +----------+---------+---------+-------------+-------------+
       | AME ...  |   Seq   | FOMKE   |  sample     | ciphertext  |
       |          | masked  | 13 B    |  16 B       |             |
       +----------+----|----+---------+------|------+-------------+
                       |                     |
                       |     BLAKE3-MAC(header key, sample) -> 4 B
                       |                     |
                       +<------- XOR --------+
```

The sample is 16 bytes of the **tag**, which differs on every frame, so the
mask does too. A mask derived from Seq itself would give equal bytes for equal
counters.

Unmasking is the same XOR. The sample lies outside the masked bytes, so a
receiver reads it first.

- **This is not a second encryption layer.** It hides one counter from an
  observer. An edit gains nothing: a flipped bit changes the Seq the receiver
  recovers, that Seq is tag input, and the frame fails to open.
- **The header key is derived once per epoch and direction**, never per frame.
  Deriving it runs every switched-on KDF slot; masking is one keyed BLAKE3
  call over 16 bytes.
- **BLAKE3, not Gimli.** Both endpoints must produce the same mask, and it
  cannot be negotiated. `-d:bifrostSymmetric=` could leave Gimli out of one
  build; BLAKE3 is always compiled.

#### Rotating the session id label ⌜guide⌟

With Seq masked, the session id label (routing value in the header) is the
last field that links frames: eight equal bytes on every frame. It rotates in
two frames:

```text
requester                             answerer
---------                             --------
SessionIdRequest  ------------------>
                                      picks an unused id
                  <------------------ SessionIdAssign (new id inside)
takes the new id                      takes the new id
```

Both frames are sealed under the **old** label, the only one both endpoints
share during the exchange. Each endpoint switches only after the assign frame
is sealed or opened.

| | what it is | rotates? |
|---|---|---|
| `auth.sessionId` | the session identity, mixed into every key | never |
| `sessionId` | the session id label, for routing | yes |

Rotating the label derives nothing again. Every traffic key, both header keys
and every sealed package stay the same. The label is still under the tag.

The receiver accepts the previous label for `ameSessionIdGraceFrames` (100)
more frames, for one carrier only:

```text
TCP   order is guaranteed; every frame after the assign has the new label
DAC   datagrams reorder; a frame sealed before the assign can arrive after it
```

The grace window holds one integer, not a key.

### Padding

Off by default. It is a property of the epoch, so both endpoints hold the same
value or the frame is refused. `setAmePadding(S, apadBlock64)` stages it; it
takes effect at the next rotation, inside the offer, like the tag length. The
responder names it for epoch 1 in its server hello.

When on, the payload is rounded up to whole 64-byte blocks before sealing
(same filler rule as packages, count in the last byte) and the padded bit is
set in the header. It costs **1 to 64 bytes on every frame**. Switch it on
when message sizes would reveal something (which command, who is typing).
`ameFrameOverheadBytes(S)` returns the worst-case bytes per frame, for sizing
datagrams against an MTU (maximum transmission unit).

### FOMKE envelope: header **13 B**

```text
offset  0       4            12     13
        +-------+------------+------+--------+------------+
        | Epoch | Index      | Lane | Tag    | Ciphertext |
        | u32   | u64        | u8   | T bytes| n bytes    |
        +-------+------------+------+--------+------------+
Total = 13 + T + n     (T is 16, 24 or 32; n equals the plaintext length)
```

Four fields are **absent** on purpose:

- **No magic, no version.** The envelope only travels as the body of an AME
  frame, whose kind already names it.
- **No nonce.** Both endpoints derive it from the same step. 24 bytes saved
  per message, and one less field an attacker can set.
- **No ciphertext length.** It is whatever follows the tag.
- **No tag length.** The receiver uses the length its own epoch agreed and
  would refuse any other. A frame of the previous epoch is refused, and the
  carrier sends it again. A package can outlive its epoch; it carries its own
  tag length in its `ASP` (secure package) header.

The tag covers: a label, the layout, the tier, the tag length, the message's
epoch, index and lane, the AAD (the whole AME header), and the ciphertext.

### FKU1 commit (rotation confirmation): fixed **108 B**

Travels inside an authenticated EpochReady frame.

### Size table (default tier, 32-byte tag)

| item | bytes |
|---|---:|
| stream header | 4 |
| AME header | 26 |
| FOMKE header + tag | 13 + 32 = 45 |
| FKU1 | 108 |
| **TCP data overhead** | **4 + 26 + 45 + P = 75 + P** |
| **DAC data overhead** | **27 + 26 + 45 + P = 98 + P** |

With a 16-byte tag the last two are **59 + P** and **82 + P**.

| | AME header | envelope + tag | per frame |
|---|---:|---:|---:|
| two nested AEADs | 36 | 12 + 24 + 32, then 27 + 24 + 32 | **187** |
| one AEAD (encryption + one tag) | 34 | 22 + 32 | **88** |
| no repeated fields | 26 | 13 + 32 | **71** |

### Handshake records

```text
AMC2 client hello  = "AMC" | ver | session u64 | mode u8 | nonce (32)
                           | u16+layout | u16+tier | u16+cookie | ... tail
                             tail, AM1A / AM1S:    u32+offer            (unencrypted)
                             tail, AM1P / AM1P+S:  flag u8 | salt (32) | tag (32)
                                                   | u32+sealed offer   (sealed)
AMR2 hello retry   = "AMR" | ver | session u64 | u16+cookie
AMS2 server hello  = "AMS" | ver | mode u8 | nonce (32) | u32+KEM reply
                           | tagLen u8 | padding u8 | tag | u32+sealed block
AMF2 client finish = "AMF" | ver | tagLen u8 | padding u8 | tag | u32+sealed block
```

- `ver` = 2.
- `mode`: `0` AM1A, `1` AM1S, `2` AM1P, `3` AM1P+S. It alone decides which
  tail follows.
- `flag`: `1` when the sealed hello and the key schedule also took a CS
  (carried secret), `0` otherwise.

Fixed-size fields carry no length. Variable fields use `u16` where the field
is small by design and `u32` only where a post-quantum key can reach
megabytes.

The two bytes after the KEM reply are epoch 1's tag length and padding
policy. The **responder** chooses; the initiator accepts or stops. They are
unencrypted because the initiator needs them to open the next block, and the
block's tag covers them. With padding on, the sealed blocks are padded too:
hiding who connects while showing the size of their certificate would do half
the job.

A sealed block holds up to two halves, in a fixed order:

```text
server hello block                   AM1A/AM1S   AM1P   AM1P+S
  u32+name | u32 count (1) + tag         -        yes     yes
  certificate body                      yes        -      yes
  u32 count + authority signatures      yes        -      yes
  u32 count + signatures                yes        -      yes

client finish block                  AM1A/AM1S   AM1P   AM1P+S
  u32+name | u32 count (1) + tag         -        yes     yes
  certificate body                      yes        -      yes
  u32 count + authority signatures      yes        -      yes
  u32+transcript hash                   yes       yes     yes
  u32 count + signatures                yes        -      yes
```

All shapes are padded under the same policy, so the block length does not show
the mode.

The certificate body is not length-framed: it is the exact byte string the
authority signed. A length frame would make the verified bytes and the stored
bytes differ.

Offer and reply sizes grow with the KEM public keys and ciphertexts
(FireSaber pk 1312 / ct 1472; X25519 pk 32 / sender pk 32).

## Issue Playbook

**Handshake and PSK**

- **"client hello did not open under the shared secret"** (AM1P, AM1P+S): the
  two endpoints do not hold the same key for the sealed hello. Check, in
  order: the same PSK name and PSK bytes on both endpoints; the same CS
  (carried secret) on both endpoints, or none on either. An endpoint restored
  from a backup holds an older CS: remove it on both endpoints with
  `withAmeNextSecret(@[])` and start again with the PSK only.
- **"client used a next secret this side does not hold"**: the initiator kept
  a CS from an earlier session and the responder did not. Give the responder
  the same CS, or remove it from the initiator.
- **"client hello did not carry the required next secret"**: the responder
  was built with `required = true` and the initiator sent no CS. This setting
  prevents a forced fallback. Set it to `false` only while an endpoint that
  lost its CS gets a new one.
- **"client asked for an authentication mode this side does not run"**: the
  two endpoints are configured with different modes. Nothing is negotiated;
  configure both the same.
- Records from before the key-schedule rework (`ver` 1, mode names AM1C / AM1M)
  are refused with "AME handshake wire version mismatch". Both endpoints must
  run the same build. FOMKE checkpoints written before NS existed are refused
  with "FOMKE state version mismatch". There is no conversion; run a new
  handshake.
- **"certificate proof count does not match the pinned root"**: the
  certificate has fewer authority signatures than the authority has slots,
  usually from an older single-algorithm authority. Issue it again.
- **"local clock is too far outside the identity validity window"**: this
  machine's clock is more than one day outside the certificate's window. Fix
  the clock; the library does not guess.
- **"AME handshake step number is wrong"**: a record arrived where another one
  belongs. Records carry their step in the frame sequence; a wrong order is
  refused before parsing.
- `AmeAuthorityRoot` must come from `initAmeAuthorityRoot`. A hand-filled root
  with default values has an empty authority name and is refused.

**Rotation**

- A layout mismatch is refused. Compare the output of `encodeAmeSuiteLayout`.
- A tier mismatch is refused. Compare the output of `encodeAmeMaskTier`.
- A stale offer is refused. Check the request id and the base epoch id.
- A mask with a bit for an unoccupied slot is refused.
- "AME cannot start an exchange while a peer candidate epoch is pending": the
  other endpoint's rotation arrived first. Finish it, then start yours.
- "AME initiator keeps its own exchange during a simultaneous start": both
  endpoints started at once. The responder yields; nothing is lost.
- A tier whose KEM mask equals the current one rotates without a new KEM
  exchange only when `rekeyMask = 0` is passed. The default runs one.
- Data triggers count successfully transferred plaintext bytes, not bytes sent
  again.

**FOMKE**

- **"FOMKE epoch or sender lane mismatch" right after `initAmeSession`**:
  the endpoint role was set *after* `initAmeSession`. The session starts its
  lanes immediately and reads the role from the auth package, so the role must
  be right in `initAmeAuthPackage`.
- **"FOMKE KEM upgrade is pending"** when sealing: a rotation was staged before
  this endpoint finished sending. A responder calls
  `stageAmeSessionFomkeUpgrade` *after* its reply frame is sealed; the carrier
  calls already do this in that order.
- **"FOMKE upgrade confirmation mismatch"**: the two endpoints staged at
  different lane indices. Deliver outstanding messages and empty the reorder
  cache before a rotation.
- **"FOMKE skipped messages must be resolved before a KEM upgrade"**: held
  keys exist. The DAC relay erases them when a package ends; without the relay,
  call `discardAmeSessionSkipped`.
- `fomkeReorderCeiling` outside 4 .. 4096 in `config.toml` refuses the whole
  config at load time. Raise it for links that reorder heavily, not for loss:
  a held key of a lost datagram is erased once it falls further behind than
  the reorder ceiling anyway.

**Builds and transports**

- AVX2 tasks produce binaries for one CPU family. Use the ordinary tasks for
  x86 machines that may lack AVX2.
- Package repair uses XOR recovery for one lost chunk and exact-chunk requests
  for more; Eir parity checks rebuilt groups.
- Native TLS accepts only TLS 1.3, X25519, Ed25519, SHA-256 and
  `TLS_CHACHA20_POLY1305_SHA256`; anything else is refused.
- Native TLS client trust is a pinned root only. Operating-system trust stores
  and RSA/ECDSA certificate paths are not supported.
- TLS record compression is absent on purpose. Compress HTTP content before
  sealing when the application negotiates a standard content encoding.
- The benchmark task keeps its binary under `--out:build/benchmarks/...`. The
  default `nimble build` command is not a supported artifact path; use
  `nimble buildLib`.
- `nix flake check path:$PWD` validates the package build, the reproducible
  TLS transport tests, and the NixOS module rules.

### Findings the evaluation tools report on purpose ⌜guide⌟

`otter-gate.sh` reports these every time. They were checked; they are the tool
being careful, not the code being wrong.

| report | reason |
|---|---|
| PLACEHOLDERS: `raiseExcludedKem` / `raiseExcludedSig` / `raiseExcludedSym` | Refusing is the whole job: a build without a family refuses a layout that names it. |
| PLACEHOLDERS: `buildTlsContext` | Only the `when not defined(ssl)` half is flagged. A build without TLS must raise there. |
| PLACEHOLDERS: `defaultAmeCompressionPolicy`, `initChunkedDecoder`, `initTls13SocketSession` | A default provider and a constructor without arguments return the same answer every time. |
| STATE: `AmeSession.lastErr`, `Tls13ClientOutput.connected` | Read by tests below `evaluation/`, which the tool does not scan for reads. |
| STATE: `DacGroupRepairReport.err` | Public API; a caller reads it. |
| DEAD CODE: unused public | Bifrost is a library; its callers live outside this tree. |
| SECRETS in `evaluation/` and `.android-sdk/` | Test vectors and a vendored NDK (Android native development kit). Not keys of ours. |
| EMBEDDED CODE | Almost all of it is Python inside the vendored NDK. |

- **Check `evaluation/` before deleting a "never read" field.** The tool does
  not scan it, so its list is a list of candidates.
- **`stage: stDone` does not silence a placeholder finding.** A routine that
  only raises or only returns a constant stays listed.

### Standing risks

- **The primitives are self-made.** GB3HKDF and the XOR-combined multi-MAC tag
  have no external analysis. The constructions around them are careful
  (domain separation, encrypt-then-MAC, transcript binding, constant-time
  comparison of secrets, all-or-nothing state updates, erased secrets), but
  that cannot rescue a weak primitive. This risk comes first.
- **Metadata is visible by design.** The AME header is authenticated but
  unencrypted: session id label, lane ids and frame length are readable on the
  path (Seq is masked). Identities are not readable; traffic patterns are.
  Padding reduces lengths to 64-byte steps; it does not hide the header or
  the time a frame was sent.
- **A sealed pre-shared hello can be replayed.** A replay gains no key (the
  answer uses a new KEM exchange) but costs the responder one KEM
  encapsulation. The cookie limits this to addresses that can receive.
- **Preparing key blocks ahead weakens forward secrecy for messages not yet
  sent.** Off by default. See the FOMKE section.

# Direct LAN Messenger

**Definitions**

- `BMSG` := the length-prefixed frame of the LAN messenger.
- `LAN` := local area network: devices on the same router or switch.

Bifrost includes an Android client and a Nim-WebUI desktop client. Both
exchange the same BMSG (length-prefixed messenger) frames as the automated
transport test.

```text
desktop :48371  <---- local Wi-Fi / Ethernet ---->  Android :48371
```

Run the desktop client:

```sh
nimble runWebui
```

Build it without starting the UI:

```sh
nimble buildWebui
```

Build both Android APKs and run the physical host/phone exchange:

```sh
nimble androidLanTest
```

No router port forwarding is needed when both devices are in the same subnet.
The machine firewall must allow phone-to-host TCP. On NixOS, add these ports
to the system configuration and rebuild:

```nix
networking.firewall.allowedTCPPorts = [ 48371 49371 ];
```

`48371` is the messenger port. `49371` is reserved for the instrumented
device test. The test checks host-to-phone traffic first, then phone-to-host
traffic, and names the firewall when only the return path is blocked.
