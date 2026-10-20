# Code Layout

## Dependency Levels

```text
src/protocols
├── types.nim
├── config.nim
├── transport/
│   ├── types.nim
│   ├── protocols.nim
│   ├── stream_framing.nim
│   ├── tcp_ops.nim
│   ├── udp_ops.nim
│   ├── socket_write.nim   <- every byte out, or an error (std send loops on EPIPE)
│   ├── socket_read.nim    <- what has arrived (std recv waits for all n bytes)
│   ├── async_stream_ops.nim
│   └── tls_ops.nim
├── bfx2/
├── ame.nim      <- the one public AME surface, and the two build flags
├── ame/
│   ├── types.nim
│   ├── level0/  <- bits, bytes, protocol descriptor
│   ├── level1/  <- algorithms, paths, suites, derivation, the secret stack,
│   │                triggers, compression, header protection, the
│   │                Gimli route block (route_block.nim), and tier_aead: the one
│   │                cipher-XOR + MAC-XOR construction
│   │   ├── kems/       <- one file per KEM family
│   │   ├── sigs/       <- one file per signature family, plus the hybrid pair
│   │   └── symmetric/  <- one file per symmetric primitive
│   │       (each folder has a flag-gated dispatcher beside it)
│   ├── level2/  <- epochs.nim     the AmeSession type, epoch, keys, and the
│   │                               exchange steps that change them
│   │                session.nim    starting a session, reading it, settings;
│   │                               passes epochs.nim on
│   │                seal_open.nim  one frame: seal, open, the AME/DAC seam
│   │                framing.nim    conversations of frames: exchange steps,
│   │                               sending one frame safely, id rotation;
│   │                               passes seal_open and requests on
│   │                requests.nim   building a request by name
│   │                route_wire.nim    the outer "ART" route frame: sealed
│   │                                  address, replay window, open payload
│   │                route_directory.nim  "whom may I reach?" (AME kind 0x14)
│   │                lane_jump.nim  jump ask (0x15) and jump (0x16) frames
│   │                plus agreement, at-rest protection, trust, AME wire
│   │   └── carriers/ <- tcp.nim and dac.nim; the flag picks which compile
│   └── level3/  <- handshake.nim   steps 3 and 4 (finish, accept), and the
│                                   one import that brings in all the rest
│                    _hello.nim     steps 1 and 2: the (sealed) hello, the answer
│                    _authentication.nim  the four modes AM1A/AM1S/AM1P/AM1P+S
│                                   and the one AmeAuthentication object
│                    _identity.nim  identities, certificates, how each is checked
│                    _cookie.nim    proving you can receive where you claim
│                    _records.nim   the shape of the four messages
│                    _wire.nim      those same four, byte for byte
│                    _transcript.nim  the record both sides sign
│                    _tcp/_dac/_transport.nim  running one over a socket
│                    router.nim     multi-hop routing: directory, forward,
│                                   deliver to self,
│                                   return notes (docs/routing.md)
│                    plus secure package, and the DAC relay that
│                    assembles loop + peers + crypto
├── dac/
│   ├── types.nim
│   ├── level0/  <- transport, message-kind ids, body codecs (with the LE helpers), and
│   │                the path-profile table
│   ├── level1/  <- DAC message bodies, the self-inferred ACK/repair pacing,
│   │                what the receiver measures (path_meter), and what it does
│   │                about a peer's report (path_policy)
│   ├── level2/  <- package planning, XOR/Reed-Solomon repair, exact repair, commit
│   └── level3/  <- the link loop that drives all of it, plus the bounded
│                    per-peer link table; both transport-agnostic
├── fomke/
│   ├── types.nim
│   ├── level0/  <- XHKDF and protocol descriptor
│   ├── level1/  <- chain_send.nim  the epoch split [LK1|LK2|TK], the two
│   │                                 chains, sealing, children of TK
│   │                chain.nim       opening, the reorder window, and exact
│   │                                 AME upgrade commits (NK from TK + new
│   │                                 KEM -> next epoch); passes chain_send on
│   │                jump.nim        proved lane jumps (JK from TK)
│   │                (the ratchet is the ONLY payload protection)
│   ├── level2/  <- envelope/FKU1 bounded wire codecs, plus the checkpoint store
│   └── level3/  <- public operation export surface
└── chunkyaead/
    ├── level0/  <- format types and memory policy
    ├── level1/  <- nonce and streaming crypto operations
    └── level2/  <- threaded file encryption, decryption, and hashing

```

## Dependency Lookup

```text
nimble task
  -> submodules/<dependency>/src
  -> repo-local dependency folder fallback
  -> parent workspace sibling fallback
```

The checked-in production path is the `submodules/` line. The other paths exist
for local development and emergency override only.

## Config Path

```text
config.toml / userconfig.toml
  -> parseBifrostConfigText
  -> sanitizeBifrostConfig
  -> applyBifrostConfig
  -> bifrost* global defaults
```

## Read Path

```text
raw bytes
  -> transport stream frame or UDP datagram
  -> AME frame decode             <- one framing, both carriers
  -> FOMKE envelope (epoch + index + lane + tag + ciphertext)
  -> FOMKE auth, THEN decrypt     <- one layer, checked before opening
  -> caller payload
```

## Initial Handshake

```text
client hello (no identity: nonce, layout, tier, KEM public keys)
  -> optional cookie retry, before any key work is spent
  -> server encapsulates, derives a temporary key from KEM + transcript
  -> server hello: nonce and KEM answer clear, certificate SEALED
  -> client opens it, checks every authority proof, validity, serial, clock
  -> client finish: its own certificate and transcript proof, SEALED
  -> server opens it and checks the same things
  -> return first AmeAuthPackage to both peers
```

Handshake records (AMC2/AMR2/AMS2/AMF2) travel as ordinary AME frames with a
handshake packet kind (0x0C..0x0F). They are not encrypted -- there are no
session keys yet -- but each of the last two carries its own sealed block, so
no identity is ever on the wire in the clear.

## Package Path

```text
plaintext
  -> optional compression (OFF by default -- see the README)
  -> AME seal, ONCE, over the whole package
  -> DAC package plan: chunks and parity over the SEALED bytes
  -> unordered chunk delivery
  -> XOR recovery or exact repair
  -> BLAKE3 package commit
  -> AME open (one tag, checked once, on reassembled bytes)
  -> bounded decode
  -> plaintext
```

## Write Path

```text
caller payload
  -> FOMKE directional message ratchet
  -> slot construction: XOR every cipher, XOR every authenticator
  -> FOMKE envelope (no nonce, no lengths, no magic on the wire)
  -> AME frame encode             <- one framing, both carriers
  -> transport stream frame or UDP datagram send
```

## Stream Fallback

```text
TCP/TLS bytes
  -> [Len32 little endian][Payload]
  -> decodeProtocolStreamFrame
  -> ok + consumed + payload
  -> or needMore for incomplete buffers
  -> or reject oversized lengths before payload allocation
```

## Android Harness

```text
src/clients/android/app
  -> Kotlin UI/demo transport harness
  -> JNI bridge into Nim AME helpers
  -> AME public-bundle descriptors for LAN peer visibility
  -> debug-only demo security shortcuts
```
