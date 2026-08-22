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
│   └── tls_ops.nim
├── bfx2/
├── ame.nim      <- the one public AME surface, and the two build flags
├── ame/
│   ├── types.nim
│   ├── level0/  <- bits, bytes, protocol descriptor
│   ├── level1/  <- algorithms, paths, suites, derivation, triggers, compression,
│   │                and tier_aead: the one cipher-XOR + MAC-XOR construction
│   │   ├── kems/       <- one file per KEM family
│   │   ├── sigs/       <- one file per signature family, plus the hybrid pair
│   │   └── symmetric/  <- one file per symmetric primitive
│   │       (each folder has a flag-gated dispatcher beside it)
│   ├── level2/  <- agreement, at-rest protection, trust, AME wire, session
│   │   └── carriers/ <- tcp.nim and dac.nim; the flag picks which compile
│   └── level3/  <- handshake, its wire and transport, the TCP handshake
│                    driver, secure package, and the DAC relay that
│                    assembles loop + peers + crypto
├── dac/
│   ├── types.nim
│   ├── level0/  <- framing, transport, body codecs, sender/receiver helpers
│   ├── level1/  <- DAC1 message bodies, plus the self-inferred ACK/repair pacing
│   ├── level2/  <- package planning, XOR/Reed-Solomon repair, exact repair, commit
│   └── level3/  <- the link loop that drives all of it, plus the bounded
│                    per-peer link table; both transport-agnostic
├── fomke/
│   ├── types.nim
│   ├── level0/  <- GB3HKDF and protocol descriptor
│   ├── level1/  <- directional chains and exact AME upgrade commits
│   │                (the ratchet is the ONLY payload protection)
│   ├── level2/  <- envelope/FKU1 bounded wire codecs, plus the checkpoint store
│   └── level3/  <- public operation export surface
├── preparation/
│   ├── types.nim
│   ├── gimli_batch.nim
│   └── xchacha_streams.nim  <- thin Tyr batch/scalar selector
└── chunkyaead/
    ├── level0/  <- format types and memory policy
    ├── level1/  <- nonce and streaming crypto operations
    └── level2/  <- threaded file encryption, decryption, and hashing

```

## Dependency Lookup

```text
nimble task
  -> .iron/.local.gitmodules.toml override when present
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

Handshake records (AMC1/AMR1/AMS1/AMF1) travel as ordinary AME frames with a
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
