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
│   ├── level1/  <- algorithms, paths, suites, derivation, triggers, compression
│   │   ├── kems/       <- one file per KEM family
│   │   ├── sigs/       <- one file per signature family, plus the hybrid pair
│   │   └── symmetric/  <- one file per symmetric primitive
│   │       (each folder has a flag-gated dispatcher beside it)
│   ├── level2/  <- agreement, protection, trust, AME2 wire, live session
│   │   └── carriers/ <- tcp.nim and dac.nim; the flag picks which compile
│   └── level3/  <- handshake, handshake wire, secure package, and the
│                    DAC relay that assembles loop + peers + crypto
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
│   ├── level2/  <- FOM1/FKU2 bounded wire codecs
│   └── level3/  <- public operation export surface
├── preparation/
│   ├── types.nim
│   ├── gimli_batch.nim
│   └── xchacha_streams.nim  <- thin Tyr batch/scalar selector
├── tmeaead/
│   ├── types.nim
│   └── ops.nim
├── ggaead/
│   ├── types.nim
│   └── ops.nim
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
  -> AME2 frame decode            <- one framing, both carriers
  -> AME protected body (epoch + nonce + tag + ciphertext)
  -> AME auth/decrypt
  -> FOMKE auth/decrypt when enabled
  -> caller payload
```

## Initial Handshake

```text
pinned authority root
  -> verify client/server certificates and validity time
  -> verify signed ClientHello and ServerHello
  -> perform exact AME KEM exchange
  -> verify signed ClientFinish transcript hash
  -> return first AmeAuthPackage to both peers
```

Handshake records (AMC1/AMS1/AMF1) travel bare or in a TCP stream frame.
They are not wrapped in AME2 until epoch keys exist.

## Package Path

```text
plaintext
  -> bounded Eir compression
  -> AME protection
  -> DAC package plan
  -> unordered chunk delivery
  -> XOR recovery or exact repair
  -> BLAKE3 package commit
  -> AME open
  -> bounded Eir decode
  -> plaintext
```

## Write Path

```text
caller payload
  -> FOMKE directional message ratchet when enabled
  -> AME protect (epoch AEAD)
  -> AME protected body (epoch + nonce + tag + ct)
  -> AME2 frame encode            <- one framing, both carriers
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
