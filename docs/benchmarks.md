# Benchmarks

This repo now ships a committed protocol benchmark harness at
`evaluation/benchmarks/bench_protocols.nim`.

## Commands

```text
nimble benchmarks
nim c -d:release --out:build/benchmarks/bench_protocols -r evaluation/benchmarks/bench_protocols.nim
nim c -d:release --out:build/benchmarks/bench_protocols -r evaluation/benchmarks/bench_protocols.nim -- --iterations=10000 --payload-bytes=4096
nim c -d:release --out:build/benchmarks/bench_protocols -r evaluation/benchmarks/bench_protocols.nim -- --only=ame_dac_seal,ame_dac_open --json-out=build/benchmarks/protocols.json
```

The default `nimble benchmarks` task runs the whole suite in release mode. The
tool itself accepts:

- `--iterations=N`
- `--warmup=N`
- `--payload-bytes=N`
- `--only=name1,name2`
- `--json-out=PATH`

Use the explicit `--out:build/benchmarks/bench_protocols` form for direct `nim c`
invocations so the compiled helper binary stays under ignored build roots
instead of landing in `tools/`.

## Coverage

```text
+----------------+-----------------------------------------------+
| Benchmark      | Coverage                                      |
+----------------+-----------------------------------------------+
| ame_protect    | AME payload protect with representative AAD   |
| ame_open       | AME payload open with representative AAD      |
| dac_encode     | DAC package-chunk body encode                 |
| dac_decode     | DAC package-chunk body decode                 |
| bfx2_encode    | BFX2 envelope write/checksum path             |
| bfx2_decode    | BFX2 envelope read/checksum path              |
| ame_dac_seal   | AME over DAC seal + frame construction        |
| ame_dac_open   | AME over DAC open + carrier validation        |
+-------------------------+--------------------------------------+
| fomke_seal_1slot        | ratchet seal, one cipher + one MAC   |
| fomke_seal_2slot        | ratchet seal, two ciphers + two MACs |
| fomke_cached_seal_*     | the same, from a prepared send slot  |
| fomke_prepare8_*        | building eight prepared slots        |
+-------------------------+--------------------------------------+
```

The harness prints:

- total milliseconds
- nanoseconds per operation
- MiB/s based on plaintext or payload bytes
- sample wire bytes for the encoded frame/envelope
- optional JSON for later before/after comparison

## Policy

Run the harness when:

- AME profile defaults or protection code change
- DAC frame header or body-size rules change
- BFX2 envelope/checksum rules change
- AME carrier framing, AAD binding, or validation changes

```text
source bytes
   |
   v
AME protect/open
   |
   v
DAC frame wrap/unwrap
   |
   v
BFX2 envelope write/read
   |
   v
compare latency + bytes moved
```

Keep comparisons honest:

- compare runs on the same machine/toolchain when possible
- treat results as relative evidence, not cross-host absolutes
- keep the payload size called out in the change notes when it differs from the default

## Otter

`Otter-RepoEvaluation` and `otterBench` are still useful when a downstream repo
already depends on that harness, but this repo no longer depends on an external
benchmark framework to measure its own hot paths.

## What The Slot Numbers Mean

`fomke_seal_1slot` against `fomke_seal_2slot` prices the one decision that
changes the shape of every message: how many cipher and authenticator slots
the tier switches on.

```text
one slot   plaintext --XOR XChaCha20--> ciphertext, one BLAKE3 tag
two slots  plaintext --XOR XChaCha20--> --XOR Gimli--> ciphertext,
                     BLAKE3 tag XOR Poly1305 tag
```

Two slots costs roughly half again as much per message. What it buys is that
an attacker must break **both** ciphers and **both** authenticators rather
than the weaker of each. That is a deployment decision, not a protocol one,
which is why it is a layout setting and shows up here as a measurement.

The `cached_` variants seal from a prepared slot, so they exclude the key
derivation. The gap between a cached and an uncached seal is exactly what
`setAmeFomkePregeneration` moves off the send path — and exactly the latency
you pay for the forward secrecy of not holding future keys in memory.

## Relay forwarding time: relaySuperFastUDP against relayFastExtraFrame

`nimble benchRelay` (file: `evaluation/benchmarks/bench_relay_forward.nim`).

**What is timed.** One thing: how long the relay holds a datagram.

```text
  datagram handed to the relay ──► relay decides ──► frame ready to send
  |<-------------------- this span, per datagram -------------------->|
```

**What is NOT in it.**

- The sender's sealing and the receiver's opening. Every route frame is built
  before the clock starts, so no client or server encryption is measured.
- Sockets. Both relays are the decision half only; the kernel's receive and
  send cost is the same for both and is left out.
- The clock. Reading it twice costs 10-17 ns; that is measured on an empty
  loop and taken off the median and p99 (not off the mean).

**Setup.** 50 000 datagrams per payload size, release build, one thread.
CPU: 13th Gen Intel Core i9-13900K. Nanoseconds per datagram:

| payload | plain copy | relaySuperFastUDP (median / mean) | relayFastExtraFrame (median / mean) | extra time | ratio (mean) |
|---:|---:|---:|---:|---:|---:|
| 100 B | - | 69 / 114 | 773 / 814 | ~700 ns | 7x |
| 1200 B | 28 | 45 / 74 | 1306 / 1366 | ~1290 ns | 18x |
| 8000 B | - | 82 / 114 | 4540 / 4641 | ~4530 ns | 40x |

Two runs at 1200 B differ by under 2 %. p99 at 1200 B: 63 ns and 1852 ns.

**Reading it.**

- relaySuperFastUDP costs about one copy of the datagram plus a table lookup:
  **well under 0.2 µs**, flat in the payload size.
- relayFastExtraFrame has a fixed part (about 0.7 µs: neighbour lookup, replay
  check, opening the 16 address bytes, sealing them again) and a part that
  grows with the payload (about 0.45 ns per byte, i.e. the payload is copied
  twice on the way through). At 1200 B it is **about 1.3 µs, 18 times
  the forwarder**.
- Seen from the wire: 1.3 µs is about 770 000 datagrams per second per core
  for the extra-frame relay, against over 10 million for the forwarder. A real
  deployment is limited by the sockets long before either number.
- The payload-sized part is not cryptography (only the 16 address bytes are
  sealed). It is copying and allocation, and the code shows where:
  `openAmeRouteFrame` copies the payload into a new sequence
  (`route_wire.nim`, `result.payload = @(...)`), and `sealRouteWire` appends it
  again into the outgoing frame. Handing the payload on as a view of the
  incoming bytes would remove both. It is the first place to look if this
  relay ever needs to be faster.

### What the VIP list costs (relaySuperFastUDP, 1200 B, 100 000 datagrams)

The list is read only while the relay is congested. The worst case is measured:
8 VIPs on the list and a sender that is not one of them, so every entry is
compared. Three runs, mean per datagram (the machine was not otherwise idle, so
runs differ by about 20 ns):

| relay | run 1 | run 2 | run 3 |
|---|---:|---:|---:|
| no VIP list | 84 ns | 105 ns | 91 ns |
| 8 VIPs, not congested | 76 ns | 125 ns | 76 ns |
| 8 VIPs, congested (brake on, nothing dropped) | 95 ns | 151 ns | 98 ns |

Reading it: while nothing is congested the list adds nothing that rises above
the noise. While congested it adds roughly 10 to 45 ns per datagram, which is
small beside the ~1300 ns the extra-frame relay needs.
