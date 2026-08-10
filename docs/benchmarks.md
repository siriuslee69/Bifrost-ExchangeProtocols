# Benchmarks

This repo now ships a committed protocol benchmark harness at
`tools/bench_protocols.nim`.

## Commands

```text
nimble benchmarks
nim c -d:release --out:build/tools/bench_protocols -r tools/bench_protocols.nim
nim c -d:release --out:build/tools/bench_protocols -r tools/bench_protocols.nim -- --iterations=10000 --payload-bytes=4096
nim c -d:release --out:build/tools/bench_protocols -r tools/bench_protocols.nim -- --only=ame_dac_seal,ame_dac_open --json-out=build/benchmarks/protocols.json
```

The default `nimble benchmarks` task runs the whole suite in release mode. The
tool itself accepts:

- `--iterations=N`
- `--warmup=N`
- `--payload-bytes=N`
- `--only=name1,name2`
- `--json-out=PATH`

Use the explicit `--out:build/tools/bench_protocols` form for direct `nim c`
invocations so the compiled helper binary stays under ignored build roots
instead of landing in `tools/`.

## Coverage

```text
+----------------+-----------------------------------------------+
| Benchmark      | Coverage                                      |
+----------------+-----------------------------------------------+
| ame_protect    | AME payload protect with representative AAD   |
| ame_open       | AME payload open with representative AAD      |
| dac_encode     | DAC1 frame encode over one package payload    |
| dac_decode     | DAC1 frame decode over one package payload    |
| bfx2_encode    | BFX2 envelope write/checksum path             |
| bfx2_decode    | BFX2 envelope read/checksum path              |
| ame_dac_seal   | AME over DAC protect + frame construction     |
| ame_dac_open   | AME over DAC open + carrier validation        |
+----------------+-----------------------------------------------+
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
