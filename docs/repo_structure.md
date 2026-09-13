# Repo Structure

## Tree

```text
Bifrost-ExchangeProtocols
├── agents/
│   └── PROGRESS.md   project state and handoff notes
├── docs/
├── examples/
├── src/
│   ├── bifrost_exchange_protocols.nim
│   ├── protocols/
│   └── clients/android/
├── evaluation/
│   ├── tests/       verification and vector checks
│   ├── benchmarks/  performance measurements
│   └── statistics/  repository and code statistics
├── tools/
├── submodules/    pinned dependencies, nothing else
├── nix/           shell and dependency pins
├── web/
├── config.nims
├── bifrost_exchange_protocols.nimble
├── README.md
└── CONTRIBUTING.md
```

## Responsibility Split

```text
+----------------------+-----------------------------------------------+
| Folder               | Responsibility                                |
+----------------------+-----------------------------------------------+
| agents/              | project state and agent handoff notes         |
| docs/                | production notes and maintainer docs          |
| examples/            | runnable protocol references                  |
| src/protocols/       | canonical wire and transport code             |
| src/clients/android/ | Android harness around canonical protocol lib |
| evaluation/tests/    | verification and vector checks                |
| evaluation/benchmarks/ | performance measurements                    |
| evaluation/statistics/ | repository and code statistics              |
| tools/               | helper generators and maintenance utilities   |
+----------------------+-----------------------------------------------+
```
