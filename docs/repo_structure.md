# Repo Structure

## Tree

```text
Bifrost-ExchangeProtocols
├── .iron/
│   ├── PROGRESS.md
│   ├── conventions/
│   └── meta/
├── docs/
├── examples/
├── src/
│   ├── bifrost_exchange_protocols.nim
│   ├── protocols/
│   └── clients/android/
├── tests/
├── tools/
├── bifrost_exchange_protocols.nimble
├── README.md
└── CONTRIBUTING.md
```

## Responsibility Split

```text
+----------------------+-----------------------------------------------+
| Folder               | Responsibility                                |
+----------------------+-----------------------------------------------+
| .iron/               | coordination, conventions, progress           |
| docs/                | production notes and maintainer docs          |
| examples/            | runnable protocol references                  |
| src/protocols/       | canonical wire and transport code             |
| src/clients/android/ | Android harness around canonical protocol lib |
| tests/               | verification and vector checks                |
| tools/               | helper generators and maintenance utilities   |
+----------------------+-----------------------------------------------+
```
