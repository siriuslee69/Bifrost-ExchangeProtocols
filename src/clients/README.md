# These are TEST clients, not an app

```text
  what is in here          what it is for
  -----------------------  --------------------------------------------------
  android/                 an Android node that talks to another device
  desktop/                 a desktop node (Nim-WebUI) that talks to another device
  shared/lan_message.nim   the one message shape both test nodes use
```

These clients exist to test a **connection and a data transfer between several
machines** (or VMs). That is not a local test you can run on one box: it needs two
or more devices talking to each other, so the code that plays "the other device"
lives here, next to the protocols it tests.

```text
  machine A                       machine B
  ┌─────────────────┐             ┌─────────────────┐
  │ desktop/ or a    │  BMSG/TCP  │ android/ or      │
  │ test script      │ ─────────▶ │ another desktop  │
  └─────────────────┘             └─────────────────┘
        both sides run the SAME protocols from src/protocols/
```

## The rules for this folder

- They are **test harness**, not a product app. They stay in this repo by the
  operator's decision (2026-11-12); see `agents/BORDERS.md`.
- Do **not** grow them into a product app. A real window or app belongs in its own
  repo (a client is never a library — WORKFLOW.md 2).
- Do **not** propose cutting them out to shrink the line count; the size is the
  wire job plus this test harness, and the operator chose to keep both.
- They must keep using the one shared message shape (`shared/lan_message.nim`) and
  the protocols in `src/protocols/`, never a second copy of the wire logic.