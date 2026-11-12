# Group enrollment 🌊

One public key — the **enroller** — lets other public keys join a group. A key can
also get in from a **predefined list**, or because the **operator added it** by hand
through the CLI. Everything reuses the existing AME identities; there is no second
key system.

```text
  predefined list ─────────────┐
  operator-added key ──────────┼──▶  the key is a member of the group
  enroller-signed enrollment ──┘
```

## ╭─ ❧ The words 🐦‍🔥

Def. 1 (enroller): one AME authority key (`AmeAuthorityKey`). Its public half
(`AmeAuthorityRoot`) is pinned in the roster. Only its signature can enroll a key
that is not already in a list.

Def. 2 (member): an AME identity (`AmeIdentityKey`). A member is named by
`ameIdentityKeyId` — 32 hex characters computed from its public keys — never by a
name it chose for itself. Renaming a member does not change who it is.

Def. 3 (enrollment): the enroller's signed admission of one member key into one
group, with a serial and a validity window.

Def. 4 (roster): the enroller pin plus two key lists — `predefined` (configuration)
and `added` (what the operator put in by hand).

## ╭─ ❧ Is this key a member of this group? 🍣

```text
  keyId = ameIdentityKeyId(memberKeys)

  keyId in predefined or added ?  ── yes ─▶  member
            │ no
  a token was presented ?         ── no ──▶  refused
            │ yes
  token.group == this group ?     ── no ──▶  refused
  token.memberKeyId == keyId ?    ── no ──▶  refused
            │ yes
  every enroller slot verifies,
  and now is inside the window ?  ── no ──▶  refused
            │ yes
          member
```

Every refusal answers `tuple[ok: false, err: ...]`; nothing raises on a stranger's
bytes. A token for one group does not open another, and a token for one key does
not admit a different key.

## ╭─ ❧ The bytes ⟡

One canonical encoding is used both as the thing the enroller signs and as the
thing that travels over the wire. Little-endian, `u32+x` means a u32 length then
that many bytes.

Enrollment token:

```text
  u8 version | u32+group | u32+memberKeyId | u64 serial
  i64 validFrom | i64 validUntil | u32 proofCount | { u32+proof } ...
```

The signed text is the domain label plus every field except the proofs:

```text
  "GROUP-ENROLL-v1" | version | group | memberKeyId | serial | validFrom | validUntil
```

Every enroller slot signs and every slot must verify, so breaking one algorithm is
not enough to forge an admission — the same key-stack rule AME certificates use.
`signAmeMessage` / `verifyAmeMessage` are reused, not a second signature path.

Roster (what the CLI keeps in a file):

```text
  u8 version | u32+enrollerName
  u8 keyCount | { u8 alg, u32+publicKey } ...
  u32 predefinedCount | { u32+keyId } ...
  u32 addedCount | { u32+keyId } ...
```

Every reader refuses a length that reaches past the end, and the counts are capped
(`enrollmentMaxKeys`, `enrollmentMaxProofs`), so a truncated or over-sized file is
refused, never read beyond what it holds.

## ╭─ ❧ The operator CLI ❧

`src/clients/cli/enrollment.nim` (run `nimble runCli`, build `nimble buildCli`):

```text
  init FILE [NAME]     make a roster and a fresh enroller; the enroller's secret
                       half goes to FILE.key — protect it, whoever holds it can
                       enroll keys
  add FILE KEYID       admit a public key by hand (32 hex characters)
  list FILE            show the enroller and both key lists
  remove FILE KEYID    take a hand-added key back out
```

The CLI is the only part of enrollment that touches a disk. The protocol module
(`protocols/enrollment`) stays bytes-in, bytes-out: who keeps the roster bytes is
the caller's business, per this repo's charter.

## ╭─ ❧ Where it sits ◈

```text
  protocols/enrollment/types          GroupEnrollment, GroupRoster, the limits
  protocols/enrollment/level0/token   issue / verify / encode / decode, enroller codec
  protocols/enrollment/level1/roster  membership, add/remove key, roster codec
  protocols/enrollment.nim            the one import
```

It is a trust primitive, not tied to the relay `rmGroup` or the archive spaces;
either can call `groupMemberAllowed` later. See `examples/group_enrollment.nim`
for the API and `evaluation/tests/test_group_enrollment.nim` for the checks,
including truncated and over-sized bytes.