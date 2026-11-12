# Dump <- where received messages wait until they are safely on a disk

Bifrost opens frames but keeps nothing on a disk. Something else has to write
what arrives. The dump is the hand-over point between the two. It holds each
message in memory until the keeper says "that is on disk now".

```text
  network ──▶ offerDump ──▶ waiting ──grabDump──▶ in the keeper's hands
                              ▲                      │             │
                              └──── giveBackDump ────┘             │
                                                      settleDump ──┘
                                                      memory freed
```

╭⟢ 1. Definitions 🌊
├⟢ 2. The four calls 🍣
├⟢ 3. What happens in a crash ⚠️
╰⟢ 4. The bytes ❧

## 1. Definitions

```text
Def. 1 (stream)   one line of messages, named by whoever feeds the dump.
Def. 2 (number)   the place of a message in its stream, from 1. 0 asks the
                  dump to count.
Def. 3 (settled)  the keeper confirmed this number is on disk. A settled
                  number is never accepted again.
Def. 4 (ticket)   names one batch that was handed out.
```

## 2. The four calls

```nim
import protocols/dump

var D = initDumpBuffer(maxRecords = 4096, maxBytes = 64 * 1024 * 1024,
  maxStreams = 65536)
discard D.offerDump(DumpRecord(stream: "chat/7", sender: "alice", body: msg))

var batch = D.grabDump()
if writeToDisk(batch.records):
  discard D.settleDump(batch.ticket)    # the memory is freed
else:
  discard D.giveBackDump(batch.ticket)  # it waits again, in its old place
```

```text
offerDump answers   meaning                             what the sender does
──────────────────  ──────────────────────────────────  ─────────────────────
doTaken             it waits now                        nothing
doDuplicate         seen before: waiting, out, or       nothing, it arrived
                    settled
doFull              no room. Nothing was thrown out     slow down, send again
                    (records, bytes, or a NEW stream
                    name past `maxStreams`)
doRefused           it can never fit                    give up
```

The dump remembers every stream it was fed, so that a number seen before is
recognised. Stream names come from the feeder (one per sender on a relay), so
their count has a ceiling too: `maxStreams`. When a sender is gone for good,
`forgetDumpStream(D, "relay/30")` frees its place; it answers false while one
of that stream's records is still waiting.

`dumpBrakeLevel` turns how full the dump is into 0 to 3, the same words a relay's
brake already speaks.

A relay delivery goes in with `dumpDelivered(D, step, sender, nowMs)`
(`relay/relay_dump.nim`).

## 3. What happens in a crash

```text
  written to disk?   settled?   after a restart
  ─────────────────  ─────────  ─────────────────────────────────────────
  no                 no         the sender sends again; it is written once
  yes                no         the sender sends again; the keeper must
                                see that it already has that number
  yes                yes        restoreDumpCursor says so; a resend is
                                refused as a duplicate
```

So a message is never lost, and at worst offered twice. The keeper's write has
to recognise a stream and number it already holds.

## 4. The bytes

All numbers little-endian.

```text
one record   ver u8 | u16 + stream | number u64 | atMs u64 | u16 + sender | u32 + body
cursors      count u16 | count x (u16 + stream | settled u64)
```

Example 1. Stream "a", number 2, atMs 3, sender "s", body FF:

```text
01 | 01 00 61 | 02 00 00 00 00 00 00 00 | 03 00 00 00 00 00 00 00 | 01 00 73 | 01 00 00 00 FF
```
