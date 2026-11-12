## -------------------------------------------------------------------------
## Dump Buffer <- offer, grab, settle: nothing leaves until it is on a disk
## -------------------------------------------------------------------------
##
##   call          what it does
##   ------------  ----------------------------------------------------------
##   offerDump     one message in; refused when full, never throws one out
##   grabDump      the oldest waiting messages, as one batch with a ticket
##   settleDump    "that batch is on disk": the memory is freed
##   giveBackDump  "that batch failed": it waits again, in its old place
##
## Example 1. A crash between the disk and the word "settled":
##
##   offer a/1  grab  write to disk  CRASH
##   restart: restoreDumpCursor("a", 0), the sender resends a/1
##   the keeper sees a/1 again and must treat it as already written
##   a/1 is written at most once in effect, and never lost
##
## Example 2. Numbers with a gap (a/3 is late):
##
##   settle 1, 2, 4   settled = 2, ahead = [4]
##   settle 3         settled = 4, ahead = []
##
## The buffer keeps order per grab: a batch holds records in the order they
## were offered, and a batch given back returns to the front.

import std/[algorithm, deques, tables]

import ../types
import runePragmas
import var_invariants

proc initDumpBuffer*(maxRecords: int = dumpDefaultMaxRecords,
    maxBytes: int = dumpDefaultMaxBytes,
    maxStreams: int = dumpDefaultMaxStreams): DumpBuffer {.role: configurator,
    tag: "dump|appApi",
    needs: maxRecords > 0 and maxBytes > 0 and maxStreams > 0.} =
  ## maxRecords/maxBytes: the most it holds. Both are ceilings, not reservations.
  ## maxStreams: the most streams it remembers (see `forgetDumpStream`).
  result.maxStreams = maxStreams
  result.maxRecords = maxRecords
  result.maxBytes = maxBytes
  result.waiting = initDeque[DumpRecord]()
  result.grabbed = initTable[uint64, seq[DumpRecord]]()
  result.lines = initTable[string, DumpLine]()
  result.nextTicket = 1'u64

proc lineOf(D: var DumpBuffer, stream: string): var DumpLine {.role: helper.} =
  ## D/stream: this stream's memory, made when first seen.
  if not D.lines.hasKey(stream):
    D.lines[stream] = DumpLine(nextAuto: 1'u64)
  result = D.lines[stream]

proc alreadyHere(L: DumpLine, n: uint64): bool {.role: parser, inline.} =
  ## L/n: true when this number is waiting, in somebody's hands, or settled.
  result = n <= L.settled or L.ahead.binarySearch(n) >= 0 or n in L.held

proc offerDump*(D: var DumpBuffer, R: DumpRecord): DumpOffered {.role: actor,
    tag: "dump|appApi".} =
  ## D: the dump. R: the message; number 0 asks the dump to count (Def. 2).
  ## Nothing already held is ever thrown out to make room.
  var
    T: DumpRecord = R
  if R.stream.len == 0 or R.stream.len > dumpNameMax or
      R.sender.len > dumpNameMax or R.body.len > D.maxBytes:
    return DumpOffered(state: doRefused)
  if not D.lines.hasKey(R.stream) and D.lines.len >= D.maxStreams:
    return DumpOffered(state: doFull)
  if T.number == 0'u64:
    T.number = max(D.lineOf(R.stream).nextAuto, D.lineOf(R.stream).settled + 1'u64)
  result.number = T.number
  if D.lineOf(R.stream).alreadyHere(T.number):
    result.state = doDuplicate
    return
  if D.count >= D.maxRecords or D.bytes + R.body.len > D.maxBytes:
    result.state = doFull
    return
  D.lineOf(R.stream).held.add(T.number)
  D.lineOf(R.stream).nextAuto = max(D.lineOf(R.stream).nextAuto, T.number + 1'u64)
  D.bytes = D.bytes + R.body.len
  D.count = D.count + 1
  D.waiting.addLast(T)
  result.state = doTaken

proc grabDump*(D: var DumpBuffer, maxRecords: int = 256,
    maxBytes: int = 16 * 1024 * 1024): DumpBatch {.role: actor,
    tag: "dump|appApi", needs: maxRecords > 0.} =
  ## D: the dump. maxRecords/maxBytes: the size of one batch; one record is
  ## always handed out even when it alone is larger than maxBytes.
  var
    n: int = 0
  while D.waiting.len > 0 and result.records.len < maxRecords and
      (result.records.len == 0 or n + D.waiting.peekFirst().body.len <= maxBytes):
    n = n + D.waiting.peekFirst().body.len
    result.records.add(D.waiting.popFirst())
  if result.records.len == 0:
    return
  result.ticket = D.nextTicket
  D.nextTicket = D.nextTicket + 1'u64
  D.grabbed[result.ticket] = result.records

proc closeGaps(L: var DumpLine) {.role: actor, inline.} =
  ## L: `settled` moved forward over every number that now joins it.
  while L.ahead.len > 0 and L.ahead[0] <= L.settled + 1'u64:
    L.settled = max(L.settled, L.ahead[0])
    L.ahead.delete(0)

proc noteSettled(L: var DumpLine, n: uint64) {.role: actor.} =
  ## L/n: this number is on disk. A full `ahead` list closes its oldest gap by
  ## force, and counts that: the numbers in that gap can no longer be told apart
  ## from old ones.
  var
    i: int = L.held.find(n)
  if i >= 0:
    L.held.delete(i)
  if n <= L.settled or L.ahead.binarySearch(n) >= 0:
    return
  L.ahead.insert(n, L.ahead.lowerBound(n))
  L.closeGaps()
  if L.ahead.len > dumpMaxAhead:
    L.settled = L.ahead[0]
    L.givenUp = L.givenUp + 1'u64
    L.closeGaps()

proc settleDump*(D: var DumpBuffer, ticket: uint64): bool {.role: actor,
    tag: "dump|appApi".} =
  ## D/ticket: the batch is on disk; its memory is freed. False for a ticket
  ## that is not out (settled twice, or never handed out).
  if not D.grabbed.hasKey(ticket):
    return false
  for r in D.grabbed[ticket]:
    D.lineOf(r.stream).noteSettled(r.number)
    D.bytes = D.bytes - r.body.len
    D.count = D.count - 1
  D.grabbed.del(ticket)
  result = true

proc giveBackDump*(D: var DumpBuffer, ticket: uint64): bool {.role: actor,
    tag: "dump|appApi".} =
  ## D/ticket: the batch could not be written; it waits again at the front, in
  ## its old order. False for a ticket that is not out.
  var
    i: int = 0
  if not D.grabbed.hasKey(ticket):
    return false
  i = D.grabbed[ticket].len - 1
  while i >= 0:
    D.waiting.addFirst(D.grabbed[ticket][i])
    i = i - 1
  D.grabbed.del(ticket)
  result = true

proc dumpCursor*(D: DumpBuffer, stream: string): uint64 {.role: parser,
    tag: "dump|appApi".} =
  ## D/stream: every number up to this one is on disk (Def. 3).
  if D.lines.hasKey(stream):
    result = D.lines[stream].settled

proc restoreDumpCursor*(D: var DumpBuffer, stream: string, settled: uint64) {.
    role: actor, tag: "dump|appApi".} =
  ## D/stream/settled: after a restart, what the disk says it already holds.
  ## Lower than what the dump knows changes nothing.
  D.lineOf(stream).settled = max(D.lineOf(stream).settled, settled)
  D.lineOf(stream).nextAuto = max(D.lineOf(stream).nextAuto, settled + 1'u64)
  D.lineOf(stream).closeGaps()

proc forgetDumpStream*(D: var DumpBuffer, stream: string): bool {.role: actor,
    tag: "dump|appApi".} =
  ## D/stream: stop remembering a stream that will not be fed again (a sender
  ## that left for good), so its place is free for another. False, and nothing
  ## changes, while one of its records is still waiting or in somebody's hands.
  ## After this the dump no longer knows which of its numbers are on disk: the
  ## keeper gives that back with `restoreDumpCursor` if the stream returns.
  if not D.lines.hasKey(stream):
    return true
  if D.lines[stream].held.len > 0:
    return false
  D.lines.del(stream)
  result = true

proc dumpWaiting*(D: DumpBuffer): int {.role: parser, inline, tag: "dump".} =
  ## D: records not handed out yet.
  result = D.waiting.len

proc dumpBrakeLevel*(D: DumpBuffer): uint8 {.role: parser, tag: "dump|appApi".} =
  ## D: how hard senders should slow down, 0 to 3, the words a relay's brake
  ## already understands (relay/relay_brake.nim).
  ##
  ##   fuller than  50%  75%  90%
  ##   level         1    2    3
  var
    a: int = D.count * 100 div D.maxRecords
    b: int = int(D.bytes.int64 * 100'i64 div D.maxBytes.int64)
    fill: int = max(a, b)
  if fill >= 90: return 3'u8
  if fill >= 75: return 2'u8
  if fill >= 50: return 1'u8
  result = 0'u8
