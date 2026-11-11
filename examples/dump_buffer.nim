## -------------------------------------------------------------------------
## Dump <- received messages wait here until they are safely on a disk
## -------------------------------------------------------------------------
##
## Run from the repo root:
##   nim c -r examples/dump_buffer.nim
##
##   offer ──▶ waiting ──grab──▶ in the keeper's hands ──settle──▶ gone
##                ▲                      │
##                └────── give back ─────┘   (the disk refused)

import ../src/protocols/dump
import ../src/protocols/types

proc bytes(s: string): ByteSeq =
  ## s: its bytes.
  result = cast[ByteSeq](s)

var
  D: DumpBuffer = initDumpBuffer(maxRecords = 4)
  batch: DumpBatch = DumpBatch()

# three messages arrive; number 0 lets the dump count
echo D.offerDump(DumpRecord(stream: "chat/7", sender: "alice", body: bytes("one"))).state
echo D.offerDump(DumpRecord(stream: "chat/7", sender: "alice", body: bytes("two"))).state
echo D.offerDump(DumpRecord(stream: "chat/7", sender: "bob", body: bytes("three"))).state

# the keeper takes them, and the disk fails: they wait again, in their old order
batch = D.grabDump()
echo "grabbed ", batch.records.len, ", the disk refused"
discard D.giveBackDump(batch.ticket)

# second try works: only now does the dump forget them
batch = D.grabDump()
discard D.settleDump(batch.ticket)
echo "settled up to number ", D.dumpCursor("chat/7"), "; still held: ", D.count

# the sender never heard the answer and sends number 2 again: recognised
echo D.offerDump(DumpRecord(stream: "chat/7", number: 2, body: bytes("two"))).state
