## Dump tests <- offer, grab, settle: nothing is lost, nothing counted twice.
##
##   suite            what it holds down
##   ---------------  ------------------------------------------------------
##   "the dump"       order, duplicates, full never drops, give back, gaps
##   "after a crash"  a restored cursor refuses what is already on disk
##   "records"        the bytes of a record and of the cursors

import std/unittest

import ../../src/protocols/dump
import ../../src/protocols/types

proc rec(stream: string, n: uint64, s: string = "x"): DumpRecord =
  ## stream/n/s: a small test message.
  result = DumpRecord(stream: stream, number: n, sender: "alice",
    body: cast[ByteSeq](s))

suite "the dump":
  # {.testKind: tkUnit, covers: "offerDump|grabDump|settleDump".}
  test "records leave in order and the memory comes back":
    var D = initDumpBuffer()
    check D.offerDump(rec("a", 1)).state == doTaken
    check D.offerDump(rec("a", 2)).state == doTaken
    var b = D.grabDump()
    check b.records.len == 2 and b.records[0].number == 1'u64
    check D.count == 2
    check D.settleDump(b.ticket)
    check D.count == 0 and D.bytes == 0 and D.dumpCursor("a") == 2'u64

  # {.testKind: tkEdgeCase, covers: "offerDump".}
  test "a number seen before is refused, wherever it is":
    var D = initDumpBuffer()
    discard D.offerDump(rec("a", 1))
    check D.offerDump(rec("a", 1)).state == doDuplicate
    var b = D.grabDump()
    check D.offerDump(rec("a", 1)).state == doDuplicate
    discard D.settleDump(b.ticket)
    check D.offerDump(rec("a", 1)).state == doDuplicate

  # {.testKind: tkUnit, covers: "offerDump".}
  test "number 0 asks the dump to count":
    var D = initDumpBuffer()
    check D.offerDump(rec("a", 0)).number == 1'u64
    check D.offerDump(rec("a", 0)).number == 2'u64
    check D.offerDump(rec("b", 0)).number == 1'u64

  # {.testKind: tkEdgeCase, covers: "offerDump|dumpBrakeLevel".}
  test "a full dump refuses the new one and keeps the old ones":
    var D = initDumpBuffer(maxRecords = 2)
    discard D.offerDump(rec("a", 1))
    discard D.offerDump(rec("a", 2))
    check D.offerDump(rec("a", 3)).state == doFull
    check D.dumpBrakeLevel() == 3'u8
    var b = D.grabDump()
    check b.records.len == 2 and b.records[1].number == 2'u64
    discard D.settleDump(b.ticket)
    check D.offerDump(rec("a", 3)).state == doTaken

  # {.testKind: tkEdgeCase, covers: "offerDump".}
  test "too large for any dump is refused, not full":
    var D = initDumpBuffer(maxBytes = 4)
    check D.offerDump(rec("a", 1, "12345")).state == doRefused

  # {.testKind: tkUnit, covers: "giveBackDump".}
  test "a batch given back waits at the front in its old order":
    var D = initDumpBuffer()
    for n in 1'u64 .. 3'u64: discard D.offerDump(rec("a", n))
    var one = D.grabDump(maxRecords = 2)
    check D.giveBackDump(one.ticket)
    var two = D.grabDump()
    check two.records.len == 3 and two.records[0].number == 1'u64 and
      two.records[2].number == 3'u64
    check not D.giveBackDump(one.ticket)
    check D.count == 3

  # {.testKind: tkEdgeCase, covers: "settleDump".}
  test "settling twice is refused and frees nothing twice":
    var D = initDumpBuffer()
    discard D.offerDump(rec("a", 1))
    var b = D.grabDump()
    check D.settleDump(b.ticket)
    check not D.settleDump(b.ticket)
    check D.count == 0

  # {.testKind: tkEdgeCase, covers: "settleDump|dumpCursor".}
  test "a gap holds the cursor back until it is filled":
    var D = initDumpBuffer()
    discard D.offerDump(rec("a", 1))
    discard D.offerDump(rec("a", 2))
    discard D.offerDump(rec("a", 4))
    discard D.settleDump(D.grabDump().ticket)
    check D.dumpCursor("a") == 2'u64
    check D.offerDump(rec("a", 4)).state == doDuplicate
    discard D.offerDump(rec("a", 3))
    discard D.settleDump(D.grabDump().ticket)
    check D.dumpCursor("a") == 4'u64

  # {.testKind: tkEdgeCase, covers: "grabDump".}
  test "one record larger than the batch size still leaves":
    var D = initDumpBuffer()
    discard D.offerDump(rec("a", 1, "123456"))
    discard D.offerDump(rec("a", 2, "1"))
    check D.grabDump(maxBytes = 2).records.len == 1

suite "after a crash":
  # {.testKind: tkRegression, covers: "restoreDumpCursor".}
  test "a restored cursor refuses what the disk already holds":
    var D = initDumpBuffer()
    D.restoreDumpCursor("a", 5)
    check D.offerDump(rec("a", 5)).state == doDuplicate
    check D.offerDump(rec("a", 0)).number == 6'u64

suite "records":
  # {.testKind: tkUnit, covers: "encodeDumpRecord|decodeDumpRecord".}
  test "a record goes to bytes and back, as documented":
    var
      R = DumpRecord(stream: "a", number: 2, atMs: 3, sender: "s", body: @[0xFF'u8])
      A = encodeDumpRecord(R)
      o = 0
    check A == @[1'u8, 1, 0, 0x61, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0,
      1, 0, 0x73, 1, 0, 0, 0, 0xFF]
    var back = decodeDumpRecord(A, o)
    check o == A.len and back == R

  # {.testKind: tkEdgeCase, covers: "decodeDumpRecord".}
  test "every shortened record is refused":
    var
      A = encodeDumpRecord(rec("stream", 9, "body"))
      n = 0
    while n < A.len:
      var o = 0
      expect ValueError:
        discard decodeDumpRecord(A.toOpenArray(0, n - 1), o)
      n = n + 1

  # {.testKind: tkUnit, covers: "encodeDumpCursors|decodeDumpCursors".}
  test "cursors go to bytes and back":
    var C = @[(stream: "a", settled: 7'u64), (stream: "b", settled: 0'u64)]
    check decodeDumpCursors(encodeDumpCursors(C)) == C
