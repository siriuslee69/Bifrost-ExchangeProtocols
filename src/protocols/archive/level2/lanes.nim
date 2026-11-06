## -------------------------------------------------------------------------
## Archive Lanes <- the order of records: who writes where next, what is missing
## -------------------------------------------------------------------------
##
## No forward secrecy here, and no disk: these are the RULES of the order. The
## caller (Nebel) keeps the bytes this file hands out and gives them back.
##
##   writing device                       reading device
##   --------------                       --------------
##   nextArchiveSend ── position ──▶      seal, store once
##     mustSave? write `state` FIRST      fetch ──▶ noteArchiveRead
##                                          in order / after a gap / late /
##                                          duplicate
##
## A record's NUMBER on its lane is epoch * epochSize + index:
##
##   epochSize 256:   (epoch 0, index 0)   -> 0
##                    (epoch 0, index 255) -> 255
##                    (epoch 1, index 0)   -> 256
##
## ╭─ ❧ Def. 1: the saved state of a sending lane, fixed 19 B 🌊
##
##   offset 0     1        5      7           9                17
##          +-----+--------+------+-----------+----------------+-------------+
##          | ver | lane   | gen  | epochSize | reservedUntil  | reserveStep |
##          | u8  | u32    | u16  | u16       | u64            | u16         |
##          +-----+--------+------+-----------+----------------+-------------+
##
## ╭─ ❧ Def. 2: reserving ahead, so a crash never reuses a number 🐦‍🔥
##
##   reserveStep 4
##   number    0    1    2    3  | 4    5    6    7  | 8 ...
##   save      ^ "reserved until 4"  ^ "reserved until 8"
##   crash after sealing 5 -> restart at 8; 6 and 7 are never used
##
## A record is sealed only at a number below what is SAVED as reserved. So
## the newest saved state is always ahead of everything ever sealed, and a
## restart from it can only skip numbers, never repeat one. The salt in every
## record (../level1/log.nim) is the second net, for a state restored from an
## old backup.
##
## ╭─ ❧ Def. 3: whose lane is it? 🍣
##
##   lane has a lane record in MY vault                   -> aloOwn
##   otherwise, and its first record lists one of MY lanes -> aloConflict
##   otherwise                                             -> aloPeer
##
## A lane record can only be sealed by its owner (it lives in the owner's
## vault), so no other member can make a lane look like mine. A server that
## HIDES one of my lane records would make my old records look like another
## member's; the first record of every lane lists the lanes its writer knows
## of its own user (`encodeArchiveLaneList`), which is what catches that.

import ../../types
import ../../ame/level0/bytes
import ../types
import runePragmas
import var_invariants

proc archiveNumberOf*(P: ArchivePosition, epochSize: uint16): uint64 {.
    role: math, tag: "archive", needs: epochSize > 0'u16.} =
  ## P/epochSize: the record's number on its lane (see the top).
  result = uint64(P.epoch) * uint64(epochSize) + uint64(P.index)

proc archivePositionOf*(gen: uint16, lane: uint32, n: uint64,
    epochSize: uint16): ArchivePosition {.role: math, tag: "archive",
    needs: epochSize > 0'u16.} =
  ## gen/lane/n/epochSize: the position of number n on that lane.
  if n div uint64(epochSize) > uint64(high(uint32)):
    raise newException(ValueError, "archive lane is exhausted")
  result = ArchivePosition(gen: gen, lane: lane,
    epoch: uint32(n div uint64(epochSize)),
    index: uint16(n mod uint64(epochSize)))

## ╭⟢ writing

proc initArchiveSendLane*(lane: uint32, gen: uint16,
    epochSize: uint16 = archiveDefaultEpochSize,
    reserveStep: uint16 = archiveDefaultReserveStep): ArchiveSendLane {.
    role: truthBuilder, tag: "archive|appApi",
    needs: epochSize > 0'u16 and reserveStep > 0'u16.} =
  ## lane/gen/epochSize/reserveStep: a lane this device starts writing.
  ## Nothing is reserved yet: the first `nextArchiveSend` asks for a save.
  result.lane = lane
  result.gen = gen
  result.epochSize = epochSize
  result.next = 0'u64
  result.reservedUntil = 0'u64
  result.reserveStep = reserveStep

proc encodeArchiveSendLane*(L: ArchiveSendLane): ByteSeq {.role: dataWriter,
    tag: "archive|wire", gives: result.len == archiveSendStateBytes.} =
  ## L: Def. 1. What the caller keeps on disk for this lane.
  result.add(archiveRecordVersion)
  appendAmeU32(result, L.lane)
  appendAmeU16(result, L.gen)
  appendAmeU16(result, L.epochSize)
  appendAmeU64(result, L.reservedUntil)
  appendAmeU16(result, L.reserveStep)

proc resumeArchiveSendLane*(A: openArray[uint8]): ArchiveSendLane {.
    role: parser, tag: "archive|appApi|wire".} =
  ## A: the newest saved state (Def. 1). The lane goes on at `reservedUntil`:
  ## every number below it may already have been sealed (Def. 2).
  if A.len != archiveSendStateBytes or A[0] != archiveRecordVersion:
    raise newException(ValueError, "archive lane state is malformed")
  result.lane = uint32(A[1]) or (uint32(A[2]) shl 8) or (uint32(A[3]) shl 16) or
    (uint32(A[4]) shl 24)
  result.gen = readAmeU16(A, 5)
  result.epochSize = readAmeU16(A, 7)
  result.reservedUntil = readAmeU64(A, 9)
  result.reserveStep = readAmeU16(A, 17)
  result.next = result.reservedUntil
  if result.epochSize == 0'u16 or result.reserveStep == 0'u16:
    raise newException(ValueError, "archive lane state is malformed")

proc nextArchiveSend*(L: var ArchiveSendLane): ArchiveSendStep {.
    role: actor, tag: "archive|appApi".} =
  ## L: the lane. Returns where the next record goes and moves past it.
  ## When `mustSave`, the caller writes `state` BEFORE sealing (Def. 2); if
  ## that write fails, it drops this position and asks again.
  result.position = archivePositionOf(L.gen, L.lane, L.next, L.epochSize)
  result.mustSave = L.next >= L.reservedUntil
  if result.mustSave:
    L.reservedUntil = L.next + uint64(L.reserveStep)
    result.state = encodeArchiveSendLane(L)
  L.next = L.next + 1'u64

proc renewArchiveSendLane*(L: ArchiveSendLane, gen: uint16): ArchiveSendLane {.
    role: truthBuilder, tag: "archive|appApi".} =
  ## L/gen: the same lane number in a new generation of the space, from 0.
  result = initArchiveSendLane(L.lane, gen, L.epochSize, L.reserveStep)

## ╭⟢ reading

proc initArchiveReadLane*(lane: uint32, gen: uint16,
    epochSize: uint16 = archiveDefaultEpochSize): ArchiveReadLane {.
    role: truthBuilder, tag: "archive|appApi", needs: epochSize > 0'u16.} =
  ## lane/gen/epochSize: a lane this device starts reading, from number 0.
  result.lane = lane
  result.gen = gen
  result.epochSize = epochSize
  result.next = 0'u64
  result.missing = @[]
  result.givenUp = 0'u64

proc missingIndexOf(R: ArchiveReadLane, n: uint64): int {.role: parser.} =
  ## R/n: where n sits in `missing`, or -1.
  var
    i: int = 0
  while i < R.missing.len:
    if R.missing[i] == n:
      return i
    i = i + 1
  result = -1

proc noteArchiveGap(R: var ArchiveReadLane, n: uint64) {.role: actor.} =
  ## R/n: every number from R.next up to n-1 becomes missing. The list holds
  ## at most archiveMaxMissing; the oldest are given up first.
  var
    k: uint64 = R.next
  while k < n:
    R.missing.add(k)
    k = k + 1'u64
  while R.missing.len > archiveMaxMissing:
    R.missing.delete(0)
    R.givenUp = R.givenUp + 1'u64

proc noteArchiveRead*(R: var ArchiveReadLane, P: ArchivePosition): ArchiveReadStep {.
    role: actor, tag: "archive|appApi".} =
  ## R/P: a record of this lane OPENED (its tag checked) at position P.
  ## Call it only after `openArchiveLog` said ok: a forged position must not
  ## move the lane.
  var
    n: uint64 = 0'u64
    i: int = -1
  if P.lane != R.lane or P.gen != R.gen or P.index >= R.epochSize:
    raise newException(ValueError, "archive record is not of this lane")
  n = archiveNumberOf(P, R.epochSize)
  if n == R.next:
    R.next = n + 1'u64
    return arsInOrder
  if n > R.next:
    R.noteArchiveGap(n)
    R.next = n + 1'u64
    return arsAfterGap
  i = R.missingIndexOf(n)
  if i < 0:
    return arsDuplicate
  R.missing.delete(i)
  result = arsLate

proc archiveHeldBack*(R: ArchiveReadLane, claimed: ArchivePosition): uint64 {.
    role: parser, tag: "archive|appApi".} =
  ## R/claimed: another member says it has seen this lane up to `claimed`
  ## (inclusive). Returns how many of those records this reader still lacks:
  ## not yet arrived, or held back by the store. 0 when nothing is owed.
  var
    upTo: uint64 = archiveNumberOf(claimed, R.epochSize) + 1'u64
    owed: uint64 = 0'u64
  if claimed.lane != R.lane or claimed.gen != R.gen:
    return 0'u64
  if upTo > R.next:
    owed = upTo - R.next
  for m in R.missing:
    if m < upTo:
      owed = owed + 1'u64
  result = owed

## ╭⟢ whose lane

proc encodeArchiveLaneList*(A: openArray[uint32]): ByteSeq {.role: dataWriter,
    tag: "archive|wire", needs: A.len <= 255.} =
  ## A: the lanes of ONE user in one space that the writer knows of, its own
  ## included. The first record of every lane carries this (Def. 3).
  ##
  ##   count u8 | count × lane u32
  result.add(uint8(A.len))
  for l in A:
    appendAmeU32(result, l)

proc decodeArchiveLaneList*(A: openArray[uint8]): seq[uint32] {.role: parser,
    tag: "archive|wire".} =
  ## A: bytes from `encodeArchiveLaneList`. Raises when the count is wrong.
  var
    i: int = 0
    o: int = 1
  if A.len == 0 or A.len != 1 + 4 * int(A[0]):
    raise newException(ValueError, "archive lane list is malformed")
  while i < int(A[0]):
    result.add(uint32(A[o]) or (uint32(A[o + 1]) shl 8) or
      (uint32(A[o + 2]) shl 16) or (uint32(A[o + 3]) shl 24))
    o = o + 4
    i = i + 1

proc archiveLaneOwner*(own: openArray[uint32], lane: uint32,
    firstListing: openArray[uint32]): ArchiveLaneOwner {.role: parser,
    tag: "archive|appApi".} =
  ## own: the lanes this user's lane records name in this space.
  ## lane/firstListing: the lane, and what its first record listed (Def. 3).
  if lane in own:
    return aloOwn
  for l in firstListing:
    if l in own:
      return aloConflict
  result = aloPeer
