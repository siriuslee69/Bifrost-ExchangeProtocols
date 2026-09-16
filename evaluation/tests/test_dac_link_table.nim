## ---------------------------------------------------------------------
## DAC Link Table <- many peers, one process, a bounded amount of memory
## ---------------------------------------------------------------------

import unittest

import ../../src/protocols/types
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/defaults
import ../../src/protocols/dac/level0/wire_helpers
import ../../src/protocols/dac/level1/package_manifest
import ../../src/protocols/dac/level3/link
import ../../src/protocols/dac/level3/link_table
import runePragmas

proc rampBytes(n: int): ByteSeq =
  ## n: payload length filled with a deterministic ramp.
  var
    i: int = 0
  result = newSeq[uint8](n)
  while i < n:
    result[i] = uint8((i * 7 + 5) mod 251)
    i = i + 1

proc peerKey(n: int): DacLinkKey =
  ## n: index turned into a distinct peer address.
  result = initDacLinkKey("10.0.0." & $n, uint16(4000 + n), dlcDatagram)

proc manifestBody(packageId: uint64): ByteSeq {.role: truthBuilder.} =
  ## packageId: identity a peer opens a conversation with.
  ##
  ## A BODY, not a frame. DAC frames nothing itself -- the AME layer carries
  ## the kind and these bytes, and the loop only ever sees them after the tag
  ## has checked out.
  var
    digest: array[32, uint8]
  digest[0] = 0x7E'u8
  result = encodeDacPackageManifest(initDacPackageManifest(packageId,
    dtcUserData, dacDefaultsFor(dscBadSignal), 4_000'u64, digest))

proc admitAndFeed(T: var DacLinkTable, k: DacLinkKey, kind: DacMessageKind,
    body: ByteSeq, sessionId: uint64, laneId: uint32,
    nowMs: uint32): DacLinkRoute {.role: orchestrator.} =
  ## Stands in for what `AmeDacRelay` does on every arriving datagram: the
  ## peer must already hold a slot from its session, and only then is its
  ## message handed to the loop.
  ##
  ## `routeDacFrame` used to do this from a bare frame, letting a stranger
  ## claim a slot by sending the right kind. That is gone: a slot comes from
  ## the handshake now, never from a datagram.
  var
    a: tuple[admit: DacLinkAdmit, slot: int] = admitDacLink(T, k, nowMs)
  result.admit = a.admit
  result.slot = a.slot
  if a.slot < 0:
    result.step.kind = dlkIgnored
    return
  T.slots[a.slot].lastSeenMs = nowMs
  result.step = feedDacMessage(T.slots[a.slot].link, kind, body, nowMs)

suite "DAC link table routing":
  # {.testKind: tkUnit.}
  test "two peers get two links and neither sees the other's package":
    var
      T: DacLinkTable = initDacLinkTable(dacDefaultsFor(dscBadSignal), 1'u64)
      a: DacLinkRoute = admitAndFeed(T, peerKey(1), dmkPackageManifest,
        manifestBody(100'u64), 5'u64, 1'u32, 0'u32)
      b: DacLinkRoute = admitAndFeed(T, peerKey(2), dmkPackageManifest,
        manifestBody(200'u64), 6'u64, 1'u32, 0'u32)
    check a.admit == dlaAdmitted
    check b.admit == dlaAdmitted
    check a.slot != b.slot
    check dacLinkTableLive(T) == 2
    check a.step.kind == dlkManifestAccepted
    check b.step.kind == dlkManifestAccepted

  # {.testKind: tkUnit.}
  test "the same peer is routed back to the link it already had":
    var
      T: DacLinkTable = initDacLinkTable(dacDefaultsFor(dscBadSignal), 1'u64)
      a: DacLinkRoute = admitAndFeed(T, peerKey(1), dmkPackageManifest,
        manifestBody(100'u64), 5'u64, 1'u32, 0'u32)
      b: DacLinkRoute = admitAndFeed(T, peerKey(1), dmkAckRange, @[],
        5'u64, 1'u32, 10'u32)
    check a.admit == dlaAdmitted
    check b.admit == dlaExisting
    check a.slot == b.slot
    check dacLinkTableLive(T) == 1

  # {.testKind: tkUnit.}
  test "one address on two carriers is two links":
    var
      T: DacLinkTable = initDacLinkTable(dacDefaultsFor(dscBadSignal), 1'u64)
      k1: DacLinkKey = initDacLinkKey("10.0.0.9", 5000'u16, dlcDatagram)
      k2: DacLinkKey = initDacLinkKey("10.0.0.9", 5000'u16, dlcStream)
    discard admitAndFeed(T, k1, dmkPackageManifest, manifestBody(1'u64),
      5'u64, 1'u32, 0'u32)
    discard admitAndFeed(T, k2, dmkPackageManifest, manifestBody(1'u64),
      5'u64, 1'u32, 0'u32)
    check dacLinkTableLive(T) == 2
    check findDacLinkSlot(T, k1) != findDacLinkSlot(T, k2)

  ## Two tests stood here and are gone with the code they guarded: "rubbish
  ## from an unknown address consumes no slot" and "a valid frame that opens
  ## nothing consumes no slot". Both fed a BARE frame from a stranger and
  ## checked the table refused it. A stranger cannot present a frame any more
  ## -- `AmeDacRelay` drops a datagram from an address holding no session
  ## before it is parsed, and the equivalent check now lives in
  ## test_attack_surface.nim, "a flood from many addresses cannot exhaust the
  ## relay".

suite "DAC link table bounds":
  # {.testKind: tkEdgeCase.}
  test "capacity is a hard number and the surplus is refused":
    var
      T: DacLinkTable = initDacLinkTable(dacDefaultsFor(dscBadSignal), 1'u64,
        capacity = 8)
      r: DacLinkRoute
      admitted: int = 0
      refused: int = 0
      i: int = 0
    while i < 64:
      r = admitAndFeed(T, peerKey(i), dmkPackageManifest, manifestBody(1'u64),
      uint64(i), 1'u32, 0'u32)
      if r.admit == dlaAdmitted:
        admitted = admitted + 1
      if r.admit == dlaRefusedFull:
        refused = refused + 1
      i = i + 1
    check admitted == 8
    check refused == 56
    check dacLinkTableLive(T) == 8
    check dacLinkTableFull(T)
    check T.refusals == 56'u32

  # {.testKind: tkEdgeCase.}
  test "a flood cannot displace a peer that is mid-transfer":
    var
      T: DacLinkTable = initDacLinkTable(dacDefaultsFor(dscBadSignal), 1'u64,
        capacity = 4, idleMs = 10'u32)
      keep: DacLinkKey = initDacLinkKey("192.168.1.5", 9000'u16, dlcDatagram)
      r: DacLinkRoute
      i: int = 0
    discard admitAndFeed(T, keep, dmkPackageManifest, manifestBody(42'u64),
      77'u64, 1'u32, 0'u32)
    check findDacLinkSlot(T, keep) >= 0
    check not dacLinkIdle(T.slots[findDacLinkSlot(T, keep)].link)
    while i < 200:
      r = admitAndFeed(T, peerKey(i), dmkPackageManifest, manifestBody(1'u64),
      uint64(i), 1'u32, uint32(100_000 + i))
      check r.admit != dlaRefusedFrame
      i = i + 1
    check findDacLinkSlot(T, keep) >= 0
    check not dacLinkIdle(T.slots[findDacLinkSlot(T, keep)].link)

  # {.testKind: tkUnit.}
  test "an idle link's slot is reused once its quiet window passes":
    var
      T: DacLinkTable = initDacLinkTable(dacDefaultsFor(dscBadSignal), 1'u64,
        capacity = 1, idleMs = 50'u32)
      first: DacLinkKey = peerKey(1)
      second: DacLinkKey = peerKey(2)
      a: tuple[admit: DacLinkAdmit, slot: int]
    a = admitDacLink(T, first, 0'u32)
    check a.admit == dlaAdmitted
    a = admitDacLink(T, second, 10'u32)
    check a.admit == dlaRefusedFull
    a = admitDacLink(T, second, 60'u32)
    check a.admit == dlaReplacedIdle
    check dacLinkTableLive(T) == 1
    check findDacLinkSlot(T, first) < 0
    check findDacLinkSlot(T, second) >= 0

  # {.testKind: tkUnit.}
  test "sweeping releases quiet links and leaves busy ones":
    var
      T: DacLinkTable = initDacLinkTable(dacDefaultsFor(dscBadSignal), 1'u64,
        capacity = 8, idleMs = 50'u32)
      busy: DacLinkKey = peerKey(99)
      i: int = 0
    while i < 4:
      discard admitDacLink(T, peerKey(i), 0'u32)
      i = i + 1
    discard admitAndFeed(T, busy, dmkPackageManifest, manifestBody(3'u64),
      70'u64, 1'u32, 0'u32)
    check dacLinkTableLive(T) == 5
    check sweepDacLinkTable(T, 10'u32) == 0
    check sweepDacLinkTable(T, 100'u32) == 4
    check dacLinkTableLive(T) == 1
    check findDacLinkSlot(T, busy) >= 0

  # {.testKind: tkUnit.}
  test "closing a link frees its slot immediately":
    var
      T: DacLinkTable = initDacLinkTable(dacDefaultsFor(dscBadSignal), 1'u64,
        capacity = 2)
      k: DacLinkKey = peerKey(3)
    discard admitAndFeed(T, k, dmkPackageManifest, manifestBody(1'u64),
      5'u64, 1'u32, 0'u32)
    check dacLinkTableLive(T) == 1
    check closeDacLink(T, k)
    check dacLinkTableLive(T) == 0
    check not closeDacLink(T, k)

  # {.testKind: tkEdgeCase.}
  test "a zero or negative capacity is refused at construction":
    expect ValueError:
      discard initDacLinkTable(dacDefaultsFor(dscBadSignal), 1'u64, capacity = 0)

suite "DAC link table transfer":
  # {.testKind: tkUnit.}
  test "two tables carry a whole package between two peers":
    var
      A: DacLinkTable = initDacLinkTable(dacDefaultsFor(dscBadSignal), 11'u64)
      B: DacLinkTable = initDacLinkTable(dacDefaultsFor(dscBadSignal), 22'u64)
      ka: DacLinkKey = initDacLinkKey("10.1.1.1", 7000'u16, dlcDatagram)
      kb: DacLinkKey = initDacLinkKey("10.2.2.2", 8000'u16, dlcDatagram)
      payload: ByteSeq = rampBytes(7_000)
      messages: seq[DacTaggedMessage] = @[]
      r: DacLinkRoute = default(DacLinkRoute)
      done: bool = false
      i: int = 0
    discard admitDacLink(A, kb, 0'u32)
    messages = beginDacPackage(dacLinkFor(A, kb)[], 5'u64, payload, 0'u32)
    check messages.len > 0
    while i < messages.len:
      r = admitAndFeed(B, ka, messages[i].kind, messages[i].body, 31'u64,
        1'u32, uint32(i))
      if r.step.kind == dlkPackageComplete:
        check r.step.payload == payload
        done = true
      i = i + 1
    check done
    check dacLinkTableLive(B) == 1

  # {.testKind: tkUnit.}
  test "each peer draws its own scramble stream from one table seed":
    var
      T: DacLinkTable = initDacLinkTable(dacDefaultsFor(dscBadSignal), 5'u64,
        capacity = 4)
      payload: ByteSeq = rampBytes(6_000)
      one: seq[DacTaggedMessage] = @[]
      two: seq[DacTaggedMessage] = @[]
      differ: bool = false
      i: int = 0
    discard admitDacLink(T, peerKey(1), 0'u32)
    discard admitDacLink(T, peerKey(2), 0'u32)
    one = beginDacPackage(dacLinkFor(T, peerKey(1))[], 9'u64, payload, 0'u32)
    two = beginDacPackage(dacLinkFor(T, peerKey(2))[], 9'u64, payload, 0'u32)
    check one.len == two.len
    while i < one.len:
      if one[i].body != two[i].body:
        differ = true
      i = i + 1
    check differ

  # {.testKind: tkEdgeCase.}
  test "an unknown peer flooding a busy table never raises":
    var
      T: DacLinkTable = initDacLinkTable(dacDefaultsFor(dscBadSignal), 1'u64,
        capacity = 4, idleMs = 5'u32)
      steps: seq[DacLinkRoute]
      i: int = 0
    while i < 300:
      discard admitAndFeed(T, peerKey(i mod 9), dmkPackageManifest,
        manifestBody(uint64(i)), uint64(i), 1'u32, uint32(i * 3))
      steps = tickDacLinkTable(T, uint32(i * 3))
      i = i + 1
    check dacLinkTableLive(T) <= 4
