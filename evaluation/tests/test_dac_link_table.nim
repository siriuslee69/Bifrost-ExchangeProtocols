## ---------------------------------------------------------------------
## DAC Link Table <- many peers, one process, a bounded amount of memory
## ---------------------------------------------------------------------

import unittest

import ../../src/protocols/types
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/defaults
import ../../src/protocols/dac/level0/framing
import ../../src/protocols/dac/level1/package_manifest
import ../../src/protocols/dac/level3/link
import ../../src/protocols/dac/level3/link_table
import bifrostPragmas

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

proc manifestFrame(sessionId: uint64, laneId: uint32,
    packageId: uint64): ByteSeq {.role: truthBuilder.} =
  ## sessionId/laneId/packageId: identity a peer opens a conversation with.
  var
    digest: array[32, uint8]
    flags: DacFrameFlags
    body: ByteSeq
    h: DacFrameHeader
  digest[0] = 0x7E'u8
  body = encodeDacPackageManifest(initDacPackageManifest(packageId,
    dtcUserData, dacDefaultsFor(dscBadSignal), 4_000'u64, digest))
  flags.needsAck = true
  h = initDacFrameHeader(dmkPackageManifest, sessionId, laneId, 0'u16, 0'u32,
    uint32(body.len), flags)
  result = encodeDacFrame(h, body)

proc ackFrame(sessionId: uint64, laneId: uint32): ByteSeq =
  ## sessionId/laneId: identity on a frame that refers to state, not one that
  ## starts anything.
  var
    flags: DacFrameFlags
    h: DacFrameHeader = initDacFrameHeader(dmkAckRange, sessionId, laneId,
      0'u16, 0'u32, 0'u32, flags)
  result = encodeDacFrame(h, @[])

suite "DAC frame identity peek":
  # {.testKind: tkUnit.}
  test "a well-formed frame yields its routing fields":
    var
      f: ByteSeq = manifestFrame(9'u64, 3'u32, 21'u64)
      id: DacFrameIdentity = peekDacFrameIdentity(f)
    check id.ok
    check id.sessionId == 9'u64
    check id.laneId == 3'u32
    check id.messageKind == dmkPackageManifest
    check id.headerLen + int(id.bodyLen) == f.len

  # {.testKind: tkEdgeCase.}
  test "rubbish is refused without raising and leaves every field zero":
    var
      id: DacFrameIdentity
      cases: seq[ByteSeq] = @[
        @[],
        @[0'u8],
        rampBytes(26),
        rampBytes(64)]
      i: int = 0
    while i < cases.len:
      id = peekDacFrameIdentity(cases[i])
      check not id.ok
      check id.sessionId == 0'u64
      check id.laneId == 0'u32
      check id.headerLen == 0
      check id.messageKind == dmkUnknown
      i = i + 1

  # {.testKind: tkEdgeCase.}
  test "a truncated or padded frame is refused":
    var
      f: ByteSeq = manifestFrame(9'u64, 3'u32, 21'u64)
      shortF: ByteSeq = f
      longF: ByteSeq = f
    shortF.setLen(f.len - 1)
    longF.add(0'u8)
    check not peekDacFrameIdentity(shortF).ok
    check not peekDacFrameIdentity(longF).ok

  # {.testKind: tkUnit.}
  test "the peek agrees with the full decoder on a valid frame":
    var
      f: ByteSeq = manifestFrame(12'u64, 4'u32, 8'u64)
      id: DacFrameIdentity = peekDacFrameIdentity(f)
      d: DacDecodedFrame = decodeDacFrame(f)
    check id.sessionId == d.header.sessionId
    check id.laneId == d.header.laneId
    check id.epochId == d.header.epochId
    check id.sequence == d.header.sequence
    check id.bodyLen == d.header.bodyLen
    check id.messageKind == d.header.messageKind

suite "DAC link table routing":
  # {.testKind: tkUnit.}
  test "two peers get two links and neither sees the other's package":
    var
      T: DacLinkTable = initDacLinkTable(dacDefaultsFor(dscBadSignal), 1'u64)
      a: DacLinkRoute = routeDacFrame(T, peerKey(1), manifestFrame(5'u64,
        1'u32, 100'u64), 0'u32)
      b: DacLinkRoute = routeDacFrame(T, peerKey(2), manifestFrame(6'u64,
        1'u32, 200'u64), 0'u32)
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
      a: DacLinkRoute = routeDacFrame(T, peerKey(1), manifestFrame(5'u64,
        1'u32, 100'u64), 0'u32)
      b: DacLinkRoute = routeDacFrame(T, peerKey(1), ackFrame(5'u64, 1'u32),
        10'u32)
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
    discard routeDacFrame(T, k1, manifestFrame(5'u64, 1'u32, 1'u64), 0'u32)
    discard routeDacFrame(T, k2, manifestFrame(5'u64, 1'u32, 1'u64), 0'u32)
    check dacLinkTableLive(T) == 2
    check findDacLinkSlot(T, k1) != findDacLinkSlot(T, k2)

  # {.testKind: tkEdgeCase.}
  test "rubbish from an unknown address consumes no slot":
    var
      T: DacLinkTable = initDacLinkTable(dacDefaultsFor(dscBadSignal), 1'u64)
      r: DacLinkRoute
      i: int = 0
    while i < 500:
      r = routeDacFrame(T, peerKey(i), rampBytes(40), uint32(i))
      check r.admit == dlaRefusedFrame
      check r.slot == -1
      i = i + 1
    check dacLinkTableLive(T) == 0

  # {.testKind: tkUnit.}
  test "a valid frame that opens nothing consumes no slot":
    var
      T: DacLinkTable = initDacLinkTable(dacDefaultsFor(dscBadSignal), 1'u64)
      r: DacLinkRoute
      i: int = 0
    while i < 500:
      r = routeDacFrame(T, peerKey(i), ackFrame(uint64(i), 1'u32), uint32(i))
      check r.admit == dlaRefusedKind
      check r.slot == -1
      i = i + 1
    check dacLinkTableLive(T) == 0

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
      r = routeDacFrame(T, peerKey(i), manifestFrame(uint64(i), 1'u32,
        1'u64), 0'u32)
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
    discard routeDacFrame(T, keep, manifestFrame(77'u64, 1'u32, 42'u64), 0'u32)
    check findDacLinkSlot(T, keep) >= 0
    check not dacLinkIdle(T.slots[findDacLinkSlot(T, keep)].link)
    while i < 200:
      r = routeDacFrame(T, peerKey(i), manifestFrame(uint64(i), 1'u32,
        1'u64), uint32(100_000 + i))
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
    a = admitDacLink(T, first, 5'u64, 1'u32, 0'u32)
    check a.admit == dlaAdmitted
    a = admitDacLink(T, second, 6'u64, 1'u32, 10'u32)
    check a.admit == dlaRefusedFull
    a = admitDacLink(T, second, 6'u64, 1'u32, 60'u32)
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
      discard admitDacLink(T, peerKey(i), uint64(i), 1'u32, 0'u32)
      i = i + 1
    discard routeDacFrame(T, busy, manifestFrame(70'u64, 1'u32, 3'u64), 0'u32)
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
    discard routeDacFrame(T, k, manifestFrame(5'u64, 1'u32, 1'u64), 0'u32)
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
      frames: seq[ByteSeq]
      r: DacLinkRoute
      done: bool = false
      i: int = 0
    discard admitDacLink(A, kb, 31'u64, 1'u32, 0'u32)
    frames = renderDacFrames(dacLinkFor(A, kb)[],
      beginDacPackage(dacLinkFor(A, kb)[], 5'u64, payload, 0'u32))
    check frames.len > 0
    while i < frames.len:
      r = routeDacFrame(B, ka, frames[i], uint32(i))
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
      one: seq[ByteSeq]
      two: seq[ByteSeq]
      differ: bool = false
      i: int = 0
    discard admitDacLink(T, peerKey(1), 5'u64, 1'u32, 0'u32)
    discard admitDacLink(T, peerKey(2), 5'u64, 1'u32, 0'u32)
    one = renderDacFrames(dacLinkFor(T, peerKey(1))[],
      beginDacPackage(dacLinkFor(T, peerKey(1))[], 9'u64, payload, 0'u32))
    two = renderDacFrames(dacLinkFor(T, peerKey(2))[],
      beginDacPackage(dacLinkFor(T, peerKey(2))[], 9'u64, payload, 0'u32))
    check one.len == two.len
    while i < one.len:
      if one[i] != two[i]:
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
      discard routeDacFrame(T, peerKey(i mod 9), manifestFrame(uint64(i),
        1'u32, uint64(i)), uint32(i * 3))
      steps = tickDacLinkTable(T, uint32(i * 3))
      i = i + 1
    check dacLinkTableLive(T) <= 4
