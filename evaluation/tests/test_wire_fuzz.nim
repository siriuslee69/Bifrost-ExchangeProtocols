## ---------------------------------------------------------------------
## Wire Fuzz <- every parser must refuse rubbish without crashing
## ---------------------------------------------------------------------
##
## A protocol library's decoders are the part an attacker reaches first, so
## the only acceptable outcomes for arbitrary bytes are: a value, or a
## CatchableError. Never an IndexDefect, a RangeDefect, an overflow, or a
## hang. This walks structured mutations of REAL frames rather than pure
## noise, because a random buffer almost never survives the magic check and
## would leave the interesting code paths untested.

import unittest

import ../../src/protocols/types
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/defaults
import ../../src/protocols/dac/level0/framing
import ../../src/protocols/dac/level0/ack_range
import ../../src/protocols/dac/level0/package_commit
import ../../src/protocols/dac/level0/path_stats
import ../../src/protocols/dac/level1/package_manifest
import ../../src/protocols/dac/level1/package_chunk
import ../../src/protocols/dac/level1/parity_shard
import ../../src/protocols/dac/level1/repair_hint
import ../../src/protocols/dac/level1/repair_chunk
import ../../src/protocols/dac/level1/path_probe
import ../../src/protocols/dac/level1/path_switch
import ../../src/protocols/dac/level1/drift_payload
import ../../src/protocols/dac/level3/link
import ../../src/protocols/dac/level3/link_table
import ./fuzz_support

proc sampleFrame(): ByteSeq =
  ## A well-formed DAC frame carrying a package chunk.
  var
    flags: DacFrameFlags
    h: DacFrameHeader = initDacFrameHeader(dmkPackageChunk, 7'u64, 2'u32,
      1'u16, 5'u32, 24'u32, flags)
  result = encodeDacFrame(h, rampBytes(24))

proc sampleManifest(): ByteSeq =
  ## A well-formed package manifest body.
  var
    digest: array[32, uint8]
  digest[0] = 0x5A'u8
  result = encodeDacPackageManifest(initDacPackageManifest(7'u64, dtcUserData,
    dacDefaultsFor(dscBadSignal), 20_000'u64, digest))

suite "DAC frame envelope fuzz":
  # {.testKind: tkFuzz.}
  test "the outer frame decoder never raises a Defect":
    fuzzBody("decodeDacFrame", 1'u64, sampleFrame()):
      discard decodeDacFrame(data)

  # {.testKind: tkFuzz.}
  test "every defined flag pattern round-trips and undefined bits are refused":
    var
      i: int = 0
      refused: int = 0
      broke: bool = false
    while i <= int(high(uint16)) and not broke:
      try:
        check packDacFrameFlags(unpackDacFrameFlags(uint16(i))) == uint16(i)
      except ValueError:
        refused = refused + 1
      except Defect as e:
        checkpoint("unpackDacFrameFlags raised a Defect on " & $i & ": " & e.msg)
        broke = true
      i = i + 1
    check not broke
    check refused == 0x10000 - 0x0200

  # {.testKind: tkFuzz.}
  test "every message-kind byte maps or reports unknown":
    var
      i: int = 0
      known: int = 0
    while i < 256:
      if dacMessageKindFromId(uint8(i)) != dmkUnknown:
        known = known + 1
      i = i + 1
    check known == 12

suite "DAC body decoder fuzz":
  # {.testKind: tkFuzz.}
  test "manifest":
    fuzzBody("decodeDacPackageManifest", 2'u64, sampleManifest()):
      discard decodeDacPackageManifest(data)

  # {.testKind: tkFuzz.}
  test "package chunk":
    fuzzBody("decodeDacPackageChunk", 3'u64,
        encodeDacPackageChunk(initDacPackageChunk(7'u64, 1'u32, 2'u16,
        1536'u32, rampBytes(64)))):
      discard decodeDacPackageChunk(data)

  # {.testKind: tkFuzz.}
  test "parity shard":
    fuzzBody("decodeDacParityShard", 4'u64,
        encodeDacParityShard(initDacParityShard(7'u64, 1'u32, 0'u16,
        drmReedSolomon, rampBytes(64)))):
      discard decodeDacParityShard(data)

  # {.testKind: tkFuzz.}
  test "ack range in run mode":
    var
      a: DacAckRange = initDacAckRange(44'u32, 2'u8)
    addDacAckRange(a, initDacAckRangeEntry(44'u32, 4'u16))
    addDacAckRange(a, initDacAckRangeEntry(60'u32, 2'u16))
    fuzzBody("decodeDacAckRange runs", 5'u64, encodeDacAckRange(a)):
      discard decodeDacAckRange(data)

  # {.testKind: tkFuzz.}
  test "ack range in bitmap mode":
    fuzzBody("decodeDacAckRange bitmap", 6'u64,
        encodeDacAckRange(initDacAckGapMap(44'u32, 1'u8, rampBytes(32)))):
      discard decodeDacAckRange(data)

  # {.testKind: tkFuzz.}
  test "repair hint":
    fuzzBody("decodeDacRepairHint", 7'u64,
        encodeDacRepairHint(initDacRepairHint(7'u64, 1'u32, 2'u16, 0'u16,
        2'u16, @[0b01010000'u8, 0b00000011'u8], drmTcpExact, drrMissing))):
      discard decodeDacRepairHint(data)

  # {.testKind: tkFuzz.}
  test "repair chunk":
    fuzzBody("decodeDacRepairChunk", 8'u64,
        encodeDacRepairChunk(initDacRepairChunk(7'u64, 1'u32, 2'u16,
        drsTcpExactChunk, rampBytes(48)))):
      discard decodeDacRepairChunk(data)

  # {.testKind: tkFuzz.}
  test "package commit":
    var
      digest: array[32, uint8]
    digest[0] = 0x11'u8
    fuzzBody("decodeDacPackageCommit", 9'u64,
        encodeDacPackageCommit(initDacPackageCommit(7'u64, digest, 4'u16,
        1'u16, dcsCommittedWithRepair))):
      discard decodeDacPackageCommit(data)

  # {.testKind: tkFuzz.}
  test "path stats":
    fuzzBody("decodeDacPathStats", 10'u64,
        encodeDacPathStats(initDacPathStats(120'u32, 15'u16, 3'u16, 1'u16,
        1400'u16, 4'u16, 600'u16))):
      discard decodeDacPathStats(data)

  # {.testKind: tkFuzz.}
  test "path probe":
    var
      nonce: array[9, uint8] = [1'u8, 2, 3, 4, 5, 6, 7, 8, 9]
    fuzzBody("decodeDacPathProbe", 11'u64,
        encodeDacPathProbe(initDacPathProbe(9'u32, dplMobilePath, 48374'u16,
        48375'u16, nonce))):
      discard decodeDacPathProbe(data)

  # {.testKind: tkFuzz.}
  test "path switch":
    fuzzBody("decodeDacPathSwitch", 12'u64,
        encodeDacPathSwitch(initDacPathSwitch(2'u16, 3'u16, dplCleanPath,
        dplLossyPath, dpsrLoss))):
      discard decodeDacPathSwitch(data)

  # {.testKind: tkFuzz.}
  test "drift payload":
    var
      p: DacDriftPacket
      got: DacDriftPacket
    p.kind = ddpkSnapshot
    p.tick = 42'u32
    fuzzBody("decodeDacDriftPacket", 13'u64, encodeDacDriftPacket(p)):
      discard decodeDacDriftPacket(data, got)

suite "DAC link fuzz":
  # {.testKind: tkFuzz.}
  test "the loop survives arbitrary frames without raising":
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscBadSignal)
      S: DacLink = initDacLink(7'u64, 2'u32, d, 99'u64)
      R: Rng = Rng(seed: 4242'u64)
      sample: ByteSeq = sampleFrame()
      data: ByteSeq = @[]
      step: DacLinkStep
      round: int = 0
      broke: bool = false
    while round < 4000 and not broke:
      data = mutate(R, sample)
      try:
        step = feedDacFrame(S, data, uint32(round))
        check step.kind != dlkNone or true
      except Defect as e:
        checkpoint("feedDacFrame raised a Defect on round " & $round &
          ": " & e.msg)
        broke = true
      except CatchableError as e:
        checkpoint("feedDacFrame escaped an error on round " & $round &
          ": " & e.msg)
        broke = true
      round = round + 1
    check not broke

  # {.testKind: tkFuzz.}
  test "the identity peek never raises and never half-fills a result":
    var
      R: Rng = Rng(seed: 8181'u64)
      sample: ByteSeq = sampleFrame()
      id: DacFrameIdentity
      data: ByteSeq = @[]
      round: int = 0
      broke: bool = false
    while round < 6000 and not broke:
      data = mutate(R, sample)
      try:
        id = peekDacFrameIdentity(data)
        if not id.ok and (id.sessionId != 0'u64 or id.laneId != 0'u32 or
            id.headerLen != 0 or id.messageKind != dmkUnknown):
          checkpoint("peekDacFrameIdentity left fields set on a refusal at " &
            "round " & $round)
          broke = true
        if id.ok and id.headerLen + int(id.bodyLen) != data.len:
          checkpoint("peekDacFrameIdentity accepted a length mismatch at " &
            "round " & $round)
          broke = true
      except CatchableError as e:
        checkpoint("peekDacFrameIdentity raised at round " & $round & ": " & e.msg)
        broke = true
      except Defect as e:
        checkpoint("peekDacFrameIdentity raised a Defect at round " & $round &
          ": " & e.msg)
        broke = true
      round = round + 1
    check not broke

  # {.testKind: tkFuzz.}
  test "the peek accepts exactly what the full decoder accepts":
    var
      R: Rng = Rng(seed: 9191'u64)
      sample: ByteSeq = sampleFrame()
      data: ByteSeq = @[]
      decoded: bool = false
      round: int = 0
      mismatches: int = 0
    while round < 6000:
      data = mutate(R, sample)
      decoded = true
      try:
        discard decodeDacFrame(data)
      except CatchableError:
        decoded = false
      if decoded != peekDacFrameIdentity(data).ok:
        mismatches = mismatches + 1
      round = round + 1
    check mismatches == 0

  # {.testKind: tkFuzz.}
  test "a hostile peer cannot make the link table raise or overgrow":
    var
      T: DacLinkTable = initDacLinkTable(dacDefaultsFor(dscBadSignal), 3'u64,
        capacity = 8, idleMs = 25'u32)
      R: Rng = Rng(seed: 5150'u64)
      sample: ByteSeq = sampleFrame()
      data: ByteSeq = @[]
      r: DacLinkRoute
      round: int = 0
      broke: bool = false
    while round < 6000 and not broke:
      data = mutate(R, sample)
      try:
        r = routeDacFrame(T, initDacLinkKey("10.9.9." & $(round mod 251),
          uint16(1024 + (round mod 4096)), dlcDatagram), data, uint32(round))
        if r.slot >= T.slots.len or dacLinkTableLive(T) > T.slots.len:
          checkpoint("link table exceeded its capacity at round " & $round)
          broke = true
      except CatchableError as e:
        checkpoint("routeDacFrame escaped an error at round " & $round &
          ": " & e.msg)
        broke = true
      except Defect as e:
        checkpoint("routeDacFrame raised a Defect at round " & $round &
          ": " & e.msg)
        broke = true
      round = round + 1
    check not broke
    check dacLinkTableLive(T) <= 8

  # {.testKind: tkFuzz.}
  test "a real package interleaved with rubbish still completes":
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscBadSignal)
      sender: DacLink = initDacLink(7'u64, 2'u32, d, 1'u64)
      receiver: DacLink = initDacLink(7'u64, 2'u32, d, 2'u64)
      R: Rng = Rng(seed: 77'u64)
      payload: ByteSeq = rampBytes(9_000)
      frames: seq[ByteSeq] = renderDacFrames(sender,
        beginDacPackage(sender, 5'u64, payload, 0'u32))
      step: DacLinkStep
      done: bool = false
      i: int = 0
    while i < frames.len:
      discard feedDacFrame(receiver, mutate(R, sampleFrame()), uint32(i))
      step = feedDacFrame(receiver, frames[i], uint32(i))
      if step.kind == dlkPackageComplete:
        check step.payload == payload
        done = true
      i = i + 1
    check done
