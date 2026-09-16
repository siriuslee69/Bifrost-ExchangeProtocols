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
import ../../src/protocols/dac/level0/wire_helpers
import ../../src/protocols/dac/level0/ack_range
import ../../src/protocols/dac/level0/package_commit
import ../../src/protocols/dac/level0/path_stats
import ../../src/protocols/dac/level1/package_manifest
import ../../src/protocols/dac/level1/package_chunk
import ../../src/protocols/dac/level1/parity_shard
import ../../src/protocols/dac/level1/repair_hint
import ../../src/protocols/dac/level1/repair_chunk
import ../../src/protocols/dac/level3/link
import ../../src/protocols/dac/level3/link_table
import ./fuzz_support

proc sampleChunkBody(): ByteSeq =
  ## A well-formed package-chunk BODY.
  ##
  ## There is no frame to fuzz any more: DAC frames nothing itself, so the
  ## only bytes it ever parses are a body that AME has already authenticated.
  ## That makes this the interesting input -- what a peer WITH the keys can
  ## still send, which is anything at all.
  result = encodeDacPackageChunk(initDacPackageChunk(7'u64, 1'u32, 5'u16,
    0'u32, rampBytes(24)))

proc sampleManifest(): ByteSeq =
  ## A well-formed package manifest body.
  var
    digest: array[32, uint8]
  digest[0] = 0x5A'u8
  result = encodeDacPackageManifest(initDacPackageManifest(7'u64, dtcUserData,
    dacDefaultsFor(dscBadSignal), 20_000'u64, digest))

suite "DAC message fuzz":
  # {.testKind: tkFuzz.}
  test "every message-kind byte maps or reports unknown":
    var
      i: int = 0
      known: int = 0
    while i < 256:
      if dacMessageKindFromId(uint8(i)) != dmkUnknown:
        known = known + 1
      i = i + 1
    check known == 8

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


suite "DAC link fuzz":
  # {.testKind: tkFuzz.}
  test "the loop survives an arbitrary body without raising":
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscBadSignal)
      S: DacLink = initDacLink(d, 99'u64)
      R: Rng = Rng(seed: 4242'u64)
      sample: ByteSeq = sampleChunkBody()
      data: ByteSeq = @[]
      step: DacLinkStep
      round: int = 0
      broke: bool = false
    while round < 4000 and not broke:
      data = mutate(R, sample)
      try:
        step = feedDacMessage(S, dmkPackageChunk, data, uint32(round))
        check step.kind != dlkNone or true
      except Defect as e:
        checkpoint("feedDacMessage raised a Defect on round " & $round &
          ": " & e.msg)
        broke = true
      except CatchableError as e:
        checkpoint("feedDacMessage escaped an error on round " & $round &
          ": " & e.msg)
        broke = true
      round = round + 1
    check not broke

  ## Two tests stood here, both fuzzing `peekDacFrameIdentity` -- the cheap
  ## prefix read a dispatcher used to decide which link a BARE datagram
  ## belonged to. There is no bare datagram any more: a peer is identified by
  ## the session its address already holds, so there is no prefix to read and
  ## nothing for a stranger to malform.

  # {.testKind: tkFuzz.}
  test "a hostile peer cannot make the link table raise or overgrow":
    var
      T: DacLinkTable = initDacLinkTable(dacDefaultsFor(dscBadSignal), 3'u64,
        capacity = 8, idleMs = 25'u32)
      R: Rng = Rng(seed: 5150'u64)
      sample: ByteSeq = sampleChunkBody()
      data: ByteSeq = @[]
      a: tuple[admit: DacLinkAdmit, slot: int] = (dlaExisting, -1)
      round: int = 0
      broke: bool = false
    while round < 6000 and not broke:
      data = mutate(R, sample)
      try:
        a = admitDacLink(T, initDacLinkKey("10.9.9." & $(round mod 251),
          uint16(1024 + (round mod 4096)), dlcDatagram), uint32(round))
        if a.slot >= 0:
          discard feedDacMessage(T.slots[a.slot].link, dmkPackageChunk, data,
            uint32(round))
        if a.slot >= T.slots.len or dacLinkTableLive(T) > T.slots.len:
          checkpoint("link table exceeded its capacity at round " & $round)
          broke = true
      except CatchableError as e:
        checkpoint("feedDacMessage escaped an error at round " & $round &
          ": " & e.msg)
        broke = true
      except Defect as e:
        checkpoint("feedDacMessage raised a Defect at round " & $round &
          ": " & e.msg)
        broke = true
      round = round + 1
    check not broke
    check dacLinkTableLive(T) <= 8

  # {.testKind: tkFuzz.}
  test "a real package interleaved with rubbish still completes":
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscBadSignal)
      sender: DacLink = initDacLink(d, 1'u64)
      receiver: DacLink = initDacLink(d, 2'u64)
      R: Rng = Rng(seed: 77'u64)
      payload: ByteSeq = rampBytes(9_000)
      frames: seq[DacTaggedMessage] = beginDacPackage(sender, 5'u64,
        payload, 0'u32)
      step: DacLinkStep
      done: bool = false
      i: int = 0
    while i < frames.len:
      discard feedDacMessage(receiver, dmkPackageChunk,
        mutate(R, sampleChunkBody()), uint32(i))
      step = feedDacMessage(receiver, frames[i].kind, frames[i].body,
        uint32(i))
      if step.kind == dlkPackageComplete:
        check step.payload == payload
        done = true
      i = i + 1
    check done
