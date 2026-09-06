## ---------------------------------------------------------------------
## DAC Package Repair Tests <- XOR and Reed-Solomon group recovery
## ---------------------------------------------------------------------

import unittest

import ../../src/protocols/types
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/defaults
import ../../src/protocols/dac/level2/package_transfer

proc rampBytes(n: int): ByteSeq =
  ## n: payload length filled with a deterministic ramp.
  var
    i: int = 0
  result = newSeq[uint8](n)
  while i < n:
    result[i] = uint8(i mod 251)
    i = i + 1

proc receiverMissing(P: DacPackagePlan,
    A: openArray[uint16]): DacPackageReceiver =
  ## P: sender plan whose chunks are delivered.
  ## A: chunk ids withheld from the receiver.
  result = initDacPackageReceiver(P.manifest)
  for chunk in P.chunks:
    if chunk.chunkId notin A:
      result.acceptDacPackageChunk(chunk)

proc dropShards(S: var DacPackageGroupRepair, A: openArray[int]) =
  ## S: repair record whose parity slots are emptied.
  ## A: parity shard ids that never arrived.
  var
    i: int = 0
  while i < A.len:
    S.shards[A[i]] = @[]
    i = i + 1

suite "DAC repair-group geometry":
  test "group spans follow the manifest and the last group is short":
    var
      d: DacScenarioDefaults = badSignalDacDefaults()
      plan: DacPackagePlan = planDacPackage(41'u64, rampBytes(20_000), d)
      m: DacPackageManifest = plan.manifest
      width: uint16 = dacGroupDataWidth(m)
      last: uint32 = uint32(plan.repairs.len) - 1'u32
    check width == m.groupSize - m.parityCount
    check dacGroupFirstChunk(m, 0'u32) == 0'u16
    check dacGroupChunkCount(m, 0'u32) == width
    check dacGroupFirstChunk(m, 1'u32) == width
    check dacGroupChunkCount(m, last) <= width
    check int(dacGroupFirstChunk(m, last)) +
      int(dacGroupChunkCount(m, last)) == int(m.dataCount)
    expect ValueError:
      discard dacGroupFirstChunk(m, uint32(plan.repairs.len))

  test "every planned group matches its manifest span":
    var
      plan: DacPackagePlan = planDacPackage(42'u64, rampBytes(9_000),
        badSignalDacDefaults())
      i: int = 0
    while i < plan.repairs.len:
      check plan.repairs[i].firstChunk ==
        dacGroupFirstChunk(plan.manifest, uint32(i))
      check plan.repairs[i].chunkCount ==
        dacGroupChunkCount(plan.manifest, uint32(i))
      check plan.repairs[i].shards.len == int(plan.manifest.parityCount)
      i = i + 1

suite "DAC XOR repair":
  test "one loss rebuilds, two losses are refused with a reason":
    var
      plan: DacPackagePlan = planDacPackage(7'u64, rampBytes(5_000),
        cleanLanDacDefaults())
      one: DacPackageReceiver = receiverMissing(plan, [2'u16])
      two: DacPackageReceiver = receiverMissing(plan, [2'u16, 4'u16])
      report: DacGroupRepairReport
    check plan.manifest.repairMode == drmXor
    check plan.repairs[0].shards.len == 1
    report = one.repairGroup(plan.repairs[0])
    check report.ok
    check report.rebuilt == @[2'u16]
    check finishDacPackage(one).ok
    report = two.repairGroup(plan.repairs[0])
    check not report.ok
    check report.err.len > 0
    check not finishDacPackage(two).ok

  test "a lost XOR shard is refused rather than guessed":
    var
      plan: DacPackagePlan = planDacPackage(8'u64, rampBytes(5_000),
        cleanLanDacDefaults())
      S: DacPackageReceiver = receiverMissing(plan, [3'u16])
      r: DacPackageGroupRepair = plan.repairs[0]
      report: DacGroupRepairReport
    dropShards(r, [0])
    report = S.repairGroup(r)
    check not report.ok
    check S.received[3] == false

suite "DAC Reed-Solomon repair":
  test "the full parity budget rebuilds and one more loss does not":
    var
      d: DacScenarioDefaults = badSignalDacDefaults()
      plan: DacPackagePlan = planDacPackage(9'u64, rampBytes(20_000), d)
      budget: DacPackageReceiver = receiverMissing(plan,
        [1'u16, 4'u16, 9'u16, 14'u16])
      overBudget: DacPackageReceiver = receiverMissing(plan,
        [1'u16, 4'u16, 9'u16, 14'u16, 15'u16])
      report: DacGroupRepairReport
    check plan.manifest.repairMode == drmReedSolomon
    check plan.manifest.parityCount == 4'u16
    check plan.repairs[0].shards.len == 4
    report = budget.repairGroup(plan.repairs[0])
    check report.ok
    check report.rebuilt == @[1'u16, 4'u16, 9'u16, 14'u16]
    check finishDacPackage(budget).ok
    check finishDacPackage(budget).payload == rampBytes(20_000)
    report = overBudget.repairGroup(plan.repairs[0])
    check not report.ok
    check overBudget.received[1] == false

  test "losing parity shards spends the budget the same way":
    var
      plan: DacPackagePlan = planDacPackage(10'u64, rampBytes(20_000),
        badSignalDacDefaults())
      S: DacPackageReceiver = receiverMissing(plan, [0'u16, 7'u16])
      r: DacPackageGroupRepair = plan.repairs[0]
      report: DacGroupRepairReport
    dropShards(r, [1, 3])
    report = S.repairGroup(r)
    check report.ok
    check report.rebuilt == @[0'u16, 7'u16]
    check finishDacPackage(S).ok

  test "a short final group rebuilds on its own width":
    var
      plan: DacPackagePlan = planDacPackage(11'u64, rampBytes(13_000),
        badSignalDacDefaults())
      last: int = plan.repairs.len - 1
      dropped: uint16 = plan.repairs[last].firstChunk
      S: DacPackageReceiver = receiverMissing(plan, [dropped])
      report: DacGroupRepairReport
    check plan.repairs[last].chunkCount < dacGroupDataWidth(plan.manifest)
    report = S.repairGroup(plan.repairs[last])
    check report.ok
    check report.rebuilt == @[dropped]
    check finishDacPackage(S).ok

  test "nothing missing rebuilds nothing":
    var
      plan: DacPackagePlan = planDacPackage(12'u64, rampBytes(20_000),
        badSignalDacDefaults())
      S: DacPackageReceiver = initDacPackageReceiver(plan.manifest)
      report: DacGroupRepairReport
    for chunk in plan.chunks:
      S.acceptDacPackageChunk(chunk)
    report = S.repairGroup(plan.repairs[0])
    check report.ok
    check report.rebuilt.len == 0
    check finishDacPackage(S).commit.status == dcsCommitted

suite "DAC parity shards on the wire":
  test "shards survive the trip out and back into a repair record":
    var
      plan: DacPackagePlan = planDacPackage(13'u64, rampBytes(20_000),
        badSignalDacDefaults())
      shards: seq[DacParityShard] = groupParityShards(plan, 0'u32)
      rebuilt: DacPackageGroupRepair
      S: DacPackageReceiver = receiverMissing(plan, [2'u16, 3'u16])
      report: DacGroupRepairReport
      i: int = 0
    check shards.len == int(plan.manifest.parityCount)
    while i < shards.len:
      check shards[i].shardId == uint16(i)
      check shards[i].repairMode == drmReedSolomon
      i = i + 1
    rebuilt = collectGroupRepair(plan.manifest, 0'u32, shards)
    check rebuilt.firstChunk == plan.repairs[0].firstChunk
    check rebuilt.chunkCount == plan.repairs[0].chunkCount
    check rebuilt.shards == plan.repairs[0].shards
    report = S.repairGroup(rebuilt)
    check report.ok
    check finishDacPackage(S).ok

  test "a shard from the wrong group or package is refused":
    var
      plan: DacPackagePlan = planDacPackage(14'u64, rampBytes(20_000),
        badSignalDacDefaults())
      shards: seq[DacParityShard] = groupParityShards(plan, 0'u32)
      strayGroup: seq[DacParityShard] = shards
      strayPackage: seq[DacParityShard] = shards
    strayGroup[1].groupId = 9'u32
    strayPackage[1].packageId = 99'u64
    expect ValueError:
      discard collectGroupRepair(plan.manifest, 0'u32, strayGroup)
    expect ValueError:
      discard collectGroupRepair(plan.manifest, 0'u32, strayPackage)
    expect ValueError:
      discard groupParityShards(plan, uint32(plan.repairs.len))

  test "a partial parity set leaves the missing slots empty":
    var
      plan: DacPackagePlan = planDacPackage(15'u64, rampBytes(20_000),
        badSignalDacDefaults())
      shards: seq[DacParityShard] = groupParityShards(plan, 0'u32)
      rebuilt: DacPackageGroupRepair
      S: DacPackageReceiver = receiverMissing(plan, [6'u16])
      report: DacGroupRepairReport
    rebuilt = collectGroupRepair(plan.manifest, 0'u32, @[shards[2]])
    check rebuilt.shards.len == int(plan.manifest.parityCount)
    check rebuilt.shards[0].len == 0
    check rebuilt.shards[2].len > 0
    report = S.repairGroup(rebuilt)
    check report.ok
    check finishDacPackage(S).ok

suite "DAC repair modes without parity":
  test "exact-repair and no-repair modes say so instead of failing silently":
    var
      plan: DacPackagePlan = planDacPackage(16'u64, rampBytes(4_000),
        meteredDacDefaults())
      S: DacPackageReceiver = receiverMissing(plan, [1'u16])
      report: DacGroupRepairReport
    check plan.manifest.repairMode == drmTcpExact
    check plan.repairs[0].shards.len == 0
    report = S.repairGroup(plan.repairs[0])
    check not report.ok
    check report.err.len > 0

  test "a group outside the package is refused":
    var
      plan: DacPackagePlan = planDacPackage(17'u64, rampBytes(4_000),
        cleanLanDacDefaults())
      S: DacPackageReceiver = initDacPackageReceiver(plan.manifest)
      r: DacPackageGroupRepair = plan.repairs[0]
      report: DacGroupRepairReport
    r.firstChunk = uint16(plan.chunks.len)
    report = S.repairGroup(r)
    check not report.ok
