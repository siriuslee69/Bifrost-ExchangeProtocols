## ----------------------------------------------------------
## DAC Defaults Tests <- transport profiles and frame schemas
## ----------------------------------------------------------

import std/strutils
import unittest

import ../../src/protocols/types
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/wire_helpers
import ../../src/protocols/dac/level0/defaults
import ../../src/protocols/dac/level0/path_stats
import ../../src/protocols/dac/level1/package_manifest
import ../../src/protocols/dac/level0/ack_range
import ../../src/protocols/dac/level0/package_commit
import ../../src/protocols/dac/level1/repair_hint
import ../../src/protocols/dac/level1/path_policy
import ../../src/protocols/dac/level0/protocols

suite "DAC defaults":
  # {.testKind: tkUnit.}
  test "descriptor exposes Data Adaptive Connection":
    var
      d = initDacDescriptor()
    check d.protocolId == dacProtocolId
    check d.name == "DAC"
    check dacProtocolLongName == "Data Adaptive Connection"
    check not d.capabilities.supportsCompression
    check d.capabilities.supportsReliability
    check d.capabilities.supportsAck

  # {.testKind: tkUnit.}
  test "super clean, clean, and recovery defaults expose expected budgets":
    var
      superClean: DacScenarioDefaults
      clean: DacScenarioDefaults
      recovery: DacScenarioDefaults
    superClean = dacDefaultsFor(dscSameRoom)
    clean = dacDefaultsFor(dscCleanLan)
    recovery = dacDefaultsFor(dscWeakRecovery)
    check superClean.pathLane == dplSuperCleanPath
    check superClean.chunkBytes == 32768'u16
    check superClean.repairMode == drmNone
    check validateDacDefaults(superClean)
    check clean.chunkBytes == 1200'u16
    check clean.dataShards == 32'u16
    check clean.parityShards == 1'u16
    check clean.ackBatchChunks == 64'u16
    check recovery.pathLane == dplRecoveryPath
    check recovery.transferClass == dtcRecovery
    check recovery.parityShards == 6'u16
    check recovery.ackMode == damVerified
    check validateDacDefaults(clean)
    check validateDacDefaults(recovery)

  # {.testKind: tkEdgeCase.}
  test "every lane has one validated preset, except the one that cannot":
    var
      lane: DacPathLane
    ## A lane move has to land on a complete parameter set, so each lane
    ## resolves to a preset that passes the same validation a hand-built
    ## config would.
    for lane in [dplSuperCleanPath, dplCleanPath, dplMobilePath, dplThinPath,
        dplLossyPath, dplRecoveryPath]:
      check validateDacDefaults(dacDefaultsForPath(lane))
      check dacDefaultsForPath(lane).pathLane == lane
    ## BlockedUdpPath is the exception, and it fails loudly rather than
    ## handing back a datagram policy for a path that carries no datagrams.
    ## The path policy never targets this lane, so reaching here means a
    ## caller went looking for parameters it should not have wanted.
    expect ValueError:
      discard dacDefaultsForPath(dplBlockedUdpPath)

  # {.testKind: tkUnit.}
  test "message schemas initialize with defaults":
    var
      stats: DacPathStats
      manifest: DacPackageManifest
      ack: DacAckRange
      commit: DacPackageCommit
      repair: DacRepairHint
      defaults: DacScenarioDefaults
      digest: array[32, uint8]
      gapMap: ByteSeq
    defaults = dacDefaultsFor(dscBadSignal)
    digest[0] = 1'u8
    gapMap = @[0b00010000'u8]
    stats = initDacPathStats(60000'u32, 120'u16, 40'u16, 4'u16,
      1200'u16, 20'u16, 30'u16)
    manifest = initDacPackageManifest(7'u64, dtcUserData, defaults, 2048'u64,
      digest)
    ack = initDacAckRange(1'u32, 0'u8)
    commit = initDacPackageCommit(7'u64, digest, manifest.dataCount, 1'u16,
      dcsCommittedWithRepair)
    repair = initDacRepairHint(7'u64, 1'u32, 1'u16, 0'u16, 1'u16, gapMap,
      drmReedSolomon, drrMissing)
    addDacAckRange(ack, initDacAckRangeEntry(1'u32, 4'u16))
    check dacShouldEnterLossyPath(stats)
    check manifest.dataCount == 3'u16
    check manifest.groupSize == 20'u16
    check commit.digest == digest
    check repair.gapMap == gapMap
    check ack.ranges.len == 1
    check dacDefaultsAscii.len > 0
    expect ValueError:
      discard initDacPackageManifest(8'u64, dtcUserData, defaults, 2048'u64,
        default(array[32, uint8]))
    expect ValueError:
      discard initDacPackageManifest(9'u64, dtcUserData,
        initDacDefaults(dplLossyPath, dtcUserData, drmReedSolomon, damBatch,
          768'u16, high(uint16), 1'u16, 16'u16, 500'u16,
          350'u16, 2'u8), 2048'u64, digest)
    ## A repair mode with no parity shards is inconsistent, and a manifest
    ## built from it must not be accepted.
    expect ValueError:
      discard initDacPackageManifest(10'u64, dtcUserData,
        initDacDefaults(dplLossyPath, dtcUserData, drmReedSolomon, damExplicit,
          1024'u16, 16'u16, 0'u16, 8'u16, 500'u16, 300'u16,
          2'u8), 2048'u64, digest)
    expect ValueError:
      discard initDacRepairHint(7'u64, 1'u32, 1'u16, 0'u16, 1'u16,
        drmReedSolomon, drrMissing)

  # {.testKind: tkUnit.}
  test "path policy recommends one-step switches from stats and failures":
    var
      stats: DacPathStats
      rec: DacPathRecommendation
    stats = initDacPathStats(90000'u32, 220'u16, 70'u16, 20'u16,
      900'u16, 120'u16, 120'u16)
    rec = recommendDacPathFromStats(dplCleanPath, stats)
    check rec.ok
    check rec.path == dplMobilePath
    check rec.reason == dpsrLoss
    rec = recommendDacPathFromFailures(dplMobilePath, 2'u8, 0'u8)
    check rec.ok
    check rec.path == dplThinPath
    check rec.reason == dpsrLoss
    rec = recommendDacPathFromFailures(dplThinPath, 0'u8, 3'u8)
    check rec.ok
    check rec.path == dplRecoveryPath
    check rec.reason == dpsrReceiverPressure
