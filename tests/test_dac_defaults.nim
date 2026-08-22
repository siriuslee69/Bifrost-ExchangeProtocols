## ----------------------------------------------------------
## DAC Defaults Tests <- transport profiles and frame schemas
## ----------------------------------------------------------

import std/strutils
import unittest

import ../src/protocols/types
import ../src/protocols/dac/types
import ../src/protocols/dac/level0/framing
import ../src/protocols/dac/level0/defaults
import ../src/protocols/dac/level1/path_probe
import ../src/protocols/dac/level0/path_stats
import ../src/protocols/dac/level1/package_manifest
import ../src/protocols/dac/level0/ack_range
import ../src/protocols/dac/level0/package_commit
import ../src/protocols/dac/level1/repair_hint
import ../src/protocols/dac/level1/path_switch
import ../src/protocols/dac/level1/path_policy
import ../src/protocols/dac/level0/protocols

suite "DAC defaults":
  test "descriptor exposes Data Adaptive Connection":
    var
      d = initDacDescriptor()
    check d.protocolId == dacProtocolId
    check d.name == "DAC"
    check dacProtocolLongName == "Data Adaptive Connection"
    check not d.capabilities.supportsCompression
    check d.capabilities.supportsReliability
    check d.capabilities.supportsAck

  test "super clean, clean, and recovery defaults expose expected budgets":
    var
      superClean: DacScenarioDefaults
      clean: DacScenarioDefaults
      recovery: DacScenarioDefaults
    superClean = superCleanDacDefaults()
    clean = cleanLanDacDefaults()
    recovery = recoveryWeakDacDefaults()
    check superClean.pathLane == dplSuperCleanPath
    check superClean.bodyLenMode == dblU32
    check superClean.maxBodyLen == dacSuperCleanMaxBodyLen
    check superClean.chunkBytes == 32768'u16
    check superClean.repairMode == drmNone
    check validateDacDefaults(superClean)
    check clean.chunkBytes == 1200'u16
    check clean.bodyLenMode == dblU16
    check clean.maxBodyLen == uint32(high(uint16))
    check clean.dataShards == 32'u16
    check clean.parityShards == 1'u16
    check clean.ackBatchChunks == 64'u16
    check recovery.pathLane == dplRecoveryPath
    check recovery.transferClass == dtcRecovery
    check recovery.parityShards == 6'u16
    check recovery.ackMode == damVerified
    check recovery.useTcpRepair
    check validateDacDefaults(clean)
    check validateDacDefaults(recovery)

  test "frame headers pack flags and keep DAC magic/version byte":
    var
      flags: DacFrameFlags
      h: DacFrameHeader
      frame: ByteSeq
      decoded: DacDecodedFrame
    flags.needsAck = true
    flags.creditBound = true
    flags.tcpRepairAllowed = true
    h = initDacFrameHeader(dmkPackageManifest, 42'u64, 5'u32, 2'u16,
      9'u32, 16'u32, flags)
    check h.magic == dacMagic
    check h.formatVersion == dacFormatVersion
    check dacBaseHeaderLen == 27
    check dacExtendedHeaderLen == 29
    check h.flags == 0x00C1'u16
    check h.bodyLenMode == dblU16
    check h.messageKind == dmkPackageManifest
    frame = encodeDacFrame(h, @[byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
      12, 13, 14, 15, 16])
    decoded = decodeDacFrame(frame)
    check decoded.header.messageKind == dmkPackageManifest
    check decoded.header.sessionId == 42'u64
    check decoded.header.bodyLenMode == dblU16
    check decoded.flags.needsAck
    check decoded.flags.creditBound
    check decoded.payload.len == 16
    check dacMessageKindFromId(0x03'u8) == dmkPackageManifest
    h = initDacSuperCleanFrameHeader(dmkPackageChunk, 42'u64, 5'u32, 2'u16,
      10'u32, 70000'u32, flags)
    check h.flags == 0x01C1'u16
    check h.bodyLenMode == dblU32
    check h.bodyLen == 70000'u32
    frame = encodeDacFrame(h, newSeq[byte](70000))
    decoded = decodeDacFrame(frame)
    check decoded.header.bodyLen == 70000'u32
    check decoded.flags.extendedBodyLen
    expect ValueError:
      discard initDacFrameHeader(dmkPackageChunk, 42'u64, 5'u32, 2'u16,
        10'u32, 70000'u32, flags)
    expect ValueError:
      discard initDacSuperCleanFrameHeader(dmkPackageChunk, 42'u64, 5'u32,
        2'u16, 10'u32, dacSuperCleanMaxBodyLen + 1'u32, flags)
    frame[0] = uint8('X')
    expect ValueError:
      discard decodeDacFrame(frame)
    check dacPathLaneName(dplSuperCleanPath) == "SuperCleanPath"
    check dacBodyLenModeForPath(dplSuperCleanPath) == dblU32
    check dacHeaderLenForMode(dblU32) == uint8(dacExtendedHeaderLen)
    check dacBaseFrameAscii.contains("Common DAC1 Envelope")
    check dacBaseFrameAscii.contains("SuperCleanPath extended envelope")
    check dacBaseFrameAscii.contains("AME parses")
    check dacBaseFrameAscii.contains("3-byte magic DAC + 1-byte format version")
    check dacBaseFrameAscii.contains("DAC   | u8")

  test "message schemas initialize with defaults":
    var
      p: DacPathProbe
      stats: DacPathStats
      manifest: DacPackageManifest
      ack: DacAckRange
      commit: DacPackageCommit
      repair: DacRepairHint
      switch: DacPathSwitch
      defaults: DacScenarioDefaults
      digest: array[32, uint8]
      gapMap: ByteSeq
      nonce: array[9, uint8]
    defaults = badSignalDacDefaults()
    digest[0] = 1'u8
    gapMap = @[0b00010000'u8]
    nonce = [1'u8, 2'u8, 3'u8, 4'u8, 5'u8, 6'u8, 7'u8, 8'u8, 9'u8]
    p = initDacPathProbe(9'u32, dplMobilePath, 48374'u16, 48375'u16,
      nonce)
    stats = initDacPathStats(60000'u32, 120'u16, 40'u16, 4'u16,
      1200'u16, 20'u16, 30'u16)
    manifest = initDacPackageManifest(7'u64, dtcUserData, defaults, 2048'u64,
      digest)
    ack = initDacAckRange(1'u32, 0'u8)
    commit = initDacPackageCommit(7'u64, digest, manifest.dataCount, 1'u16,
      dcsCommittedWithRepair)
    repair = initDacRepairHint(7'u64, 1'u32, 1'u16, 0'u16, 1'u16, gapMap,
      drmReedSolomon, drrMissing)
    switch = initDacPathSwitch(2'u16, 3'u16, dplMobilePath, dplLossyPath,
      dpsrLoss)
    addDacAckRange(ack, initDacAckRangeEntry(1'u32, 4'u16))
    check p.probeId == 9'u32
    check p.nonce == nonce
    check dacShouldEnterLossyPath(stats)
    check manifest.dataCount == 3'u16
    check manifest.groupSize == 20'u16
    check commit.digest == digest
    check repair.gapMap == gapMap
    check validateDacPathSwitch(switch)
    check ack.ranges.len == 1
    check dacPathProbeAscii.contains("Common DAC1 Envelope")
    check dacDefaultsAscii.len > 0
    expect ValueError:
      discard initDacPackageManifest(8'u64, dtcUserData, defaults, 2048'u64,
        default(array[32, uint8]))
    expect ValueError:
      discard initDacPackageManifest(9'u64, dtcUserData,
        initDacDefaults(dplLossyPath, dtcUserData, drmReedSolomon, damBatch,
          768'u16, high(uint16), 1'u16, 16'u16, 500'u16,
          350'u16, 2'u8, 1'u8, false, false, false), 2048'u64, digest)
    expect ValueError:
      discard initDacPackageManifest(10'u64, dtcUserData,
        initDacDefaults(dplBlockedUdpPath, dtcUserData, drmNone, damExplicit,
          4096'u16, 0'u16, 0'u16, 1'u16, 500'u16, 0'u16,
          0'u8, 1'u8, true, false, true), 2048'u64, digest)
    expect ValueError:
      discard initDacRepairHint(7'u64, 1'u32, 1'u16, 0'u16, 1'u16,
        drmReedSolomon, drrMissing)
    expect ValueError:
      discard initDacPathSwitch(2'u16, 2'u16, dplMobilePath, dplLossyPath,
        dpsrLoss)

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
