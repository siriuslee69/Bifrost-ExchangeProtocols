## ---------------------------------------------------------
## DAC Wire Tests <- body codec roundtrips and validation
## ---------------------------------------------------------

import unittest

import ../src/protocols/types
import ../src/protocols/dac/types
import ../src/protocols/dac/level0/framing
import ../src/protocols/dac/level0/defaults
import ../src/protocols/dac/level0/path_stats
import ../src/protocols/dac/level0/ack_range
import ../src/protocols/dac/level0/package_commit
import ../src/protocols/dac/level1/path_probe
import ../src/protocols/dac/level1/package_manifest
import ../src/protocols/dac/level1/package_chunk
import ../src/protocols/dac/level1/parity_shard
import ../src/protocols/dac/level1/repair_hint
import ../src/protocols/dac/level1/repair_chunk
import ../src/protocols/dac/level1/path_switch

suite "DAC wire":
  test "fixed-width bodies roundtrip and validate reserved bytes":
    var
      digest: array[32, uint8]
      nonce: array[9, uint8]
      stats: DacPathStats
      commit: DacPackageCommit
      probe: DacPathProbe
      switchReq: DacPathSwitch
      body: ByteSeq
      decodedStats: DacPathStats
      decodedCommit: DacPackageCommit
      decodedProbe: DacPathProbe
      decodedSwitch: DacPathSwitch
    digest[0] = 0xAA'u8
    nonce = [1'u8, 2'u8, 3'u8, 4'u8, 5'u8, 6'u8, 7'u8, 8'u8, 9'u8]
    stats = initDacPathStats(120'u32, 15'u16, 3'u16, 1'u16, 1400'u16,
      4'u16, 600'u16)
    commit = initDacPackageCommit(71'u64, digest, 4'u16, 1'u16,
      dcsCommittedWithRepair)
    probe = initDacPathProbe(9'u32, dplMobilePath, 48374'u16, 48371'u16,
      nonce)
    switchReq = initDacPathSwitch(2'u16, 3'u16, dplCleanPath,
      dplLossyPath, dpsrLoss)

    body = encodeDacPathStats(stats)
    check body.len == dacPathStatsLen
    decodedStats = decodeDacPathStats(body)
    check decodedStats == stats
    body[^1] = 1'u8
    expect ValueError:
      discard decodeDacPathStats(body)

    body = encodeDacPackageCommit(commit)
    check body.len == dacPackageCommitLen
    decodedCommit = decodeDacPackageCommit(body)
    check decodedCommit == commit
    body[^1] = 0xFF'u8
    expect ValueError:
      discard decodeDacPackageCommit(body)

    body = encodeDacPathProbe(probe)
    check body.len == dacPathProbeLen
    decodedProbe = decodeDacPathProbe(body)
    check decodedProbe == probe
    body[4] = 0xFF'u8
    expect ValueError:
      discard decodeDacPathProbe(body)

    body = encodeDacPathSwitch(switchReq)
    check body.len == dacPathSwitchLen
    decodedSwitch = decodeDacPathSwitch(body)
    check decodedSwitch == switchReq
    body[^1] = 1'u8
    expect ValueError:
      discard decodeDacPathSwitch(body)

  test "ack ranges roundtrip and reject malformed shapes":
    var
      ack: DacAckRange
      body: ByteSeq
      decoded: DacAckRange
    ack = initDacAckRange(44'u32, 2'u8)
    addDacAckRange(ack, initDacAckRangeEntry(44'u32, 4'u16))
    addDacAckRange(ack, initDacAckRangeEntry(60'u32, 2'u16))
    body = encodeDacAckRange(ack)
    check body.len == dacAckRangeHeaderLen + (2 * dacAckRangeEntryLen)
    decoded = decodeDacAckRange(body)
    check decoded == ack
    expect ValueError:
      discard initDacAckRangeEntry(44'u32, 0'u16)
    body[4] = 3'u8
    expect ValueError:
      discard decodeDacAckRange(body)

  test "manifest codec validates chunk counts and repair semantics":
    var
      defaults: DacScenarioDefaults
      digest: array[32, uint8]
      manifest: DacPackageManifest
      body: ByteSeq
      decoded: DacPackageManifest
    defaults = badSignalDacDefaults()
    digest[0] = 0x11'u8
    manifest = initDacPackageManifest(7001'u64, dtcUserData, defaults,
      2048'u64, digest)
    body = encodeDacPackageManifest(manifest)
    check body.len == dacPackageManifestLen
    decoded = decodeDacPackageManifest(body)
    check decoded == manifest
    body[11] = 0'u8
    body[12] = 0'u8
    expect ValueError:
      discard decodeDacPackageManifest(body)
    body = encodeDacPackageManifest(manifest)
    body[17] = uint8(ord(drmNone))
    expect ValueError:
      discard decodeDacPackageManifest(body)

  test "payload-carrying bodies roundtrip":
    var
      chunk: DacPackageChunk
      parity: DacParityShard
      hint: DacRepairHint
      repair: DacRepairChunk
      gapMap: ByteSeq
      body: ByteSeq
      decodedChunk: DacPackageChunk
      decodedParity: DacParityShard
      decodedHint: DacRepairHint
      decodedRepair: DacRepairChunk
    gapMap = @[0b00010000'u8, 0b00000001'u8]
    chunk = initDacPackageChunk(7001'u64, 2'u32, 1'u16, 1024'u32,
      @[byte 1, 2, 3, 4])
    parity = initDacParityShard(7001'u64, 2'u32, 9'u16, drmReedSolomon,
      @[byte 5, 6, 7])
    hint = initDacRepairHint(7001'u64, 2'u32, 1'u16, 0'u16, 1'u16, gapMap,
      drmTcpExact, drrMissing)
    repair = initDacRepairChunk(7001'u64, 2'u32, 1'u16, drsTcpExactChunk,
      @[byte 8, 9, 10])

    body = encodeDacPackageChunk(chunk)
    check body.len == dacPackageChunkHeaderLen + chunk.payload.len
    decodedChunk = decodeDacPackageChunk(body)
    check decodedChunk == chunk
    expect ValueError:
      discard decodeDacPackageChunk(@[byte 1, 2, 3])

    body = encodeDacParityShard(parity)
    check body.len == dacParityShardHeaderLen + parity.payload.len
    decodedParity = decodeDacParityShard(body)
    check decodedParity == parity
    body[14] = 0xFF'u8
    expect ValueError:
      discard decodeDacParityShard(body)

    body = encodeDacRepairHint(hint)
    check body.len == dacRepairHintFixedLen + hint.gapMap.len
    decodedHint = decodeDacRepairHint(body)
    check decodedHint == hint
    body[^1] = 1'u8
    expect ValueError:
      discard decodeDacRepairHint(body)

    body = encodeDacRepairChunk(repair)
    check body.len == dacRepairChunkHeaderLen + repair.payload.len
    decodedRepair = decodeDacRepairChunk(body)
    check decodedRepair == repair
    body[14] = 0xFF'u8
    expect ValueError:
      discard decodeDacRepairChunk(body)

  test "parity shards carry a Reed-Solomon payload across the wire":
    var
      shard: DacParityShard
      body: ByteSeq
      decoded: DacParityShard
    shard = initDacParityShard(7001'u64, 3'u32, 4'u16, drmReedSolomon,
      @[byte 9, 4, 1, 7, 3, 2, 8, 5, 6])
    body = encodeDacParityShard(shard)
    check body.len == dacParityShardHeaderLen + shard.payload.len
    decoded = decodeDacParityShard(body)
    check decoded == shard
    check decoded.repairMode == drmReedSolomon
    body[14] = uint8(ord(drmNone))
    expect ValueError:
      discard decodeDacParityShard(body)

  test "manifest body roundtrips through DAC1 framing":
    var
      defaults: DacScenarioDefaults
      digest: array[32, uint8]
      manifest: DacPackageManifest
      body: ByteSeq
      header: DacFrameHeader
      frame: ByteSeq
      decodedFrame: DacDecodedFrame
      decodedManifest: DacPackageManifest
      flags: DacFrameFlags
    defaults = cleanLanDacDefaults()
    digest[0] = 0x42'u8
    manifest = initDacPackageManifest(9001'u64, dtcArchive, defaults,
      4096'u64, digest)
    body = encodeDacPackageManifest(manifest)
    flags.needsAck = true
    header = initDacFrameHeader(dmkPackageManifest, 42'u64, 5'u32, 2'u16,
      9'u32, uint32(body.len), flags)
    frame = encodeDacFrame(header, body)
    decodedFrame = decodeDacFrame(frame)
    decodedManifest = decodeDacPackageManifest(decodedFrame.payload)
    check decodedFrame.header.messageKind == dmkPackageManifest
    check decodedManifest == manifest
