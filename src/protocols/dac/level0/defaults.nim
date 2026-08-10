## ----------------------------------------------------------------------
## DAC Defaults <- path scenario repair, batch, ACK, and interval values
## ----------------------------------------------------------------------

import ../types
import ../../../analysis_pragmas

const
  dacDefaultsAscii* = """
+-----------------------------+-------------------+-------------+-------------+-----------+-----------+-------------+-------------+
| Scenario                    | Horizontal lane   | Chunk bytes | Repair      | ACK batch | Gap bits  | Repair wait | BodyLen     |
+-----------------------------+-------------------+-------------+-------------+-----------+-----------+-------------+-------------+
| Same-room servers           | SuperCleanPath    | 32768       | none        | 256 chunks| 16        | 25 ms       | u32/16 MiB  |
| Clean LAN/Wi-Fi             | CleanPath         | 1200        | 32D + 1P    | 64 chunks | 64        | 75 ms       | u16         |
| Mobile data                 | MobilePath        | 900         | 24D + 2P    | 32 chunks | 64        | 250 ms      | u16         |
| Metered mobile              | Mobile + Thin     | 700         | 16D + 1P    | 16 chunks | 32        | 500 ms      | u16         |
| Limited bandwidth           | ThinPath          | 576         | 12D + 1P    | 12 chunks | 32        | 700 ms      | u16         |
| Bad signal                  | LossyPath         | 768         | 16D + 4P    | 16 chunks | 96        | 350 ms      | u16         |
| Heavy packet loss           | LossyPath         | 512         | 12D + 6P    | 8 chunks  | 128       | 200 ms      | u16         |
| High jitter/reorder         | LossyPath         | 1000        | 24D + 3P    | 32 chunks | 128       | 900 ms      | u16         |
| UDP blocked                 | BlockedUdpPath    | 4096 stream | none        | 1 frame   | 0         | n/a         | u16         |
| NAT/path unstable           | Mobile + Lossy    | 768         | 16D + 3P    | 16 chunks | 96        | 300 ms      | u16         |
| Receiver overloaded         | ThinPath          | 576         | 8D + 1P     | 8 chunks  | 32        | 1000 ms     | u16         |
| Battery saver               | MobilePath        | 900         | 16D + 1P    | 64 chunks | 32        | 1000 ms     | u16         |
| Critical weak recovery      | Lossy + Recovery  | 512         | 8D + 6P     | 4 chunks  | 128       | 150 ms      | u16         |
+-----------------------------+-------------------+-------------+-------------+-----------+-----------+-------------+-------------+
"""

proc initDacDefaults*(p: DacPathLane, c: DacTransferClass,
    repair: DacRepairMode, ack: DacAckMode, chunkBytes, dataShards,
    parityShards, ackBatchChunks, ackMaxDelayMs: uint16, ackRangeCount: uint8,
    gapBits, repairWaitMs: uint16, repairRounds, activeGroups: uint8,
    useTcpRepair, compressManifest, orderedStream: bool,
    bodyLenMode: DacBodyLenMode = dblU16,
    maxBodyLen: uint32 = uint32(high(uint16))): DacScenarioDefaults {.role: wrapper.} =
  ## p/c/repair/ack: path, transfer, repair, and ACK policies.
  ## chunkBytes/dataShards/parityShards: frame and repair-group sizing.
  ## ackBatchChunks/ackMaxDelayMs/ackRangeCount: ACK pacing defaults.
  ## gapBits/repairWaitMs/repairRounds/activeGroups: repair control defaults.
  ## useTcpRepair/compressManifest/orderedStream: mode toggles.
  ## bodyLenMode/maxBodyLen: width and maximum for the DAC body length field.
  result.pathLane = p
  result.bodyLenMode = bodyLenMode
  result.transferClass = c
  result.repairMode = repair
  result.ackMode = ack
  result.maxBodyLen = maxBodyLen
  result.chunkBytes = chunkBytes
  result.dataShards = dataShards
  result.parityShards = parityShards
  result.ackBatchChunks = ackBatchChunks
  result.ackMaxDelayMs = ackMaxDelayMs
  result.ackRangeCount = ackRangeCount
  result.gapBits = gapBits
  result.repairWaitMs = repairWaitMs
  result.repairRounds = repairRounds
  result.activeGroups = activeGroups
  result.useTcpRepair = useTcpRepair
  result.compressManifest = compressManifest
  result.orderedStream = orderedStream

proc validateDacDefaults*(d: DacScenarioDefaults): bool {.role: parser.} =
  ## d: DAC scenario defaults to validate before use.
  if d.pathLane == dplSuperCleanPath and
      (d.bodyLenMode != dblU32 or d.maxBodyLen > dacSuperCleanMaxBodyLen):
    return false
  if d.pathLane != dplSuperCleanPath and
      (d.bodyLenMode != dblU16 or d.maxBodyLen > uint32(high(uint16))):
    return false
  if d.chunkBytes == 0'u16:
    return false
  if d.ackMode != damSilent and d.ackBatchChunks == 0'u16:
    return false
  if d.ackMode != damSilent and d.ackRangeCount == 0'u8:
    return false
  if d.orderedStream:
    result = d.repairMode == drmNone and d.dataShards == 0'u16 and
      d.parityShards == 0'u16 and d.activeGroups > 0'u8
    return
  if d.dataShards == 0'u16 or d.activeGroups == 0'u8:
    return false
  if d.repairMode == drmNone:
    result = d.parityShards == 0'u16
    return
  result = d.parityShards > 0'u16 and d.repairRounds > 0'u8

proc superCleanDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class for same-room server or same-rack paths.
  result = initDacDefaults(dplSuperCleanPath, c, drmNone, damBatch, 32768'u16,
    64'u16, 0'u16, 256'u16, 25'u16, 2'u8, 16'u16, 25'u16, 1'u8, 8'u8,
    false, false, false, dblU32, dacSuperCleanMaxBodyLen)

proc cleanLanDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplCleanPath, c, drmXor, damBatch, 1200'u16,
    32'u16, 1'u16, 64'u16, 100'u16, 4'u8, 64'u16, 75'u16, 2'u8, 4'u8,
    false, false, false)

proc mobileDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplMobilePath, c, drmReedSolomon, damBatch,
    900'u16, 24'u16, 2'u16, 32'u16, 400'u16, 6'u8, 64'u16, 250'u16,
    2'u8, 2'u8, false, false, false)

proc meteredDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplThinPath, c, drmTcpExact, damNackOnly,
    700'u16, 16'u16, 1'u16, 16'u16, 700'u16, 4'u8, 32'u16, 500'u16,
    2'u8, 1'u8, true, true, false)

proc thinDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplThinPath, c, drmXor, damBatch, 576'u16,
    12'u16, 1'u16, 12'u16, 1000'u16, 4'u8, 32'u16, 700'u16, 2'u8,
    1'u8, false, true, false)

proc badSignalDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplLossyPath, c, drmReedSolomon, damBatch,
    768'u16, 16'u16, 4'u16, 16'u16, 500'u16, 8'u8, 96'u16, 350'u16,
    3'u8, 2'u8, false, false, false)

proc heavyLossDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplLossyPath, c, drmReedSolomon, damExplicit,
    512'u16, 12'u16, 6'u16, 8'u16, 300'u16, 8'u8, 128'u16, 200'u16,
    3'u8, 1'u8, true, false, false)

proc jitterDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplLossyPath, c, drmReedSolomon, damBatch,
    1000'u16, 24'u16, 3'u16, 32'u16, 1200'u16, 8'u8, 128'u16, 900'u16,
    3'u8, 2'u8, false, false, false)

proc blockedUdpDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplBlockedUdpPath, c, drmNone, damExplicit,
    4096'u16, 0'u16, 0'u16, 1'u16, 0'u16, 2'u8, 0'u16, 0'u16, 0'u8,
    1'u8, false, false, true)

proc unstablePathDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplLossyPath, c, drmReedSolomon, damBatch,
    768'u16, 16'u16, 3'u16, 16'u16, 500'u16, 6'u8, 96'u16, 300'u16,
    3'u8, 2'u8, false, false, false)

proc overloadedDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplThinPath, c, drmXor, damBatch, 576'u16,
    8'u16, 1'u16, 8'u16, 1500'u16, 4'u8, 32'u16, 1000'u16, 1'u8,
    1'u8, false, true, false)

proc batterySaverDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplMobilePath, c, drmXor, damBatch, 900'u16,
    16'u16, 1'u16, 64'u16, 2500'u16, 4'u8, 32'u16, 1000'u16, 1'u8,
    1'u8, false, false, false)

proc recoveryWeakDacDefaults*(): DacScenarioDefaults {.role: wrapper.} =
  ## recoveryWeakDacDefaults: initialize weak-network recovery defaults.
  result = initDacDefaults(dplRecoveryPath, dtcRecovery, drmReedSolomon,
    damAudited, 512'u16, 8'u16, 6'u16, 4'u16, 200'u16, 8'u8, 128'u16,
    150'u16, 4'u8, 1'u8, true, false, false)
