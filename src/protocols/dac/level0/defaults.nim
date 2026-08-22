## ----------------------------------------------------------------------
## DAC Defaults <- path scenario repair, batch, ACK, and interval values
## ----------------------------------------------------------------------

import ../types
import ../../../analysis_pragmas

const
  dacDefaultsAscii* = """
+-----------------------------+-------------------+-------------+-------------+-----------+-------------+-------------+
| Scenario                    | Horizontal lane   | Chunk bytes | Repair      | ACK batch | ACK deadline| Repair wait |
+-----------------------------+-------------------+-------------+-------------+-----------+-------------+-------------+
| Same-room servers           | SuperCleanPath    | 32768       | none        | 256 chunks| 25 ms       | 25 ms       |
| Clean LAN/Wi-Fi             | CleanPath         | 1200        | 32D + 1P    | 64 chunks | 100 ms      | 75 ms       |
| Mobile data                 | MobilePath        | 900         | 24D + 2P    | 32 chunks | 400 ms      | 250 ms      |
| Metered mobile              | Mobile + Thin     | 700         | 16D + 1P    | 16 chunks | 700 ms      | 500 ms      |
| Limited bandwidth           | ThinPath          | 576         | 12D + 1P    | 12 chunks | 1000 ms     | 700 ms      |
| Bad signal                  | LossyPath         | 768         | 16D + 4P    | 16 chunks | 500 ms      | 350 ms      |
| Heavy packet loss           | LossyPath         | 512         | 12D + 6P    | 8 chunks  | 300 ms      | 200 ms      |
| High jitter/reorder         | LossyPath         | 1000        | 24D + 3P    | 32 chunks | 1200 ms     | 900 ms      |
| UDP blocked                 | BlockedUdpPath    | 4096 stream | none        | 1 frame   | 0 ms        | n/a         |
| NAT/path unstable           | Mobile + Lossy    | 768         | 16D + 3P    | 16 chunks | 500 ms      | 300 ms      |
| Receiver overloaded         | ThinPath          | 576         | 8D + 1P     | 8 chunks  | 1500 ms     | 1000 ms     |
| Battery saver               | MobilePath        | 900         | 16D + 1P    | 64 chunks | 2500 ms     | 1000 ms     |
| Critical weak recovery      | Lossy + Recovery  | 512         | 8D + 6P     | 4 chunks  | 200 ms      | 150 ms      |
+-----------------------------+-------------------+-------------+-------------+-----------+-------------+-------------+

The ACK batch and deadline are a starting point, not a fixed rule: the
receiver moves them from what it observes arriving. Notice that heavy loss
gets the SMALL batch, not the large one -- every un-acknowledged frame is
retransmit state the sender cannot free. Long deadlines are for battery
radios, where the cost being saved is a wake-up, not bandwidth.
"""

proc initDacDefaults*(p: DacPathLane, c: DacTransferClass,
    repair: DacRepairMode, ack: DacAckMode, chunkBytes, dataShards,
    parityShards, ackBatchChunks, ackMaxDelayMs, repairWaitMs: uint16,
    repairRounds, activeGroups: uint8,
    useTcpRepair, compressManifest, orderedStream: bool,
    bodyLenMode: DacBodyLenMode = dblU16,
    maxBodyLen: uint32 = uint32(high(uint16))): DacScenarioDefaults {.role: wrapper.} =
  ## p/c/repair/ack: path, transfer, repair, and ACK policies.
  ## chunkBytes/dataShards/parityShards: frame and repair-group sizing.
  ## ackBatchChunks/ackMaxDelayMs: starting ACK batch size and time bound.
  ## repairWaitMs/repairRounds/activeGroups: repair control defaults.
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
    64'u16, 0'u16, 256'u16, 25'u16, 25'u16, 1'u8, 8'u8,
    false, false, false, dblU32, dacSuperCleanMaxBodyLen)

proc cleanLanDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplCleanPath, c, drmXor, damBatch, 1200'u16,
    32'u16, 1'u16, 64'u16, 100'u16, 75'u16, 2'u8, 4'u8,
    false, false, false)

proc mobileDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplMobilePath, c, drmReedSolomon, damBatch,
    900'u16, 24'u16, 2'u16, 32'u16, 400'u16, 250'u16,
    2'u8, 2'u8, false, false, false)

proc meteredDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplThinPath, c, drmTcpExact, damNackOnly,
    700'u16, 16'u16, 1'u16, 16'u16, 700'u16, 500'u16,
    2'u8, 1'u8, true, true, false)

proc thinDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplThinPath, c, drmXor, damBatch, 576'u16,
    12'u16, 1'u16, 12'u16, 1000'u16, 700'u16, 2'u8,
    1'u8, false, true, false)

proc badSignalDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplLossyPath, c, drmReedSolomon, damBatch,
    768'u16, 16'u16, 4'u16, 16'u16, 500'u16, 350'u16,
    3'u8, 2'u8, false, false, false)

proc heavyLossDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplLossyPath, c, drmReedSolomon, damExplicit,
    512'u16, 12'u16, 6'u16, 8'u16, 300'u16, 200'u16,
    3'u8, 1'u8, true, false, false)

proc jitterDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplLossyPath, c, drmReedSolomon, damBatch,
    1000'u16, 24'u16, 3'u16, 32'u16, 1200'u16, 900'u16,
    3'u8, 2'u8, false, false, false)

proc blockedUdpDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplBlockedUdpPath, c, drmNone, damExplicit,
    4096'u16, 0'u16, 0'u16, 1'u16, 0'u16, 0'u16, 0'u8,
    1'u8, false, false, true)

proc unstablePathDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplLossyPath, c, drmReedSolomon, damBatch,
    768'u16, 16'u16, 3'u16, 16'u16, 500'u16, 300'u16,
    3'u8, 2'u8, false, false, false)

proc overloadedDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplThinPath, c, drmXor, damBatch, 576'u16,
    8'u16, 1'u16, 8'u16, 1500'u16, 1000'u16, 1'u8,
    1'u8, false, true, false)

proc batterySaverDacDefaults*(c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## c: vertical transfer class.
  result = initDacDefaults(dplMobilePath, c, drmXor, damBatch, 900'u16,
    16'u16, 1'u16, 64'u16, 2500'u16, 1000'u16, 1'u8,
    1'u8, false, false, false)

proc recoveryWeakDacDefaults*(): DacScenarioDefaults {.role: wrapper.} =
  ## recoveryWeakDacDefaults: initialize weak-network recovery defaults.
  result = initDacDefaults(dplRecoveryPath, dtcRecovery, drmReedSolomon,
    damVerified, 512'u16, 8'u16, 6'u16, 4'u16, 200'u16,
    150'u16, 4'u8, 1'u8, true, false, false)

proc dacDefaultsForPath*(p: DacPathLane,
    c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: wrapper.} =
  ## p: path lane a policy decision landed on.
  ## c: transfer class to keep across the move.
  ## The path policy recommends a LANE; this is what turns that into the
  ## parameters a link actually sends with. One preset per lane, so a lane
  ## move is a complete, validated parameter set rather than a field poke.
  case p
  of dplSuperCleanPath:
    result = superCleanDacDefaults(c)
  of dplCleanPath:
    result = cleanLanDacDefaults(c)
  of dplMobilePath:
    result = mobileDacDefaults(c)
  of dplThinPath:
    result = thinDacDefaults(c)
  of dplLossyPath:
    result = badSignalDacDefaults(c)
  of dplBlockedUdpPath:
    result = blockedUdpDacDefaults(c)
  of dplRecoveryPath:
    result = recoveryWeakDacDefaults()
