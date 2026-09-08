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
| NAT/path unstable           | Mobile + Lossy    | 768         | 16D + 3P    | 16 chunks | 500 ms      | 300 ms      |
| Receiver overloaded         | ThinPath          | 576         | 8D + 1P     | 8 chunks  | 1500 ms     | 1000 ms     |
| Battery saver               | MobilePath        | 900         | 16D + 1P    | 64 chunks | 2500 ms     | 1000 ms     |
| Critical weak recovery      | Lossy + Recovery  | 512         | 8D + 6P     | 4 chunks  | 200 ms      | 150 ms      |
+-----------------------------+-------------------+-------------+-------------+-----------+-------------+-------------+

The BlockedUdpPath lane has no row. It is the one lane that is not a set
of datagram parameters: it means UDP does not work on this path at all, and
the answer to it is the TCP carrier rather than a gentler DAC profile.

The ACK batch and deadline are a starting point, not a fixed rule: the
receiver moves them from what it observes arriving. Notice that heavy loss
gets the SMALL batch, not the large one -- every un-acknowledged frame is
retransmit state the sender cannot free. Long deadlines are for battery
radios, where the cost being saved is a wake-up, not bandwidth.
"""

proc initDacDefaults*(p: DacPathLane, c: DacTransferClass,
    repair: DacRepairMode, ack: DacAckMode, chunkBytes, dataShards,
    parityShards, ackBatchChunks, ackMaxDelayMs, repairWaitMs: uint16,
    repairRounds: uint8,
    bodyLenMode: DacBodyLenMode = dblU16,
    maxBodyLen: uint32 = uint32(high(uint16))): DacScenarioDefaults {.role: configurator.} =
  ## p/c/repair/ack: path, transfer, repair, and ACK policies.
  ## chunkBytes/dataShards/parityShards: frame and repair-group sizing.
  ## ackBatchChunks/ackMaxDelayMs: starting ACK batch size and time bound.
  ## repairWaitMs/repairRounds: repair control defaults.
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
  if d.dataShards == 0'u16:
    return false
  if d.repairMode == drmNone:
    result = d.parityShards == 0'u16
    return
  result = d.parityShards > 0'u16 and d.repairRounds > 0'u8

type
  ## DacScenario: which row of the table above is meant. The lane says what
  ## the path is like; the scenario says which set of numbers to send with.
  ## Several scenarios share a lane -- bad signal, heavy loss, jitter and an
  ## unstable path are all `dplLossyPath` and want different parity.
  DacScenario* = enum
    dscSameRoom, dscCleanLan, dscMobile, dscMetered, dscThin,
    dscBadSignal, dscHeavyLoss, dscJitter, dscUnstablePath,
    dscOverloaded, dscBatterySaver, dscWeakRecovery

  ## One row of numbers, in the order the table above prints them.
  DacScenarioPreset = tuple
    lane: DacPathLane
    repair: DacRepairMode
    ack: DacAckMode
    chunkBytes: uint16
    dataShards: uint16
    parityShards: uint16
    ackBatchChunks: uint16
    ackMaxDelayMs: uint16
    repairWaitMs: uint16
    repairRounds: uint8
    bodyLenMode: DacBodyLenMode
    maxBodyLen: uint32
    forcedClass: bool

const
  ## The table at the top of this file, as data. It used to be twelve
  ## near-identical procs that differed only in these numbers, so the
  ## documentation and the code could drift apart without anything noticing.
  dacScenarioPresets: array[DacScenario, DacScenarioPreset] = [
    (dplSuperCleanPath, drmNone, damBatch, 32768'u16, 64'u16, 0'u16,
      256'u16, 25'u16, 25'u16, 1'u8, dblU32, dacSuperCleanMaxBodyLen, false),
    (dplCleanPath, drmXor, damBatch, 1200'u16, 32'u16, 1'u16,
      64'u16, 100'u16, 75'u16, 2'u8, dblU16, uint32(high(uint16)), false),
    (dplMobilePath, drmReedSolomon, damBatch, 900'u16, 24'u16, 2'u16,
      32'u16, 400'u16, 250'u16, 2'u8, dblU16, uint32(high(uint16)), false),
    (dplThinPath, drmTcpExact, damNackOnly, 700'u16, 16'u16, 1'u16,
      16'u16, 700'u16, 500'u16, 2'u8, dblU16, uint32(high(uint16)), false),
    (dplThinPath, drmXor, damBatch, 576'u16, 12'u16, 1'u16,
      12'u16, 1000'u16, 700'u16, 2'u8, dblU16, uint32(high(uint16)), false),
    (dplLossyPath, drmReedSolomon, damBatch, 768'u16, 16'u16, 4'u16,
      16'u16, 500'u16, 350'u16, 3'u8, dblU16, uint32(high(uint16)), false),
    (dplLossyPath, drmReedSolomon, damExplicit, 512'u16, 12'u16, 6'u16,
      8'u16, 300'u16, 200'u16, 3'u8, dblU16, uint32(high(uint16)), false),
    (dplLossyPath, drmReedSolomon, damBatch, 1000'u16, 24'u16, 3'u16,
      32'u16, 1200'u16, 900'u16, 3'u8, dblU16, uint32(high(uint16)), false),
    (dplLossyPath, drmReedSolomon, damBatch, 768'u16, 16'u16, 3'u16,
      16'u16, 500'u16, 300'u16, 3'u8, dblU16, uint32(high(uint16)), false),
    (dplThinPath, drmXor, damBatch, 576'u16, 8'u16, 1'u16,
      8'u16, 1500'u16, 1000'u16, 1'u8, dblU16, uint32(high(uint16)), false),
    (dplMobilePath, drmXor, damBatch, 900'u16, 16'u16, 1'u16,
      64'u16, 2500'u16, 1000'u16, 1'u8, dblU16, uint32(high(uint16)), false),
    (dplRecoveryPath, drmReedSolomon, damVerified, 512'u16, 8'u16, 6'u16,
      4'u16, 200'u16, 150'u16, 4'u8, dblU16, uint32(high(uint16)), true)
  ]

proc dacDefaultsFor*(s: DacScenario,
    c: DacTransferClass = dtcUserData): DacScenarioDefaults {.
    role: configurator.} =
  ## s: which row of the scenario table is wanted.
  ## c: transfer class, ignored by the one scenario that fixes its own.
  ##
  ## Weak recovery is that one: it exists to get bytes through a path that is
  ## barely working, so calling it with `dtcUserData` and getting user-data
  ## pacing back would defeat the point.
  var
    p: DacScenarioPreset = dacScenarioPresets[s]
    cls: DacTransferClass = c
  if p.forcedClass:
    cls = dtcRecovery
  result = initDacDefaults(p.lane, cls, p.repair, p.ack, p.chunkBytes,
    p.dataShards, p.parityShards, p.ackBatchChunks, p.ackMaxDelayMs,
    p.repairWaitMs, p.repairRounds, p.bodyLenMode, p.maxBodyLen)

proc dacDefaultsForPath*(p: DacPathLane,
    c: DacTransferClass = dtcUserData): DacScenarioDefaults {.role: truthBuilder.} =
  ## p: path lane a policy decision landed on.
  ## c: transfer class to keep across the move.
  ## The path policy recommends a LANE; this is what turns that into the
  ## parameters a link actually sends with. One preset per lane, so a lane
  ## move is a complete, validated parameter set rather than a field poke.
  case p
  of dplSuperCleanPath:
    result = dacDefaultsFor(dscSameRoom, c)
  of dplCleanPath:
    result = dacDefaultsFor(dscCleanLan, c)
  of dplMobilePath:
    result = dacDefaultsFor(dscMobile, c)
  of dplThinPath:
    result = dacDefaultsFor(dscThin, c)
  of dplLossyPath:
    result = dacDefaultsFor(dscBadSignal, c)
  of dplBlockedUdpPath:
    ## There is no datagram policy for a path that carries no datagrams.
    ## The lane is a signal, not a configuration: a peer reporting it is
    ## saying "UDP does not work here", and the answer is a different
    ## carrier, not different DAC parameters. Asking for defaults on this
    ## lane means a caller kept sending where sending cannot work, so it
    ## fails loudly and names the fix.
    raise newException(ValueError,
      "DAC has no defaults for a blocked-UDP path; carry the session over " &
      "the TCP carrier (acrTcp) instead")
  of dplRecoveryPath:
    result = dacDefaultsFor(dscWeakRecovery)
