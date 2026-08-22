## --------------------------------------------------------------------
## DAC Body Codec <- shared little-endian helpers and enum decoders
## --------------------------------------------------------------------

import ../../types
import ../types
import ../../../analysis_pragmas

proc appendDacU16*(dst: var ByteSeq, v: uint16) {.role: stateController.} =
  ## dst: destination byte sequence.
  ## v: little-endian uint16 to append.
  dst.add(uint8(v and 0xff'u16))
  dst.add(uint8((v shr 8) and 0xff'u16))

proc appendDacU32*(dst: var ByteSeq, v: uint32) {.role: stateController.} =
  ## dst: destination byte sequence.
  ## v: little-endian uint32 to append.
  dst.add(uint8(v and 0xff'u32))
  dst.add(uint8((v shr 8) and 0xff'u32))
  dst.add(uint8((v shr 16) and 0xff'u32))
  dst.add(uint8((v shr 24) and 0xff'u32))

proc appendDacU64*(dst: var ByteSeq, v: uint64) {.role: stateController.} =
  ## dst: destination byte sequence.
  ## v: little-endian uint64 to append.
  var
    i: int = 0
  while i < 8:
    dst.add(uint8((v shr (8 * i)) and 0xff'u64))
    i = i + 1

proc appendDacBytes*(dst: var ByteSeq, A: openArray[uint8]) {.role: stateController.} =
  ## dst: destination byte sequence.
  ## A: byte range to append.
  for b in A:
    dst.add(b)

proc appendDacZeroBytes*(dst: var ByteSeq, count: int) {.role: stateController.} =
  ## dst: destination byte sequence.
  ## count: number of zero bytes to append.
  var
    i: int = 0
  if count < 0:
    raise newException(ValueError, "DAC zero-pad count must not be negative")
  while i < count:
    dst.add(0'u8)
    i = i + 1

proc readDacU16*(A: openArray[uint8], o: int): uint16 {.role: parser.} =
  ## A: source bytes.
  ## o: byte offset.
  result = uint16(A[o]) or (uint16(A[o + 1]) shl 8)

proc readDacU32*(A: openArray[uint8], o: int): uint32 {.role: parser.} =
  ## A: source bytes.
  ## o: byte offset.
  result = uint32(A[o]) or (uint32(A[o + 1]) shl 8) or
    (uint32(A[o + 2]) shl 16) or (uint32(A[o + 3]) shl 24)

proc readDacU64*(A: openArray[uint8], o: int): uint64 {.role: parser.} =
  ## A: source bytes.
  ## o: byte offset.
  var
    i: int = 0
  while i < 8:
    result = result or (uint64(A[o + i]) shl (8 * i))
    i = i + 1

proc copyDacSpan*(A: openArray[uint8], offset, count: int): ByteSeq {.role: helper.} =
  ## A: source bytes.
  ## offset/count: span to copy.
  var
    i: int = 0
  if offset < 0 or count < 0 or offset > A.len or count > A.len - offset:
    raise newException(ValueError, "DAC body slice is out of bounds")
  result = newSeq[uint8](count)
  while i < count:
    result[i] = A[offset + i]
    i = i + 1

proc copyDacBytes*(A: openArray[uint8]): ByteSeq {.role: helper.} =
  ## A: source bytes to copy in full.
  result = copyDacSpan(A, 0, A.len)

proc rangeIsZero*(A: openArray[uint8], offset, count: int): bool {.role: parser.} =
  ## A: source bytes.
  ## offset/count: span to test for all-zero bytes.
  var
    i: int = 0
  if offset < 0 or count < 0 or offset > A.len or count > A.len - offset:
    return false
  result = true
  while i < count:
    if A[offset + i] != 0'u8:
      return false
    i = i + 1

proc dacPathLaneFromId*(id: uint8): DacPathLane {.role: parser.} =
  ## id: raw DAC path lane byte.
  case id
  of 0x00'u8:
    result = dplCleanPath
  of 0x01'u8:
    result = dplMobilePath
  of 0x02'u8:
    result = dplThinPath
  of 0x03'u8:
    result = dplLossyPath
  of 0x04'u8:
    result = dplBlockedUdpPath
  of 0x05'u8:
    result = dplRecoveryPath
  of 0x06'u8:
    result = dplSuperCleanPath
  else:
    raise newException(ValueError, "DAC path lane id mismatch")

proc dacTransferClassFromId*(id: uint8): DacTransferClass {.role: parser.} =
  ## id: raw DAC transfer class byte.
  case id
  of 0x00'u8:
    result = dtcStatus
  of 0x01'u8:
    result = dtcControl
  of 0x02'u8:
    result = dtcUserData
  of 0x03'u8:
    result = dtcArchive
  of 0x04'u8:
    result = dtcRecovery
  of 0x05'u8:
    result = dtcRealtime
  else:
    raise newException(ValueError, "DAC transfer class id mismatch")

proc dacRepairModeFromId*(id: uint8): DacRepairMode {.role: parser.} =
  ## id: raw DAC repair mode byte.
  case id
  of 0x00'u8:
    result = drmNone
  of 0x01'u8:
    result = drmXor
  of 0x02'u8:
    result = drmReedSolomon
  of 0x03'u8:
    result = drmTcpExact
  else:
    raise newException(ValueError, "DAC repair mode id mismatch")

proc dacRepairReasonFromId*(id: uint8): DacRepairReason {.role: parser.} =
  ## id: raw DAC repair reason byte.
  case id
  of 0x00'u8:
    result = drrMissing
  of 0x01'u8:
    result = drrCorrupt
  of 0x02'u8:
    result = drrDecodeFailed
  of 0x03'u8:
    result = drrTimeout
  else:
    raise newException(ValueError, "DAC repair reason id mismatch")

proc dacRepairSourceFromId*(id: uint8): DacRepairSource {.role: parser.} =
  ## id: raw DAC repair source byte.
  case id
  of 0x00'u8:
    result = drsUdpExtraParity
  of 0x01'u8:
    result = drsTcpExactChunk
  of 0x02'u8:
    result = drsTcpFullFallback
  else:
    raise newException(ValueError, "DAC repair source id mismatch")

proc dacCommitStatusFromId*(id: uint8): DacCommitStatus {.role: parser.} =
  ## id: raw DAC commit status byte.
  case id
  of 0x00'u8:
    result = dcsRejected
  of 0x01'u8:
    result = dcsCommitted
  of 0x02'u8:
    result = dcsCommittedWithRepair
  of 0x03'u8:
    result = dcsExpired
  else:
    raise newException(ValueError, "DAC commit status id mismatch")

proc dacPathSwitchReasonFromId*(id: uint8): DacPathSwitchReason {.role: parser.} =
  ## id: raw DAC path-switch reason byte.
  case id
  of 0x00'u8:
    result = dpsrLoss
  of 0x01'u8:
    result = dpsrMetered
  of 0x02'u8:
    result = dpsrUdpBlocked
  of 0x03'u8:
    result = dpsrAddressChanged
  of 0x04'u8:
    result = dpsrReceiverPressure
  of 0x05'u8:
    result = dpsrBatterySaver
  else:
    raise newException(ValueError, "DAC path switch reason id mismatch")
