## ----------------------------------------------------------------------
## DAC Wire Helpers <- little-endian readers/writers and message-kind names
## ----------------------------------------------------------------------

import ../../types
import ../types
import runePragmas

proc appendDacU16(dst: var ByteSeq, v: uint16) {.role: dataWriter.} =
  ## dst: destination byte sequence.
  ## v: little-endian uint16 to append.
  dst.add(uint8(v and 0xff'u16))
  dst.add(uint8((v shr 8) and 0xff'u16))

proc appendDacU32(dst: var ByteSeq, v: uint32) {.role: dataWriter.} =
  ## dst: destination byte sequence.
  ## v: little-endian uint32 to append.
  dst.add(uint8(v and 0xff'u32))
  dst.add(uint8((v shr 8) and 0xff'u32))
  dst.add(uint8((v shr 16) and 0xff'u32))
  dst.add(uint8((v shr 24) and 0xff'u32))

proc appendDacU64(dst: var ByteSeq, v: uint64) {.role: dataWriter.} =
  ## dst: destination byte sequence.
  ## v: little-endian uint64 to append.
  var
    i: int = 0
  while i < 8:
    dst.add(uint8((v shr (8 * i)) and 0xff'u64))
    i = i + 1

proc readDacU16(A: openArray[uint8], o: int): uint16 {.role: parser.} =
  ## A: source bytes.
  ## o: byte offset.
  result = uint16(A[o]) or (uint16(A[o + 1]) shl 8)

proc readDacU32(A: openArray[uint8], o: int): uint32 {.role: parser.} =
  ## A: source bytes.
  ## o: byte offset.
  result = uint32(A[o]) or (uint32(A[o + 1]) shl 8) or
    (uint32(A[o + 2]) shl 16) or (uint32(A[o + 3]) shl 24)

proc readDacU64(A: openArray[uint8], o: int): uint64 {.role: parser.} =
  ## A: source bytes.
  ## o: byte offset.
  var
    i: int = 0
  while i < 8:
    result = result or (uint64(A[o + i]) shl (8 * i))
    i = i + 1

proc dacMessageKindFromId*(id: uint8): DacMessageKind {.role: parser.} =
  ## id: the first byte of a DAC body, exactly as it came off the wire.
  ##
  ## An id no kind claims reads as `dmkUnknown`. It does NOT raise: this runs
  ## on a byte a peer chose, and the caller's answer to "I do not know this
  ## word" is to drop the message, not to unwind.
  ##
  ## The enum states every value, so the byte IS the kind and there is nothing
  ## to keep in step. This used to be a twenty-two line case that listed each
  ## id a second time, and it had already drifted from the enum once.
  if id > uint8(ord(high(DacMessageKind))):
    return dmkUnknown
  result = DacMessageKind(id)

proc dacPathLaneName*(p: DacPathLane): string {.role: truthBuilder.} =
  ## p: path lane to render.
  case p
  of dplCleanPath:
    result = "CleanPath"
  of dplMobilePath:
    result = "MobilePath"
  of dplThinPath:
    result = "ThinPath"
  of dplLossyPath:
    result = "LossyPath"
  of dplBlockedUdpPath:
    result = "BlockedUdpPath"
  of dplRecoveryPath:
    result = "RecoveryPath"
  of dplSuperCleanPath:
    result = "SuperCleanPath"

proc dacTransferClassName*(c: DacTransferClass): string {.role: truthBuilder.} =
  ## c: transfer class to render.
  case c
  of dtcStatus:
    result = "Status"
  of dtcControl:
    result = "Control"
  of dtcUserData:
    result = "UserData"
  of dtcArchive:
    result = "Archive"
  of dtcRecovery:
    result = "Recovery"
  of dtcRealtime:
    result = "Realtime"

