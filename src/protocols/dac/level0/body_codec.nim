## --------------------------------------------------------------------
## DAC Body Codec <- shared little-endian helpers and enum decoders
## --------------------------------------------------------------------

import ../../types
import ../types
import runePragmas

proc appendDacU16*(dst: var ByteSeq, v: uint16) {.role: dataWriter.} =
  ## dst: destination byte sequence.
  ## v: little-endian uint16 to append.
  dst.add(uint8(v and 0xff'u16))
  dst.add(uint8((v shr 8) and 0xff'u16))

proc appendDacU32*(dst: var ByteSeq, v: uint32) {.role: dataWriter.} =
  ## dst: destination byte sequence.
  ## v: little-endian uint32 to append.
  dst.add(uint8(v and 0xff'u32))
  dst.add(uint8((v shr 8) and 0xff'u32))
  dst.add(uint8((v shr 16) and 0xff'u32))
  dst.add(uint8((v shr 24) and 0xff'u32))

proc appendDacU64*(dst: var ByteSeq, v: uint64) {.role: dataWriter.} =
  ## dst: destination byte sequence.
  ## v: little-endian uint64 to append.
  var
    i: int = 0
  while i < 8:
    dst.add(uint8((v shr (8 * i)) and 0xff'u64))
    i = i + 1

proc appendDacBytes*(dst: var ByteSeq, A: openArray[uint8]) {.role: dataWriter.} =
  ## dst: destination byte sequence.
  ## A: byte range to append.
  for b in A:
    dst.add(b)

proc appendDacZeroBytes*(dst: var ByteSeq, count: int) {.role: dataWriter.} =
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

proc dacEnumFromId[T: enum](id: uint8, what: string): T {.role: parser,
    inline.} =
  ## id: the raw byte off the wire.
  ## what: the field's name, used only to word the refusal.
  ##
  ## Every DAC enum below is uint8-backed and numbered from 0x00 upward with
  ## no gaps, so the byte IS the ordinal and no lookup table is needed:
  ##
  ##   byte 0x00  0x01  0x02  0x03  ...  high(T)   past high(T)
  ##        |     |     |     |          |         |
  ##        v     v     v     v          v         raise ValueError
  ##       name0 name1 name2 name3      nameN
  ##
  ## Adding a name to one of those enums extends the accepted range on its
  ## own. Giving one an explicit non-contiguous value would break that, which
  ## is why the enums state every value rather than leaving them implicit.
  if id > uint8(ord(high(T))):
    raise newException(ValueError, "DAC " & what & " id mismatch")
  result = T(id)

proc dacPathLaneFromId*(id: uint8): DacPathLane {.role: parser.} =
  ## id: raw DAC path lane byte.
  result = dacEnumFromId[DacPathLane](id, "path lane")

proc dacTransferClassFromId*(id: uint8): DacTransferClass {.role: parser.} =
  ## id: raw DAC transfer class byte.
  result = dacEnumFromId[DacTransferClass](id, "transfer class")

proc dacRepairModeFromId*(id: uint8): DacRepairMode {.role: parser.} =
  ## id: raw DAC repair mode byte.
  result = dacEnumFromId[DacRepairMode](id, "repair mode")

proc dacRepairReasonFromId*(id: uint8): DacRepairReason {.role: parser.} =
  ## id: raw DAC repair reason byte.
  result = dacEnumFromId[DacRepairReason](id, "repair reason")

proc dacRepairSourceFromId*(id: uint8): DacRepairSource {.role: parser.} =
  ## id: raw DAC repair source byte.
  result = dacEnumFromId[DacRepairSource](id, "repair source")

proc dacCommitStatusFromId*(id: uint8): DacCommitStatus {.role: parser.} =
  ## id: raw DAC commit status byte.
  result = dacEnumFromId[DacCommitStatus](id, "commit status")

proc dacPathSwitchReasonFromId*(id: uint8): DacPathSwitchReason {.
    role: parser.} =
  ## id: raw DAC path-switch reason byte.
  result = dacEnumFromId[DacPathSwitchReason](id, "path switch reason")
