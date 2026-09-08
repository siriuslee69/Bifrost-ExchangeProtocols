## ----------------------------------------------------------------------
## DAC Framing <- fixed header helpers and ASCII frame flag definitions
## ----------------------------------------------------------------------

import ../../types
import ../types
import ../../../analysis_pragmas

const
  dacKnownFrameFlagMask* = 0x01FF'u16
  dacFrameFlagsAscii* = """
+------+----------------------+------------------------------------------------+
| Bit  | Name                 | Meaning                                        |
+------+----------------------+------------------------------------------------+
| 0    | NeedsAck             | receiver should emit ACK or batch ACK          |
| 1    | IsRepair             | body contains repair data or repair request    |
| 2    | IsParity             | body carries parity, not original data         |
| 3    | EndOfGroup           | last frame in current repair group             |
| 4    | EndOfPackage         | package data is complete from sender side      |
| 5    | PathProbe            | frame is used for path detection               |
| 6    | CreditBound          | sender is obeying receive-credit budget        |
| 7    | TcpRepairAllowed     | receiver may request exact TCP repair          |
| 8    | ExtendedBodyLen      | BodyLen is u32, used by SuperCleanPath         |
+------+----------------------+------------------------------------------------+
"""

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

proc dacBodyLenModeForPath*(p: DacPathLane): DacBodyLenMode {.role: truthBuilder.} =
  ## p: path lane used to select body length width.
  case p
  of dplSuperCleanPath:
    result = dblU32
  else:
    result = dblU16

proc dacHeaderLenForMode*(m: DacBodyLenMode): uint8 {.role: truthBuilder.} =
  ## m: body length width mode.
  case m
  of dblU32:
    result = uint8(dacExtendedHeaderLen)
  else:
    result = uint8(dacBaseHeaderLen)

proc dacMaxBodyLenForMode*(m: DacBodyLenMode): uint32 {.role: truthBuilder.} =
  ## m: body length width mode.
  case m
  of dblU32:
    result = high(uint32)
  else:
    result = uint32(high(uint16))

proc dacMessageKindFromId*(id: uint8): DacMessageKind {.role: parser.} =
  ## id: raw message kind id.
  case id
  of 0x01'u8:
    result = dmkPathProbe
  of 0x02'u8:
    result = dmkPathStats
  of 0x03'u8:
    result = dmkPackageManifest
  of 0x04'u8:
    result = dmkPackageChunk
  of 0x05'u8:
    result = dmkParityShard
  of 0x06'u8:
    result = dmkAckRange
  of 0x07'u8:
    result = dmkRepairHint
  of 0x08'u8:
    result = dmkRepairChunk
  of 0x09'u8:
    result = dmkPackageCommit
  of 0x0A'u8:
    result = dmkPathSwitchRequest
  of 0x0B'u8:
    result = dmkPathSwitchAck
  of 0x0C'u8:
    result = dmkDriftPayload
  else:
    result = dmkUnknown

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

proc packDacFrameFlags*(f: DacFrameFlags): uint16 {.role: truthBuilder.} =
  ## f: structured frame flags.
  if f.needsAck:
    result = result or 0x0001'u16
  if f.isRepair:
    result = result or 0x0002'u16
  if f.isParity:
    result = result or 0x0004'u16
  if f.endOfGroup:
    result = result or 0x0008'u16
  if f.endOfPackage:
    result = result or 0x0010'u16
  if f.pathProbe:
    result = result or 0x0020'u16
  if f.creditBound:
    result = result or 0x0040'u16
  if f.tcpRepairAllowed:
    result = result or 0x0080'u16
  if f.extendedBodyLen:
    result = result or 0x0100'u16

proc unpackDacFrameFlags*(bits: uint16): DacFrameFlags {.role: parser.} =
  ## bits: packed DAC frame flags.
  if (bits and (not dacKnownFrameFlagMask)) != 0'u16:
    raise newException(ValueError, "DAC frame has unknown flag bits")
  result.needsAck = (bits and 0x0001'u16) != 0'u16
  result.isRepair = (bits and 0x0002'u16) != 0'u16
  result.isParity = (bits and 0x0004'u16) != 0'u16
  result.endOfGroup = (bits and 0x0008'u16) != 0'u16
  result.endOfPackage = (bits and 0x0010'u16) != 0'u16
  result.pathProbe = (bits and 0x0020'u16) != 0'u16
  result.creditBound = (bits and 0x0040'u16) != 0'u16
  result.tcpRepairAllowed = (bits and 0x0080'u16) != 0'u16
  result.extendedBodyLen = (bits and 0x0100'u16) != 0'u16

proc initDacFrameHeader*(k: DacMessageKind, sessionId: uint64,
    laneId: uint32, epochId: uint16, sequence: uint32, bodyLen: uint32,
    flags: DacFrameFlags): DacFrameHeader {.role: configurator.} =
  ## k/sessionId/laneId/epochId/sequence/bodyLen: fixed frame metadata.
  ## flags: structured flags to pack into the header.
  var
    f: DacFrameFlags
  f = flags
  if k == dmkUnknown:
    raise newException(ValueError, "DAC frame kind must not be unknown")
  if f.extendedBodyLen or bodyLen > uint32(high(uint16)):
    raise newException(ValueError, "DAC extended body length requires SuperClean framing")
  result.magic = dacMagic
  result.formatVersion = dacFormatVersion
  result.messageKind = k
  result.flags = packDacFrameFlags(f)
  result.sessionId = sessionId
  result.laneId = laneId
  result.epochId = epochId
  result.sequence = sequence
  result.bodyLenMode = dblU16
  result.bodyLen = bodyLen

proc initDacSuperCleanFrameHeader*(k: DacMessageKind, sessionId: uint64,
    laneId: uint32, epochId: uint16, sequence: uint32, bodyLen: uint32,
    flags: DacFrameFlags): DacFrameHeader {.role: configurator.} =
  ## k/sessionId/laneId/epochId/sequence/bodyLen: extended clean-path metadata.
  ## flags: structured flags to pack with ExtendedBodyLen forced on.
  var
    f: DacFrameFlags
  if k == dmkUnknown:
    raise newException(ValueError, "DAC frame kind must not be unknown")
  if bodyLen > dacSuperCleanMaxBodyLen:
    raise newException(ValueError, "DAC SuperClean body length exceeds limit")
  f = flags
  f.extendedBodyLen = true
  result.magic = dacMagic
  result.formatVersion = dacFormatVersion
  result.messageKind = k
  result.flags = packDacFrameFlags(f)
  result.sessionId = sessionId
  result.laneId = laneId
  result.epochId = epochId
  result.sequence = sequence
  result.bodyLenMode = dblU32
  result.bodyLen = bodyLen

proc dacHeaderFlagsMatchMode(h: DacFrameHeader, f: DacFrameFlags): bool {.role: parser.} =
  ## h: DAC header to inspect.
  ## f: unpacked frame flags.
  result = (h.bodyLenMode == dblU32 and f.extendedBodyLen) or
    (h.bodyLenMode == dblU16 and not f.extendedBodyLen)

proc validateDacFrameHeader*(h: DacFrameHeader): bool {.role: parser.} =
  ## h: DAC frame header to validate before encoding.
  var
    f: DacFrameFlags
  if h.magic != dacMagic:
    return false
  if h.formatVersion != dacFormatVersion:
    return false
  if h.messageKind == dmkUnknown:
    return false
  try:
    f = unpackDacFrameFlags(h.flags)
  except CatchableError:
    return false
  if not dacHeaderFlagsMatchMode(h, f):
    return false
  if h.bodyLenMode == dblU16 and h.bodyLen > uint32(high(uint16)):
    return false
  if h.bodyLenMode == dblU32 and h.bodyLen > dacSuperCleanMaxBodyLen:
    return false
  result = true

proc encodeDacFrame*(h: DacFrameHeader,
    payload: openArray[uint8]): ByteSeq {.role: dataWriter.} =
  ## h: DAC frame header.
  ## payload: body bytes to carry.
  var
    i: int = 0
  if not validateDacFrameHeader(h):
    raise newException(ValueError, "DAC frame header is invalid")
  if h.bodyLen != uint32(payload.len):
    raise newException(ValueError, "DAC frame body length mismatch")
  while i < dacMagic.len:
    result.add(h.magic[i])
    i = i + 1
  result.add(h.formatVersion)
  result.add(uint8(ord(h.messageKind)))
  appendDacU16(result, h.flags)
  appendDacU64(result, h.sessionId)
  appendDacU32(result, h.laneId)
  appendDacU16(result, h.epochId)
  appendDacU32(result, h.sequence)
  case h.bodyLenMode
  of dblU16:
    appendDacU16(result, uint16(h.bodyLen))
  of dblU32:
    appendDacU32(result, h.bodyLen)
  for b in payload:
    result.add(b)

proc dacPrefixMagicOk(A: openArray[uint8]): bool {.role: parser.} =
  ## A: arriving bytes whose first four header bytes are checked.
  var
    i: int = 0
  if A.len < dacBaseHeaderLen:
    return false
  while i < dacMagic.len:
    if A[i] != dacMagic[i]:
      return false
    i = i + 1
  result = A[3] == dacFormatVersion

proc dacPrefixFlags(A: openArray[uint8], f: var DacFrameFlags): bool {.role: parser.} =
  ## A: arriving bytes.
  ## f: receives the unpacked flags when they are all defined.
  try:
    f = unpackDacFrameFlags(readDacU16(A, 5))
  except CatchableError:
    return false
  result = true

proc dacPrefixBodyLen(A: openArray[uint8], f: DacFrameFlags): uint32 {.role: parser.} =
  ## A: arriving bytes, already known to hold the matching header width.
  ## f: flags selecting the body length width.
  if f.extendedBodyLen:
    return readDacU32(A, 25)
  result = uint32(readDacU16(A, 25))

proc peekDacFrameIdentity*(A: openArray[uint8]): DacFrameIdentity {.role: parser.} =
  ## A: bytes as they arrived, of any length and any content.
  ## Reads only the fixed prefix, so a datagram that is not for us costs no
  ## allocation and no body parse. It returns `ok = false` instead of raising,
  ## because a dispatcher holding many peers reaches this on every arriving
  ## packet and refusing one must be the cheapest path through it. Every field
  ## stays zero unless `ok` is true, so a caller cannot read half an identity.
  var
    flags: DacFrameFlags
    headerLen: int = dacBaseHeaderLen
    bodyLen: uint32 = 0'u32
    kind: DacMessageKind = dmkUnknown
  if not dacPrefixMagicOk(A):
    return
  kind = dacMessageKindFromId(A[4])
  if kind == dmkUnknown:
    return
  if not dacPrefixFlags(A, flags):
    return
  if flags.extendedBodyLen:
    headerLen = dacExtendedHeaderLen
  if A.len < headerLen:
    return
  bodyLen = dacPrefixBodyLen(A, flags)
  if flags.extendedBodyLen and bodyLen > dacSuperCleanMaxBodyLen:
    return
  if A.len != headerLen + int(bodyLen):
    return
  result.messageKind = kind
  result.sessionId = readDacU64(A, 7)
  result.laneId = readDacU32(A, 15)
  result.epochId = readDacU16(A, 19)
  result.sequence = readDacU32(A, 21)
  result.bodyLen = bodyLen
  result.headerLen = headerLen
  result.ok = true

proc decodeDacFrame*(A: openArray[uint8]): DacDecodedFrame {.role: parser.} =
  ## A: complete DAC1 frame bytes.
  var
    flags: DacFrameFlags
    mode: DacBodyLenMode = dblU16
    headerLen: int = dacBaseHeaderLen
    bodyLen: uint32 = 0'u32
    i: int = 0
  if A.len < dacBaseHeaderLen:
    raise newException(ValueError, "DAC frame too short")
  while i < dacMagic.len:
    if A[i] != dacMagic[i]:
      raise newException(ValueError, "DAC magic mismatch")
    i = i + 1
  if A[3] != dacFormatVersion:
    raise newException(ValueError, "DAC format version mismatch")
  result.header.messageKind = dacMessageKindFromId(A[4])
  if result.header.messageKind == dmkUnknown:
    raise newException(ValueError, "DAC message kind mismatch")
  result.header.flags = readDacU16(A, 5)
  flags = unpackDacFrameFlags(result.header.flags)
  if flags.extendedBodyLen:
    mode = dblU32
    headerLen = dacExtendedHeaderLen
  if A.len < headerLen:
    raise newException(ValueError, "DAC frame too short")
  if mode == dblU16:
    bodyLen = uint32(readDacU16(A, 25))
  else:
    bodyLen = readDacU32(A, 25)
  if mode == dblU32 and bodyLen > dacSuperCleanMaxBodyLen:
    raise newException(ValueError, "DAC SuperClean body length exceeds limit")
  if A.len != headerLen + int(bodyLen):
    raise newException(ValueError, "DAC frame body length mismatch")
  result.header.magic = dacMagic
  result.header.formatVersion = dacFormatVersion
  result.header.sessionId = readDacU64(A, 7)
  result.header.laneId = readDacU32(A, 15)
  result.header.epochId = readDacU16(A, 19)
  result.header.sequence = readDacU32(A, 21)
  result.header.bodyLenMode = mode
  result.header.bodyLen = bodyLen
  result.flags = flags
  result.payload = newSeq[uint8](int(bodyLen))
  i = 0
  while i < int(bodyLen):
    result.payload[i] = A[headerLen + i]
    i = i + 1
