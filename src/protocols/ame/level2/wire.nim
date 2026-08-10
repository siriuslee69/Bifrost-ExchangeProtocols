## -------------------------------------------------------------------------
## AME Wire <- fixed AME2 frame header and exact payload framing
## -------------------------------------------------------------------------

import ../../types
import ../types
import ../level0/bytes
import ../../../analysis_pragmas

proc readU16(A: openArray[uint8], o: int): uint16 {.role: parser.} =
  ## A/o: source bytes and little-endian offset.
  result = uint16(A[o]) or (uint16(A[o + 1]) shl 8)

proc readU32(A: openArray[uint8], o: int): uint32 {.role: parser.} =
  ## A/o: source bytes and little-endian offset.
  result = uint32(A[o]) or (uint32(A[o + 1]) shl 8) or
    (uint32(A[o + 2]) shl 16) or (uint32(A[o + 3]) shl 24)

proc readU64(A: openArray[uint8], o: int): uint64 {.role: parser.} =
  ## A/o: source bytes and little-endian offset.
  var i: int = 0
  while i < 8:
    result = result or (uint64(A[o + i]) shl (8 * i))
    i = i + 1

proc packetKindValid(id: uint8): bool {.role: parser.} =
  ## id: AME2 packet kind wire value.
  result = id <= uint8(ord(high(AmePacketKind)))

proc messageClassValid(id: uint8): bool {.role: parser.} =
  ## id: AME2 message class wire value.
  result = id <= uint8(ord(high(AmeMessageClass)))

proc initAmeFrameHeader*(kind: AmePacketKind, messageClass: AmeMessageClass,
    sessionId: uint64, rootLaneId, parentLaneId, laneId, sequence,
    payloadLen: uint32): AmeFrameHeader {.role: wrapper.} =
  ## kind/messageClass/session/lane/sequence/payloadLen: exact frame metadata.
  if kind == ampkUnknown:
    raise newException(ValueError, "AME packet kind is unknown")
  result.magic = ameMagic
  result.formatVersion = ameFormatVersion
  result.packetKind = kind
  result.messageClass = messageClass
  result.sessionId = sessionId
  result.rootLaneId = rootLaneId
  result.parentLaneId = parentLaneId
  result.laneId = laneId
  result.sequence = sequence
  result.payloadLen = payloadLen

proc encodeAmeFrameHeader*(h: AmeFrameHeader): ByteSeq {.
    role: stateController.} =
  ## h: validated AME2 fixed header.
  var i: int = 0
  if h.magic != ameMagic or h.formatVersion != ameFormatVersion:
    raise newException(ValueError, "AME frame header identity mismatch")
  if h.packetKind == ampkUnknown:
    raise newException(ValueError, "AME packet kind is unknown")
  while i < ameMagic.len:
    result.add(h.magic[i])
    i = i + 1
  appendAmeU16(result, h.formatVersion)
  result.add(uint8(ord(h.packetKind)))
  result.add(uint8(ord(h.messageClass)))
  appendAmeU64(result, h.sessionId)
  appendAmeU32(result, h.rootLaneId)
  appendAmeU32(result, h.parentLaneId)
  appendAmeU32(result, h.laneId)
  appendAmeU32(result, h.sequence)
  appendAmeU32(result, h.payloadLen)

proc decodeAmeFrameHeader*(A: openArray[uint8]): AmeFrameHeader {.
    role: parser.} =
  ## A: at least one AME2 fixed header.
  var i: int = 0
  if A.len < ameFrameHeaderLen:
    raise newException(ValueError, "AME frame is too short")
  while i < ameMagic.len:
    if A[i] != ameMagic[i]:
      raise newException(ValueError, "AME frame magic mismatch")
    i = i + 1
  if readU16(A, 4) != ameFormatVersion:
    raise newException(ValueError, "AME frame version mismatch")
  if not packetKindValid(A[6]) or A[6] == 0'u8:
    raise newException(ValueError, "AME frame packet kind mismatch")
  if not messageClassValid(A[7]):
    raise newException(ValueError, "AME frame message class mismatch")
  result.magic = ameMagic
  result.formatVersion = ameFormatVersion
  result.packetKind = AmePacketKind(A[6])
  result.messageClass = AmeMessageClass(A[7])
  result.sessionId = readU64(A, 8)
  result.rootLaneId = readU32(A, 16)
  result.parentLaneId = readU32(A, 20)
  result.laneId = readU32(A, 24)
  result.sequence = readU32(A, 28)
  result.payloadLen = readU32(A, 32)

proc encodeAmeFrame*(h: AmeFrameHeader,
    payload: openArray[uint8]): ByteSeq {.role: stateController.} =
  ## h/payload: header and exact payload bytes.
  if uint32(payload.len) != h.payloadLen:
    raise newException(ValueError, "AME frame payload length mismatch")
  result = encodeAmeFrameHeader(h)
  appendAmeBytes(result, payload)

proc encodeAmeFrame*(kind: AmePacketKind, messageClass: AmeMessageClass,
    sessionId: uint64, rootLaneId, parentLaneId, laneId, sequence: uint32,
    payload: openArray[uint8]): ByteSeq {.role: stateController.} =
  ## kind/messageClass/session/lane/sequence/payload: complete AME2 frame.
  var h: AmeFrameHeader
  requireAmeU32Len(payload.len, "frame payload")
  h = initAmeFrameHeader(kind, messageClass, sessionId, rootLaneId,
    parentLaneId, laneId, sequence, uint32(payload.len))
  result = encodeAmeFrame(h, payload)

proc decodeAmeFrame*(A: openArray[uint8]): AmeDecodedFrame {.role: parser.} =
  ## A: complete AME2 frame.
  var
    i: int = 0
    n: int = 0
  result.header = decodeAmeFrameHeader(A)
  n = checkedAmeWireLen(result.header.payloadLen,
    uint32(max(0, A.len - ameFrameHeaderLen)), "frame payload")
  if A.len != ameFrameHeaderLen + n:
    raise newException(ValueError, "AME frame payload length mismatch")
  result.payload = newSeq[uint8](n)
  while i < n:
    result.payload[i] = A[ameFrameHeaderLen + i]
    i = i + 1
