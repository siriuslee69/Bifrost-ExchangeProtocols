## -----------------------------------------------------
## BFX2 Reader <- little-endian readers and value decode
## -----------------------------------------------------

import std/json

import ../types
import ./types
import ./errors
import ./checksum
import ../../analysis_pragmas

proc hashFieldId(k: string): uint16 {.gcsafe, role: helper.} =
  ## hashFieldId: rebuild one canonical object-field id from its key bytes.
  var
    h: uint32 = 2166136261'u32
    i: int = 0
  while i < k.len:
    h = h xor uint32(uint8(k[i]))
    h = h * 16777619'u32
    i.inc
  result = uint16(h and 0xFFFF'u32)

proc readU16*(bs: ByteSeq, o: int, v: var uint16): bool {.gcsafe, role: stateController.} =
  ## readU16: read 16.
  var
    b0: uint16
    b1: uint16
  if o < 0 or o + 2 > bs.len:
    return false
  b0 = uint16(bs[o])
  b1 = uint16(bs[o + 1])
  v = b0 or (b1 shl 8)
  result = true

proc readU32*(bs: ByteSeq, o: int, v: var uint32): bool {.gcsafe, role: stateController.} =
  ## readU32: read 32.
  var
    b0: uint32
    b1: uint32
    b2: uint32
    b3: uint32
  if o < 0 or o + 4 > bs.len:
    return false
  b0 = uint32(bs[o])
  b1 = uint32(bs[o + 1])
  b2 = uint32(bs[o + 2])
  b3 = uint32(bs[o + 3])
  v = b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)
  result = true

proc readU64*(bs: ByteSeq, o: int, v: var uint64): bool {.gcsafe, role: stateController.} =
  ## readU64: read 64.
  var
    x0: uint64
    x1: uint64
    x2: uint64
    x3: uint64
    x4: uint64
    x5: uint64
    x6: uint64
    x7: uint64
  if o < 0 or o + 8 > bs.len:
    return false
  x0 = uint64(bs[o])
  x1 = uint64(bs[o + 1])
  x2 = uint64(bs[o + 2])
  x3 = uint64(bs[o + 3])
  x4 = uint64(bs[o + 4])
  x5 = uint64(bs[o + 5])
  x6 = uint64(bs[o + 6])
  x7 = uint64(bs[o + 7])
  v = x0 or (x1 shl 8) or (x2 shl 16) or (x3 shl 24) or
    (x4 shl 32) or (x5 shl 40) or (x6 shl 48) or (x7 shl 56)
  result = true

proc bytesToStr(bs: ByteSeq): string {.gcsafe, role: helper.} =
  ## bytesToStr: build bytes to str.
  var
    s: string
    i: int = 0
  s = newString(bs.len)
  while i < bs.len:
    s[i] = char(bs[i])
    i.inc
  result = s

proc jsonIntNodeFromUint64(v: uint64): tuple[ok: bool, node: JsonNode, err: string] {.gcsafe, role: helper.} =
  ## jsonIntNodeFromUint64: reject one unsigned integer that does not fit host JSON ints.
  if v > uint64(high(int)):
    return (false, newJNull(), bfxErrIntegerOutOfRange)
  result = (true, newJInt(int(v)), "")

proc jsonIntNodeFromInt64(v: int64): tuple[ok: bool, node: JsonNode, err: string] {.gcsafe, role: helper.} =
  ## jsonIntNodeFromInt64: reject one signed integer that does not fit host JSON ints.
  when sizeof(int) < sizeof(int64):
    if v < int64(low(int)) or v > int64(high(int)):
      return (false, newJNull(), bfxErrIntegerOutOfRange)
  result = (true, newJInt(int(v)), "")

proc parseJsonNodeFromRaw(wt: BfxWireType, raw: ByteSeq, depth: int = 0): tuple[ok: bool, node: JsonNode, err: string] {.gcsafe, role: parser.}
  ## parseJsonNodeFromRaw: parse JSON node from raw.

proc parsePacket(bs: ByteSeq): tuple[ok: bool, wt: BfxWireType, raw: ByteSeq, err: string] {.gcsafe, role: parser.} =
  ## parsePacket: parse packet.
  var
    l: uint32 = 0'u32
    wtRaw: uint8 = 0'u8
  if bs.len < 5:
    return (false, bfxWtUnknown, @[], bfxErrTruncated)
  wtRaw = bs[0]
  if wtRaw > uint8(ord(high(BfxWireType))):
    return (false, bfxWtUnknown, @[], bfxErrInvalidWireType)
  if not readU32(bs, 1, l):
    return (false, bfxWtUnknown, @[], bfxErrTruncated)
  if l > uint32(bfxMaxValuePacketBytes):
    return (false, bfxWtUnknown, @[], bfxErrResourceLimit)
  if int(l) != bs.len - 5:
    return (false, bfxWtUnknown, @[], bfxErrTruncated)
  result.ok = true
  result.wt = BfxWireType(wtRaw)
  result.raw = bs[5 .. ^1]

proc parseObject(raw: ByteSeq, depth: int): tuple[ok: bool, node: JsonNode, err: string] {.gcsafe, role: parser.} =
  ## parseObject: parse object.
  var
    c: uint16 = 0'u16
    i: int = 0
    o: int = 0
    fieldId: uint16
    wtRaw: uint8
    reserved: uint8
    l: uint32
    keyLen: uint16
    keyBs: ByteSeq = @[]
    keyName: string = ""
    prevKeyName: string = ""
    prevFieldId: uint16 = 0'u16
    hasPrevField: bool = false
    valueRaw: ByteSeq = @[]
    child: tuple[ok: bool, node: JsonNode, err: string]
    childWt: BfxWireType
  result.node = newJObject()
  if raw.len < 2:
    return (false, newJNull(), bfxErrInvalidObjectField)
  if not readU16(raw, 0, c):
    return (false, newJNull(), bfxErrInvalidObjectField)
  if int(c) > bfxMaxCollectionEntries:
    return (false, newJNull(), bfxErrResourceLimit)
  o = 2
  i = 0
  while i < int(c):
    if o + 8 > raw.len:
      return (false, newJNull(), bfxErrInvalidObjectField)
    if not readU16(raw, o, fieldId):
      return (false, newJNull(), bfxErrInvalidObjectField)
    wtRaw = raw[o + 2]
    reserved = raw[o + 3]
    if reserved != 0'u8:
      return (false, newJNull(), bfxErrInvalidObjectField)
    if wtRaw > uint8(ord(high(BfxWireType))):
      return (false, newJNull(), bfxErrInvalidWireType)
    if not readU32(raw, o + 4, l):
      return (false, newJNull(), bfxErrInvalidObjectField)
    o = o + 8
    if o + int(l) > raw.len:
      return (false, newJNull(), bfxErrInvalidObjectField)
    valueRaw = raw[o ..< o + int(l)]
    if valueRaw.len < 2:
      return (false, newJNull(), bfxErrInvalidObjectField)
    if not readU16(valueRaw, 0, keyLen):
      return (false, newJNull(), bfxErrInvalidObjectField)
    if 2 + int(keyLen) > valueRaw.len:
      return (false, newJNull(), bfxErrInvalidObjectField)
    keyBs = valueRaw[2 ..< 2 + int(keyLen)]
    keyName = bytesToStr(keyBs)
    if hashFieldId(keyName) != fieldId:
      return (false, newJNull(), bfxErrInvalidObjectField)
    if hasPrevField:
      if fieldId < prevFieldId:
        return (false, newJNull(), bfxErrInvalidObjectField)
      if fieldId == prevFieldId and cmp(keyName, prevKeyName) <= 0:
        return (false, newJNull(), bfxErrInvalidObjectField)
    prevFieldId = fieldId
    prevKeyName = keyName
    hasPrevField = true
    childWt = BfxWireType(wtRaw)
    child = parseJsonNodeFromRaw(childWt, valueRaw[2 + int(keyLen) .. ^1],
      depth + 1)
    if not child.ok:
      return child
    result.node[keyName] = child.node
    o = o + int(l)
    i.inc
  if o != raw.len:
    return (false, newJNull(), bfxErrInvalidObjectField)
  result.ok = true

proc parseSeq(raw: ByteSeq, depth: int): tuple[ok: bool, node: JsonNode, err: string] {.gcsafe, role: parser.} =
  ## parseSeq: parse seq.
  var
    count: uint32 = 0'u32
    i: int = 0
    o: int = 0
    l: uint32 = 0'u32
    packet: tuple[ok: bool, wt: BfxWireType, raw: ByteSeq, err: string]
    child: tuple[ok: bool, node: JsonNode, err: string]
  if raw.len < 4:
    return (false, newJNull(), bfxErrInvalidSequenceField)
  if not readU32(raw, 0, count):
    return (false, newJNull(), bfxErrInvalidSequenceField)
  if count > uint32(bfxMaxCollectionEntries):
    return (false, newJNull(), bfxErrResourceLimit)
  result.node = newJArray()
  o = 4
  i = 0
  while i < int(count):
    if o + 4 > raw.len:
      return (false, newJNull(), bfxErrInvalidSequenceField)
    if not readU32(raw, o, l):
      return (false, newJNull(), bfxErrInvalidSequenceField)
    o = o + 4
    if o + int(l) > raw.len:
      return (false, newJNull(), bfxErrInvalidSequenceField)
    packet = parsePacket(raw[o ..< o + int(l)])
    if not packet.ok:
      return (false, newJNull(), packet.err)
    child = parseJsonNodeFromRaw(packet.wt, packet.raw, depth + 1)
    if not child.ok:
      return child
    result.node.add(child.node)
    o = o + int(l)
    i.inc
  if o != raw.len:
    return (false, newJNull(), bfxErrInvalidSequenceField)
  result.ok = true

proc parseOption(raw: ByteSeq, depth: int): tuple[ok: bool, node: JsonNode, err: string] {.gcsafe, role: parser.} =
  ## parseOption: parse option.
  var
    hasValue: uint8 = 0'u8
    l: uint32 = 0'u32
    packet: tuple[ok: bool, wt: BfxWireType, raw: ByteSeq, err: string]
    child: tuple[ok: bool, node: JsonNode, err: string]
  if raw.len < 1:
    return (false, newJNull(), bfxErrInvalidOptionField)
  hasValue = raw[0]
  if hasValue > 1'u8:
    return (false, newJNull(), bfxErrInvalidOptionField)
  if hasValue == 0'u8:
    if raw.len != 1:
      return (false, newJNull(), bfxErrInvalidOptionField)
    return (true, newJNull(), "")
  if raw.len < 5:
    return (false, newJNull(), bfxErrInvalidOptionField)
  if not readU32(raw, 1, l):
    return (false, newJNull(), bfxErrInvalidOptionField)
  if int(l) != raw.len - 5:
    return (false, newJNull(), bfxErrInvalidOptionField)
  packet = parsePacket(raw[5 .. ^1])
  if not packet.ok:
    return (false, newJNull(), packet.err)
  child = parseJsonNodeFromRaw(packet.wt, packet.raw, depth + 1)
  if not child.ok:
    return child
  result = child

proc parseJsonNodeFromRaw(wt: BfxWireType, raw: ByteSeq, depth: int = 0): tuple[ok: bool, node: JsonNode, err: string] {.gcsafe, role: parser.} =
  ## parseJsonNodeFromRaw: parse JSON node from raw.
  var
    u64v: uint64 = 0'u64
    i64v: int64 = 0'i64
    f64v: float64 = 0.0
    f32v: float32 = 0.0'f32
    u32v: uint32 = 0'u32
    u16v: uint16 = 0'u16
  if depth > bfxMaxNestingDepth:
    return (false, newJNull(), bfxErrResourceLimit)
  case wt
  of bfxWtBool:
    if raw.len != 1:
      return (false, newJNull(), bfxErrTruncated)
    if raw[0] > 1'u8:
      return (false, newJNull(), bfxErrInvalidBoolField)
    result.ok = true
    result.node = newJBool(raw[0] != 0'u8)
  of bfxWtU8:
    if raw.len != 1:
      return (false, newJNull(), bfxErrTruncated)
    result = jsonIntNodeFromUint64(uint64(raw[0]))
  of bfxWtU16:
    if raw.len != 2:
      return (false, newJNull(), bfxErrTruncated)
    if not readU16(raw, 0, u16v):
      return (false, newJNull(), bfxErrTruncated)
    result = jsonIntNodeFromUint64(uint64(u16v))
  of bfxWtU32:
    if raw.len != 4:
      return (false, newJNull(), bfxErrTruncated)
    if not readU32(raw, 0, u32v):
      return (false, newJNull(), bfxErrTruncated)
    result = jsonIntNodeFromUint64(uint64(u32v))
  of bfxWtU64, bfxWtEnum:
    if raw.len != 8:
      return (false, newJNull(), bfxErrTruncated)
    if not readU64(raw, 0, u64v):
      return (false, newJNull(), bfxErrTruncated)
    result = jsonIntNodeFromUint64(u64v)
  of bfxWtI64:
    if raw.len != 8:
      return (false, newJNull(), bfxErrTruncated)
    if not readU64(raw, 0, u64v):
      return (false, newJNull(), bfxErrTruncated)
    i64v = cast[int64](u64v)
    result = jsonIntNodeFromInt64(i64v)
  of bfxWtI32:
    if raw.len != 4:
      return (false, newJNull(), bfxErrTruncated)
    if not readU32(raw, 0, u32v):
      return (false, newJNull(), bfxErrTruncated)
    result = jsonIntNodeFromInt64(int64(cast[int32](u32v)))
  of bfxWtI16:
    if raw.len != 2:
      return (false, newJNull(), bfxErrTruncated)
    if not readU16(raw, 0, u16v):
      return (false, newJNull(), bfxErrTruncated)
    result = jsonIntNodeFromInt64(int64(cast[int16](u16v)))
  of bfxWtI8:
    if raw.len != 1:
      return (false, newJNull(), bfxErrTruncated)
    result = jsonIntNodeFromInt64(int64(cast[int8](raw[0])))
  of bfxWtF64:
    if raw.len != 8:
      return (false, newJNull(), bfxErrTruncated)
    if not readU64(raw, 0, u64v):
      return (false, newJNull(), bfxErrTruncated)
    f64v = cast[float64](u64v)
    result.ok = true
    result.node = newJFloat(f64v)
  of bfxWtF32:
    if raw.len != 4:
      return (false, newJNull(), bfxErrTruncated)
    if not readU32(raw, 0, u32v):
      return (false, newJNull(), bfxErrTruncated)
    f32v = cast[float32](u32v)
    result.ok = true
    result.node = newJFloat(float64(f32v))
  of bfxWtBytes:
    result.ok = true
    result.node = %bytesToStr(raw)
  of bfxWtString:
    result.ok = true
    result.node = newJString(bytesToStr(raw))
  of bfxWtObject:
    result = parseObject(raw, depth)
  of bfxWtSeq:
    result = parseSeq(raw, depth)
  of bfxWtOption:
    result = parseOption(raw, depth)
  else:
    result = (false, newJNull(), bfxErrInvalidWireType)

proc decodeJsonNodePacket*(bs: ByteSeq): tuple[ok: bool, node: JsonNode, err: string] {.gcsafe, role: parser.} =
  ## decodeJsonNodePacket: decode JSON node packet.
  var
    packet: tuple[ok: bool, wt: BfxWireType, raw: ByteSeq, err: string]
  packet = parsePacket(bs)
  if not packet.ok:
    return (false, newJNull(), packet.err)
  result = parseJsonNodeFromRaw(packet.wt, packet.raw)

proc decodeBfxEnvelope*(bs: ByteSeq): tuple[ok: bool, header: BfxHeader, payload: ByteSeq, err: string] {.gcsafe, role: parser.} =
  ## decodeBfxEnvelope: decode BFX envelope.
  var
    formatVersion: uint16 = 0'u16
    schemaId: uint16 = 0'u16
    schemaVersion: uint16 = 0'u16
    flags: uint16 = 0'u16
    payloadLen: uint32 = 0'u32
    checksumStored: uint32 = 0'u32
    checksumComputed: uint32 = 0'u32
    checksumScope: ByteSeq = @[]
    i: int = 0
  if bs.len == 0:
    return (false, BfxHeader(), @[], bfxErrEmptyInput)
  if bs.len < bfxHeaderLen:
    return (false, BfxHeader(), @[], bfxErrHeaderTooShort)
  i = 0
  while i < bfxMagic.len:
    if bs[i] != bfxMagic[i]:
      return (false, BfxHeader(), @[], bfxErrBadMagic)
    i.inc
  if not readU16(bs, 4, formatVersion):
    return (false, BfxHeader(), @[], bfxErrHeaderTooShort)
  if formatVersion != bfxFormatVersion:
    return (false, BfxHeader(), @[], bfxErrUnsupportedFormatVersion)
  if not readU16(bs, 6, schemaId):
    return (false, BfxHeader(), @[], bfxErrHeaderTooShort)
  if not readU16(bs, 8, schemaVersion):
    return (false, BfxHeader(), @[], bfxErrHeaderTooShort)
  if not readU16(bs, 10, flags):
    return (false, BfxHeader(), @[], bfxErrHeaderTooShort)
  if not readU32(bs, 12, payloadLen):
    return (false, BfxHeader(), @[], bfxErrHeaderTooShort)
  if not readU32(bs, 16, checksumStored):
    return (false, BfxHeader(), @[], bfxErrHeaderTooShort)
  if payloadLen > uint32(bfxMaxEnvelopePayloadBytes):
    return (false, BfxHeader(), @[], bfxErrResourceLimit)
  if int(payloadLen) != bs.len - bfxHeaderLen:
    return (false, BfxHeader(), @[], bfxErrPayloadLengthMismatch)
  if (flags and bfxFlagChecksum) == 0'u16:
    if checksumStored != 0'u32:
      return (false, BfxHeader(), @[], bfxErrChecksumMismatch)
  else:
    checksumScope = bs[0 .. 15]
    if payloadLen > 0'u32:
      checksumScope.add(bs[bfxHeaderLen .. ^1])
    checksumComputed = crc32(checksumScope)
    if checksumStored != checksumComputed:
      return (false, BfxHeader(), @[], bfxErrChecksumMismatch)
  result.ok = true
  result.header.magic = bfxMagic
  result.header.formatVersion = formatVersion
  result.header.schemaId = schemaId
  result.header.schemaVersion = schemaVersion
  result.header.flags = flags
  result.header.payloadLen = payloadLen
  result.header.headerChecksum = checksumStored
  if payloadLen > 0'u32:
    result.payload = bs[bfxHeaderLen .. ^1]
