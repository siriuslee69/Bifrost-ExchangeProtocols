## -----------------------------------------------------
## BFX2 Writer <- little-endian writers and value encode
## -----------------------------------------------------

import std/[algorithm, json]

import ../types
import ./types
import ./checksum
import ../../analysis_pragmas

proc strToBytes(s: string): ByteSeq {.gcsafe, role: helper.} =
  ## strToBytes: build str to bytes.
  var
    bs: ByteSeq
    i: int = 0
  bs.setLen(s.len)
  while i < s.len:
    bs[i] = uint8(s[i])
    i.inc
  result = bs

proc writeU16*(bs: var ByteSeq, v: uint16) {.gcsafe, role: stateController.} =
  ## writeU16: write 16.
  bs.add(uint8(v and 0xff))
  bs.add(uint8((v shr 8) and 0xff))

proc writeU32*(bs: var ByteSeq, v: uint32) {.gcsafe, role: stateController.} =
  ## writeU32: write 32.
  bs.add(uint8(v and 0xff))
  bs.add(uint8((v shr 8) and 0xff))
  bs.add(uint8((v shr 16) and 0xff))
  bs.add(uint8((v shr 24) and 0xff))

proc writeU64*(bs: var ByteSeq, v: uint64) {.gcsafe, role: stateController.} =
  ## writeU64: write 64.
  bs.add(uint8(v and 0xff))
  bs.add(uint8((v shr 8) and 0xff))
  bs.add(uint8((v shr 16) and 0xff))
  bs.add(uint8((v shr 24) and 0xff))
  bs.add(uint8((v shr 32) and 0xff))
  bs.add(uint8((v shr 40) and 0xff))
  bs.add(uint8((v shr 48) and 0xff))
  bs.add(uint8((v shr 56) and 0xff))

proc hashFieldId(k: string): uint16 {.gcsafe, role: helper.} =
  ## hashFieldId: build hash field id.
  var
    h: uint32 = 2166136261'u32
    i: int = 0
  i = 0
  while i < k.len:
    h = h xor uint32(uint8(k[i]))
    h = h * 16777619'u32
    i.inc
  result = uint16(h and 0xFFFF'u32)

proc checkedU16Len(n: int; label: string): uint16 {.gcsafe, role: helper.} =
  ## checkedU16Len: reject one length/count that does not fit into u16.
  if n < 0 or n > int(high(uint16)):
    raise newException(ValueError, label & " exceeds u16")
  result = uint16(n)

proc checkedU32Len(n: int; label: string): uint32 {.gcsafe, role: helper.} =
  ## checkedU32Len: reject one length/count that does not fit into u32.
  if n < 0:
    raise newException(ValueError, label & " is negative")
  if uint64(n) > uint64(high(uint32)):
    raise newException(ValueError, label & " exceeds u32")
  result = uint32(n)

proc encodeValuePacket*(wt: BfxWireType, raw: ByteSeq): ByteSeq {.gcsafe, role: wrapper.} =
  ## encodeValuePacket: encode value packet.
  var
    rs: ByteSeq = @[]
  rs.add(uint8(wt))
  writeU32(rs, checkedU32Len(raw.len, "BFX2 packet payload length"))
  rs.add(raw)
  result = rs

proc encodeNodeRaw(n: JsonNode): tuple[wt: BfxWireType, raw: ByteSeq] {.gcsafe, role: helper.}
  ## encodeNodeRaw: encode node raw.

proc compareFields(a, b: BfxField): int {.gcsafe, role: helper.} =
  ## compareFields: build compare fields.
  if a.fieldId < b.fieldId:
    return -1
  if a.fieldId > b.fieldId:
    return 1
  result = cmp(a.fieldName, b.fieldName)

proc encodeObject(n: JsonNode): ByteSeq {.gcsafe, role: helper.} =
  ## encodeObject: encode object.
  var
    fs: seq[BfxField] = @[]
    t: tuple[wt: BfxWireType, raw: ByteSeq]
    keyBytes: ByteSeq
    valueBytes: ByteSeq
    i: int = 0
  for k, v in n:
    t = encodeNodeRaw(v)
    fs.add(BfxField(
      fieldId: hashFieldId(k),
      fieldName: k,
      wireType: t.wt,
      value: t.raw
    ))
  fs.sort(compareFields)
  writeU16(result, checkedU16Len(fs.len, "BFX2 object field count"))
  i = 0
  while i < fs.len:
    writeU16(result, fs[i].fieldId)
    result.add(uint8(fs[i].wireType))
    result.add(0'u8)
    keyBytes = strToBytes(fs[i].fieldName)
    valueBytes = @[]
    writeU16(valueBytes, checkedU16Len(keyBytes.len, "BFX2 object key length"))
    valueBytes.add(keyBytes)
    valueBytes.add(fs[i].value)
    writeU32(result, checkedU32Len(valueBytes.len, "BFX2 object field payload length"))
    result.add(valueBytes)
    i.inc

proc encodeSeq(n: JsonNode): ByteSeq {.gcsafe, role: helper.} =
  ## encodeSeq: encode seq.
  var
    i: int = 0
    t: tuple[wt: BfxWireType, raw: ByteSeq]
    packet: ByteSeq = @[]
  writeU32(result, checkedU32Len(n.len, "BFX2 sequence element count"))
  i = 0
  while i < n.len:
    t = encodeNodeRaw(n[i])
    packet = encodeValuePacket(t.wt, t.raw)
    writeU32(result, checkedU32Len(packet.len, "BFX2 sequence packet length"))
    result.add(packet)
    i.inc

proc encodeNodeRaw(n: JsonNode): tuple[wt: BfxWireType, raw: ByteSeq] {.gcsafe, role: helper.} =
  ## encodeNodeRaw: encode node raw.
  var
    f64u: uint64 = 0'u64
    iv: int64 = 0'i64
  case n.kind
  of JNull:
    result.wt = bfxWtOption
    result.raw = @[0'u8]
  of JBool:
    result.wt = bfxWtBool
    result.raw = @[if n.getBool(): 1'u8 else: 0'u8]
  of JInt:
    result.wt = bfxWtI64
    result.raw = @[]
    iv = int64(n.getInt())
    writeU64(result.raw, cast[uint64](iv))
  of JFloat:
    result.wt = bfxWtF64
    result.raw = @[]
    f64u = cast[uint64](n.getFloat())
    writeU64(result.raw, f64u)
  of JString:
    result.wt = bfxWtString
    result.raw = strToBytes(n.getStr())
  of JObject:
    result.wt = bfxWtObject
    result.raw = encodeObject(n)
  of JArray:
    result.wt = bfxWtSeq
    result.raw = encodeSeq(n)

proc encodeJsonNodePacket*(n: JsonNode): ByteSeq {.gcsafe, role: wrapper.} =
  ## encodeJsonNodePacket: encode JSON node packet.
  var
    t: tuple[wt: BfxWireType, raw: ByteSeq]
  t = encodeNodeRaw(n)
  result = encodeValuePacket(t.wt, t.raw)

proc encodeBfxEnvelope*(schemaId: uint16, schemaVersion: uint16,
    payload: ByteSeq, flags: uint16 = 0'u16): ByteSeq {.gcsafe, role: wrapper.} =
  ## encodeBfxEnvelope: encode a current BFX2 envelope. Checksum bytes are
  ## zero when the checksum flag is absent; v2 checks header prefix + payload.
  var
    hdr: ByteSeq = @[]
    resultBytes: ByteSeq = @[]
    cs: uint32
    i: int = 0
  if payload.len > bfxMaxEnvelopePayloadBytes:
    raise newException(ValueError, "BFX2 envelope payload exceeds its limit")
  i = 0
  while i < bfxMagic.len:
    hdr.add(bfxMagic[i])
    i.inc
  writeU16(hdr, bfxFormatVersion)
  writeU16(hdr, schemaId)
  writeU16(hdr, schemaVersion)
  writeU16(hdr, flags)
  writeU32(hdr, checkedU32Len(payload.len, "BFX2 envelope payload length"))
  resultBytes = hdr
  if (flags and bfxFlagChecksum) != 0'u16:
    resultBytes.add(payload)
    cs = crc32(resultBytes)
    resultBytes.setLen(16)
  writeU32(resultBytes, cs)
  resultBytes.add(payload)
  result = resultBytes
