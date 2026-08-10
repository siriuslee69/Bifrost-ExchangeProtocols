## -----------------------------------------------------
## BFX2 Wire Tests <- envelope and dynamic value codecs
## -----------------------------------------------------

import std/[json, os, strutils, unittest]

import bifrost_exchange_protocols

proc hexNibble(c: char): int =
  if c >= '0' and c <= '9':
    return ord(c) - ord('0')
  if c >= 'a' and c <= 'f':
    return 10 + ord(c) - ord('a')
  if c >= 'A' and c <= 'F':
    return 10 + ord(c) - ord('A')
  result = -1

proc parseHexBytes(s: string): ByteSeq =
  let t = s.strip()
  if (t.len mod 2) != 0:
    return @[]
  var i = 0
  while i < t.len:
    let hi = hexNibble(t[i])
    let lo = hexNibble(t[i + 1])
    if hi < 0 or lo < 0:
      return @[]
    result.add(uint8((hi shl 4) or lo))
    i = i + 2

proc bytesToHex(bs: ByteSeq): string =
  var i = 0
  while i < bs.len:
    result.add(toHex(int(bs[i]), 2))
    i.inc

proc rewritePacketPayloadLen(packet: var ByteSeq) =
  var rawLen: uint32 = 0'u32
  if packet.len < 5:
    return
  rawLen = uint32(packet.len - 5)
  packet[1] = uint8(rawLen and 0xff'u32)
  packet[2] = uint8((rawLen shr 8) and 0xff'u32)
  packet[3] = uint8((rawLen shr 16) and 0xff'u32)
  packet[4] = uint8((rawLen shr 24) and 0xff'u32)

proc swapFirstTwoObjectFields(packet: var ByteSeq): bool =
  var
    rawLen: uint32 = 0'u32
    fieldCount: uint16 = 0'u16
    firstLen: uint32 = 0'u32
    secondLen: uint32 = 0'u32
    rawStart: int = 5
    firstStart: int = 0
    firstEnd: int = 0
    secondEnd: int = 0
    firstField: ByteSeq
    secondField: ByteSeq
    prefix: ByteSeq
    suffix: ByteSeq
  if packet.len < 7 or packet[0] != uint8(bfxWtObject):
    return false
  if not readU32(packet, 1, rawLen):
    return false
  if packet.len != rawStart + int(rawLen):
    return false
  if not readU16(packet, rawStart, fieldCount):
    return false
  if fieldCount < 2:
    return false
  firstStart = rawStart + 2
  if firstStart + 8 > packet.len:
    return false
  if not readU32(packet, firstStart + 4, firstLen):
    return false
  firstEnd = firstStart + 8 + int(firstLen)
  if firstEnd + 8 > packet.len:
    return false
  if not readU32(packet, firstEnd + 4, secondLen):
    return false
  secondEnd = firstEnd + 8 + int(secondLen)
  if secondEnd > packet.len:
    return false
  firstField = packet[firstStart ..< firstEnd]
  secondField = packet[firstEnd ..< secondEnd]
  prefix = packet[0 ..< firstStart]
  if secondEnd < packet.len:
    suffix = packet[secondEnd .. ^1]
  packet = prefix
  packet.add(secondField)
  packet.add(firstField)
  packet.add(suffix)
  result = true

suite "BFX2 Wire":
  test "json node packet roundtrip":
    var
      n0: JsonNode
      d: tuple[ok: bool, node: JsonNode, err: string]
    n0 = %*{
      "name": "alpha",
      "enabled": true,
      "count": 42,
      "tags": ["a", "b", "c"],
      "meta": {"version": 1}
    }
    d = decodeJsonNodePacket(encodeJsonNodePacket(n0))
    check d.ok
    check d.node["name"].getStr() == "alpha"
    check d.node["enabled"].getBool()
    check d.node["count"].getInt() == 42
    check d.node["tags"].len == 3
    check d.node["meta"]["version"].getInt() == 1

  test "option null roundtrip":
    var
      d: tuple[ok: bool, node: JsonNode, err: string]
    d = decodeJsonNodePacket(encodeJsonNodePacket(newJNull()))
    check d.ok
    check d.node.kind == JNull

  test "json node packet rejects non-canonical bool payload bytes":
    var
      packet: ByteSeq
      d: tuple[ok: bool, node: JsonNode, err: string]
    packet = encodeValuePacket(bfxWtBool, @[2'u8])
    d = decodeJsonNodePacket(packet)
    check not d.ok
    check d.err == bfxErrInvalidBoolField

  test "json node packet rejects non-canonical option presence bytes":
    var
      child: ByteSeq
      raw: ByteSeq = @[2'u8]
      packet: ByteSeq
      d: tuple[ok: bool, node: JsonNode, err: string]
    child = encodeJsonNodePacket(newJString("value"))
    writeU32(raw, uint32(child.len))
    raw.add(child)
    packet = encodeValuePacket(bfxWtOption, raw)
    d = decodeJsonNodePacket(packet)
    check not d.ok
    check d.err == bfxErrInvalidOptionField

  test "json node packet rejects u64 values that exceed host JSON int range":
    var
      raw: ByteSeq = @[]
      packet: ByteSeq
      d: tuple[ok: bool, node: JsonNode, err: string]
    writeU64(raw, high(uint64))
    packet = encodeValuePacket(bfxWtU64, raw)
    d = decodeJsonNodePacket(packet)
    check not d.ok
    check d.err == bfxErrIntegerOutOfRange

  test "json node packet rejects oversized u16 scalar payloads":
    var
      raw: ByteSeq = @[]
      packet: ByteSeq
      d: tuple[ok: bool, node: JsonNode, err: string]
    writeU16(raw, 7'u16)
    raw.add(0'u8)
    packet = encodeValuePacket(bfxWtU16, raw)
    d = decodeJsonNodePacket(packet)
    check not d.ok
    check d.err == bfxErrTruncated

  test "json node packet rejects oversized f64 scalar payloads":
    var
      raw: ByteSeq = @[]
      packet: ByteSeq
      d: tuple[ok: bool, node: JsonNode, err: string]
    writeU64(raw, 0x3ff0000000000000'u64)
    raw.add(0'u8)
    packet = encodeValuePacket(bfxWtF64, raw)
    d = decodeJsonNodePacket(packet)
    check not d.ok
    check d.err == bfxErrTruncated

  test "json node packet rejects trailing bytes inside object payload":
    var
      n0: JsonNode
      packet: ByteSeq
      d: tuple[ok: bool, node: JsonNode, err: string]
    n0 = %*{"name": "alpha"}
    packet = encodeJsonNodePacket(n0)
    packet.add(0'u8)
    rewritePacketPayloadLen(packet)
    d = decodeJsonNodePacket(packet)
    check not d.ok
    check d.err == bfxErrInvalidObjectField

  test "json node packet rejects trailing bytes inside sequence payload":
    var
      n0: JsonNode
      packet: ByteSeq
      d: tuple[ok: bool, node: JsonNode, err: string]
    n0 = %*["a", "b"]
    packet = encodeJsonNodePacket(n0)
    packet.add(0'u8)
    rewritePacketPayloadLen(packet)
    d = decodeJsonNodePacket(packet)
    check not d.ok
    check d.err == bfxErrInvalidSequenceField

  test "json node packet rejects mismatched object field ids":
    var
      n0: JsonNode
      packet: ByteSeq
      d: tuple[ok: bool, node: JsonNode, err: string]
    n0 = %*{"name": "alpha"}
    packet = encodeJsonNodePacket(n0)
    packet[7] = packet[7] xor 0x01'u8
    d = decodeJsonNodePacket(packet)
    check not d.ok
    check d.err == bfxErrInvalidObjectField

  test "json node packet rejects non-canonical object field order":
    var
      n0: JsonNode
      packet: ByteSeq
      d: tuple[ok: bool, node: JsonNode, err: string]
    n0 = %*{"alpha": 1, "omega": 2}
    packet = encodeJsonNodePacket(n0)
    check swapFirstTwoObjectFields(packet)
    d = decodeJsonNodePacket(packet)
    check not d.ok
    check d.err == bfxErrInvalidObjectField

  test "json node packet rejects trailing bytes after null option payload":
    var
      packet: ByteSeq
      d: tuple[ok: bool, node: JsonNode, err: string]
    packet = encodeJsonNodePacket(newJNull())
    packet.add(0'u8)
    rewritePacketPayloadLen(packet)
    d = decodeJsonNodePacket(packet)
    check not d.ok
    check d.err == bfxErrInvalidOptionField

  test "json node packet rejects object keys that exceed u16 wire length":
    var
      n0: JsonNode
      longKey: string
    longKey = repeat('k', int(high(uint16)) + 1)
    n0 = newJObject()
    n0[longKey] = newJString("x")
    expect ValueError:
      discard encodeJsonNodePacket(n0)

  test "json node packet rejects object field counts that exceed u16 wire length":
    var
      n0: JsonNode
      i: int = 0
    n0 = newJObject()
    while i <= int(high(uint16)):
      n0[$i] = newJInt(i)
      i = i + 1
    expect ValueError:
      discard encodeJsonNodePacket(n0)

  test "envelope roundtrip":
    var
      payload: ByteSeq = @[1'u8, 2'u8, 3'u8, 4'u8]
      d: tuple[ok: bool, header: BfxHeader, payload: ByteSeq, err: string]
      bs: ByteSeq
    bs = encodeBfxEnvelope(410'u16, 1'u16, payload, bfxFlagChecksum)
    d = decodeBfxEnvelope(bs)
    check d.ok
    check d.header.schemaId == 410'u16
    check d.payload == payload

  test "checksum envelope accepts an empty payload":
    var
      d: tuple[ok: bool, header: BfxHeader, payload: ByteSeq, err: string]
    d = decodeBfxEnvelope(encodeBfxEnvelope(414'u16, 1'u16, @[],
      bfxFlagChecksum))
    check d.ok
    check d.payload.len == 0

  test "generic vector is stable":
    let hexPath = joinPath(getCurrentDir(), "tests", "vectors", "bfx2", "hello_payload_v2.hex")
    let jsonPath = joinPath(getCurrentDir(), "tests", "vectors", "bfx2", "hello_payload_v2.json")
    let packetHex = readFile(hexPath).strip().toUpperAscii()
    let meta = parseJson(readFile(jsonPath))
    let payload = encodeJsonNodePacket(meta["payload"])
    let packet = encodeBfxEnvelope(
      uint16(meta["schemaId"].getInt()),
      uint16(meta["schemaVersion"].getInt()),
      payload,
      uint16(meta["flags"].getInt())
    )
    check bytesToHex(packet) == packetHex
    let dec = decodeBfxEnvelope(parseHexBytes(packetHex))
    check dec.ok
    check dec.header.schemaId == uint16(meta["schemaId"].getInt())
    check dec.payload == payload

  test "envelope checksum rejects checksum and payload changes":
    var
      payload: ByteSeq = @[7'u8, 8'u8, 9'u8]
      bs: ByteSeq
      d: tuple[ok: bool, header: BfxHeader, payload: ByteSeq, err: string]
    bs = encodeBfxEnvelope(411'u16, 1'u16, payload, bfxFlagChecksum)
    bs[16] = bs[16] xor 0x01'u8
    d = decodeBfxEnvelope(bs)
    check not d.ok
    check d.err == bfxErrChecksumMismatch
    bs = encodeBfxEnvelope(411'u16, 1'u16, payload, bfxFlagChecksum)
    bs[^1] = bs[^1] xor 0x01'u8
    d = decodeBfxEnvelope(bs)
    check not d.ok
    check d.err == bfxErrChecksumMismatch

  test "checksum mode and old version handling are explicit":
    var
      payload: ByteSeq = @[7'u8, 8'u8, 9'u8]
      bs: ByteSeq
      d: tuple[ok: bool, header: BfxHeader, payload: ByteSeq, err: string]
    bs = encodeBfxEnvelope(412'u16, 1'u16, payload)
    check bs[16] == 0'u8
    check bs[17] == 0'u8
    check bs[18] == 0'u8
    check bs[19] == 0'u8
    d = decodeBfxEnvelope(bs)
    check d.ok
    bs[4] = 1'u8
    bs[5] = 0'u8
    d = decodeBfxEnvelope(bs)
    check not d.ok
    check d.err == bfxErrUnsupportedFormatVersion

  test "decoder rejects hostile dimensions and nesting":
    var
      raw: ByteSeq = @[]
      packet: ByteSeq
      nested: JsonNode = newJNull()
      parent: JsonNode
      d: tuple[ok: bool, node: JsonNode, err: string]
      i: int = 0
    writeU32(raw, uint32(bfxMaxCollectionEntries) + 1'u32)
    packet = encodeValuePacket(bfxWtSeq, raw)
    d = decodeJsonNodePacket(packet)
    check not d.ok
    check d.err == bfxErrResourceLimit
    while i <= bfxMaxNestingDepth:
      parent = newJArray()
      parent.add(nested)
      nested = parent
      i = i + 1
    d = decodeJsonNodePacket(encodeJsonNodePacket(nested))
    check not d.ok
    check d.err == bfxErrResourceLimit

  test "truncated payload fails":
    var
      payload: ByteSeq = @[11'u8, 12'u8, 13'u8]
      bs: ByteSeq
      d: tuple[ok: bool, header: BfxHeader, payload: ByteSeq, err: string]
    bs = encodeBfxEnvelope(412'u16, 1'u16, payload)
    bs.setLen(bs.len - 1)
    d = decodeBfxEnvelope(bs)
    check not d.ok
    check d.err == bfxErrPayloadLengthMismatch
