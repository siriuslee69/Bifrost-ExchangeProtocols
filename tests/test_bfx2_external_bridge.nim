## ---------------------------------------------------------------
## BFX2 External Bridge Tests <- extension contract and id ranges
## ---------------------------------------------------------------

import std/[json, os, strutils, unittest]

import bifrost_exchange_protocols

proc hexNibble(c: char): int =
  ## Parse one hexadecimal nibble.
  if c >= '0' and c <= '9':
    return ord(c) - ord('0')
  if c >= 'a' and c <= 'f':
    return 10 + ord(c) - ord('a')
  if c >= 'A' and c <= 'F':
    return 10 + ord(c) - ord('A')
  result = -1

proc parseHexBytes(s: string): ByteSeq =
  ## Parse hex string into bytes.
  var
    t: string
    i: int
    hi: int
    lo: int
  t = s.strip()
  if (t.len mod 2) != 0:
    return @[]
  i = 0
  while i < t.len:
    hi = hexNibble(t[i])
    lo = hexNibble(t[i + 1])
    if hi < 0 or lo < 0:
      return @[]
    result.add(uint8((hi shl 4) or lo))
    i = i + 2

proc bytesToHex(bs: ByteSeq): string =
  ## Encode bytes as uppercase hex.
  var
    i: int
  i = 0
  while i < bs.len:
    result.add(toHex(int(bs[i]), 2))
    i = i + 1

suite "BFX2 External Bridge":
  test "external schema classification":
    check isExternalSchemaId(schemaErmineReservedStart)
    check isExternalSchemaId(schemaErmineReservedEnd)
    check isErmineSchemaId(schemaErmineReservedStart)
    check not isErmineSchemaId(schemaExternalReservedEnd)
    check not isExternalSchemaId(399'u16)

  test "external envelope roundtrip":
    var
      p0: ByteSeq = @[1'u8, 2'u8, 3'u8, 4'u8]
      enc: tuple[ok: bool, packet: ByteSeq, err: string]
      dec: ExternalDecodeResult
    enc = encodeExternalEnvelope(410'u16, 1'u16, p0, bfxFlagChecksum)
    check enc.ok
    dec = decodeExternalEnvelope(enc.packet)
    check dec.ok
    check dec.envelope.schemaId == 410'u16
    check dec.envelope.schemaVersion == 1'u16
    check dec.envelope.payload == p0

  test "reject non-external schema in bridge encode/decode":
    var
      p0: ByteSeq = @[9'u8, 8'u8]
      enc: tuple[ok: bool, packet: ByteSeq, err: string]
      dec: ExternalDecodeResult
      rawCore: ByteSeq
    enc = encodeExternalEnvelope(399'u16, 1'u16, p0)
    check not enc.ok
    rawCore = encodeBfxEnvelope(399'u16, 1'u16, p0)
    dec = decodeExternalEnvelope(rawCore)
    check not dec.ok

  test "external bridge vector is stable":
    var
      hexPath: string
      jsonPath: string
      packetHex: string
      meta: JsonNode
      payload: ByteSeq
      enc: tuple[ok: bool, packet: ByteSeq, err: string]
      dec: ExternalDecodeResult
    hexPath = joinPath(getCurrentDir(), "tests", "vectors", "bfx2_external", "ermine_schema_410_v2.hex")
    jsonPath = joinPath(getCurrentDir(), "tests", "vectors", "bfx2_external", "ermine_schema_410_v2.json")
    packetHex = readFile(hexPath).strip().toUpperAscii()
    meta = parseJson(readFile(jsonPath))
    payload = parseHexBytes(meta["payloadHex"].getStr())
    enc = encodeExternalEnvelope(
      uint16(meta["schemaId"].getInt()),
      uint16(meta["schemaVersion"].getInt()),
      payload,
      uint16(meta["flags"].getInt())
    )
    check enc.ok
    check bytesToHex(enc.packet) == packetHex
    dec = decodeExternalEnvelope(parseHexBytes(packetHex))
    check dec.ok
    check dec.envelope.schemaId == uint16(meta["schemaId"].getInt())
