## ------------------------------------------------------------------
## LAN Message <- BMSG v1 codec shared by desktop and Android clients
## ------------------------------------------------------------------

import std/[times, unicode]

import bifrostPragmas
import ../../protocols/types

type
  LanProtocol* = enum
    lpSystem = 0
    lpDiscovery = 1
    lpTcp = 2
    lpTls = 3
    lpUdp = 4
    lpAme = 5

  LanMessage* {.role: truthState.} = object
    protocol*: LanProtocol
    senderId*: string
    senderName*: string
    body*: string
    sequence*: uint64
    timestampMillis*: uint64
    isAck*: bool

const
  LanMessageMagic = [byte 'B', byte 'M', byte 'S', byte 'G']
  LanMessageVersion = 1'u16
  LanMessageFixedBytes = 32
  LanMessageMaxBodyBytes* = 1024 * 1024

proc addU16(A: var ByteSeq, v: uint16) {.role: dataWriter, metaTags: {tagInterop}.} =
  ## A: output bytes. v: little-endian unsigned value.
  A.add(byte(v and 0xff'u16))
  A.add(byte(v shr 8))

proc addU32(A: var ByteSeq, v: uint32) {.role: dataWriter, metaTags: {tagInterop}.} =
  ## A: output bytes. v: little-endian unsigned value.
  var
    i: int = 0
  while i < 4:
    A.add(byte((v shr (i * 8)) and 0xff'u32))
    i = i + 1

proc addU64(A: var ByteSeq, v: uint64) {.role: dataWriter, metaTags: {tagInterop}.} =
  ## A: output bytes. v: little-endian unsigned value.
  var
    i: int = 0
  while i < 8:
    A.add(byte((v shr (i * 8)) and 0xff'u64))
    i = i + 1

proc readU16(A: openArray[byte], i: int): uint16 {.role: parser, metaTags: {tagInterop}.} =
  ## A: input bytes. i: first byte offset.
  result = uint16(A[i]) or (uint16(A[i + 1]) shl 8)

proc readU32(A: openArray[byte], i: int): uint32 {.role: parser, metaTags: {tagInterop}.} =
  ## A: input bytes. i: first byte offset.
  var
    j: int = 0
  while j < 4:
    result = result or (uint32(A[i + j]) shl (j * 8))
    j = j + 1

proc readU64(A: openArray[byte], i: int): uint64 {.role: parser, metaTags: {tagInterop}.} =
  ## A: input bytes. i: first byte offset.
  var
    j: int = 0
  while j < 8:
    result = result or (uint64(A[i + j]) shl (j * 8))
    j = j + 1

proc addText(A: var ByteSeq, s: string) {.role: dataWriter, metaTags: {tagInterop}.} =
  ## A: output bytes. s: UTF-8 text to append unchanged.
  for c in s:
    A.add(byte(c))

proc readText(A: openArray[byte], i, n: int): string {.role: parser, metaTags: {tagInterop}.} =
  ## A: input bytes. i/n: first byte and byte count.
  result = newString(n)
  for j in 0 ..< n:
    result[j] = char(A[i + j])
  if validateUtf8(result) >= 0:
    raise newException(ValueError, "BMSG text is not valid UTF-8")

proc requireLanText(s, label: string, maxBytes: int) {.role: sanitizer, metaTags: {tagValidation}.} =
  ## s: UTF-8 text. label/maxBytes: validation context and byte limit.
  if s.len > maxBytes:
    raise newException(ValueError, label & " exceeds byte limit")
  if validateUtf8(s) >= 0:
    raise newException(ValueError, label & " is not valid UTF-8")

proc initLanMessage*(p: LanProtocol, id, name, body: string, sequence: uint64,
    timestampMillis: uint64 = 0'u64): LanMessage {.role: truthBuilder, metaTags: {tagInterop}.} =
  ## p: transport. id/name: sender identity. body: user message.
  ## sequence/timestampMillis: ordering and creation time.
  requireLanText(id, "sender id", int(high(uint16)))
  requireLanText(name, "sender name", int(high(uint16)))
  requireLanText(body, "message body", LanMessageMaxBodyBytes)
  result.protocol = p
  result.senderId = id
  result.senderName = name
  result.body = body
  result.sequence = sequence
  if timestampMillis == 0'u64:
    result.timestampMillis = uint64(getTime().toUnixFloat() * 1000.0)
  else:
    result.timestampMillis = timestampMillis

proc initLanAck*(source: LanMessage, id, name: string,
    sequence: uint64): LanMessage {.role: truthBuilder, metaTags: {tagInterop}.} =
  ## source: received message. id/name/sequence: acknowledging sender facts.
  result = initLanMessage(source.protocol, id, name,
    "ack " & $source.protocol & " #" & $source.sequence, sequence)
  result.isAck = true

proc encodeLanMessage*(m: LanMessage): ByteSeq {.role: dataWriter, metaTags: {tagCodecBoundary, tagInterop}.} =
  ## m: validated BMSG message to serialize.
  requireLanText(m.senderId, "sender id", int(high(uint16)))
  requireLanText(m.senderName, "sender name", int(high(uint16)))
  requireLanText(m.body, "message body", LanMessageMaxBodyBytes)
  result.add(LanMessageMagic)
  addU16(result, LanMessageVersion)
  result.add(byte(ord(m.protocol)))
  result.add(if m.isAck: 1'u8 else: 0'u8)
  addU64(result, m.timestampMillis)
  addU64(result, m.sequence)
  addU16(result, uint16(m.senderId.len))
  addU16(result, uint16(m.senderName.len))
  addU32(result, uint32(m.body.len))
  addText(result, m.senderId)
  addText(result, m.senderName)
  addText(result, m.body)

proc decodeLanMessage*(A: openArray[byte]): LanMessage {.role: parser, metaTags: {tagCodecBoundary, tagInterop}.} =
  ## A: one complete unframed BMSG payload.
  var
    protocolId: int = 0
    flags: byte = 0
    idLen: int = 0
    nameLen: int = 0
    bodyLen: int = 0
    expected: uint64 = 0'u64
    offset: int = LanMessageFixedBytes
  if A.len < LanMessageFixedBytes:
    raise newException(ValueError, "BMSG payload is too short")
  for i in 0 ..< LanMessageMagic.len:
    if A[i] != LanMessageMagic[i]:
      raise newException(ValueError, "BMSG magic mismatch")
  if readU16(A, 4) != LanMessageVersion:
    raise newException(ValueError, "BMSG version mismatch")
  protocolId = int(A[6])
  if protocolId < ord(low(LanProtocol)) or protocolId > ord(high(LanProtocol)):
    raise newException(ValueError, "BMSG protocol mismatch")
  flags = A[7]
  if (flags and 0xfe'u8) != 0'u8:
    raise newException(ValueError, "BMSG flags mismatch")
  idLen = int(readU16(A, 24))
  nameLen = int(readU16(A, 26))
  bodyLen = int(readU32(A, 28))
  if bodyLen > LanMessageMaxBodyBytes:
    raise newException(ValueError, "BMSG body exceeds byte limit")
  expected = uint64(LanMessageFixedBytes) + uint64(idLen) + uint64(nameLen) + uint64(bodyLen)
  if expected != uint64(A.len):
    raise newException(ValueError, "BMSG length mismatch")
  result.protocol = LanProtocol(protocolId)
  result.isAck = (flags and 1'u8) == 1'u8
  result.timestampMillis = readU64(A, 8)
  result.sequence = readU64(A, 16)
  result.senderId = readText(A, offset, idLen)
  offset = offset + idLen
  result.senderName = readText(A, offset, nameLen)
  offset = offset + nameLen
  result.body = readText(A, offset, bodyLen)
