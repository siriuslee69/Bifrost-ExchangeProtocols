## ---------------------------------------------------------------------
## DAC Drift Payload <- compact realtime pose body carried by DAC/AME
## ---------------------------------------------------------------------

import ../../types
import ../types
import ../../../analysis_pragmas

const
  dacDriftPayloadLen* = 29
  dacDriftPayloadAscii* = """
+--------------- Common DAC1 Envelope ----------------+
| Kind = DriftPayload | Flags = NeedsAck optional      |
+------+-------+------+------+------+------+------+------+
| Kind | Tick  | PosX | PosY | PosZ | RotX | RotY | RotZ |
| u8   | u32   | f32  | f32  | f32  | f32  | f32  | f32  |
+------+-------+------+------+------+------+------+------+
| Body length = 29 bytes. AME can protect this body before DAC carries it. |
+--------------------------------------------------------------------------+
"""

proc initDacDriftSnapshot*(p: DacDriftPose, t: uint32): DacDriftPacket {.role: wrapper.} =
  ## p: full pose snapshot.
  ## t: simulation or stream tick.
  result.kind = ddpkSnapshot
  result.tick = t
  result.pose = p

proc initDacDriftDelta*(p: DacDriftPose, t: uint32): DacDriftPacket {.role: wrapper.} =
  ## p: pose delta.
  ## t: simulation or stream tick.
  result.kind = ddpkDelta
  result.tick = t
  result.pose = p

proc writeU32(bs: var ByteSeq, v: uint32) {.role: stateController.} =
  ## bs: byte sequence to update.
  ## v: little-endian value to append.
  bs.add(uint8(v and 0xff))
  bs.add(uint8((v shr 8) and 0xff))
  bs.add(uint8((v shr 16) and 0xff))
  bs.add(uint8((v shr 24) and 0xff))

proc writeF32(bs: var ByteSeq, v: float32) {.role: stateController.} =
  ## bs: byte sequence to update.
  ## v: float value to append.
  var
    raw: uint32 = 0
  raw = cast[uint32](v)
  writeU32(bs, raw)

proc readU32(bs: ByteSeq, o: int, v: var uint32): bool {.role: stateController.} =
  ## bs: byte sequence to read.
  ## o: byte offset.
  ## v: output value.
  var
    b0: uint32 = 0
    b1: uint32 = 0
    b2: uint32 = 0
    b3: uint32 = 0
  if o < 0 or o + 4 > bs.len:
    return false
  b0 = uint32(bs[o])
  b1 = uint32(bs[o + 1])
  b2 = uint32(bs[o + 2])
  b3 = uint32(bs[o + 3])
  v = b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)
  result = true

proc readF32(bs: ByteSeq, o: int, v: var float32): bool {.role: stateController.} =
  ## bs: byte sequence to read.
  ## o: byte offset.
  ## v: output value.
  var
    raw: uint32 = 0
  if not readU32(bs, o, raw):
    return false
  v = cast[float32](raw)
  result = true

proc encodeDacDriftPacket*(p: DacDriftPacket): ByteSeq {.role: wrapper.} =
  ## p: DAC drift packet to encode as a DAC body.
  result.add(uint8(ord(p.kind)))
  writeU32(result, p.tick)
  writeF32(result, p.pose.position.x)
  writeF32(result, p.pose.position.y)
  writeF32(result, p.pose.position.z)
  writeF32(result, p.pose.rotation.x)
  writeF32(result, p.pose.rotation.y)
  writeF32(result, p.pose.rotation.z)

proc decodeDacDriftPacket*(bs: ByteSeq, p: var DacDriftPacket): bool {.role: stateController.} =
  ## bs: DAC drift body bytes.
  ## p: output packet.
  var
    kindRaw: uint8 = 0
    tick: uint32 = 0
    posX: float32 = 0
    posY: float32 = 0
    posZ: float32 = 0
    rotX: float32 = 0
    rotY: float32 = 0
    rotZ: float32 = 0
  if bs.len != dacDriftPayloadLen:
    return false
  kindRaw = bs[0]
  if kindRaw > uint8(ord(high(DacDriftPayloadKind))):
    return false
  if not readU32(bs, 1, tick):
    return false
  if not readF32(bs, 5, posX):
    return false
  if not readF32(bs, 9, posY):
    return false
  if not readF32(bs, 13, posZ):
    return false
  if not readF32(bs, 17, rotX):
    return false
  if not readF32(bs, 21, rotY):
    return false
  if not readF32(bs, 25, rotZ):
    return false
  p.kind = DacDriftPayloadKind(kindRaw)
  p.tick = tick
  p.pose.position.x = posX
  p.pose.position.y = posY
  p.pose.position.z = posZ
  p.pose.rotation.x = rotX
  p.pose.rotation.y = rotY
  p.pose.rotation.z = rotZ
  result = true
