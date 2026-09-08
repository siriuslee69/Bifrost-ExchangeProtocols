## ---------------------------------------------------------
## DAC Drift Payload Tests <- salvaged realtime pose bodies
## ---------------------------------------------------------

import unittest

import bifrost_exchange_protocols

suite "DAC Drift Payload":
  # {.testKind: tkUnit.}
  test "encode and decode snapshot body":
    var
      pose: DacDriftPose
      p0: DacDriftPacket
      p1: DacDriftPacket
      p2: DacDriftPacket
      bs: ByteSeq = @[]
      frame: ByteSeq = @[]
      flags: DacFrameFlags
      header: DacFrameHeader
      decoded: DacDecodedFrame
      ok: bool = false
    pose.position.x = 1.25'f32
    pose.position.y = -2.5'f32
    pose.position.z = 3.75'f32
    pose.rotation.x = 0.5'f32
    pose.rotation.y = 1.0'f32
    pose.rotation.z = -0.25'f32
    p0 = initDacDriftSnapshot(pose, 99'u32)
    bs = encodeDacDriftPacket(p0)
    flags.needsAck = true
    header = initDacFrameHeader(dmkDriftPayload, 11'u64, 5'u32, 1'u16,
      3'u32, uint32(bs.len), flags)
    frame = encodeDacFrame(header, bs)
    decoded = decodeDacFrame(frame)
    check decoded.header.messageKind == dmkDriftPayload
    check decoded.payload == bs
    ok = decodeDacDriftPacket(decoded.payload, p2)
    check ok
    check p2.tick == 99'u32
    ok = decodeDacDriftPacket(bs, p1)
    check ok
    check bs.len == dacDriftPayloadLen
    check p1.kind == ddpkSnapshot
    check p1.tick == 99'u32
    check p1.pose.position.x == pose.position.x
    check p1.pose.position.y == pose.position.y
    check p1.pose.position.z == pose.position.z
    check p1.pose.rotation.x == pose.rotation.x
    check p1.pose.rotation.y == pose.rotation.y
    check p1.pose.rotation.z == pose.rotation.z

  # {.testKind: tkUnit.}
  test "encode and decode delta body":
    var
      pose: DacDriftPose
      p0: DacDriftPacket
      p1: DacDriftPacket
      bs: ByteSeq = @[]
      ok: bool = false
    pose.position.x = 0.125'f32
    pose.position.y = 0.25'f32
    pose.position.z = -0.5'f32
    pose.rotation.x = 0.01'f32
    pose.rotation.y = 0.02'f32
    pose.rotation.z = 0.03'f32
    p0 = initDacDriftDelta(pose, 7'u32)
    bs = encodeDacDriftPacket(p0)
    ok = decodeDacDriftPacket(bs, p1)
    check ok
    check p1.kind == ddpkDelta
    check p1.tick == 7'u32
    check p1.pose.position.z == pose.position.z
    check p1.pose.rotation.z == pose.rotation.z

  # {.testKind: tkEdgeCase.}
  test "reject wrong length and unknown kind":
    var
      p: DacDriftPacket
      bs: ByteSeq = @[]
      ok: bool = false
    bs = @[uint8(0), uint8(1)]
    ok = decodeDacDriftPacket(bs, p)
    check not ok
    bs = newSeq[uint8](dacDriftPayloadLen)
    bs[0] = 9'u8
    ok = decodeDacDriftPacket(bs, p)
    check not ok
