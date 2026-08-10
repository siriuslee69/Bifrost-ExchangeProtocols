package com.siriuslee.bifrost.android

import java.io.ByteArrayInputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BifrostWireTest {
  @Test
  fun tcpFrameLengthIsLittleEndianLikeNimTransport() {
    val frame = BifrostWire.frame(byteArrayOf(1, 2, 3, 4, 5))
    assertArrayEquals(byteArrayOf(5, 0, 0, 0), frame.copyOfRange(0, 4))
  }

  @Test
  fun readFrameRejectsUnsignedLengthWithHighBitSet() {
    val failure = expectIllegalArgument {
      BifrostWire.readFrame(ByteArrayInputStream(byteArrayOf(
        0xff.toByte(),
        0xff.toByte(),
        0xff.toByte(),
        0xff.toByte(),
      )))
    }
    assertTrue(failure.message.orEmpty().contains("frame too large: 4294967295"))
  }

  @Test
  fun messageRoundTripKeepsProtocolAndAckFlag() {
    val message = BifrostMessage(
      protocol = ProtocolKind.UDP,
      senderId = "node-a",
      senderName = "phone-a",
      body = "hello",
      sequence = 7,
      timestampMillis = 1234,
      isAck = false,
    )
    val decoded = BifrostWire.decodeMessage(BifrostWire.encodeMessage(message))
    assertEquals(ProtocolKind.UDP, decoded.protocol)
    assertEquals("node-a", decoded.senderId)
    assertEquals("phone-a", decoded.senderName)
    assertEquals("hello", decoded.body)
    assertEquals(7, decoded.sequence)
    assertFalse(decoded.isAck)
  }

  @Test
  fun messageRejectsUnknownProtocolWireId() {
    val encoded = BifrostWire.encodeMessage(
      BifrostMessage(
        protocol = ProtocolKind.UDP,
        senderId = "node-a",
        senderName = "phone-a",
        body = "hello",
        sequence = 7,
        timestampMillis = 1234,
        isAck = false,
      ),
    ).copyOf()
    encoded[6] = 0x7f

    val failure = expectIllegalArgument {
      BifrostWire.decodeMessage(encoded)
    }
    assertTrue(failure.message.orEmpty().contains("message protocol mismatch"))
  }

  @Test
  fun messageRejectsUnknownFlagBits() {
    val encoded = BifrostWire.encodeMessage(
      BifrostMessage(
        protocol = ProtocolKind.UDP,
        senderId = "node-a",
        senderName = "phone-a",
        body = "hello",
        sequence = 7,
        timestampMillis = 1234,
        isAck = false,
      ),
    ).copyOf()
    encoded[7] = 0x04

    val failure = expectIllegalArgument {
      BifrostWire.decodeMessage(encoded)
    }
    assertTrue(failure.message.orEmpty().contains("message flags mismatch"))
  }

  @Test
  fun messageRejectsUnsignedBodyLengthBeyondJvmRange() {
    val encoded = BifrostWire.encodeMessage(
      BifrostMessage(
        protocol = ProtocolKind.UDP,
        senderId = "node-a",
        senderName = "phone-a",
        body = "hello",
        sequence = 7,
        timestampMillis = 1234,
        isAck = false,
      ),
    ).copyOf()
    encoded[28] = 0xff.toByte()
    encoded[29] = 0xff.toByte()
    encoded[30] = 0xff.toByte()
    encoded[31] = 0xff.toByte()

    val failure = expectIllegalArgument {
      BifrostWire.decodeMessage(encoded)
    }
    assertTrue(failure.message.orEmpty().contains("message body length out of range for byte-array length"))
  }

  @Test
  fun ameRootHeaderMatchesDraftOffsets() {
    val payload = byteArrayOf(9, 8, 7)
    val frame = BifrostWire.encodeAmeRootFrame(
      BifrostWire.AmePacketKind.UPGRADE_REQUEST,
      42,
      3,
      payload,
    )
    assertArrayEquals(byteArrayOf('A'.code.toByte(), 'M'.code.toByte(), 'E'.code.toByte(), '1'.code.toByte()), frame.copyOfRange(0, 4))
    assertEquals(2, frame[4].toInt() and 0xff)
    assertEquals(0, frame[5].toInt() and 0xff)
    assertEquals(0x02, frame[6].toInt() and 0xff)
    assertEquals(3, frame[24].toInt() and 0xff)
    val decoded = BifrostWire.decodeAmeFrame(frame)
    assertTrue(decoded.isRoot)
    assertEquals(BifrostWire.AmePacketKind.UPGRADE_REQUEST, decoded.packetKind)
    assertEquals(1, decoded.initMode)
    assertEquals(1L, decoded.rootLaneId)
    assertEquals(0L, decoded.parentLaneId)
    assertEquals(1L, decoded.laneId)
    assertArrayEquals(payload, decoded.payload)
  }

  @Test
  fun ameChildHeaderMatchesDraftOffsets() {
    val frame = BifrostWire.encodeAmeChildFrame(
      BifrostWire.AmePacketKind.LANE_DATA,
      77,
      9,
      5,
      byteArrayOf(1),
    )
    assertEquals(0x08, frame[6].toInt() and 0xff)
    assertEquals(4, frame[7].toInt() and 0xff)
    assertEquals(5, frame[24].toInt() and 0xff)
    assertEquals(1, frame[32].toInt() and 0xff)
    val decoded = BifrostWire.decodeAmeFrame(frame)
    assertFalse(decoded.isRoot)
    assertEquals(5, decoded.laneId)
    assertEquals(1L, decoded.rootLaneId)
    assertEquals(1L, decoded.parentLaneId)
    assertEquals(BifrostWire.AmePacketKind.LANE_DATA, decoded.packetKind)
  }

  @Test
  fun ameRootEncoderSupportsExplicitInitModeAndRootLaneId() {
    val decoded = BifrostWire.decodeAmeFrame(
      BifrostWire.encodeAmeRootFrame(
        packetKind = BifrostWire.AmePacketKind.ROOT_OPEN,
        sessionId = 88,
        sequence = 12,
        payload = byteArrayOf(0x11, 0x12),
        initMode = 2,
        rootLaneId = 9,
      ),
    )

    assertTrue(decoded.isRoot)
    assertEquals(BifrostWire.AmePacketKind.ROOT_OPEN, decoded.packetKind)
    assertEquals(2, decoded.initMode)
    assertEquals(9L, decoded.rootLaneId)
    assertEquals(9L, decoded.laneId)
  }

  @Test
  fun ameChildEncoderSupportsExplicitUnsignedLaneBindings() {
    val rootBits = 0xD0000002L
    val parentBits = 0xC0000003L
    val laneBits = 0xE0000001L
    val decoded = BifrostWire.decodeAmeFrame(
      BifrostWire.encodeAmeChildFrame(
        packetKind = BifrostWire.AmePacketKind.LANE_DATA,
        sessionId = 89,
        sequence = 13,
        laneId = laneBits,
        payload = byteArrayOf(0x13),
        messageClass = 4,
        rootLaneId = rootBits,
        parentLaneId = parentBits,
      ),
    )

    assertFalse(decoded.isRoot)
    assertEquals(rootBits, decoded.rootLaneId)
    assertEquals(parentBits, decoded.parentLaneId)
    assertEquals(laneBits, decoded.laneId)
  }

  private fun expectIllegalArgument(block: () -> Unit): IllegalArgumentException {
    try {
      block()
    } catch (failure: IllegalArgumentException) {
      return failure
    }
    throw AssertionError("expected IllegalArgumentException")
  }
}
