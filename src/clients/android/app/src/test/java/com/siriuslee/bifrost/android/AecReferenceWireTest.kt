package com.siriuslee.bifrost.android

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AecReferenceWireTest {
  @Test
  fun ameChildCarrierIsAmeChildFrameWithAecEnvelopePayload() {
    val envelope = sampleEnvelope()
    val frame = AecReferenceWire.encodeAmeChildCarrier(
      sessionId = 500,
      ameSequence = 7,
      laneId = 9,
      envelope = envelope,
    )
    val decoded = AecReferenceWire.decodeAmeChildCarrier(frame)
    assertEquals(AecReferenceWire.Carrier.AME_CHILD, decoded.carrier)
    assertFalse(decoded.ameFrame.isRoot)
    assertEquals(BifrostWire.AmePacketKind.LANE_DATA, decoded.ameFrame.packetKind)
    assertEquals(500L, decoded.ameFrame.sessionId)
    assertEquals(7L, decoded.ameFrame.sequence)
    assertEquals(9L, decoded.ameFrame.laneId)
    assertArrayEquals(envelope.nonce, decoded.envelope.nonce)
    assertArrayEquals(envelope.authTag, decoded.envelope.authTag)
    assertArrayEquals(envelope.payload, decoded.envelope.payload)

    val aad = AecReferenceWire.buildAadForAmeChild(frame)
    assertEquals("AEC1-AAD", aad.copyOfRange(0, 8).toString(Charsets.US_ASCII))
    assertEquals(AecReferenceWire.Carrier.AME_CHILD.id, aad[8].toInt() and 0xff)
  }

  @Test
  fun dacCarrierWrapsAmeChildFrameAsPackageChunk() {
    val envelope = sampleEnvelope()
    val frame = AecReferenceWire.encodeDacCarrier(
      sessionId = 700,
      ameSequence = 3,
      dacSequence = 4,
      laneId = 11,
      envelope = envelope,
    )
    val decoded = AecReferenceWire.decodeDacCarrier(frame)
    val dac = decoded.dacFrame ?: error("DAC frame missing")
    assertEquals(AecReferenceWire.Carrier.DAC, decoded.carrier)
    assertEquals(DacReferenceWire.MessageKind.PACKAGE_CHUNK, dac.header.messageKind)
    assertTrue(dac.flags.endOfPackage)
    assertEquals(700L, dac.header.sessionId)
    assertEquals(11L, dac.header.laneId)
    assertEquals(4L, dac.header.sequence)
    assertEquals(dac.payload.size, dac.header.bodyLen)
    assertEquals('A'.code, dac.payload[0].toInt() and 0xff)
    assertEquals('M'.code, dac.payload[1].toInt() and 0xff)
    assertArrayEquals(envelope.payload, decoded.envelope.payload)
  }

  @Test
  fun dacAadChangesWhenDacSequenceChanges() {
    val envelope = sampleEnvelope()
    val first = AecReferenceWire.encodeDacCarrier(700, 3, 4, 11, envelope)
    val second = AecReferenceWire.encodeDacCarrier(700, 3, 5, 11, envelope)
    val firstAad = AecReferenceWire.buildAadForDac(first)
    val secondAad = AecReferenceWire.buildAadForDac(second)
    assertFalse(firstAad.contentEquals(secondAad))
    assertEquals("AEC1-AAD", firstAad.copyOfRange(0, 8).toString(Charsets.US_ASCII))
    assertTrue(firstAad.toString(Charsets.ISO_8859_1).contains("DAC1"))
  }

  @Test
  fun malformedAecAndDacLengthsAreRejected() {
    val envelope = sampleEnvelope()
    val protected = AecReferenceWire.encodeProtectedEnvelope(envelope).copyOf()
    protected[12] = (protected[12].toInt() + 1).toByte()
    assertFails { AecReferenceWire.decodeProtectedEnvelope(protected) }

    val dac = AecReferenceWire.encodeDacCarrier(700, 3, 4, 11, envelope).copyOf()
    dac[25] = (dac[25].toInt() + 1).toByte()
    assertFails { DacReferenceWire.decodeFrame(dac) }
  }

  @Test
  fun highBitUnsignedAecAndDacLengthsAreRejectedBeforeSignedNarrowing() {
    val envelope = sampleEnvelope()

    val protected = AecReferenceWire.encodeProtectedEnvelope(envelope).copyOf()
    protected[12] = 0xff.toByte()
    protected[13] = 0xff.toByte()
    protected[14] = 0xff.toByte()
    protected[15] = 0xff.toByte()
    val protectedFailure = expectIllegalArgument {
      AecReferenceWire.decodeProtectedEnvelope(protected)
    }
    assertTrue(protectedFailure.message.orEmpty().contains("AEC protected envelope payload length out of range for byte-array length"))

    val dac = DacReferenceWire.encodePackageChunk(
      sessionId = 700,
      laneId = 11,
      epochId = 0,
      sequence = 4,
      payload = byteArrayOf(0x01, 0x02, 0x03),
      superClean = true,
    ).copyOf()
    dac[25] = 0xff.toByte()
    dac[26] = 0xff.toByte()
    dac[27] = 0xff.toByte()
    dac[28] = 0xff.toByte()
    val dacFailure = expectIllegalArgument {
      DacReferenceWire.decodeFrame(dac)
    }
    assertTrue(dacFailure.message.orEmpty().contains("DAC frame body length out of range for byte-array length"))
  }

  @Test
  fun nonCanonicalAecAuthTagLengthIsRejected() {
    val envelope = AecReferenceWire.ProtectedEnvelope(
      nonce = ByteArray(24) { i -> (0x20 + i).toByte() },
      authTag = ByteArray(16) { i -> (0x60 + i).toByte() },
      payload = byteArrayOf(0x0a, 0x0b, 0x0c),
    )
    assertFails { AecReferenceWire.decodeProtectedEnvelope(AecReferenceWire.encodeProtectedEnvelope(envelope)) }
  }

  @Test
  fun dacCarrierRejectsAmeSessionOrLaneMismatch() {
    val envelope = sampleEnvelope()
    val ameFrame = AecReferenceWire.encodeAmeChildCarrier(
      sessionId = 700,
      ameSequence = 3,
      laneId = 11,
      envelope = envelope,
    )
    val wrongSession = DacReferenceWire.encodePackageChunk(
      sessionId = 701,
      laneId = 11,
      epochId = 0,
      sequence = 4,
      payload = ameFrame,
    )
    val wrongLane = DacReferenceWire.encodePackageChunk(
      sessionId = 700,
      laneId = 12,
      epochId = 0,
      sequence = 4,
      payload = ameFrame,
    )

    assertFails { AecReferenceWire.decodeDacCarrier(wrongSession) }
    assertFails { AecReferenceWire.decodeDacCarrier(wrongLane) }
  }

  @Test
  fun dacCarrierNormalizesHighBitLaneIdFromSignedIntInput() {
    val envelope = sampleEnvelope()
    val laneBits = 0xE0000001L
    val frame = AecReferenceWire.encodeDacCarrier(
      sessionId = 710,
      ameSequence = 6,
      dacSequence = 7,
      laneId = laneBits.toInt(),
      envelope = envelope,
    )
    val decoded = AecReferenceWire.decodeDacCarrier(frame)
    val dac = decoded.dacFrame ?: error("DAC frame missing")

    assertEquals(laneBits, decoded.ameFrame.laneId)
    assertEquals(laneBits, dac.header.laneId)
  }

  @Test
  fun dacCarrierSupportsExplicitRootLaneBinding() {
    val envelope = sampleEnvelope()
    val frame = AecReferenceWire.encodeDacCarrier(
      sessionId = 711,
      ameSequence = 8,
      dacSequence = 9,
      laneId = 0xE0000001L,
      envelope = envelope,
      rootLaneId = 9,
    )
    val decoded = AecReferenceWire.decodeDacCarrier(frame)

    assertEquals(9L, decoded.ameFrame.rootLaneId)
    assertEquals(9L, decoded.ameFrame.parentLaneId)
    assertEquals(0xE0000001L, decoded.ameFrame.laneId)
  }

  @Test
  fun dacEncoderRejectsOutOfRangeFields() {
    val payload = byteArrayOf(0x44)
    assertFails {
      DacReferenceWire.encodePackageChunk(
        sessionId = 1,
        laneId = 1,
        epochId = 0,
        sequence = 0x1_0000_0000L,
        payload = payload,
      )
    }
    assertFails {
      DacReferenceWire.encodePackageChunk(
        sessionId = 1,
        laneId = 1,
        epochId = -1,
        sequence = 1,
        payload = payload,
      )
    }
  }

  private fun sampleEnvelope(): AecReferenceWire.ProtectedEnvelope =
    AecReferenceWire.ProtectedEnvelope(
      nonce = ByteArray(24) { i -> (0x20 + i).toByte() },
      authTag = ByteArray(32) { i -> (0x60 + i).toByte() },
      payload = byteArrayOf(0x0a, 0x0b, 0x0c),
    )

  private fun expectIllegalArgument(block: () -> Unit): IllegalArgumentException {
    try {
      block()
    } catch (failure: IllegalArgumentException) {
      return failure
    }
    throw AssertionError("expected IllegalArgumentException")
  }

  private fun assertFails(block: () -> Unit) {
    var failed = false
    try {
      block()
    } catch (_: IllegalArgumentException) {
      failed = true
    }
    assertTrue(failed)
  }
}
