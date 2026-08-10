package com.siriuslee.bifrost.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AecProtocolInstrumentedTest {
  @Test
  fun profilesMatchEveryReferenceTierOnDevice() {
    AmeTier.entries.forEach { tier ->
      assertEquals(AmeProfile.reference(tier), NativeAme.profileForTier(tier))
    }
  }

  @Test
  fun dacCarriesAmeRootUpgradeOnDevice() {
    val rootMessage = BifrostMessage(
      protocol = ProtocolKind.AME,
      senderId = "sender-node",
      senderName = "sender",
      body = "upgrade sender",
      sequence = 1,
      timestampMillis = 100,
    )
    val rootFrame = BifrostWire.encodeAmeRootFrame(
      packetKind = BifrostWire.AmePacketKind.UPGRADE_REQUEST,
      sessionId = 321,
      sequence = 1,
      payload = BifrostWire.encodeMessage(rootMessage),
      profile = AmeProfile.reference(AmeTier.LIGHTWEIGHT),
    )
    val dacFrame = DacReferenceWire.encodePackageChunk(
      sessionId = 321,
      laneId = 0,
      epochId = 0,
      sequence = 0,
      payload = rootFrame,
    )
    val decodedDac = DacReferenceWire.decodeFrame(dacFrame)
    val decodedRoot = BifrostWire.decodeAmeFrame(decodedDac.payload)
    val decodedMessage = BifrostWire.decodeMessage(decodedRoot.payload)

    assertEquals(DacReferenceWire.MessageKind.PACKAGE_CHUNK, decodedDac.header.messageKind)
    assertEquals(321L, decodedDac.header.sessionId)
    assertEquals(0L, decodedDac.header.laneId)
    assertEquals(0L, decodedDac.header.sequence)
    assertTrue(decodedRoot.isRoot)
    assertEquals(BifrostWire.AmePacketKind.UPGRADE_REQUEST, decodedRoot.packetKind)
    assertEquals(321L, decodedRoot.sessionId)
    assertTrue(decodedRoot.profile != null)
    assertEquals("upgrade sender", decodedMessage.body)
  }

  @Test
  fun ameChildCarrierIsAmeChildFrameWithAecEnvelopePayloadOnDevice() {
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
  }

  @Test
  fun dacCarrierWrapsAmeChildFrameAsPackageChunkOnDevice() {
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
    assertArrayEquals(envelope.payload, decoded.envelope.payload)
  }

  @Test
  fun dacAadChangesWhenDacSequenceChangesOnDevice() {
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
  fun malformedAecAndDacLengthsAreRejectedOnDevice() {
    val envelope = sampleEnvelope()
    val protected = AecReferenceWire.encodeProtectedEnvelope(envelope).copyOf()
    protected[12] = (protected[12].toInt() + 1).toByte()
    assertFails { AecReferenceWire.decodeProtectedEnvelope(protected) }

    val dac = AecReferenceWire.encodeDacCarrier(700, 3, 4, 11, envelope).copyOf()
    dac[25] = (dac[25].toInt() + 1).toByte()
    assertFails { DacReferenceWire.decodeFrame(dac) }
  }

  private fun sampleEnvelope(): AecReferenceWire.ProtectedEnvelope =
    AecReferenceWire.ProtectedEnvelope(
      nonce = ByteArray(24) { i -> (0x20 + i).toByte() },
      authTag = ByteArray(32) { i -> (0x60 + i).toByte() },
      payload = byteArrayOf(0x0a, 0x0b, 0x0c),
    )

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
