package com.siriuslee.bifrost.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AmeDacProtocolInstrumentedTest {
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
}
