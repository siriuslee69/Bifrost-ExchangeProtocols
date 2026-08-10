package com.siriuslee.bifrost.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AmeReferenceWireTest {
  @Test
  fun rootOpenAndDowngradeRequestStayRootShapedInReferenceDecoder() {
    val profile = AmeProfile.reference(AmeTier.HIGH)
    val rootOpen = AmeReferenceWire.decodeFrame(
      AmeReferenceWire.encodeRootFrame(
        BifrostWire.AmePacketKind.ROOT_OPEN,
        sessionId = 41,
        sequence = 7,
        payload = byteArrayOf(0x01, 0x02),
        profile = profile,
      ),
    )
    val downgrade = AmeReferenceWire.decodeFrame(
      AmeReferenceWire.encodeRootFrame(
        BifrostWire.AmePacketKind.DOWNGRADE_REQUEST,
        sessionId = 42,
        sequence = 8,
        payload = byteArrayOf(0x03, 0x04),
        profile = profile,
      ),
    )

    assertTrue(rootOpen.isRoot)
    assertEquals(BifrostWire.AmePacketKind.ROOT_OPEN.id, rootOpen.packetKindId)
    assertEquals(profile.keyBits, rootOpen.keyBits)
    assertEquals(1, rootOpen.initMode)
    assertEquals(1L, rootOpen.rootLaneId)
    assertEquals(0L, rootOpen.parentLaneId)
    assertTrue(downgrade.isRoot)
    assertEquals(BifrostWire.AmePacketKind.DOWNGRADE_REQUEST.id, downgrade.packetKindId)
    assertEquals(profile.authBits, downgrade.authBits)
  }

  @Test
  fun pingStaysChildShapedInReferenceDecoder() {
    val decoded = AmeReferenceWire.decodeFrame(
      AmeReferenceWire.encodeChildFrame(
        BifrostWire.AmePacketKind.PING,
        sessionId = 55,
        sequence = 9,
        laneId = 6,
        payload = byteArrayOf(0x0a),
        messageClass = 2,
      ),
    )

    assertFalse(decoded.isRoot)
    assertEquals(BifrostWire.AmePacketKind.PING.id, decoded.packetKindId)
    assertEquals(2, decoded.messageClass)
    assertEquals(1L, decoded.rootLaneId)
    assertEquals(1L, decoded.parentLaneId)
    assertEquals(6L, decoded.laneId)
  }

  @Test
  fun explicitRootInitModeAndLaneBindingRoundTripInReferenceEncoder() {
    val decoded = AmeReferenceWire.decodeFrame(
      AmeReferenceWire.encodeRootFrame(
        BifrostWire.AmePacketKind.ROOT_OPEN,
        sessionId = 56,
        sequence = 10,
        payload = byteArrayOf(0x0b, 0x0c),
        profile = AmeProfile.reference(AmeTier.MEDIUM_PLUS),
        initMode = 2,
        rootLaneId = 9,
      ),
    )

    assertTrue(decoded.isRoot)
    assertEquals(2, decoded.initMode)
    assertEquals(9L, decoded.rootLaneId)
    assertEquals(9L, decoded.laneId)
  }

  @Test
  fun highBitChildLaneAndSequenceStayUnsignedInReferenceDecoder() {
    val laneBits = 0xE0000001L
    val sequenceBits = 0xF0000002L
    val decoded = AmeReferenceWire.decodeFrame(
      AmeReferenceWire.encodeChildFrame(
        BifrostWire.AmePacketKind.LANE_DATA,
        sessionId = 73,
        sequence = sequenceBits,
        laneId = laneBits.toInt(),
        payload = byteArrayOf(0x55),
        messageClass = 4,
      ),
    )

    assertFalse(decoded.isRoot)
    assertEquals(sequenceBits, decoded.sequence)
    assertEquals(laneBits, decoded.laneId)
  }

  @Test
  fun explicitChildRootAndParentLaneBindingsRoundTripInReferenceEncoder() {
    val rootBits = 0xD0000002L
    val parentBits = 0xC0000003L
    val laneBits = 0xE0000001L
    val decoded = AmeReferenceWire.decodeFrame(
      AmeReferenceWire.encodeChildFrame(
        BifrostWire.AmePacketKind.LANE_DATA,
        sessionId = 74,
        sequence = 18,
        laneId = laneBits,
        payload = byteArrayOf(0x56),
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

  @Test
  fun rootMasterKeyTierRoundTripsInReferenceDecoder() {
    val profile = AmeProfile.reference(AmeTier.HIGH).copy(masterKeyTierId = 5)
    val raw = AmeReferenceWire.encodeRootFrame(
      BifrostWire.AmePacketKind.UPGRADE_REQUEST,
      sessionId = 81,
      sequence = 14,
      payload = byteArrayOf(0x21),
      profile = profile,
    )
    val decoded = AmeReferenceWire.decodeFrame(raw)
    val publicDecoded = BifrostWire.decodeAmeFrame(raw)

    assertTrue(decoded.isRoot)
    assertEquals(5, decoded.masterKeyTierId)
    assertEquals(1, decoded.initMode)
    assertEquals(5, publicDecoded.profile!!.masterKeyTierId)
  }

  @Test
  fun childRootAndParentLaneMetadataRoundTripInReferenceDecoder() {
    val decoded = AmeReferenceWire.decodeFrame(
      AmeReferenceWire.encodeChildFrame(
        BifrostWire.AmePacketKind.LANE_DATA,
        sessionId = 84,
        sequence = 17,
        laneId = 6,
        payload = byteArrayOf(0x24),
        messageClass = 4,
        rootLaneId = 9,
        parentLaneId = 4,
      ),
    )

    assertFalse(decoded.isRoot)
    assertEquals(9L, decoded.rootLaneId)
    assertEquals(4L, decoded.parentLaneId)
    assertEquals(6L, decoded.laneId)
  }

  @Test(expected = IllegalArgumentException::class)
  fun invalidRootMasterKeyTierIsRejectedInReferenceDecoder() {
    val raw = AmeReferenceWire.encodeRootFrame(
      BifrostWire.AmePacketKind.UPGRADE_REQUEST,
      sessionId = 82,
      sequence = 15,
      payload = byteArrayOf(0x22),
      profile = AmeProfile.reference(AmeTier.MEDIUM),
    )
    raw[34] = 0
    AmeReferenceWire.decodeFrame(raw)
  }

  @Test
  fun nonPresetCanonicalRootProfileDerivesMediumTierInsteadOfHeuristicHighTier() {
    val profile = AmeProfile.fromRootBits(
      keyBits = 0b101000000000000,
      symmetricBits = 0b110,
      macBits = 0b1100,
      otpBits = 0b111,
      authBits = 0b011000,
      masterKeyTierId = 2,
    )

    assertEquals(AmeTier.MEDIUM, profile.tier)
    assertEquals(1, profile.asymmetricBand)
    assertEquals(4, profile.asymmetricTier)
    assertEquals(2, profile.symmetricTier)
    assertEquals(2, profile.verificationTier)
  }

  @Test(expected = IllegalArgumentException::class)
  fun nonCanonicalMixedBandRootProfileIsRejectedInReferenceDecoder() {
    val raw = AmeReferenceWire.encodeRootFrame(
      BifrostWire.AmePacketKind.UPGRADE_REQUEST,
      sessionId = 83,
      sequence = 16,
      payload = byteArrayOf(0x23),
      profile = AmeProfile.reference(AmeTier.MEDIUM),
    )
    raw[28] = 0x10
    raw[29] = 0x40
    AmeReferenceWire.decodeFrame(raw)
  }

  @Test
  fun oversizedAmeSequenceIsRejectedBeforeEncoding() {
    assertFails {
      NativeAme.encodeChildFrame(
        BifrostWire.AmePacketKind.LANE_DATA,
        sessionId = 91,
        sequence = 0x1_0000_0000L,
        laneId = 4,
        payload = byteArrayOf(0x33),
        messageClass = 4,
      )
    }
  }

  @Test
  fun invalidChildMessageClassIsRejectedBeforeEncoding() {
    assertFails {
      NativeAme.encodeChildFrame(
        BifrostWire.AmePacketKind.LANE_DATA,
        sessionId = 92,
        sequence = 18,
        laneId = 7L,
        payload = byteArrayOf(0x34),
        messageClass = 8,
      )
    }
  }

  @Test
  fun referenceDecoderRejectsUnsignedPayloadLengthsBeyondJvmRange() {
    val root = AmeReferenceWire.encodeRootFrame(
      BifrostWire.AmePacketKind.UPGRADE_REQUEST,
      sessionId = 94,
      sequence = 20,
      payload = byteArrayOf(0x36),
      profile = AmeProfile.reference(AmeTier.MEDIUM),
    ).copyOf()
    root[24] = 0xff.toByte()
    root[25] = 0xff.toByte()
    root[26] = 0xff.toByte()
    root[27] = 0xff.toByte()
    val rootFailure = expectIllegalArgument {
      AmeReferenceWire.decodeFrame(root)
    }
    assertTrue(rootFailure.message.orEmpty().contains("AME root payload length out of range for byte-array length"))

    val child = AmeReferenceWire.encodeChildFrame(
      BifrostWire.AmePacketKind.LANE_DATA,
      sessionId = 95,
      sequence = 21,
      laneId = 6,
      payload = byteArrayOf(0x37),
      messageClass = 4,
    ).copyOf()
    child[32] = 0xff.toByte()
    child[33] = 0xff.toByte()
    child[34] = 0xff.toByte()
    child[35] = 0xff.toByte()
    val childFailure = expectIllegalArgument {
      AmeReferenceWire.decodeFrame(child)
    }
    assertTrue(childFailure.message.orEmpty().contains("AME child payload length out of range for byte-array length"))
  }

  @Test
  fun nonCanonicalRootProfileIsRejectedBeforeEncoding() {
    val invalidProfile = AmeProfile.reference(AmeTier.MEDIUM).copy(keyBits = 0b100001000000000)
    assertFails {
      NativeAme.encodeRootFrame(
        BifrostWire.AmePacketKind.UPGRADE_REQUEST,
        sessionId = 93,
        sequence = 19,
        payload = byteArrayOf(0x35),
        profile = invalidProfile,
      )
    }
  }

  @Test
  fun fallbackAutoUpgradeAcceptsAllNegotiationRequestKinds() {
    val stronger = BifrostWire.decodeAmeFrame(
      AmeReferenceWire.encodeRootFrame(
        BifrostWire.AmePacketKind.ROOT_OPEN,
        sessionId = 61,
        sequence = 11,
        payload = byteArrayOf(0x11),
        profile = AmeProfile.reference(AmeTier.HIGH),
      ),
    )
    val weaker = BifrostWire.decodeAmeFrame(
      AmeReferenceWire.encodeRootFrame(
        BifrostWire.AmePacketKind.DOWNGRADE_REQUEST,
        sessionId = 62,
        sequence = 12,
        payload = byteArrayOf(0x12),
        profile = AmeProfile.reference(AmeTier.LIGHTWEIGHT),
      ),
    )
    val ack = BifrostWire.decodeAmeFrame(
      AmeReferenceWire.encodeRootFrame(
        BifrostWire.AmePacketKind.UPGRADE_ACK,
        sessionId = 63,
        sequence = 13,
        payload = byteArrayOf(0x13),
        profile = AmeProfile.reference(AmeTier.HIGH),
      ),
    )

    assertEquals(AmeTier.HIGH.id, AmeReferenceWire.autoUpgradeTierId(AmeTier.MEDIUM, true, stronger))
    assertEquals(AmeTier.LIGHTWEIGHT.id, AmeReferenceWire.autoUpgradeTierId(AmeTier.MEDIUM, true, weaker))
    assertEquals(-1, AmeReferenceWire.autoUpgradeTierId(AmeTier.MEDIUM, true, ack))
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

  private fun expectIllegalArgument(block: () -> Unit): IllegalArgumentException {
    try {
      block()
    } catch (failure: IllegalArgumentException) {
      return failure
    }
    throw AssertionError("expected IllegalArgumentException")
  }
}
