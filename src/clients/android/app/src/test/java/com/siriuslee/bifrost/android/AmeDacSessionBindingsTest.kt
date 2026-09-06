package com.siriuslee.bifrost.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.DatagramPacket
import java.net.InetAddress

class AmeDacSessionBindingsTest {
  @Test
  fun packetPeerUsesHostAddressAndPort() {
    val packet = DatagramPacket(ByteArray(4), 4, InetAddress.getByName("127.0.0.1"), 48375)
    val peer = ameDacPeerOf(packet)
    assertEquals(AmeDacPeer("127.0.0.1", 48375), peer)
  }

  @Test
  fun unexpectedPacketPeerIsRejected() {
    val packet = DatagramPacket(ByteArray(4), 4, InetAddress.getByName("127.0.0.1"), 48376)
    val failure = expectIllegalArgument {
      requireAmeDacPeer(packet, AmeDacPeer("127.0.0.1", 48375), "AME/DAC lane ack")
    }
    assertTrue(failure.message.orEmpty().contains("unexpected DAC peer 127.0.0.1:48376"))
  }

  @Test
  fun conflictingSessionPeerIsRejected() {
    val failure = expectIllegalArgument {
      requireAmeDacSessionPeer(
        sessionId = 77,
        actual = AmeDacPeer("127.0.0.1", 48375),
        existing = AmeDacPeer("127.0.0.1", 48379),
      )
    }
    assertTrue(failure.message.orEmpty().contains("AME/DAC/DAC session 77 already bound to 127.0.0.1:48379"))
  }

  @Test
  fun laneAckMessageMustUseAmeAckContract() {
    val notAck = BifrostMessage(
      protocol = ProtocolKind.AME,
      senderId = "node-a",
      senderName = "peer-a",
      body = "hello",
      sequence = 7,
      timestampMillis = 1234,
      isAck = false,
    )
    val wrongProtocol = notAck.copy(protocol = ProtocolKind.UDP, isAck = true)

    val notAckFailure = expectIllegalArgument {
      requireAmeDacAckMessage(notAck, "AME/DAC lane ack")
    }
    assertTrue(notAckFailure.message.orEmpty().contains("expected ack message"))

    val wrongProtocolFailure = expectIllegalArgument {
      requireAmeDacAckMessage(wrongProtocol, "AME/DAC lane ack")
    }
    assertTrue(wrongProtocolFailure.message.orEmpty().contains("expected AME protocol message"))
  }

  @Test
  fun inboundAmeDacDataMessageMustUseAmeNonAckContract() {
    val validData = BifrostMessage(
      protocol = ProtocolKind.AME,
      senderId = "node-a",
      senderName = "peer-a",
      body = "payload",
      sequence = 7,
      timestampMillis = 1234,
      isAck = false,
    )
    val wrongProtocol = validData.copy(protocol = ProtocolKind.UDP)
    val wrongAck = validData.copy(isAck = true)

    requireAmeDacDataMessage(validData, "AME/DAC lane frame")

    val wrongProtocolFailure = expectIllegalArgument {
      requireAmeDacDataMessage(wrongProtocol, "AME/DAC lane frame")
    }
    assertTrue(wrongProtocolFailure.message.orEmpty().contains("expected AME protocol message"))

    val wrongAckFailure = expectIllegalArgument {
      requireAmeDacDataMessage(wrongAck, "AME/DAC lane frame")
    }
    assertTrue(wrongAckFailure.message.orEmpty().contains("expected non-ack message"))
  }

  @Test
  fun validAckMessageIsAccepted() {
    requireAmeDacAckMessage(
      BifrostMessage(
        protocol = ProtocolKind.AME,
        senderId = "node-a",
        senderName = "peer-a",
        body = "ack AME #7",
        sequence = 8,
        timestampMillis = 1234,
        isAck = true,
      ),
      "AME/DAC lane ack",
    )
  }

  @Test
  fun missingLaneSessionIsRejectedExplicitly() {
    val runtime = BifrostNodeRuntimeState()
    val failure = expectIllegalArgument {
      requireAmeDacSession(runtime, 77, "AME/DAC/DAC lane frame")
    }
    assertTrue(failure.message.orEmpty().contains("AME/DAC/DAC lane frame session 77 not negotiated"))
    runtime.stop()
  }

  @Test
  fun completedLaneSessionIsRejectedExplicitly() {
    val runtime = BifrostNodeRuntimeState()
    runtime.markAmeDacSessionCompleted(77L, 1000)
    val failure = expectIllegalArgument {
      requireAmeDacSession(runtime, 77, "AME/DAC/DAC lane frame")
    }
    assertTrue(failure.message.orEmpty().contains("AME/DAC/DAC lane frame session 77 already completed"))
    runtime.stop()
  }

  @Test
  fun completedRootSessionIsRejectedExplicitly() {
    val runtime = BifrostNodeRuntimeState()
    runtime.markAmeDacSessionCompleted(77L, 1000)
    val failure = expectIllegalArgument {
      requireAmeDacSessionNotCompleted(runtime, 77, "AME/DAC root request")
    }
    assertTrue(failure.message.orEmpty().contains("AME/DAC root request session 77 already completed"))
    runtime.stop()
  }

  @Test
  fun rootFrameValidationSupportsCustomRootLaneAndRejectsBindingMismatch() {
    val rootFrame = BifrostWire.decodeAmeFrame(
      BifrostWire.encodeAmeRootFrame(
        packetKind = BifrostWire.AmePacketKind.UPGRADE_REQUEST,
        sessionId = 77,
        sequence = 1,
        payload = BifrostWire.encodeMessage(
          BifrostMessage(
            protocol = ProtocolKind.AME,
            senderId = "node-a",
            senderName = "peer-a",
            body = "upgrade peer-a",
            sequence = 7,
            timestampMillis = 1234,
            isAck = false,
          ),
        ),
        rootLaneId = 9,
      ),
    )

    requireAmeDacRootFrame(
      frame = rootFrame,
      expectedSessionId = 77,
      expectedSequence = 1,
      expectedPacketKind = BifrostWire.AmePacketKind.UPGRADE_REQUEST,
      context = "AME/DAC root request",
      expectedRootLaneId = 9,
    )

    val wrongSession = expectIllegalArgument {
      requireAmeDacRootFrame(
        frame = rootFrame,
        expectedSessionId = 78,
        expectedSequence = 1,
        expectedPacketKind = BifrostWire.AmePacketKind.UPGRADE_REQUEST,
        context = "AME/DAC root request",
      )
    }
    assertTrue(wrongSession.message.orEmpty().contains("session mismatch"))

    val wrongRootLane = expectIllegalArgument {
      requireAmeDacRootFrame(
        frame = rootFrame,
        expectedSessionId = 77,
        expectedSequence = 1,
        expectedPacketKind = BifrostWire.AmePacketKind.UPGRADE_REQUEST,
        context = "AME/DAC root request",
        expectedRootLaneId = 1,
      )
    }
    assertTrue(wrongRootLane.message.orEmpty().contains("root lane mismatch"))
  }

  @Test
  fun laneSessionConsumptionHappensOnlyAfterSuccessfulValidation() {
    val runtime = BifrostNodeRuntimeState()
    val session = AmeDacSession(
      peerName = "peer-a",
      tier = AmeTier.MEDIUM,
      seed = byteArrayOf(1, 2, 3, 4),
      rootLaneId = 1L,
      remote = AmeDacPeer("127.0.0.1", 48375),
      createdAtMillis = 1000,
    )
    runtime.ameDacSessions[77L] = session

    val failure = expectIllegalArgument {
      consumeAmeDacSessionAfter(runtime, 77L, session) {
        throw IllegalArgumentException("bad lane frame")
      }
    }
    assertTrue(failure.message.orEmpty().contains("bad lane frame"))
    assertTrue(runtime.ameDacSessions.containsKey(77L))

    consumeAmeDacSessionAfter(runtime, 77L, session) { "ok" }
    assertTrue(!runtime.ameDacSessions.containsKey(77L))
    runtime.stop()
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
