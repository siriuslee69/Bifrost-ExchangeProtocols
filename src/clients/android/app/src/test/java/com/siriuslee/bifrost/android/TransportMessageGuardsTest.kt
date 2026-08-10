package com.siriuslee.bifrost.android

import org.junit.Assert.assertTrue
import org.junit.Test

class TransportMessageGuardsTest {
  @Test
  fun transportMessageProtocolMustMatchCarrier() {
    val mismatch = BifrostMessage(
      protocol = ProtocolKind.UDP,
      senderId = "node-a",
      senderName = "peer-a",
      body = "payload",
      sequence = 7,
      timestampMillis = 1234,
      isAck = false,
    )

    val failure = expectIllegalArgument {
      requireTransportMessageProtocol(mismatch, ProtocolKind.TCP, "TCP stream")
    }
    assertTrue(failure.message.orEmpty().contains("TCP stream expected TCP protocol message"))
  }

  @Test
  fun transportAckMustMatchCarrierAndAckShape() {
    val wrongProtocol = BifrostMessage(
      protocol = ProtocolKind.UDP,
      senderId = "node-a",
      senderName = "peer-a",
      body = "ack TCP #7",
      sequence = 8,
      timestampMillis = 1234,
      isAck = true,
    )
    val wrongAckBit = wrongProtocol.copy(protocol = ProtocolKind.TCP, isAck = false)

    val wrongProtocolFailure = expectIllegalArgument {
      requireTransportAckMessage(wrongProtocol, ProtocolKind.TCP, "TCP ack")
    }
    assertTrue(wrongProtocolFailure.message.orEmpty().contains("TCP ack expected TCP protocol message"))

    val wrongAckFailure = expectIllegalArgument {
      requireTransportAckMessage(wrongAckBit, ProtocolKind.TCP, "TCP ack")
    }
    assertTrue(wrongAckFailure.message.orEmpty().contains("TCP ack expected ack message"))
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
