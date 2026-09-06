package com.siriuslee.bifrost.android

import java.net.DatagramPacket
import java.net.InetAddress

internal data class AmeDacPeer(
  val hostAddress: String,
  val port: Int,
) {
  fun display(): String = "$hostAddress:$port"
}

internal fun ameDacPeerOf(packet: DatagramPacket): AmeDacPeer =
  AmeDacPeer(
    hostAddress = packet.address?.hostAddress ?: "",
    port = packet.port,
  )

internal fun ameDacPeerOf(address: InetAddress, port: Int): AmeDacPeer =
  AmeDacPeer(
    hostAddress = address.hostAddress ?: address.hostName,
    port = port,
  )

internal fun requireAmeDacPeer(packet: DatagramPacket, expected: AmeDacPeer, context: String) {
  val actual = ameDacPeerOf(packet)
  require(actual == expected) {
    "$context from unexpected DAC peer ${actual.display()}"
  }
}

internal fun requireAmeDacSessionPeer(
  sessionId: Long,
  actual: AmeDacPeer,
  existing: AmeDacPeer?,
) {
  require(existing == null || existing == actual) {
    "AME/DAC/DAC session $sessionId already bound to ${existing!!.display()}"
  }
}

internal fun requireAmeDacSession(
  runtime: BifrostNodeRuntimeState,
  sessionId: Long,
  context: String,
): AmeDacSession =
  runtime.ameDacSessions[sessionId]
    ?: throw IllegalArgumentException(
      if (runtime.isAmeDacSessionCompleted(sessionId)) {
        "$context session $sessionId already completed"
      } else {
        "$context session $sessionId not negotiated"
      },
    )

internal fun requireAmeDacSessionNotCompleted(
  runtime: BifrostNodeRuntimeState,
  sessionId: Long,
  context: String,
) {
  require(!runtime.isAmeDacSessionCompleted(sessionId)) {
    "$context session $sessionId already completed"
  }
}

internal fun requireAmeDacRootFrame(
  frame: BifrostWire.AmeFrame,
  expectedSessionId: Long,
  expectedSequence: Long,
  expectedPacketKind: BifrostWire.AmePacketKind,
  context: String,
  expectedRootLaneId: Long? = null,
) {
  require(frame.isRoot) {
    "$context expected root frame"
  }
  require(frame.sessionId == expectedSessionId) {
    "$context session mismatch"
  }
  require(frame.sequence == expectedSequence) {
    "$context AME sequence mismatch"
  }
  require(frame.packetKind == expectedPacketKind) {
    "$context packet kind mismatch"
  }
  require(frame.parentLaneId == 0L) {
    "$context parent lane mismatch"
  }
  if (expectedRootLaneId != null) {
    require(frame.rootLaneId == expectedRootLaneId) {
      "$context root lane mismatch"
    }
  }
}

internal inline fun <T> consumeAmeDacSessionAfter(
  runtime: BifrostNodeRuntimeState,
  sessionId: Long,
  session: AmeDacSession,
  block: () -> T,
): T {
  val result = block()
  runtime.consumeAmeDacSession(sessionId, session)
  return result
}

internal fun requireAmeDacAckMessage(message: BifrostMessage, context: String) {
  require(message.protocol == ProtocolKind.AME) {
    "$context expected AME protocol message"
  }
  require(message.isAck) {
    "$context expected ack message"
  }
}

internal fun requireAmeDacDataMessage(message: BifrostMessage, context: String) {
  require(message.protocol == ProtocolKind.AME) {
    "$context expected AME protocol message"
  }
  require(!message.isAck) {
    "$context expected non-ack message"
  }
}
