package com.siriuslee.bifrost.android

import java.net.DatagramPacket
import java.net.InetAddress

internal data class AecDacPeer(
  val hostAddress: String,
  val port: Int,
) {
  fun display(): String = "$hostAddress:$port"
}

internal fun aecDacPeerOf(packet: DatagramPacket): AecDacPeer =
  AecDacPeer(
    hostAddress = packet.address?.hostAddress ?: "",
    port = packet.port,
  )

internal fun aecDacPeerOf(address: InetAddress, port: Int): AecDacPeer =
  AecDacPeer(
    hostAddress = address.hostAddress ?: address.hostName,
    port = port,
  )

internal fun requireAecDacPeer(packet: DatagramPacket, expected: AecDacPeer, context: String) {
  val actual = aecDacPeerOf(packet)
  require(actual == expected) {
    "$context from unexpected DAC peer ${actual.display()}"
  }
}

internal fun requireAecDacSessionPeer(
  sessionId: Long,
  actual: AecDacPeer,
  existing: AecDacPeer?,
) {
  require(existing == null || existing == actual) {
    "AEC/DAC session $sessionId already bound to ${existing!!.display()}"
  }
}

internal fun requireAecDacSession(
  runtime: BifrostNodeRuntimeState,
  sessionId: Long,
  context: String,
): AecDacSession =
  runtime.aecDacSessions[sessionId]
    ?: throw IllegalArgumentException(
      if (runtime.isAecDacSessionCompleted(sessionId)) {
        "$context session $sessionId already completed"
      } else {
        "$context session $sessionId not negotiated"
      },
    )

internal fun requireAecDacSessionNotCompleted(
  runtime: BifrostNodeRuntimeState,
  sessionId: Long,
  context: String,
) {
  require(!runtime.isAecDacSessionCompleted(sessionId)) {
    "$context session $sessionId already completed"
  }
}

internal fun requireAecDacRootFrame(
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

internal inline fun <T> consumeAecDacSessionAfter(
  runtime: BifrostNodeRuntimeState,
  sessionId: Long,
  session: AecDacSession,
  block: () -> T,
): T {
  val result = block()
  runtime.consumeAecDacSession(sessionId, session)
  return result
}

internal fun requireAecDacAckMessage(message: BifrostMessage, context: String) {
  require(message.protocol == ProtocolKind.AME) {
    "$context expected AME protocol message"
  }
  require(message.isAck) {
    "$context expected ack message"
  }
}

internal fun requireAecDacDataMessage(message: BifrostMessage, context: String) {
  require(message.protocol == ProtocolKind.AME) {
    "$context expected AME protocol message"
  }
  require(!message.isAck) {
    "$context expected non-ack message"
  }
}
