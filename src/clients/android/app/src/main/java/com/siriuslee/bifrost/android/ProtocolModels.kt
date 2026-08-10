package com.siriuslee.bifrost.android

import java.util.Locale

enum class ProtocolKind(
  val wireId: Int,
  val label: String,
) {
  SYSTEM(0, "SYS"),
  DISCOVERY(1, "LAN"),
  TCP(2, "TCP"),
  TLS(3, "TLS"),
  UDP(4, "UDP"),
  AME(5, "AME");

  companion object {
    fun fromWireIdOrNull(id: Int): ProtocolKind? =
      entries.firstOrNull { it.wireId == id }

    fun fromWireId(id: Int): ProtocolKind =
      fromWireIdOrNull(id) ?: SYSTEM
  }
}

enum class LogDirection(val label: String) {
  IN("IN"),
  OUT("OUT"),
  INFO("INFO"),
  ERROR("ERR"),
}

object BifrostPorts {
  const val DISCOVERY = 48370
  const val TCP = 48371
  const val TLS = 48372
  const val UDP = 48373
  const val DAC = 48375
}

data class LocalNode(
  val nodeId: String,
  val displayName: String,
)

data class PeerEndpoint(
  val nodeId: String,
  val displayName: String,
  val host: String,
  val tcpPort: Int = BifrostPorts.TCP,
  val tlsPort: Int = BifrostPorts.TLS,
  val udpPort: Int = BifrostPorts.UDP,
  val dacPort: Int = BifrostPorts.DAC,
  val ameTierId: Int = AmeTier.MEDIUM.id,
  val amePublicKey: String = "",
  val lastSeenMillis: Long = System.currentTimeMillis(),
) {
  val shortId: String
    get() = nodeId.take(8).uppercase(Locale.US)

  val ameTier: AmeTier
    get() = AmeTier.fromId(ameTierId)

  val shortAmePublicKey: String
    get() = shortAmePublicDisplay(amePublicKey)
}

data class BifrostMessage(
  val protocol: ProtocolKind,
  val senderId: String,
  val senderName: String,
  val body: String,
  val sequence: Long,
  val timestampMillis: Long,
  val isAck: Boolean = false,
)

data class BifrostLogEntry(
  val timestampMillis: Long,
  val protocol: ProtocolKind,
  val direction: LogDirection,
  val peer: String,
  val message: String,
) {
  fun toLogLine(): String =
    "$timestampMillis ${protocol.label} ${direction.label} $peer $message"
}
