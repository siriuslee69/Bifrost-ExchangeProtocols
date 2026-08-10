package com.siriuslee.bifrost.android

import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets

object BifrostWire {
  private val messageMagic = byteArrayOf('B'.code.toByte(), 'M'.code.toByte(), 'S'.code.toByte(), 'G'.code.toByte())
  private const val messageVersion = 1
  private const val maxFrameLen = 1024 * 1024
  private const val ackFlag = 0x01
  private const val knownMessageFlagMask = ackFlag

  enum class AmePacketKind(val id: Int, val label: String) {
    UNKNOWN(0x00, "unknown"),
    UPGRADE_ADVERT(0x01, "upgrade-advert"),
    UPGRADE_REQUEST(0x02, "upgrade-request"),
    UPGRADE_ACK(0x03, "upgrade-ack"),
    ROOT_OPEN(0x04, "root-open"),
    ROOT_OPEN_ACK(0x05, "root-open-ack"),
    FORK_REQUEST(0x06, "fork-request"),
    FORK_ACK(0x07, "fork-ack"),
    LANE_DATA(0x08, "lane-data"),
    LANE_ACK(0x09, "lane-ack"),
    ESCALATION_REQUEST(0x0a, "escalation-request"),
    ESCALATION_ACK(0x0b, "escalation-ack"),
    DOWNGRADE_REQUEST(0x0c, "downgrade-request"),
    DOWNGRADE_ACK(0x0d, "downgrade-ack"),
    LANE_CLOSE(0x0e, "lane-close"),
    PROBLEM(0x0f, "problem"),
    PING(0x10, "ping"),
    PONG(0x11, "pong");

    fun isRootKind(): Boolean =
      when (this) {
        UPGRADE_ADVERT,
        UPGRADE_REQUEST,
        UPGRADE_ACK,
        ROOT_OPEN,
        ROOT_OPEN_ACK,
        ESCALATION_REQUEST,
        ESCALATION_ACK,
        DOWNGRADE_REQUEST,
        DOWNGRADE_ACK,
        -> true
        else -> false
      }

    fun isNegotiationRequestKind(): Boolean =
      when (this) {
        UPGRADE_REQUEST,
        ROOT_OPEN,
        ESCALATION_REQUEST,
        DOWNGRADE_REQUEST,
        -> true
        else -> false
      }

    companion object {
      fun fromId(id: Int): AmePacketKind =
        entries.firstOrNull { it.id == id } ?: UNKNOWN
    }
  }

  data class AmeFrame(
    val isRoot: Boolean,
    val packetKind: AmePacketKind,
    val sessionId: Long,
    val sequence: Long,
    val laneId: Long,
    val payload: ByteArray,
    val messageClass: Int = 0,
    val profile: AmeProfile? = null,
    val initMode: Int = 0,
    val rootLaneId: Long = 0,
    val parentLaneId: Long = 0,
  )

  fun encodeMessage(message: BifrostMessage): ByteArray {
    val senderId = message.senderId.toByteArray(StandardCharsets.UTF_8)
    val senderName = message.senderName.toByteArray(StandardCharsets.UTF_8)
    val body = message.body.toByteArray(StandardCharsets.UTF_8)
    val out = ByteArrayOutputStream()
    out.write(messageMagic)
    writeU16(out, messageVersion)
    out.write(message.protocol.wireId)
    out.write(if (message.isAck) 0x01 else 0x00)
    writeU64(out, message.timestampMillis)
    writeU64(out, message.sequence)
    writeU16(out, senderId.size)
    writeU16(out, senderName.size)
    writeU32(out, body.size)
    out.write(senderId)
    out.write(senderName)
    out.write(body)
    return out.toByteArray()
  }

  fun decodeMessage(payload: ByteArray): BifrostMessage {
    require(payload.size >= 32) { "message payload too short" }
    require(payload.sliceArray(0 until 4).contentEquals(messageMagic)) { "message magic mismatch" }
    val fixed = ByteBuffer.wrap(payload, 4, 28).order(ByteOrder.LITTLE_ENDIAN)
    val version = fixed.short.toInt() and 0xffff
    require(version == messageVersion) { "unsupported message version $version" }
    val protocolId = fixed.get().toInt() and 0xff
    val protocol = ProtocolKind.fromWireIdOrNull(protocolId)
    require(protocol != null) { "message protocol mismatch" }
    val flags = fixed.get().toInt() and 0xff
    require((flags and knownMessageFlagMask.inv()) == 0) { "message flags mismatch" }
    val timestampMillis = fixed.long
    val sequence = fixed.long
    val senderIdLen = fixed.short.toInt() and 0xffff
    val senderNameLen = fixed.short.toInt() and 0xffff
    val bodyLen = requireWireByteArrayLen("message body length", fixed.int.toLong() and 0xffff_ffffL)
    val expectedLen = 32L + senderIdLen.toLong() + senderNameLen.toLong() + bodyLen.toLong()
    require(payload.size.toLong() == expectedLen) { "message length mismatch" }
    var offset = 32
    val senderId = String(payload, offset, senderIdLen, StandardCharsets.UTF_8)
    offset += senderIdLen
    val senderName = String(payload, offset, senderNameLen, StandardCharsets.UTF_8)
    offset += senderNameLen
    val body = String(payload, offset, bodyLen, StandardCharsets.UTF_8)
    return BifrostMessage(
      protocol = protocol,
      senderId = senderId,
      senderName = senderName,
      body = body,
      sequence = sequence,
      timestampMillis = timestampMillis,
      isAck = (flags and ackFlag) == ackFlag,
    )
  }

  fun frame(payload: ByteArray): ByteArray {
    val out = ByteArrayOutputStream(payload.size + 4)
    writeU32(out, payload.size)
    out.write(payload)
    return out.toByteArray()
  }

  fun readFrame(input: InputStream): ByteArray {
    val lenBytes = readExact(input, 4)
    val len = decodeU32Unsigned(lenBytes, 0)
    require(len <= maxFrameLen.toLong()) { "frame too large: $len" }
    if (len == 0L) return ByteArray(0)
    return readExact(input, len.toInt())
  }

  fun encodeAmeRootFrame(
    packetKind: AmePacketKind,
    sessionId: Long,
    sequence: Long,
    payload: ByteArray,
    profile: AmeProfile = NativeAme.profileForTier(AmeTier.MEDIUM_PLUS),
    initMode: Int = 0x01,
    rootLaneId: Long = 1,
  ): ByteArray = NativeAme.encodeRootFrame(packetKind, sessionId, sequence, payload, profile, initMode, rootLaneId)

  fun encodeAmeChildFrame(
    packetKind: AmePacketKind,
    sessionId: Long,
    sequence: Long,
    laneId: Int,
    payload: ByteArray,
    messageClass: Int = 4,
    rootLaneId: Long = 1,
    parentLaneId: Long = rootLaneId,
  ): ByteArray = NativeAme.encodeChildFrame(
    packetKind,
    sessionId,
    sequence,
    laneId,
    payload,
    messageClass,
    rootLaneId,
    parentLaneId,
  )

  fun encodeAmeChildFrame(
    packetKind: AmePacketKind,
    sessionId: Long,
    sequence: Long,
    laneId: Long,
    payload: ByteArray,
    messageClass: Int = 4,
    rootLaneId: Long = 1,
    parentLaneId: Long = rootLaneId,
  ): ByteArray = NativeAme.encodeChildFrame(
    packetKind,
    sessionId,
    sequence,
    laneId,
    payload,
    messageClass,
    rootLaneId,
    parentLaneId,
  )

  fun decodeAmeFrame(frame: ByteArray): AmeFrame {
    val decoded = NativeAme.decodeFrame(frame)
    return AmeFrame(
      isRoot = decoded.isRoot,
      packetKind = AmePacketKind.fromId(decoded.packetKindId),
      sessionId = decoded.sessionId,
      sequence = decoded.sequence,
      laneId = decoded.laneId,
      payload = decoded.payload,
      messageClass = decoded.messageClass,
      profile = if (decoded.isRoot) {
        NativeAme.profileFromRootBits(
          decoded.keyBits,
          decoded.symmetricBits,
          decoded.macBits,
          decoded.otpBits,
          decoded.authBits,
          decoded.masterKeyTierId,
        )
      } else {
        null
      },
      initMode = decoded.initMode,
      rootLaneId = decoded.rootLaneId,
      parentLaneId = decoded.parentLaneId,
    )
  }

  fun ackFor(local: LocalNode, original: BifrostMessage, sequence: Long): BifrostMessage =
    BifrostMessage(
      protocol = original.protocol,
      senderId = local.nodeId,
      senderName = local.displayName,
      body = "ack ${original.protocol.label} #${original.sequence}",
      sequence = sequence,
      timestampMillis = System.currentTimeMillis(),
      isAck = true,
    )

  private fun writeU16(out: ByteArrayOutputStream, value: Int) {
    out.write(value and 0xff)
    out.write((value ushr 8) and 0xff)
  }

  private fun writeU32(out: ByteArrayOutputStream, value: Int) {
    out.write(value and 0xff)
    out.write((value ushr 8) and 0xff)
    out.write((value ushr 16) and 0xff)
    out.write((value ushr 24) and 0xff)
  }

  private fun writeU64(out: ByteArrayOutputStream, value: Long) {
    var shift = 0
    while (shift < 64) {
      out.write(((value ushr shift) and 0xff).toInt())
      shift += 8
    }
  }

  private fun readExact(input: InputStream, len: Int): ByteArray {
    val data = ByteArray(len)
    var offset = 0
    while (offset < len) {
      val count = input.read(data, offset, len - offset)
      if (count < 0) throw EOFException("socket closed")
      offset += count
    }
    return data
  }

  private fun decodeU32(data: ByteArray, offset: Int): Int =
    (data[offset].toInt() and 0xff) or
      ((data[offset + 1].toInt() and 0xff) shl 8) or
      ((data[offset + 2].toInt() and 0xff) shl 16) or
      ((data[offset + 3].toInt() and 0xff) shl 24)

  private fun decodeU32Unsigned(data: ByteArray, offset: Int): Long =
    decodeU32(data, offset).toLong() and 0xffff_ffffL
}
