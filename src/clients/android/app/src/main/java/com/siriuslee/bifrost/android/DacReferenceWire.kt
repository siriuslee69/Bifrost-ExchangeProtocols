package com.siriuslee.bifrost.android

import java.io.ByteArrayOutputStream

object DacReferenceWire {
  private val dacMagic = byteArrayOf('D'.code.toByte(), 'A'.code.toByte(), 'C'.code.toByte())
  private const val dacFormatVersion = 1
  private const val baseHeaderLen = 27
  private const val extendedHeaderLen = 29
  private const val knownFrameFlagMask = 0x01ff
  private const val superCleanMaxBodyLen = 16_777_216

  enum class MessageKind(val id: Int) {
    UNKNOWN(0x00),
    PATH_PROBE(0x01),
    PATH_STATS(0x02),
    RECEIVE_BUDGET(0x03),
    PACKAGE_MANIFEST(0x04),
    PACKAGE_CHUNK(0x05),
    PARITY_SHARD(0x06),
    ACK_RANGE(0x07),
    REPAIR_HINT(0x08),
    REPAIR_CHUNK(0x09),
    PACKAGE_COMMIT(0x0a),
    PATH_SWITCH_REQUEST(0x0b),
    PATH_SWITCH_ACK(0x0c),
    DRIFT_PAYLOAD(0x0d);

    companion object {
      fun fromId(id: Int): MessageKind =
        entries.firstOrNull { it.id == id } ?: UNKNOWN
    }
  }

  enum class BodyLenMode(val id: Int) {
    U16(0),
    U32(1),
  }

  data class FrameFlags(
    val needsAck: Boolean = false,
    val isRepair: Boolean = false,
    val isParity: Boolean = false,
    val endOfGroup: Boolean = false,
    val endOfPackage: Boolean = false,
    val pathProbe: Boolean = false,
    val creditBound: Boolean = false,
    val tcpRepairAllowed: Boolean = false,
    val extendedBodyLen: Boolean = false,
  ) {
    fun pack(): Int {
      var bits = 0
      if (needsAck) bits = bits or 0x0001
      if (isRepair) bits = bits or 0x0002
      if (isParity) bits = bits or 0x0004
      if (endOfGroup) bits = bits or 0x0008
      if (endOfPackage) bits = bits or 0x0010
      if (pathProbe) bits = bits or 0x0020
      if (creditBound) bits = bits or 0x0040
      if (tcpRepairAllowed) bits = bits or 0x0080
      if (extendedBodyLen) bits = bits or 0x0100
      return bits
    }

    companion object {
      fun unpack(bits: Int): FrameFlags {
        require((bits and knownFrameFlagMask.inv()) == 0) { "DAC frame has unknown flag bits" }
        return FrameFlags(
          needsAck = (bits and 0x0001) != 0,
          isRepair = (bits and 0x0002) != 0,
          isParity = (bits and 0x0004) != 0,
          endOfGroup = (bits and 0x0008) != 0,
          endOfPackage = (bits and 0x0010) != 0,
          pathProbe = (bits and 0x0020) != 0,
          creditBound = (bits and 0x0040) != 0,
          tcpRepairAllowed = (bits and 0x0080) != 0,
          extendedBodyLen = (bits and 0x0100) != 0,
        )
      }
    }
  }

  data class FrameHeader(
    val messageKind: MessageKind,
    val flags: Int,
    val sessionId: Long,
    val laneId: Long,
    val epochId: Int,
    val sequence: Long,
    val bodyLenMode: BodyLenMode,
    val bodyLen: Int,
  )

  data class DecodedFrame(
    val header: FrameHeader,
    val flags: FrameFlags,
    val payload: ByteArray,
  )

  fun packageChunkHeader(
    sessionId: Long,
    laneId: Long,
    epochId: Int,
    sequence: Long,
    bodyLen: Int,
    superClean: Boolean = false,
    flags: FrameFlags = FrameFlags(endOfPackage = true),
  ): FrameHeader {
    val mode = if (superClean || bodyLen > 0xffff) BodyLenMode.U32 else BodyLenMode.U16
    val normalized = if (mode == BodyLenMode.U32) flags.copy(extendedBodyLen = true) else flags.copy(extendedBodyLen = false)
    return FrameHeader(
      messageKind = MessageKind.PACKAGE_CHUNK,
      flags = normalized.pack(),
      sessionId = sessionId,
      laneId = laneId,
      epochId = epochId,
      sequence = sequence,
      bodyLenMode = mode,
      bodyLen = bodyLen,
    )
  }

  fun encodePackageChunk(
    sessionId: Long,
    laneId: Long,
    epochId: Int,
    sequence: Long,
    payload: ByteArray,
    superClean: Boolean = false,
  ): ByteArray =
    encodeFrame(packageChunkHeader(sessionId, laneId, epochId, sequence, payload.size, superClean), payload)

  fun encodeFrame(header: FrameHeader, payload: ByteArray): ByteArray {
    require(header.messageKind != MessageKind.UNKNOWN) { "DAC frame kind must not be unknown" }
    require(header.bodyLen == payload.size) { "DAC frame body length mismatch" }
    val laneId = requireWireU32("DAC laneId", header.laneId)
    val sequence = requireWireU32("DAC sequence", header.sequence)
    val epochId = requireWireU16("DAC epochId", header.epochId)
    val flags = FrameFlags.unpack(header.flags)
    require((header.bodyLenMode == BodyLenMode.U32) == flags.extendedBodyLen) { "DAC frame flags do not match body length mode" }
    if (header.bodyLenMode == BodyLenMode.U16) {
      require(header.bodyLen <= 0xffff) { "DAC base body length exceeds u16" }
    } else {
      require(header.bodyLen <= superCleanMaxBodyLen) { "DAC SuperClean body length exceeds limit" }
    }
    val out = ByteArrayOutputStream((if (header.bodyLenMode == BodyLenMode.U32) extendedHeaderLen else baseHeaderLen) + payload.size)
    out.write(dacMagic)
    out.write(dacFormatVersion)
    out.write(header.messageKind.id)
    writeU16(out, header.flags)
    writeU64(out, header.sessionId)
    writeU32(out, laneId)
    writeU16(out, epochId)
    writeU32(out, sequence)
    if (header.bodyLenMode == BodyLenMode.U32) {
      writeU32(out, header.bodyLen.toLong())
    } else {
      writeU16(out, header.bodyLen)
    }
    out.write(payload)
    return out.toByteArray()
  }

  fun decodeFrame(frame: ByteArray): DecodedFrame {
    require(frame.size >= baseHeaderLen) { "DAC frame too short" }
    require(frame.copyOfRange(0, 3).contentEquals(dacMagic)) { "DAC magic mismatch" }
    require((frame[3].toInt() and 0xff) == dacFormatVersion) { "DAC format version mismatch" }
    val messageKind = MessageKind.fromId(frame[4].toInt() and 0xff)
    require(messageKind != MessageKind.UNKNOWN) { "DAC message kind mismatch" }
    val flagBits = readU16(frame, 5)
    val flags = FrameFlags.unpack(flagBits)
    val mode = if (flags.extendedBodyLen) BodyLenMode.U32 else BodyLenMode.U16
    val headerLen = if (mode == BodyLenMode.U32) extendedHeaderLen else baseHeaderLen
    require(frame.size >= headerLen) { "DAC frame too short" }
    val bodyLen = if (mode == BodyLenMode.U32) {
      requireWireByteArrayLen("DAC frame body length", readU32(frame, 25))
    } else {
      readU16(frame, 25)
    }
    require(mode != BodyLenMode.U32 || bodyLen <= superCleanMaxBodyLen) { "DAC SuperClean body length exceeds limit" }
    require(frame.size.toLong() == headerLen.toLong() + bodyLen.toLong()) { "DAC frame body length mismatch" }
    val header = FrameHeader(
      messageKind = messageKind,
      flags = flagBits,
      sessionId = readU64(frame, 7),
      laneId = readU32(frame, 15),
      epochId = readU16(frame, 19),
      sequence = readU32(frame, 21),
      bodyLenMode = mode,
      bodyLen = bodyLen,
    )
    return DecodedFrame(
      header = header,
      flags = flags,
      payload = frame.copyOfRange(headerLen, frame.size),
    )
  }

  private fun writeU16(out: ByteArrayOutputStream, value: Int) {
    out.write(value and 0xff)
    out.write((value ushr 8) and 0xff)
  }

  private fun writeU32(out: ByteArrayOutputStream, value: Long) {
    out.write((value and 0xffL).toInt())
    out.write(((value ushr 8) and 0xffL).toInt())
    out.write(((value ushr 16) and 0xffL).toInt())
    out.write(((value ushr 24) and 0xffL).toInt())
  }

  private fun writeU64(out: ByteArrayOutputStream, value: Long) {
    var shift = 0
    while (shift < 64) {
      out.write(((value ushr shift) and 0xffL).toInt())
      shift += 8
    }
  }

  private fun readU16(data: ByteArray, offset: Int): Int =
    (data[offset].toInt() and 0xff) or
      ((data[offset + 1].toInt() and 0xff) shl 8)

  private fun readU32(data: ByteArray, offset: Int): Long =
    (data[offset].toLong() and 0xffL) or
      ((data[offset + 1].toLong() and 0xffL) shl 8) or
      ((data[offset + 2].toLong() and 0xffL) shl 16) or
      ((data[offset + 3].toLong() and 0xffL) shl 24)

  private fun readU64(data: ByteArray, offset: Int): Long {
    var value = 0L
    var i = 0
    while (i < 8) {
      value = value or ((data[offset + i].toLong() and 0xffL) shl (8 * i))
      i += 1
    }
    return value
  }
}
