package com.siriuslee.bifrost.android

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

object AecReferenceWire {
  private val aecMagic = byteArrayOf('A'.code.toByte(), 'E'.code.toByte(), 'C'.code.toByte(), '1'.code.toByte())
  private const val aecPayloadVersion = 1
  private const val canonicalAuthTagLen = 32
  private const val envelopeHeaderLen = 16
  private const val ameChildHeaderLen = 36

  enum class Carrier(val id: Int) {
    AME_CHILD(0),
    DAC(1),
  }

  data class ProtectedEnvelope(
    val nonce: ByteArray,
    val authTag: ByteArray,
    val payload: ByteArray,
  )

  data class DecodedCarrier(
    val carrier: Carrier,
    val ameFrame: BifrostWire.AmeFrame,
    val envelope: ProtectedEnvelope,
    val dacFrame: DacReferenceWire.DecodedFrame? = null,
  )

  fun encodeProtectedEnvelope(envelope: ProtectedEnvelope): ByteArray {
    require(envelope.nonce.isNotEmpty()) { "AEC protected envelope empty crypto field" }
    require(envelope.authTag.isNotEmpty()) { "AEC protected envelope empty crypto field" }
    require(envelope.nonce.size <= 0xffff) { "AEC protected envelope field too large" }
    require(envelope.authTag.size <= 0xffff) { "AEC protected envelope field too large" }
    val out = ByteArrayOutputStream(envelopeHeaderLen + envelope.nonce.size + envelope.authTag.size + envelope.payload.size)
    out.write(aecMagic)
    writeU16(out, aecPayloadVersion)
    writeU16(out, 0)
    writeU16(out, envelope.nonce.size)
    writeU16(out, envelope.authTag.size)
    writeU32(out, envelope.payload.size.toLong())
    out.write(envelope.nonce)
    out.write(envelope.authTag)
    out.write(envelope.payload)
    return out.toByteArray()
  }

  fun decodeProtectedEnvelope(data: ByteArray): ProtectedEnvelope {
    require(data.size >= envelopeHeaderLen) { "AEC protected envelope too short" }
    require(data.copyOfRange(0, 4).contentEquals(aecMagic)) { "AEC protected envelope magic mismatch" }
    require(readU16(data, 4) == aecPayloadVersion) { "AEC protected envelope version mismatch" }
    require(readU16(data, 6) == 0) { "AEC protected envelope reserved bits mismatch" }
    val nonceLen = readU16(data, 8)
    val authTagLen = readU16(data, 10)
    val payloadLen = requireWireByteArrayLen("AEC protected envelope payload length", readU32(data, 12))
    require(nonceLen > 0 && authTagLen > 0) { "AEC protected envelope empty crypto field" }
    require(authTagLen == canonicalAuthTagLen) { "AEC protected envelope auth tag length mismatch" }
    val expectedLen = envelopeHeaderLen.toLong() + nonceLen.toLong() + authTagLen.toLong() + payloadLen.toLong()
    require(data.size.toLong() == expectedLen) { "AEC protected envelope length mismatch" }
    var offset = envelopeHeaderLen
    val nonce = data.copyOfRange(offset, offset + nonceLen)
    offset += nonceLen
    val authTag = data.copyOfRange(offset, offset + authTagLen)
    offset += authTagLen
    val payload = data.copyOfRange(offset, offset + payloadLen)
    return ProtectedEnvelope(nonce = nonce, authTag = authTag, payload = payload)
  }

  fun encodeAmeChildCarrier(
    sessionId: Long,
    ameSequence: Long,
    laneId: Int,
    envelope: ProtectedEnvelope,
    messageClass: Int = 4,
    rootLaneId: Long = 1,
    parentLaneId: Long = rootLaneId,
  ): ByteArray =
    encodeAmeChildCarrier(
      sessionId,
      ameSequence,
      intBitsToWireU32(laneId),
      envelope,
      messageClass,
      rootLaneId,
      parentLaneId,
    )

  fun encodeAmeChildCarrier(
    sessionId: Long,
    ameSequence: Long,
    laneId: Long,
    envelope: ProtectedEnvelope,
    messageClass: Int = 4,
    rootLaneId: Long = 1,
    parentLaneId: Long = rootLaneId,
  ): ByteArray =
    BifrostWire.encodeAmeChildFrame(
      BifrostWire.AmePacketKind.LANE_DATA,
      sessionId,
      ameSequence,
      laneId,
      encodeProtectedEnvelope(envelope),
      messageClass,
      rootLaneId,
      parentLaneId,
    )

  fun decodeAmeChildCarrier(frame: ByteArray): DecodedCarrier {
    val ame = BifrostWire.decodeAmeFrame(frame)
    require(!ame.isRoot) { "AEC expected AME child lane data" }
    require(ame.packetKind == BifrostWire.AmePacketKind.LANE_DATA) { "AEC expected AME lane data packet" }
    return DecodedCarrier(
      carrier = Carrier.AME_CHILD,
      ameFrame = ame,
      envelope = decodeProtectedEnvelope(ame.payload),
    )
  }

  fun encodeDacCarrier(
    sessionId: Long,
    ameSequence: Long,
    dacSequence: Long,
    laneId: Int,
    envelope: ProtectedEnvelope,
    epochId: Int = 0,
    messageClass: Int = 4,
    superClean: Boolean = false,
    rootLaneId: Long = 1,
    parentLaneId: Long = rootLaneId,
  ): ByteArray =
    encodeDacCarrier(
      sessionId,
      ameSequence,
      dacSequence,
      intBitsToWireU32(laneId),
      envelope,
      epochId,
      messageClass,
      superClean,
      rootLaneId,
      parentLaneId,
    )

  fun encodeDacCarrier(
    sessionId: Long,
    ameSequence: Long,
    dacSequence: Long,
    laneId: Long,
    envelope: ProtectedEnvelope,
    epochId: Int = 0,
    messageClass: Int = 4,
    superClean: Boolean = false,
    rootLaneId: Long = 1,
    parentLaneId: Long = rootLaneId,
  ): ByteArray {
    val ameFrame = encodeAmeChildCarrier(
      sessionId,
      ameSequence,
      laneId,
      envelope,
      messageClass,
      rootLaneId,
      parentLaneId,
    )
    return DacReferenceWire.encodePackageChunk(
      sessionId = sessionId,
      laneId = laneId,
      epochId = epochId,
      sequence = dacSequence,
      payload = ameFrame,
      superClean = superClean,
    )
  }

  fun decodeDacCarrier(frame: ByteArray): DecodedCarrier {
    val dac = DacReferenceWire.decodeFrame(frame)
    require(dac.header.messageKind == DacReferenceWire.MessageKind.PACKAGE_CHUNK) { "AEC expected DAC package chunk" }
    val decoded = decodeAmeChildCarrier(dac.payload)
    require(dac.header.sessionId == decoded.ameFrame.sessionId) { "AEC DAC/AME session mismatch" }
    require(dac.header.laneId == decoded.ameFrame.laneId) { "AEC DAC/AME lane mismatch" }
    return decoded.copy(carrier = Carrier.DAC, dacFrame = dac)
  }

  fun buildAadForAmeChild(frame: ByteArray): ByteArray {
    val decoded = decodeAmeChildCarrier(frame)
    val headerBytes = frame.copyOfRange(0, ameChildHeaderLen)
    return buildAad(Carrier.AME_CHILD, headerBytes, decoded.dacFrame?.header)
  }

  fun buildAadForDac(frame: ByteArray): ByteArray {
    val decoded = decodeDacCarrier(frame)
    val dac = decoded.dacFrame ?: error("DAC frame missing")
    val headerBytes = dac.payload.copyOfRange(0, ameChildHeaderLen)
    return buildAad(Carrier.DAC, headerBytes, dac.header)
  }

  private fun buildAad(
    carrier: Carrier,
    ameHeaderBytes: ByteArray,
    dacHeader: DacReferenceWire.FrameHeader?,
  ): ByteArray {
    val out = ByteArrayOutputStream()
    out.write("AEC1-AAD".toByteArray(StandardCharsets.US_ASCII))
    out.write(carrier.id)
    writeU32(out, ameHeaderBytes.size.toLong())
    out.write(ameHeaderBytes)
    if (carrier == Carrier.DAC) {
      require(dacHeader != null) { "AEC DAC AAD requires DAC header" }
      appendDacHeaderAad(out, dacHeader)
    }
    return out.toByteArray()
  }

  private fun appendDacHeaderAad(out: ByteArrayOutputStream, header: DacReferenceWire.FrameHeader) {
    out.write("DAC1".toByteArray(StandardCharsets.US_ASCII))
    out.write(header.messageKind.id)
    writeU16(out, header.flags)
    writeU64(out, header.sessionId)
    writeU32(out, header.laneId)
    writeU16(out, header.epochId)
    writeU32(out, header.sequence)
    out.write(header.bodyLenMode.id)
    writeU32(out, header.bodyLen.toLong())
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
}
