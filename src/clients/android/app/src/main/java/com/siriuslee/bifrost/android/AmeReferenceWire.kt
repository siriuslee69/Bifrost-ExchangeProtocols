package com.siriuslee.bifrost.android

import java.nio.ByteBuffer
import java.nio.ByteOrder

object AmeReferenceWire {
  private val ameMagic = byteArrayOf('A'.code.toByte(), 'M'.code.toByte(), 'E'.code.toByte(), '1'.code.toByte())
  private const val ameVersion = 2
  private const val rootHeaderLen = 36
  private const val childHeaderLen = 36

  fun encodeRootFrame(
    packetKind: BifrostWire.AmePacketKind,
    sessionId: Long,
    sequence: Long,
    payload: ByteArray,
    profile: AmeProfile,
    initMode: Int = 0x01,
    rootLaneId: Long = 1,
  ): ByteArray {
    require(packetKind.isRootKind()) { "AME root header packet kind is not root-shaped" }
    require(initMode in 0..2) { "AME init mode mismatch" }
    val canonicalProfile = AmeProfile.fromRootBits(
      profile.keyBits,
      profile.symmetricBits,
      profile.macBits,
      profile.otpBits,
      profile.authBits,
      profile.masterKeyTierId,
    )
    val header = ByteBuffer.allocate(rootHeaderLen).order(ByteOrder.LITTLE_ENDIAN)
    header.put(ameMagic)
    header.putShort(ameVersion.toShort())
    header.put(packetKind.id.toByte())
    header.put(initMode.toByte())
    header.putLong(sessionId)
    header.putInt(requireWireU32Int("AME rootLaneId", rootLaneId))
    header.putInt(requireWireU32Int("AME sequence", sequence))
    header.putInt(payload.size)
    header.putShort(canonicalProfile.keyBits.toShort())
    header.put(canonicalProfile.symmetricBits.toByte())
    header.put(canonicalProfile.macBits.toByte())
    header.put(canonicalProfile.otpBits.toByte())
    header.put(canonicalProfile.authBits.toByte())
    header.put(canonicalProfile.masterKeyTierId.toByte())
    header.put(0.toByte())
    return header.array() + payload
  }

  fun encodeChildFrame(
    packetKind: BifrostWire.AmePacketKind,
    sessionId: Long,
    sequence: Long,
    laneId: Int,
    payload: ByteArray,
    messageClass: Int = 4,
    rootLaneId: Long = 1,
    parentLaneId: Long = rootLaneId,
  ): ByteArray =
    encodeChildFrame(
      packetKind,
      sessionId,
      sequence,
      intBitsToWireU32(laneId),
      payload,
      messageClass,
      rootLaneId,
      parentLaneId,
    )

  fun encodeChildFrame(
    packetKind: BifrostWire.AmePacketKind,
    sessionId: Long,
    sequence: Long,
    laneId: Long,
    payload: ByteArray,
    messageClass: Int = 4,
    rootLaneId: Long = 1,
    parentLaneId: Long = rootLaneId,
  ): ByteArray {
    require(packetKind != BifrostWire.AmePacketKind.UNKNOWN && !packetKind.isRootKind()) {
      "AME child header packet kind is not child-shaped"
    }
    require(messageClass in 0..7) { "AME message class mismatch" }
    val header = ByteBuffer.allocate(childHeaderLen).order(ByteOrder.LITTLE_ENDIAN)
    header.put(ameMagic)
    header.putShort(ameVersion.toShort())
    header.put(packetKind.id.toByte())
    header.put(messageClass.toByte())
    header.putLong(sessionId)
    header.putInt(requireWireU32Int("AME rootLaneId", rootLaneId))
    header.putInt(requireWireU32Int("AME parentLaneId", parentLaneId))
    header.putInt(requireWireU32Int("AME laneId", laneId))
    header.putInt(requireWireU32Int("AME sequence", sequence))
    header.putInt(payload.size)
    return header.array() + payload
  }

  fun decodeFrame(frame: ByteArray): NativeAme.DecodedFrame {
    require(frame.size >= rootHeaderLen) { "AME frame too short" }
    require(frame.sliceArray(0 until 4).contentEquals(ameMagic)) { "AME magic mismatch" }
    val version = decodeU16(frame, 4)
    require(version == ameVersion) { "unsupported AME version $version" }
    val packetKind = BifrostWire.AmePacketKind.fromId(frame[6].toInt() and 0xff)
    require(packetKind != BifrostWire.AmePacketKind.UNKNOWN) { "AME packet kind mismatch" }
    val sessionId = decodeU64(frame, 8)
    val isRoot = packetKind.isRootKind()
    if (isRoot) {
      val initMode = frame[7].toInt() and 0xff
      val sequence = decodeU32(frame, 20)
      val payloadLen = requireWireByteArrayLen("AME root payload length", decodeU32(frame, 24))
      val masterKeyTierId = frame[34].toInt() and 0xff
      require(initMode <= 2) { "AME init mode mismatch" }
      require(AmeProfile.masterKeyTierIdValid(masterKeyTierId)) { "AME master-key tier mismatch" }
      require((frame[35].toInt() and 0xff) == 0) { "AME root reserved byte mismatch" }
      AmeProfile.fromRootBits(
        keyBits = decodeU16(frame, 28),
        symmetricBits = frame[30].toInt() and 0xff,
        macBits = frame[31].toInt() and 0xff,
        otpBits = frame[32].toInt() and 0xff,
        authBits = frame[33].toInt() and 0xff,
        masterKeyTierId = masterKeyTierId,
      )
      require(frame.size.toLong() == rootHeaderLen.toLong() + payloadLen.toLong()) { "AME root payload length mismatch" }
      return NativeAme.DecodedFrame(
        isRoot = true,
        packetKindId = packetKind.id,
        sessionId = sessionId,
        sequence = sequence,
        laneId = decodeU32(frame, 16),
        payload = frame.copyOfRange(rootHeaderLen, frame.size),
        messageClass = 0,
        keyBits = decodeU16(frame, 28),
        symmetricBits = frame[30].toInt() and 0xff,
        macBits = frame[31].toInt() and 0xff,
        otpBits = frame[32].toInt() and 0xff,
        authBits = frame[33].toInt() and 0xff,
        masterKeyTierId = masterKeyTierId,
        initMode = initMode,
        rootLaneId = decodeU32(frame, 16),
        parentLaneId = 0,
      )
    }
    val messageClass = frame[7].toInt() and 0xff
    val sequence = decodeU32(frame, 28)
    val payloadLen = requireWireByteArrayLen("AME child payload length", decodeU32(frame, 32))
    require(messageClass <= 7) { "AME message class mismatch" }
    require(frame.size.toLong() == childHeaderLen.toLong() + payloadLen.toLong()) { "AME child payload length mismatch" }
    return NativeAme.DecodedFrame(
      isRoot = false,
      packetKindId = packetKind.id,
      sessionId = sessionId,
      sequence = sequence,
      laneId = decodeU32(frame, 24),
      payload = frame.copyOfRange(childHeaderLen, frame.size),
      messageClass = messageClass,
      keyBits = 0,
      symmetricBits = 0,
      macBits = 0,
      otpBits = 0,
      authBits = 0,
      masterKeyTierId = 0,
      initMode = 0,
      rootLaneId = decodeU32(frame, 16),
      parentLaneId = decodeU32(frame, 20),
    )
  }

  fun autoUpgradeTierId(currentTier: AmeTier, autoEnabled: Boolean, frame: BifrostWire.AmeFrame): Int {
    if (!autoEnabled) return -1
    if (!frame.isRoot) return -1
    if (!frame.packetKind.isNegotiationRequestKind()) return -1
    val requested = frame.profile ?: return -1
    val current = AmeProfile.reference(currentTier)
    if (requested.keyBits == current.keyBits &&
      requested.symmetricBits == current.symmetricBits &&
      requested.macBits == current.macBits &&
      requested.otpBits == current.otpBits &&
      requested.authBits == current.authBits &&
      requested.masterKeyTierId == current.masterKeyTierId
    ) {
      return -1
    }
    return requested.tier.id
  }

  private fun decodeU16(data: ByteArray, offset: Int): Int =
    (data[offset].toInt() and 0xff) or
      ((data[offset + 1].toInt() and 0xff) shl 8)

  private fun decodeU32(data: ByteArray, offset: Int): Long =
    (data[offset].toLong() and 0xffL) or
      ((data[offset + 1].toLong() and 0xffL) shl 8) or
      ((data[offset + 2].toLong() and 0xffL) shl 16) or
      ((data[offset + 3].toLong() and 0xffL) shl 24)

  private fun decodeU64(data: ByteArray, offset: Int): Long {
    var value = 0L
    var i = 0
    while (i < 8) {
      value = value or ((data[offset + i].toLong() and 0xffL) shl (8 * i))
      i += 1
    }
    return value
  }
}
