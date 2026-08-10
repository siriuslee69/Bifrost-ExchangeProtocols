package com.siriuslee.bifrost.android

import android.util.Log
import java.nio.charset.StandardCharsets

object NativeAme {
  data class DecodedFrame(
    val isRoot: Boolean,
    val packetKindId: Int,
    val sessionId: Long,
    val sequence: Long,
    val laneId: Long,
    val payload: ByteArray,
    val messageClass: Int,
    val keyBits: Int,
    val symmetricBits: Int,
    val macBits: Int,
    val otpBits: Int,
    val authBits: Int,
    val masterKeyTierId: Int,
    val initMode: Int,
    val rootLaneId: Long,
    val parentLaneId: Long,
  )

  val loaded: Boolean = runCatching {
    System.loadLibrary("bifrost_ame_nim")
    System.loadLibrary("bifrost_ame_jni")
    nativeLoaded()
  }.onFailure { logLoadFailure(it) }.getOrDefault(false)

  fun encodeRootFrame(
    packetKind: BifrostWire.AmePacketKind,
    sessionId: Long,
    sequence: Long,
    payload: ByteArray,
    profile: AmeProfile,
    initMode: Int = 0x01,
    rootLaneId: Long = 1,
  ): ByteArray {
    require(initMode in 0..2) { "AME init mode mismatch" }
    val wireSequence = requireWireU32("AME sequence", sequence)
    val wireRootLaneId = requireWireU32("AME rootLaneId", rootLaneId)
    AmeProfile.fromRootBits(
      profile.keyBits,
      profile.symmetricBits,
      profile.macBits,
      profile.otpBits,
      profile.authBits,
      profile.masterKeyTierId,
    )
    return if (loaded) {
      encodeRootFrameNative(
        packetKind.id,
        sessionId,
        wireSequence,
        initMode,
        wireRootLaneId,
        payload,
        profile.keyBits,
        profile.symmetricBits,
        profile.macBits,
        profile.otpBits,
        profile.authBits,
        profile.masterKeyTierId,
      )
    } else {
      AmeReferenceWire.encodeRootFrame(
        packetKind,
        sessionId,
        wireSequence,
        payload,
        profile,
        initMode,
        wireRootLaneId,
      )
    }
  }

  fun encodeChildFrame(
    packetKind: BifrostWire.AmePacketKind,
    sessionId: Long,
    sequence: Long,
    laneId: Int,
    payload: ByteArray,
    messageClass: Int,
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
    messageClass: Int,
    rootLaneId: Long = 1,
    parentLaneId: Long = rootLaneId,
  ): ByteArray {
    require(messageClass in 0..7) { "AME message class mismatch" }
    val wireSequence = requireWireU32("AME sequence", sequence)
    val wireRootLaneId = requireWireU32("AME rootLaneId", rootLaneId)
    val wireParentLaneId = requireWireU32("AME parentLaneId", parentLaneId)
    val wireLaneId = requireWireU32("AME laneId", laneId)
    return if (loaded) {
      encodeChildFrameNative(
        packetKind.id,
        sessionId,
        wireSequence,
        wireRootLaneId,
        wireParentLaneId,
        wireLaneId,
        payload,
        messageClass,
      )
    } else {
      AmeReferenceWire.encodeChildFrame(
        packetKind,
        sessionId,
        wireSequence,
        wireLaneId,
        payload,
        messageClass,
        wireRootLaneId,
        wireParentLaneId,
      )
    }
  }

  fun decodeFrame(frame: ByteArray): DecodedFrame =
    if (loaded) {
      decodeFrameNative(frame)
    } else {
      AmeReferenceWire.decodeFrame(frame)
    }

  fun profileForTier(tier: AmeTier): AmeProfile =
    if (loaded) {
      AmeProfile.fromRaw(profileForTierNative(tier.id))
    } else {
      AmeProfile.reference(tier)
    }

  fun profileFromRootBits(
    keyBits: Int,
    symmetricBits: Int,
    macBits: Int,
    otpBits: Int,
    authBits: Int,
    masterKeyTierId: Int,
  ): AmeProfile =
    AmeProfile.fromRootBits(keyBits, symmetricBits, macBits, otpBits, authBits, masterKeyTierId)

  fun autoUpgradeTier(currentTier: AmeTier, autoEnabled: Boolean, frame: BifrostWire.AmeFrame): AmeTier? {
    val profile = frame.profile ?: return null
    val targetId = if (loaded) {
      autoUpgradeTierNative(
        currentTier.id,
        autoEnabled,
        frame.isRoot,
        frame.packetKind.id,
        profile.keyBits,
        profile.symmetricBits,
        profile.macBits,
        profile.otpBits,
        profile.authBits,
        profile.masterKeyTierId,
      )
    } else {
      AmeReferenceWire.autoUpgradeTierId(currentTier, autoEnabled, frame)
    }
    return if (targetId >= 0) AmeTier.fromId(targetId) else null
  }

  fun keyBundleForTier(
    tier: AmeTier,
    includeSecret: Boolean,
    allowSecretExport: Boolean = false,
  ): String =
    if (loaded) {
      String(keyBundleForTierNative(tier.id, includeSecret, allowSecretExport), StandardCharsets.UTF_8)
    } else {
      AmeReferenceKeys.keyBundle(tier, includeSecret, allowSecretExport)
    }

  private external fun nativeLoaded(): Boolean
  external fun rootHeaderLen(): Int
  external fun childHeaderLen(): Int
  external fun formatVersion(): Int
  private external fun profileForTierNative(tierId: Int): IntArray
  private external fun profileFromBitsNative(
    keyBits: Int,
    symmetricBits: Int,
    macBits: Int,
    otpBits: Int,
    authBits: Int,
    masterKeyTierId: Int,
  ): IntArray
  private external fun keyBundleForTierNative(tierId: Int, includeSecret: Boolean, allowSecretExport: Boolean): ByteArray
  private external fun encodeRootFrameNative(
    packetKind: Int,
    sessionId: Long,
    sequence: Long,
    initMode: Int,
    rootLaneId: Long,
    payload: ByteArray,
    keyBits: Int,
    symmetricBits: Int,
    macBits: Int,
    otpBits: Int,
    authBits: Int,
    masterKeyTierId: Int,
  ): ByteArray
  private external fun encodeChildFrameNative(
    packetKind: Int,
    sessionId: Long,
    sequence: Long,
    rootLaneId: Long,
    parentLaneId: Long,
    laneId: Long,
    payload: ByteArray,
    messageClass: Int,
  ): ByteArray
  private external fun decodeFrameNative(frame: ByteArray): DecodedFrame
  private external fun autoUpgradeTierNative(
    currentTierId: Int,
    autoEnabled: Boolean,
    isRoot: Boolean,
    packetKind: Int,
    keyBits: Int,
    symmetricBits: Int,
    macBits: Int,
    otpBits: Int,
    authBits: Int,
    masterKeyTierId: Int,
  ): Int

  private fun logLoadFailure(error: Throwable) {
    runCatching { Log.e("NativeAme", "native bridge load failed", error) }
  }
}
