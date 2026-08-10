package com.siriuslee.bifrost.android

object NativeAec {
  fun roundTripDac(): Int =
    if (NativeAme.loaded) roundTripDacNative() else -1000

  fun sealDac(
    payload: ByteArray,
    seed: ByteArray,
    tier: AmeTier,
    sessionId: Long,
    laneId: Int,
    ameSequence: Long,
    dacSequence: Long,
    rootLaneId: Long = 1,
  ): ByteArray =
    sealDac(
      payload = payload,
      seed = seed,
      tier = tier,
      sessionId = sessionId,
      laneId = intBitsToWireU32(laneId),
      ameSequence = ameSequence,
      dacSequence = dacSequence,
      rootLaneId = rootLaneId,
    )

  fun sealDac(
    payload: ByteArray,
    seed: ByteArray,
    tier: AmeTier,
    sessionId: Long,
    laneId: Long,
    ameSequence: Long,
    dacSequence: Long,
    rootLaneId: Long = 1,
  ): ByteArray {
    require(NativeAme.loaded) { "native AME/AEC bridge unavailable" }
    require(seed.isNotEmpty()) { "AEC seed is empty" }
    return sealDacNative(
      tier.id,
      sessionId,
      requireWireU32("AEC rootLaneId", rootLaneId),
      requireWireU32("AEC laneId", laneId),
      requireWireU32("AEC AME sequence", ameSequence),
      requireWireU32("AEC DAC sequence", dacSequence),
      seed,
      payload,
    )
  }

  fun openDac(
    frame: ByteArray,
    seed: ByteArray,
    tier: AmeTier,
    sessionId: Long,
    laneId: Int,
    expectedAmeSequence: Long,
    expectedDacSequence: Long,
    rootLaneId: Long = 1,
  ): ByteArray =
    openDac(
      frame = frame,
      seed = seed,
      tier = tier,
      sessionId = sessionId,
      laneId = intBitsToWireU32(laneId),
      expectedAmeSequence = expectedAmeSequence,
      expectedDacSequence = expectedDacSequence,
      rootLaneId = rootLaneId,
    )

  fun openDac(
    frame: ByteArray,
    seed: ByteArray,
    tier: AmeTier,
    sessionId: Long,
    laneId: Long,
    expectedAmeSequence: Long,
    expectedDacSequence: Long,
    rootLaneId: Long = 1,
  ): ByteArray {
    require(NativeAme.loaded) { "native AME/AEC bridge unavailable" }
    require(seed.isNotEmpty()) { "AEC seed is empty" }
    return openDacNative(
      tier.id,
      sessionId,
      requireWireU32("AEC rootLaneId", rootLaneId),
      requireWireU32("AEC laneId", laneId),
      requireWireU32("AEC expected AME sequence", expectedAmeSequence),
      requireWireU32("AEC expected DAC sequence", expectedDacSequence),
      seed,
      frame,
    )
  }

  private external fun roundTripDacNative(): Int
  private external fun sealDacNative(
    tierId: Int,
    sessionId: Long,
    rootLaneId: Long,
    laneId: Long,
    ameSequence: Long,
    dacSequence: Long,
    seed: ByteArray,
    payload: ByteArray,
  ): ByteArray
  private external fun openDacNative(
    tierId: Int,
    sessionId: Long,
    rootLaneId: Long,
    laneId: Long,
    expectedAmeSequence: Long,
    expectedDacSequence: Long,
    seed: ByteArray,
    frame: ByteArray,
  ): ByteArray
}
