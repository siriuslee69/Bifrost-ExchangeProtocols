package com.siriuslee.bifrost.android

enum class AmeTier(
  val id: Int,
  val label: String,
) {
  MEDIUM(0, "Medium"),
  LIGHTWEIGHT(1, "Lightweight"),
  LIGHTWEIGHT_PLUS(2, "LightweightPlus"),
  MEDIUM_PLUS(3, "MediumPlus"),
  HIGH(4, "High"),
  HIGH_PLUS(5, "HighPlus");

  companion object {
    fun fromId(id: Int): AmeTier =
      entries.firstOrNull { it.id == id } ?: MEDIUM
  }
}

data class AmeProfile(
  val tier: AmeTier,
  val asymmetricBand: Int,
  val asymmetricTier: Int,
  val symmetricTier: Int,
  val verificationTier: Int,
  val ghostTier: Int,
  val keyBits: Int,
  val symmetricBits: Int,
  val macBits: Int,
  val otpBits: Int,
  val authBits: Int,
  val masterKeyTierId: Int,
) {
  val asymmetricLabel: String
    get() = if (asymmetricTier <= 0) "TierNone" else "Tier${bandLabel(asymmetricBand)}$asymmetricTier"

  val symmetricLabel: String
    get() = tierLabel(symmetricTier)

  val verificationLabel: String
    get() = tierLabel(verificationTier)

  val ghostLabel: String
    get() = if (ghostTier <= 0) "TierNone" else "Tier$ghostTier"

  val summary: String
    get() = "${tier.label}  $asymmetricLabel  sym $symmetricLabel  verify $verificationLabel  ghost $ghostLabel  kdf $masterKeyLabel"

  val bitsSummary: String
    get() = "key ${bits(keyBits, 15)}  sym ${bits(symmetricBits, 3)}  mac ${bits(macBits, 4)}  otp ${bits(otpBits, 3)}  auth ${bits(authBits, 6)}"

  val masterKeyLabel: String
    get() = masterKeyTierLabel(masterKeyTierId)

  companion object {
    fun fromRaw(raw: IntArray): AmeProfile {
      require(raw.size >= 12) { "AME profile payload too short" }
      return AmeProfile(
        tier = AmeTier.fromId(raw[0]),
        asymmetricBand = raw[1],
        asymmetricTier = raw[2],
        symmetricTier = raw[3],
        verificationTier = raw[4],
        ghostTier = raw[5],
        keyBits = raw[6],
        symmetricBits = raw[7],
        macBits = raw[8],
        otpBits = raw[9],
        authBits = raw[10],
        masterKeyTierId = raw[11],
      )
    }

    fun reference(tier: AmeTier): AmeProfile =
      when (tier) {
        AmeTier.LIGHTWEIGHT -> AmeProfile(tier, 3, 5, 3, 4, 3, 0b000000000010000, 0b010, 0b1000, 0b100, 0b000001, 5)
        AmeTier.LIGHTWEIGHT_PLUS -> AmeProfile(tier, 3, 4, 2, 3, 2, 0b000000000010100, 0b110, 0b1100, 0b110, 0b000110, 4)
        AmeTier.MEDIUM -> AmeProfile(tier, 2, 4, 2, 3, 2, 0b000001010000000, 0b110, 0b1100, 0b110, 0b000110, 3)
        AmeTier.MEDIUM_PLUS -> AmeProfile(tier, 2, 2, 1, 2, 2, 0b000001111000000, 0b111, 0b1100, 0b110, 0b011000, 2)
        AmeTier.HIGH -> AmeProfile(tier, 1, 4, 1, 2, 1, 0b101000000000000, 0b111, 0b1100, 0b111, 0b011000, 2)
        AmeTier.HIGH_PLUS -> AmeProfile(tier, 1, 1, 1, 1, 1, 0b111110000000000, 0b111, 0b1100, 0b111, 0b111000, 1)
      }

    fun fromRootBits(
      keyBits: Int,
      symmetricBits: Int,
      macBits: Int,
      otpBits: Int,
      authBits: Int,
      masterKeyTierId: Int,
    ): AmeProfile {
      require(masterKeyTierIdValid(masterKeyTierId)) { "AME master-key tier mismatch" }
      val profile = AmeProfile(
        tier = AmeTier.MEDIUM,
        asymmetricBand = deriveAsymmetricBand(keyBits),
        asymmetricTier = deriveAsymmetricTier(keyBits),
        symmetricTier = deriveSymmetricTier(symmetricBits, macBits),
        verificationTier = deriveVerificationTier(authBits),
        ghostTier = deriveGhostTier(otpBits),
        keyBits = keyBits,
        symmetricBits = symmetricBits,
        macBits = macBits,
        otpBits = otpBits,
        authBits = authBits,
        masterKeyTierId = masterKeyTierId,
      )
      require(profileBitsAreCanonical(profile)) { "AME profile bits are invalid" }
      return profile.copy(tier = deriveAeadTier(profile))
    }

    fun masterKeyTierIdValid(id: Int): Boolean = id in 1..5
  }
}

private fun bandLabel(band: Int): String =
  when (band) {
    1 -> "A"
    2 -> "B"
    3 -> "C"
    else -> "?"
  }

private fun tierLabel(tier: Int): String =
  if (tier <= 0) "TierNone" else "Tier$tier"

private fun bits(value: Int, width: Int): String =
  value.toString(2).padStart(width, '0').takeLast(width)

private fun masterKeyTierLabel(id: Int): String =
  when (id) {
    1 -> "TierK1-Argon2id-xor-SHA3-xor-BLAKE3-xor-Gimli"
    2 -> "TierK2-SHA3-xor-BLAKE3-xor-Gimli"
    3 -> "TierK3-BLAKE3-xor-Gimli"
    4 -> "TierK4-SHA3"
    5 -> "TierK5-Gimli"
    else -> "TierK?"
  }

private val kemOrderA = intArrayOf(0b100000000000000, 0b001000000000000, 0b010000000000000, 0b000100000000000, 0b000010000000000)
private val kemOrderB = intArrayOf(0b000001000000000, 0b000000010000000, 0b000000100000000, 0b000000001000000, 0b000000000100000)
private val kemOrderC = intArrayOf(0b000000000010000, 0b000000000000100, 0b000000000001000, 0b000000000000010, 0b000000000000001)

private const val ameKemMaskA = 0b111110000000000
private const val ameKemMaskB = 0b000001111100000
private const val ameKemMaskC = 0b000000000011111
private const val ameKemAllMask = ameKemMaskA or ameKemMaskB or ameKemMaskC

private const val ameSymmetricBitXChaCha20 = 0b100
private const val ameSymmetricBitGimli = 0b010
private const val ameSymmetricBitAesCtr = 0b001
private const val ameCipherTier1 = ameSymmetricBitXChaCha20 or ameSymmetricBitGimli or ameSymmetricBitAesCtr
private const val ameCipherTier2 = ameSymmetricBitXChaCha20 or ameSymmetricBitGimli
private const val ameCipherTier3 = ameSymmetricBitGimli
private const val ameCipherAllMask = ameSymmetricBitXChaCha20 or ameSymmetricBitGimli or ameSymmetricBitAesCtr

private const val ameMacBitGimli = 0b1000
private const val ameMacBitSha3 = 0b0100
private const val ameMacBitBlake3 = 0b0010
private const val ameMacBitPoly1305 = 0b0001
private const val ameMacGimliSha3 = ameMacBitSha3 or ameMacBitGimli
private const val ameMacAllMask = ameMacBitGimli or ameMacBitSha3 or ameMacBitBlake3 or ameMacBitPoly1305

private const val ameOtpBitGimli = 0b100
private const val ameOtpBitBlake3 = 0b010
private const val ameOtpBitAesCtr = 0b001
private const val ameOtpAllMask = ameOtpBitGimli or ameOtpBitBlake3 or ameOtpBitAesCtr
private const val ameGhostTier1Bits = ameOtpBitGimli or ameOtpBitBlake3 or ameOtpBitAesCtr
private const val ameGhostTier2Bits = ameOtpBitGimli or ameOtpBitBlake3
private const val ameGhostTier3Bits = ameOtpBitGimli

private const val ameAuthBitSphincs = 0b100000
private const val ameAuthBitFalcon1024 = 0b010000
private const val ameAuthBitDilithium2 = 0b001000
private const val ameAuthBitFalcon512 = 0b000100
private const val ameAuthBitDilithium1 = 0b000010
private const val ameAuthBitDilithium0 = 0b000001
private const val ameAuthTier1Bits = ameAuthBitSphincs or ameAuthBitFalcon1024 or ameAuthBitDilithium2
private const val ameAuthTier2Bits = ameAuthBitFalcon1024 or ameAuthBitDilithium2
private const val ameAuthTier3Bits = ameAuthBitFalcon512 or ameAuthBitDilithium1
private const val ameAuthTier4Bits = ameAuthBitDilithium0
private const val ameAuthAllMask = ameAuthBitSphincs or ameAuthBitFalcon1024 or ameAuthBitDilithium2 or
  ameAuthBitFalcon512 or ameAuthBitDilithium1 or ameAuthBitDilithium0

private fun hasBit(value: Int, bit: Int): Boolean =
  bit != 0 && (value and bit) == bit

private fun prefixCount(value: Int, order: IntArray): Int {
  var index = 0
  while (index < order.size) {
    if (!hasBit(value, order[index])) return index
    index += 1
  }
  return order.size
}

private fun prefixBits(order: IntArray, count: Int): Int {
  var result = 0
  var index = 0
  while (index < count && index < order.size) {
    result = result or order[index]
    index += 1
  }
  return result
}

private fun kemBitsArePrefix(bits: Int, order: IntArray): Boolean =
  bits == prefixBits(order, prefixCount(bits, order))

private fun keyBitsAreCanonical(keyBits: Int): Boolean {
  if ((keyBits and ameKemAllMask.inv()) != 0) return false
  if (keyBits == 0) return true
  val bandA = keyBits and ameKemMaskA
  if (bandA != 0) return bandA == keyBits && kemBitsArePrefix(bandA, kemOrderA)
  val bandB = keyBits and ameKemMaskB
  if (bandB != 0) return bandB == keyBits && kemBitsArePrefix(bandB, kemOrderB)
  val bandC = keyBits and ameKemMaskC
  if (bandC != 0) return bandC == keyBits && kemBitsArePrefix(bandC, kemOrderC)
  return false
}

private fun cipherMacBitsAreCanonical(symmetricBits: Int, macBits: Int): Boolean {
  if ((symmetricBits and ameCipherAllMask.inv()) != 0) return false
  if ((macBits and ameMacAllMask.inv()) != 0) return false
  if (symmetricBits == 0 || macBits == 0) return symmetricBits == 0 && macBits == 0
  if (symmetricBits == ameCipherTier1) return macBits == ameMacGimliSha3
  if (symmetricBits == ameCipherTier2) return macBits == ameMacGimliSha3
  if (symmetricBits == ameCipherTier3) return macBits == ameMacBitGimli || macBits == ameMacGimliSha3
  return false
}

private fun otpBitsAreCanonical(otpBits: Int): Boolean {
  if ((otpBits and ameOtpAllMask.inv()) != 0) return false
  return otpBits == 0 || otpBits == ameGhostTier1Bits || otpBits == ameGhostTier2Bits || otpBits == ameGhostTier3Bits
}

private fun authBitsAreCanonical(authBits: Int): Boolean {
  if ((authBits and ameAuthAllMask.inv()) != 0) return false
  return authBits == 0 || authBits == ameAuthTier1Bits || authBits == ameAuthTier2Bits ||
    authBits == ameAuthTier3Bits || authBits == ameAuthTier4Bits
}

private fun profileBitsAreCanonical(profile: AmeProfile): Boolean =
  keyBitsAreCanonical(profile.keyBits) &&
    cipherMacBitsAreCanonical(profile.symmetricBits, profile.macBits) &&
    otpBitsAreCanonical(profile.otpBits) &&
    authBitsAreCanonical(profile.authBits)

private fun deriveAsymmetricBand(keyBits: Int): Int =
  when {
    (keyBits and ameKemMaskA) != 0 -> 1
    (keyBits and ameKemMaskB) != 0 -> 2
    else -> 3
  }

private fun deriveAsymmetricTier(keyBits: Int): Int {
  if ((keyBits and ameKemAllMask) == 0) return 0
  val order = when (deriveAsymmetricBand(keyBits)) {
    1 -> kemOrderA
    2 -> kemOrderB
    else -> kemOrderC
  }
  return when (prefixCount(keyBits, order)) {
    0 -> 0
    1 -> 5
    2 -> 4
    3 -> 3
    4 -> 2
    else -> 1
  }
}

private fun deriveSymmetricTier(symmetricBits: Int, macBits: Int): Int =
  when {
    symmetricBits == ameCipherTier1 && macBits == ameMacGimliSha3 -> 1
    symmetricBits == ameCipherTier2 && macBits == ameMacGimliSha3 -> 2
    symmetricBits == ameCipherTier3 && (macBits == ameMacBitGimli || macBits == ameMacGimliSha3) -> 3
    else -> 0
  }

private fun deriveGhostTier(otpBits: Int): Int =
  when (otpBits) {
    ameGhostTier1Bits -> 1
    ameGhostTier2Bits -> 2
    ameGhostTier3Bits -> 3
    else -> 0
  }

private fun deriveVerificationTier(authBits: Int): Int =
  when {
    (authBits and ameAuthTier1Bits) == ameAuthTier1Bits -> 1
    (authBits and ameAuthTier2Bits) == ameAuthTier2Bits -> 2
    (authBits and ameAuthTier3Bits) == ameAuthTier3Bits -> 3
    (authBits and ameAuthTier4Bits) == ameAuthTier4Bits -> 4
    else -> 0
  }

private fun deriveAeadTier(profile: AmeProfile): AmeTier =
  when {
    profile.asymmetricBand == 3 && profile.asymmetricTier == 5 &&
      profile.symmetricTier == 3 && profile.verificationTier == 4 && profile.masterKeyTierId == 5 -> AmeTier.LIGHTWEIGHT
    profile.asymmetricBand == 3 && profile.asymmetricTier == 4 &&
      profile.symmetricTier == 2 && profile.verificationTier == 3 && profile.masterKeyTierId == 4 -> AmeTier.LIGHTWEIGHT_PLUS
    profile.asymmetricBand == 2 && profile.asymmetricTier == 2 &&
      profile.symmetricTier == 1 && profile.verificationTier == 2 && profile.masterKeyTierId == 2 -> AmeTier.MEDIUM_PLUS
    profile.asymmetricBand == 1 && profile.asymmetricTier == 4 &&
      profile.symmetricTier == 1 && profile.verificationTier == 2 && profile.masterKeyTierId == 2 -> AmeTier.HIGH
    profile.asymmetricBand == 1 && profile.asymmetricTier == 1 &&
      profile.symmetricTier == 1 && profile.verificationTier == 1 && profile.masterKeyTierId == 1 -> AmeTier.HIGH_PLUS
    else -> AmeTier.MEDIUM
  }
