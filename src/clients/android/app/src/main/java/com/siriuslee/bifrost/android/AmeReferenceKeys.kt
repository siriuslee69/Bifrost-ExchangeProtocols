package com.siriuslee.bifrost.android

import java.security.MessageDigest
import java.util.Base64

object AmeReferenceKeys {
  fun keyBundle(tier: AmeTier, includeSecret: Boolean, allowSecretExport: Boolean = false): String {
    require(!includeSecret || allowSecretExport) {
      "AME secret bundle export requires explicit debug/provisioning approval"
    }
    val profile = AmeProfile.reference(tier)
    val names = when (tier) {
      AmeTier.LIGHTWEIGHT -> listOf("LightSaber")
      AmeTier.LIGHTWEIGHT_PLUS -> listOf("LightSaber", "NTRU-HPS-2048-509")
      AmeTier.MEDIUM -> listOf("Saber", "NTRU-HPS-2048-677")
      AmeTier.MEDIUM_PLUS -> listOf("Saber", "NTRU-HPS-2048-677", "Kyber768", "FrodoKEM-976-AES")
      AmeTier.HIGH -> listOf("FireSaber", "NTRU-HPS-4096-821")
      AmeTier.HIGH_PLUS -> listOf("FireSaber", "NTRU-HPS-4096-821", "Kyber1024", "FrodoKEM-1344-AES", "Classic-McEliece-8192128f")
    }
    val out = StringBuilder()
    out.append("tier=").append(tier.label).append('\n')
    out.append("profile=").append(profile.summary).append(' ').append(profile.bitsSummary).append('\n')
    for (name in names) {
      val publicKey = pseudoKey("public:${tier.label}:$name")
      val secretKey = pseudoKey("secret:${tier.label}:$name")
      out.append("kem=").append(name).append('\n')
      out.append("public.len=").append(publicKey.size).append('\n')
      out.append("public=").append(encode(publicKey)).append('\n')
      if (includeSecret) {
        out.append("secret.len=").append(secretKey.size).append('\n')
        out.append("secret=").append(encode(secretKey)).append('\n')
      }
      out.append('\n')
    }
    return out.toString()
  }

  private fun pseudoKey(seed: String): ByteArray =
    MessageDigest.getInstance("SHA-256").digest(seed.toByteArray()).copyOf(32)

  private fun encode(bytes: ByteArray): String =
    Base64.getEncoder().encodeToString(bytes)
}
