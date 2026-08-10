package com.siriuslee.bifrost.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AmeIdentityTest {
  @Test
  fun secretSummariesDoNotRevealSecretPreview() {
    val secretText = "tier=HighPlus\nsecret=super-sensitive-material"
    val publicText = "tier=HighPlus\npublic=shareable-material"
    val secretSummary = summarizeKeyText(secretText, revealPreview = false)
    val publicSummary = summarizeKeyText(publicText, revealPreview = true)

    assertTrue(secretSummary.contains("redacted"))
    assertFalse(secretSummary.contains("super-sensitive-material"))
    assertTrue(publicSummary.contains("shareable-material"))
  }

  @Test
  fun publicDescriptorsExposeKemShapeWithoutSecretMaterial() {
    val publicText = """
      tier=MediumPlus
      profile=AME MediumPlus key=256
      kem=Saber
      public.len=992
      public=c2hhcmVhYmxl

      kem=Kyber768
      public.len=1184
      public=bWF0ZXJpYWw=
    """.trimIndent()
    val descriptor = describeAmePublicKey(publicText)

    assertEquals("MediumPlus", descriptor.tier)
    assertEquals(2, descriptor.kems.size)
    assertEquals("Saber", descriptor.kems[0].name)
    assertEquals(992, descriptor.kems[0].publicLen)
    assertTrue(descriptor.displayText.contains("kems=Saber:992,Kyber768:1184"))
    assertFalse(descriptor.displayText.contains("shareable"))
  }

  @Test
  fun publicBeaconRoundTripUsesCompactPublicDescriptor() {
    val publicText = """
      tier=High
      profile=AME High key=512
      kem=FireSaber
      public.len=1312
      public=cHVibGljLW9ubHk=
    """.trimIndent()
    val descriptor = describeAmePublicKey(publicText)
    val decoded = decodeAmePublicBeacon(descriptor.beaconText)

    assertFalse(descriptor.beaconText.contains("|"))
    assertFalse(descriptor.beaconText.contains("\n"))
    assertTrue(decoded.contains("tier=High"))
    assertTrue(decoded.contains("kems=FireSaber:1312"))
  }

  @Test
  fun publicDescriptorsRejectSecretLines() {
    var failed = false
    try {
      describeAmePublicKey("tier=Medium\nkem=Saber\npublic=ok\nsecret=not-ok")
    } catch (_: IllegalArgumentException) {
      failed = true
    }

    assertTrue(failed)
  }

  @Test
  fun secretBundleExportRequiresExplicitApproval() {
    var failed = false
    val publicBundle = AmeReferenceKeys.keyBundle(AmeTier.MEDIUM, includeSecret = false)

    try {
      AmeReferenceKeys.keyBundle(AmeTier.MEDIUM, includeSecret = true)
    } catch (_: IllegalArgumentException) {
      failed = true
    }

    assertTrue(failed)
    assertFalse(publicBundle.contains("secret="))
    assertTrue(AmeReferenceKeys.keyBundle(AmeTier.MEDIUM,
      includeSecret = true, allowSecretExport = true).contains("secret="))
  }
}
