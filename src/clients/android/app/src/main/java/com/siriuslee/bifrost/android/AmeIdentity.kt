package com.siriuslee.bifrost.android

import android.content.Context
import java.security.MessageDigest
import java.util.Base64

data class AmeKeyMaterial(
  val tier: AmeTier,
  val publicKeyText: String,
  val secretKeyText: String,
) {
  val publicDescriptor: AmePublicKeyDescriptor
    get() = describeAmePublicKey(publicKeyText)

  val publicSummary: String
    get() = summarizeKeyText(publicKeyText, revealPreview = true)

  val secretSummary: String
    get() = summarizeKeyText(secretKeyText, revealPreview = false)

  val publicBeaconText: String
    get() = publicDescriptor.beaconText
}

data class AmePublicKemDescriptor(
  val name: String,
  val publicLen: Int,
)

data class AmePublicKeyDescriptor(
  val tier: String,
  val profile: String,
  val kems: List<AmePublicKemDescriptor>,
  val fingerprint: String,
  val bundleLength: Int,
) {
  val displayText: String
    get() {
      val tierText = tier.ifBlank { "-" }
      val kemText = if (kems.isEmpty()) {
        "-"
      } else {
        kems.joinToString(",") { "${it.name}:${it.publicLen}" }
      }
      return "sha256:$fingerprint len=$bundleLength tier=$tierText kems=$kemText"
    }

  val shortText: String
    get() = "sha256:${fingerprint.take(12)} kems=${kems.size}"

  val beaconText: String
    get() = encodeAmePublicBeacon(this)
}

object AmeIdentity {
  private const val prefsName = "bifrost-ame-identity"

  fun load(context: Context, tier: AmeTier): AmeKeyMaterial {
    val prefs = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
    val publicKeyName = "public-${tier.id}"
    val secretKeyName = "secret-${tier.id}"
    var publicKey = prefs.getString(publicKeyName, null)
    var secretKey = AmeSecretStore.load(prefs, secretKeyName)
    val legacySecretKey = prefs.getString(secretKeyName, null)
    if (secretKey.isNullOrBlank() && !legacySecretKey.isNullOrBlank()) {
      secretKey = legacySecretKey
      AmeSecretStore.store(prefs, secretKeyName, secretKey)
    }
    if (publicKey.isNullOrBlank()) {
      publicKey = publicOnly(NativeAme.keyBundleForTier(tier, includeSecret = false))
      prefs.edit()
        .putString(publicKeyName, publicKey)
        .apply()
    }
    if (secretKey.isNullOrBlank() && BuildConfig.DEBUG) {
      val provisioningBundle = NativeAme.keyBundleForTier(tier,
        includeSecret = true, allowSecretExport = true)
      secretKey = secretOnly(provisioningBundle)
      AmeSecretStore.store(prefs, secretKeyName, secretKey)
    }
    return AmeKeyMaterial(tier = tier,
      publicKeyText = publicKey.orEmpty(), secretKeyText = secretKey.orEmpty())
  }
}

fun summarizeKeyText(text: String, revealPreview: Boolean): String {
  val clean = text.trim()
  if (clean.isEmpty()) return "-"
  val digest = MessageDigest.getInstance("SHA-256").digest(clean.toByteArray(Charsets.UTF_8))
  val hash = digest.joinToString("") { "%02x".format(it) }.take(24)
  if (!revealPreview) return "sha256:$hash len=${clean.length} redacted"
  val compact = clean.replace("\n", " ")
  val preview = if (compact.length <= 96) compact else compact.take(56) + "..." + compact.takeLast(24)
  return "sha256:$hash len=${clean.length} $preview"
}

fun describeAmePublicKey(text: String): AmePublicKeyDescriptor {
  val clean = sanitizeAmePublicBundle(text)
  val lines = clean.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }
  var tier = ""
  var profile = ""
  var currentKem = ""
  var currentPublicLen = -1
  val kems = mutableListOf<AmePublicKemDescriptor>()
  for (line in lines) {
    when {
      line.startsWith("tier=") -> tier = line.removePrefix("tier=").trim()
      line.startsWith("profile=") -> profile = line.removePrefix("profile=").trim()
      line.startsWith("kem=") -> {
        appendKemDescriptor(kems, currentKem, currentPublicLen)
        currentKem = line.removePrefix("kem=").trim()
        currentPublicLen = -1
      }
      line.startsWith("public.len=") -> {
        currentPublicLen = line.removePrefix("public.len=").trim().toIntOrNull() ?: -1
      }
      line.startsWith("public=") && currentPublicLen < 0 -> {
        currentPublicLen = decodedBase64Length(line.removePrefix("public=").trim())
      }
    }
  }
  appendKemDescriptor(kems, currentKem, currentPublicLen)
  return AmePublicKeyDescriptor(
    tier = tier,
    profile = profile,
    kems = kems.toList(),
    fingerprint = sha256Prefix(clean, 24),
    bundleLength = clean.length,
  )
}

fun sanitizeAmePublicBundle(text: String): String {
  val clean = text.replace("\r\n", "\n").replace('\r', '\n').trim()
  require(clean.lineSequence().none { it.trimStart().startsWith("secret") }) {
    "AME public bundle contains secret material"
  }
  return clean
}

fun decodeAmePublicBeacon(text: String): String {
  val clean = text.trim()
  if (!clean.startsWith("ame1:")) return clean
  val payload = String(Base64.getUrlDecoder().decode(clean.removePrefix("ame1:")), Charsets.UTF_8)
  require(!payload.contains("secret", ignoreCase = true)) { "AME beacon contains secret material" }
  val fields = payload.split(";")
    .mapNotNull {
      val split = it.indexOf('=')
      if (split <= 0) null else it.take(split) to it.drop(split + 1)
    }
    .toMap()
  val fingerprint = fields["fp"].orEmpty()
  val bundleLength = fields["len"]?.toIntOrNull() ?: 0
  val tier = decodeUrlText(fields["tier"].orEmpty())
  val profile = decodeUrlText(fields["profile"].orEmpty())
  val kems = fields["kems"].orEmpty()
    .split(",")
    .filter { it.isNotBlank() }
    .map {
      val split = it.lastIndexOf(':')
      val name = if (split <= 0) it else it.take(split)
      val length = if (split <= 0) -1 else it.drop(split + 1).toIntOrNull() ?: -1
      AmePublicKemDescriptor(decodeUrlText(name), length)
    }
  return AmePublicKeyDescriptor(tier, profile, kems, fingerprint, bundleLength).displayText
}

fun shortAmePublicDisplay(text: String): String {
  val clean = text.trim()
  if (clean.isEmpty()) return "-"
  val decoded = decodeAmePublicBeacon(clean)
  if (decoded.startsWith("sha256:")) {
    val fingerprint = decoded.removePrefix("sha256:").takeWhile { it != ' ' }
    return "sha256:${fingerprint.take(12)}"
  }
  return decoded.take(12)
}

private fun encodeAmePublicBeacon(descriptor: AmePublicKeyDescriptor): String {
  val kems = descriptor.kems.joinToString(",") {
    "${encodeUrlText(it.name)}:${it.publicLen}"
  }
  val payload = listOf(
    "fp=${descriptor.fingerprint}",
    "len=${descriptor.bundleLength}",
    "tier=${encodeUrlText(descriptor.tier)}",
    "profile=${encodeUrlText(descriptor.profile)}",
    "kems=$kems",
  ).joinToString(";")
  return "ame1:${Base64.getUrlEncoder().withoutPadding().encodeToString(payload.toByteArray(Charsets.UTF_8))}"
}

private fun appendKemDescriptor(
  kems: MutableList<AmePublicKemDescriptor>,
  name: String,
  publicLen: Int,
) {
  if (name.isBlank()) return
  kems.add(AmePublicKemDescriptor(name, publicLen.coerceAtLeast(0)))
}

private fun decodedBase64Length(text: String): Int =
  try {
    Base64.getDecoder().decode(text).size
  } catch (_: IllegalArgumentException) {
    -1
  }

private fun sha256Prefix(text: String, count: Int): String =
  MessageDigest.getInstance("SHA-256")
    .digest(text.toByteArray(Charsets.UTF_8))
    .joinToString("") { "%02x".format(it) }
    .take(count)

private fun encodeUrlText(text: String): String =
  Base64.getUrlEncoder().withoutPadding().encodeToString(text.toByteArray(Charsets.UTF_8))

private fun decodeUrlText(text: String): String =
  if (text.isBlank()) {
    ""
  } else {
    String(Base64.getUrlDecoder().decode(text), Charsets.UTF_8)
  }

private fun publicOnly(bundle: String): String =
  sanitizeAmePublicBundle(bundle.lineSequence()
    .filter { !it.trimStart().startsWith("secret") }
    .joinToString("\n")
    .trim())

private fun secretOnly(bundle: String): String =
  bundle.lineSequence()
    .filter { it.startsWith("tier=") || it.startsWith("profile=") || it.startsWith("kem=") || it.startsWith("secret") }
    .joinToString("\n")
    .trim()
