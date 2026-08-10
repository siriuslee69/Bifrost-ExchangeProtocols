package com.siriuslee.bifrost.android

import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object AmeSecretStore {
  private const val androidKeyStore = "AndroidKeyStore"
  private const val keyAlias = "bifrost-ame-secret-v1"
  private const val transform = "AES/GCM/NoPadding"
  private const val gcmTagBits = 128

  fun load(prefs: SharedPreferences, name: String): String? {
    val ciphertextText = prefs.getString(ciphertextName(name), null) ?: return null
    val ivText = prefs.getString(ivName(name), null) ?: return null
    val ciphertext = Base64.getDecoder().decode(ciphertextText)
    val iv = Base64.getDecoder().decode(ivText)
    val cipher = Cipher.getInstance(transform)
    cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(gcmTagBits, iv))
    return String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8)
  }

  fun store(prefs: SharedPreferences, name: String, value: String) {
    val cipher = Cipher.getInstance(transform)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey())
    val ciphertext = cipher.doFinal(value.toByteArray(StandardCharsets.UTF_8))
    prefs.edit()
      .putString(ciphertextName(name), Base64.getEncoder().encodeToString(ciphertext))
      .putString(ivName(name), Base64.getEncoder().encodeToString(cipher.iv))
      .remove(name)
      .apply()
  }

  private fun secretKey(): SecretKey {
    val keyStore = KeyStore.getInstance(androidKeyStore)
    keyStore.load(null)
    val existing = keyStore.getKey(keyAlias, null)
    if (existing is SecretKey) return existing

    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, androidKeyStore)
    val spec = KeyGenParameterSpec.Builder(
      keyAlias,
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
    )
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setRandomizedEncryptionRequired(true)
      .build()
    generator.init(spec)
    return generator.generateKey()
  }

  private fun ciphertextName(name: String): String =
    "$name.ciphertext"

  private fun ivName(name: String): String =
    "$name.iv"
}
