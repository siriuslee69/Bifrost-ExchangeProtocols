package com.siriuslee.bifrost.android

import android.content.Context
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.net.ServerSocketFactory
import javax.net.SocketFactory
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory

object TlsTools {
  private const val identityFileName = "bifrost_tls_identity.p12"
  private const val passwordFileName = "bifrost_tls_password.txt"
  private const val externalTlsDirName = "tls"

  fun serverSocketFactory(context: Context): ServerSocketFactory =
    context(context).serverSocketFactory

  fun socketFactory(context: Context): SocketFactory =
    context(context).socketFactory

  fun isProvisioned(context: Context): Boolean =
    resolveIdentityFile(context) != null && resolvePasswordFile(context) != null

  fun provisioningSummary(context: Context): String =
    if (isProvisioned(context)) {
      "TLS identity provisioned"
    } else {
      "TLS disabled until $identityFileName and $passwordFileName are provisioned"
    }

  fun configureServer(socket: SSLServerSocket): SSLServerSocket {
    socket.enabledProtocols = socket.supportedProtocols.filter { it == "TLSv1.3" || it == "TLSv1.2" }.toTypedArray()
    socket.needClientAuth = false
    return socket
  }

  fun configureClient(socket: SSLSocket): SSLSocket {
    socket.enabledProtocols = socket.supportedProtocols.filter { it == "TLSv1.3" || it == "TLSv1.2" }.toTypedArray()
    return socket
  }

  private fun internalIdentityFile(context: Context): File =
    File(context.filesDir, identityFileName)

  private fun internalPasswordFile(context: Context): File =
    File(context.filesDir, passwordFileName)

  private fun externalTlsDir(context: Context): File? =
    context.getExternalFilesDir(externalTlsDirName)

  private fun externalIdentityFile(context: Context): File? =
    externalTlsDir(context)?.let { File(it, identityFileName) }

  private fun externalPasswordFile(context: Context): File? =
    externalTlsDir(context)?.let { File(it, passwordFileName) }

  private fun resolveProvisionedFile(primary: File, secondary: File?): File? {
    if (primary.isFile) return primary
    if (secondary != null && secondary.isFile) return secondary
    return null
  }

  private fun resolveIdentityFile(context: Context): File? =
    resolveProvisionedFile(internalIdentityFile(context), externalIdentityFile(context))

  private fun resolvePasswordFile(context: Context): File? =
    resolveProvisionedFile(internalPasswordFile(context), externalPasswordFile(context))

  private fun requiredProvisionedFile(file: File?, kind: String): File {
    require(file != null) {
      "TLS $kind file is missing. Provision $identityFileName and $passwordFileName before enabling TLS."
    }
    return file
  }

  private fun provisionedPassword(context: Context): CharArray {
    val passwordFile = requiredProvisionedFile(resolvePasswordFile(context), "password")
    val password = passwordFile.readText(Charsets.UTF_8).trim()
    require(password.isNotEmpty()) {
      "TLS password file is empty"
    }
    return password.toCharArray()
  }

  private fun context(context: Context): SSLContext {
    val identityFile = requiredProvisionedFile(resolveIdentityFile(context), "identity")
    val password = provisionedPassword(context)
    val keyStore = KeyStore.getInstance("PKCS12")
    identityFile.inputStream().use { keyStore.load(it, password) }
    val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
    kmf.init(keyStore, password)
    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    tmf.init(keyStore)
    val ctx = SSLContext.getInstance("TLS")
    ctx.init(kmf.keyManagers, tmf.trustManagers, SecureRandom())
    return ctx
  }
}
