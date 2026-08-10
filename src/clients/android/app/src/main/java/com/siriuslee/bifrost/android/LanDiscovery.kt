package com.siriuslee.bifrost.android

import android.content.Context
import android.content.pm.ApplicationInfo
import android.net.wifi.WifiManager
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class LanDiscovery(
  private val context: Context,
  private val local: LocalNode,
  private val tierProvider: () -> AmeTier,
  private val publicKeyProvider: () -> String,
  private val onPeer: (PeerEndpoint) -> Unit,
  private val onLog: (BifrostLogEntry) -> Unit,
) {
  private val running = AtomicBoolean(false)
  private var socket: DatagramSocket? = null
  private var scheduler: ScheduledExecutorService? = null
  private var multicastLock: WifiManager.MulticastLock? = null

  fun start() {
    if (!running.compareAndSet(false, true)) return
    scheduler = Executors.newScheduledThreadPool(2)
    acquireMulticastLock()
    startReceiver()
    scheduler?.scheduleWithFixedDelay({ sendBeacon() }, 0, 2, TimeUnit.SECONDS)
  }

  fun stop() {
    running.set(false)
    socket?.close()
    socket = null
    scheduler?.shutdownNow()
    scheduler = null
    multicastLock?.release()
    multicastLock = null
  }

  private fun startReceiver() {
    scheduler?.execute {
      try {
        val sock = DatagramSocket(null)
        sock.reuseAddress = true
        sock.broadcast = true
        sock.soTimeout = 1200
        sock.bind(InetSocketAddress(BifrostPorts.DISCOVERY))
        socket = sock
        onLog(info("discovery listening :${BifrostPorts.DISCOVERY}"))
        receiveLoop(sock)
      } catch (t: Throwable) {
        onLog(error("discovery failed: ${t.message ?: t.javaClass.simpleName}"))
      }
    }
  }

  private fun receiveLoop(sock: DatagramSocket) {
    val buf = ByteArray(2048)
    while (running.get()) {
      try {
        val packet = DatagramPacket(buf, buf.size)
        sock.receive(packet)
        val text = String(packet.data, packet.offset, packet.length, StandardCharsets.UTF_8)
        val peer = decodeBeacon(text, packet.address.hostAddress ?: "")
        if (peer != null && peer.nodeId != local.nodeId) onPeer(peer)
      } catch (_: java.net.SocketTimeoutException) {
      } catch (_: java.net.SocketException) {
        if (running.get()) onLog(error("discovery socket closed"))
      } catch (t: Throwable) {
        if (running.get()) onLog(error("discovery packet rejected: ${t.message ?: t.javaClass.simpleName}"))
      }
    }
  }

  private fun sendBeacon() {
    if (!running.get()) return
    val sock = socket ?: return
    val payload = encodeBeacon().toByteArray(StandardCharsets.UTF_8)
    for (address in broadcastAddresses()) {
      try {
        sock.send(DatagramPacket(payload, payload.size, address, BifrostPorts.DISCOVERY))
      } catch (t: Throwable) {
        onLog(error("beacon send failed ${address.hostAddress}: ${t.message ?: t.javaClass.simpleName}"))
      }
    }
  }

  private fun encodeBeacon(): String {
    val name = Base64.getUrlEncoder().withoutPadding()
      .encodeToString(local.displayName.toByteArray(StandardCharsets.UTF_8))
    val tier = tierProvider()
    val tlsPort = if (TlsTools.isProvisioned(context)) BifrostPorts.TLS else 0
    val dacPort = if (demoSecurityEnabled()) BifrostPorts.DAC else 0
    return listOf(
      "BIFROST-LAN",
      "5",
      local.nodeId,
      name,
      BifrostPorts.TCP.toString(),
      tlsPort.toString(),
      BifrostPorts.UDP.toString(),
      System.currentTimeMillis().toString(),
      tier.id.toString(),
      publicKeyProvider(),
      dacPort.toString(),
    ).joinToString("|")
  }

  private fun decodeBeacon(text: String, host: String): PeerEndpoint? {
    val parts = text.trim().split("|")
    if (parts.size < 9 || parts[0] != "BIFROST-LAN") return null
    val version = parts[1]
    if (version != "2" && version != "3" && version != "4" && version != "5") return null
    val dacOnly = version == "5"
    val tierIndex = if (dacOnly) 8 else 9
    val publicKeyIndex = if (dacOnly) 9 else 10
    val dacPortIndex = if (dacOnly) 10 else 11
    val name = String(Base64.getUrlDecoder().decode(parts[3]), StandardCharsets.UTF_8)
    return PeerEndpoint(
      nodeId = parts[2],
      displayName = name,
      host = host,
      tcpPort = parts[4].toIntOrNull() ?: BifrostPorts.TCP,
      tlsPort = parts[5].toIntOrNull() ?: BifrostPorts.TLS,
      udpPort = parts[6].toIntOrNull() ?: BifrostPorts.UDP,
      dacPort = parts.getOrNull(dacPortIndex)?.toIntOrNull() ?: BifrostPorts.DAC,
      ameTierId = parts.getOrNull(tierIndex)?.toIntOrNull() ?: AmeTier.MEDIUM.id,
      amePublicKey = decodeAmePublicBeacon(parts.getOrNull(publicKeyIndex).orEmpty()),
      lastSeenMillis = System.currentTimeMillis(),
    )
  }

  private fun broadcastAddresses(): List<InetAddress> {
    val addresses = linkedSetOf<InetAddress>()
    try {
      val interfaces = NetworkInterface.getNetworkInterfaces()
      while (interfaces.hasMoreElements()) {
        val iface = interfaces.nextElement()
        if (!iface.isUp || iface.isLoopback) continue
        for (ifaceAddress in iface.interfaceAddresses) {
          val broadcast = ifaceAddress.broadcast
          if (broadcast != null) addresses.add(broadcast)
        }
      }
    } catch (t: Throwable) {
      onLog(error("broadcast scan failed: ${t.message ?: t.javaClass.simpleName}"))
    }
    addresses.add(InetAddress.getByName("255.255.255.255"))
    return addresses.toList()
  }

  private fun acquireMulticastLock() {
    val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
    multicastLock = wifi?.createMulticastLock("bifrost-lan-discovery")?.apply {
      setReferenceCounted(false)
      acquire()
    }
  }

  private fun demoSecurityEnabled(): Boolean =
    (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

  private fun info(message: String): BifrostLogEntry =
    BifrostLogEntry(System.currentTimeMillis(), ProtocolKind.DISCOVERY, LogDirection.INFO, "local", message)

  private fun error(message: String): BifrostLogEntry =
    BifrostLogEntry(System.currentTimeMillis(), ProtocolKind.DISCOVERY, LogDirection.ERROR, "local", message)
}
