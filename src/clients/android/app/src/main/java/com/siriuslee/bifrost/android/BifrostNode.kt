package com.siriuslee.bifrost.android

import android.content.Context
import android.content.pm.ApplicationInfo
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlin.random.Random

internal data class AmeDacSession(
  val peerName: String,
  val tier: AmeTier,
  val seed: ByteArray,
  val rootLaneId: Long,
  val remote: AmeDacPeer,
  val createdAtMillis: Long,
)

private data class AmeDacRootAck(
  val message: BifrostMessage,
  val rootLaneId: Long,
)

internal class BifrostNodeRuntimeState {
  @Volatile
  private var io: ExecutorService = Executors.newCachedThreadPool()

  val ameDacSessions = ConcurrentHashMap<Long, AmeDacSession>()
  val completedAmeDacSessions = ConcurrentHashMap<Long, Long>()

  @Synchronized
  fun executor(): ExecutorService {
    if (io.isShutdown || io.isTerminated) {
      io = Executors.newCachedThreadPool()
    }
    return io
  }

  @Synchronized
  fun stop() {
    ameDacSessions.clear()
    completedAmeDacSessions.clear()
    io.shutdownNow()
  }

  fun pruneExpiredAmeDacSessions(nowMillis: Long, maxAgeMillis: Long) {
    for ((sessionId, session) in ameDacSessions.entries) {
      if (nowMillis - session.createdAtMillis >= maxAgeMillis) {
        ameDacSessions.remove(sessionId, session)
      }
    }
    for ((sessionId, completedAtMillis) in completedAmeDacSessions.entries) {
      if (nowMillis - completedAtMillis >= maxAgeMillis) {
        completedAmeDacSessions.remove(sessionId, completedAtMillis)
      }
    }
  }

  fun consumeAmeDacSession(sessionId: Long, session: AmeDacSession): Boolean =
    ameDacSessions.remove(sessionId, session)

  fun markAmeDacSessionCompleted(sessionId: Long, completedAtMillis: Long) {
    completedAmeDacSessions[sessionId] = completedAtMillis
  }

  fun isAmeDacSessionCompleted(sessionId: Long): Boolean =
    completedAmeDacSessions.containsKey(sessionId)
}

class BifrostNode(
  private val context: Context,
  private val listener: Listener,
) {
  interface Listener {
    fun onPeer(peer: PeerEndpoint)
    fun onLog(entry: BifrostLogEntry)
  }

  val local: LocalNode = NodeIdentity.load(context)
  val logFile: File = File(context.filesDir, "bifrost-lan.log")

  private val running = AtomicBoolean(false)
  private val sequence = AtomicLong(1)
  private val ameTier = AtomicReference(loadAmeTier())
  private val autoAmeUpgradeEnabled = AtomicBoolean(loadAutoAmeUpgrade())
  private val peers = ConcurrentHashMap<String, PeerEndpoint>()
  private val runtimeState = BifrostNodeRuntimeState()
  private var discovery: LanDiscovery? = null
  private var tcpServer: ServerSocket? = null
  private var tlsServer: SSLServerSocket? = null
  private var udpSocket: DatagramSocket? = null
  private var dacSocket: DatagramSocket? = null

  private companion object {
    const val ameRootLaneId = 0L
    const val ameLaneId = 5
    const val ameRootRequestSequence = 1L
    const val ameRootAckSequence = 2L
    const val ameLaneDataSequence = 3L
    const val ameLaneAckSequence = 4L
    const val dacRootRequestSequence = 0L
    const val dacRootAckSequence = 1L
    const val dacLaneDataSequence = 2L
    const val dacLaneAckSequence = 3L
    const val ameDacSessionTtlMillis = 15_000L
    const val dacMaxFrameBytes = 64 * 1024
  }

  fun start() {
    if (!running.compareAndSet(false, true)) return
    emit(ProtocolKind.SYSTEM, LogDirection.INFO, "local", "node ${local.displayName}")
    emit(ProtocolKind.AME, LogDirection.INFO, "local", "native nim bridge ${if (NativeAme.loaded) "loaded" else "missing"}")
    emit(ProtocolKind.AME, LogDirection.INFO, "local", "tier ${ameProfile().summary}")
    emit(ProtocolKind.AME, LogDirection.INFO, "local", "auto ${if (autoAmeUpgrade()) "on" else "off"}")
    emit(ProtocolKind.AME, LogDirection.INFO, "local", "public ${ameKeyMaterial().publicDescriptor.displayText}")
    emit(ProtocolKind.TLS, LogDirection.INFO, "local", TlsTools.provisioningSummary(context))
    if (demoSecurityEnabled()) {
      emit(ProtocolKind.SYSTEM, LogDirection.INFO, "local", "debug demo security helpers enabled for Android LAN harness")
    }
    startUdpServer()
    startTcpServer()
    startTlsServer()
    startDacServer()
    discovery = LanDiscovery(context, local, ::selectedAmeTier, { ameKeyMaterial().publicBeaconText }, ::upsertPeer, ::emit)
    discovery?.start()
  }

  fun stop() {
    running.set(false)
    discovery?.stop()
    discovery = null
    closeQuietly(tcpServer)
    tcpServer = null
    closeQuietly(tlsServer)
    tlsServer = null
    udpSocket?.close()
    udpSocket = null
    dacSocket?.close()
    dacSocket = null
    runtimeState.stop()
  }

  fun addManualPeer(host: String): PeerEndpoint {
    val clean = host.trim()
    require(clean.isNotEmpty()) { "host is empty" }
    val peer = PeerEndpoint(
      nodeId = "manual-$clean",
      displayName = clean,
      host = clean,
      lastSeenMillis = System.currentTimeMillis(),
    )
    upsertPeer(peer)
    emit(ProtocolKind.SYSTEM, LogDirection.INFO, clean, "manual peer")
    return peer
  }

  fun send(protocol: ProtocolKind, peer: PeerEndpoint, body: String) {
    if (!running.get()) {
      emit(ProtocolKind.SYSTEM, LogDirection.ERROR, peer.displayName, "node is not running")
      return
    }
    when (protocol) {
      ProtocolKind.TCP -> submitIo { sendTcp(peer, body) }
      ProtocolKind.TLS -> submitIo { sendTls(peer, body) }
      ProtocolKind.UDP -> submitIo { sendUdp(peer, body) }
      ProtocolKind.AME -> submitIo { sendAme(peer, body) }
      else -> emit(ProtocolKind.SYSTEM, LogDirection.ERROR, peer.displayName, "unsupported send protocol")
    }
  }

  fun selectedAmeTier(): AmeTier =
    ameTier.get()

  fun ameProfile(): AmeProfile =
    NativeAme.profileForTier(selectedAmeTier())

  fun ameKeyMaterial(): AmeKeyMaterial =
    AmeIdentity.load(context, selectedAmeTier())

  fun autoAmeUpgrade(): Boolean =
    autoAmeUpgradeEnabled.get()

  fun setAutoAmeUpgrade(enabled: Boolean) {
    val previous = autoAmeUpgradeEnabled.getAndSet(enabled)
    if (previous == enabled) return
    statePrefs()
      .edit()
      .putBoolean("autoUpgrade", enabled)
      .apply()
    emit(ProtocolKind.AME, LogDirection.INFO, "local", "auto ${if (enabled) "on" else "off"}")
  }

  fun setAmeTier(tier: AmeTier) {
    applyAmeTier(tier, "manual", "local")
  }

  private fun applyAmeTier(tier: AmeTier, reason: String, peer: String): Boolean {
    val previous = ameTier.getAndSet(tier)
    if (previous == tier) return false
    statePrefs()
      .edit()
      .putInt("tier", tier.id)
      .apply()
    emit(ProtocolKind.AME, LogDirection.INFO, peer, "$reason ${previous.label}->${tier.label} ${ameProfile().summary}")
    emit(ProtocolKind.AME, LogDirection.INFO, "local", "public ${ameKeyMaterial().publicDescriptor.displayText}")
    return true
  }

  fun localAddressSummary(): String {
    val addresses = mutableListOf<String>()
    try {
      val interfaces = java.net.NetworkInterface.getNetworkInterfaces()
      while (interfaces.hasMoreElements()) {
        val iface = interfaces.nextElement()
        if (!iface.isUp || iface.isLoopback) continue
        val inetAddresses = iface.inetAddresses
        while (inetAddresses.hasMoreElements()) {
          val address = inetAddresses.nextElement()
          val host = address.hostAddress
          if (!address.isLoopbackAddress && host != null) {
            addresses.add(host)
          }
        }
      }
    } catch (_: Throwable) {
    }
    return if (addresses.isEmpty()) "no LAN address" else addresses.joinToString("  ")
  }

  private fun upsertPeer(peer: PeerEndpoint) {
    val previous = peers.put(peer.nodeId, peer)
    listener.onPeer(peer)
    if (previous == null || previous.host != peer.host) {
      emit(ProtocolKind.DISCOVERY, LogDirection.INFO, peer.displayName, "${peer.host} ${peer.shortId} ${peer.ameTier.label} ${peer.shortAmePublicKey}")
    }
  }

  private fun demoSecurityEnabled(): Boolean =
    (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

  private fun startTcpServer() {
    submitIo {
      try {
        val server = ServerSocket()
        server.reuseAddress = true
        server.bind(InetSocketAddress(BifrostPorts.TCP))
        tcpServer = server
        emit(ProtocolKind.TCP, LogDirection.INFO, "local", "listen :${BifrostPorts.TCP}")
        acceptLoop(server, ProtocolKind.TCP)
      } catch (t: Throwable) {
        emit(ProtocolKind.TCP, LogDirection.ERROR, "local", t.message ?: t.javaClass.simpleName)
      }
    }
  }

  private fun startTlsServer() {
    if (!TlsTools.isProvisioned(context)) {
      emit(ProtocolKind.TLS, LogDirection.INFO, "local", TlsTools.provisioningSummary(context))
      return
    }
    submitIo {
      try {
        val server = TlsTools.serverSocketFactory(context).createServerSocket(BifrostPorts.TLS) as SSLServerSocket
        TlsTools.configureServer(server)
        tlsServer = server
        emit(ProtocolKind.TLS, LogDirection.INFO, "local", "listen :${BifrostPorts.TLS}")
        acceptLoop(server, ProtocolKind.TLS)
      } catch (t: Throwable) {
        emit(ProtocolKind.TLS, LogDirection.ERROR, "local", t.message ?: t.javaClass.simpleName)
      }
    }
  }

  private fun startUdpServer() {
    submitIo {
      try {
        val sock = DatagramSocket(null)
        sock.reuseAddress = true
        sock.soTimeout = 1200
        sock.bind(InetSocketAddress(BifrostPorts.UDP))
        udpSocket = sock
        emit(ProtocolKind.UDP, LogDirection.INFO, "local", "listen :${BifrostPorts.UDP}")
        receiveUdpLoop(sock)
      } catch (t: Throwable) {
        emit(ProtocolKind.UDP, LogDirection.ERROR, "local", t.message ?: t.javaClass.simpleName)
      }
    }
  }

  private fun startDacServer() {
    if (!demoSecurityEnabled()) {
      emit(ProtocolKind.AME, LogDirection.INFO, "local", "debug-only demo AME/DAC/DAC listener disabled in release")
      return
    }
    if (!NativeAme.loaded) {
      emit(ProtocolKind.AME, LogDirection.ERROR, "local", "native bridge missing; AME/DAC/DAC listener disabled")
      return
    }
    submitIo {
      try {
        val sock = DatagramSocket(null)
        sock.reuseAddress = true
        sock.soTimeout = 1200
        sock.bind(InetSocketAddress(BifrostPorts.DAC))
        dacSocket = sock
        emit(ProtocolKind.AME, LogDirection.INFO, "local", "DAC listen :${BifrostPorts.DAC}")
        receiveDacLoop(sock)
      } catch (t: Throwable) {
        emit(ProtocolKind.AME, LogDirection.ERROR, "local", t.message ?: t.javaClass.simpleName)
      }
    }
  }

  private fun acceptLoop(server: ServerSocket, protocol: ProtocolKind) {
    while (running.get()) {
      try {
        val socket = server.accept()
        submitIo { handleStreamSocket(socket, protocol) }
      } catch (_: SocketException) {
        if (running.get()) emit(protocol, LogDirection.ERROR, "local", "server socket closed")
      } catch (t: Throwable) {
        if (running.get()) emit(protocol, LogDirection.ERROR, "local", t.message ?: t.javaClass.simpleName)
      }
    }
  }

  private fun receiveUdpLoop(sock: DatagramSocket) {
    val buf = ByteArray(64 * 1024)
    while (running.get()) {
      try {
        val packet = DatagramPacket(buf, buf.size)
        sock.receive(packet)
        val payload = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
        val message = BifrostWire.decodeMessage(payload)
        requireTransportMessageProtocol(message, ProtocolKind.UDP, "UDP datagram")
        val remote = packet.address.hostAddress ?: "udp-peer"
        emit(ProtocolKind.UDP, LogDirection.IN, message.senderName, message.body)
        if (!message.isAck) {
          val ack = BifrostWire.encodeMessage(BifrostWire.ackFor(local, message, sequence.getAndIncrement()))
          sock.send(DatagramPacket(ack, ack.size, packet.address, BifrostPorts.UDP))
          emit(ProtocolKind.UDP, LogDirection.OUT, remote, "ack #${message.sequence}")
        }
      } catch (_: SocketTimeoutException) {
      } catch (_: SocketException) {
        if (running.get()) emit(ProtocolKind.UDP, LogDirection.ERROR, "local", "udp socket closed")
      } catch (t: Throwable) {
        if (running.get()) emit(ProtocolKind.UDP, LogDirection.ERROR, "local", t.message ?: t.javaClass.simpleName)
      }
    }
  }

  private fun receiveDacLoop(sock: DatagramSocket) {
    val buf = ByteArray(dacMaxFrameBytes)
    while (running.get()) {
      try {
        val packet = DatagramPacket(buf, buf.size)
        sock.receive(packet)
        val frame = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
        val dac = DacReferenceWire.decodeFrame(frame)
        val ameFrame = BifrostWire.decodeAmeFrame(dac.payload)
        if (ameFrame.isRoot) {
          handleDacRootFrame(sock, packet, dac, ameFrame)
        } else {
          handleAmeDacLaneFrame(sock, packet, frame, dac)
        }
      } catch (_: SocketTimeoutException) {
      } catch (_: SocketException) {
        if (running.get()) emit(ProtocolKind.AME, LogDirection.ERROR, "local", "DAC socket closed")
      } catch (t: Throwable) {
        if (running.get()) emit(ProtocolKind.AME, LogDirection.ERROR, "local", "AME/DAC/DAC rejected: ${t.message ?: t.javaClass.simpleName}")
      }
    }
  }

  private fun handleDacRootFrame(
    sock: DatagramSocket,
    packet: DatagramPacket,
    dac: DacReferenceWire.DecodedFrame,
    rootFrame: BifrostWire.AmeFrame,
  ) {
    val nowMillis = System.currentTimeMillis()
    runtimeState.pruneExpiredAmeDacSessions(nowMillis, ameDacSessionTtlMillis)
    try {
      requireAmeDacSessionNotCompleted(runtimeState, rootFrame.sessionId, "AME/DAC root request")
    } catch (t: IllegalArgumentException) {
      emit(ProtocolKind.AME, LogDirection.ERROR, packet.address.hostAddress ?: "dac-peer", t.message ?: "AME/DAC root request rejected")
      return
    }
    require(dac.header.messageKind == DacReferenceWire.MessageKind.PACKAGE_CHUNK) { "AME/DAC expected DAC package chunk" }
    require(dac.header.sessionId == rootFrame.sessionId) { "AME/DAC root session mismatch" }
    require(dac.header.laneId == ameRootLaneId) { "AME/DAC expected root lane" }
    require(dac.header.sequence == dacRootRequestSequence) { "AME/DAC root sequence mismatch" }
    requireAmeDacRootFrame(
      frame = rootFrame,
      expectedSessionId = dac.header.sessionId,
      expectedSequence = ameRootRequestSequence,
      expectedPacketKind = BifrostWire.AmePacketKind.UPGRADE_REQUEST,
      context = "AME/DAC root request",
    )
    val rootMessage = BifrostWire.decodeMessage(rootFrame.payload)
    requireAmeDacDataMessage(rootMessage, "AME/DAC root request")
    maybeAutoUpgradeFrom(rootFrame, rootMessage.senderName)
    val profile = rootFrame.profile ?: ameProfile()
    val tier = profile.tier
    val remote = ameDacPeerOf(packet)
    requireAmeDacSessionPeer(
      sessionId = rootFrame.sessionId,
      actual = remote,
      existing = runtimeState.ameDacSessions[rootFrame.sessionId]?.remote,
    )
    val seed = deriveAmeDacSessionSeed(local.nodeId, rootMessage.senderId, rootFrame.sessionId, tier)
    val session = AmeDacSession(
      peerName = rootMessage.senderName,
      tier = tier,
      seed = seed,
      rootLaneId = rootFrame.rootLaneId,
      remote = remote,
      createdAtMillis = nowMillis,
    )
    val rootLabel = ameFrameLabel(rootFrame)
    emit(ProtocolKind.AME, LogDirection.IN, rootMessage.senderName, "DAC $rootLabel ${rootMessage.body}")
    val rootAckMessage = BifrostWire.ackFor(local, rootMessage, sequence.getAndIncrement())
    val rootAckFrame = BifrostWire.encodeAmeRootFrame(
      BifrostWire.AmePacketKind.UPGRADE_ACK,
      rootFrame.sessionId,
      ameRootAckSequence,
      BifrostWire.encodeMessage(rootAckMessage),
      ameProfile(),
      rootLaneId = rootFrame.rootLaneId,
    )
    val rootAckDac = DacReferenceWire.encodePackageChunk(
      sessionId = rootFrame.sessionId,
      laneId = ameRootLaneId,
      epochId = 0,
      sequence = dacRootAckSequence,
      payload = rootAckFrame,
    )
    sock.send(DatagramPacket(rootAckDac, rootAckDac.size, packet.address, packet.port))
    runtimeState.ameDacSessions[rootFrame.sessionId] = session
    emit(ProtocolKind.AME, LogDirection.OUT, rootMessage.senderName, "DAC root ack #${rootMessage.sequence}")
  }

  private fun handleAmeDacLaneFrame(
    sock: DatagramSocket,
    packet: DatagramPacket,
    frame: ByteArray,
    dac: DacReferenceWire.DecodedFrame,
  ) {
    runtimeState.pruneExpiredAmeDacSessions(System.currentTimeMillis(), ameDacSessionTtlMillis)
    val session = try {
      requireAmeDacSession(runtimeState, dac.header.sessionId, "AME/DAC/DAC lane frame")
    } catch (t: IllegalArgumentException) {
      emit(ProtocolKind.AME, LogDirection.ERROR, packet.address.hostAddress ?: "dac-peer", t.message ?: "AME/DAC/DAC lane frame rejected")
      return
    }
    requireAmeDacPeer(packet, session.remote, "AME/DAC/DAC lane frame")
    val message = consumeAmeDacSessionAfter(runtimeState, dac.header.sessionId, session) {
      val lanePayload = NativeAmeDac.openDac(
        frame = frame,
        seed = session.seed,
        tier = session.tier,
        sessionId = dac.header.sessionId,
        laneId = ameLaneId,
        expectedAmeSequence = ameLaneDataSequence,
        expectedDacSequence = dacLaneDataSequence,
        rootLaneId = session.rootLaneId,
      )
      val decoded = BifrostWire.decodeMessage(lanePayload)
      requireAmeDacDataMessage(decoded, "AME/DAC lane frame")
      decoded
    }
    runtimeState.markAmeDacSessionCompleted(dac.header.sessionId, System.currentTimeMillis())
    emit(ProtocolKind.AME, LogDirection.IN, message.senderName, "DAC lane $ameLaneId protected ${message.body}")
    val ackMessage = BifrostWire.ackFor(local, message, sequence.getAndIncrement())
    val ackFrame = NativeAmeDac.sealDac(
      payload = BifrostWire.encodeMessage(ackMessage),
      seed = session.seed,
      tier = session.tier,
      sessionId = dac.header.sessionId,
      laneId = ameLaneId,
      ameSequence = ameLaneAckSequence,
      dacSequence = dacLaneAckSequence,
      rootLaneId = session.rootLaneId,
    )
    sock.send(DatagramPacket(ackFrame, ackFrame.size, packet.address, packet.port))
    emit(ProtocolKind.AME, LogDirection.OUT, session.peerName, "DAC ack #${message.sequence}")
  }

  private fun handleStreamSocket(socket: Socket, protocol: ProtocolKind) {
    socket.use { s ->
      try {
        if (s is SSLSocket) s.startHandshake()
        val payload = BifrostWire.readFrame(s.getInputStream())
        val message = BifrostWire.decodeMessage(payload)
        requireTransportMessageProtocol(message, protocol, "${protocol.label} stream")
        emit(protocol, LogDirection.IN, message.senderName, message.body)
        if (!message.isAck) {
          val ack = BifrostWire.ackFor(local, message, sequence.getAndIncrement())
          s.getOutputStream().write(BifrostWire.frame(BifrostWire.encodeMessage(ack)))
          s.getOutputStream().flush()
        }
      } catch (t: Throwable) {
        emit(protocol, LogDirection.ERROR, s.inetAddress.hostAddress ?: "peer", t.message ?: t.javaClass.simpleName)
      }
    }
  }

  private fun sendTcp(peer: PeerEndpoint, body: String) {
    val message = newMessage(ProtocolKind.TCP, body)
    try {
      Socket().use { socket ->
        socket.connect(InetSocketAddress(peer.host, peer.tcpPort), 3500)
        socket.soTimeout = 3500
        socket.getOutputStream().write(BifrostWire.frame(BifrostWire.encodeMessage(message)))
        socket.getOutputStream().flush()
        emit(ProtocolKind.TCP, LogDirection.OUT, peer.displayName, body)
        readStreamAck(socket, ProtocolKind.TCP)
      }
    } catch (t: Throwable) {
      emit(ProtocolKind.TCP, LogDirection.ERROR, peer.displayName, t.message ?: t.javaClass.simpleName)
    }
  }

  private fun sendTls(peer: PeerEndpoint, body: String) {
    if (!TlsTools.isProvisioned(context)) {
      emit(ProtocolKind.TLS, LogDirection.ERROR, peer.displayName, TlsTools.provisioningSummary(context))
      return
    }
    val message = newMessage(ProtocolKind.TLS, body)
    try {
      val raw = TlsTools.socketFactory(context).createSocket() as SSLSocket
      raw.use { socket ->
        socket.connect(InetSocketAddress(peer.host, peer.tlsPort), 3500)
        socket.soTimeout = 3500
        TlsTools.configureClient(socket)
        socket.startHandshake()
        socket.getOutputStream().write(BifrostWire.frame(BifrostWire.encodeMessage(message)))
        socket.getOutputStream().flush()
        emit(ProtocolKind.TLS, LogDirection.OUT, peer.displayName, body)
        readStreamAck(socket, ProtocolKind.TLS)
      }
    } catch (t: Throwable) {
      emit(ProtocolKind.TLS, LogDirection.ERROR, peer.displayName, t.message ?: t.javaClass.simpleName)
    }
  }

  private fun sendUdp(peer: PeerEndpoint, body: String) {
    val message = newMessage(ProtocolKind.UDP, body)
    try {
      val payload = BifrostWire.encodeMessage(message)
      val sock = udpSocket ?: DatagramSocket()
      val address = InetAddress.getByName(peer.host)
      sock.send(DatagramPacket(payload, payload.size, address, peer.udpPort))
      emit(ProtocolKind.UDP, LogDirection.OUT, peer.displayName, body)
    } catch (t: Throwable) {
      emit(ProtocolKind.UDP, LogDirection.ERROR, peer.displayName, t.message ?: t.javaClass.simpleName)
    }
  }

  private fun sendAme(peer: PeerEndpoint, body: String) {
    if (!demoSecurityEnabled()) {
      emit(ProtocolKind.AME, LogDirection.ERROR, peer.displayName, "debug-only demo AME/DAC/DAC is disabled in release")
      return
    }
    if (!NativeAme.loaded) {
      emit(ProtocolKind.AME, LogDirection.ERROR, peer.displayName, "native bridge missing; AME/AME/DAC send disabled")
      return
    }
    val sessionId = Random.nextLong(1, Long.MAX_VALUE)
    val profile = ameProfile()
    val keys = ameKeyMaterial()
    val rootLaneId = 1L
    val rootMessage = newMessage(ProtocolKind.AME, "upgrade ${local.displayName} tier=${profile.tier.label} public=${keys.publicDescriptor.displayText}")
    val laneMessage = newMessage(ProtocolKind.AME, body)
    try {
      DatagramSocket().use { dac ->
        dac.soTimeout = 3500
        val address = InetAddress.getByName(peer.host)
        dac.connect(address, peer.dacPort)
        val expectedPeer = ameDacPeerOf(address, peer.dacPort)
        val rootPayload = BifrostWire.encodeMessage(rootMessage)
        val rootFrame = BifrostWire.encodeAmeRootFrame(
          BifrostWire.AmePacketKind.UPGRADE_REQUEST,
          sessionId,
          ameRootRequestSequence,
          rootPayload,
          profile,
          rootLaneId = rootLaneId,
        )
        val rootDacFrame = DacReferenceWire.encodePackageChunk(
          sessionId = sessionId,
          laneId = ameRootLaneId,
          epochId = 0,
          sequence = dacRootRequestSequence,
          payload = rootFrame,
        )
        dac.send(DatagramPacket(rootDacFrame, rootDacFrame.size))
        emit(ProtocolKind.AME, LogDirection.OUT, peer.displayName, "DAC root upgrade ${profile.tier.label}")
        val rootAck = readDacRootAck(dac, peer, expectedPeer, sessionId, rootLaneId)
        val seed = deriveAmeDacSessionSeed(local.nodeId, rootAck.message.senderId, sessionId, profile.tier)

        val dacFrame = NativeAmeDac.sealDac(
          payload = BifrostWire.encodeMessage(laneMessage),
          seed = seed,
          tier = profile.tier,
          sessionId = sessionId,
          laneId = ameLaneId,
          ameSequence = ameLaneDataSequence,
          dacSequence = dacLaneDataSequence,
          rootLaneId = rootAck.rootLaneId,
        )
        dac.send(DatagramPacket(dacFrame, dacFrame.size))
        emit(ProtocolKind.AME, LogDirection.OUT, peer.displayName, "DAC lane $ameLaneId protected $body")
        readAmeDacAck(dac, peer, expectedPeer, seed, profile.tier, sessionId, rootAck.rootLaneId)
      }
    } catch (t: Throwable) {
      emit(ProtocolKind.AME, LogDirection.ERROR, peer.displayName, t.message ?: t.javaClass.simpleName)
    }
  }

  private fun readStreamAck(socket: Socket, protocol: ProtocolKind) {
    try {
      val ack = BifrostWire.decodeMessage(BifrostWire.readFrame(socket.getInputStream()))
      requireTransportAckMessage(ack, protocol, "${protocol.label} ack")
      emit(protocol, LogDirection.IN, ack.senderName, ack.body)
    } catch (t: Throwable) {
      emit(protocol, LogDirection.ERROR, socket.inetAddress.hostAddress ?: "peer", "ack failed: ${t.message ?: t.javaClass.simpleName}")
    }
  }

  private fun readDacRootAck(
    sock: DatagramSocket,
    peer: PeerEndpoint,
    expectedPeer: AmeDacPeer,
    sessionId: Long,
    rootLaneId: Long,
  ): AmeDacRootAck {
    val packet = DatagramPacket(ByteArray(dacMaxFrameBytes), dacMaxFrameBytes)
    sock.receive(packet)
    requireAmeDacPeer(packet, expectedPeer, "AME/DAC root ack")
    val dac = DacReferenceWire.decodeFrame(packet.data.copyOfRange(packet.offset, packet.offset + packet.length))
    require(dac.header.messageKind == DacReferenceWire.MessageKind.PACKAGE_CHUNK) { "AME/DAC expected DAC package chunk" }
    require(dac.header.sessionId == sessionId) { "AME/DAC root ack session mismatch" }
    require(dac.header.laneId == ameRootLaneId) { "AME/DAC root ack lane mismatch" }
    require(dac.header.sequence == dacRootAckSequence) { "AME/DAC root ack sequence mismatch" }
    val ackFrame = BifrostWire.decodeAmeFrame(dac.payload)
    requireAmeDacRootFrame(
      frame = ackFrame,
      expectedSessionId = sessionId,
      expectedSequence = ameRootAckSequence,
      expectedPacketKind = BifrostWire.AmePacketKind.UPGRADE_ACK,
      context = "AME/DAC root ack",
      expectedRootLaneId = rootLaneId,
    )
    val ack = BifrostWire.decodeMessage(ackFrame.payload)
    requireAmeDacAckMessage(ack, "AME/DAC root ack")
    maybeAutoUpgradeFrom(ackFrame, ack.senderName)
    val label = ameFrameLabel(ackFrame)
    emit(ProtocolKind.AME, LogDirection.IN, peer.displayName, "DAC $label ${ack.body}")
    return AmeDacRootAck(message = ack, rootLaneId = ackFrame.rootLaneId)
  }

  private fun readAmeDacAck(
    sock: DatagramSocket,
    peer: PeerEndpoint,
    expectedPeer: AmeDacPeer,
    seed: ByteArray,
    tier: AmeTier,
    sessionId: Long,
    rootLaneId: Long,
  ) {
    val packet = DatagramPacket(ByteArray(dacMaxFrameBytes), dacMaxFrameBytes)
    sock.receive(packet)
    requireAmeDacPeer(packet, expectedPeer, "AME/DAC lane ack")
    val frame = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
    val ackPayload = NativeAmeDac.openDac(
      frame = frame,
      seed = seed,
      tier = tier,
      sessionId = sessionId,
      laneId = ameLaneId,
      expectedAmeSequence = ameLaneAckSequence,
      expectedDacSequence = dacLaneAckSequence,
      rootLaneId = rootLaneId,
    )
    val ack = BifrostWire.decodeMessage(ackPayload)
    requireAmeDacAckMessage(ack, "AME/DAC lane ack")
    emit(ProtocolKind.AME, LogDirection.IN, peer.displayName, "DAC lane $ameLaneId protected ${ack.body}")
  }

  private fun maybeAutoUpgradeFrom(frame: BifrostWire.AmeFrame, peerName: String) {
    val target = NativeAme.autoUpgradeTier(selectedAmeTier(), autoAmeUpgrade(), frame) ?: return
    applyAmeTier(target, "auto", peerName)
  }

  private fun ameFrameLabel(frame: BifrostWire.AmeFrame): String {
    val base = if (frame.isRoot) "root ${frame.packetKind.label}" else "lane ${frame.laneId} ${frame.packetKind.label}"
    val profile = frame.profile ?: return base
    return "$base ${profile.tier.label}"
  }

  private fun deriveAmeDacSessionSeed(
    localNodeId: String,
    remoteNodeId: String,
    sessionId: Long,
    tier: AmeTier,
  ): ByteArray {
    val ordered = listOf(localNodeId, remoteNodeId).sorted().joinToString("|")
    val material = "BIFROST-ANDROID-AME/DAC-DEMO-v1|$ordered|session=$sessionId|tier=${tier.id}"
    return MessageDigest.getInstance("SHA-256").digest(material.toByteArray(Charsets.UTF_8))
  }

  private fun newMessage(protocol: ProtocolKind, body: String): BifrostMessage =
    BifrostMessage(
      protocol = protocol,
      senderId = local.nodeId,
      senderName = local.displayName,
      body = body,
      sequence = sequence.getAndIncrement(),
      timestampMillis = System.currentTimeMillis(),
    )

  private fun emit(entry: BifrostLogEntry) {
    appendLog(entry)
    listener.onLog(entry)
  }

  private fun emit(protocol: ProtocolKind, direction: LogDirection, peer: String, message: String) {
    emit(BifrostLogEntry(System.currentTimeMillis(), protocol, direction, peer, message))
  }

  private fun submitIo(task: () -> Unit) {
    runtimeState.executor().execute(task)
  }

  private fun appendLog(entry: BifrostLogEntry) {
    try {
      logFile.appendText(entry.toLogLine() + "\n")
    } catch (_: Throwable) {
    }
  }

  private fun closeQuietly(socket: ServerSocket?) {
    try {
      socket?.close()
    } catch (_: Throwable) {
    }
  }

  private fun loadAmeTier(): AmeTier {
    val tierId = statePrefs()
      .getInt("tier", AmeTier.MEDIUM.id)
    return AmeTier.fromId(tierId)
  }

  private fun loadAutoAmeUpgrade(): Boolean =
    statePrefs().getBoolean("autoUpgrade", false)

  private fun statePrefs() =
    context.getSharedPreferences("bifrost-ame-state", Context.MODE_PRIVATE)
}
