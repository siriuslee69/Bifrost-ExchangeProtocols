package com.siriuslee.bifrost.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DirectLanInstrumentedTest {
  @Test
  fun phoneAndHostExchangeBmsgFramesOverLanIp() {
    val args = InstrumentationRegistry.getArguments()
    val host = args.getString("bifrostHost")
    assumeTrue("bifrostHost is required for the physical LAN test", !host.isNullOrBlank())
    val hostPort = args.getString("bifrostHostPort")?.toIntOrNull() ?: 49371
    val phonePort = args.getString("bifrostPhonePort")?.toIntOrNull() ?: 49372
    val phoneMessage = "phone-to-host-${System.currentTimeMillis()}"
    val hostMessage = "host-to-phone"
    val local = LocalNode("motorola-test", "Motorola")

    ServerSocket().use { server ->
      server.reuseAddress = true
      server.soTimeout = 15_000
      server.bind(InetSocketAddress("0.0.0.0", phonePort))

      server.accept().use { socket ->
        socket.soTimeout = 8_000
        val incoming = BifrostWire.decodeMessage(BifrostWire.readFrame(socket.getInputStream()))
        assertEquals(ProtocolKind.TCP, incoming.protocol)
        assertEquals(hostMessage, incoming.body)
        val ack = BifrostWire.ackFor(local, incoming, 2)
        socket.getOutputStream().write(BifrostWire.frame(BifrostWire.encodeMessage(ack)))
        socket.getOutputStream().flush()
      }

      Socket().use { socket ->
        socket.connect(InetSocketAddress(host!!, hostPort), 8_000)
        socket.soTimeout = 8_000
        val outgoing = BifrostMessage(
          protocol = ProtocolKind.TCP,
          senderId = local.nodeId,
          senderName = local.displayName,
          body = phoneMessage,
          sequence = 1,
          timestampMillis = System.currentTimeMillis(),
        )
        socket.getOutputStream().write(BifrostWire.frame(BifrostWire.encodeMessage(outgoing)))
        socket.getOutputStream().flush()
        val ack = BifrostWire.decodeMessage(BifrostWire.readFrame(socket.getInputStream()))
        assertTrue(ack.isAck)
        assertEquals(ProtocolKind.TCP, ack.protocol)
      }
    }
  }
}
