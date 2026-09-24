## -------------------------------------------------------------------------
## AME DAC Client <- the one-socket client, and pinning a localhost peer
## -------------------------------------------------------------------------
##
##   connectAmeDacClient   opens a DAC socket to one peer and carries an
##                         already agreed session: send / receive / close
##   pinLocalhostDacPeer   "localhost" may be 127.0.0.1 or ::1, so a socket
##                         opened to it stays unconnected and remembers only
##                         the port. Once the peer has answered from a real
##                         address, pinning connects the socket to it.

import std/[net, unittest]

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/secret_stack
import ../../src/protocols/ame/level2/framing
import ../../src/protocols/ame/level2/carriers
import ../../src/protocols/dac/level0/transport
import runePragmas

proc pairAuth(role: AmeEndpointRole): AmeAuthPackage {.role: configurator.} =
  ## role: one end of a pair that shares one fixed first exchange.
  var
    layout: AmeSuiteLayout = defaultAmeLayout([akaX25519])
    tier: AmeMaskTier = fullAmeMaskTier(layout)
    state: AmeExchangeState = initAmeExchangeState(layout.kems)
  applyAmeExchange(state, layout, initAmeExchangeRequest(layout.kems, tier,
    tier.masks.kem), [@[byte 4, 3, 2, 1]])
  result = initAmeAuthPackage(layout, tier, state, endpointRole = role)

proc listener(): tuple[sock: DacSocket, a: DacAddress] {.
    role: configurator.} =
  ## A bound datagram socket and its address.
  result.sock = openDacListener(initDacAddress("127.0.0.1", 0'u16))
  result.a = initDacAddress("127.0.0.1", dacLocalPort(result.sock).port)

proc peerOf(sock: DacSocket): bool {.role: parser.} =
  ## sock: true when the OS socket is connected to one peer.
  try:
    discard sock.getPeerAddr()
    result = true
  except OSError:
    result = false

suite "AME DAC client":
  # {.testKind: tkIntegration, covers: "connectAmeDacClient".}
  test "a client sends, receives the answer, and closes":
    var
      server: AmeSession = initAmeSession(pairAuth(aerResponder),
        peerTrustRequired = false)
      rx: tuple[sock: DacSocket, a: DacAddress] = listener()
      client: AmeDacClient = connectAmeDacClient(rx.a, initAmeSession(
        pairAuth(aerInitiator), peerTrustRequired = false))
      got: DacFrameBytesResult = DacFrameBytesResult()
      opened: AmeOpenResult = AmeOpenResult()
    send(client, [byte 1, 2, 3])
    got = recvDacFrameBytes(rx.sock, 65536, 2000)
    check got.ok
    opened = openAmeDacFrame(server, got.payload)
    check opened.ok
    check opened.packet.payload == @[byte 1, 2, 3]
    sendAmeDac(rx.sock, got.remote, server, [byte 9])
    opened = receive(client, 2000)
    check opened.ok
    check opened.packet.payload == @[byte 9]
    close(client)
    check client.socket == nil
    rx.sock.close()

suite "DAC localhost pinning":
  # {.testKind: tkIntegration, covers: "pinLocalhostDacPeer".}
  test "a localhost socket is connected to the address that answered":
    var
      rx: tuple[sock: DacSocket, a: DacAddress] = listener()
      sock: DacSocket = openDacPeer(initDacAddress("localhost", rx.a.port))
      got: DacFrameBytesResult = DacFrameBytesResult()
    check not peerOf(sock)
    sendDacFrameBytes(sock, @[byte 7])
    got = recvDacFrameBytes(rx.sock, 64, 2000)
    check got.ok
    pinLocalhostDacPeer(sock, rx.a)
    check peerOf(sock)
    sendDacFrameBytes(sock, @[byte 8])
    got = recvDacFrameBytes(rx.sock, 64, 2000)
    check got.payload == @[byte 8]
    closeDac(sock)
    rx.sock.close()

  # {.testKind: tkEdgeCase, covers: "pinLocalhostDacPeer".}
  test "a socket opened to a real address is left alone":
    var
      rx: tuple[sock: DacSocket, a: DacAddress] = listener()
      other: tuple[sock: DacSocket, a: DacAddress] = listener()
      sock: DacSocket = openDacPeer(rx.a)
    pinLocalhostDacPeer(sock, other.a)
    check sock.getPeerAddr()[1] == Port(rx.a.port)
    closeDac(sock)
    rx.sock.close()
    other.sock.close()
