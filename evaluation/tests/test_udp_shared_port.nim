## ---------------------------------------------------------------------
## UDP Shared Port Tests <- several forwarders on one port, with a warning
## ---------------------------------------------------------------------

import std/[sets, unittest, net]

import ../../src/protocols/types
import ../../src/protocols/transport/types as transport_types
import ../../src/protocols/transport/udp_ops
import ../../src/protocols/transport/socket_write

proc portOf(s: Socket): uint16 =
  result = uint16(s.getLocalAddr()[1])

proc tryRead(s: Socket): int =
  ## How many datagrams are waiting on s.
  var
    got: UdpDatagramResult = recvUdpDatagram(s, 64, 100)
  while got.ok:
    result = result + 1
    got = recvUdpDatagram(s, 64, 100)

suite "UDP shared port":
  # {.testKind: tkRegression, covers: "bindUdp", pins: "port 0 handed out a port already in use".}
  test "port 0 never hands out a port that is already in use":
    ## A forwarder opens one socket on port 0 per client. When the sockets could
    ## share ports, 1100 of them shared about 25, and home's answer for one
    ## client reached another. Open as many as this machine allows (up to 1500).
    var
      socks: seq[Socket] = @[]
      ports: HashSet[uint16] = initHashSet[uint16]()
      i: int = 0
    try:
      while i < 1500:
        socks.add bindUdp(initUdpAddress("127.0.0.1", 0'u16))
        ports.incl portOf(socks[i])
        i = i + 1
    except CatchableError:
      echo "  (only " & $socks.len & " sockets could be opened: file limit)"
    check socks.len >= 200
    check ports.len == socks.len
    for s in socks:
      closeSocketQuietly(s)

  # {.testKind: tkEdgeCase, covers: "bindUdp".}
  test "a second plain bind of a held port is refused, and leaves no socket open":
    var
      a: Socket = bindUdp(initUdpAddress("127.0.0.1", 0'u16))
      p: uint16 = portOf(a)
    expect OSError:
      discard bindUdp(initUdpAddress("127.0.0.1", p))
    closeSocketQuietly(a)
    check not udpPortInUse(initUdpAddress("127.0.0.1", p))

  # {.testKind: tkUnit, covers: "udpPortInUse".}
  test "a free port is not in use, a held one is":
    var
      s: Socket = bindUdp(initUdpAddress("127.0.0.1", 0'u16))
      p: uint16 = portOf(s)
    check udpPortInUse(initUdpAddress("127.0.0.1", p))
    closeSocketQuietly(s)
    check not udpPortInUse(initUdpAddress("127.0.0.1", p))
    check not udpPortInUse(initUdpAddress("127.0.0.1", 0'u16))

  when defined(linux):
    # {.testKind: tkIntegration, covers: "bindUdpShared".}
    test "the second holder is allowed and warned about":
      var
        a = bindUdpShared(initUdpAddress("127.0.0.1", 0'u16))
        p: uint16 = portOf(a.sock)
        b = bindUdpShared(initUdpAddress("127.0.0.1", p))
        c = bindUdpShared(initUdpAddress("127.0.0.1", p))
      check a.warning == ""
      check b.warning != ""
      check c.warning != ""
      closeSocketQuietly(a.sock)
      closeSocketQuietly(b.sock)
      closeSocketQuietly(c.sock)

    # {.testKind: tkIntegration, covers: "bindUdpShared".}
    test "one client always lands on the same holder":
      var
        a = bindUdpShared(initUdpAddress("127.0.0.1", 0'u16))
        p: uint16 = portOf(a.sock)
        b = bindUdpShared(initUdpAddress("127.0.0.1", p))
        client: Socket = connectUdp(initUdpAddress("127.0.0.1", p))
        i: int = 0
        na: int = 0
        nb: int = 0
      while i < 12:
        sendUdpDatagram(client, @[byte i])
        i = i + 1
      na = tryRead(a.sock)
      nb = tryRead(b.sock)
      check na + nb == 12
      check na == 0 or nb == 0
      closeSocketQuietly(client)
      closeSocketQuietly(a.sock)
      closeSocketQuietly(b.sock)

    # {.testKind: tkIntegration, covers: "bindUdpShared".}
    test "many clients are spread over the holders":
      var
        a = bindUdpShared(initUdpAddress("127.0.0.1", 0'u16))
        p: uint16 = portOf(a.sock)
        b = bindUdpShared(initUdpAddress("127.0.0.1", p))
        clients: seq[Socket] = @[]
        i: int = 0
        na: int = 0
        nb: int = 0
      while i < 24:
        clients.add(connectUdp(initUdpAddress("127.0.0.1", p)))
        sendUdpDatagram(clients[i], @[byte i])
        i = i + 1
      na = tryRead(a.sock)
      nb = tryRead(b.sock)
      check na + nb == 24
      check na > 0 and nb > 0
      for c in clients:
        closeSocketQuietly(c)
      closeSocketQuietly(a.sock)
      closeSocketQuietly(b.sock)
