## ---------------------------------------------------------------------
## Wait Readable Tests <- waiting for sockets, however many there are
## ---------------------------------------------------------------------
##
##   suite                  what it holds down
##   ---------------------  ------------------------------------------------
##   waiting for sockets    only the ready ones are left in the list; a quiet
##                          list returns 0 after the time; an empty list is
##                          not a crash
##   a crowd of sockets     with 1100 sockets open, a datagram on the LAST
##                          one (its number is above 1023) is found, and
##                          `recvUdpDatagram` reads it. Nim's own
##                          `selectRead` overruns its table here (a build
##                          with glibc fortify checks is stopped by it).

import std/[nativesockets, net, unittest]

import ../../src/protocols/types
import ../../src/protocols/transport/types as transport_types
import ../../src/protocols/transport/udp_ops
import ../../src/protocols/transport/socket_write
import ../../src/protocols/transport/wait_readable

const
  crowd: int = 1100

proc portOf(s: Socket): uint16 =
  result = uint16(s.getLocalAddr()[1])

proc toward(s: Socket): UdpAddress =
  ## s: the loopback address a datagram must be sent to reach it.
  result = initUdpAddress("127.0.0.1", portOf(s))

suite "waiting for sockets":
  # {.testKind: tkUnit, covers: "waitReadable".}
  test "only the sockets with something to read are left":
    var
      quiet: Socket = bindUdp(initUdpAddress("127.0.0.1", 0'u16))
      busy: Socket = bindUdp(initUdpAddress("127.0.0.1", 0'u16))
      sender: Socket = connectUdp(toward(busy))
      fds: seq[SocketHandle] = @[]
    sendUdpDatagram(sender, @[1'u8, 2, 3])
    fds = @[quiet.getFd(), busy.getFd()]
    check waitReadable(fds, 500) == 1
    check fds == @[busy.getFd()]
    closeSocketQuietly(quiet)
    closeSocketQuietly(busy)
    closeSocketQuietly(sender)

  # {.testKind: tkEdgeCase, covers: "waitReadable".}
  test "a quiet list answers 0 after the time, and an empty list is no crash":
    var
      quiet: Socket = bindUdp(initUdpAddress("127.0.0.1", 0'u16))
      fds: seq[SocketHandle] = @[quiet.getFd()]
      none: seq[SocketHandle] = @[]
    check waitReadable(fds, 20) == 0
    check fds.len == 0
    check waitReadable(none, 5) == 0
    closeSocketQuietly(quiet)

suite "a crowd of sockets":
  # {.testKind: tkRegression, covers: "waitReadable|recvUdpDatagram", pins: "select table overrun above descriptor 1023".}
  test "a datagram on a socket numbered above 1023 is found and read":
    var
      socks: seq[Socket] = @[]
      sender: Socket = nil
      fds: seq[SocketHandle] = @[]
      got: UdpDatagramResult = default(UdpDatagramResult)
      i: int = 0
      failed: bool = false
    try:
      while i < crowd:
        socks.add bindUdp(initUdpAddress("127.0.0.1", 0'u16))
        i = i + 1
    except CatchableError:
      failed = true
    if failed:
      ## This machine allows fewer open files than the test needs (`ulimit -n`).
      ## Say so instead of passing without having looked.
      echo "  (skipped: only " & $socks.len & " sockets could be opened)"
    else:
      sender = connectUdp(toward(socks[^1]))
      sendUdpDatagram(sender, @[7'u8])
      i = 0
      while i < socks.len:
        fds.add socks[i].getFd()
        i = i + 1
      check int(socks[^1].getFd()) > 1023
      check waitReadable(fds, 500) == 1
      check fds == @[socks[^1].getFd()]
      sendUdpDatagram(sender, @[8'u8])
      got = recvUdpDatagram(socks[^1], 64, 500)
      check got.ok
      closeSocketQuietly(sender)
    for s in socks:
      closeSocketQuietly(s)
