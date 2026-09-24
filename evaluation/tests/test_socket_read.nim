## -------------------------------------------------------------------------
## Socket Read <- whatever has arrived, not "all n bytes or time out"
## -------------------------------------------------------------------------
##
##   case                                   readAvailableSocket gives
##   -------------------------------------  --------------------------------
##   peer sent fewer bytes than asked for   those bytes, at once
##   a line read left bytes in the buffer   those buffered bytes first
##   nothing arrives                        timedOut, no bytes
##   peer closed                            not ok, not timedOut

import std/[net, unittest]

import ../../src/protocols/transport/socket_read
import runePragmas

proc connectedPair(): tuple[a, b, listener: Socket] {.role: configurator.} =
  ## Two ends of one loopback TCP connection, plus the listener.
  var
    client: Socket = nil
  result.listener = newSocket()
  result.listener.setSockOpt(OptReuseAddr, true)
  result.listener.bindAddr(Port(0), "127.0.0.1")
  result.listener.listen()
  result.a = newSocket()
  result.a.connect("127.0.0.1", result.listener.getLocalAddr()[1])
  result.listener.accept(client)
  result.b = client

proc closePair(p: tuple[a, b, listener: Socket]) {.role: actor.} =
  ## p: every socket of the pair.
  p.a.close()
  p.b.close()
  p.listener.close()

suite "socket read: what has arrived":
  # {.testKind: tkRegression, covers: "readAvailableSocket", pins: "std recv(n, timeout) waited for all n bytes and stalled the TLS handshake".}
  test "fewer bytes than asked for come back at once":
    var
      p = connectedPair()
      r: SocketReadResult = SocketReadResult()
    p.a.send("hello")
    r = readAvailableSocket(p.b, 4096, 2000)
    check r.ok
    check r.data == "hello"
    closePair(p)

  # {.testKind: tkEdgeCase, covers: "readAvailableSocket".}
  test "bytes a line read left in the buffer come first":
    var
      p = connectedPair()
      r: SocketReadResult = SocketReadResult()
    p.a.send("STARTTLS\r\nHELLO")
    check p.b.recvLine(2000) == "STARTTLS"
    r = readAvailableSocket(p.b, 4096, 2000)
    check r.ok
    check r.data == "HELLO"
    closePair(p)

  # {.testKind: tkEdgeCase, covers: "readAvailableSocket".}
  test "nothing arriving is a timeout, a closed peer is not":
    var
      p = connectedPair()
      r: SocketReadResult = SocketReadResult()
    r = readAvailableSocket(p.b, 16, 100)
    check not r.ok
    check r.timedOut
    p.a.close()
    r = readAvailableSocket(p.b, 16, 2000)
    check not r.ok
    check not r.timedOut
    p.b.close()
    p.listener.close()
