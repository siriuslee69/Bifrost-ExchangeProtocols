## ---------------------------------------------------
## Transport Ops Tests <- generic TCP/UDP transport helpers
## ---------------------------------------------------

import std/[os, net, strutils, unittest]
when defined(ssl):
  from ./tls_test_support import
    ensureTlsTestCertificate,
    initTlsTestServerConfig,
    initTlsTestClientConfig

import ../../src/protocols/types
import ../../src/protocols/dac/level0/transport
import ../../src/protocols/transport/types
import ../../src/protocols/transport/stream_framing
import ../../src/protocols/transport/tcp_ops
import ../../src/protocols/transport/udp_ops
import runePragmas

type
  TransportServerArgs = object
    a: TcpAddress

  UdpServerArgs = object
    a: UdpAddress

when defined(ssl):
  type
    TlsTransportServerArgs = object
      e: TcpEndpoint

proc runTransportServer(a: TransportServerArgs) {.thread.} =
  var
    server: Socket
    client: Socket
    recvRes: TcpFrameResult
  server = listenTcp(a.a)
  defer:
    server.close()
  client = acceptTcpClient(server)
  defer:
    client.close()
  recvRes = recvTcpFrame(client, 4000)
  if recvRes.ok:
    sendTcpFrame(client, recvRes.payload)

proc runUdpServer(a: UdpServerArgs) {.thread, role: orchestrator.} =
  var
    server: Socket
    recvRes: UdpDatagramResult
  server = bindUdp(a.a)
  defer:
    server.close()
  recvRes = recvUdpDatagram(server, 4096, 4000)
  if recvRes.ok:
    sendUdpDatagram(server, recvRes.remote, recvRes.payload)

when defined(ssl):
  proc runTlsTransportServer(a: TlsTransportServerArgs) {.thread.} =
    var
      server: Socket
      client: Socket
      recvRes: TcpFrameResult
    server = listenTcp(a.e)
    defer:
      server.close()
    client = acceptTcpClient(server, a.e)
    defer:
      client.close()
    recvRes = recvTcpFrame(client, 4000)
    if recvRes.ok:
      sendTcpFrame(client, recvRes.payload)

proc ipv6LoopbackAvailable(): bool =
  ## ipv6LoopbackAvailable: detect whether the host can bind the IPv6 loopback.
  var
    sock: Socket
  try:
    sock = bindUdp(initUdpAddress("::1", 0'u16))
    close(sock)
    result = true
  except CatchableError:
    result = false

proc nextUnusedTcpAddress(host: string): TcpAddress {.role: dataFetcher.} =
  ## nextUnusedTcpAddress: best-effort unused TCP endpoint on the requested host.
  var
    sock: Socket
    bound: tuple[host: string, port: Port]
  sock = listenTcp(initTcpAddress(host, 0'u16))
  bound = sock.getLocalAddr()
  close(sock)
  result = initTcpAddress(bound.host, uint16(bound.port))

proc nextUnusedUdpAddress(host: string): UdpAddress =
  ## nextUnusedUdpAddress: best-effort unused UDP endpoint on the requested host.
  var
    sock: Socket
    bound: tuple[host: string, port: Port]
  sock = bindUdp(initUdpAddress(host, 0'u16))
  bound = sock.getLocalAddr()
  close(sock)
  result = initUdpAddress(bound.host, uint16(bound.port))

proc reopenDacPeerUntilFd(remote: DacAddress, wantedFd: int,
    attempts: int = 32): DacSocket {.role: orchestrator.} =
  ## remote: DAC endpoint to connect.
  ## wantedFd: socket fd that should be reused so the stale-registry path is exercised.
  ## attempts: bounded retry count to avoid an unbounded test loop.
  var
    i: int = 0
  while i < attempts:
    result = openDacPeer(remote, 4000)
    if int(result.getFd()) == wantedFd:
      return
    closeDac(result)
    i = i + 1
  raise newException(IOError, "failed to reuse DAC socket fd for localhost stale-registry test")

suite "transport ops":
  # {.testKind: tkIntegration.}
  test "parse and format tcp address":
    var
      p: tuple[ok: bool, a: TcpAddress]
    p = parseTcpAddress("tcp://127.0.0.1:49001")
    check p.ok
    check p.a.host == "127.0.0.1"
    check p.a.port == 49001'u16
    check formatTcpAddress(p.a) == "127.0.0.1:49001"

  # {.testKind: tkIntegration.}
  test "parse and format tcp ipv6 address":
    var
      p: tuple[ok: bool, a: TcpAddress]
    p = parseTcpAddress("tcp://[::1]:49005")
    check p.ok
    check p.a.host == "::1"
    check p.a.port == 49005'u16
    check formatTcpAddress(p.a) == "[::1]:49005"

  # {.testKind: tkIntegration.}
  test "parse and format udp address":
    var
      p: tuple[ok: bool, a: UdpAddress]
    p = parseUdpAddress("udp://127.0.0.1:49003")
    check p.ok
    check p.a.host == "127.0.0.1"
    check p.a.port == 49003'u16
    check formatUdpAddress(p.a) == "127.0.0.1:49003"

  # {.testKind: tkIntegration.}
  test "parse and format udp ipv6 address":
    var
      p: tuple[ok: bool, a: UdpAddress]
    p = parseUdpAddress("udp://[::1]:49006")
    check p.ok
    check p.a.host == "::1"
    check p.a.port == 49006'u16
    check formatUdpAddress(p.a) == "[::1]:49006"

  # {.testKind: tkEdgeCase.}
  test "tcp parser rejects mismatched scheme and ambiguous unbracketed ipv6 forms":
    var
      p: tuple[ok: bool, a: TcpAddress]
    p = parseTcpAddress("udp://127.0.0.1:49001")
    check not p.ok
    p = parseTcpAddress("tcp://udp://127.0.0.1:49001")
    check not p.ok
    p = parseTcpAddress("::1")
    check not p.ok
    p = parseTcpAddress("tcp://2001:db8::1:49005")
    check not p.ok

  # {.testKind: tkEdgeCase.}
  test "udp parser rejects mismatched scheme and ambiguous unbracketed ipv6 forms":
    var
      p: tuple[ok: bool, a: UdpAddress]
    p = parseUdpAddress("tcp://127.0.0.1:49003")
    check not p.ok
    p = parseUdpAddress("udp://tcp://127.0.0.1:49003")
    check not p.ok
    p = parseUdpAddress("::1")
    check not p.ok
    p = parseUdpAddress("udp://2001:db8::1:49006")
    check not p.ok

  # {.testKind: tkEdgeCase.}
  test "dac parser rejects mismatched carrier scheme and unbracketed ipv6 authorities":
    var
      p: tuple[ok: bool, a: DacAddress]
    p = parseDacAddress("udp://127.0.0.1:49007")
    check not p.ok
    p = parseDacAddress("dac://udp://127.0.0.1:49007")
    check not p.ok
    p = parseDacAddress("dac://2001:db8::1:49007")
    check not p.ok
    p = parseDacAddress("dac://127.0.0.1:49007")
    check p.ok
    check p.a.host == "127.0.0.1"
    check p.a.port == 49007'u16

  # {.testKind: tkEdgeCase.}
  test "separate host constructors reject schemes and embedded ports":
    expect ValueError:
      discard initTcpAddress("tcp://127.0.0.1", 49001'u16)
    expect ValueError:
      discard initTcpAddress("127.0.0.1:49001", 49001'u16)
    expect ValueError:
      discard initUdpAddress("udp://127.0.0.1", 49003'u16)
    expect ValueError:
      discard initDacAddress("dac://127.0.0.1", 49007'u16)

  # {.testKind: tkIntegration.}
  test "separate host constructors normalize bracketed ipv6":
    check initTcpAddress("[::1]", 49005'u16).host == "::1"
    check initUdpAddress("[::1]", 49006'u16).host == "::1"
    check initDacAddress("[2001:db8::7]", 49007'u16).host == "2001:db8::7"

  # {.testKind: tkEdgeCase.}
  test "string parsers reject userinfo and path-like host junk":
    var
      tcp: tuple[ok: bool, a: TcpAddress]
      udp: tuple[ok: bool, a: UdpAddress]
      dac: tuple[ok: bool, a: DacAddress]
    tcp = parseTcpAddress("tcp://user@127.0.0.1:49001")
    check not tcp.ok
    tcp = parseTcpAddress("tcp://127.0.0.1/path:49001")
    check not tcp.ok
    udp = parseUdpAddress("udp://user@127.0.0.1:49003")
    check not udp.ok
    udp = parseUdpAddress("udp://127.0.0.1?peer=a:49003")
    check not udp.ok
    dac = parseDacAddress("dac://user@127.0.0.1:49007")
    check not dac.ok
    dac = parseDacAddress("dac://127.0.0.1/path:49007")
    check not dac.ok

  # {.testKind: tkIntegration.}
  test "send and receive framed payload":
    var
      th: Thread[TransportServerArgs]
      args: TransportServerArgs
      sock: Socket
      recvRes: TcpFrameResult
      payload: ByteSeq
    args.a = initTcpAddress("127.0.0.1", 49002'u16)
    createThread(th, runTransportServer, args)
    sleep(250)
    sock = connectTcp(args.a, 4000)
    defer:
      sock.close()
    payload = @[9'u8, 8'u8, 7'u8, 6'u8]
    sendTcpFrame(sock, payload)
    recvRes = recvTcpFrame(sock, 4000)
    joinThread(th)
    check recvRes.ok
    check recvRes.payload == payload

  # {.testKind: tkIntegration.}
  test "recv tcp frame timeout returns an error instead of throwing":
    var
      listener: Socket
      serverSock: Socket
      clientSock: Socket
      bound: tuple[host: string, port: Port]
      recvRes: TcpFrameResult
      payload: ByteSeq = @[byte 8, 5, 3]
    listener = listenTcp(initTcpAddress("127.0.0.1", 0'u16))
    defer:
      listener.close()
    bound = listener.getLocalAddr()
    clientSock = connectTcp(initTcpAddress("127.0.0.1", uint16(bound.port)), 4000)
    defer:
      clientSock.close()
    serverSock = acceptTcpClient(listener)
    defer:
      serverSock.close()

    recvRes = recvTcpFrame(serverSock, 50)
    check not recvRes.ok
    check recvRes.err.contains("timed out")

    sendTcpFrame(clientSock, payload)
    recvRes = recvTcpFrame(serverSock, 4000)
    check recvRes.ok
    check recvRes.payload == payload

  # {.testKind: tkIntegration.}
  test "tcp localhost reaches an ipv6-only listener":
    if not ipv6LoopbackAvailable():
      skip()
    else:
      var
        th: Thread[TransportServerArgs]
        args: TransportServerArgs
        sock: Socket
        recvRes: TcpFrameResult
        payload: ByteSeq
      args.a = nextUnusedTcpAddress("::1")
      createThread(th, runTransportServer, args)
      sleep(250)
      sock = connectTcp(initTcpAddress("localhost", args.a.port), 4000)
      defer:
        sock.close()
      payload = @[byte 3, 1, 4, 1, 5]
      sendTcpFrame(sock, payload)
      recvRes = recvTcpFrame(sock, 4000)
      joinThread(th)
      check recvRes.ok
      check recvRes.payload == payload

  # {.testKind: tkIntegration.}
  test "tcp ipv6 wildcard listener accepts an ipv4 client":
    if not ipv6LoopbackAvailable():
      skip()
    else:
      var
        listener: Socket
        serverSock: Socket
        clientSock: Socket
        bound: tuple[host: string, port: Port]
        recvRes: TcpFrameResult
        payload: ByteSeq
      listener = listenTcp(initTcpAddress("::", 0'u16))
      defer:
        listener.close()
      bound = listener.getLocalAddr()
      clientSock = connectTcp(initTcpAddress("127.0.0.1", uint16(bound.port)),
        4000)
      defer:
        clientSock.close()
      serverSock = acceptTcpClient(listener)
      defer:
        serverSock.close()
      payload = @[byte 6, 2, 6, 4]
      sendTcpFrame(clientSock, payload)
      recvRes = recvTcpFrame(serverSock, 4000)
      check recvRes.ok
      check recvRes.payload == payload

  when defined(ssl):
    # {.testKind: tkIntegration.}
    test "tls tcp frame roundtrip succeeds with verified localhost certificate":
      var
        th: Thread[TlsTransportServerArgs]
        args: TlsTransportServerArgs
        certs: tuple[certFile: string, keyFile: string]
        sock: Socket
        recvRes: TcpFrameResult
        payload: ByteSeq
      certs = ensureTlsTestCertificate()
      args.e = initTcpEndpoint("127.0.0.1", nextUnusedTcpAddress("127.0.0.1").port,
        initTlsTestServerConfig(certs.certFile, certs.keyFile))
      createThread(th, runTlsTransportServer, args)
      sleep(250)
      sock = connectTcp(initTcpEndpoint("127.0.0.1", args.e.address.port,
        initTlsTestClientConfig(tvmPeer, serverName = "localhost",
        caFile = certs.certFile)), 4000)
      defer:
        sock.close()
      payload = @[byte 2, 0, 2, 6]
      sendTcpFrame(sock, payload)
      recvRes = recvTcpFrame(sock, 4000)
      joinThread(th)
      check recvRes.ok
      check recvRes.payload == payload

    # {.testKind: tkEdgeCase.}
    test "tls tcp peer verification rejects a mismatched server name":
      var
        th: Thread[TlsTransportServerArgs]
        args: TlsTransportServerArgs
        certs: tuple[certFile: string, keyFile: string]
      certs = ensureTlsTestCertificate()
      args.e = initTcpEndpoint("127.0.0.1", nextUnusedTcpAddress("127.0.0.1").port,
        initTlsTestServerConfig(certs.certFile, certs.keyFile))
      createThread(th, runTlsTransportServer, args)
      sleep(250)
      expect CatchableError:
        discard connectTcp(initTcpEndpoint("127.0.0.1", args.e.address.port,
          initTlsTestClientConfig(tvmPeer, serverName = "wrong-host.invalid",
          caFile = certs.certFile)), 4000)
      joinThread(th)

    # {.testKind: tkEdgeCase.}
    test "tls tcp verification-disabled mode ignores hostname mismatch":
      var
        th: Thread[TlsTransportServerArgs]
        args: TlsTransportServerArgs
        certs: tuple[certFile: string, keyFile: string]
        sock: Socket
        recvRes: TcpFrameResult
        payload: ByteSeq
      certs = ensureTlsTestCertificate()
      args.e = initTcpEndpoint("127.0.0.1", nextUnusedTcpAddress("127.0.0.1").port,
        initTlsTestServerConfig(certs.certFile, certs.keyFile))
      createThread(th, runTlsTransportServer, args)
      sleep(250)
      sock = connectTcp(initTcpEndpoint("127.0.0.1", args.e.address.port,
        initTlsTestClientConfig(tvmDisabled, serverName = "wrong-host.invalid")),
        4000)
      defer:
        sock.close()
      payload = @[byte 9, 2, 6, 5]
      sendTcpFrame(sock, payload)
      recvRes = recvTcpFrame(sock, 4000)
      joinThread(th)
      check recvRes.ok
      check recvRes.payload == payload

  # {.testKind: tkEdgeCase.}
  test "send tcp frame rejects payload above caller maximum before write":
    var
      sock: Socket
      payload: ByteSeq
    payload = @[1'u8, 2'u8, 3'u8, 4'u8]
    expect ValueError:
      sendTcpFrame(sock, payload, maxFrameBytes = 3'u32)

  # {.testKind: tkEdgeCase.}
  test "send tcp frame rejects payload above default maximum before write":
    var
      sock: Socket
      payload: ByteSeq
    payload = newSeq[uint8](int(maxTcpFrameBytes) + 1)
    expect ValueError:
      sendTcpFrame(sock, payload)

  # {.testKind: tkIntegration.}
  test "protocol stream frame roundtrips and reports consumed bytes":
    var
      payload: ByteSeq
      frame: ByteSeq
      tail: ByteSeq
      decoded: ProtocolStreamFrameResult
    payload = @[1'u8, 2'u8, 3'u8, 4'u8]
    tail = @[99'u8, 100'u8]
    frame = encodeProtocolStreamFrame(payload)
    for b in tail:
      frame.add(b)
    decoded = decodeProtocolStreamFrame(frame)
    check decoded.ok
    check not decoded.needMore
    check decoded.consumed == 8
    check decoded.payload == payload

  # {.testKind: tkEdgeCase.}
  test "protocol stream frame rejects oversized declared lengths":
    var
      frame: ByteSeq
      decoded: ProtocolStreamFrameResult
    frame = @[5'u8, 0'u8, 0'u8, 0'u8, 1'u8, 2'u8, 3'u8, 4'u8, 5'u8]
    decoded = decodeProtocolStreamFrame(frame, maxFrameBytes = 4'u32)
    check not decoded.ok
    check not decoded.needMore
    check decoded.err == "stream frame length exceeds maximum"

  # {.testKind: tkIntegration.}
  test "protocol stream batch handles many frames and trailing partial data":
    var
      first: ByteSeq
      second: ByteSeq
      buffer: ByteSeq
      decoded: ProtocolStreamBatchResult
    first = encodeProtocolStreamFrame(@[9'u8, 8'u8])
    second = encodeProtocolStreamFrame(@[7'u8])
    buffer = @[]
    for b in first:
      buffer.add(b)
    for b in second:
      buffer.add(b)
    buffer.add(3'u8)
    buffer.add(0'u8)
    decoded = decodeProtocolStreamFrames(buffer)
    check decoded.ok
    check decoded.needMore
    check decoded.consumed == first.len + second.len
    check decoded.frames.len == 2
    check decoded.frames[0] == @[9'u8, 8'u8]
    check decoded.frames[1] == @[7'u8]

  # {.testKind: tkIntegration.}
  test "send and receive udp datagram":
    var
      th: Thread[UdpServerArgs]
      args: UdpServerArgs
      sock: Socket
      recvRes: UdpDatagramResult
      payload: ByteSeq
    args.a = initUdpAddress("127.0.0.1", 49004'u16)
    createThread(th, runUdpServer, args)
    sleep(250)
    sock = connectUdp(args.a, 4000)
    defer:
      sock.close()
    payload = @[4'u8, 5'u8, 6'u8, 7'u8]
    sendUdpDatagram(sock, payload)
    recvRes = recvUdpDatagram(sock, 4096, 4000)
    joinThread(th)
    check recvRes.ok
    check recvRes.payload == payload

  # {.testKind: tkIntegration.}
  test "udp localhost reaches an ipv6-only listener":
    if not ipv6LoopbackAvailable():
      skip()
    else:
      var
        th: Thread[UdpServerArgs]
        args: UdpServerArgs
        sock: Socket
        recvRes: UdpDatagramResult
        payload: ByteSeq
      args.a = nextUnusedUdpAddress("::1")
      createThread(th, runUdpServer, args)
      sleep(250)
      sock = connectUdp(initUdpAddress("localhost", args.a.port), 4000)
      defer:
        sock.close()
      payload = @[byte 2, 7, 1, 8]
      sendUdpDatagram(sock, payload)
      recvRes = recvUdpDatagram(sock, 4096, 4000)
      joinThread(th)
      check recvRes.ok
      check recvRes.payload == payload

  # {.testKind: tkIntegration.}
  test "udp explicit localhost sendTo reaches an ipv6-only listener":
    if not ipv6LoopbackAvailable():
      skip()
    else:
      var
        th: Thread[UdpServerArgs]
        args: UdpServerArgs
        sock: Socket
        recvRes: UdpDatagramResult
        payload: ByteSeq
      args.a = nextUnusedUdpAddress("::1")
      createThread(th, runUdpServer, args)
      sleep(250)
      sock = bindUdp(initUdpAddress("::", 0'u16))
      defer:
        sock.close()
      payload = @[byte 5, 0, 5, 0]
      sendUdpDatagram(sock, initUdpAddress("localhost", args.a.port), payload)
      recvRes = recvUdpDatagram(sock, 4096, 4000)
      joinThread(th)
      check recvRes.ok
      check recvRes.payload == payload

  # {.testKind: tkIntegration.}
  test "udp ipv6 wildcard listener accepts an ipv4 client":
    if not ipv6LoopbackAvailable():
      skip()
    else:
      var
        server: Socket
        client: Socket
        bound: tuple[host: string, port: Port]
        recvRes: UdpDatagramResult
        payload: ByteSeq
      server = bindUdp(initUdpAddress("::", 0'u16))
      defer:
        server.close()
      bound = server.getLocalAddr()
      client = connectUdp(initUdpAddress("127.0.0.1", uint16(bound.port)), 4000)
      defer:
        client.close()
      payload = @[byte 1, 6, 1, 8]
      sendUdpDatagram(client, payload)
      recvRes = recvUdpDatagram(server, 4096, 4000)
      check recvRes.ok
      check recvRes.payload == payload

  # {.testKind: tkIntegration.}
  test "raw close on localhost DAC peer does not poison a later reused fd":
    var
      staleListener: DacSocket
      targetListener: DacSocket
      staleBound: tuple[host: string, port: Port]
      targetBound: tuple[host: string, port: Port]
      staleSock: DacSocket
      candidate: DacSocket
      staleFd: int = -1
      payload: ByteSeq = @[byte 0xD0, byte 0xAC, byte 0x7F]
      staleRecv: DacFrameBytesResult
      targetRecv: DacFrameBytesResult
    staleListener = openDacListener(initDacAddress("127.0.0.1", 0'u16))
    defer:
      closeDac(staleListener)
    targetListener = openDacListener(initDacAddress("127.0.0.1", 0'u16))
    defer:
      closeDac(targetListener)
    staleBound = staleListener.getLocalAddr()
    targetBound = targetListener.getLocalAddr()

    staleSock = openDacPeer(initDacAddress("localhost", uint16(staleBound.port)), 4000)
    staleFd = int(staleSock.getFd())
    staleSock.close()

    candidate = reopenDacPeerUntilFd(
      initDacAddress("127.0.0.1", uint16(targetBound.port)), staleFd)
    defer:
      closeDac(candidate)

    sendDacFrameBytes(candidate, payload)
    staleRecv = recvDacFrameBytes(staleListener, 1024, 50)
    targetRecv = recvDacFrameBytes(targetListener, 1024, 4000)
    check not staleRecv.ok
    check targetRecv.ok
    if targetRecv.ok:
      check targetRecv.payload == payload
