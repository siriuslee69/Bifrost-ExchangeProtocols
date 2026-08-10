## ----------------------------------------------------------------
## TCP Ops <- generic framed TCP helpers for protocol repos (IPv4/6)
## ----------------------------------------------------------------

import std/[net, nativesockets, options, strutils]
when not defined(windows):
  import std/posix

import ../types
import ./types
import ./tls_ops
import ../../analysis_pragmas

const
  maxTcpFrameBytes* = 16_777_216'u32

proc encodeLen32*(v: uint32): string {.role: wrapper.} =
  ## encodeLen32: encode len 32.
  result = newString(4)
  result[0] = char(int(v and 0xFF'u32))
  result[1] = char(int((v shr 8) and 0xFF'u32))
  result[2] = char(int((v shr 16) and 0xFF'u32))
  result[3] = char(int((v shr 24) and 0xFF'u32))

proc decodeLen32*(s: string): uint32 {.role: parser.} =
  ## decodeLen32: decode len 32.
  if s.len != 4:
    return 0'u32
  result = uint32(uint8(s[0])) or
    (uint32(uint8(s[1])) shl 8) or
    (uint32(uint8(s[2])) shl 16) or
    (uint32(uint8(s[3])) shl 24)

proc normalizeHostLiteral(h: string): string {.role: parser.} =
  ## normalizeHostLiteral: normalize host literal.
  result = h.strip()
  if result.len >= 2 and result[0] == '[' and result[^1] == ']':
    result = result[1 .. ^2]

proc isIpv6Host(h: string): bool {.role: helper.} =
  ## isIpv6Host: build is ipv 6 host.
  var
    clean: string
  clean = normalizeHostLiteral(h)
  result = clean.contains(':')

type
  ResolvedTcpTarget = object
    host: string
    domain: Domain

proc addResolvedTcpTarget(order: var seq[ResolvedTcpTarget], host: string,
    d: Domain) {.role: stateController.} =
  ## order: unique resolution order collected for one host name.
  ## host/d: newly resolved literal host and matching socket family.
  var
    i: int = 0
  while i < order.len:
    if order[i].domain == d and order[i].host == host:
      return
    i = i + 1
  order.add(ResolvedTcpTarget(host: host, domain: d))

proc resolvedTcpTargets(h: string): seq[ResolvedTcpTarget] {.role: helper.} =
  ## h: TCP host literal or hostname whose concrete targets should be tried.
  var
    clean: string
    aiList: ptr AddrInfo = nil
    it: ptr AddrInfo = nil
    known: Option[Domain]
    literal: string = ""
  clean = normalizeHostLiteral(h)
  if isIpv6Host(clean):
    result.add(ResolvedTcpTarget(host: clean, domain: AF_INET6))
    return
  if clean.toLowerAscii() == "localhost":
    addResolvedTcpTarget(result, "::1", AF_INET6)
    addResolvedTcpTarget(result, "127.0.0.1", AF_INET)
    return
  try:
    aiList = getAddrInfo(clean, Port(0), AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP)
    it = aiList
    while it != nil:
      known = toKnownDomain(it.ai_family)
      if known.isSome and known.get() != AF_UNSPEC:
        literal = getAddrString(it.ai_addr)
        addResolvedTcpTarget(result, normalizeHostLiteral(literal), known.get())
      it = it.ai_next
  except CatchableError:
    discard
  finally:
    if aiList != nil:
      freeAddrInfo(aiList)
  if result.len == 0:
    result.add(ResolvedTcpTarget(host: clean, domain: AF_INET))

proc formatHostPort(h: string, p: uint16): string {.role: helper.} =
  ## formatHostPort: format host port.
  var
    clean: string
  clean = normalizeHostLiteral(h)
  if isIpv6Host(clean):
    result = "[" & clean & "]:" & $p
  else:
    result = clean & ":" & $p

proc maybeEnableDualStackWildcard(sock: Socket, host: string) {.role: helper.} =
  ## sock: IPv6 listener candidate whose wildcard bind may need dual-stack mode.
  ## host: normalized bind host literal.
  if host != "::":
    return
  when not defined(windows):
    try:
      setSockOptInt(sock.getFd(), int(toInt(IPPROTO_IPV6)), int(posix.IPV6_V6ONLY),
        0)
    except CatchableError:
      discard

proc parseHostPort(rawInput: string, scheme: string):
    tuple[ok: bool, host: string, port: uint16] {.role: parser.} =
  ## parseHostPort: parse host port.
  var
    raw: string
    idx: int
    endBracket: int
    hostPart: string
    portRaw: string
    p: int
  raw = rawInput.strip()
  if raw.len == 0:
    return
  if raw.startsWith(scheme):
    raw = raw[scheme.len .. ^1]
  elif raw.find("://") >= 0:
    return
  raw = raw.strip()
  if raw.len == 0:
    return
  if raw.find("://") >= 0:
    return

  if raw[0] == '[':
    endBracket = raw.find(']')
    if endBracket <= 0:
      return
    if endBracket + 2 >= raw.len or raw[endBracket + 1] != ':':
      return
    hostPart = raw[1 ..< endBracket]
    portRaw = raw[endBracket + 2 .. ^1]
  else:
    idx = raw.rfind(':')
    if idx <= 0 or idx >= raw.len - 1:
      return
    hostPart = raw[0 ..< idx]
    portRaw = raw[idx + 1 .. ^1]
    if raw.find(':') != idx:
      return

  hostPart = normalizeHostLiteral(hostPart)
  if hostPart.len == 0:
    return
  try:
    hostPart = initTcpAddress(hostPart, 1'u16).host
  except ValueError:
    return

  try:
    p = parseInt(portRaw)
    if p <= 0 or p > int(high(uint16)):
      return
    result.ok = true
    result.host = hostPart
    result.port = uint16(p)
  except CatchableError:
    result.ok = false

proc tcpDomainForHost(h: string): Domain {.role: helper.} =
  ## tcpDomainForHost: build TCP domain for host.
  result = resolvedTcpTargets(h)[0].domain

proc formatTcpAddress*(a: TcpAddress): string {.role: wrapper.} =
  ## formatTcpAddress: format TCP address.
  result = formatHostPort(a.host, a.port)

proc parseTcpAddress*(s: string): tuple[ok: bool, a: TcpAddress] {.role: parser.} =
  ## parseTcpAddress: parse TCP address.
  var
    p: tuple[ok: bool, host: string, port: uint16]
  p = parseHostPort(s, "tcp://")
  if not p.ok:
    return
  result.a.host = p.host
  result.a.port = p.port
  result.ok = true

proc sendTcpFrame*(sock: Socket, bs: ByteSeq,
    maxFrameBytes: uint32 = maxTcpFrameBytes) {.role: orchestrator.} =
  ## sock: connected TCP socket.
  ## bs: payload bytes to send as one length-prefixed frame.
  ## maxFrameBytes: maximum accepted payload length before writing.
  var
    body: string
    head: string
  if uint64(bs.len) > uint64(high(uint32)):
    raise newException(ValueError, "TCP frame payload exceeds uint32 length")
  if uint64(bs.len) > uint64(maxFrameBytes):
    raise newException(ValueError, "TCP frame payload exceeds maximum")
  body = bytesToString(bs)
  head = encodeLen32(uint32(bs.len))
  sock.send(head)
  if body.len > 0:
    sock.send(body)

proc recvExact(sock: Socket, n, timeoutMs: int):
    tuple[ok: bool, data: string, err: string] {.role: helper.} =
  ## sock: connected TCP socket.
  ## n: exact number of bytes to read.
  ## timeoutMs: per-read timeout.
  var
    chunk: string = ""
  result.data = ""
  while result.data.len < n:
    try:
      chunk = sock.recv(n - result.data.len, timeoutMs)
    except CatchableError as e:
      result.ok = false
      result.err = e.msg
      return
    if chunk.len == 0:
      result.ok = false
      result.err = ""
      return
    result.data.add(chunk)
  result.ok = true
  result.err = ""

proc recvTcpFrame*(sock: Socket, timeoutMs: int,
    maxFrameBytes: uint32 = maxTcpFrameBytes): TcpFrameResult {.role: orchestrator.} =
  ## recvTcpFrame: receive TCP frame.
  var
    head: string
    body: string
    n: uint32
    exact: tuple[ok: bool, data: string, err: string]
  exact = recvExact(sock, 4, timeoutMs)
  if not exact.ok:
    result.ok = false
    if exact.err.len > 0:
      result.err = exact.err
    else:
      result.err = "failed to read frame length"
    return
  head = exact.data
  n = decodeLen32(head)
  if n > maxFrameBytes:
    result.ok = false
    result.err = "frame length exceeds maximum"
    return
  if n == 0'u32:
    result.ok = true
    result.payload = @[]
    result.err = ""
    return
  exact = recvExact(sock, int(n), timeoutMs)
  if not exact.ok:
    result.ok = false
    if exact.err.len > 0:
      result.err = exact.err
    else:
      result.err = "failed to read full frame payload"
    return
  body = exact.data
  result.ok = true
  result.payload = stringToBytes(body)
  result.err = ""

proc connectTcp*(a: TcpAddress, timeoutMs: int,
    t: TlsConfig = defaultTlsConfig()): Socket {.role: orchestrator.} =
  ## connectTcp: connect TCP.
  var
    host: string
    targets: seq[ResolvedTcpTarget] = @[]
    sock: Socket
    lastErr: string = ""
  host = normalizeHostLiteral(a.host)
  targets = resolvedTcpTargets(host)
  for target in targets:
    sock = newSocket(target.domain, SOCK_STREAM, IPPROTO_TCP)
    try:
      sock.connect(target.host, Port(a.port), timeoutMs)
      if t.enabled:
        wrapSocketTls(sock, t, trClient, host)
      return sock
    except CatchableError as e:
      lastErr = e.msg
      try:
        sock.close()
      except CatchableError:
        discard
  if lastErr.len == 0:
    lastErr = "failed to connect TCP socket"
  raise newException(IOError, lastErr)

proc connectTcp*(e: TcpEndpoint, timeoutMs: int): Socket {.role: orchestrator.} =
  ## connectTcp: connect TCP.
  result = connectTcp(e.address, timeoutMs, e.tls)

proc listenTcp*(a: TcpAddress): Socket {.role: orchestrator.} =
  ## listenTcp: listen TCP.
  var
    host: string
  host = normalizeHostLiteral(a.host)
  result = newSocket(tcpDomainForHost(host), SOCK_STREAM, IPPROTO_TCP)
  result.setSockOpt(OptReuseAddr, true)
  maybeEnableDualStackWildcard(result, host)
  result.bindAddr(Port(a.port), host)
  result.listen()

proc listenTcp*(e: TcpEndpoint): Socket {.role: orchestrator.} =
  ## listenTcp: listen TCP.
  result = listenTcp(e.address)

proc acceptTcpClient*(sock: Socket,
    t: TlsConfig = defaultTlsConfig()): Socket {.role: orchestrator.} =
  ## acceptTcpClient: accept TCP client.
  var
    c: owned(Socket)
  sock.accept(c)
  result = c
  if t.enabled:
    try:
      wrapSocketTls(result, t, trServer)
    except CatchableError:
      try:
        result.close()
      except CatchableError:
        discard
      raise

proc acceptTcpClient*(sock: Socket, e: TcpEndpoint): Socket {.role: orchestrator.} =
  ## acceptTcpClient: accept TCP client.
  result = acceptTcpClient(sock, e.tls)
