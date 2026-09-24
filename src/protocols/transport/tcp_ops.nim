## ----------------------------------------------------------------
## TCP Ops <- generic framed TCP helpers for protocol repos (IPv4/6)
## ----------------------------------------------------------------

import std/[net, nativesockets, options, strutils]
when not defined(windows):
  import std/posix

import ../types
import ./types
import ./tls_ops
import ./socket_write
import runePragmas

const
  maxTcpFrameBytes* = 16_777_216'u32

proc encodeLen32*(v: uint32): string {.role: helper.} =
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
    d: Domain) {.role: dataWriter.} =
  ## order: unique resolution order collected for one host name.
  ## host/d: newly resolved literal host and matching socket family.
  var
    i: int = 0
  while i < order.len:
    if order[i].domain == d and order[i].host == host:
      return
    i = i + 1
  order.add(ResolvedTcpTarget(host: host, domain: d))

proc collectTcpTargets(R: var seq[ResolvedTcpTarget], aiList: ptr AddrInfo) {.
    role: truthBuilder.} =
  ## R/aiList: every address the resolver returned, in a family we know.
  var
    it: ptr AddrInfo = aiList
    known: Option[Domain] = none(Domain)
  while it != nil:
    known = toKnownDomain(it.ai_family)
    if known.isSome and known.get() != AF_UNSPEC:
      addResolvedTcpTarget(R, normalizeHostLiteral(getAddrString(it.ai_addr)), known.get())
    it = it.ai_next

proc resolvedTcpTargets(h: string): seq[ResolvedTcpTarget] {.role: helper.} =
  ## h: TCP host literal or hostname whose concrete targets should be tried.
  var
    clean: string
    aiList: ptr AddrInfo = nil
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
    collectTcpTargets(result, aiList)
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

proc formatTcpAddress*(a: TcpAddress): string {.role: truthBuilder.} =
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

proc requireTcpFrameSendable*(n: int,
    maxFrameBytes: uint32 = maxTcpFrameBytes) {.role: parser.} =
  ## n/maxFrameBytes: payload length and limit. The checks `sendTcpFrame`
  ## makes before its first byte, callable on their own so a caller can
  ## still undo work when they fail.
  if uint64(n) > uint64(high(uint32)):
    raise newException(ValueError, "TCP frame payload exceeds uint32 length")
  if uint64(n) > uint64(maxFrameBytes):
    raise newException(ValueError, "TCP frame payload exceeds maximum")

proc sendTcpFrame*(sock: Socket, bs: ByteSeq,
    maxFrameBytes: uint32 = maxTcpFrameBytes) {.role: orchestrator.} =
  ## sock: connected TCP socket.
  ## bs: payload bytes to send as one length-prefixed frame.
  ## maxFrameBytes: maximum accepted payload length before writing.
  var
    body: string = ""
    head: string = ""
  requireTcpFrameSendable(bs.len, maxFrameBytes)
  body = bytesToString(bs)
  head = encodeLen32(uint32(bs.len))
  writeAllSocket(sock, head)
  if body.len > 0:
    writeAllSocket(sock, body)

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

proc openTcpTarget(target: ResolvedTcpTarget, port: uint16, timeoutMs: int,
    t: TlsConfig, host: string): Socket {.role: orchestrator.} =
  ## target/port/timeoutMs: connect to one resolved address; t/host: wrap
  ## it in TLS when enabled. A failure closes the socket and raises.
  result = newSocket(target.domain, SOCK_STREAM, IPPROTO_TCP)
  try:
    result.connect(target.host, Port(port), timeoutMs)
    if t.enabled:
      wrapSocketTls(result, t, trClient, host)
  except CatchableError:
    closeSocketQuietly(result)
    raise

proc connectTcp*(a: TcpAddress, timeoutMs: int,
    t: TlsConfig = defaultTlsConfig()): Socket {.role: orchestrator.} =
  ## connectTcp: connect TCP.
  var
    host: string
    targets: seq[ResolvedTcpTarget] = @[]
    lastErr: string = ""
  host = normalizeHostLiteral(a.host)
  targets = resolvedTcpTargets(host)
  for target in targets:
    try:
      return openTcpTarget(target, a.port, timeoutMs, t, host)
    except CatchableError as e:
      lastErr = e.msg
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
      closeSocketQuietly(result)
      raise

proc acceptTcpClient*(sock: Socket, e: TcpEndpoint): Socket {.role: orchestrator.} =
  ## acceptTcpClient: accept TCP client.
  result = acceptTcpClient(sock, e.tls)
