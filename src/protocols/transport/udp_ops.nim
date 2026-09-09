## -------------------------------------------------------
## UDP Ops <- generic datagram UDP helpers for protocol repos
## -------------------------------------------------------

import std/[net, nativesockets, options, strutils]
when not defined(windows):
  import std/posix

import ../types
import ./types
import runePragmas

proc formatUdpAddress*(a: UdpAddress): string {.role: truthBuilder.} =
  ## formatUdpAddress: format UDP address.
  var
    host: string
  host = a.host.strip()
  if host.len >= 2 and host[0] == '[' and host[^1] == ']':
    host = host[1 .. ^2]
  if host.contains(':'):
    result = "[" & host & "]:" & $a.port
  else:
    result = host & ":" & $a.port

proc normalizeUdpHost(h: string): string {.role: parser.} =
  ## normalizeUdpHost: normalize UDP host.
  result = h.strip()
  if result.len >= 2 and result[0] == '[' and result[^1] == ']':
    result = result[1 .. ^2]

type
  ResolvedUdpTarget = object
    host: string
    domain: Domain

proc addResolvedUdpTarget(order: var seq[ResolvedUdpTarget], host: string,
    d: Domain) {.role: dataWriter.} =
  ## order: unique resolution order collected for one host name.
  ## host/d: newly resolved literal host and matching socket family.
  var
    i: int = 0
  while i < order.len:
    if order[i].domain == d and order[i].host == host:
      return
    i = i + 1
  order.add(ResolvedUdpTarget(host: host, domain: d))

proc resolvedUdpTargets(h: string): seq[ResolvedUdpTarget] {.role: helper.} =
  ## h: UDP host literal or hostname whose concrete targets should be tried.
  var
    clean: string
    aiList: ptr AddrInfo = nil
    it: ptr AddrInfo = nil
    known: Option[Domain]
    literal: string = ""
  clean = normalizeUdpHost(h)
  if clean.contains(':'):
    result.add(ResolvedUdpTarget(host: clean, domain: AF_INET6))
    return
  if clean.toLowerAscii() == "localhost":
    addResolvedUdpTarget(result, "::1", AF_INET6)
    addResolvedUdpTarget(result, "127.0.0.1", AF_INET)
    return
  try:
    aiList = getAddrInfo(clean, Port(0), AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP)
    it = aiList
    while it != nil:
      known = toKnownDomain(it.ai_family)
      if known.isSome and known.get() != AF_UNSPEC:
        literal = getAddrString(it.ai_addr)
        addResolvedUdpTarget(result, normalizeUdpHost(literal), known.get())
      it = it.ai_next
  except CatchableError:
    discard
  finally:
    if aiList != nil:
      freeAddrInfo(aiList)
  if result.len == 0:
    result.add(ResolvedUdpTarget(host: clean, domain: AF_INET))

proc parseUdpHostPort(rawInput: string): tuple[ok: bool, host: string, port: uint16] {.role: parser.} =
  ## parseUdpHostPort: parse UDP host port.
  var
    raw: string
    idx: int = 0
    endBracket: int = 0
    hostPart: string = ""
    portRaw: string = ""
    p: int = 0
  raw = rawInput.strip()
  if raw.len == 0:
    return
  if raw.startsWith("udp://"):
    raw = raw[6 .. ^1]
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

  hostPart = normalizeUdpHost(hostPart)
  if hostPart.len == 0:
    return
  try:
    hostPart = initUdpAddress(hostPart, 1'u16).host
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

proc udpDomainForHost(h: string): Domain {.role: helper.} =
  ## udpDomainForHost: build UDP domain for host.
  result = resolvedUdpTargets(h)[0].domain

proc wildcardUdpBindHost*(h: string): string {.role: helper.} =
  ## h: remote or configured UDP host whose resolved family selects wildcard bind.
  if udpDomainForHost(h) == AF_INET6:
    result = "::"
  else:
    result = "0.0.0.0"

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

proc parseUdpAddress*(s: string): tuple[ok: bool, a: UdpAddress] {.role: parser.} =
  ## parseUdpAddress: parse UDP address.
  var
    p: tuple[ok: bool, host: string, port: uint16]
  p = parseUdpHostPort(s)
  if not p.ok:
    return
  result.a.host = p.host
  result.a.port = p.port
  result.ok = true

proc bindUdp*(a: UdpAddress): Socket {.role: truthBuilder.} =
  ## bindUdp: build bind UDP.
  var
    host: string
  host = normalizeUdpHost(a.host)
  result = newSocket(udpDomainForHost(host), SOCK_DGRAM, IPPROTO_UDP)
  result.setSockOpt(OptReuseAddr, true)
  maybeEnableDualStackWildcard(result, host)
  result.bindAddr(Port(a.port), host)

proc connectUdp*(a: UdpAddress, timeoutMs: int = 4000): Socket {.role: orchestrator.} =
  ## connectUdp: connect UDP.
  var
    host: string
    targets: seq[ResolvedUdpTarget] = @[]
    sock: Socket
    lastErr: string = ""
  host = normalizeUdpHost(a.host)
  targets = resolvedUdpTargets(host)
  for target in targets:
    sock = newSocket(target.domain, SOCK_DGRAM, IPPROTO_UDP)
    try:
      sock.connect(target.host, Port(a.port), timeoutMs)
      return sock
    except CatchableError as e:
      lastErr = e.msg
      try:
        sock.close()
      except CatchableError:
        discard
  if lastErr.len == 0:
    lastErr = "failed to connect UDP socket"
  raise newException(IOError, lastErr)

proc sendUdpDatagram*(sock: Socket, bs: ByteSeq) {.role: orchestrator.} =
  ## sendUdpDatagram: send UDP datagram.
  var
    body: string
  body = bytesToString(bs)
  if body.len == 0:
    return
  sock.send(body)

proc sendUdpDatagram*(sock: Socket, a: UdpAddress, bs: ByteSeq) {.role: orchestrator.} =
  ## sendUdpDatagram: send UDP datagram.
  var
    body: string
    host: string
    targets: seq[ResolvedUdpTarget] = @[]
    lastErr: string = ""
  body = bytesToString(bs)
  if body.len == 0:
    return
  host = normalizeUdpHost(a.host)
  targets = resolvedUdpTargets(host)
  for target in targets:
    try:
      sock.sendTo(target.host, Port(a.port), cstring(body), body.len,
        target.domain)
      return
    except CatchableError as e:
      lastErr = e.msg
  if lastErr.len == 0:
    lastErr = "failed to send UDP datagram"
  raise newException(IOError, lastErr)

proc recvUdpDatagram*(sock: Socket, maxBytes: int,
    timeoutMs: int = 4000): UdpDatagramResult {.role: orchestrator.} =
  ## recvUdpDatagram: receive UDP datagram.
  var
    fds: seq[SocketHandle] = @[]
    body: string
    host: string = ""
    port: Port = Port(0)
    n: int = 0
  if maxBytes <= 0:
    result.ok = false
    result.err = "invalid max datagram size"
    return
  fds = @[sock.getFd()]
  if selectRead(fds, timeoutMs) <= 0:
    result.ok = false
    result.err = "timed out waiting for datagram"
    return
  body = newString(maxBytes)
  try:
    n = sock.recvFrom(body, maxBytes, host, port)
  except CatchableError as e:
    result.ok = false
    result.err = e.msg
    return
  if n < 0:
    result.ok = false
    result.err = "failed to receive datagram"
    return
  body.setLen(n)
  result.ok = true
  result.payload = stringToBytes(body)
  result.remote = initUdpAddress(host, uint16(port))
  result.err = ""
