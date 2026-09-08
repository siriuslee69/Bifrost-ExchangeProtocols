## -----------------------------------------------------------------
## DAC Transport <- DAC socket helpers around the active carrier
## -----------------------------------------------------------------

import std/[locks, net, strutils]

import ../../types
import ../types as dac_types
import ../../transport/types as transport_types
import ../../transport/udp_ops as udp_ops
import bifrostPragmas

export DacAddress

type
  ## DacSocket: DAC endpoint handle. The concrete socket type remains hidden
  ## behind DAC-named send/receive helpers at higher layers.
  DacSocket* = Socket

  ## DacFrameBytesResult: one received encoded DAC frame and its remote peer.
  DacFrameBytesResult* {.role: truthState.} = object
    ok*: bool
    payload*: ByteSeq
    remote*: DacAddress
    err*: string

type
  LocalhostDacPeerEntry = object
    key: int
    port: uint16
    localPort: uint16
    next: ptr LocalhostDacPeerEntry

var
  dacPeerRegistryLock: Lock
  dacLocalhostPeerRegistry: ptr LocalhostDacPeerEntry

initLock(dacPeerRegistryLock)

proc dacPeerSockKey(sock: DacSocket): int {.role: helper.} =
  ## sock: DAC socket whose fd identifies any remembered peer mapping.
  result = int(sock.getFd())

proc dacLocalPort*(sock: DacSocket): tuple[ok: bool, port: uint16] {.
    role: helper.} =
  ## sock: DAC socket whose current bound local port should be loaded.
  ## Public because binding to port 0 is the normal way to take an ephemeral
  ## port, and the caller then has no other way to learn which one it got.
  var
    bound: tuple[host: string, port: Port]
  try:
    bound = sock.getLocalAddr()
    result.ok = true
    result.port = uint16(bound.port)
  except CatchableError:
    discard

proc dacSocketHasPeer(sock: DacSocket): bool {.role: helper.} =
  ## sock: DAC socket whose connected-peer state distinguishes connected sockets
  ## from the unconnected localhost fanout sockets tracked here.
  var
    peerHost: string
    peerPort: Port
  try:
    (peerHost, peerPort) = sock.getPeerAddr()
    discard peerHost
    discard peerPort
    result = true
  except CatchableError:
    result = false

proc unlinkLocalhostDacPeer(prev, node: ptr LocalhostDacPeerEntry) {.
    role: actor.} =
  ## prev/node: linked-list cursor for removing a stale remembered peer entry.
  if prev == nil:
    dacLocalhostPeerRegistry = node[].next
  else:
    prev[].next = node[].next
  deallocShared(node)

proc rememberLocalhostDacPeer(sock: DacSocket, port: uint16) {.
    role: actor.} =
  ## sock/port: remember that this socket should fan out to localhost loopback
  ## aliases for the given DAC port.
  var
    node: ptr LocalhostDacPeerEntry = nil
    key: int = dacPeerSockKey(sock)
    localPort: tuple[ok: bool, port: uint16]
  localPort = dacLocalPort(sock)
  if not localPort.ok:
    raise newException(IOError,
      "failed to load localhost DAC peer local port")
  acquire(dacPeerRegistryLock)
  try:
    node = dacLocalhostPeerRegistry
    while node != nil:
      if node[].key == key:
        node[].port = port
        node[].localPort = localPort.port
        return
      node = node[].next
    node = cast[ptr LocalhostDacPeerEntry](
      allocShared0(sizeof(LocalhostDacPeerEntry)))
    if node == nil:
      raise newException(IOError,
        "failed to allocate localhost DAC peer registry entry")
    node[].key = key
    node[].port = port
    node[].localPort = localPort.port
    node[].next = dacLocalhostPeerRegistry
    dacLocalhostPeerRegistry = node
  finally:
    release(dacPeerRegistryLock)

proc forgetDacPeer(sock: DacSocket) {.role: actor.} =
  ## sock: DAC socket whose remembered logical remote should be cleared.
  var
    key: int = dacPeerSockKey(sock)
    node: ptr LocalhostDacPeerEntry = nil
    prev: ptr LocalhostDacPeerEntry = nil
  acquire(dacPeerRegistryLock)
  try:
    node = dacLocalhostPeerRegistry
    while node != nil:
      if node[].key == key:
        if prev == nil:
          dacLocalhostPeerRegistry = node[].next
        else:
          prev[].next = node[].next
        deallocShared(node)
        return
      prev = node
      node = node[].next
  finally:
    release(dacPeerRegistryLock)

proc lookupLocalhostDacPeer(sock: DacSocket): tuple[ok: bool, port: uint16] {.
    role: helper.} =
  ## sock: DAC socket whose localhost fanout mapping should be loaded.
  var
    key: int = dacPeerSockKey(sock)
    node: ptr LocalhostDacPeerEntry = nil
    prev: ptr LocalhostDacPeerEntry = nil
    localPort: tuple[ok: bool, port: uint16]
    hasPeer: bool = false
  localPort = dacLocalPort(sock)
  hasPeer = dacSocketHasPeer(sock)
  acquire(dacPeerRegistryLock)
  try:
    node = dacLocalhostPeerRegistry
    while node != nil:
      if node[].key == key:
        if hasPeer or not localPort.ok or node[].localPort != localPort.port:
          unlinkLocalhostDacPeer(prev, node)
          return
        result.ok = true
        result.port = node[].port
        return
      prev = node
      node = node[].next
  finally:
    release(dacPeerRegistryLock)

proc stripDacScheme(s: string): string {.role: parser.} =
  ## s: caller-provided DAC endpoint string.
  result = s.strip()
  if result.startsWith("dac://"):
    result = result[6 .. ^1]

proc initDacAddress*(h: string, p: uint16): DacAddress {.role: configurator.} =
  ## h: peer host name or IP address.
  ## p: DAC service port.
  var carrier = transport_types.initUdpAddress(h, p)
  result.host = carrier.host
  result.port = carrier.port

proc carrierAddressFromDac(a: DacAddress): transport_types.UdpAddress {.
    role: truthBuilder.} =
  ## a: DAC endpoint to pass into the active packet carrier.
  result.host = a.host
  result.port = a.port

proc dacAddressFromCarrier(a: transport_types.UdpAddress): DacAddress {.
    role: truthBuilder.} =
  ## a: carrier endpoint returned by the active packet backend.
  result.host = a.host
  result.port = a.port

proc parseDacAddress*(s: string): tuple[ok: bool, a: DacAddress] {.
    role: parser.} =
  ## s: `dac://host:port` or `host:port`.
  var
    raw: string
    parsed: tuple[ok: bool, a: transport_types.UdpAddress]
  raw = s.strip()
  if raw.find("://") >= 0 and not raw.startsWith("dac://"):
    return
  raw = stripDacScheme(raw)
  if raw.find("://") >= 0:
    return
  parsed = udp_ops.parseUdpAddress(raw)
  result.ok = parsed.ok
  result.a = dacAddressFromCarrier(parsed.a)

proc formatDacAddress*(a: DacAddress): string {.role: truthBuilder.} =
  ## a: DAC endpoint to render.
  result = "dac://" & udp_ops.formatUdpAddress(carrierAddressFromDac(a))

proc openDacListener*(a: DacAddress): DacSocket {.role: truthBuilder.} =
  ## a: local DAC endpoint to bind for inbound frames.
  result = udp_ops.bindUdp(carrierAddressFromDac(a))

proc openDacPeer*(a: DacAddress, timeoutMs: int = 4000): DacSocket {.
    role: orchestrator.} =
  ## a: remote DAC endpoint for outbound frames.
  ## timeoutMs: backend connect/setup timeout.
  if a.host.strip().toLowerAscii() == "localhost":
    discard timeoutMs
    result = openDacListener(initDacAddress(udp_ops.wildcardUdpBindHost(a.host),
      0'u16))
    rememberLocalhostDacPeer(result, a.port)
    return
  result = udp_ops.connectUdp(carrierAddressFromDac(a), timeoutMs)

proc sendDacFrameBytes*(sock: DacSocket, a: DacAddress,
    bs: ByteSeq) {.role: orchestrator.}

proc closeDac*(sock: DacSocket) {.role: orchestrator.} =
  ## sock: DAC endpoint handle to close.
  forgetDacPeer(sock)
  sock.close()

proc pinLocalhostDacPeer*(sock: DacSocket, a: DacAddress,
    timeoutMs: int = 4000) {.role: orchestrator.} =
  ## sock: DAC socket returned by `openDacPeer("localhost", ...)`.
  ## a: concrete peer endpoint that authenticated on the loopback socket.
  ## timeoutMs: backend connect/setup timeout for pinning the socket.
  var
    peer: tuple[ok: bool, port: uint16]
  peer = lookupLocalhostDacPeer(sock)
  if not peer.ok:
    return
  sock.connect(a.host, Port(a.port), timeoutMs)
  forgetDacPeer(sock)

proc sendDacFrameBytes*(sock: DacSocket, bs: ByteSeq) {.role: orchestrator.} =
  ## sock: DAC endpoint handle.
  ## bs: complete encoded DAC frame bytes.
  var
    peer: tuple[ok: bool, port: uint16]
  peer = lookupLocalhostDacPeer(sock)
  if peer.ok:
    sendDacFrameBytes(sock, initDacAddress("localhost", peer.port), bs)
    return
  udp_ops.sendUdpDatagram(sock, bs)

proc sendDacFrameBytes*(sock: DacSocket, a: DacAddress,
    bs: ByteSeq) {.role: orchestrator.} =
  ## sock: DAC endpoint handle.
  ## a: remote DAC endpoint.
  ## bs: complete encoded DAC frame bytes.
  var
    host: string
    sent: bool = false
    lastErr: string = ""
  host = a.host.strip().toLowerAscii()
  # `localhost` can resolve to both loopback families. UDP send succeeds
  # without proving a peer exists, so a single-family choice can silently
  # black-hole the first packet. Fan out only across the local loopback aliases
  # here; once AME authenticates traffic, higher layers pin to the concrete
  # literal source address and stop using the hostname.
  if host == "localhost":
    for alias in [initDacAddress("::1", a.port), initDacAddress("127.0.0.1",
        a.port)]:
      try:
        udp_ops.sendUdpDatagram(sock, carrierAddressFromDac(alias), bs)
        sent = true
      except CatchableError as e:
        lastErr = e.msg
    if sent:
      return
    if lastErr.len == 0:
      lastErr = "failed to send UDP datagram"
    raise newException(IOError, lastErr)
  udp_ops.sendUdpDatagram(sock, carrierAddressFromDac(a), bs)

proc recvDacFrameBytes*(sock: DacSocket, maxBytes: int,
    timeoutMs: int = 4000): DacFrameBytesResult {.role: orchestrator.} =
  ## sock: DAC endpoint handle.
  ## maxBytes: maximum encoded DAC frame size to receive.
  ## timeoutMs: receive timeout.
  var
    r: transport_types.UdpDatagramResult
  r = udp_ops.recvUdpDatagram(sock, maxBytes, timeoutMs)
  result.ok = r.ok
  result.payload = r.payload
  result.remote = dacAddressFromCarrier(r.remote)
  result.err = r.err
