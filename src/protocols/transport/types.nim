## -----------------------------------------------------------------
## Transport Types <- shared TCP/TLS/UDP endpoint profile records
## -----------------------------------------------------------------

import std/strutils

import ../types
import ../../analysis_pragmas

type
  ## TransportAddress: plain host + port endpoint for generic transport usage.
  TransportAddress* {.role: truthState.} = object
    host*: string
    port*: uint16

  ## TcpAddress: plain host + port endpoint.
  TcpAddress* = TransportAddress

  ## UdpAddress: plain host + port endpoint for datagram usage.
  UdpAddress* = TransportAddress

  ## TlsVerifyMode: peer certificate validation policy.
  TlsVerifyMode* = enum
    tvmDisabled,
    tvmPeer,
    tvmPeerUseEnv

  ## TlsRole: TLS handshake side.
  TlsRole* = enum
    trClient,
    trServer

  ## TlsConfig: generic TLS runtime settings.
  ## enabled: enable TLS wrapping for the socket.
  ## verifyMode: peer validation mode.
  ## certFile/keyFile: local cert material for servers or mutual TLS.
  ## caDir/caFile: CA certificate overrides.
  ## serverName: client-side hostname/SNI override.
  ## sessionIdContext: optional server-side session reuse context.
  TlsConfig* {.role: configurator.} = object
    enabled*: bool
    verifyMode*: TlsVerifyMode
    certFile*: string
    keyFile*: string
    caDir*: string
    caFile*: string
    serverName*: string
    sessionIdContext*: string

  ## TcpEndpoint: address plus optional TLS policy.
  TcpEndpoint* {.role: configurator.} = object
    address*: TcpAddress
    tls*: TlsConfig

  ## TcpFrameResult: generic framed receive result.
  TcpFrameResult* {.role: truthState.} = object
    ok*: bool
    payload*: ByteSeq
    err*: string

  ## ProtocolStreamFrameResult: one length-prefixed frame parsed from a byte stream.
  ## ok: true when a full frame was decoded.
  ## needMore: true when the buffer is valid but incomplete.
  ## consumed: number of input bytes consumed when ok is true.
  ## payload: decoded payload bytes when ok is true.
  ## err: human-readable failure detail.
  ProtocolStreamFrameResult* {.role: truthState.} = object
    ok*: bool
    needMore*: bool
    consumed*: int
    payload*: ByteSeq
    err*: string

  ## ProtocolStreamBatchResult: repeated frame parse result for buffered streams.
  ## ok: true when no malformed or oversized frame was found.
  ## needMore: true when trailing bytes form an incomplete frame.
  ## consumed: full-frame byte count consumed from the input buffer.
  ## frames: decoded payloads in stream order.
  ## err: human-readable failure detail.
  ProtocolStreamBatchResult* {.role: truthState.} = object
    ok*: bool
    needMore*: bool
    consumed*: int
    frames*: seq[ByteSeq]
    err*: string

  ## UdpDatagramResult: generic datagram receive result.
  ## ok: receive status.
  ## payload: datagram bytes.
  ## remote: source endpoint for the datagram.
  ## err: human-readable failure detail.
  UdpDatagramResult* {.role: truthState.} = object
    ok*: bool
    payload*: ByteSeq
    remote*: UdpAddress
    err*: string

proc bytesToString*(bs: ByteSeq): string {.role: wrapper.} =
  ## bytesToString: build bytes to string.
  var
    i: int = 0
  result = newString(bs.len)
  while i < bs.len:
    result[i] = char(bs[i])
    i.inc

proc stringToBytes*(s: string): ByteSeq {.role: wrapper.} =
  ## stringToBytes: build string to bytes.
  var
    i: int = 0
  result = newSeq[uint8](s.len)
  while i < s.len:
    result[i] = uint8(ord(s[i]))
    i.inc

proc defaultTlsConfig*(): TlsConfig {.role: wrapper.} =
  ## defaultTlsConfig: build the default TLS config.
  result.enabled = false
  result.verifyMode = tvmPeer

proc normalizeTransportHostValue(h: string): string {.role: parser.} =
  ## h: host-only address value without scheme or embedded port.
  var
    t: string
    inner: string
    colonCount: int
    i: int
    ch: char
  t = h.strip()
  if t.len == 0:
    raise newException(ValueError, "transport host must not be blank")
  if t.find("://") >= 0:
    raise newException(ValueError, "transport host must not include a URI scheme")
  i = 0
  while i < t.len:
    ch = t[i]
    if ch == ' ' or ch == '\t' or ch == '\r' or ch == '\n':
      raise newException(ValueError, "transport host must not contain whitespace")
    if ch == '/' or ch == '?' or ch == '#' or ch == '@':
      raise newException(ValueError,
        "transport host must not include path, fragment, query, or userinfo data")
    i = i + 1
  if t[0] == '[' or t[^1] == ']':
    if t.len < 2 or t[0] != '[' or t[^1] != ']':
      raise newException(ValueError, "transport host has a malformed bracketed IPv6 literal")
    inner = t[1 .. ^2]
    if inner.len == 0 or inner.find(':') < 0 or inner.find('[') >= 0 or
        inner.find(']') >= 0:
      raise newException(ValueError, "transport host has a malformed bracketed IPv6 literal")
    return inner
  if t.find('[') >= 0 or t.find(']') >= 0:
    raise newException(ValueError, "transport host has a malformed bracketed IPv6 literal")
  colonCount = t.count(':')
  if colonCount == 1:
    raise newException(ValueError, "transport host must not include an embedded port")
  if colonCount > 1:
    if t[0] == ':' and (t.len < 2 or t[1] != ':'):
      raise newException(ValueError, "transport host has a malformed IPv6 literal")
    if t[^1] == ':' and (t.len < 2 or t[^2] != ':'):
      raise newException(ValueError, "transport host has a malformed IPv6 literal")
  result = t

proc initTransportAddress*(h: string, p: uint16): TransportAddress {.role: wrapper.} =
  ## initTransportAddress: initialize transport address.
  result.host = normalizeTransportHostValue(h)
  result.port = p

proc initTcpAddress*(h: string, p: uint16): TcpAddress {.role: wrapper.} =
  ## initTcpAddress: initialize TCP address.
  result = initTransportAddress(h, p)

proc initUdpAddress*(h: string, p: uint16): UdpAddress {.role: wrapper.} =
  ## initUdpAddress: initialize UDP address.
  result = initTransportAddress(h, p)

proc initTcpEndpoint*(h: string, p: uint16, t: TlsConfig = defaultTlsConfig()):
    TcpEndpoint {.role: wrapper.} =
  ## initTcpEndpoint: initialize TCP endpoint.
  result.address = initTcpAddress(h, p)
  result.tls = t
