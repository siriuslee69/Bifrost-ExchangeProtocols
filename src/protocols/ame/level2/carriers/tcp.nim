## -------------------------------------------------------------------------
## AME TCP Carrier <- sealed AME frames over one stream socket
## -------------------------------------------------------------------------
##
## Everything here needs a real socket, which is why it lives apart from the
## session core: a build that speaks only DAC never imports this file and so
## never compiles Nim's stream-socket stack or the TLS setup behind it.

import std/net

import ../../../transport/types as transport_types
import ../../../transport/tcp_ops
import ../../../types
import ../../types
import ../framing
import runePragmas

type
  AmeTcpClient* {.role: truthState.} = object
    ## One connected AME session and the stream socket carrying it.
    connection*: AmeSession
    socket*: Socket
    remote*: transport_types.TcpAddress
    tls*: transport_types.TlsConfig

proc loseAmeTcpConnection(sock: Socket, S: var AmeSession, err: string) {.
    role: actor.} =
  ## sock/S/err: a write failed after sealing. The ratchet step stays used
  ## (never sealed twice), the half-written stream is closed, and the caller
  ## learns it has to reconnect.
  S.lastErr = "AME TCP write failed after sealing; connection closed: " & err
  try:
    sock.close()
  except CatchableError:
    discard
  raise newException(AmeConnectionLost, S.lastErr)

proc sendAmeTcp*(sock: Socket, S: var AmeSession,
    payload: openArray[uint8]) {.role: orchestrator.} =
  ## sock/S/payload: seal (undone if it fails), then write (never undone;
  ## a failed write closes the connection -- see framing.nim, "sending one
  ## frame").
  var
    frame: ByteSeq = @[]
  ameSealTransaction(S):
    frame = sealAmeTcpFrame(S, payload)
    requireTcpFrameSendable(frame.len)
  try:
    sendTcpFrame(sock, frame)
  except CatchableError as e:
    loseAmeTcpConnection(sock, S, e.msg)
  discard recordTransferredBytes(S, uint64(payload.len))

proc recvAmeTcp*(sock: Socket, S: var AmeSession, timeoutMs: int = 4000,
    maxFrameBytes: uint32 = uint32(defaultAmeMaxFrameBytes)):
    AmeOpenResult {.role: orchestrator.} =
  ## sock/S/timeout/max: receive one framed TCP AME2 payload.
  var frame = recvTcpFrame(sock, timeoutMs, maxFrameBytes)
  if not frame.ok:
    result.err = frame.err
    return
  result = openAmeTcpFrame(S, frame.payload)

proc wrapAmeTcpClient*(sock: Socket, S: AmeSession,
    remote: transport_types.TcpAddress = default(transport_types.TcpAddress),
    tls: transport_types.TlsConfig = default(transport_types.TlsConfig)):
    AmeTcpClient {.role: truthBuilder.} =
  ## sock/S/remote/tls: caller-owned connected socket and validated AME state.
  if sock == nil:
    raise newException(ValueError, "AME TCP client socket is nil")
  requireAmeAuth(S.auth)
  result.socket = sock
  result.connection = S
  result.remote = remote
  result.tls = tls

proc connectAmeTcpClient*(remote: transport_types.TcpAddress,
    S: AmeSession, timeoutMs: int = 4000,
    tls: transport_types.TlsConfig = default(transport_types.TlsConfig)):
    AmeTcpClient {.role: orchestrator.} =
  ## remote/S/timeoutMs/tls: endpoint, pre-negotiated state, and transport setup.
  result = wrapAmeTcpClient(connectTcp(remote, timeoutMs, tls), S, remote, tls)

proc close*(client: var AmeTcpClient) {.role: orchestrator.} =
  ## client: TCP client whose socket is closed.
  if client.socket != nil:
    client.socket.close()
    client.socket = nil
  clearAmeSession(client.connection)

proc send*(client: var AmeTcpClient, payload: openArray[uint8]) {.
    role: orchestrator.} =
  ## client/payload: direct TCP AME send.
  sendAmeTcp(client.socket, client.connection, payload)

proc receive*(client: var AmeTcpClient, timeoutMs: int = 4000,
    maxFrameBytes: uint32 = uint32(defaultAmeMaxFrameBytes)):
    AmeOpenResult {.role: orchestrator.} =
  ## client/timeout/max: direct TCP AME receive.
  result = recvAmeTcp(client.socket, client.connection, timeoutMs, maxFrameBytes)
