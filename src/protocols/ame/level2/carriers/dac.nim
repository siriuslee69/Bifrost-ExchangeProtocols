## -------------------------------------------------------------------------
## AME DAC Carrier <- sealed AME frames over the datagram DAC transport
## -------------------------------------------------------------------------
##
## Everything here needs a real socket, which is why it lives apart from the
## session core: a build that speaks only TCP never imports this file and so
## never compiles the DAC datagram transport or its peer registry.

import ../../../types
import ../../types
import ../../../dac/level0/transport as dac_transport
import ../framing
import runePragmas

type
  AmeDacClient* {.role: truthState.} = object
    ## One AME session and the DAC endpoint carrying it.
    connection*: AmeSession
    socket*: dac_transport.DacSocket
    remote*: dac_transport.DacAddress

template writeKeepingUnsent(S: var AmeSession, frame: ByteSeq, n: int,
    write: untyped) {.role: dataWriter.} =
  ## S/frame/n/write: `write` sends `frame`. If it fails the frame is kept,
  ## so the next send repeats these exact bytes instead of sealing again.
  try:
    write
  except CatchableError:
    keepAmeUnsentFrame(S, frame, n)
    raise
  discard recordTransferredBytes(S, uint64(n))

template sendAmeDacVia(S: var AmeSession, payload: openArray[uint8],
    send: untyped) {.role: orchestrator.} =
  ## S/payload/send: `send(frame)` writes one datagram. The kept frame goes
  ## first (a failure keeps it and stops here), then the new one is sealed
  ## (undone if sealing fails) and written (kept if writing fails).
  var
    frame {.inject.}: ByteSeq = @[]
  if ameHasUnsentFrame(S):
    frame = S.unsentFrame
    send
    sentAmeUnsentFrame(S)
  ameSealTransaction(S):
    frame = sealAmeDacFrame(S, payload)
  writeKeepingUnsent(S, frame, payload.len):
    send

proc sendAmeDac*(sock: dac_transport.DacSocket, S: var AmeSession,
    payload: openArray[uint8]) {.role: orchestrator.} =
  ## sock/S/payload: connected-DAC send -- see framing.nim, "sending one
  ## frame", for what a failure leaves behind.
  sendAmeDacVia(S, payload):
    sendDacFrameBytes(sock, frame)

proc sendAmeDac*(sock: dac_transport.DacSocket,
    remote: dac_transport.DacAddress, S: var AmeSession,
    payload: openArray[uint8]) {.role: orchestrator.} =
  ## sock/remote/S/payload: unconnected-DAC send, same rules.
  sendAmeDacVia(S, payload):
    sendDacFrameBytes(sock, remote, frame)

proc recvAmeDac*(sock: dac_transport.DacSocket, S: var AmeSession,
    timeoutMs: int = 4000, maxFrameBytes: int = defaultAmeMaxFrameBytes):
    AmeOpenResult {.role: orchestrator.} =
  ## sock/S/timeout/max: receive one DAC AME2 payload.
  var received = recvDacFrameBytes(sock, maxFrameBytes, timeoutMs)
  if not received.ok:
    result.err = received.err
    S.lastErr = result.err
    return
  result = openAmeDacFrame(S, received.payload, received.remote)

proc connectAmeDacClient*(remote: dac_transport.DacAddress,
    S: AmeSession, timeoutMs: int = 4000): AmeDacClient {.
    role: orchestrator.} =
  ## remote/S/timeoutMs: DAC endpoint and pre-negotiated AME state.
  requireAmeAuth(S.auth)
  result.socket = openDacPeer(remote, timeoutMs)
  result.connection = S
  result.remote = remote

proc close*(client: var AmeDacClient) {.role: orchestrator.} =
  ## client: DAC client whose socket is closed.
  if client.socket != nil:
    dac_transport.closeDac(client.socket)
    client.socket = nil
  clearAmeSession(client.connection)

proc send*(client: var AmeDacClient, payload: openArray[uint8]) {.
    role: orchestrator.} =
  ## client/payload: direct DAC AME send.
  sendAmeDac(client.socket, client.connection, payload)

proc receive*(client: var AmeDacClient, timeoutMs: int = 4000,
    maxFrameBytes: int = defaultAmeMaxFrameBytes):
    AmeOpenResult {.role: orchestrator.} =
  ## client/timeout/max: direct DAC AME receive.
  result = recvAmeDac(client.socket, client.connection, timeoutMs, maxFrameBytes)
