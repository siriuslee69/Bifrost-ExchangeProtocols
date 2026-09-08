## -------------------------------------------------------------------------
## AME DAC Endpoint <- the relay, finally holding a socket
## -------------------------------------------------------------------------

import ../../dac/build

when not dacAdaptiveBuilt:
  {.error: "This module is part of the DAC adaptive layer, which -d:bifrostDac=off removed from this build.".}

import ../../dac/types
import ../../dac/level0/transport as dac_transport
import ../../dac/level3/link_table
import ./dac_relay
import bifrostPragmas

const
  ameDacEndpointAscii* = """
Everything below this owns no socket, deliberately. This is the one place
that does, so it is the only file that has to be trusted about blocking,
timeouts and partial reads.

   recvDacFrameBytes()  ->  feedAmeDacDatagram()  ->  sendDacFrameBytes()
                                     |
   the clock  ------------------->  tickAmeDacRelay()  ->  sendDacFrameBytes()

The endpoint adds nothing to the protocol. It moves bytes between a UDP
socket and the relay, and turns the relay's outbox into sends. Every security
decision was already made below it: which peers exist, what authenticates,
what is dropped.

A receive timeout is NOT an error here. A datagram loop spends most of its
life waiting, and the caller still needs the tick to run so ACK deadlines and
repair timers fire on a quiet link.
"""

  ameDacEndpointMaxDatagram* = 65_507
    ## Largest UDP payload a v4 datagram can carry. The relay bounds what it
    ## will do with the bytes; this only bounds what is read off the wire.

type
  ## AmeDacEndpoint: one socket and the relay behind it.
  AmeDacEndpoint* {.role: truthState.} = object
    socket*: dac_transport.DacSocket
    relay*: AmeDacRelay
    sent*: uint64
    received*: uint64
    sendFailures*: uint32

proc initAmeDacEndpoint*(socket: dac_transport.DacSocket,
    relay: AmeDacRelay): AmeDacEndpoint {.role: configurator.} =
  ## socket: an already-open DAC listener or peer socket.
  ## relay: a relay whose peers were admitted by the handshake layer.
  result.socket = socket
  result.relay = relay

proc dacKeyFromAddress*(a: DacAddress): DacLinkKey {.role: truthBuilder.} =
  ## a: the remote address the transport reported.
  result = initDacLinkKey(a.host, a.port, dlcDatagram)

proc dacAddressFromKey*(k: DacLinkKey): DacAddress {.role: truthBuilder.} =
  ## k: peer key turned back into an address to send to.
  result = initDacAddress(k.host, k.port)

proc flushRelayStep(E: var AmeDacEndpoint, step: AmeDacRelayStep): int {.
    role: orchestrator.} =
  ## E/step: endpoint and one relay outcome whose datagrams are transmitted.
  ## Returns how many left. A send that fails is counted rather than raised:
  ## one unreachable peer must not end the loop for every other peer.
  var
    to: DacAddress = dacAddressFromKey(step.peer)
    i: int = 0
  while i < step.send.len:
    try:
      sendDacFrameBytes(E.socket, to, step.send[i])
      E.sent = E.sent + 1'u64
      result = result + 1
    except CatchableError:
      E.sendFailures = E.sendFailures + 1'u32
    i = i + 1

proc pumpAmeDacEndpoint*(E: var AmeDacEndpoint, nowMs: uint32,
    timeoutMs: int = 50): AmeDacRelayStep {.role: orchestrator.} =
  ## E: endpoint whose socket is read once.
  ## nowMs: caller's millisecond clock.
  ## timeoutMs: how long to wait for a datagram before returning quietly.
  ## Reads at most one datagram, feeds it to the relay, and transmits whatever
  ## the relay wants to say back. A timeout returns `adrNone`, not an error.
  var
    got: dac_transport.DacFrameBytesResult = recvDacFrameBytes(E.socket,
      ameDacEndpointMaxDatagram, timeoutMs)
  if not got.ok:
    result.kind = adrNone
    return
  E.received = E.received + 1'u64
  result = feedAmeDacDatagram(E.relay, dacKeyFromAddress(got.remote),
    got.payload, nowMs)
  discard flushRelayStep(E, result)

proc tickAmeDacEndpoint*(E: var AmeDacEndpoint,
    nowMs: uint32): seq[AmeDacRelayStep] {.role: orchestrator.} =
  ## E: endpoint whose every peer acts on elapsed time.
  ## nowMs: caller's millisecond clock.
  ## Call it on any convenient cadence. This is what makes ACK deadlines and
  ## repair timers fire on a link that has gone quiet, so a loop that only
  ## pumps receives will stall on the first lost datagram.
  var
    i: int = 0
  result = tickAmeDacRelay(E.relay, nowMs)
  while i < result.len:
    discard flushRelayStep(E, result[i])
    i = i + 1

proc sendAmeDacEndpointPackage*(E: var AmeDacEndpoint, key: DacLinkKey,
    packageId: uint64, payload: openArray[uint8],
    nowMs: uint32): AmeDacRelayStep {.role: orchestrator.} =
  ## E/key: endpoint and the peer the package goes to.
  ## packageId/payload/nowMs: package identity, bytes, and clock.
  ## Plans the package, seals every datagram and transmits them in order.
  result = sendAmeDacPackage(E.relay, key, packageId, payload, nowMs)
  if result.kind == adrDropped:
    return
  discard flushRelayStep(E, result)

proc closeAmeDacEndpoint*(E: var AmeDacEndpoint) {.role: orchestrator.} =
  ## E: endpoint whose socket is released. The relay's sessions are dropped
  ## with it, so no peer keys outlive the socket that carried them.
  closeDac(E.socket)
  E.relay = default(AmeDacRelay)
