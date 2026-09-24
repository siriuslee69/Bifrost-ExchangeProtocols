## -------------------------------------------------------------------------
## AME Send Failures <- a failed write never seals the same step twice
## -------------------------------------------------------------------------
##
## What these tests hold down (framing.nim, "sending one frame"):
##
##   seal fails         the ratchet is where it was (nothing left the machine)
##   TCP write fails    the step stays used, the socket is closed,
##                      AmeConnectionLost is raised
##   DAC write fails    the sealed bytes are kept; the next send writes those
##                      EXACT bytes first, then the new message
##   DAC give-up        discardAmeUnsentFrame: the receiver sees a lost
##                      message and steps past it
##
## A write is made to fail the way a real one does, with an OS error: a TCP
## socket that was never connected, and a datagram to an IPv6 address from
## an IPv4 socket. (A CLOSED socket is no good: Nim stops that with an
## assertion before the OS is ever asked.)

import std/[net, unittest]

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/secret_stack
import ../../src/protocols/ame/level2/framing
import ../../src/protocols/ame/level2/carriers
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/transport
import runePragmas

proc pairAuth(role: AmeEndpointRole): AmeAuthPackage {.role: configurator.} =
  ## role: one end of a pair that shares one fixed first exchange.
  var
    layout: AmeSuiteLayout = defaultAmeLayout([akaX25519])
    tier: AmeMaskTier = fullAmeMaskTier(layout)
    state: AmeExchangeState = initAmeExchangeState(layout.kems)
  applyAmeExchange(state, layout, initAmeExchangeRequest(layout.kems, tier,
    tier.masks.kem), [@[byte 4, 3, 2, 1]])
  result = initAmeAuthPackage(layout, tier, state, endpointRole = role)

proc pairSessions(): tuple[a, b: AmeSession] {.role: configurator.} =
  ## Two ends of one session; `a` sends on lane 1.
  result.a = initAmeSession(pairAuth(aerInitiator), peerTrustRequired = false)
  result.b = initAmeSession(pairAuth(aerResponder), peerTrustRequired = false)

const
  unreachable: DacAddress = DacAddress(host: "::1", port: 9'u16)
    ## An IPv6 address; an IPv4 socket cannot write to it.

proc listener(): tuple[sock: DacSocket, a: DacAddress] {.
    role: configurator.} =
  ## A bound datagram socket and its address.
  result.sock = openDacListener(initDacAddress("127.0.0.1", 0'u16))
  result.a = initDacAddress("127.0.0.1", dacLocalPort(result.sock).port)

proc nextDatagram(sock: DacSocket): ByteSeq {.role: dataFetcher.} =
  ## sock: the next datagram's bytes (empty on timeout).
  var
    r: DacFrameBytesResult = recvDacFrameBytes(sock, 65536, 2000)
  if r.ok:
    result = r.payload

suite "AME send failures":
  # {.testKind: tkEdgeCase, covers: "ameSealTransaction".}
  test "a refused seal leaves the ratchet where it was":
    var
      p: tuple[a, b: AmeSession] = pairSessions()
      tx: DacSocket = openDacListener(initDacAddress("127.0.0.1", 0'u16))
      before: uint64 = p.a.fomke.lane1.nextIndex
    ## Sending is refused while this side waits for an answer.
    discard beginAmeTcpExchangeFrame(p.a, ameAddExchangeRequest(p.a,
      [akaX25519]))
    before = p.a.fomke.lane1.nextIndex
    expect ValueError:
      sendAmeDac(tx, unreachable, p.a, [byte 1])
    check p.a.fomke.lane1.nextIndex == before
    check not ameHasUnsentFrame(p.a)
    tx.close()

  # {.testKind: tkRegression, covers: "sendAmeTcp", pins: "a failed write rewound the ratchet, so the next message reused its key and nonce".}
  test "a failed TCP write keeps the step used and closes the connection":
    var
      p: tuple[a, b: AmeSession] = pairSessions()
      sock: Socket = newSocket()   # never connected
      before: uint64 = p.a.fomke.lane1.nextIndex
    expect AmeConnectionLost:
      sendAmeTcp(sock, p.a, [byte 1, 2, 3])
    check p.a.fomke.lane1.nextIndex == before + 1'u64
    check p.a.lastErr.len > 0

  # {.testKind: tkRegression, covers: "sendAmeDac|keepAmeUnsentFrame", pins: "a failed write rewound the ratchet, so the next message reused its key and nonce".}
  test "a failed DAC write keeps the bytes; the next send repeats them first":
    var
      p: tuple[a, b: AmeSession] = pairSessions()
      rx: tuple[sock: DacSocket, a: DacAddress] = listener()
      tx: DacSocket = openDacListener(initDacAddress("127.0.0.1", 0'u16))
      kept: ByteSeq = @[]
      first: ByteSeq = @[]
      second: ByteSeq = @[]
      before: uint64 = p.a.fomke.lane1.nextIndex
    expect CatchableError:
      sendAmeDac(tx, unreachable, p.a, [byte 1, 1, 1])
    check ameHasUnsentFrame(p.a)
    check p.a.fomke.lane1.nextIndex == before + 1'u64
    kept = p.a.unsentFrame
    sendAmeDac(tx, rx.a, p.a, [byte 2, 2, 2])
    first = nextDatagram(rx.sock)
    second = nextDatagram(rx.sock)
    ## The repeat is the SAME bytes, not a new seal at the same step.
    check first == kept
    check not ameHasUnsentFrame(p.a)
    check openAmeDacFrame(p.b, first).packet.payload == @[byte 1, 1, 1]
    check openAmeDacFrame(p.b, second).packet.payload == @[byte 2, 2, 2]
    tx.close()
    rx.sock.close()

  # {.testKind: tkEdgeCase, covers: "discardAmeUnsentFrame".}
  test "a given-up DAC frame is a lost message; the receiver steps past":
    var
      p: tuple[a, b: AmeSession] = pairSessions()
      rx: tuple[sock: DacSocket, a: DacAddress] = listener()
      tx: DacSocket = openDacListener(initDacAddress("127.0.0.1", 0'u16))
      got: AmeOpenResult = default(AmeOpenResult)
    expect CatchableError:
      sendAmeDac(tx, unreachable, p.a, [byte 1])
    discardAmeUnsentFrame(p.a)
    check not ameHasUnsentFrame(p.a)
    sendAmeDac(tx, rx.a, p.a, [byte 2])
    got = openAmeDacFrame(p.b, nextDatagram(rx.sock))
    check got.ok
    check got.packet.payload == @[byte 2]
    check ameSessionSkippedMessages(p.b) == 1
    tx.close()
    rx.sock.close()
