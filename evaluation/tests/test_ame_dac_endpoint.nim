## ---------------------------------------------------------------------
## AME DAC Endpoint <- a package crossing a real UDP socket
## ---------------------------------------------------------------------
##
## Every other DAC test drives the loop in-process on purpose. This one uses
## two loopback sockets, because "owns no socket" is only a virtue if
## something, somewhere, actually holds one and still works.

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level2/session
import ../../src/protocols/ame/level3/dac_relay
import ../../src/protocols/ame/level3/dac_endpoint
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/defaults
import ../../src/protocols/dac/level0/transport
import ../../src/protocols/dac/level3/link_table
import bifrostPragmas

const
  exactKems: AmeKemAlgorithms = [akaFireSaber, akaX25519, akaFireSaber]

proc exactAuth(role: AmeEndpointRole = aerInitiator): AmeAuthPackage =
  ## One established epoch both endpoints share.
  var
    layout: AmeSuiteLayout = defaultAmeLayout(exactKems)
    tier: AmeMaskTier = initAmeMaskTier(layout, 1'u32,
      initAmeTierMasks(0b10000000'u8,
        occupiedAmeMask(layout.ciphers.length),
        occupiedAmeMask(layout.macs.length),
        occupiedAmeMask(layout.hashes.length),
        occupiedAmeMask(layout.signatures.length),
        occupiedAmeMask(layout.kdfs.length)))
    state: AmeExchangeState = initAmeExchangeState(exactKems)
  applyAmeExchange(state, initAmeExchangeRequest(exactKems, tier,
    0b10000000'u8), [@[byte 9, 8, 7, 6, 5, 4, 3, 2]])
  result = initAmeAuthPackage(layout, tier, state, endpointRole = role)

proc rampBytes(n: int): ByteSeq =
  ## n: payload length filled with a deterministic ramp.
  var
    i: int = 0
  result = newSeq[uint8](n)
  while i < n:
    result[i] = uint8((i * 17 + 11) mod 251)
    i = i + 1

suite "AME DAC endpoint over loopback":
  # {.testKind: tkIntegration.}
  test "a package crosses two real sockets and commits":
    var
      senderSock: DacSocket = openDacListener(initDacAddress("127.0.0.1",
        0'u16))
      receiverSock: DacSocket = openDacListener(initDacAddress("127.0.0.1",
        0'u16))
      senderAddr: DacAddress = initDacAddress("127.0.0.1",
        dacLocalPort(senderSock).port)
      receiverAddr: DacAddress = initDacAddress("127.0.0.1",
        dacLocalPort(receiverSock).port)
      a: AmeSession = initAmeSession(exactAuth(aerInitiator),
        peerTrustRequired = false)
      b: AmeSession = initAmeSession(exactAuth(aerResponder),
        peerTrustRequired = false)
      sender: AmeDacEndpoint
      receiver: AmeDacEndpoint
      payload: ByteSeq = rampBytes(6_000)
      step: AmeDacRelayStep
      nowMs: uint32 = 0'u32
      done: bool = false
      round: int = 0
    sender = initAmeDacEndpoint(senderSock,
      initAmeDacRelay(dacDefaultsFor(dscCleanLan), 1'u64))
    receiver = initAmeDacEndpoint(receiverSock,
      initAmeDacRelay(dacDefaultsFor(dscCleanLan), 2'u64))
    check admitAmeDacPeer(sender.relay, dacKeyFromAddress(receiverAddr), a,
      0'u32).ok
    check admitAmeDacPeer(receiver.relay, dacKeyFromAddress(senderAddr), b,
      0'u32).ok
    step = sendAmeDacEndpointPackage(sender, dacKeyFromAddress(receiverAddr),
      21'u64, payload, nowMs)
    check step.kind == adrProgress
    check sender.sent > 0'u64
    while round < 400 and not done:
      nowMs = nowMs + 5'u32
      step = pumpAmeDacEndpoint(receiver, nowMs, timeoutMs = 20)
      if step.kind == adrPackageComplete:
        check step.payload == payload
        done = true
      discard pumpAmeDacEndpoint(sender, nowMs, timeoutMs = 5)
      discard tickAmeDacEndpoint(receiver, nowMs)
      discard tickAmeDacEndpoint(sender, nowMs)
      round = round + 1
    check done
    check receiver.received > 0'u64
    closeAmeDacEndpoint(sender)
    closeAmeDacEndpoint(receiver)

  # {.testKind: tkIntegration.}
  test "a receive timeout is quiet, not an error":
    var
      sock: DacSocket = openDacListener(initDacAddress("127.0.0.1", 0'u16))
      E: AmeDacEndpoint = initAmeDacEndpoint(sock,
        initAmeDacRelay(dacDefaultsFor(dscCleanLan), 3'u64))
      step: AmeDacRelayStep = pumpAmeDacEndpoint(E, 0'u32, timeoutMs = 20)
    check step.kind == adrNone
    check step.err.len == 0
    check E.received == 0'u64
    closeAmeDacEndpoint(E)

  # {.testKind: tkEdgeCase.}
  test "a datagram from an unknown address is dropped, not admitted":
    var
      listenSock: DacSocket = openDacListener(initDacAddress("127.0.0.1",
        0'u16))
      strangerSock: DacSocket = openDacListener(initDacAddress("127.0.0.1",
        0'u16))
      listenAddr: DacAddress = initDacAddress("127.0.0.1",
        dacLocalPort(listenSock).port)
      E: AmeDacEndpoint = initAmeDacEndpoint(listenSock,
        initAmeDacRelay(dacDefaultsFor(dscCleanLan), 4'u64, capacity = 4))
      step: AmeDacRelayStep
    sendDacFrameBytes(strangerSock, listenAddr, rampBytes(200))
    step = pumpAmeDacEndpoint(E, 0'u32, timeoutMs = 500)
    check step.kind == adrDropped
    check step.err == "DAC datagram from a peer with no session"
    check ameDacRelayLive(E.relay) == 0
    check E.relay.dropped == 1'u32
    closeDac(strangerSock)
    closeAmeDacEndpoint(E)
