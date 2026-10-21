## -------------------------------------------------------------------------
## Relay Fixtures <- link pairs, ids and made-up addresses shared by the
##                   relayFastExtraFrame and relaySlowExtractEncrypt tests
## -------------------------------------------------------------------------
##
##   phone (0x30) ==A==> relay 1 (0x10) ==B==> relay 2 (0x11) ==C==> nas (0x20)
##   10.0.0.48         10.0.0.16            10.0.0.17          10.0.0.32
##
## Each `==X==>` is one AME LINK session (`RtPair`): `left` is held by the
## node on the left, `right` by the node on the right. A node's made-up
## address is "10.0.0.<id>", so address -> neighbour is exact in a test.

import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/secret_stack
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/path_triggers
import ../../src/protocols/ame/level2/session
import ../../src/protocols/transport/types as transport_types

const
  rtKems*: AmeKemAlgorithms = [akaX25519, akaFireSaber]
  idR1*: uint64 = 0x10'u64
  idR2*: uint64 = 0x11'u64
  idNas*: uint64 = 0x20'u64
  idCam*: uint64 = 0x21'u64
  idPhone*: uint64 = 0x30'u64
  idLaptop*: uint64 = 0x31'u64
  nowUnix*: int64 = 500'i64

type
  ## RtPair: the two ends of one link session.
  RtPair* = object
    left*: AmeSession
    right*: AmeSession

proc rtLayout*(): AmeSuiteLayout =
  result = defaultAmeLayout(rtKems)

proc rtTier*(L: AmeSuiteLayout): AmeMaskTier =
  result = initAmeMaskTier(L, 1'u32, initAmeTierMasks(0b11000000'u8,
    occupiedAmeMask(L.ciphers.length), occupiedAmeMask(L.macs.length),
    occupiedAmeMask(L.hashes.length), occupiedAmeMask(L.signatures.length),
    occupiedAmeMask(L.kdfs.length)))

proc rtAuth*(role: AmeEndpointRole, seed: byte): AmeAuthPackage =
  ## role/seed: one end; the same seed on both roles makes a pair.
  var
    layout: AmeSuiteLayout = rtLayout()
    tier: AmeMaskTier = rtTier(layout)
    state: AmeExchangeState = initAmeExchangeState(rtKems)
  applyAmeExchange(state, layout, initAmeExchangeRequest(rtKems, tier,
    0b11000000'u8), [@[seed, 2'u8, 3'u8, 4'u8], @[seed, 6'u8, 7'u8, 8'u8]])
  result = initAmeAuthPackage(layout, tier, state, endpointRole = role)

proc rtPair*(seed: byte): RtPair =
  ## seed: which link; every link in a test gets its own.
  result.left = initAmeSession(rtAuth(aerInitiator, seed),
    peerTrustRequired = false)
  result.right = initAmeSession(rtAuth(aerResponder, seed),
    peerTrustRequired = false)

proc at*(id: uint64): transport_types.UdpAddress =
  ## id: a node; its made-up address, one per id, so address -> slot is exact.
  result = initTransportAddress("10.0.0." & $(id and 0xff'u64), 47656'u16)

