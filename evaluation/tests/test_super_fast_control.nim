## ---------------------------------------------------------------------
## Super-fast control link Tests <- forwarder tells server, server tells clients
## ---------------------------------------------------------------------
##
##   forwarder ==link 1== server ==link 2== client
##   (SuperFastControl)    (AmeDacRelay)    (AmeDacRelay)
##
## Every hop is a real sealed frame. The forwarder still passes client bytes
## blind; only the control frames are keyed.

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/transport/types as transport_types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level2/seal_open
import ../../src/protocols/ame/level3/dac_relay
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/brake
import ../../src/protocols/dac/level0/defaults
import ../../src/protocols/dac/level3/link
import ../../src/protocols/dac/level3/link_table
import ../../src/protocols/relay/super_fast_udp
import ../../src/protocols/relay/super_fast_control
import ./relay_fixtures

type
  ## Chain: the three ends and the keys they know each other by.
  Chain = object
    F: RelaySuperFastUdp
    ctl: SuperFastControl
    server: AmeDacRelay
    client: AmeDacRelay
    fwdKey: DacLinkKey
    clientKey: DacLinkKey
    serverKey: DacLinkKey

proc newChain(serverFollows: bool = true, clientFollows: bool = true,
    capacity: int = 5000): Chain =
  var
    p1: RtPair = rtPair(10'u8)
    p2: RtPair = rtPair(11'u8)
    d: DacScenarioDefaults = dacDefaultsFor(dscCleanLan)
  result.F = initRelaySuperFastUdp(initUdpAddress("10.0.0.2", 9000'u16))
  result.ctl = initSuperFastControl(p1.left, capacity)
  result.fwdKey = initDacLinkKey("10.0.0.9", 7000'u16)
  result.clientKey = initDacLinkKey("10.0.0.9", 7001'u16)
  result.serverKey = initDacLinkKey("10.0.0.2", 9000'u16)
  result.server = initAmeDacRelay(d, 1'u64, relayForceRequest = serverFollows)
  result.client = initAmeDacRelay(d, 2'u64, relayForceRequest = clientFollows)
  discard admitAmeDacPeer(result.server, result.fwdKey, p1.right, 0'u32)
  discard admitAmeDacPeer(result.server, result.clientKey, p2.left, 0'u32)
  discard setAmeDacBrakeSource(result.server, result.fwdKey)
  discard admitAmeDacPeer(result.client, result.serverKey, p2.right, 0'u32,
    peerIsRelay = true)

proc clientLevel(H: Chain): uint8 =
  result = dacBrakeLevel(H.client.table.slots[ameDacPeerSlot(H.client,
    H.serverKey)].link)

proc serverLinkToClient(H: Chain): DacLink =
  result = H.server.table.slots[ameDacPeerSlot(H.server, H.clientKey)].link

proc pass(H: var Chain, nowMs: uint32): int =
  ## One round: forwarder tick -> server -> server tick -> client. Returns how
  ## many frames reached the client.
  var
    out1: seq[UdpForwardOut] = tickSuperFastControl(H.ctl, H.F, uint64(nowMs))
    steps: seq[AmeDacRelayStep] = @[]
    i: int = 0
    j: int = 0
  for o in out1:
    discard feedAmeDacDatagram(H.server, H.fwdKey, o.payload, nowMs)
  steps = tickAmeDacRelay(H.server, nowMs)
  while i < steps.len:
    if dacKeyEqual(steps[i].peer, H.clientKey):
      j = 0
      while j < steps[i].send.len:
        discard feedAmeDacDatagram(H.client, H.serverKey, steps[i].send[j],
          nowMs)
        result = result + 1
        j = j + 1
    i = i + 1

suite "super-fast control link":
  # {.testKind: tkIntegration, covers: "tickSuperFastControl".}
  test "the forwarder's level reaches the server and every client":
    var
      H: Chain = newChain()
    discard H.F.setSuperFastBrake(2'u8)
    check pass(H, 1_000'u32) == 1
    check clientLevel(H) == 2'u8
    check dacBrakeLevel(serverLinkToClient(H)) == 2'u8
    check dacSendDelayMs(H.server.table.slots[ameDacPeerSlot(H.server,
      H.clientKey)].link) >= 16'u16

  # {.testKind: tkIntegration, covers: "tickSuperFastControl".}
  test "it is sent on change, repeated while above 0, and reset by 0":
    var
      H: Chain = newChain()
    discard H.F.setSuperFastBrake(3'u8)
    check pass(H, 1_000'u32) == 1
    check pass(H, 5_000'u32) == 0
    check pass(H, 1_000'u32 + dacBrakeRefreshMs) == 1
    discard H.F.setSuperFastBrake(0'u8)
    check pass(H, 20_000'u32) == 1
    check clientLevel(H) == 0'u8
    check pass(H, 30_000'u32) == 0

  # {.testKind: tkIntegration, covers: "measureLoad".}
  test "load alone raises the level":
    var
      H: Chain = newChain(capacity = 100)
      i: int = 0
    check pass(H, 0'u32) == 0
    while i < 95:
      discard fromClient(H.F, initUdpAddress("203.0.113.1", 40000'u16),
        @[byte 1], 500'u64)
      i = i + 1
    check pass(H, 1_000'u32) == 1
    check clientLevel(H) == 3'u8

  # {.testKind: tkIntegration, covers: "fromServerControl".}
  test "a server that will not follow is not sent orders":
    var
      H: Chain = newChain(serverFollows = false)
      steps: seq[AmeDacRelayStep] = tickAmeDacRelay(H.server, 10'u32)
    check steps.len == 1
    check dacKeyEqual(steps[0].peer, H.fwdKey)
    check H.ctl.fromServerControl(steps[0].send[0], 10'u64).ok
    check H.ctl.deaf
    discard H.F.setSuperFastBrake(2'u8)
    check pass(H, 1_000'u32) == 0
    check tickSuperFastControl(H.ctl, H.F, 2_000'u64).len == 0

  # {.testKind: tkIntegration, covers: "ameDacSpreadBrake".}
  test "a client that will not follow is slowed on the server's side only":
    var
      H: Chain = newChain(clientFollows = false)
      steps: seq[AmeDacRelayStep] = tickAmeDacRelay(H.client, 10'u32)
    check steps.len == 1
    discard feedAmeDacDatagram(H.server, H.clientKey, steps[0].send[0],
      10'u32)
    check not dacPeerFollows(serverLinkToClient(H))
    discard H.F.setSuperFastBrake(2'u8)
    check pass(H, 1_000'u32) == 0
    check clientLevel(H) == 0'u8
    check dacBrakeLevel(serverLinkToClient(H)) == 2'u8

  # {.testKind: tkEdgeCase, covers: "setAmeDacBrakeSource".}
  test "an order from a peer that is not the source reaches nobody":
    var
      H: Chain = newChain()
      frame: ByteSeq = @[]
      step: AmeDacRelayStep = default(AmeDacRelayStep)
    check not setAmeDacBrakeSource(H.server,
      initDacLinkKey("10.9.9.9", 1'u16))
    ## A client seals a full-brakes order and sends it to the server. It is a
    ## peer, but not the source and not marked as a relay: nothing changes.
    frame = sealAmeDacControl(H.client.sessions[ameDacPeerSlot(H.client,
      H.serverKey)], dmkBrake, encodeDacBrake(3'u8))
    step = feedAmeDacDatagram(H.server, H.clientKey, frame, 5'u32)
    check step.kind == adrNone
    check tickAmeDacRelay(H.server, 6'u32).len == 0
    check dacBrakeLevel(serverLinkToClient(H)) == 0'u8

  # {.testKind: tkEdgeCase, covers: "fromServerControl".}
  test "junk on the control socket is refused":
    var
      H: Chain = newChain()
    check not H.ctl.fromServerControl(@[byte 1, 2, 3], 10'u64).ok

suite "super-fast control link is kept alive":
  # {.testKind: tkIntegration, covers: "controlSilent|tickSuperFastControl".}
  test "level 0 is still touched now and then, and the server answers every order":
    var
      H: Chain = newChain()
      out1: seq[UdpForwardOut] = @[]
      back: seq[AmeDacRelayStep] = @[]
      i: int = 0
    discard H.F.setSuperFastBrake(1'u8)
    check pass(H, 1_000'u32) == 1
    discard H.F.setSuperFastBrake(0'u8)
    check pass(H, 2_000'u32) == 1
    check pass(H, 10_000'u32) == 0
    check pass(H, 2_000'u32 + uint32(controlKeepaliveMs)) == 1
    ## the server answered the order it was sent with its stance
    out1 = tickSuperFastControl(H.ctl, H.F, 62_000'u64 + uint64(controlKeepaliveMs))
    for o in out1:
      discard feedAmeDacDatagram(H.server, H.fwdKey, o.payload, 70_000'u32)
    back = tickAmeDacRelay(H.server, 70_001'u32)
    while i < back.len:
      if dacKeyEqual(back[i].peer, H.fwdKey) and back[i].send.len > 0:
        check H.ctl.fromServerControl(back[i].send[0], 70_002'u64).ok
      i = i + 1
    check H.ctl.heardMs == 70_002'u64

  # {.testKind: tkEdgeCase, covers: "controlSilent".}
  test "a link the server never answers counts as dead after 90 seconds":
    var
      H: Chain = newChain()
    discard H.F.setSuperFastBrake(1'u8)
    discard tickSuperFastControl(H.ctl, H.F, 1_000'u64)
    check not H.ctl.controlSilent(1_000'u64 + controlSilentMs)
    check H.ctl.controlSilent(1_001'u64 + controlSilentMs)

suite "super-fast control link carries an admin word":
  # {.testKind: tkIntegration, covers: "openFromServer|sealToServer".}
  test "a controller's request reaches the forwarder and its reply comes back":
    var
      H: Chain = newChain()
      slot: int = ameDacPeerSlot(H.server, H.fwdKey)
      req: ByteSeq = sealAmeDacControl(H.server.sessions[slot], dmkAdmin,
        @[byte 1, 2, 3])
      opened: AmeDacControlOpen = default(AmeDacControlOpen)
      reply: ByteSeq = @[]
      back: AmeDacControlOpen = default(AmeDacControlOpen)
    opened = H.ctl.openFromServer(req, 500'u64)
    check opened.ok
    check opened.kind == dmkAdmin
    check opened.body == @[byte 1, 2, 3]
    check H.ctl.heardMs == 500'u64
    reply = H.ctl.sealToServer(dmkAdminReply, @[byte 9])
    back = openAmeDacControl(H.server.sessions[slot], reply)
    check back.ok and back.kind == dmkAdminReply and back.body == @[byte 9]

  # {.testKind: tkEdgeCase, covers: "openFromServer".}
  test "junk is refused and counts as no sign of life":
    var
      H: Chain = newChain()
      opened: AmeDacControlOpen = H.ctl.openFromServer(@[byte 1, 2, 3], 700'u64)
    check not opened.ok
    check H.ctl.heardMs == 0'u64

  # {.testKind: tkUnit, covers: "openFromServer".}
  test "a stance is still read on the way":
    var
      H: Chain = newChain()
      slot: int = ameDacPeerSlot(H.server, H.fwdKey)
      opened: AmeDacControlOpen = H.ctl.openFromServer(sealAmeDacControl(
        H.server.sessions[slot], dmkBrakeStance, encodeDacBrakeStance(false)),
        10'u64)
    check opened.ok and opened.kind == dmkBrakeStance
    check H.ctl.deaf

suite "super-fast control link with several forwarders":
  # {.testKind: tkUnit, covers: "tickSuperFastControl|measureLoad".}
  test "the load is the sum of all of them; the brake is the strongest":
    var
      H: Chain = newChain(capacity = 100)
      out1: seq[UdpForwardOut] = @[]
      srv: transport_types.UdpAddress = initUdpAddress("10.0.0.2", 9000'u16)
    discard H.ctl.tickSuperFastControl(0'u64, 0'u8, srv, 0'u64)
    ## two routes pass 50 each in a second: together 100 = full load
    out1 = H.ctl.tickSuperFastControl(100'u64, 0'u8, srv, 1_000'u64)
    check out1.len == 1
    check H.ctl.level == 3'u8
    ## the strongest operator level among the routes counts too
    check H.ctl.tickSuperFastControl(100'u64, 3'u8, srv, 1_500'u64).len == 0
    check H.ctl.level == 3'u8

  # {.testKind: tkEdgeCase, covers: "measureLoad".}
  test "a total that goes down (a route was closed) is no load, not a wrap-around":
    var
      H: Chain = newChain(capacity = 100)
      srv: transport_types.UdpAddress = initUdpAddress("10.0.0.2", 9000'u16)
    discard H.ctl.tickSuperFastControl(5000'u64, 0'u8, srv, 0'u64)
    discard H.ctl.tickSuperFastControl(40'u64, 0'u8, srv, 1_000'u64)
    check H.ctl.loadLevel == 0'u8
    discard H.ctl.tickSuperFastControl(60'u64, 0'u8, srv, 2_000'u64)
    check H.ctl.loadLevel == 0'u8
