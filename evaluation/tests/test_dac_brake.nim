## ---------------------------------------------------------------------
## DAC Brake Tests <- a relay slows a neighbour down; nobody else can
## ---------------------------------------------------------------------
##
##   relay (RelayFastExtraFrame) ==one AME link==> client (AmeDacRelay)
##
## The words are checked bare first, then on a link, then across a real
## sealed link in both directions.

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/config
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level2/seal_open
import ../../src/protocols/ame/level3/dac_relay
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/brake
import ../../src/protocols/dac/level0/defaults
import ../../src/protocols/dac/level1/scramble
import ../../src/protocols/dac/level3/link
import ../../src/protocols/dac/level3/link_table
import ../../src/protocols/relay/relay_node
import ../../src/protocols/relay/relay_brake
import ../../src/protocols/relay/fast_extra_frame
import ./relay_fixtures
import ./dac_link_support

proc quietLink(relay: bool, follows: bool = true): DacLink =
  ## A link with no scramble delay, so the only wait is the brake's.
  result = initDacLink(dacDefaultsFor(dscCleanLan), 1'u64,
    quietDacScramblePolicy())
  setDacPeerIsRelay(result, relay)
  setDacRelayForceRequest(result, follows)

proc orderOf(S: var DacLink, level: uint8, nowMs: uint32): DacLinkStep =
  result = feedDacMessage(S, dmkBrake, encodeDacBrake(level), nowMs)

suite "DAC brake words":
  # {.testKind: tkUnit, covers: "encodeDacBrake".}
  test "a brake body is one byte, 0..3, and nothing else":
    check encodeDacBrake(2'u8) == @[2'u8]
    check decodeDacBrake([3'u8]) == 3'u8
    expect ValueError:
      discard decodeDacBrake([4'u8])
    expect ValueError:
      discard decodeDacBrake([])
    expect ValueError:
      discard decodeDacBrake([1'u8, 0'u8])

  # {.testKind: tkUnit, covers: "decodeDacBrakeStance".}
  test "a stance body is one byte, 0 or 1":
    check decodeDacBrakeStance(encodeDacBrakeStance(true))
    check not decodeDacBrakeStance(encodeDacBrakeStance(false))
    expect ValueError:
      discard decodeDacBrakeStance([2'u8])

  # {.testKind: tkEdgeCase, covers: "dacBrakeChunkBytes".}
  test "the chunk shrinks by level and never below the floor":
    check dacBrakeChunkBytes(1200'u16, 0'u8) == 1200'u16
    check dacBrakeChunkBytes(1200'u16, 1'u8) == 900'u16
    check dacBrakeChunkBytes(1200'u16, 3'u8) == 300'u16
    check dacBrakeChunkBytes(400'u16, 3'u8) == dacBrakeMinChunkBytes
    check dacBrakeChunkBytes(100'u16, 3'u8) == 100'u16

  # {.testKind: tkUnit, covers: "dacBrakeForLoad".}
  test "load picks a level":
    check dacBrakeForLoad(0, 100) == 0'u8
    check dacBrakeForLoad(49, 100) == 0'u8
    check dacBrakeForLoad(50, 100) == 1'u8
    check dacBrakeForLoad(75, 100) == 2'u8
    check dacBrakeForLoad(90, 100) == 3'u8
    check dacBrakeForLoad(5, 0) == 0'u8

suite "DAC brake on a link":
  # {.testKind: tkUnit, covers: "feedDacMessage".}
  test "a relay's order slows the sends and shrinks the chunks":
    var
      S: DacLink = quietLink(true)
      step: DacLinkStep = default(DacLinkStep)
      msgs: seq[DacTaggedMessage] = @[]
    check dacSendDelayMs(S) == 0'u16
    step = orderOf(S, 2'u8, 100'u32)
    check step.kind == dlkBrakeReceived
    check dacBrakeLevel(S) == 2'u8
    check dacSendDelayMs(S) == 16'u16
    msgs = beginDacPackage(S, 9'u64, rampBytes(8_000), 100'u32)
    check S.outgoing.plan.manifest.chunkBytes == 600'u16

  # {.testKind: tkUnit, covers: "feedDacMessage".}
  test "an order from a peer that is not a relay is ignored":
    var
      S: DacLink = quietLink(false)
      step: DacLinkStep = orderOf(S, 3'u8, 5'u32)
    check step.kind == dlkIgnored
    check dacBrakeLevel(S) == 0'u8
    check dacSendDelayMs(S) == 0'u16

  # {.testKind: tkUnit, covers: "feedDacMessage".}
  test "an order is a lease: it lapses unless it is repeated":
    var
      S: DacLink = quietLink(true)
    discard orderOf(S, 3'u8, 1_000'u32)
    discard tickDacLink(S, 1_000'u32 + dacBrakeHoldMs)
    check dacBrakeLevel(S) == 3'u8
    discard tickDacLink(S, 1_001'u32 + dacBrakeHoldMs)
    check dacBrakeLevel(S) == 0'u8
    discard orderOf(S, 3'u8, 50_000'u32)
    discard orderOf(S, 3'u8, 70_000'u32)
    discard tickDacLink(S, 90_000'u32)
    check dacBrakeLevel(S) == 3'u8

  # {.testKind: tkUnit, covers: "feedDacMessage".}
  test "level 0 resets everything":
    var
      S: DacLink = quietLink(true)
    discard orderOf(S, 3'u8, 10'u32)
    discard orderOf(S, 0'u8, 20'u32)
    check dacBrakeLevel(S) == 0'u8
    check dacSendDelayMs(S) == 0'u16

  # {.testKind: tkEdgeCase, covers: "feedDacMessage".}
  test "a body that is not 0..3 changes nothing":
    var
      S: DacLink = quietLink(true)
      step: DacLinkStep = feedDacMessage(S, dmkBrake, @[7'u8], 10'u32)
    check step.kind == dlkIgnored
    check dacBrakeLevel(S) == 0'u8

  # {.testKind: tkUnit, covers: "setDacRelayForceRequest".}
  test "a side that refuses says so once, and ignores the order":
    var
      S: DacLink = quietLink(true, follows = false)
      step: DacLinkStep = tickDacLink(S, 1'u32)
    check step.messages.len == 1
    check step.messages[0].kind == dmkBrakeStance
    check not decodeDacBrakeStance(step.messages[0].body)
    check tickDacLink(S, 2'u32).messages.len == 0
    step = orderOf(S, 3'u8, 3'u32)
    check step.kind == dlkIgnored
    check dacBrakeLevel(S) == 0'u8
    check tickDacLink(S, 4'u32).messages.len == 1

  # {.testKind: tkUnit, covers: "setDacRelayForceRequest".}
  test "a side that follows, or a peer that is no relay, announces nothing":
    var
      A: DacLink = quietLink(true)
      B: DacLink = quietLink(false, follows = false)
    check tickDacLink(A, 1'u32).messages.len == 0
    check tickDacLink(B, 1'u32).messages.len == 0

proc linkOf(R: AmeDacRelay, k: DacLinkKey): int =
  result = ameDacPeerSlot(R, k)

suite "DAC brake across a sealed link":
  # {.testKind: tkIntegration, covers: "setRelayBrake".}
  test "the relay orders, repeats, and resets":
    var
      P: RtPair = rtPair(1'u8)
      N: RelayFastExtraFrame = initRelayFastExtraFrame(idR1)
      C: AmeDacRelay = initAmeDacRelay(dacDefaultsFor(dscCleanLan), 3'u64)
      key: DacLinkKey = initDacLinkKey("10.0.0.16", 47656'u16)
      adm = N.admitRelayNeighbour(P.left, idPhone, "phone", at(idPhone),
        acrDac)
      step: RelayStep = default(RelayStep)
      got: AmeDacRelayStep = default(AmeDacRelayStep)
      steps: seq[RelayStep] = @[]
      slot: int = 0
    check adm.ok
    check admitAmeDacPeer(C, key, P.right, 0'u32, peerIsRelay = true).ok
    slot = linkOf(C, key)
    step = N.setRelayBrake(adm.slot, 2'u8, 1_000'u32)
    check step.send.len == 1
    check relayBrakeOf(N, adm.slot) == 2'u8
    got = feedAmeDacDatagram(C, key, step.send[0].frame, 1_000'u32)
    check got.kind == adrProgress
    check dacBrakeLevel(C.table.slots[slot].link) == 2'u8
    check N.setRelayBrake(adm.slot, 2'u8, 1_100'u32).send.len == 0
    check N.tickRelayBrakes(5_000'u32).len == 0
    steps = N.tickRelayBrakes(1_000'u32 + dacBrakeRefreshMs)
    check steps.len == 1
    check steps[0].send.len == 1
    discard feedAmeDacDatagram(C, key, steps[0].send[0].frame,
      1_000'u32 + dacBrakeRefreshMs)
    steps = N.resetRelayBrakes(30_000'u32)
    check steps.len == 1
    discard feedAmeDacDatagram(C, key, steps[0].send[0].frame, 30_000'u32)
    check dacBrakeLevel(C.table.slots[slot].link) == 0'u8
    check relayBrakeOf(N, adm.slot) == 0'u8

  # {.testKind: tkIntegration, covers: "feedRelayBrake".}
  test "a client that will not follow tells the relay at the start":
    var
      P: RtPair = rtPair(2'u8)
      N: RelayFastExtraFrame = initRelayFastExtraFrame(idR1)
      C: AmeDacRelay = initAmeDacRelay(dacDefaultsFor(dscCleanLan), 3'u64,
        relayForceRequest = false)
      key: DacLinkKey = initDacLinkKey("10.0.0.16", 47656'u16)
      adm = N.admitRelayNeighbour(P.left, idPhone, "phone", at(idPhone),
        acrDac)
      ticks: seq[AmeDacRelayStep] = @[]
      step: RelayStep = default(RelayStep)
    check admitAmeDacPeer(C, key, P.right, 0'u32, peerIsRelay = true).ok
    check relayFollowsBrake(N, adm.slot)
    ticks = tickAmeDacRelay(C, 10'u32)
    check ticks.len == 1
    check ticks[0].send.len == 1
    step = N.feedRelayFastExtraFrame(adm.slot, ticks[0].send[0], 10'u32)
    check step.event == reAnswered
    check not relayFollowsBrake(N, adm.slot)
    check N.setRelayBrake(adm.slot, 3'u8, 20'u32).send.len == 0
    check relayBrakeOf(N, adm.slot) == 0'u8

  # {.testKind: tkIntegration, covers: "feedRelayBrake".}
  test "a lost stance is repaired by the next order the client refuses":
    var
      P: RtPair = rtPair(3'u8)
      N: RelayFastExtraFrame = initRelayFastExtraFrame(idR1)
      C: AmeDacRelay = initAmeDacRelay(dacDefaultsFor(dscCleanLan), 3'u64,
        relayForceRequest = false)
      key: DacLinkKey = initDacLinkKey("10.0.0.16", 47656'u16)
      adm = N.admitRelayNeighbour(P.left, idPhone, "phone", at(idPhone),
        acrDac)
      order: RelayStep = default(RelayStep)
      ticks: seq[AmeDacRelayStep] = @[]
    check admitAmeDacPeer(C, key, P.right, 0'u32, peerIsRelay = true).ok
    discard tickAmeDacRelay(C, 10'u32)
    order = N.setRelayBrake(adm.slot, 1'u8, 20'u32)
    check order.send.len == 1
    discard feedAmeDacDatagram(C, key, order.send[0].frame, 20'u32)
    ticks = tickAmeDacRelay(C, 30'u32)
    check ticks.len == 1
    discard N.feedRelayFastExtraFrame(adm.slot, ticks[0].send[0], 30'u32)
    check not relayFollowsBrake(N, adm.slot)

  # {.testKind: tkEdgeCase, covers: "feedRelayBrake".}
  test "a client cannot order a relay: only the stance is read":
    var
      P: RtPair = rtPair(4'u8)
      N: RelayFastExtraFrame = initRelayFastExtraFrame(idR1)
      adm = N.admitRelayNeighbour(P.left, idPhone, "phone", at(idPhone),
        acrDac)
      frame: ByteSeq = @[]
      step: RelayStep = default(RelayStep)
    frame = sealAmeDacControl(P.right, dmkBrake, encodeDacBrake(3'u8))
    step = N.feedRelayFastExtraFrame(adm.slot, frame, 5'u32)
    check step.event == reDropped
    check relayBrakeOf(N, adm.slot) == 0'u8
    check relayFollowsBrake(N, adm.slot)

suite "DAC brake setting":
  # {.testKind: tkUnit, covers: "parseBifrostConfigText".}
  test "relayForceRequest is on by default and can be switched off":
    check defaultBifrostConfig().relayForceRequest
    check parseBifrostConfigText("relayForceRequest = true").relayForceRequest
    check not parseBifrostConfigText(
      "relayForceRequest = false").relayForceRequest
    check initAmeDacRelay(dacDefaultsFor(dscCleanLan), 1'u64).relayForceRequest
