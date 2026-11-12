## ---------------------------------------------------------------------
## UDP Forward VIP Tests <- some clients are kept when the relay is crowded
## ---------------------------------------------------------------------
##
## The VIP list is only looked at while the relay is CONGESTED:
##
##   a brake is on  /  the client table is full  /  the NAS is away
##
## Time is passed in, so every rule is exact.

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/transport/types as transport_types
import ../../src/protocols/relay/super_fast_udp

proc ep(h: string, p: uint16 = 40000'u16): transport_types.UdpAddress =
  result = initUdpAddress(h, p)

proc nas(): transport_types.UdpAddress =
  result = initUdpAddress("10.0.0.2", 9000'u16)

proc away(cfg: UdpForwardConfig): RelaySuperFastUdp =
  ## A relay whose NAS was heard at 0 and has been silent for a long time.
  result = initRelaySuperFastUdp(nas(), cfg)
  discard noteNasSeen(result, nas(), 0'u64)

suite "VIP list":
  # {.testKind: tkUnit, covers: "addSuperFastVip".}
  test "fixed width; port 0 means every port of that host":
    var
      F: RelaySuperFastUdp = initRelaySuperFastUdp(nas(),
        initUdpForwardConfig(vipSlots = 2))
    check F.addSuperFastVip(ep("198.51.100.1", 0'u16)).ok
    check F.addSuperFastVip(ep("198.51.100.1", 0'u16)).ok
    check F.addSuperFastVip(ep("198.51.100.2", 5000'u16)).ok
    check not F.addSuperFastVip(ep("198.51.100.3", 1'u16)).ok
    check not F.addSuperFastVip(default(transport_types.UdpAddress)).ok
    F.clearSuperFastVips()
    check F.addSuperFastVip(ep("198.51.100.3", 1'u16)).ok

  # {.testKind: tkUnit, covers: "fromClient".}
  test "while nothing is congested the list is not used":
    var
      F: RelaySuperFastUdp = initRelaySuperFastUdp(nas())
      i: int = 0
    check F.addSuperFastVip(ep("198.51.100.1", 0'u16)).ok
    while i < 20:
      check fromClient(F, ep("198.51.100.1"), @[byte 1], 1000'u64).event ==
        ufeForwarded
      i = i + 1
    check F.vipForwarded == 0'u64

suite "VIP under a brake":
  # {.testKind: tkIntegration, covers: "fromClient".}
  test "the cap drops ordinary clients and spares the VIP":
    var
      F: RelaySuperFastUdp = initRelaySuperFastUdp(nas(),
        initUdpForwardConfig(brakePerSecond = [0, 4000, 1000, 5]))
      plain: int = 0
      vip: int = 0
      i: int = 0
    check F.addSuperFastVip(ep("198.51.100.1", 0'u16)).ok
    check F.setSuperFastBrake(3'u8).ok
    while i < 40:
      if fromClient(F, ep("203.0.113." & $(1 + i mod 20)), @[byte 1],
          1000'u64).event == ufeForwarded:
        plain = plain + 1
      if fromClient(F, ep("198.51.100.1"), @[byte 1], 1000'u64).event ==
          ufeForwarded:
        vip = vip + 1
      i = i + 1
    check plain == 5
    check vip == 40
    check F.vipForwarded == 40'u64
    check F.braked == 35'u64

suite "VIP with a full table":
  # {.testKind: tkIntegration, covers: "slotForClient".}
  test "a VIP newcomer takes the quietest ordinary place; an ordinary one is refused":
    var
      F: RelaySuperFastUdp = initRelaySuperFastUdp(nas(),
        initUdpForwardConfig(maxClients = 2))
    check F.addSuperFastVip(ep("198.51.100.1", 0'u16)).ok
    check fromClient(F, ep("203.0.113.1"), @[byte 1], 100'u64).event == ufeForwarded
    check fromClient(F, ep("203.0.113.2"), @[byte 1], 200'u64).event == ufeForwarded
    check F.usedSlots == 2
    check fromClient(F, ep("203.0.113.3"), @[byte 1], 300'u64).event == ufeDropped
    check fromClient(F, ep("198.51.100.1"), @[byte 1], 400'u64).event == ufeForwarded
    check F.usedSlots == 2
    check udpForwardClients(F) == 2
    ## the quietest ordinary client (203.0.113.1) lost its place; .2 kept it
    check fromClient(F, ep("203.0.113.2"), @[byte 1], 500'u64).event == ufeForwarded
    check F.vipForwarded == 1'u64

  # {.testKind: tkEdgeCase, covers: "slotForClient".}
  test "when every place is a VIP, nobody is pushed out":
    var
      F: RelaySuperFastUdp = initRelaySuperFastUdp(nas(),
        initUdpForwardConfig(maxClients = 1))
    check F.addSuperFastVip(ep("198.51.100.1", 0'u16)).ok
    check F.addSuperFastVip(ep("198.51.100.2", 0'u16)).ok
    check fromClient(F, ep("198.51.100.1"), @[byte 1], 100'u64).event == ufeForwarded
    check fromClient(F, ep("198.51.100.2"), @[byte 1], 200'u64).event == ufeDropped

suite "VIP while the NAS is away":
  # {.testKind: tkIntegration, covers: "bufferVipForNas|drainBuffer".}
  test "VIP datagrams wait in their own box and leave first":
    var
      F: RelaySuperFastUdp = away(initUdpForwardConfig(nasKeepaliveMs = 1000'u64,
        nasSilentMs = 2000'u64, bufferDatagrams = 2, vipBufferDatagrams = 2))
      back: UdpForwardStep = default(UdpForwardStep)
      i: int = 0
    check F.addSuperFastVip(ep("198.51.100.1", 0'u16)).ok
    while i < 4:
      discard fromClient(F, ep("203.0.113.1"), @[byte(10 + i)], 10_000'u64)
      i = i + 1
    discard fromClient(F, ep("198.51.100.1"), @[byte 1], 10_001'u64)
    discard fromClient(F, ep("198.51.100.1"), @[byte 2], 10_002'u64)
    check udpForwardBuffered(F) == 4
    back = noteNasSeen(F, nas(), 11_000'u64)
    check back.send.len == 4
    check back.send[0].payload == @[byte 1]
    check back.send[1].payload == @[byte 2]
    check back.send[2].payload == @[byte 12]
    check back.send[3].payload == @[byte 13]

  # {.testKind: tkEdgeCase, covers: "bufferVipForNas".}
  test "a full VIP box throws its OLDEST out and counts it":
    var
      F: RelaySuperFastUdp = away(initUdpForwardConfig(nasKeepaliveMs = 1000'u64,
        nasSilentMs = 2000'u64, vipBufferDatagrams = 2))
      back: UdpForwardStep = default(UdpForwardStep)
    check F.addSuperFastVip(ep("198.51.100.1", 0'u16)).ok
    discard fromClient(F, ep("198.51.100.1"), @[byte 1], 10_000'u64)
    discard fromClient(F, ep("198.51.100.1"), @[byte 2], 10_001'u64)
    discard fromClient(F, ep("198.51.100.1"), @[byte 3], 10_002'u64)
    check F.droppedTotal == 1'u64
    back = noteNasSeen(F, nas(), 11_000'u64)
    check back.send.len == 2
    check back.send[0].payload == @[byte 2]

suite "the NAS is never held back":
  # {.testKind: tkIntegration, covers: "fromNas".}
  test "answers pass under the strongest brake, with the table full":
    var
      F: RelaySuperFastUdp = initRelaySuperFastUdp(nas(),
        initUdpForwardConfig(maxClients = 1, brakePerSecond = [0, 1, 1, 1]))
      first: UdpForwardStep = default(UdpForwardStep)
      i: int = 0
    check F.setSuperFastBrake(3'u8).ok
    first = fromClient(F, ep("203.0.113.1"), @[byte 1], 1000'u64)
    check first.event == ufeForwarded
    while i < 50:
      check fromNas(F, F.nas, first.send[0].tag, @[byte 9], 1001'u64).event ==
        ufeForwarded
      i = i + 1
