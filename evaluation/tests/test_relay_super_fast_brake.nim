## ---------------------------------------------------------------------
## UDP Forward Brake Tests <- one slow-down for every client at once
## ---------------------------------------------------------------------
##
## relaySuperFastUDP opens no frame, so it cannot order a client to slow down.
## It limits how many datagrams per second it passes on, for all clients
## together. Time is passed in, so a second is exact.

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/transport/types as transport_types
import ../../src/protocols/relay/super_fast_udp

proc relay(rates: array[4, int] = udpForwardBrakePerSecond): RelaySuperFastUdp =
  result = initRelaySuperFastUdp(initUdpAddress("10.0.0.2", 9000'u16),
    initUdpForwardConfig(brakePerSecond = rates))

proc client(n: int): transport_types.UdpAddress =
  result = initUdpAddress("203.0.113." & $n, 40000'u16)

proc passed(F: var RelaySuperFastUdp, count: int, nowMs: uint64): int =
  ## How many of `count` datagrams (spread over clients) got through at nowMs.
  var
    i: int = 0
  while i < count:
    if fromClient(F, client(1 + i mod 50), @[byte 1], nowMs).event ==
        ufeForwarded:
      result = result + 1
    i = i + 1

suite "UDP forward brake":
  # {.testKind: tkUnit, covers: "setSuperFastBrake".}
  test "level 0 has no limit":
    var
      F: RelaySuperFastUdp = relay()
    check passed(F, 5000, 1000'u64) == 5000

  # {.testKind: tkUnit, covers: "setSuperFastBrake".}
  test "a level limits all clients together, per second":
    var
      F: RelaySuperFastUdp = relay([0, 4000, 100, 20])
    check F.setSuperFastBrake(3'u8) == ""
    check passed(F, 60, 1000'u64) == 20
    check F.braked == 40'u64
    check passed(F, 60, 1999'u64) == 0
    check passed(F, 60, 2000'u64) == 20

  # {.testKind: tkUnit, covers: "setSuperFastBrake".}
  test "level 0 again lifts it":
    var
      F: RelaySuperFastUdp = relay([0, 4000, 100, 20])
    discard F.setSuperFastBrake(3'u8)
    check passed(F, 60, 1000'u64) == 20
    discard F.setSuperFastBrake(0'u8)
    check passed(F, 60, 1000'u64) == 60

  # {.testKind: tkEdgeCase, covers: "setSuperFastBrake".}
  test "a level above 3 is refused and changes nothing":
    var
      F: RelaySuperFastUdp = relay()
    check F.setSuperFastBrake(4'u8) != ""
    check F.brake == 0'u8

  # {.testKind: tkUnit, covers: "fromNas".}
  test "answers from the NAS are not braked":
    var
      F: RelaySuperFastUdp = relay([0, 4000, 100, 1])
      first: UdpForwardStep = default(UdpForwardStep)
      back: UdpForwardStep = default(UdpForwardStep)
    discard F.setSuperFastBrake(3'u8)
    first = fromClient(F, client(1), @[byte 1], 1000'u64)
    check first.event == ufeForwarded
    check fromClient(F, client(1), @[byte 1], 1001'u64).event == ufeDropped
    back = fromNas(F, F.nas, first.send[0].tag, @[byte 2], 1002'u64)
    check back.event == ufeForwarded

  # {.testKind: tkEdgeCase, covers: "initUdpForwardConfig".}
  test "a negative rate is refused":
    expect ValueError:
      discard initUdpForwardConfig(brakePerSecond = [0, -1, 5, 5])
