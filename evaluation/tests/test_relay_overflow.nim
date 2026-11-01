## ---------------------------------------------------------------------
## Relay Overflow Tests <- a crowded relay holds a few frames instead of
##                         losing all of them
## ---------------------------------------------------------------------
##
##   frames in -> budget left?  yes -> out now
##                              no  -> fixed-width ring (oldest out when full)
##   next turn -> the ring empties first, oldest first, up to the budget

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level2/route_wire
import ../../src/protocols/transport/types as transport_types
import ../../src/protocols/relay/overflow_ring
import ../../src/protocols/relay/relay_node
import ../../src/protocols/relay/fast_extra_frame
import ../../src/protocols/relay/super_fast_udp
import ./relay_fixtures

proc forwardFrom(R: var RelayFastExtraFrame, slot: int, link: var RtPair,
    n: int): RelayStep =
  ## One forward from the phone, fed to the relay. The phone's session is
  ## passed by reference: each frame must carry the NEXT sequence number.
  result = R.feedRelayFastExtraFrame(slot, sealAmeRouteForward(link.left,
    idNas, @[byte n]), 0'u32)

suite "overflow ring":
  # {.testKind: tkUnit, covers: "addLast".}
  test "first in, first out; a full ring throws the oldest out":
    var
      B: OverflowRing[int] = initOverflowRing[int](3)
    check B.width == 3
    check B.addLast(1) and B.addLast(2) and B.addLast(3)
    check B.isFull
    check B.addLast(4)
    check B.dropped == 1'u64
    check B.len == 3
    check B.popFirst() == 2
    check B.popFirst() == 3
    check B.popFirst() == 4
    check B.len == 0

  # {.testKind: tkEdgeCase, covers: "addLast".}
  test "width 0 holds nothing and counts what it refused":
    var
      B: OverflowRing[int] = initOverflowRing[int](0)
    check not B.addLast(1)
    check B.len == 0
    check B.dropped == 1'u64

  # {.testKind: tkUnit, covers: "addLast".}
  test "the ring wraps around many times and never grows":
    var
      B: OverflowRing[int] = initOverflowRing[int](4)
      i: int = 0
    while i < 1000:
      discard B.addLast(i)
      i = i + 1
    check B.width == 4
    check B.popFirst() == 996

suite "keyed relay overflow":
  # {.testKind: tkIntegration, covers: "queueSend|tickRelayOverflow".}
  test "past the budget frames wait in the ring, then leave oldest first":
    var
      phone: RtPair = rtPair(1'u8)
      nas: RtPair = rtPair(2'u8)
      R: RelayFastExtraFrame = initRelayFastExtraFrame(idR1, 4,
        overflowSlots = 3)
      sPhone: int = R.admitRelayNeighbour(phone.right, idPhone, "phone",
        at(idPhone), acrDac).slot
      sNas: int = R.admitRelayNeighbour(nas.right, idNas, "nas", at(idNas),
        acrDac).slot
      step: RelayStep = default(RelayStep)
      out1: int = 0
      i: int = 0
    R.addRelayTarget(idNas, "nas", ["phone"])
    R.setRelayBudget(2)
    discard sNas
    while i < 6:
      step = forwardFrom(R, sPhone, phone, i)
      out1 = out1 + step.send.len
      i = i + 1
    check out1 == 2
    check relayOverflowHeld(R) == 3
    check relayOverflowDropped(R) == 1'u64
    step = R.tickRelayOverflow()
    check step.send.len == 2
    check step.send[0].address == at(idNas)
    check relayOverflowHeld(R) == 1
    step = R.tickRelayOverflow()
    check step.send.len == 1
    check relayOverflowHeld(R) == 0

  # {.testKind: tkEdgeCase, covers: "tickRelayOverflow".}
  test "a frame for a neighbour that has left is dropped, not re-aimed":
    var
      phone: RtPair = rtPair(3'u8)
      nas: RtPair = rtPair(4'u8)
      R: RelayFastExtraFrame = initRelayFastExtraFrame(idR1, 4)
      sPhone: int = R.admitRelayNeighbour(phone.right, idPhone, "phone",
        at(idPhone), acrDac).slot
      sNas: int = R.admitRelayNeighbour(nas.right, idNas, "nas", at(idNas),
        acrDac).slot
      step: RelayStep = default(RelayStep)
    R.addRelayTarget(idNas, "nas", ["phone"])
    R.setRelayBudget(1)
    discard forwardFrom(R, sPhone, phone, 1)
    discard forwardFrom(R, sPhone, phone, 2)
    check relayOverflowHeld(R) == 1
    R.releaseRelayNeighbour(sNas)
    step = R.tickRelayOverflow()
    check step.send.len == 0
    check relayOverflowHeld(R) == 0

  # {.testKind: tkUnit, covers: "setRelayBudget".}
  test "budget 0 means no limit and the ring stays empty":
    var
      phone: RtPair = rtPair(5'u8)
      nas: RtPair = rtPair(6'u8)
      R: RelayFastExtraFrame = initRelayFastExtraFrame(idR1, 4)
      sPhone: int = R.admitRelayNeighbour(phone.right, idPhone, "phone",
        at(idPhone), acrDac).slot
      i: int = 0
      sent: int = 0
    discard R.admitRelayNeighbour(nas.right, idNas, "nas", at(idNas), acrDac)
    R.addRelayTarget(idNas, "nas", ["phone"])
    while i < 10:
      sent = sent + forwardFrom(R, sPhone, phone, i).send.len
      i = i + 1
    check sent == 10
    check relayOverflowHeld(R) == 0

suite "super-fast relay overflow":
  # {.testKind: tkIntegration, covers: "fromClient".}
  test "the width is the setting: 3 held, the rest counted as dropped":
    var
      F: RelaySuperFastUdp = initRelaySuperFastUdp(
        initUdpAddress("10.0.0.2", 9000'u16),
        initUdpForwardConfig(nasKeepaliveMs = 1000'u64, nasSilentMs = 2000'u64,
          bufferDatagrams = 3))
      c: transport_types.UdpAddress = initUdpAddress("203.0.113.1", 4000'u16)
      i: int = 0
    discard noteNasSeen(F, initUdpAddress("10.0.0.2", 9000'u16), 0'u64)
    while i < 5:
      discard fromClient(F, c, @[byte i], 10_000'u64)
      i = i + 1
    check udpForwardBuffered(F) == 3
    check F.droppedTotal == 2'u64
    check F.buffer.width == 3
