## -------------------------------------------------------------------------
## relayFastExtraFrame Tests <- one link handshake, then end to end through relays
## -------------------------------------------------------------------------
##
## The picture every multi-hop test below builds:
##
##   phone (0x30) ==A==> router 1 (0x10) ==B==> router 2 (0x11) ==C==> nas (0x20)
##
## Each `==X==>` is one AME LINK session: one end held by the left node,
## the other by the right. Every node -- the phone and the nas too -- is an
## RelayFastExtraFrame with its own id. No socket is opened; a frame is handed from
## one node to the next by hand, so every rule is checked exactly.
##
##   what is checked                         where
##   --------------------------------------  ---------------------------
##   the Gimli block opens only in place     "AME route block"
##   the ART frame, its tag and replay       "AME route wire"
##   the directory question, inside FOMKE    "AME route directory"
##   Def. 2 (who may send) and Def. 3        "relayFastExtraFrame, one hop"
##   two routers, end to end, and back       "relayFastExtraFrame, two hops"

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/secret_stack
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/path_triggers
import ../../src/protocols/ame/level1/route_block
import ../../src/protocols/ame/level2/seal_open
import ../../src/protocols/ame/level2/session
import ../../src/protocols/ame/level2/route_wire
import ../../src/protocols/ame/level2/route_directory
import ../../src/protocols/transport/types as transport_types
import ../../src/protocols/relay/relay_node
import ../../src/protocols/relay/fast_extra_frame
import ../../src/protocols/ame/level3/handshake
import ../../src/protocols/ame/level3/handshake_wire
import ./relay_fixtures
import runePragmas

proc onlyFrame(step: RelayStep, slot: int): ByteSeq =
  ## step/slot: the single frame the node queued, which must be for slot.
  check step.send.len == 1
  check step.send[0].slot == slot
  if step.send.len == 1:
    result = step.send[0].frame

proc containsWindow(A, B: openArray[byte]): bool =
  ## A/B: true when B appears anywhere inside A.
  var
    i: int = 0
  while i + B.len <= A.len:
    if A[i ..< i + B.len] == B:
      return true
    i = i + 1

proc testKey(seed: byte): ByteSeq =
  result = newSeq[uint8](ameRouteKeyLen)
  result[0] = seed

proc testNonce(seed: byte): ByteSeq =
  result = newSeq[uint8](ameRouteNonceLen)
  result[15] = seed

suite "AME route block":
  # {.testKind: tkUnit, covers: "sealAmeRouteBlock|openAmeRouteBlock".}
  test "a block opens with the same key and nonce":
    var
      sealed: ByteSeq = sealAmeRouteBlock(testKey(7), testNonce(1), idNas,
        idPhone)
      ids: AmeRouteIds = openAmeRouteBlock(testKey(7), testNonce(1), sealed)
    check sealed.len == ameRouteBlockLen
    check ids.ok
    check ids.target == idNas
    check ids.origin == idPhone

  # {.testKind: tkEdgeCase, covers: "openAmeRouteBlock".}
  test "another nonce, another key, a flipped bit or a short block fail":
    var
      sealed: ByteSeq = sealAmeRouteBlock(testKey(7), testNonce(1), idNas, 0)
      flipped: ByteSeq = sealed
    flipped[3] = flipped[3] xor 0x01'u8
    check not openAmeRouteBlock(testKey(7), testNonce(2), sealed).ok
    check not openAmeRouteBlock(testKey(8), testNonce(1), sealed).ok
    check not openAmeRouteBlock(testKey(7), testNonce(1), flipped).ok
    check not openAmeRouteBlock(testKey(7), testNonce(1), sealed[0 .. 22]).ok

  # {.testKind: tkUnit, covers: "sealAmeRouteBlock".}
  test "the same ids under two nonces do not look alike":
    var
      a: ByteSeq = sealAmeRouteBlock(testKey(7), testNonce(1), idNas, 0)
      b: ByteSeq = sealAmeRouteBlock(testKey(7), testNonce(2), idNas, 0)
    check a[0 .. 15] != b[0 .. 15]

suite "AME route wire":
  # {.testKind: tkUnit, covers: "sealAmeRouteForward|openAmeRouteFrame".}
  test "a forward carries target, hops and the payload untouched":
    var
      link: RtPair = rtPair(2'u8)
      frame: ByteSeq = sealAmeRouteForward(link.left, idNas, @[byte 1, 2, 3])
      got: AmeRouteFrame = default(AmeRouteFrame)
    check isAmeRouteFrame(frame)
    check frame.len == ameRouteOverhead + 3
    check frame[^3 .. ^1] == @[byte 1, 2, 3]
    check not containsWindow(frame, @[byte 0x20, 0, 0, 0, 0, 0, 0, 0])
    got = openAmeRouteFrame(link.right, frame)
    check got.ok
    check got.kind == arkForward
    check got.target == idNas
    check got.origin == 0'u64
    check got.hopsLeft == ameRouteDefaultHops
    check got.payload == @[byte 1, 2, 3]

  # {.testKind: tkUnit, covers: "isAmeRouteFrame".}
  test "an ordinary AME frame is not a route frame":
    var
      link: RtPair = rtPair(3'u8)
    check not isAmeRouteFrame(sealAmeDacFrame(link.left, @[byte 1, 2, 3]))
    check not isAmeRouteFrame(@[byte 0x41, 0x52, 0x54, 1])

  # {.testKind: tkRegression, covers: "openAmeRouteFrame", pins: "a captured route frame could be sent again".}
  test "a frame seen once is refused the second time":
    var
      link: RtPair = rtPair(4'u8)
      first: ByteSeq = sealAmeRouteForward(link.left, idNas, @[byte 1])
      second: ByteSeq = sealAmeRouteForward(link.left, idNas, @[byte 2])
    check openAmeRouteFrame(link.right, second).ok
    check openAmeRouteFrame(link.right, first).ok        # late, not replayed
    check openAmeRouteFrame(link.right, first).err ==
      "AME route replay rejected"
    check openAmeRouteFrame(link.right, second).err ==
      "AME route replay rejected"

  # {.testKind: tkEdgeCase, covers: "openAmeRouteFrame".}
  test "a frame older than the 64-frame window is refused":
    var
      link: RtPair = rtPair(5'u8)
      old: ByteSeq = sealAmeRouteForward(link.left, idNas, @[byte 1])
      i: int = 0
    while i < 70:
      check openAmeRouteFrame(link.right,
        sealAmeRouteForward(link.left, idNas, @[byte 2])).ok
      i = i + 1
    check openAmeRouteFrame(link.right, old).err == "AME route replay rejected"

  # {.testKind: tkEdgeCase, covers: "openAmeRouteFrame".}
  test "an edited counter, hop count or length breaks the tag":
    ## Each edit is checked on a fresh copy; none may open. A failed tag
    ## must not move the replay window either, so the honest frame still
    ## opens at the end.
    var
      link: RtPair = rtPair(6'u8)
      frame: ByteSeq = sealAmeRouteForward(link.left, idNas, @[byte 1, 2])
      edited: ByteSeq = @[]
    edited = frame
    edited[14] = edited[14] xor 0x05'u8
    check openAmeRouteFrame(link.right, edited).err ==
      "AME route block did not authenticate"
    edited = frame
    edited[5] = 0x40'u8
    check not openAmeRouteFrame(link.right, edited).ok
    edited = frame
    edited.add(0x00'u8)
    check not openAmeRouteFrame(link.right, edited).ok
    edited = frame[0 .. ^2]
    check not openAmeRouteFrame(link.right, edited).ok
    edited = frame
    edited[6] = edited[6] xor 0x01'u8
    check openAmeRouteFrame(link.right, edited).err ==
      "AME route frame belongs to another session"
    check openAmeRouteFrame(link.right, frame).ok

  # {.testKind: tkEdgeCase, covers: "openAmeRouteFrame".}
  test "the payload's content is the end-to-end frame's to protect":
    ## Same length, other bytes: the route tag does not cover the content
    ## (Def. 2 in route_wire.nim). It opens here; the end-to-end session at
    ## the target is what refuses it.
    var
      link: RtPair = rtPair(7'u8)
      frame: ByteSeq = sealAmeRouteForward(link.left, idNas, @[byte 1, 2])
    frame[^1] = 0x09'u8
    check openAmeRouteFrame(link.right, frame).ok

  # {.testKind: tkUnit, covers: "sealAmeRouteRefuse|openAmeRouteFrame".}
  test "a refusal carries ids and reason, and no payload":
    var
      link: RtPair = rtPair(8'u8)
      frame: ByteSeq = sealAmeRouteRefuse(link.right, idCam, idPhone,
        arrHopsSpent)
      got: AmeRouteFrame = openAmeRouteFrame(link.left, frame)
    check frame.len == ameRouteOverhead
    check got.ok
    check got.kind == arkRefuse
    check got.target == idCam
    check got.origin == idPhone
    check got.refusal == arrHopsSpent
    expect ValueError:
      discard sealAmeRouteRefuse(link.right, idCam, idPhone, arrNone)

  # {.testKind: tkEdgeCase, covers: "openAmeRouteFrame".}
  test "a frame sealed on one link does not open on another":
    var
      a: RtPair = rtPair(9'u8)
      b: RtPair = rtPair(10'u8)
    check not openAmeRouteFrame(b.right,
      sealAmeRouteForward(a.left, idNas, @[byte 1])).ok

suite "AME route directory":
  # {.testKind: tkUnit, covers: "sealAmeRouteAsk|openAmeRouteDirectory".}
  test "ask and directory survive the wire":
    var
      link: RtPair = rtPair(11'u8)
      got: AmeRouteDirectory = default(AmeRouteDirectory)
      page: AmeRouteDirectory = AmeRouteDirectory(kind: araDirectory,
        start: 0, total: 2, entries: @[AmeRouteEntry(id: idNas, name: "nas"),
        AmeRouteEntry(id: idCam, name: "")])
    got = openAmeRouteDirectory(link.right, acrDac,
      sealAmeRouteAsk(link.left, acrDac, 3'u16))
    check got.ok
    check got.kind == araAsk
    check got.start == 3'u16
    got = openAmeRouteDirectory(link.left, acrDac,
      sealAmeRouteDirectory(link.right, acrDac, page))
    check got.ok
    check got.kind == araDirectory
    check got.total == 2'u16
    check got.entries == page.entries

  # {.testKind: tkEdgeCase, covers: "openAmeRouteDirectory".}
  test "a body that does not parse is refused, never raised":
    var
      link: RtPair = rtPair(12'u8)
    check not openAmeRouteDirectory(link.right, acrDac,
      sealControlFrame(link.left, ampkRoute, acrDac, @[byte 0x09, 0, 0])).ok
    check not openAmeRouteDirectory(link.right, acrDac,
      sealControlFrame(link.left, ampkRoute, acrDac, @[byte 0x01, 0])).ok
    check not openAmeRouteDirectory(link.right, acrDac,
      sealControlFrame(link.left, ampkRoute, acrDac,
      @[byte 0x02, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 40])).ok

  # {.testKind: tkEdgeCase, covers: "sealAmeRouteDirectory".}
  test "names over 32 bytes and pages over 24 lines are not written":
    var
      link: RtPair = rtPair(13'u8)
      page: AmeRouteDirectory = AmeRouteDirectory(kind: araDirectory,
        total: 1, entries: @[AmeRouteEntry(id: idNas, name: newString(33))])
    expect ValueError:
      discard sealAmeRouteDirectory(link.left, acrDac, page)
    page.entries = newSeq[AmeRouteEntry](25)
    page.total = 25
    expect ValueError:
      discard sealAmeRouteDirectory(link.left, acrDac, page)

suite "relayFastExtraFrame, one hop":
  ## phone (0x30), laptop (0x31) and nas (0x20) on one router (0x10).
  ## nas is visible to the phone; cam is listed for the laptop only.
  setup:
    var
      R: RelayFastExtraFrame = initRelayFastExtraFrame(idR1, 8)
      phoneNode: RelayFastExtraFrame = initRelayFastExtraFrame(idPhone, 1)
      nasNode: RelayFastExtraFrame = initRelayFastExtraFrame(idNas, 1)
      phone: RtPair = rtPair(20'u8)
      laptop: RtPair = rtPair(21'u8)
      nas: RtPair = rtPair(22'u8)
      sPhone: int = -1
      sLaptop: int = -1
      sNas: int = -1
      step: RelayStep = default(RelayStep)
      dir: AmeRouteDirectory = default(AmeRouteDirectory)
    R.addRelayTarget(idNas, "nas", ["phone"])
    R.addRelayTarget(idCam, "cam", ["laptop"])
    sPhone = R.admitRelayNeighbour(phone.right, idPhone, "phone", at(idPhone), acrDac).slot
    sLaptop = R.admitRelayNeighbour(laptop.right, idLaptop, "laptop", at(idLaptop),
      acrDac).slot
    sNas = R.admitRelayNeighbour(nas.right, idNas, "nas", at(idNas), acrDac).slot
    discard phoneNode.admitRelayNeighbour(phone.left, idR1, "router1", at(idR1), acrDac,
      router = true)
    discard nasNode.admitRelayNeighbour(nas.left, idR1, "router1", at(idR1), acrDac,
      router = true)

  # {.testKind: tkUnit, covers: "feedRelayAsk".}
  test "the directory lists only what this identity may see":
    step = R.feedRelayAsk(sPhone, sealAmeRouteAsk(phone.left, acrDac))
    check step.event == reAnswered
    dir = openAmeRouteDirectory(phone.left, acrDac, onlyFrame(step, sPhone))
    check dir.kind == araDirectory
    check dir.total == 1'u16
    check dir.entries == @[AmeRouteEntry(id: idNas, name: "nas")]

  # {.testKind: tkEdgeCase, covers: "feedRelayAsk".}
  test "a long directory is read in pages of 24":
    var
      i: int = 0
      seen: seq[AmeRouteEntry] = @[]
    while i < 30:
      R.addRelayTarget(0x1000'u64 + uint64(i), "t" & $i, ["*"])
      i = i + 1
    while seen.len < 31:
      step = R.feedRelayAsk(sPhone, sealAmeRouteAsk(phone.left, acrDac,
        uint16(seen.len)))
      dir = openAmeRouteDirectory(phone.left, acrDac, onlyFrame(step, sPhone))
      check dir.total == 31'u16
      check dir.start == uint16(seen.len)
      check dir.entries.len == min(ameRoutePageEntries, 31 - seen.len)
      seen.add(dir.entries)
    check seen[0].name == "nas"
    check seen[30].name == "t29"
    step = R.feedRelayAsk(sPhone, sealAmeRouteAsk(phone.left, acrDac,
      500'u16))
    dir = openAmeRouteDirectory(phone.left, acrDac, onlyFrame(step, sPhone))
    check dir.ok
    check dir.entries.len == 0

  # {.testKind: tkIntegration, covers: "feedRelayFastExtraFrame".}
  test "forward, deliver, and the answer back":
    var
      sent: ByteSeq = @[]
    step = R.feedRelayFastExtraFrame(sPhone, sealAmeRouteForward(phone.left, idNas,
      @[byte 1, 2, 3]), 0'u32)
    check step.event == reForwarded
    sent = onlyFrame(step, sNas)
    step = nasNode.feedRelayFastExtraFrame(0, sent, 0'u32)
    check step.event == reDelivered
    check step.frame.target == idNas
    check step.frame.origin == idPhone
    check step.frame.hopsLeft == ameRouteDefaultHops - 1'u8
    check step.frame.payload == @[byte 1, 2, 3]
    ## The nas has no line visible to it naming the phone. It may answer
    ## anyway, because the phone may write to it (Def. 2, the reverse).
    step = R.feedRelayFastExtraFrame(sNas, sealAmeRouteForward(nas.left,
      step.frame.origin, @[byte 9]), 0'u32)
    check step.event == reForwarded
    step = phoneNode.feedRelayFastExtraFrame(0, onlyFrame(step, sPhone), 0'u32)
    check step.event == reDelivered
    check step.frame.origin == idNas
    check step.frame.payload == @[byte 9]

  # {.testKind: tkUnit, covers: "feedRelayFastExtraFrame".}
  test "a forward for the router itself is delivered there":
    step = R.feedRelayFastExtraFrame(sLaptop, sealAmeRouteForward(laptop.left,
      idR1, @[byte 5]), 0'u32)
    check step.event == reDelivered
    check step.send.len == 0
    check step.frame.origin == idLaptop
    check step.frame.payload == @[byte 5]

  # {.testKind: tkEdgeCase, covers: "feedRelayFastExtraFrame".}
  test "hidden and unknown targets get the same refusal":
    var
      hidden: RelayStep = default(RelayStep)
      unknown: RelayStep = default(RelayStep)
    step = R.feedRelayFastExtraFrame(sPhone, sealAmeRouteForward(phone.left,
      idCam, @[byte 1]), 0'u32)
    check step.event == reRefused
    hidden = phoneNode.feedRelayFastExtraFrame(0, onlyFrame(step, sPhone), 0'u32)
    step = R.feedRelayFastExtraFrame(sPhone, sealAmeRouteForward(phone.left,
      0x99'u64, @[byte 1]), 0'u32)
    unknown = phoneNode.feedRelayFastExtraFrame(0, onlyFrame(step, sPhone), 0'u32)
    check hidden.event == reRefused
    check hidden.frame.refusal == arrNoRoute
    check unknown.frame.refusal == hidden.frame.refusal
    check hidden.frame.target == idCam
    check hidden.send.len == 0

  # {.testKind: tkEdgeCase, covers: "feedRelayFastExtraFrame".}
  test "a forward with no hops left is refused":
    step = R.feedRelayFastExtraFrame(sPhone, sealAmeRouteForward(phone.left, idNas,
      @[byte 1], 0'u8), 0'u32)
    step = phoneNode.feedRelayFastExtraFrame(0, onlyFrame(step, sPhone), 0'u32)
    check step.frame.refusal == arrHopsSpent

  # {.testKind: tkRegression, covers: "feedRelayFastExtraFrame", pins: "a client could claim any origin".}
  test "a client's own origin claim is overwritten":
    step = R.feedRelayFastExtraFrame(sPhone, sealAmeRouteForward(phone.left, idNas,
      @[byte 7], 3'u8, idLaptop), 0'u32)
    step = nasNode.feedRelayFastExtraFrame(0, onlyFrame(step, sNas), 0'u32)
    check step.frame.origin == idPhone

  # {.testKind: tkRegression, covers: "feedRelayFastExtraFrame", pins: "a captured route frame could be sent again".}
  test "a replayed forward stops at the router":
    var
      frame: ByteSeq = sealAmeRouteForward(phone.left, idNas, @[byte 1])
    check R.feedRelayFastExtraFrame(sPhone, frame, 0'u32).event == reForwarded
    step = R.feedRelayFastExtraFrame(sPhone, frame, 0'u32)
    check step.event == reDropped
    check step.send.len == 0
    check step.err == "AME route replay rejected"

  # {.testKind: tkEdgeCase, covers: "feedRelayFastExtraFrame".}
  test "junk, a frame for another link and an empty slot are dropped":
    step = R.feedRelayFastExtraFrame(sPhone, @[byte 1, 2, 3], 0'u32)
    check step.event == reDropped
    step = R.feedRelayFastExtraFrame(sPhone, sealAmeRouteForward(laptop.left,
      idNas, @[byte 1]), 0'u32)
    check step.event == reDropped
    step = R.feedRelayFastExtraFrame(7, sealAmeRouteForward(phone.left, idNas,
      @[byte 1]), 0'u32)
    check step.event == reDropped
    check step.send.len == 0

  # {.testKind: tkEdgeCase, covers: "admitRelayNeighbour".}
  test "an id is connected once, and a full router says so":
    var
      tiny: RelayFastExtraFrame = initRelayFastExtraFrame(idR2, 1)
    check not R.admitRelayNeighbour(phone.right, idPhone, "phone", at(idPhone), acrDac).ok
    check not R.admitRelayNeighbour(phone.right, idR1, "self", at(idR1), acrDac).ok
    check tiny.admitRelayNeighbour(phone.right, idPhone, "phone", at(idPhone), acrDac).ok
    check tiny.admitRelayNeighbour(nas.right, idNas, "nas", at(idNas), acrDac).err ==
      "relay is full"

  # {.testKind: tkUnit, covers: "relaySlotOf".}
  test "the sender's address names the neighbour, and every frame out names its address":
    check R.relaySlotOf(at(idPhone)) == sPhone
    check R.relaySlotOf(at(idNas)) == sNas
    step = R.feedRelayFastExtraFrame(at(idPhone), sealAmeRouteForward(
      phone.left, idNas, @[byte 5]), 0'u32)
    check step.event == reForwarded
    check step.slot == sPhone
    check step.send.len == 1
    check step.send[0].address == at(idNas)
    step = nasNode.feedRelayFastExtraFrame(at(idR1), step.send[0].frame, 0'u32)
    check step.event == reDelivered
    check step.frame.origin == idPhone

  # {.testKind: tkEdgeCase, covers: "feedRelayFastExtraFrame".}
  test "a datagram from an address that never finished a handshake is dropped":
    step = R.feedRelayFastExtraFrame(initTransportAddress("203.0.113.9",
      1'u16), sealAmeRouteForward(phone.left, idNas, @[byte 1]), 0'u32)
    check step.event == reDropped
    check step.err == "relay slot is empty"
    check step.send.len == 0

  # {.testKind: tkUnit, covers: "feedRelayFastExtraFrame".}
  test "a directory question goes through the same feed call":
    step = R.feedRelayFastExtraFrame(at(idPhone), sealAmeRouteAsk(phone.left,
      acrDac), 0'u32)
    check step.event == reAnswered
    check step.send[0].address == at(idPhone)

  # {.testKind: tkEdgeCase, covers: "admitRelayNeighbour".}
  test "one address holds one neighbour; leaving frees it":
    var
      extra: RtPair = rtPair(23'u8)
    check R.admitRelayNeighbour(extra.right, 0x44'u64, "extra", at(idPhone),
      acrDac).err == "relay address is already connected"
    R.releaseRelayNeighbour(sPhone)
    check R.relaySlotOf(at(idPhone)) == -1
    check R.admitRelayNeighbour(extra.right, 0x44'u64, "extra", at(idPhone),
      acrDac).ok

  # {.testKind: tkUnit, covers: "admitRelayNeighbour".}
  test "a neighbour's link keeps no inbox":
    check not R.neighbours[sPhone].session.keepsInbox
    check inboxCapacity(R.neighbours[sPhone].session) == 0
    check R.neighbours[sPhone].address == at(idPhone)


suite "relayFastExtraFrame, two hops":
  setup:
    var
      phoneNode: RelayFastExtraFrame = initRelayFastExtraFrame(idPhone, 1)
      R1: RelayFastExtraFrame = initRelayFastExtraFrame(idR1, 4)
      R2: RelayFastExtraFrame = initRelayFastExtraFrame(idR2, 4)
      nasNode: RelayFastExtraFrame = initRelayFastExtraFrame(idNas, 1)
      phone: RtPair = rtPair(30'u8)
      trunk: RtPair = rtPair(31'u8)
      nas: RtPair = rtPair(32'u8)
      pPhone: int = -1
      pR2: int = -1
      qR1: int = -1
      qNas: int = -1
      step: RelayStep = default(RelayStep)
    R1.addRelayTarget(idNas, "nas", ["phone"], via = idR2)
    R1.addRelayTarget(idCam, "cam", ["phone"], via = idR2)
    R2.addRelayTarget(idNas, "nas", ["router1"])
    pPhone = R1.admitRelayNeighbour(phone.right, idPhone, "phone", at(idPhone), acrDac).slot
    pR2 = R1.admitRelayNeighbour(trunk.left, idR2, "router2", at(idR2), acrDac,
      router = true).slot
    qR1 = R2.admitRelayNeighbour(trunk.right, idR1, "router1", at(idR1), acrDac,
      router = true).slot
    qNas = R2.admitRelayNeighbour(nas.right, idNas, "nas", at(idNas), acrDac).slot
    discard phoneNode.admitRelayNeighbour(phone.left, idR1, "router1", at(idR1), acrDac,
      router = true)
    discard nasNode.admitRelayNeighbour(nas.left, idR2, "router2", at(idR2), acrDac,
      router = true)

  # {.testKind: tkIntegration, covers: "feedRelayFastExtraFrame|sealAmeRouteForward".}
  test "an end-to-end AM1P handshake and session through two routers":
    ## Only the phone and the nas hold the PSK. Every handshake record and
    ## the first session frame cross both routers as route payload, and the
    ## routers hand them on byte for byte.
    var
      L: AmeSuiteLayout = rtLayout()
      t: AmeMaskTier = rtTier(L)
      psk: ByteSeq = newSeq[uint8](32)
      auth: AmeAuthentication = default(AmeAuthentication)
      client: AmeClientHandshake = default(AmeClientHandshake)
      answered: tuple[ok: bool, state: AmeServerHandshake, err: string] = (
        ok: false, state: default(AmeServerHandshake), err: "")
      clientDone: AmeHandshakeResult = default(AmeHandshakeResult)
      serverDone: AmeHandshakeResult = default(AmeHandshakeResult)
      e2ePhone: AmeSession = default(AmeSession)
      e2eNas: AmeSession = default(AmeSession)
      secret: seq[byte] = @[byte 0x73, 0x65, 0x63, 0x72, 0x65, 0x74]
      sealed: ByteSeq = @[]
      opened: AmeOpenResult = default(AmeOpenResult)

    proc toNas(payload: openArray[uint8]): ByteSeq =
      ## phone -> R1 -> R2 -> nas; returns what the nas node received.
      var
        s: RelayStep = R1.feedRelayFastExtraFrame(pPhone,
          sealAmeRouteForward(phone.left, idNas, payload), 0'u32)
      check s.event == reForwarded
      check containsWindow(onlyFrame(s, pR2), payload)
      s = R2.feedRelayFastExtraFrame(qR1, onlyFrame(s, pR2), 0'u32)
      check s.event == reForwarded
      s = nasNode.feedRelayFastExtraFrame(0, onlyFrame(s, qNas), 0'u32)
      check s.event == reDelivered
      check s.frame.origin == idPhone
      result = s.frame.payload

    proc toPhone(payload: openArray[uint8]): ByteSeq =
      ## nas -> R2 -> R1 -> phone, by the return note R2 made.
      var
        s: RelayStep = R2.feedRelayFastExtraFrame(qNas,
          sealAmeRouteForward(nas.left, idPhone, payload), 0'u32)
      check s.event == reForwarded
      s = R1.feedRelayFastExtraFrame(pR2, onlyFrame(s, qR1), 0'u32)
      check s.event == reForwarded
      s = phoneNode.feedRelayFastExtraFrame(0, onlyFrame(s, pPhone), 0'u32)
      check s.event == reDelivered
      check s.frame.origin == idNas
      result = s.frame.payload

    psk[0] = 0x42'u8
    auth = initAmePskAuthentication("e2e", psk)
    client = beginAmeHandshake(0x5151'u64, L, t, a = auth)
    answered = answerAmeHandshake(decodeAmeClientHello(toNas(
      encodeAmeClientHello(client.hello))), [initAmeTierPath(L, [t])], auth)
    check answered.ok
    clientDone = finishAmeHandshake(client, decodeAmeServerHello(L, toPhone(
      encodeAmeServerHello(answered.state.serverHello))), auth,
      nowUnix = nowUnix)
    check clientDone.ok
    serverDone = acceptAmeHandshake(answered.state, decodeAmeClientFinish(
      toNas(encodeAmeClientFinish(clientDone.finish))), nowUnix)
    check serverDone.ok
    e2ePhone = initAmeSession(clientDone.auth, initAmeTierPath(L, [t]),
      0x5151'u64, peerTrust = clientDone.peerTrust)
    e2eNas = initAmeSession(serverDone.auth, initAmeTierPath(L, [t]),
      0x5151'u64, peerTrust = serverDone.peerTrust)
    sealed = sealAmeDacFrame(e2ePhone, secret)
    opened = openAmeDacFrame(e2eNas, toNas(sealed))
    check opened.ok
    check opened.packet.payload == secret
    check not containsWindow(sealed, secret)

  # {.testKind: tkEdgeCase, covers: "feedRelayFastExtraFrame".}
  test "each hop seals the address anew; the payload stays the same":
    var
      first: ByteSeq = sealAmeRouteForward(phone.left, idNas, @[byte 1, 2])
      second: ByteSeq = @[]
    step = R1.feedRelayFastExtraFrame(pPhone, first, 0'u32)
    second = onlyFrame(step, pR2)
    check first[ameRouteHeaderLen ..< ameRouteOverhead] !=
      second[ameRouteHeaderLen ..< ameRouteOverhead]
    check first[ameRouteOverhead .. ^1] == second[ameRouteOverhead .. ^1]
    check first[5] == ameRouteDefaultHops
    check second[5] == ameRouteDefaultHops - 1'u8

  # {.testKind: tkEdgeCase, covers: "feedRelayFastExtraFrame".}
  test "a return note answers only the one written to, and only for a while":
    var
      other: RtPair = rtPair(33'u8)
      qOther: int = R2.admitRelayNeighbour(other.right, 0x40'u64, "other", at(0x40'u64),
        acrDac).slot
      otherNode: RelayFastExtraFrame = initRelayFastExtraFrame(0x40'u64, 1)
    discard otherNode.admitRelayNeighbour(other.left, idR2, "router2", at(idR2), acrDac,
      router = true)
    step = R1.feedRelayFastExtraFrame(pPhone, sealAmeRouteForward(phone.left,
      idNas, @[byte 1]), 0'u32)
    discard R2.feedRelayFastExtraFrame(qR1, onlyFrame(step, pR2), 0'u32)
    ## The phone wrote to the nas, not to `other`: the note is no ticket
    ## for anyone else on router 2.
    step = R2.feedRelayFastExtraFrame(qOther, sealAmeRouteForward(other.left,
      idPhone, @[byte 2]), 10'u32)
    step = otherNode.feedRelayFastExtraFrame(0, onlyFrame(step, qOther), 10'u32)
    check step.frame.refusal == arrNoRoute
    ## And once it has expired, the nas itself is refused as well.
    step = R2.feedRelayFastExtraFrame(qNas, sealAmeRouteForward(nas.left, idPhone,
      @[byte 3]), relayReturnMs + 1'u32)
    step = nasNode.feedRelayFastExtraFrame(0, onlyFrame(step, qNas),
      relayReturnMs + 1'u32)
    check step.frame.refusal == arrNoRoute

  # {.testKind: tkIntegration, covers: "feedRelayFastExtraFrame".}
  test "a refusal from the far router finds its way back":
    ## Router 1 lists cam behind router 2; router 2 has never heard of it.
    step = R1.feedRelayFastExtraFrame(pPhone, sealAmeRouteForward(phone.left,
      idCam, @[byte 1]), 0'u32)
    check step.event == reForwarded
    step = R2.feedRelayFastExtraFrame(qR1, onlyFrame(step, pR2), 0'u32)
    check step.event == reRefused
    step = R1.feedRelayFastExtraFrame(pR2, onlyFrame(step, qR1), 0'u32)
    check step.event == reRefused
    step = phoneNode.feedRelayFastExtraFrame(0, onlyFrame(step, pPhone), 0'u32)
    check step.event == reRefused
    check step.frame.target == idCam
    check step.frame.origin == idPhone
    check step.frame.refusal == arrNoRoute

  # {.testKind: tkRegression, covers: "feedRelayFastExtraFrame", pins: "two routers pointing at each other forward forever".}
  test "two routers pointing at each other stop at the first bounce":
    ## Router 2 is (wrongly) told cam is behind router 1, while router 1
    ## says cam is behind router 2. Router 2 would send the forward straight
    ## back where it came from, and that is refused outright. Longer loops
    ## are what `hopsLeft` is for.
    R2.addRelayTarget(idCam, "cam", ["*"], via = idR1)
    step = R1.feedRelayFastExtraFrame(pPhone, sealAmeRouteForward(phone.left,
      idCam, @[byte 1]), 0'u32)
    check step.event == reForwarded
    step = R2.feedRelayFastExtraFrame(qR1, onlyFrame(step, pR2), 0'u32)
    check step.event == reRefused
