## -------------------------------------------------------------------------
## AME Router Tests <- one handshake with a router, then anyone it allows
## -------------------------------------------------------------------------
##
## The picture every multi-hop test below builds:
##
##   phone (0x30) ==A==> router 1 (0x10) ==B==> router 2 (0x11) ==C==> nas (0x20)
##                         slot pPhone            slot qR1
##                         slot pR2               slot qNas
##
## Each `==X==>` is one AME session: one end held by the left side, the
## other by the right. No socket is opened; a frame is handed from one
## session to its partner by hand, so every rule is checked exactly.
##
##   what is checked                         where
##   --------------------------------------  ---------------------------
##   the Gimli block opens only in place     "AME route block"
##   the five bodies survive the wire        "AME route frames"
##   Def. 2 (who may send) and Def. 3        "AME router, one hop"
##   two routers, there and back again       "AME router, two hops"

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/secret_stack
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/route_block
import ../../src/protocols/ame/level2/seal_open
import ../../src/protocols/ame/level2/route_frames
import ../../src/protocols/ame/level3/router
import runePragmas

const
  rtKems: AmeKemAlgorithms = [akaX25519, akaFireSaber]
  idR1: uint64 = 0x10'u64
  idR2: uint64 = 0x11'u64
  idNas: uint64 = 0x20'u64
  idCam: uint64 = 0x21'u64
  idPhone: uint64 = 0x30'u64
  idLaptop: uint64 = 0x31'u64

type
  ## RtPair: the two ends of one session.
  RtPair = object
    left: AmeSession
    right: AmeSession

proc rtAuth(role: AmeEndpointRole, seed: byte): AmeAuthPackage =
  ## role/seed: one end; the same seed on both roles makes a pair.
  var
    layout: AmeSuiteLayout = defaultAmeLayout(rtKems)
    tier: AmeMaskTier = initAmeMaskTier(layout, 1'u32, initAmeTierMasks(
      0b11000000'u8, occupiedAmeMask(layout.ciphers.length),
      occupiedAmeMask(layout.macs.length), occupiedAmeMask(layout.hashes.length),
      occupiedAmeMask(layout.signatures.length),
      occupiedAmeMask(layout.kdfs.length)))
    state: AmeExchangeState = initAmeExchangeState(rtKems)
  applyAmeExchange(state, layout, initAmeExchangeRequest(rtKems, tier,
    0b11000000'u8), [@[seed, 2'u8, 3'u8, 4'u8], @[seed, 6'u8, 7'u8, 8'u8]])
  result = initAmeAuthPackage(layout, tier, state, endpointRole = role)

proc rtPair(seed: byte): RtPair =
  ## seed: which session; every link in a test gets its own.
  result.left = initAmeSession(rtAuth(aerInitiator, seed),
    peerTrustRequired = false)
  result.right = initAmeSession(rtAuth(aerResponder, seed),
    peerTrustRequired = false)

proc onlyFrame(step: AmeRouteStep, slot: int): ByteSeq =
  ## step/slot: the single frame the router queued, which must be for slot.
  check step.send.len == 1
  check step.send[0].slot == slot
  result = step.send[0].frame

suite "AME route block":
  # {.testKind: tkUnit, covers: "sealAmeRouteBlock|openAmeRouteBlock".}
  test "a block opens with the same key, kind and counter":
    var
      key: ByteSeq = newSeq[uint8](ameRouteKeyLen)
      sealed: ByteSeq = @[]
      ids: AmeRouteIds = default(AmeRouteIds)
    key[0] = 7'u8
    sealed = sealAmeRouteBlock(key, arkForward, 41'u32, idNas, idPhone)
    check sealed.len == ameRouteBlockLen
    ids = openAmeRouteBlock(key, arkForward, 41'u32, sealed)
    check ids.ok
    check ids.target == idNas
    check ids.origin == idPhone

  # {.testKind: tkEdgeCase, covers: "openAmeRouteBlock".}
  test "a block moved to another frame, kind or key does not open":
    ## The nonce is (kind, frame counter), so the same 24 bytes lifted into
    ## frame 42, or re-read as a refusal, fail their tag. So do a flipped
    ## bit and a different key.
    var
      key: ByteSeq = newSeq[uint8](ameRouteKeyLen)
      other: ByteSeq = newSeq[uint8](ameRouteKeyLen)
      sealed: ByteSeq = @[]
      flipped: ByteSeq = @[]
    other[31] = 1'u8
    sealed = sealAmeRouteBlock(key, arkForward, 41'u32, idNas, 0'u64)
    flipped = sealed
    flipped[3] = flipped[3] xor 0x01'u8
    check not openAmeRouteBlock(key, arkForward, 42'u32, sealed).ok
    check not openAmeRouteBlock(key, arkRefuse, 41'u32, sealed).ok
    check not openAmeRouteBlock(other, arkForward, 41'u32, sealed).ok
    check not openAmeRouteBlock(key, arkForward, 41'u32, flipped).ok
    check not openAmeRouteBlock(key, arkForward, 41'u32,
      sealed[0 .. 22]).ok

  # {.testKind: tkUnit, covers: "sealAmeRouteBlock".}
  test "the ids do not show through":
    ## Same ids, two counters: the 16 sealed bytes must differ, or a watcher
    ## holding the frame could still tell "same target as last time".
    var
      key: ByteSeq = newSeq[uint8](ameRouteKeyLen)
      a: ByteSeq = sealAmeRouteBlock(key, arkForward, 1'u32, idNas, 0'u64)
      b: ByteSeq = sealAmeRouteBlock(key, arkForward, 2'u32, idNas, 0'u64)
    check a[0 .. 15] != b[0 .. 15]

suite "AME route frames":
  # {.testKind: tkUnit, covers: "sealAmeRouteAsk|openAmeRouteFrame".}
  test "ask and directory survive the wire":
    var
      link: RtPair = rtPair(1'u8)
      got: AmeRouteMessage = default(AmeRouteMessage)
      page: AmeRouteMessage = AmeRouteMessage(kind: arkDirectory, start: 0,
        total: 2, entries: @[AmeRouteEntry(id: idNas, name: "nas"),
        AmeRouteEntry(id: idCam, name: "")])
    got = openAmeRouteFrame(link.right, acrDac,
      sealAmeRouteAsk(link.left, acrDac, 3'u16))
    check got.ok
    check got.kind == arkAsk
    check got.start == 3'u16
    got = openAmeRouteFrame(link.left, acrDac,
      sealAmeRouteFrame(link.right, acrDac, page))
    check got.ok
    check got.kind == arkDirectory
    check got.total == 2'u16
    check got.entries == page.entries

  # {.testKind: tkUnit, covers: "sealAmeRouteForward|openAmeRouteFrame".}
  test "a forward carries target, hops and payload":
    var
      link: RtPair = rtPair(2'u8)
      got: AmeRouteMessage = default(AmeRouteMessage)
    discard sealAmeRouteAsk(link.left, acrDac)   # move the counter on
    got = openAmeRouteFrame(link.right, acrDac,
      sealAmeRouteForward(link.left, acrDac, idNas, @[byte 104, 105]))
    check got.ok
    check got.kind == arkForward
    check got.target == idNas
    check got.origin == 0'u64
    check got.hopsLeft == ameRouteDefaultHops
    check got.payload == @[byte 104, 105]

  # {.testKind: tkEdgeCase, covers: "openAmeRouteFrame".}
  test "a body that does not parse is refused, never raised":
    var
      link: RtPair = rtPair(3'u8)
      got: AmeRouteMessage = default(AmeRouteMessage)
    got = openAmeRouteFrame(link.right, acrDac,
      sealControlFrame(link.left, ampkRoute, acrDac, @[byte 0x09]))
    check not got.ok
    got = openAmeRouteFrame(link.right, acrDac,
      sealControlFrame(link.left, ampkRoute, acrDac, @[byte 0x03, 1, 2]))
    check not got.ok
    got = openAmeRouteFrame(link.right, acrDac,
      sealControlFrame(link.left, ampkRoute, acrDac,
      @[byte 0x02, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 40]))
    check not got.ok

  # {.testKind: tkEdgeCase, covers: "sealAmeRouteFrame".}
  test "names over 32 bytes and pages over 24 lines are not written":
    var
      link: RtPair = rtPair(4'u8)
      tooLong: string = newString(33)
      page: AmeRouteMessage = AmeRouteMessage(kind: arkDirectory, total: 1,
        entries: @[AmeRouteEntry(id: idNas, name: tooLong)])
    expect ValueError:
      discard sealAmeRouteFrame(link.left, acrDac, page)
    page.entries = newSeq[AmeRouteEntry](25)
    page.total = 25
    expect ValueError:
      discard sealAmeRouteFrame(link.left, acrDac, page)

suite "AME router, one hop":
  ## phone (0x30), laptop (0x31), nas (0x20) and cam (0x21) on one router.
  ## nas is visible to the phone; cam to nobody but the laptop.
  setup:
    var
      R: AmeRouter = initAmeRouter(8)
      phone: RtPair = rtPair(10'u8)
      laptop: RtPair = rtPair(11'u8)
      nas: RtPair = rtPair(12'u8)
      cam: RtPair = rtPair(13'u8)
      sPhone: int = -1
      sLaptop: int = -1
      sNas: int = -1
      sCam: int = -1
      step: AmeRouteStep = default(AmeRouteStep)
      got: AmeRouteMessage = default(AmeRouteMessage)
    R.addAmeRouteTarget(idNas, "nas", ["phone"])
    R.addAmeRouteTarget(idCam, "cam", ["laptop"])
    sPhone = R.admitAmeRoutePeer(phone.right, idPhone, "phone", acrDac).slot
    sLaptop = R.admitAmeRoutePeer(laptop.right, idLaptop, "laptop",
      acrDac).slot
    sNas = R.admitAmeRoutePeer(nas.right, idNas, "nas", acrDac).slot
    sCam = R.admitAmeRoutePeer(cam.right, idCam, "cam", acrDac).slot

  # {.testKind: tkUnit, covers: "feedAmeRouteFrame".}
  test "the directory lists only what this identity may see":
    step = R.feedAmeRouteFrame(sPhone, sealAmeRouteAsk(phone.left, acrDac),
      0'u32)
    check step.event == areAnswered
    got = openAmeRouteFrame(phone.left, acrDac, onlyFrame(step, sPhone))
    check got.kind == arkDirectory
    check got.total == 1'u16
    check got.entries == @[AmeRouteEntry(id: idNas, name: "nas")]

  # {.testKind: tkEdgeCase, covers: "feedAmeRouteFrame".}
  test "a long directory is read in pages of 24":
    var
      i: int = 0
      seen: seq[AmeRouteEntry] = @[]
    while i < 30:
      R.addAmeRouteTarget(0x1000'u64 + uint64(i), "t" & $i, ["*"])
      i = i + 1
    while seen.len < 31:
      step = R.feedAmeRouteFrame(sPhone, sealAmeRouteAsk(phone.left, acrDac,
        uint16(seen.len)), 0'u32)
      got = openAmeRouteFrame(phone.left, acrDac, onlyFrame(step, sPhone))
      check got.total == 31'u16
      check got.start == uint16(seen.len)
      check got.entries.len == min(ameRoutePageEntries, 31 - seen.len)
      seen.add(got.entries)
    check seen[0].name == "nas"
    check seen[30].name == "t29"
    ## Asking past the end is answered with an empty page, not an error.
    step = R.feedAmeRouteFrame(sPhone, sealAmeRouteAsk(phone.left, acrDac,
      500'u16), 0'u32)
    got = openAmeRouteFrame(phone.left, acrDac, onlyFrame(step, sPhone))
    check got.ok
    check got.entries.len == 0

  # {.testKind: tkIntegration, covers: "feedAmeRouteFrame".}
  test "forward, deliver, and the answer back":
    step = R.feedAmeRouteFrame(sPhone, sealAmeRouteForward(phone.left,
      acrDac, idNas, @[byte 1, 2, 3]), 0'u32)
    check step.event == areDelivered
    got = openAmeRouteFrame(nas.left, acrDac, onlyFrame(step, sNas))
    check got.kind == arkDeliver
    check got.target == idNas
    check got.origin == idPhone
    check got.hopsLeft == ameRouteDefaultHops - 1'u8
    check got.payload == @[byte 1, 2, 3]
    ## The nas has no line visible to it naming the phone. It may answer
    ## anyway, because the phone may write to it (Def. 2, the reverse).
    step = R.feedAmeRouteFrame(sNas, sealAmeRouteForward(nas.left, acrDac,
      got.origin, @[byte 9]), 0'u32)
    check step.event == areDelivered
    got = openAmeRouteFrame(phone.left, acrDac, onlyFrame(step, sPhone))
    check got.origin == idNas
    check got.payload == @[byte 9]

  # {.testKind: tkEdgeCase, covers: "feedAmeRouteFrame".}
  test "hidden and unknown targets get the same refusal":
    var
      hidden: AmeRouteMessage = default(AmeRouteMessage)
      unknown: AmeRouteMessage = default(AmeRouteMessage)
    step = R.feedAmeRouteFrame(sPhone, sealAmeRouteForward(phone.left,
      acrDac, idCam, @[byte 1]), 0'u32)
    check step.event == areRefused
    hidden = openAmeRouteFrame(phone.left, acrDac, onlyFrame(step, sPhone))
    step = R.feedAmeRouteFrame(sPhone, sealAmeRouteForward(phone.left,
      acrDac, 0x99'u64, @[byte 1]), 0'u32)
    unknown = openAmeRouteFrame(phone.left, acrDac, onlyFrame(step, sPhone))
    check hidden.kind == arkRefuse
    check hidden.refusal == arrNoRoute
    check unknown.refusal == hidden.refusal
    check hidden.target == idCam

  # {.testKind: tkEdgeCase, covers: "feedAmeRouteFrame".}
  test "a forward with no hops left is refused":
    step = R.feedAmeRouteFrame(sPhone, sealAmeRouteForward(phone.left,
      acrDac, idNas, @[byte 1], 0'u8), 0'u32)
    got = openAmeRouteFrame(phone.left, acrDac, onlyFrame(step, sPhone))
    check got.refusal == arrHopsSpent

  # {.testKind: tkRegression, covers: "feedAmeRouteFrame", pins: "a client could claim any origin".}
  test "a client's own origin claim is overwritten":
    step = R.feedAmeRouteFrame(sPhone, sealAmeRouteFrame(phone.left, acrDac,
      AmeRouteMessage(kind: arkForward, target: idNas, origin: idLaptop,
      hopsLeft: 3, payload: @[byte 7])), 0'u32)
    got = openAmeRouteFrame(nas.left, acrDac, onlyFrame(step, sNas))
    check got.origin == idPhone

  # {.testKind: tkEdgeCase, covers: "feedAmeRouteFrame".}
  test "junk, a frame for another link and an empty slot are dropped":
    step = R.feedAmeRouteFrame(sPhone, @[byte 1, 2, 3], 0'u32)
    check step.event == areDropped
    step = R.feedAmeRouteFrame(sPhone, sealAmeRouteAsk(laptop.left, acrDac),
      0'u32)
    check step.event == areDropped
    step = R.feedAmeRouteFrame(7, sealAmeRouteAsk(phone.left, acrDac),
      0'u32)
    check step.event == areDropped
    check step.send.len == 0

  # {.testKind: tkEdgeCase, covers: "admitAmeRoutePeer".}
  test "an id is connected once, and a full router says so":
    var
      tiny: AmeRouter = initAmeRouter(1)
    check not R.admitAmeRoutePeer(phone.right, idPhone, "phone", acrDac).ok
    check tiny.admitAmeRoutePeer(phone.right, idPhone, "phone", acrDac).ok
    check tiny.admitAmeRoutePeer(nas.right, idNas, "nas", acrDac).err ==
      "AME router is full"
    discard sLaptop
    discard sCam

suite "AME router, two hops":
  setup:
    var
      R1: AmeRouter = initAmeRouter(4)
      R2: AmeRouter = initAmeRouter(4)
      phone: RtPair = rtPair(20'u8)
      laptop: RtPair = rtPair(21'u8)
      trunk: RtPair = rtPair(22'u8)
      nas: RtPair = rtPair(23'u8)
      pPhone: int = -1
      pLaptop: int = -1
      pR2: int = -1
      qR1: int = -1
      qNas: int = -1
      step: AmeRouteStep = default(AmeRouteStep)
      got: AmeRouteMessage = default(AmeRouteMessage)
    R1.addAmeRouteTarget(idNas, "nas", ["phone", "laptop"], via = idR2)
    R1.addAmeRouteTarget(idCam, "cam", ["phone"], via = idR2)
    R2.addAmeRouteTarget(idNas, "nas", ["router1"])
    pPhone = R1.admitAmeRoutePeer(phone.right, idPhone, "phone", acrDac).slot
    pLaptop = R1.admitAmeRoutePeer(laptop.right, idLaptop, "laptop",
      acrDac).slot
    pR2 = R1.admitAmeRoutePeer(trunk.left, idR2, "router2", acrDac,
      router = true).slot
    qR1 = R2.admitAmeRoutePeer(trunk.right, idR1, "router1", acrDac,
      router = true).slot
    qNas = R2.admitAmeRoutePeer(nas.right, idNas, "nas", acrDac).slot

  # {.testKind: tkIntegration, covers: "feedAmeRouteFrame".}
  test "there and back again through two routers":
    step = R1.feedAmeRouteFrame(pPhone, sealAmeRouteForward(phone.left,
      acrDac, idNas, @[byte 0x68, 0x69]), 0'u32)
    check step.event == areForwarded
    step = R2.feedAmeRouteFrame(qR1, onlyFrame(step, pR2), 0'u32)
    check step.event == areDelivered
    got = openAmeRouteFrame(nas.left, acrDac, onlyFrame(step, qNas))
    check got.origin == idPhone
    check got.hopsLeft == ameRouteDefaultHops - 2'u8
    check got.payload == @[byte 0x68, 0x69]
    ## The nas answers 0x30. Router 2 has no line for it; the return note
    ## it made a moment ago is the only reason it knows the way.
    step = R2.feedAmeRouteFrame(qNas, sealAmeRouteForward(nas.left, acrDac,
      idPhone, @[byte 0x6f, 0x6b]), 1000'u32)
    check step.event == areForwarded
    step = R1.feedAmeRouteFrame(pR2, onlyFrame(step, qR1), 1000'u32)
    check step.event == areDelivered
    got = openAmeRouteFrame(phone.left, acrDac, onlyFrame(step, pPhone))
    check got.origin == idNas
    check got.payload == @[byte 0x6f, 0x6b]

  # {.testKind: tkEdgeCase, covers: "feedAmeRouteFrame".}
  test "a return note answers only the one written to, and only for a while":
    var
      other: RtPair = rtPair(24'u8)
      qOther: int = R2.admitAmeRoutePeer(other.right, 0x40'u64, "other",
        acrDac).slot
    step = R1.feedAmeRouteFrame(pPhone, sealAmeRouteForward(phone.left,
      acrDac, idNas, @[byte 1]), 0'u32)
    discard R2.feedAmeRouteFrame(qR1, onlyFrame(step, pR2), 0'u32)
    ## The phone wrote to the nas, not to `other`: the note is no ticket
    ## for anyone else on router 2.
    step = R2.feedAmeRouteFrame(qOther, sealAmeRouteForward(other.left,
      acrDac, idPhone, @[byte 2]), 10'u32)
    got = openAmeRouteFrame(other.left, acrDac, onlyFrame(step, qOther))
    check got.refusal == arrNoRoute
    ## And once it has expired, the nas itself is refused as well.
    step = R2.feedAmeRouteFrame(qNas, sealAmeRouteForward(nas.left, acrDac,
      idPhone, @[byte 3]), ameRouteReturnMs + 1'u32)
    got = openAmeRouteFrame(nas.left, acrDac, onlyFrame(step, qNas))
    check got.refusal == arrNoRoute

  # {.testKind: tkIntegration, covers: "feedAmeRouteFrame".}
  test "a refusal from the far router finds its way back":
    ## Router 1 lists cam behind router 2; router 2 has never heard of it.
    step = R1.feedAmeRouteFrame(pPhone, sealAmeRouteForward(phone.left,
      acrDac, idCam, @[byte 1]), 0'u32)
    check step.event == areForwarded
    step = R2.feedAmeRouteFrame(qR1, onlyFrame(step, pR2), 0'u32)
    check step.event == areRefused
    step = R1.feedAmeRouteFrame(pR2, onlyFrame(step, qR1), 0'u32)
    check step.event == areRefused
    got = openAmeRouteFrame(phone.left, acrDac, onlyFrame(step, pPhone))
    check got.kind == arkRefuse
    check got.target == idCam
    check got.origin == idPhone
    check got.refusal == arrNoRoute
    discard pLaptop

  # {.testKind: tkRegression, covers: "feedAmeRouteFrame", pins: "two routers pointing at each other forward forever".}
  test "two routers pointing at each other stop at the first bounce":
    ## Router 2 is (wrongly) told cam is behind router 1, while router 1
    ## says cam is behind router 2. Router 2 would send the forward straight
    ## back where it came from, and that is refused outright. Longer loops
    ## are what `hopsLeft` is for.
    var
      bounces: int = 0
      frame: ByteSeq = @[]
    R2.addAmeRouteTarget(idCam, "cam", ["*"], via = idR1)
    step = R1.feedAmeRouteFrame(pPhone, sealAmeRouteForward(phone.left,
      acrDac, idCam, @[byte 1]), 0'u32)
    while step.event == areForwarded and bounces < 20:
      frame = step.send[0].frame
      step = R2.feedAmeRouteFrame(qR1, frame, 0'u32)
      bounces = bounces + 1
    check step.event == areRefused
    check bounces == 1
