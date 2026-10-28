## -------------------------------------------------------------------------
## Relay restriction tests <- three ways to say who may talk to whom
## -------------------------------------------------------------------------
##
## One relay, a server (nas) and two clients (phone, laptop). Each link is
## one AME session pair (relay_fixtures.nim); every frame is handed over by
## hand, so each rule is checked exactly. The modes compiled into this binary
## are the ones tested; a mode left out is checked to be refused.

import std/[unittest, os, strutils]
import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level2/session
import ../../src/protocols/ame/level2/route_wire
import ../../src/protocols/transport/types as transport_types
import ../../src/protocols/relay/relay_node
import ../../src/protocols/relay/fast_extra_frame
import ../../src/protocols/relay/restriction
import ./relay_fixtures
import runePragmas

const
  rtRelay: uint64 = 0x10'u64
  rtPhone: uint64 = 0x30'u64
  rtLaptop: uint64 = 0x31'u64
  rtNas: uint64 = 0x20'u64
  rtNowMs: uint32 = 1000'u32

type
  RtNet = object
    R: RelayFastExtraFrame
    phone: RtPair
    laptop: RtPair
    nas: RtPair
    sPhone: int
    sLaptop: int
    sNas: int

proc rtSetup(seed: byte, store: string = ""): RtNet =
  ## A relay with the three neighbours admitted and the routes named.
  result.R = initRelayFastExtraFrame(rtRelay, 8)
  result.phone = rtPair(seed)
  result.laptop = rtPair(seed + 1'u8)
  result.nas = rtPair(seed + 2'u8)
  result.R.addRelayTarget(rtNas, "nas", ["phone", "laptop"])
  result.R.addRelayTarget(rtLaptop, "laptop", ["phone", "nas"])
  result.sPhone = result.R.admitRelayNeighbour(result.phone.right, rtPhone,
    "phone", at(rtPhone), acrDac).slot
  result.sLaptop = result.R.admitRelayNeighbour(result.laptop.right, rtLaptop,
    "laptop", at(rtLaptop), acrDac).slot
  result.sNas = result.R.admitRelayNeighbour(result.nas.right, rtNas,
    "nas", at(rtNas), acrDac).slot

proc rtAnswer(step: RelayStep): ByteSeq =
  ## step: the one frame the relay answered with.
  result = step.send[0].frame

suite "restriction codec":

  # {.testKind: tkEdgeCase, covers: "decodeRestrictionFrame".}
  test "a body that does not parse is refused, never raised":
    check not decodeRestrictionFrame(@[]).ok
    check not decodeRestrictionFrame(@[byte 9, 1]).ok
    check not decodeRestrictionFrame(@[byte 1, 9]).ok
    check not decodeRestrictionFrame(@[byte 1, 3, 1, 0]).ok
    check not decodeRestrictionFrame(@[byte 1, 2, 0, 0, 0xFF]).ok

  # {.testKind: tkEdgeCase, covers: "decodeRestrictionFrame".}
  test "an acknowledgement is the version byte alone":
    check decodeRestrictionFrame(@[restrictionAckVersion]).ack
    check not decodeRestrictionFrame(@[restrictionAckVersion, 0]).ok

  # {.testKind: tkRegression, covers: "encodeBook|decodeBook".}
  test "the whole book survives encode and decode":
    var
      B: RestrictionBook = RestrictionBook()
      back: tuple[ok: bool, book: RestrictionBook, err: string] = (false,
        RestrictionBook(), "")
    B.groups.add GroupEntry(member: "phone", server: "nas")
    B.profiles = @[@[], @["nas", "laptop"]]
    B.profileOf.add ProfileEntry(identity: "phone", profile: 1)
    B.listed.add ListedEntry(identity: "nas", filter: ListedFilter(
      reject: @[FilterRule(host: "10.0.0.49", port: 0)]))
    back = decodeBook(encodeBook(B))
    check back.ok
    check back.book.groups == B.groups
    check back.book.profiles == B.profiles
    check back.book.profileOf == B.profileOf
    check back.book.listed == B.listed

suite "restriction modes, as rules":

  # {.testKind: tkUnit, covers: "checkRestrictionMode".}
  test "a mode that is not compiled in is refused by name":
    check checkRestrictionMode(rmOpen) == ""
    for m in [rmGroup, rmListed, rmProfile]:
      if restrictionBuilt(m):
        check checkRestrictionMode(m) == ""
      else:
        check checkRestrictionMode(m).contains("not compiled")

when restrictionGroupBuilt:
  suite "restriction mode group":

    # {.testKind: tkUnit, covers: "groupAllows|setGroup".}
    test "a member reaches its server, and the server its members only":
      var
        B: RestrictionBook = RestrictionBook()
      check setGroup(B, "nas", @["phone", "laptop"]) == ""
      check groupAllows(B, "phone", "nas")
      check groupAllows(B, "nas", "laptop")
      check not groupAllows(B, "phone", "laptop")
      check not groupAllows(B, "phone", "other")

    # {.testKind: tkRegression, covers: "setGroup".}
    test "a member already claimed by another server is refused":
      var
        B: RestrictionBook = RestrictionBook()
      check setGroup(B, "nas", @["phone"]) == ""
      check setGroup(B, "cam", @["phone"]).contains("already belongs")
      check groupAllows(B, "phone", "nas")

    # {.testKind: tkIntegration, covers: "feedRelayControl|feedRelayFastExtraFrame".}
    test "on the relay: clients never reach each other, and reach the server":
      var
        n: RtNet = rtSetup(40'u8)
        step: RelayStep = default(RelayStep)
        ack: tuple[ok: bool, err: string] = (false, "")
      check n.R.setRelayRestriction(rmGroup) == ""
      step = n.R.feedRelayFastExtraFrame(n.sNas,
        sealGroupUpdate(n.nas.left, acrDac, @["phone", "laptop"]), rtNowMs)
      check step.event == reAnswered
      ack = openRestrictionAck(n.nas.left, acrDac, rtAnswer(step))
      check ack.ok
      step = n.R.feedRelayFastExtraFrame(n.sPhone,
        sealAmeRouteForward(n.phone.left, rtNas, @[byte 1]), rtNowMs)
      check step.event == reForwarded
      check step.send.len == 1
      step = n.R.feedRelayFastExtraFrame(n.sPhone,
        sealAmeRouteForward(n.phone.left, rtLaptop, @[byte 2]), rtNowMs)
      check step.event == reDropped
      check step.send.len == 0
      check step.err.startsWith("restricted")
      check n.R.restricted == 1'u32

when restrictionListedBuilt:
  suite "restriction mode listed":

    # {.testKind: tkUnit, covers: "listedAllows|setListed".}
    test "reject wins, and an empty accept list accepts the rest":
      var
        F: ListedFilter = ListedFilter(reject: @[FilterRule(host: "10.0.0.49",
          port: 0)])
      check not listedAllows(F, initUdpAddress("10.0.0.49", 47656'u16))
      check listedAllows(F, initUdpAddress("10.0.0.50", 47656'u16))
      F.accept = @[FilterRule(host: "10.0.0.50", port: 47656'u16)]
      check not listedAllows(F, initUdpAddress("10.0.0.51", 47656'u16))
      check listedAllows(F, initUdpAddress("10.0.0.50", 47656'u16))

    # {.testKind: tkIntegration, covers: "feedRelayControl|feedRelayFastExtraFrame".}
    test "on the relay: the server refuses one address, by where it came from":
      var
        n: RtNet = rtSetup(50'u8)
        step: RelayStep = default(RelayStep)
      check n.R.setRelayRestriction(rmListed) == ""
      step = n.R.feedRelayFastExtraFrame(n.sNas,
        sealListedUpdate(n.nas.left, acrDac, ListedFilter(reject: @[
          FilterRule(host: at(rtPhone).host, port: 0)])), rtNowMs)
      check step.event == reAnswered
      step = n.R.feedRelayFastExtraFrame(n.sPhone,
        sealAmeRouteForward(n.phone.left, rtNas, @[byte 1]), rtNowMs)
      check step.event == reDropped
      check step.err.startsWith("restricted")
      step = n.R.feedRelayFastExtraFrame(n.sLaptop,
        sealAmeRouteForward(n.laptop.left, rtNas, @[byte 2]), rtNowMs)
      check step.event == reForwarded

when restrictionProfileBuilt:
  suite "restriction mode profile":

    # {.testKind: tkUnit, covers: "profileAllows|setProfile".}
    test "a device reaches exactly the set its profile names":
      var
        B: RestrictionBook = RestrictionBook(profiles: @[@[], @["nas"]])
      check setProfile(B, "phone", 1) == ""
      check profileAllows(B, "phone", "nas")
      check not profileAllows(B, "phone", "laptop")
      check not profileAllows(B, "laptop", "nas")
      check setProfile(B, "phone", 7).contains("no profile")

    # {.testKind: tkIntegration, covers: "feedRelayControl|feedRelayFastExtraFrame".}
    test "on the relay: a profile change moves a device without re-keying":
      var
        n: RtNet = rtSetup(60'u8)
        step: RelayStep = default(RelayStep)
      n.R.book.profiles = @[@[], @["nas"]]
      check n.R.setRelayRestriction(rmProfile) == ""
      step = n.R.feedRelayFastExtraFrame(n.sPhone,
        sealProfileUpdate(n.phone.left, acrDac, 1), rtNowMs)
      check step.event == reAnswered
      step = n.R.feedRelayFastExtraFrame(n.sPhone,
        sealAmeRouteForward(n.phone.left, rtNas, @[byte 1]), rtNowMs)
      check step.event == reForwarded
      step = n.R.feedRelayFastExtraFrame(n.sPhone,
        sealAmeRouteForward(n.phone.left, rtLaptop, @[byte 2]), rtNowMs)
      check step.event == reDropped
      step = n.R.feedRelayFastExtraFrame(n.sLaptop,
        sealProfileUpdate(n.laptop.left, acrDac, 5), rtNowMs)
      check step.event == reDropped
      check step.err.contains("no profile")

suite "restriction on a relay, all builds":

  # {.testKind: tkUnit, covers: "setRelayRestriction".}
  test "switching to a mode that was not compiled in is refused":
    var
      R: RelayFastExtraFrame = initRelayFastExtraFrame(rtRelay, 4)
    for m in [rmGroup, rmListed, rmProfile]:
      if restrictionBuilt(m):
        check R.setRelayRestriction(m) == ""
      else:
        check R.setRelayRestriction(m).len > 0
        check R.restriction != m

  # {.testKind: tkRegression, covers: "attachRestrictionBook|saveRestrictionBook".}
  test "the book is saved through Geist and read back by a new relay":
    let dir = getTempDir() / "bifrost_restriction_test"
    removeDir(dir)
    var
      n: RtNet = rtSetup(70'u8)
      back: RelayFastExtraFrame = initRelayFastExtraFrame(rtRelay, 4)
      step: RelayStep = default(RelayStep)
    check n.R.attachRestrictionBook(dir) == ""
    check n.R.bookDir == dir
    n.R.book.profiles = @[@[], @["nas"]]
    when restrictionGroupBuilt:
      step = n.R.feedRelayFastExtraFrame(n.sNas,
        sealGroupUpdate(n.nas.left, acrDac, @["phone"]), rtNowMs)
    elif restrictionListedBuilt:
      step = n.R.feedRelayFastExtraFrame(n.sNas,
        sealListedUpdate(n.nas.left, acrDac, ListedFilter(reject: @[
          FilterRule(host: at(rtPhone).host, port: 0)])), rtNowMs)
    else:
      step = n.R.feedRelayFastExtraFrame(n.sPhone,
        sealProfileUpdate(n.phone.left, acrDac, 1), rtNowMs)
    check step.event == reAnswered
    check back.attachRestrictionBook(dir) == ""
    check back.book == n.R.book
    removeDir(dir)
