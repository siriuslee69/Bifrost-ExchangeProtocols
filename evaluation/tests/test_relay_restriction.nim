## -------------------------------------------------------------------------
## Relay restriction tests <- who may talk to whom, judged by the relay
## -------------------------------------------------------------------------
##
## One relay, a server (nas) and two clients (phone, laptop). Each link is one
## AME session pair (relay_fixtures.nim); every frame is handed over by hand,
## so each rule is checked exactly. A mode left out of the binary is checked to
## be refused by name, and its suite is skipped.
##
##   suite                                      what it holds down
##   ----------------------------------------   ---------------------------------
##   "restriction codec"                        the bytes, both ways
##   "restriction modes, as rules"              which modes exist in this binary
##   "restriction mode group|listed|allowed"    each mode's rule, then on a relay
##   "restriction answers, one per interval"    the answer gap, and its zero
##   "restriction on a relay, all builds"       switching and the saved book

import std/[unittest, os, strutils]
import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level2/session
import ../../src/protocols/ame/level2/route_wire
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

proc rtSetup(seed: byte): RtNet =
  ## A relay with the three neighbours admitted and the routes named.
  result.R = initRelayFastExtraFrame(rtRelay, 8)
  result.phone = rtPair(seed)
  result.laptop = rtPair(seed + 1'u8)
  result.nas = rtPair(seed + 2'u8)
  result.R.addRelayTarget(rtNas, "nas", ["phone", "laptop"])
  result.R.addRelayTarget(rtLaptop, "laptop", ["phone", "nas"])
  result.R.addRelayTarget(rtPhone, "phone", ["nas", "laptop"])
  result.sPhone = result.R.admitRelayNeighbour(result.phone.right, rtPhone,
    "phone", at(rtPhone), acrDac).slot
  result.sLaptop = result.R.admitRelayNeighbour(result.laptop.right, rtLaptop,
    "laptop", at(rtLaptop), acrDac).slot
  result.sNas = result.R.admitRelayNeighbour(result.nas.right, rtNas,
    "nas", at(rtNas), acrDac).slot

proc rtAnswer(step: RelayStep): ByteSeq =
  ## step: the one frame the relay answered with.
  result = step.send[0].frame

proc srcOf(id: uint64): SourceAddr =
  ## id: a test device; its address as the relay compares it.
  result = sourceOfAddress(at(id)).src

suite "restriction codec":

  # {.testKind: tkEdgeCase, covers: "decodeRestrictionFrame".}
  test "a body that does not parse is refused, never raised":
    check not decodeRestrictionFrame(@[]).ok
    check not decodeRestrictionFrame(@[byte 9, 1]).ok
    check not decodeRestrictionFrame(@[byte 1, 9]).ok
    check not decodeRestrictionFrame(@[byte 1, 3, 1, 0]).ok
    check not decodeRestrictionFrame(@[byte 1, 2, 0, 0, 0xFF]).ok

  # {.testKind: tkEdgeCase, covers: "decodeRestrictionFrame".}
  test "an address with an unknown family is refused":
    check decodeRestrictionFrame(@[byte 1, 2, 1, 0, 0, 0]).ok
    check not decodeRestrictionFrame(@[byte 1, 2, 1, 9, 0, 0]).ok

  # {.testKind: tkEdgeCase, covers: "decodeRestrictionFrame".}
  test "an acknowledgement is the version byte alone":
    check decodeRestrictionFrame(@[restrictionAckVersion]).ack
    check not decodeRestrictionFrame(@[restrictionAckVersion, 0]).ok

  # {.testKind: tkRegression, covers: "encodeBook|decodeBook".}
  test "the whole book survives encode and decode, IPv4 and IPv6 alike":
    var
      B: RestrictionBook = RestrictionBook()
      enc: tuple[ok: bool, bytes: ByteSeq, err: string] = (false, @[], "")
      back: tuple[ok: bool, book: RestrictionBook, err: string] = (false,
        RestrictionBook(), "")
    B.group.members = @["phone", "laptop"]
    B.group.endpoints = @["nas"]
    B.group.links = @[GroupLink(member: 0, endpoint: 0),
      GroupLink(member: 1, endpoint: 0)]
    B.reach = @[ReachEntry(identity: "nas", rules: SourceRules(
      reject: @[srcOf(rtPhone)],
      allowed: @[sourceOf("2001:db8::1", 47656'u16).src, anySource(0)]))]
    enc = encodeBook(B)
    check enc.ok
    back = decodeBook(enc.bytes)
    check back.ok
    check back.book == B

  # {.testKind: tkEdgeCase, covers: "decodeBook".}
  test "a link into a member the book does not hold is refused":
    var
      B: RestrictionBook = RestrictionBook()
      enc: tuple[ok: bool, bytes: ByteSeq, err: string] = (false, @[], "")
    B.group.members = @["phone"]
    B.group.endpoints = @["nas"]
    B.group.links = @[GroupLink(member: 3, endpoint: 0)]
    enc = encodeBook(B)
    check enc.ok
    check not decodeBook(enc.bytes).ok
    check decodeBook(enc.bytes).err.contains("does not hold")

suite "restriction modes, as rules":

  # {.testKind: tkUnit, covers: "checkRestrictionMode".}
  test "every mode is either compiled in, or refused by name":
    check checkRestrictionMode(rmOpen) == ""
    for m in [rmGroup, rmListed, rmAllowed]:
      if restrictionBuilt(m):
        check checkRestrictionMode(m) == ""
      else:
        check checkRestrictionMode(m).contains("not compiled")

when restrictionGroupBuilt:
  suite "restriction mode group":

    # {.testKind: tkUnit, covers: "groupAllows|setGroup".}
    test "a member reaches its endpoint and back, never another member":
      var
        B: RestrictionBook = RestrictionBook()
      check setGroup(B, "nas", @["phone", "laptop"]) == ""
      check groupAllows(B.group, "phone", "nas")
      check groupAllows(B.group, "nas", "laptop")
      check not groupAllows(B.group, "phone", "laptop")
      check not groupAllows(B.group, "phone", "other")

    # {.testKind: tkRegression, covers: "setGroup".}
    test "a member already linked to another endpoint is refused, nothing changes":
      var
        B: RestrictionBook = RestrictionBook()
      check setGroup(B, "nas", @["phone"]) == ""
      check setGroup(B, "cam", @["phone", "tv"]).contains("already belongs")
      check groupAllows(B.group, "phone", "nas")
      check not groupAllows(B.group, "tv", "cam")

    # {.testKind: tkRegression, covers: "setGroup".}
    test "an endpoint that claims again replaces only its own links":
      var
        B: RestrictionBook = RestrictionBook()
      check setGroup(B, "nas", @["phone", "laptop"]) == ""
      check setGroup(B, "nas", @["phone"]) == ""
      check not groupAllows(B.group, "laptop", "nas")
      check groupAllows(B.group, "phone", "nas")
      check B.group.links.len == 1
      check B.group.members == @["phone"]

    # {.testKind: tkEdgeCase, covers: "setGroup".}
    test "an endpoint cannot name itself as a member":
      var
        B: RestrictionBook = RestrictionBook()
      check setGroup(B, "nas", @["nas"]).contains("names itself")

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
      check step.event == reRefused
      check step.send[0].address == at(rtPhone)
      check n.R.restricted == 1'u32

when restrictionListedBuilt:
  suite "restriction mode listed":

    # {.testKind: tkUnit, covers: "listedAllows".}
    test "reject wins, and an empty accept list accepts the rest":
      var
        F: SourceRules = SourceRules(reject: @[srcOf(rtPhone)])
      check not listedAllows(F, srcOf(rtPhone))
      check listedAllows(F, srcOf(rtLaptop))
      F.accept = @[sourceOf("10.0.0.49", 47656'u16).src]
      check not listedAllows(F, sourceOf("10.0.0.51", 47656'u16).src)
      check listedAllows(F, sourceOf("10.0.0.49", 47656'u16).src)
      check not listedAllows(F, sourceOf("10.0.0.49", 9'u16).src)

    # {.testKind: tkIntegration, covers: "feedRelayControl|feedRelayFastExtraFrame".}
    test "on the relay: the server refuses one address, by where it came from":
      var
        n: RtNet = rtSetup(50'u8)
        step: RelayStep = default(RelayStep)
      check n.R.setRelayRestriction(rmListed) == ""
      step = n.R.feedRelayFastExtraFrame(n.sNas,
        sealListedUpdate(n.nas.left, acrDac, @[], @[srcOf(rtPhone)]), rtNowMs)
      check step.event == reAnswered
      step = n.R.feedRelayFastExtraFrame(n.sPhone,
        sealAmeRouteForward(n.phone.left, rtNas, @[byte 1]), rtNowMs)
      check step.event == reRefused
      step = n.R.feedRelayFastExtraFrame(n.sLaptop,
        sealAmeRouteForward(n.laptop.left, rtNas, @[byte 2]), rtNowMs)
      check step.event == reForwarded
      check n.R.restricted == 1'u32

when restrictionAllowedBuilt:
  suite "restriction mode allowed":

    # {.testKind: tkUnit, covers: "allowedAllows".}
    test "an empty allowed list names nobody; a listed sender passes":
      var
        F: SourceRules = SourceRules()
      check not allowedAllows(F, srcOf(rtPhone))
      F.allowed = @[srcOf(rtPhone)]
      check allowedAllows(F, srcOf(rtPhone))
      check not allowedAllows(F, srcOf(rtLaptop))

    # {.testKind: tkUnit, covers: "setAllowed".}
    test "a new connection starts with an empty allowed list":
      var
        B: RestrictionBook = RestrictionBook()
      check setAllowed(B, "nas", @[srcOf(rtPhone)]) == ""
      check B.reach.len == 1
      check B.reach[0].rules.allowed == @[srcOf(rtPhone)]

    # {.testKind: tkIntegration, covers: "feedRelayControl|feedRelayFastExtraFrame".}
    test "on the relay: an empty set reaches nobody, and still reaches others":
      var
        n: RtNet = rtSetup(60'u8)
        step: RelayStep = default(RelayStep)
      check n.R.setRelayRestriction(rmAllowed) == ""
      step = n.R.feedRelayFastExtraFrame(n.sPhone,
        sealAmeRouteForward(n.phone.left, rtNas, @[byte 1]), rtNowMs)
      check step.event == reRefused
      step = n.R.feedRelayFastExtraFrame(n.sNas,
        sealAllowedUpdate(n.nas.left, acrDac, @[srcOf(rtPhone)]), rtNowMs)
      check step.event == reAnswered
      step = n.R.feedRelayFastExtraFrame(n.sPhone,
        sealAmeRouteForward(n.phone.left, rtNas, @[byte 2]), rtNowMs)
      check step.event == reForwarded
      step = n.R.feedRelayFastExtraFrame(n.sLaptop,
        sealAmeRouteForward(n.laptop.left, rtNas, @[byte 3]), rtNowMs)
      check step.event == reRefused
      step = n.R.feedRelayFastExtraFrame(n.sNas,
        sealAmeRouteForward(n.nas.left, rtPhone, @[byte 4]), rtNowMs)
      check step.event == reRefused
      check n.R.restricted == 3'u32

  suite "restriction answers, one per interval":

    # {.testKind: tkIntegration, covers: "restrictionAnswerDue|feedRelayFastExtraFrame".}
    test "a restricted neighbour gets one answer per interval, the rest are dropped":
      var
        n: RtNet = rtSetup(70'u8)
        step: RelayStep = default(RelayStep)
      check n.R.setRelayRestriction(rmAllowed) == ""
      check n.R.restrictionAnswerMs == restrictionAnswerDefaultMs
      step = n.R.feedRelayFastExtraFrame(n.sPhone,
        sealAmeRouteForward(n.phone.left, rtNas, @[byte 1]), 1000'u32)
      check step.event == reRefused
      check step.send.len == 1
      step = n.R.feedRelayFastExtraFrame(n.sPhone,
        sealAmeRouteForward(n.phone.left, rtNas, @[byte 2]), 1500'u32)
      check step.event == reDropped
      check step.send.len == 0
      check step.err.startsWith("restricted")
      step = n.R.feedRelayFastExtraFrame(n.sPhone,
        sealAmeRouteForward(n.phone.left, rtNas, @[byte 3]), 2000'u32)
      check step.event == reRefused
      check n.R.restricted == 3'u32

    # {.testKind: tkEdgeCase, covers: "restrictionAnswerDue|setRestrictionAnswerMs".}
    test "each neighbour has its own clock, and an interval of 0 never answers":
      var
        n: RtNet = rtSetup(80'u8)
        step: RelayStep = default(RelayStep)
      check n.R.setRelayRestriction(rmAllowed) == ""
      step = n.R.feedRelayFastExtraFrame(n.sPhone,
        sealAmeRouteForward(n.phone.left, rtNas, @[byte 1]), 1000'u32)
      check step.event == reRefused
      step = n.R.feedRelayFastExtraFrame(n.sLaptop,
        sealAmeRouteForward(n.laptop.left, rtNas, @[byte 2]), 1000'u32)
      check step.event == reRefused
      n.R.setRestrictionAnswerMs(0'u32)
      step = n.R.feedRelayFastExtraFrame(n.sPhone,
        sealAmeRouteForward(n.phone.left, rtNas, @[byte 3]), 9000'u32)
      check step.event == reDropped
      check step.send.len == 0
      n.R.setRestrictionAnswerMs(500'u32)
      step = n.R.feedRelayFastExtraFrame(n.sPhone,
        sealAmeRouteForward(n.phone.left, rtNas, @[byte 4]), 9100'u32)
      check step.event == reRefused

suite "restriction on a relay, all builds":

  # {.testKind: tkUnit, covers: "setRelayRestriction".}
  test "switching to a mode that was not compiled in is refused":
    var
      R: RelayFastExtraFrame = initRelayFastExtraFrame(rtRelay, 4)
    for m in [rmGroup, rmListed, rmAllowed]:
      if restrictionBuilt(m):
        check R.setRelayRestriction(m) == ""
      else:
        check R.setRelayRestriction(m).len > 0
        check R.restriction != m

  # {.testKind: tkRegression, covers: "attachRestrictionBook|saveRestrictionBook".}
  test "the book is saved through Geist and read back by a new relay":
    var
      dir: string = getTempDir() / "bifrost_restriction_test"
      n: RtNet = rtSetup(90'u8)
      back: RelayFastExtraFrame = initRelayFastExtraFrame(rtRelay, 4)
      step: RelayStep = default(RelayStep)
    removeDir(dir)
    check n.R.attachRestrictionBook(dir) == ""
    check n.R.bookDir == dir
    when restrictionGroupBuilt:
      step = n.R.feedRelayFastExtraFrame(n.sNas,
        sealGroupUpdate(n.nas.left, acrDac, @["phone"]), rtNowMs)
    elif restrictionListedBuilt:
      step = n.R.feedRelayFastExtraFrame(n.sNas,
        sealListedUpdate(n.nas.left, acrDac, @[], @[srcOf(rtPhone)]), rtNowMs)
    else:
      step = n.R.feedRelayFastExtraFrame(n.sNas,
        sealAllowedUpdate(n.nas.left, acrDac, @[srcOf(rtPhone)]), rtNowMs)
    check step.event == reAnswered
    check back.attachRestrictionBook(dir) == ""
    check back.book == n.R.book
    removeDir(dir)
