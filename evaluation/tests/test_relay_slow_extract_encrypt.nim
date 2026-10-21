## -------------------------------------------------------------------------
## relaySlowExtractEncrypt Tests <- every link opened, the payload read and
##                                  judged, then sealed again
## -------------------------------------------------------------------------
##
##   phone (0x30) ==A==> relay (0x10) ==C==> nas (0x20)
##
##   suite                                   what it holds down
##   --------------------------------------  ------------------------------
##   "the slow envelope"                     the 22 bytes inside the frame
##   "relaySlowExtractEncrypt, one hop"      forward, answer, directory,
##                                           origin, strangers, replay
##   "the inspector"                         refuse, rewrite, kind check
##
## No socket is opened; a frame is handed from one node to the next by hand.

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level2/route_directory
import ../../src/protocols/transport/types as transport_types
import ../../src/protocols/relay/slow_envelope
import ../../src/protocols/relay/relay_node
import ../../src/protocols/relay/fast_extra_frame
import ../../src/protocols/relay/slow_extract_encrypt
import ./relay_fixtures
import runePragmas

suite "the slow envelope":

  # {.testKind: tkUnit, covers: "encodeSlowEnvelope".}
  test "a forward is 22 bytes of header, then the payload as it was":
    var
      A: ByteSeq = encodeSlowEnvelope(arkForward, 6'u8, idNas, 0'u64,
        @[byte 0x68, 0x69])
      F: AmeRouteFrame = decodeSlowEnvelope(A)
    check A.len == relaySlowOverhead + 2
    check A[0 .. 5] == @[byte 0x52, 0x53, 0x45, 0x01, 0x01, 0x06]
    check A[6] == 0x20'u8
    check F.ok
    check F.kind == arkForward
    check F.target == idNas
    check F.hopsLeft == 6'u8
    check F.payload == @[byte 0x68, 0x69]

  # {.testKind: tkEdgeCase, covers: "decodeSlowEnvelope".}
  test "short, foreign, unknown and reasonless envelopes are refused, never raised":
    var
      good: ByteSeq = encodeSlowEnvelope(arkRefuse, 1'u8, idNas, idPhone, [])
      bad: ByteSeq = good
    check decodeSlowEnvelope(good).ok
    check decodeSlowEnvelope(good).refusal == arrNoRoute
    check not decodeSlowEnvelope(good[0 .. 20]).ok
    bad[0] = uint8('A')
    check not decodeSlowEnvelope(bad).ok
    bad = good
    bad[4] = 0x09'u8
    check decodeSlowEnvelope(bad).err == "relay envelope kind is unknown"
    bad = good
    bad[5] = 0x00'u8
    check decodeSlowEnvelope(bad).err ==
      "relay envelope refusal names no reason"

suite "relaySlowExtractEncrypt, one hop":
  setup:
    var
      R: RelaySlowExtractEncrypt = initRelaySlowExtractEncrypt(idR1, 4)
      phoneNode: RelaySlowExtractEncrypt = initRelaySlowExtractEncrypt(
        idPhone, 1)
      nasNode: RelaySlowExtractEncrypt = initRelaySlowExtractEncrypt(idNas, 1)
      phone: RtPair = rtPair(40'u8)
      nas: RtPair = rtPair(41'u8)
      step: RelayStep = default(RelayStep)
    R.addRelayTarget(idNas, "nas", ["phone"])
    check R.admitRelayNeighbour(phone.right, idPhone, "phone", at(idPhone),
      acrDac).ok
    check R.admitRelayNeighbour(nas.right, idNas, "nas", at(idNas), acrDac).ok
    check phoneNode.admitRelayNeighbour(phone.left, idR1, "relay", at(idR1),
      acrDac, router = true).ok
    check nasNode.admitRelayNeighbour(nas.left, idR1, "relay", at(idR1),
      acrDac, router = true).ok

  # {.testKind: tkIntegration, covers: "feedRelaySlowExtractEncrypt".}
  test "forward, deliver, and the answer back":
    step = R.feedRelaySlowExtractEncrypt(at(idPhone), sealSlowForward(
      phone.left, acrDac, idNas, @[byte 1, 2, 3]), 0'u32)
    check step.event == reForwarded
    check step.frame.payload == @[byte 1, 2, 3]   # the relay READ it
    check step.send[0].address == at(idNas)
    step = nasNode.feedRelaySlowExtractEncrypt(at(idR1), step.send[0].frame,
      0'u32)
    check step.event == reDelivered
    check step.frame.origin == idPhone
    check step.frame.payload == @[byte 1, 2, 3]
    step = R.feedRelaySlowExtractEncrypt(at(idNas), sealSlowForward(nas.left,
      acrDac, idPhone, @[byte 9]), 0'u32)
    check step.event == reForwarded
    check step.send[0].address == at(idPhone)
    step = phoneNode.feedRelaySlowExtractEncrypt(at(idR1), step.send[0].frame,
      0'u32)
    check step.event == reDelivered
    check step.frame.origin == idNas
    check step.frame.payload == @[byte 9]

  # {.testKind: tkUnit, covers: "feedRelaySlowExtractEncrypt".}
  test "a directory question goes through the same feed call":
    var
      D: AmeRouteDirectory = default(AmeRouteDirectory)
    step = R.feedRelaySlowExtractEncrypt(at(idPhone), sealAmeRouteAsk(
      phone.left, acrDac), 0'u32)
    check step.event == reAnswered
    D = openAmeRouteDirectory(phone.left, acrDac, step.send[0].frame)
    check D.entries == @[AmeRouteEntry(id: idNas, name: "nas")]

  # {.testKind: tkRegression, covers: "feedRelaySlowExtractEncrypt".}
  test "a client's own origin claim is overwritten":
    step = R.feedRelaySlowExtractEncrypt(at(idPhone), sealSlowForward(
      phone.left, acrDac, idNas, @[byte 1], origin = 0x99'u64), 0'u32)
    step = nasNode.feedRelaySlowExtractEncrypt(at(idR1), step.send[0].frame,
      0'u32)
    check step.frame.origin == idPhone

  # {.testKind: tkEdgeCase, covers: "feedRelaySlowExtractEncrypt".}
  test "a hidden target gets arrNoRoute, sealed back for the sender":
    step = R.feedRelaySlowExtractEncrypt(at(idPhone), sealSlowForward(
      phone.left, acrDac, 0x77'u64, @[byte 1]), 0'u32)
    check step.event == reRefused
    check step.send[0].address == at(idPhone)
    step = phoneNode.feedRelaySlowExtractEncrypt(at(idR1), step.send[0].frame,
      0'u32)
    check step.event == reRefused
    check step.frame.refusal == arrNoRoute
    check step.frame.target == 0x77'u64

  # {.testKind: tkEdgeCase, covers: "feedRelaySlowExtractEncrypt".}
  test "strangers, junk and a replayed frame are dropped":
    var
      frame: ByteSeq = sealSlowForward(phone.left, acrDac, idNas, @[byte 1])
    step = R.feedRelaySlowExtractEncrypt(initTransportAddress("203.0.113.9",
      1'u16), frame, 0'u32)
    check step.event == reDropped
    check step.err == "relay slot is empty"
    step = R.feedRelaySlowExtractEncrypt(at(idPhone), @[byte 1, 2, 3], 0'u32)
    check step.event == reDropped
    step = R.feedRelaySlowExtractEncrypt(at(idPhone), frame, 0'u32)
    check step.event == reForwarded
    step = R.feedRelaySlowExtractEncrypt(at(idPhone), frame, 0'u32)
    check step.event == reDropped
    check step.send.len == 0

suite "the inspector":
  setup:
    var
      seen: seq[string] = @[]
      phone: RtPair = rtPair(50'u8)
      nas: RtPair = rtPair(51'u8)
      step: RelayStep = default(RelayStep)
      R: RelaySlowExtractEncrypt = default(RelaySlowExtractEncrypt)
      nasNode: RelaySlowExtractEncrypt = default(RelaySlowExtractEncrypt)
    proc readOnly(identity: string, f: var AmeRouteFrame): bool =
      ## Lets the phone send anything but a write (first byte 0x57 'W'),
      ## and stamps a marker byte on what it lets through.
      seen.add(identity)
      if f.payload.len > 0 and f.payload[0] == 0x57'u8:
        return false
      f.payload.add(0xAA'u8)
      result = true
    R = initRelaySlowExtractEncrypt(idR1, 4, inspect = readOnly)
    nasNode = initRelaySlowExtractEncrypt(idNas, 1)
    R.addRelayTarget(idNas, "nas", ["phone"])
    check R.admitRelayNeighbour(phone.right, idPhone, "phone", at(idPhone),
      acrDac).ok
    check R.admitRelayNeighbour(nas.right, idNas, "nas", at(idNas), acrDac).ok
    check nasNode.admitRelayNeighbour(nas.left, idR1, "relay", at(idR1),
      acrDac, router = true).ok

  # {.testKind: tkUnit, covers: "initRelaySlowExtractEncrypt".}
  test "it sees the sender's identity and may rewrite the payload":
    step = R.feedRelaySlowExtractEncrypt(at(idPhone), sealSlowForward(
      phone.left, acrDac, idNas, @[byte 0x52]), 0'u32)
    check step.event == reForwarded
    check seen == @["phone"]
    step = nasNode.feedRelaySlowExtractEncrypt(at(idR1), step.send[0].frame,
      0'u32)
    check step.frame.payload == @[byte 0x52, 0xAA]

  # {.testKind: tkUnit, covers: "initRelaySlowExtractEncrypt".}
  test "what it refuses gets the same arrNoRoute as a hidden target":
    step = R.feedRelaySlowExtractEncrypt(at(idPhone), sealSlowForward(
      phone.left, acrDac, idNas, @[byte 0x57]), 0'u32)
    check step.event == reRefused
    check step.send.len == 1
    check step.send[0].address == at(idPhone)
    check R.forwarded == 0'u32

  # {.testKind: tkEdgeCase, covers: "setupRelayNode".}
  test "a fast relay cannot be given an inspector":
    var
      F: RelayFastExtraFrame = default(RelayFastExtraFrame)
    expect ValueError:
      setupRelayNode(F, rkFastExtraFrame, idR1, 4, readOnly)
