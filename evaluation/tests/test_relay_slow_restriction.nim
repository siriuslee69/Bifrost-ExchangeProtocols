## -------------------------------------------------------------------------
## relaySlowExtractEncrypt restriction tests <- the relay that reads every
##                                              payload, judged the same way
## -------------------------------------------------------------------------
##
##   phone (0x30) ==A==> relay (0x10) ==C==> nas (0x20)
##   laptop (0x31) ==B==> relay
##
## The restriction is checked at this relay before the frame is opened again
## and sealed for the next hop. A refused frame gets the same answer as a
## missing route (arrNoRoute), so the phone cannot tell "no such target" from
## "not allowed", and the answer is checked by opening it on the phone's side.
##
##   suite                                   what it holds down
##   --------------------------------------  ------------------------------------
##   "relaySlowExtractEncrypt, allowed"      an empty set, then the nas's list
##   "relaySlowExtractEncrypt, listed"       reject by arrival address
##   "relaySlowExtractEncrypt, group"        member to endpoint only

import std/[unittest, strutils]

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/transport/types as transport_types
import ../../src/protocols/relay/relay_node
import ../../src/protocols/relay/slow_envelope
import ../../src/protocols/relay/slow_extract_encrypt
import ../../src/protocols/relay/restriction
import ./relay_fixtures
import runePragmas

type
  SlowNet = object
    R: RelaySlowExtractEncrypt
    phone: RtPair
    laptop: RtPair
    nas: RtPair

proc slowSetup(seed: byte): SlowNet =
  ## A relay with the phone, the laptop and the nas admitted, routes named.
  result.R = initRelaySlowExtractEncrypt(idR1, 4)
  result.phone = rtPair(seed)
  result.laptop = rtPair(seed + 1'u8)
  result.nas = rtPair(seed + 2'u8)
  result.R.addRelayTarget(idNas, "nas", ["phone", "laptop"])
  result.R.addRelayTarget(idPhone, "phone", ["nas"])
  check result.R.admitRelayNeighbour(result.phone.right, idPhone, "phone",
    at(idPhone), acrDac).ok
  check result.R.admitRelayNeighbour(result.laptop.right, idLaptop, "laptop",
    at(idLaptop), acrDac).ok
  check result.R.admitRelayNeighbour(result.nas.right, idNas, "nas",
    at(idNas), acrDac).ok

proc srcOf(id: uint64): SourceAddr =
  ## id: a test device; its address as the relay compares it.
  result = sourceOfAddress(at(id)).src

suite "relaySlowExtractEncrypt, restrictions":

  when restrictionAllowedBuilt:
    # {.testKind: tkIntegration, covers: "feedRelaySlowExtractEncrypt|setRelayRestriction".}
    test "an empty allowed list refuses the phone, and the phone reads why":
      var
        n: SlowNet = slowSetup(40'u8)
        phoneNode: RelaySlowExtractEncrypt = initRelaySlowExtractEncrypt(idPhone, 1)
        step: RelayStep = default(RelayStep)
        back: RelayStep = default(RelayStep)
      check phoneNode.admitRelayNeighbour(n.phone.left, idR1, "relay",
        at(idR1), acrDac, router = true).ok
      check n.R.setRelayRestriction(rmAllowed) == ""
      step = n.R.feedRelaySlowExtractEncrypt(at(idPhone), sealSlowForward(
        n.phone.left, acrDac, idNas, @[byte 1, 2, 3]), 0'u32)
      check step.event == reRefused
      check step.send.len == 1
      check step.send[0].address == at(idPhone)
      back = phoneNode.feedRelaySlowExtractEncrypt(at(idR1),
        step.send[0].frame, 0'u32)
      check back.event == reRefused
      check back.frame.refusal == arrNoRoute

    # {.testKind: tkIntegration, covers: "feedRelaySlowExtractEncrypt|setAllowed".}
    test "the nas names the phone: the phone passes, the laptop is still refused":
      var
        n: SlowNet = slowSetup(50'u8)
        step: RelayStep = default(RelayStep)
      check n.R.setRelayRestriction(rmAllowed) == ""
      step = n.R.feedRelaySlowExtractEncrypt(at(idNas), sealAllowedUpdate(
        n.nas.left, acrDac, @[srcOf(idPhone)]), 0'u32)
      check step.event == reAnswered
      step = n.R.feedRelaySlowExtractEncrypt(at(idPhone), sealSlowForward(
        n.phone.left, acrDac, idNas, @[byte 1, 2, 3]), 0'u32)
      check step.event == reForwarded
      check step.frame.payload == @[byte 1, 2, 3]
      check step.send[0].address == at(idNas)
      step = n.R.feedRelaySlowExtractEncrypt(at(idLaptop), sealSlowForward(
        n.laptop.left, acrDac, idNas, @[byte 4]), 0'u32)
      check step.event == reRefused
      check n.R.restricted == 1'u32

  when restrictionListedBuilt:
    # {.testKind: tkIntegration, covers: "feedRelaySlowExtractEncrypt|setListed".}
    test "the nas rejects the laptop by where it came from, and the rest is silent":
      var
        n: SlowNet = slowSetup(60'u8)
        step: RelayStep = default(RelayStep)
      check n.R.setRelayRestriction(rmListed) == ""
      step = n.R.feedRelaySlowExtractEncrypt(at(idNas), sealListedUpdate(
        n.nas.left, acrDac, @[], @[srcOf(idLaptop)]), 0'u32)
      check step.event == reAnswered
      step = n.R.feedRelaySlowExtractEncrypt(at(idPhone), sealSlowForward(
        n.phone.left, acrDac, idNas, @[byte 1]), 0'u32)
      check step.event == reForwarded
      step = n.R.feedRelaySlowExtractEncrypt(at(idLaptop), sealSlowForward(
        n.laptop.left, acrDac, idNas, @[byte 2]), 0'u32)
      check step.event == reRefused
      step = n.R.feedRelaySlowExtractEncrypt(at(idLaptop), sealSlowForward(
        n.laptop.left, acrDac, idNas, @[byte 3]), 0'u32)
      check step.event == reDropped
      check step.send.len == 0
      check step.err.startsWith("restricted")

  when restrictionGroupBuilt:
    # {.testKind: tkIntegration, covers: "feedRelaySlowExtractEncrypt|setGroup".}
    test "a member reaches its endpoint, a device outside the group does not":
      var
        n: SlowNet = slowSetup(70'u8)
        step: RelayStep = default(RelayStep)
      check n.R.setRelayRestriction(rmGroup) == ""
      step = n.R.feedRelaySlowExtractEncrypt(at(idNas), sealGroupUpdate(
        n.nas.left, acrDac, @["phone"]), 0'u32)
      check step.event == reAnswered
      step = n.R.feedRelaySlowExtractEncrypt(at(idPhone), sealSlowForward(
        n.phone.left, acrDac, idNas, @[byte 1]), 0'u32)
      check step.event == reForwarded
      step = n.R.feedRelaySlowExtractEncrypt(at(idLaptop), sealSlowForward(
        n.laptop.left, acrDac, idNas, @[byte 2]), 0'u32)
      check step.event == reRefused
