## -------------------------------------------------------------------------
## Super-fast restriction tests <- the operator's list, before a slot is taken
## -------------------------------------------------------------------------
##
## The super-fast relay reads no AME frames, so its restriction is set by the
## operator in code or config, never by a device. It is checked on the client
## address, before the client gets a slot, so a refused client costs nothing.
##
##   suite                                  what it holds down
##   -------------------------------------  -----------------------------------
##   "super-fast, open by default"          no restriction, no parsing
##   "super-fast, listed"                   reject list; refused takes no slot
##   "super-fast, allowed"                  who may reach the NAS; empty = none
##   "super-fast, what it refuses"          group mode and unknown modes
##
## Refused datagrams are dropped and counted, never answered: this relay has
## no reply format that a client could read as a refusal.

import std/unittest
import std/strutils

import ../../src/protocols/types
import ../../src/protocols/transport/types as transport_types
import ../../src/protocols/relay/super_fast_udp
import ../../src/protocols/relay/restriction
import runePragmas

proc ep(h: string, p: uint16): transport_types.UdpAddress {.role: configurator.} =
  result = initUdpAddress(h, p)

proc nasAddr(): transport_types.UdpAddress {.role: configurator.} =
  result = ep("10.0.0.2", 9000'u16)

proc freshRelay(): RelaySuperFastUdp {.role: configurator.} =
  result = initRelaySuperFastUdp(nasAddr())

suite "super-fast, open by default":

  # {.testKind: tkUnit, covers: "fromClient".}
  test "with no restriction set, every client passes":
    var
      F: RelaySuperFastUdp = freshRelay()
      step: UdpForwardStep = fromClient(F, ep("203.0.113.7", 40000'u16),
        @[byte 1], 1000'u64)
    check F.restriction == rmOpen
    check step.event == ufeForwarded
    check F.restricted == 0'u64

when restrictionListedBuilt:
  suite "super-fast, listed":

    # {.testKind: tkIntegration, covers: "fromClient|setSuperFastRestriction".}
    test "a rejected client is dropped before it takes a slot":
      var
        F: RelaySuperFastUdp = freshRelay()
        step: UdpForwardStep = default(UdpForwardStep)
      check setSuperFastRestriction(F, rmListed, SourceRules(reject: @[
        sourceOf("203.0.113.7", 0'u16).src])) == ""
      step = fromClient(F, ep("203.0.113.7", 40000'u16), @[byte 1], 1000'u64)
      check step.event == ufeDropped
      check step.err.startsWith("restricted")
      check udpForwardClients(F) == 0
      check F.restricted == 1'u64
      step = fromClient(F, ep("203.0.113.8", 40000'u16), @[byte 2], 1000'u64)
      check step.event == ufeForwarded
      check udpForwardClients(F) == 1

when restrictionAllowedBuilt:
  suite "super-fast, allowed":

    # {.testKind: tkIntegration, covers: "fromClient|setSuperFastRestriction".}
    test "only the listed clients reach the NAS; an empty list reaches nobody":
      var
        F: RelaySuperFastUdp = freshRelay()
        step: UdpForwardStep = default(UdpForwardStep)
      check setSuperFastRestriction(F, rmAllowed, SourceRules()) == ""
      step = fromClient(F, ep("203.0.113.7", 40000'u16), @[byte 1], 1000'u64)
      check step.event == ufeDropped
      check udpForwardClients(F) == 0
      check setSuperFastRestriction(F, rmAllowed, SourceRules(allowed: @[
        sourceOf("203.0.113.7", 0'u16).src])) == ""
      step = fromClient(F, ep("203.0.113.7", 40000'u16), @[byte 2], 1000'u64)
      check step.event == ufeForwarded
      step = fromClient(F, ep("203.0.113.8", 40000'u16), @[byte 3], 1000'u64)
      check step.event == ufeDropped
      check F.restricted == 2'u64

    # {.testKind: tkEdgeCase, covers: "clientMayReach".}
    test "a client address that is not an IP is dropped while a restriction is set":
      var
        F: RelaySuperFastUdp = freshRelay()
        step: UdpForwardStep = default(UdpForwardStep)
      check setSuperFastRestriction(F, rmAllowed, SourceRules(allowed: @[
        anySource()])) == ""
      step = fromClient(F, ep("localhost", 40000'u16), @[byte 1], 1000'u64)
      check step.event == ufeDropped
      check step.err.startsWith("restricted")

suite "super-fast, what it refuses":

  # {.testKind: tkUnit, covers: "setSuperFastRestriction".}
  test "the group mode is refused: this relay reads no control frames":
    var
      F: RelaySuperFastUdp = freshRelay()
    check setSuperFastRestriction(F, rmGroup, SourceRules()).contains(
      "cannot run the group mode")
    check F.restriction == rmOpen

  # {.testKind: tkUnit, covers: "setSuperFastRestriction".}
  test "a mode left out of the binary is refused by name":
    var
      F: RelaySuperFastUdp = freshRelay()
    for m in [rmListed, rmAllowed]:
      if restrictionBuilt(m):
        check setSuperFastRestriction(F, m, SourceRules()) == ""
      else:
        check setSuperFastRestriction(F, m, SourceRules()).contains(
          "not compiled")
        check F.restriction != m
