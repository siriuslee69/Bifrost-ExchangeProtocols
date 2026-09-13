## -------------------------------------------------------------------------
## UDP Forward Tests <- a relay that moves bytes and understands none of them
## -------------------------------------------------------------------------
##
## The relay sits on a small VPS because the NAS behind it has no address the
## world can reach. It holds no key, so every rule it follows has to work
## without ever looking inside a datagram:
##
##   who sent it        -> which client slot, which tag
##   how big it is      -> refuse the impossible ones
##   when it arrived    -> expire slots, notice the NAS has gone
##
## That is the whole of its knowledge, and these tests are written only in
## those terms. Nothing below seals, opens, or inspects a payload, because the
## relay cannot either.
##
## Time is passed in rather than read from a clock, so every rule about idle
## slots, keepalives and a missing NAS is checked exactly instead of waited
## for.

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/transport/types as transport_types
import ../../src/protocols/relay/udp_forward
import runePragmas

proc ep(h: string, p: uint16): transport_types.UdpAddress {.role: configurator.} =
  result = initUdpAddress(h, p)

proc nasAddr(): transport_types.UdpAddress {.role: configurator.} =
  result = ep("10.0.0.2", 9000'u16)

proc relay(cfg: UdpForwardConfig = initUdpForwardConfig()): UdpForwarder {.
    role: configurator.} =
  result = initUdpForwarder(nasAddr(), cfg)

suite "UDP forward":
  # {.testKind: tkIntegration, covers: "fromClient".}
  test "a datagram reaches the NAS with its bytes untouched":
    var
      F: UdpForwarder = relay()
      step: UdpForwardStep = fromClient(F, ep("203.0.113.7", 40000'u16),
        @[byte 1, 2, 3, 4, 5], 1000'u64)
    check step.event == ufeForwarded
    check step.send.len == 1
    check step.send[0].peer == nasAddr()
    ## Not a byte added, removed or moved. The frame the client sealed is the
    ## frame the NAS opens, which is what lets both ends stay unaware of this.
    check step.send[0].payload == @[byte 1, 2, 3, 4, 5]
    check udpForwardClients(F) == 1

  # {.testKind: tkIntegration, covers: "fromNas".}
  test "the answer finds its way back by tag":
    var
      F: UdpForwarder = relay()
      client: transport_types.UdpAddress = ep("203.0.113.7", 40000'u16)
      out1: UdpForwardStep = fromClient(F, client, @[byte 9], 1000'u64)
      back: UdpForwardStep = default(UdpForwardStep)
    back = fromNas(F, out1.send[0].tag, @[byte 8, 8], 1100'u64)
    check back.event == ufeForwarded
    check back.send.len == 1
    check back.send[0].peer == client
    check back.send[0].payload == @[byte 8, 8]

  # {.testKind: tkUnit.}
  test "two clients never share a tag":
    var
      F: UdpForwarder = relay()
      a: UdpForwardStep = fromClient(F, ep("203.0.113.7", 40000'u16),
        @[byte 1], 1000'u64)
      b: UdpForwardStep = fromClient(F, ep("203.0.113.8", 40000'u16),
        @[byte 1], 1000'u64)
      again: UdpForwardStep = default(UdpForwardStep)
    check a.send[0].tag != b.send[0].tag
    ## The same client coming back keeps the tag it already has, so the NAS
    ## keeps seeing one conversation rather than a new one per datagram.
    again = fromClient(F, ep("203.0.113.7", 40000'u16), @[byte 2], 1200'u64)
    check again.send[0].tag == a.send[0].tag
    check udpForwardClients(F) == 2

  # {.testKind: tkRegression, covers: "fromNas", pins: "an answer could reach the wrong client after a slot was reused".}
  test "an answer for a released slot is dropped, not redirected":
    ## Tags are reused once a slot is freed. If an answer that arrives late
    ## were matched to whoever holds the tag now, one client would be handed
    ## another client's bytes -- the single worst thing a relay can do.
    var
      F: UdpForwarder = relay(initUdpForwardConfig(clientIdleMs = 5_000'u64))
      first: UdpForwardStep = fromClient(F, ep("203.0.113.7", 40000'u16),
        @[byte 1], 1000'u64)
      tag: uint32 = first.send[0].tag
      late: UdpForwardStep = default(UdpForwardStep)
    discard tickUdpForwarder(F, 100_000'u64)
    check udpForwardClients(F) == 0
    late = fromNas(F, tag, @[byte 5], 100_100'u64)
    check late.event == ufeDropped
    check late.send.len == 0
    check late.err == "UDP forward answer has no client"

  # {.testKind: tkEdgeCase, covers: "slotForClient".}
  test "the client table has a ceiling and refuses past it":
    ## Anyone who can send a datagram gets a slot, so the table has to have a
    ## top or a stranger sending from many addresses can grow it until the VPS
    ## runs out of memory. Refusing the newcomer is the right failure:
    ## evicting somebody to make room would let the stranger push out the
    ## clients that are really using the relay.
    var
      F: UdpForwarder = relay(initUdpForwardConfig(maxClients = 3))
      step: UdpForwardStep = default(UdpForwardStep)
      i: int = 0
    while i < 3:
      step = fromClient(F, ep("203.0.113." & $i, 40000'u16), @[byte 1],
        1000'u64)
      check step.event == ufeForwarded
      i = i + 1
    step = fromClient(F, ep("203.0.113.99", 40000'u16), @[byte 1], 1000'u64)
    check step.event == ufeDropped
    check step.err == "UDP forward client table is full"
    check udpForwardClients(F) == 3

  # {.testKind: tkUnit, covers: "reapIdleSlots".}
  test "a silent client loses its slot and frees the tag":
    var
      F: UdpForwarder = relay(initUdpForwardConfig(maxClients = 1,
        clientIdleMs = 5_000'u64))
      first: UdpForwardStep = fromClient(F, ep("203.0.113.7", 40000'u16),
        @[byte 1], 1000'u64)
      second: UdpForwardStep = default(UdpForwardStep)
    check udpForwardClients(F) == 1
    ## The table holds exactly one, so the newcomer can only be let in if the
    ## old slot was really released rather than merely marked.
    second = fromClient(F, ep("203.0.113.8", 40000'u16), @[byte 2],
      50_000'u64)
    check second.event == ufeForwarded
    check udpForwardClients(F) == 1
    check second.send[0].tag == first.send[0].tag

  # {.testKind: tkEdgeCase, covers: "bufferForNas".}
  test "a missing NAS sends datagrams to the buffer, not to a hole":
    var
      F: UdpForwarder = relay()
      step: UdpForwardStep = default(UdpForwardStep)
    ## The NAS has to have been heard from at least once before it can count
    ## as away. A relay starting up beside a booting NAS would otherwise
    ## buffer everything until the first reply.
    discard fromNas(F, 0'u32, @[byte 1], 1000'u64)
    step = fromClient(F, ep("203.0.113.7", 40000'u16), @[byte 7], 1000'u64)
    check step.event == ufeForwarded
    step = fromClient(F, ep("203.0.113.7", 40000'u16), @[byte 7], 200_000'u64)
    check step.event == ufeBuffered
    check step.send.len == 0
    check udpForwardBuffered(F) == 1

  # {.testKind: tkEdgeCase, covers: "dropOldestBuffered".}
  test "a full buffer gives up the oldest, and says how many":
    ## The buffer covers a reboot, not an outage. Everything in it is a
    ## datagram the real transport can ask for again, so the freshest few are
    ## worth more than a long tail of stale ones.
    var
      F: UdpForwarder = relay(initUdpForwardConfig(bufferDatagrams = 4))
      step: UdpForwardStep = default(UdpForwardStep)
      i: int = 0
    discard fromNas(F, 0'u32, @[byte 1], 1000'u64)
    while i < 4:
      step = fromClient(F, ep("203.0.113.7", 40000'u16), @[byte uint8(i)],
        200_000'u64)
      check step.event == ufeBuffered
      check step.dropped == 0
      i = i + 1
    check udpForwardBuffered(F) == 4
    step = fromClient(F, ep("203.0.113.7", 40000'u16), @[byte 99],
      200_000'u64)
    check step.dropped == 1
    check udpForwardBuffered(F) == 4
    ## And the loss is counted rather than hidden.
    check F.droppedTotal == 1'u64

  # {.testKind: tkIntegration, covers: "noteNasSeen".}
  test "a returning NAS drains the buffer in order":
    var
      F: UdpForwarder = relay()
      back: UdpForwardStep = default(UdpForwardStep)
      i: int = 0
    discard fromNas(F, 0'u32, @[byte 1], 1000'u64)
    while i < 3:
      discard fromClient(F, ep("203.0.113.7", 40000'u16), @[byte uint8(i)],
        200_000'u64)
      i = i + 1
    check udpForwardBuffered(F) == 3
    back = noteNasSeen(F, nasAddr(), 200_100'u64)
    check back.send.len == 3
    check back.send[0].payload == @[byte 0]
    check back.send[1].payload == @[byte 1]
    check back.send[2].payload == @[byte 2]
    check udpForwardBuffered(F) == 0

  # {.testKind: tkEdgeCase, covers: "noteNasSeen".}
  test "the relay follows the NAS to a new address":
    ## A home line hands out a different address after a reconnect. Insisting
    ## on the configured one would mean a relay that never recovers.
    var
      F: UdpForwarder = relay()
      moved: transport_types.UdpAddress = ep("10.0.0.55", 9000'u16)
      step: UdpForwardStep = noteNasSeen(F, moved, 5_000'u64)
    check step.event == ufeNasChanged
    check F.nas == moved
    step = fromClient(F, ep("203.0.113.7", 40000'u16), @[byte 1], 5_100'u64)
    check step.send[0].peer == moved

  # {.testKind: tkEdgeCase.}
  test "an empty or impossible datagram is refused without being read":
    var
      F: UdpForwarder = relay(initUdpForwardConfig(maxDatagramBytes = 16))
      empty: UdpForwardStep = fromClient(F, ep("203.0.113.7", 40000'u16),
        @[], 1000'u64)
      huge: UdpForwardStep = fromClient(F, ep("203.0.113.7", 40000'u16),
        newSeq[uint8](17), 1000'u64)
    check empty.event == ufeDropped
    check huge.event == ufeDropped
    ## Neither opened a slot, so rubbish cannot fill the table either.
    check udpForwardClients(F) == 0

  # {.testKind: tkUnit, covers: "tickUdpForwarder".}
  test "the NAS is poked only when a poke is due":
    ## Without a keepalive the relay cannot tell "nobody is talking" from "the
    ## NAS has gone", and the NAS's own router would drop the mapping.
    var
      F: UdpForwarder = relay()
      first: UdpForwardStep = tickUdpForwarder(F, 1_000'u64, @[byte 1])
      soon: UdpForwardStep = default(UdpForwardStep)
      later: UdpForwardStep = default(UdpForwardStep)
    check first.send.len == 1
    check first.send[0].peer == nasAddr()
    soon = tickUdpForwarder(F, 2_000'u64, @[byte 1])
    check soon.send.len == 0
    later = tickUdpForwarder(F, 30_000'u64, @[byte 1])
    check later.send.len == 1

  # {.testKind: tkUnit.}
  test "a tick with nothing to say sends nothing":
    var
      F: UdpForwarder = relay()
      step: UdpForwardStep = default(UdpForwardStep)
    discard tickUdpForwarder(F, 1_000'u64, @[byte 1])
    step = tickUdpForwarder(F, 1_500'u64)
    check step.send.len == 0
    check step.dropped == 0
    check step.event == ufeNone

  # {.testKind: tkEdgeCase, covers: "initUdpForwardConfig".}
  test "a configuration that cannot bound memory is refused":
    ## Every one of these is a ceiling on memory a stranger can make this
    ## process spend, so a nonsensical value is an error rather than something
    ## quietly corrected into a different policy than the operator asked for.
    expect ValueError:
      discard initUdpForwardConfig(maxClients = 0)
    expect ValueError:
      discard initUdpForwardConfig(bufferDatagrams = -1)
    expect ValueError:
      discard initUdpForwardConfig(maxDatagramBytes = 0)
    ## Giving the NAS less time to answer than the gap between pokes would
    ## declare it away before it had a chance to reply to the first one.
    expect ValueError:
      discard initUdpForwardConfig(nasKeepaliveMs = 30_000'u64,
        nasSilentMs = 10_000'u64)
    expect ValueError:
      discard initUdpForwarder(ep("", 0'u16))
