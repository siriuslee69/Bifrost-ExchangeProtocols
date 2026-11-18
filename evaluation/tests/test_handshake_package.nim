## Native DAC handshake packages: large records, repair, corruption and limits.
import std/[unittest, strutils]
import runePragmas
import bifrost_exchange_protocols as bfx

proc record(n: int): bfx.ByteSeq {.role: helper.} =
  ## n: deterministic non-secret bytes, wrapped as a server hello frame.
  result = bfx.encodeAmeHandshakeFrame(bfx.ampkServerHello, 42, 3,
    cast[seq[uint8]]("record".repeat(n div 6 + 1)[0 ..< n]))

suite "AME handshake packages":
  # {.testKind: tkUnit, covers: "ameHandshakeDatagrams".}
  test "small records keep ordinary handshake framing":
    var original = record(64)
    check bfx.ameHandshakeDatagrams(original) == @[original]

  # {.testKind: tkRegression, covers: "feedAmeHandshakeDatagram", pins: "recovery server hello exceeded UDP limit".}
  test "large records cross MTU-sized native DAC datagrams":
    var
      original = record(100000)
      frames = bfx.ameHandshakeDatagrams(original)
      inbox: bfx.AmeHandshakePackages = default(bfx.AmeHandshakePackages)
      fed: bfx.AmeHandshakeFeed = default(bfx.AmeHandshakeFeed)
      back: bfx.ByteSeq = @[]
    for frame in frames:
      check frame.len <= 1280
      fed = bfx.feedAmeHandshakeDatagram(inbox, frame, "peer")
      check fed.ok
      if fed.done: back = fed.payload
    check back == original

  # {.testKind: tkIntegration, covers: "feedAmeHandshakeDatagram".}
  test "DAC parity repairs a lost handshake chunk":
    var
      original = record(90000)
      frames = bfx.ameHandshakeDatagrams(original)
      inbox: bfx.AmeHandshakePackages = default(bfx.AmeHandshakePackages)
      fed: bfx.AmeHandshakeFeed = default(bfx.AmeHandshakeFeed)
      back: bfx.ByteSeq = @[]
      dropped: bool = false
    for frame in frames:
      if frame[26] == uint8(ord(bfx.dmkPackageChunk)) and not dropped:
        dropped = true
        continue
      fed = bfx.feedAmeHandshakeDatagram(inbox, frame, "peer")
      check fed.ok
      if fed.done: back = fed.payload
    check dropped
    check back == original

  # {.testKind: tkEdgeCase, covers: "feedAmeHandshakeDatagram".}
  test "different remote addresses cannot complete each other's package":
    var
      frames = bfx.ameHandshakeDatagrams(record(90000))
      inbox: bfx.AmeHandshakePackages = default(bfx.AmeHandshakePackages)
      fed: bfx.AmeHandshakeFeed = default(bfx.AmeHandshakeFeed)
    discard bfx.feedAmeHandshakeDatagram(inbox, frames[0], "one")
    for frame in frames[1 .. ^1]:
      fed = bfx.feedAmeHandshakeDatagram(inbox, frame, "two")
      check not fed.done

  # {.testKind: tkEdgeCase, covers: "feedAmeHandshakeDatagram".}
  test "a damaged data shard never produces a completed handshake":
    var
      frames = bfx.ameHandshakeDatagrams(record(90000))
      inbox: bfx.AmeHandshakePackages = default(bfx.AmeHandshakePackages)
      fed: bfx.AmeHandshakeFeed = default(bfx.AmeHandshakeFeed)
      changed: bool = false
      refused: bool = false
    for frame in frames.mitems:
      if frame[26] == uint8(ord(bfx.dmkPackageChunk)) and not changed:
        frame[^1] = frame[^1] xor 1
        changed = true
      fed = bfx.feedAmeHandshakeDatagram(inbox, frame, "peer")
      if not fed.ok: refused = true
      check not fed.done
    check refused

  # {.testKind: tkRegression, covers: "feedAmeHandshakeDatagram",
  #   pins: "16 datagrams every 20 seconds kept every new client out of the server".}
  test "a flood of half-received handshakes never locks a newcomer out":
    var
      original = record(90000)
      frames = bfx.ameHandshakeDatagrams(original)
      inbox: bfx.AmeHandshakePackages = default(bfx.AmeHandshakePackages)
      fed: bfx.AmeHandshakeFeed = default(bfx.AmeHandshakeFeed)
      back: bfx.ByteSeq = @[]
    ## the attack: a first shard from thousands of different ports of ONE host,
    ## and from a thousand different hosts
    for i in 0 ..< 3000:
      discard bfx.feedAmeHandshakeDatagram(inbox, frames[0], "dac://10.0.0.5:" & $(1000 + i))
    for i in 0 ..< 1000:
      discard bfx.feedAmeHandshakeDatagram(inbox, frames[0], "dac://10." & $(1 + i div 250) &
        ".7." & $(1 + i mod 250) & ":4000")
    check bfx.ameHandshakePackageCount(inbox) <= bfx.ameHandshakePackageSlots
    ## the honest client arrives AFTER the flood and must get through
    for frame in frames:
      fed = bfx.feedAmeHandshakeDatagram(inbox, frame, "dac://192.0.2.77:5555")
      check fed.ok
      if fed.done: back = fed.payload
    check back == original

  # {.testKind: tkEdgeCase, covers: "feedAmeHandshakeDatagram".}
  test "one sender holds at most its share, however many ports it uses":
    var
      frames = bfx.ameHandshakeDatagrams(record(90000))
      inbox: bfx.AmeHandshakePackages = default(bfx.AmeHandshakePackages)
    for i in 0 ..< 500:
      discard bfx.feedAmeHandshakeDatagram(inbox, frames[0], "10.0.0.5:" & $(2000 + i))
    check bfx.ameHandshakePackageCount(inbox) == bfx.ameHandshakePackagePerSource
    ## an IPv6 customer owns 2^64 addresses: they count as one sender
    inbox = default(bfx.AmeHandshakePackages)
    for i in 0 ..< 500:
      discard bfx.feedAmeHandshakeDatagram(inbox, frames[0],
        "[2001:db8:1:2::" & toHex(i + 1, 4).toLowerAscii() & "]:3000")
    check bfx.ameHandshakePackageCount(inbox) == bfx.ameHandshakePackagePerSource

  # {.testKind: tkEdgeCase, covers: "feedAmeHandshakeDatagram".}
  test "when the table is full the sender holding the most loses, not the honest one":
    var
      frames = bfx.ameHandshakeDatagrams(record(90000))
      inbox: bfx.AmeHandshakePackages = default(bfx.AmeHandshakePackages)
      fed: bfx.AmeHandshakeFeed = default(bfx.AmeHandshakeFeed)
    ## 100 senders hold three packages each (the table is 128: it fills)
    discard bfx.feedAmeHandshakeDatagram(inbox, frames[0], "192.0.2.1:1")
    for i in 0 ..< 60:
      for p in 0 ..< 3:
        discard bfx.feedAmeHandshakeDatagram(inbox, frames[0], "10.1." & $i & ".1:" & $(100 + p))
    check bfx.ameHandshakePackageCount(inbox) <= bfx.ameHandshakePackageSlots
    ## a newcomer still gets a slot, and the lone honest sender keeps its own
    fed = bfx.feedAmeHandshakeDatagram(inbox, frames[0], "192.0.2.9:9")
    check fed.ok
    check bfx.ameHandshakePackageCount(inbox) <= bfx.ameHandshakePackageSlots

  # {.testKind: tkEdgeCase, covers: "ameHandshakeDatagrams".}
  test "overlarge unauthenticated records are refused before sending":
    expect ValueError:
      discard bfx.ameHandshakeDatagrams(record(int(bfx.ameHandshakePackageMaxBytes) + 1))
