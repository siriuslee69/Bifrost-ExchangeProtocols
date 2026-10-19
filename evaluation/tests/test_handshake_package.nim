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

  # {.testKind: tkEdgeCase, covers: "feedAmeHandshakeDatagram".}
  test "unauthenticated package slots are bounded":
    var
      frames = bfx.ameHandshakeDatagrams(record(90000))
      inbox: bfx.AmeHandshakePackages = default(bfx.AmeHandshakePackages)
      fed: bfx.AmeHandshakeFeed = default(bfx.AmeHandshakeFeed)
    for i in 0 ..< bfx.ameHandshakePackageSlots:
      fed = bfx.feedAmeHandshakeDatagram(inbox, frames[0], $i)
      check fed.ok
    fed = bfx.feedAmeHandshakeDatagram(inbox, frames[0], "overflow")
    check not fed.ok

  # {.testKind: tkEdgeCase, covers: "ameHandshakeDatagrams".}
  test "overlarge unauthenticated records are refused before sending":
    expect ValueError:
      discard bfx.ameHandshakeDatagrams(record(int(bfx.ameHandshakePackageMaxBytes) + 1))
