## -------------------------------------------------------------------------
## Replay and failed frames <- a datagram that is not accepted changes nothing
## -------------------------------------------------------------------------
##
## Three real advisories of 2026 (WireGuard in Zephyr, Noise in Go) share one shape: a
## stranger's datagram changed the receiver's state BEFORE it was proven genuine.
##
##   advisory                                        question asked of this code
##   ----------------------------------------------  ---------------------------------------
##   replay checked after the endpoint was moved     (1) does a replayed frame change state?
##   counter advanced on a FAILED decrypt            (3) does a frame that fails to open
##                                                       leave every counter where it was?
##   a list in a hello costing one key operation     (4) is a hello's list capped before
##     per entry                                         any key work, and by what number?
##
## (2) the forwarder's NAS address and (5) an unsigned handshake are answered in the
## README playbook, "Replay and counters", with the code and test that show it.

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/derivation
import ../../src/protocols/ame/level1/secret_stack
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/padding
import ../../src/protocols/ame/level1/compression
import ../../src/protocols/ame/level1/header_protection
import ../../src/protocols/ame/level2/framing
import ../../src/protocols/ame/level2/wire
import runePragmas

const
  kems: AmeKemAlgorithms = [akaX25519, akaFireSaber]

proc layoutOf(): AmeSuiteLayout {.role: configurator.} =
  result = defaultAmeLayout(kems)

proc tierOf(L: AmeSuiteLayout): AmeMaskTier {.role: configurator.} =
  result = initAmeMaskTier(L, 1'u32, initAmeTierMasks(0b11000000'u8,
    occupiedAmeMask(L.ciphers.length), occupiedAmeMask(L.macs.length),
    occupiedAmeMask(L.hashes.length), occupiedAmeMask(L.signatures.length),
    occupiedAmeMask(L.kdfs.length)))

proc session(role: AmeEndpointRole): AmeSession {.role: configurator.} =
  ## one end of a session; the two roles with the same seed are one session
  var
    L: AmeSuiteLayout = layoutOf()
    t: AmeMaskTier = tierOf(L)
    state: AmeExchangeState = initAmeExchangeState(kems)
  applyAmeExchange(state, defaultAmeLayout(kems), initAmeExchangeRequest(kems, t,
    0b11000000'u8), [@[7'u8, 2'u8, 3'u8, 4'u8], @[7'u8, 6'u8, 7'u8, 8'u8]])
  result = initAmeSession(initAmeAuthPackage(L, t, state, endpointRole = role,
    params = AmeRuntimeParams(authTagLen: aatl32)), peerTrustRequired = false)

proc payload(i: int): ByteSeq {.role: helper.} =
  result = newSeq[byte](40)
  for k in 0 ..< result.len:
    result[k] = byte((i * 17 + k) mod 251)

proc takes(S: var AmeSession, frame: openArray[uint8]): bool {.role: actor.} =
  ## true when the frame was accepted. A malformed header raises out of the
  ## decoder and a bad tag comes back as ok = false: both are a refusal.
  try:
    result = openAmeTcpFrame(S, @frame).ok
  except CatchableError:
    result = false

suite "a frame that is not accepted changes nothing":
  # {.testKind: tkRegression, covers: "openAmeTcpFrame",
  #   pins: "advisories where a replayed or failed packet moved the receiver's state".}
  test "(1) a replayed frame, fifty times, leaves the receiver as it was; the next frames open":
    var
      sender: AmeSession = session(aerInitiator)
      receiver: AmeSession = session(aerResponder)
      f1: ByteSeq = sealAmeTcpFrame(sender, payload(1))
      f2: ByteSeq = sealAmeTcpFrame(sender, payload(2))
      f3: ByteSeq = sealAmeTcpFrame(sender, payload(3))
      before: AmeSession = AmeSession()
      o: AmeOpenResult = AmeOpenResult()
    check openAmeTcpFrame(receiver, f1).ok
    before = receiver
    for i in 0 ..< 50:
      check not receiver.takes(f1)
    receiver.lastErr = before.lastErr
    check receiver == before
    o = openAmeTcpFrame(receiver, f2)
    check o.ok and o.packet.payload == payload(2)
    o = openAmeTcpFrame(receiver, f3)
    check o.ok and o.packet.payload == payload(3)

  # {.testKind: tkFuzz, covers: "openAmeTcpFrame".}
  test "(3) every single-byte corruption of the next frame is refused, and none moves a counter":
    var
      sender: AmeSession = session(aerInitiator)
      receiver: AmeSession = session(aerResponder)
      f1: ByteSeq = sealAmeTcpFrame(sender, payload(1))
      f2: ByteSeq = sealAmeTcpFrame(sender, payload(2))
      bad: ByteSeq = @[]
      before: AmeSession = AmeSession()
      o: AmeOpenResult = AmeOpenResult()
      accepted: int = 0
    check openAmeTcpFrame(receiver, f1).ok
    before = receiver
    for pos in 0 ..< f2.len:
      for mask in [0x01'u8, 0x80'u8, 0xFF'u8]:
        bad = f2
        bad[pos] = bad[pos] xor mask
        if receiver.takes(bad):
          accepted = accepted + 1
    receiver.lastErr = before.lastErr
    check accepted == 0
    check receiver == before
    o = openAmeTcpFrame(receiver, f2)
    check o.ok and o.packet.payload == payload(2)

  # {.testKind: tkEdgeCase, covers: "openAmeTcpFrame".}
  test "(3) a frame cut short, a frame with a tail, and the sender's own frame fed back: refused, state unchanged":
    var
      sender: AmeSession = session(aerInitiator)
      receiver: AmeSession = session(aerResponder)
      f1: ByteSeq = sealAmeTcpFrame(sender, payload(1))
      before: AmeSession = receiver
    for cut in 0 ..< f1.len:
      check not receiver.takes(f1[0 ..< cut])
    check not receiver.takes(f1 & @[byte 0, 1, 2])
    check not sender.takes(f1)         ## reflected to its own sender
    receiver.lastErr = before.lastErr
    check receiver == before
    check openAmeTcpFrame(receiver, f1).ok

suite "a hello's lists are capped by a number":
  # {.testKind: tkFuzz, covers: "decodeAmeSuiteLayout",
  #   pins: "age: one key operation per list entry, 4 000 entries = 15.7 s".}
  test "(4) no byte of a suite layout can make the decoder take more than 8 per family, or crash":
    var
      good: ByteSeq = encodeAmeSuiteLayout(layoutOf())
      bad: ByteSeq = @[]
      refused: int = 0
      same: int = 0
      d: AmeSuiteLayout = AmeSuiteLayout()
    check ameMaxAlgorithmSlots == 8
    for pos in 0 ..< good.len:
      for v in 0 .. 255:
        bad = good
        bad[pos] = byte(v)
        try:
          d = decodeAmeSuiteLayout(bad)
          same = same + 1
          check d.kems.length <= ameMaxAlgorithmSlots
          check d.ciphers.length <= ameMaxAlgorithmSlots
          check d.macs.length <= ameMaxAlgorithmSlots
          check d.hashes.length <= ameMaxAlgorithmSlots
          check d.signatures.length <= ameMaxAlgorithmSlots
          check d.kdfs.length <= ameMaxAlgorithmSlots
        except ValueError:
          refused = refused + 1
    check refused > 0
    check same > 0
