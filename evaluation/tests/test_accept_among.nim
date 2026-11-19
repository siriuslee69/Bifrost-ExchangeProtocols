## Accept among many <- a server holds several pins and does not know which peer calls.
##
##   the finish is opened ONCE
##   every pin is judged, none is skipped (so the time does not tell the place)
##   the pin that fits is named by its place in the list; a stranger gets -1
##
##   five trusted peers, one finish:
##
##     pins   [ p0  p1  p2  p3  p4 ]
##     caller          p2
##     answer     at = 2

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/path_triggers
import ../../src/protocols/ame/level3/handshake
import ../../src/protocols/ame/level3/handshake_wire
import runePragmas

const
  amongKems: AmeKemAlgorithms = [akaX25519, akaMlKem768]
  nowUnix = 1_800_000_000'i64
  peerCount = 5

type
  Held {.role: truthState.} = object
    ## The server's half-finished handshake and the client's finish for it.
    server: AmeServerHandshake
    finish: AmeClientFinish
    ok: bool

proc descriptorOf(i: AmeIdentityKey): AmeIdentityCertificate {.role: helper.} =
  ## i: a direct identity valid around the test's clock.
  result = pinnedIdentityDescriptor(i, nowUnix - 60, nowUnix + 3600)

proc idOf(name: string): AmeIdentityKey {.role: helper.} =
  ## name: an identity with every signature slot of the test's layout.
  result = initAmeIdentityKey(name, defaultAmeLayout(amongKems).signatures)

proc pinsOf(P: openArray[AmeIdentityKey]): seq[AmeAuthentication] {.role: helper.} =
  ## P: one pinned authentication per identity, in the same order.
  for p in P:
    result.add(initAmePinnedAuthentication(pinnedPeerIdentity(p)))

proc hold(client, server: AmeIdentityKey, standIn: AmeAuthentication): Held {.
    role: orchestrator.} =
  ## client/server/standIn: run the handshake up to the client's finish. The
  ## server answers with `standIn`, as Nebel does with the first pin.
  var
    L: AmeSuiteLayout = defaultAmeLayout(amongKems)
    t: AmeMaskTier = fullAmeMaskTier(L)
    a: AmeAuthentication = initAmePinnedAuthentication(pinnedPeerIdentity(server))
    c: AmeClientHandshake = beginAmeHandshake(47'u64, L, t, a = a)
    answered: tuple[ok: bool, state: AmeServerHandshake, err: string] = (
      ok: false, state: default(AmeServerHandshake), err: "")
    done: AmeHandshakeResult = default(AmeHandshakeResult)
  answered = answerAmeHandshake(decodeAmeClientHello(encodeAmeClientHello(
    c.hello)), [initAmeTierPath(L, [t])], standIn, descriptorOf(server), server)
  doAssert answered.ok, answered.err
  done = finishAmeHandshake(c, decodeAmeServerHello(L,
    encodeAmeServerHello(answered.state.serverHello)), a,
    descriptorOf(client), client, nowUnix)
  doAssert done.ok, done.err
  result.server = answered.state
  result.finish = decodeAmeClientFinish(encodeAmeClientFinish(done.finish))
  result.ok = true

suite "accept among many pins":
  var
    server: AmeIdentityKey = idOf("server")
    peers: seq[AmeIdentityKey] = @[]
    pins: seq[AmeAuthentication] = @[]
  for i in 0 ..< peerCount:
    peers.add(idOf("peer" & $i))
  pins = pinsOf(peers)

  # {.testKind: tkIntegration, covers: "acceptAmeHandshakeAmong".}
  test "every place of the list is found, first, middle and last":
    for who in [0, 2, peerCount - 1]:
      var
        h: Held = hold(peers[who], server, pins[0])
        r: tuple[at: int, res: AmeHandshakeResult] = acceptAmeHandshakeAmong(
          h.server, h.finish, pins, nowUnix)
      check r.res.ok
      check r.at == who
      check r.res.peerTrust.subjectKeyId == peers[who].subject

  # {.testKind: tkIntegration, covers: "acceptAmeHandshakeAmong|acceptAmeHandshake".}
  test "the answer is the same session as the one-pin call gives":
    var
      h1: Held = hold(peers[3], server, pins[3])
      h2: Held = hold(peers[3], server, pins[0])
      one: AmeHandshakeResult = acceptAmeHandshake(h1.server, h1.finish, nowUnix)
      many: tuple[at: int, res: AmeHandshakeResult] = acceptAmeHandshakeAmong(
        h2.server, h2.finish, pins, nowUnix)
    check one.ok and many.res.ok
    check one.peerTrust.subjectKeyId == many.res.peerTrust.subjectKeyId
    check one.peerTrust.authority == many.res.peerTrust.authority

  # {.testKind: tkEdgeCase, covers: "acceptAmeHandshakeAmong".}
  test "a stranger matches nobody":
    var
      stranger: AmeIdentityKey = idOf("stranger")
      h: Held = hold(stranger, server, pins[0])
      r: tuple[at: int, res: AmeHandshakeResult] = acceptAmeHandshakeAmong(
        h.server, h.finish, pins, nowUnix)
    check not r.res.ok
    check r.at == -1
    check r.res.err.len > 0

  # {.testKind: tkEdgeCase, covers: "acceptAmeHandshakeAmong".}
  test "an empty list and a one-entry list":
    var
      h0: Held = hold(peers[1], server, pins[0])
      h1: Held = hold(peers[1], server, pins[0])
      r0: tuple[at: int, res: AmeHandshakeResult] = acceptAmeHandshakeAmong(
        h0.server, h0.finish, newSeq[AmeAuthentication](), nowUnix)
      r1: tuple[at: int, res: AmeHandshakeResult] = acceptAmeHandshakeAmong(
        h1.server, h1.finish, @[pins[1]], nowUnix)
    check r0.at == -1 and not r0.res.ok
    check r1.at == 0 and r1.res.ok

  # {.testKind: tkEdgeCase, covers: "acceptAmeHandshakeAmong".}
  test "a pin of the right peer placed twice still names the first":
    var
      h: Held = hold(peers[2], server, pins[0])
      r: tuple[at: int, res: AmeHandshakeResult] = acceptAmeHandshakeAmong(
        h.server, h.finish, @[pins[1], pins[2], pins[2]], nowUnix)
    check r.at == 1 and r.res.ok

  # {.testKind: tkEdgeCase, covers: "acceptAmeHandshakeAmong|finishFitsSchedule".}
  test "a candidate of another mode cannot be judged from this opening":
    var
      h: Held = hold(peers[0], server, pins[0])
      other: AmeAuthentication = initAmePskPinnedAuthentication("shared",
        newSeq[uint8](32), pinnedPeerIdentity(peers[0]))
      r: tuple[at: int, res: AmeHandshakeResult] = acceptAmeHandshakeAmong(
        h.server, h.finish, @[other], nowUnix)
    check r.at == -1 and not r.res.ok

  # {.testKind: tkIntegration, covers: "acceptAmeHandshakeAmong".}
  test "the open door is the last candidate: a friend stays a friend, a stranger gets in":
    var
      stranger: AmeIdentityKey = idOf("stranger")
      cands: seq[AmeAuthentication] = pins & @[initAmeOpenDoorAuthentication()]
      hf: Held = hold(peers[3], server, pins[0])
      hs: Held = hold(stranger, server, pins[0])
      rf: tuple[at: int, res: AmeHandshakeResult] = acceptAmeHandshakeAmong(
        hf.server, hf.finish, cands, nowUnix)
      rs: tuple[at: int, res: AmeHandshakeResult] = acceptAmeHandshakeAmong(
        hs.server, hs.finish, cands, nowUnix)
    check rf.at == 3 and rf.res.peerTrust.authority != "open-door"
    check rs.at == peerCount and rs.res.peerTrust.authority == "open-door"

  # {.testKind: tkEdgeCase, covers: "acceptAmeHandshakeAmong".}
  test "a damaged finish is refused for every candidate":
    var
      h: Held = hold(peers[4], server, pins[0])
      r: tuple[at: int, res: AmeHandshakeResult] = (-1, default(AmeHandshakeResult))
    h.finish.sealed[h.finish.sealed.len div 2] = h.finish.sealed[h.finish.sealed.len div 2] xor 1'u8
    r = acceptAmeHandshakeAmong(h.server, h.finish, pins, nowUnix)
    check r.at == -1 and not r.res.ok
