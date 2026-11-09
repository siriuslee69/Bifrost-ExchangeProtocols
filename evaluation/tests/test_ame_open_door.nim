## Open door tests <- a server takes a key it has never seen, and says whose.
##
##   the client still pins the server
##   the server accepts any client that proves it holds its own keys
##   the handshake reports the key id, whatever name the client chose

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/path_triggers
import ../../src/protocols/ame/level3/handshake
import ../../src/protocols/ame/level3/handshake_wire
import runePragmas

const
  doorKems: AmeKemAlgorithms = [akaX25519, akaMlKem768]
  nowUnix = 1_800_000_000'i64

type
  Done {.role: truthState.} = object
    accepted: AmeHandshakeResult
    client: AmeHandshakeResult

proc descriptorOf(i: AmeIdentityKey): AmeIdentityCertificate {.role: helper.} =
  ## i: a direct identity valid around the test's clock.
  result = pinnedIdentityDescriptor(i, nowUnix - 60, nowUnix + 3600)

proc idOf(name: string): AmeIdentityKey {.role: helper.} =
  ## name: an identity with every signature slot of the test's layout.
  result = initAmeIdentityKey(name, defaultAmeLayout(doorKems).signatures)

proc openDoor(client, server: AmeIdentityKey,
    doorSide: AmeAuthentication): Done {.role: orchestrator.} =
  ## client/server: the two identities. doorSide: what the server demands.
  var
    L: AmeSuiteLayout = defaultAmeLayout(doorKems)
    t: AmeMaskTier = fullAmeMaskTier(L)
    a: AmeAuthentication = initAmePinnedAuthentication(pinnedPeerIdentity(server))
    c: AmeClientHandshake = beginAmeHandshake(31'u64, L, t, a = a)
    answered: tuple[ok: bool, state: AmeServerHandshake, err: string] = (
      ok: false, state: default(AmeServerHandshake), err: "")
  answered = answerAmeHandshake(decodeAmeClientHello(encodeAmeClientHello(
    c.hello)), [initAmeTierPath(L, [t])], doorSide, descriptorOf(server), server)
  doAssert answered.ok, answered.err
  result.client = finishAmeHandshake(c, decodeAmeServerHello(L,
    encodeAmeServerHello(answered.state.serverHello)), a,
    descriptorOf(client), client, nowUnix)
  doAssert result.client.ok, result.client.err
  result.accepted = acceptAmeHandshake(answered.state, decodeAmeClientFinish(
    encodeAmeClientFinish(result.client.finish)), nowUnix)

suite "open door":
  # {.testKind: tkIntegration, covers: "initAmeOpenDoorAuthentication|verifyUnknownPeerIdentity".}
  test "a key the server never saw gets in, and is named by its keys":
    var
      stranger = idOf("whatever-name")
      server = idOf("server")
      d = openDoor(stranger, server, initAmeOpenDoorAuthentication())
    check d.accepted.ok
    check d.accepted.peerTrust.authority == "open-door"
    check d.accepted.peerTrust.subjectKeyId == ameIdentityKeyId(stranger.signingKeys)
    check d.accepted.peerTrust.peerKeys == stranger.signingKeys

  # {.testKind: tkEdgeCase, covers: "ameIdentityKeyId".}
  test "the name a stranger chooses does not change who it is":
    var
      a = idOf("alice")
      renamed = a
      server = idOf("server")
    renamed.subject = "bob"
    check openDoor(a, server, initAmeOpenDoorAuthentication()
      ).accepted.peerTrust.subjectKeyId ==
      openDoor(renamed, server, initAmeOpenDoorAuthentication()
      ).accepted.peerTrust.subjectKeyId

  # {.testKind: tkEdgeCase, covers: "verifyUnknownPeerIdentity".}
  test "claiming someone else's keys without their secret is refused":
    var
      victim = idOf("victim")
      thief = idOf("thief")
      server = idOf("server")
      forged = thief
    forged.signingKeys = victim.signingKeys
    check not openDoor(forged, server, initAmeOpenDoorAuthentication()).accepted.ok

  # {.testKind: tkRegression, covers: "initAmePinnedAuthentication".}
  test "a pinned server still refuses a stranger":
    var
      stranger = idOf("stranger")
      friend = idOf("friend")
      server = idOf("server")
    check not openDoor(stranger, server, initAmePinnedAuthentication(
      pinnedPeerIdentity(friend))).accepted.ok
    check openDoor(friend, server, initAmePinnedAuthentication(
      pinnedPeerIdentity(friend))).accepted.ok
