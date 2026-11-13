## Group enrollment tests <- one enroller key, two lists, and a signed token.
##
##   predefined / operator-added / enroller-signed  ->  a member
##   a stranger, a wrong group, a forged proof      ->  refused
##
## Every decoder is fed truncated and over-sized bytes: it must answer ok=false
## and never raise.

import std/unittest

import ../../src/protocols/ame/types
import ../../src/protocols/ame/level3/handshake_identity
import ../../src/protocols/enrollment
import runePragmas

const
  nowUnix = 1_800_000_000'i64

proc enrollerKey(): AmeAuthorityKey {.role: helper.} =
  result = initAmeAuthorityKey("class-enroller")

proc member(name: string): AmeIdentityKey {.role: helper.} =
  result = initAmeIdentityKey(name)

proc rosterOf(e: AmeAuthorityKey, predefined: openArray[string] = []):
    GroupRoster {.role: helper.} =
  result = initGroupRoster(initAmeAuthorityRoot(e), predefined)

proc tokenFor(e: AmeAuthorityKey, group: string, m: AmeIdentityKey,
    serial: uint64 = 1'u64): GroupEnrollment {.role: helper.} =
  result = issueGroupEnrollment(e, group, m, serial, nowUnix - 60,
    nowUnix + 3600)

suite "group enrollment, the three ways in":
  # {.testKind: tkIntegration, covers: "groupMemberAllowed|initGroupRoster".}
  test "a predefined key is a member without any token":
    var
      e = enrollerKey()
      bob = member("bob")
      R = rosterOf(e, [ameIdentityKeyId(bob.signingKeys)])
    check groupMemberAllowed(R, "class-1", bob.signingKeys,
      GroupEnrollment(), nowUnix).ok

  # {.testKind: tkIntegration, covers: "groupMemberAllowed|addRosterKey".}
  test "an operator-added key is a member without any token":
    var
      e = enrollerKey()
      stranger = member("stranger")
      R = rosterOf(e)
    check not groupMemberAllowed(R, "class-1", stranger.signingKeys,
      GroupEnrollment(), nowUnix).ok
    check addRosterKey(R, ameIdentityKeyId(stranger.signingKeys)).ok
    check groupMemberAllowed(R, "class-1", stranger.signingKeys,
      GroupEnrollment(), nowUnix).ok

  # {.testKind: tkIntegration, covers: "issueGroupEnrollment|groupMemberAllowed".}
  test "an enroller-signed enrollment admits its key into its group":
    var
      e = enrollerKey()
      alice = member("alice")
      R = rosterOf(e)
      E = tokenFor(e, "class-1", alice)
    check groupMemberAllowed(R, "class-1", alice.signingKeys, E, nowUnix).ok

suite "group enrollment, refusals":
  # {.testKind: tkEdgeCase, covers: "groupMemberAllowed".}
  test "a stranger with no token and no list entry is refused":
    var
      e = enrollerKey()
      stranger = member("stranger")
      R = rosterOf(e)
      got = groupMemberAllowed(R, "class-1", stranger.signingKeys,
        GroupEnrollment(), nowUnix)
    check not got.ok
    check got.err.len > 0

  # {.testKind: tkEdgeCase, covers: "groupMemberAllowed".}
  test "a token for one group does not open another":
    var
      e = enrollerKey()
      alice = member("alice")
      R = rosterOf(e)
      E = tokenFor(e, "class-1", alice)
    check not groupMemberAllowed(R, "class-2", alice.signingKeys, E, nowUnix).ok

  # {.testKind: tkEdgeCase, covers: "groupMemberAllowed".}
  test "a token for one key does not admit a different key":
    var
      e = enrollerKey()
      alice = member("alice")
      mallory = member("mallory")
      R = rosterOf(e)
      E = tokenFor(e, "class-1", alice)
    check not groupMemberAllowed(R, "class-1", mallory.signingKeys, E,
      nowUnix).ok

  # {.testKind: tkEdgeCase, covers: "verifyGroupEnrollment".}
  test "an expired or not-yet-valid enrollment is refused":
    var
      e = enrollerKey()
      alice = member("alice")
      R = rosterOf(e)
      E = tokenFor(e, "class-1", alice)
    check not groupMemberAllowed(R, "class-1", alice.signingKeys, E,
      nowUnix + 7200).ok
    check not groupMemberAllowed(R, "class-1", alice.signingKeys, E,
      nowUnix - 7200).ok

  # {.testKind: tkRegression, covers: "verifyGroupEnrollment", pins: "a tampered proof must not admit a key".}
  test "a tampered proof is refused":
    var
      e = enrollerKey()
      alice = member("alice")
      R = rosterOf(e)
      E = tokenFor(e, "class-1", alice)
    E.proofs[0][0] = E.proofs[0][0] xor 0xff'u8
    check not groupMemberAllowed(R, "class-1", alice.signingKeys, E, nowUnix).ok

  # {.testKind: tkEdgeCase, covers: "verifyGroupEnrollment".}
  test "a different enroller root does not verify the token":
    var
      e = enrollerKey()
      other = enrollerKey()
      alice = member("alice")
      E = tokenFor(e, "class-1", alice)
      R = rosterOf(other)
    check not groupMemberAllowed(R, "class-1", alice.signingKeys, E, nowUnix).ok

  # {.testKind: tkRegression, covers: "verifyGroupEnrollment", pins: "dropping a hybrid slot must not verify on the classical half alone".}
  test "dropping one proof of a multi-slot enroller is refused":
    var
      e = enrollerKey()
      alice = member("alice")
      R = rosterOf(e)
      E = tokenFor(e, "class-1", alice)
    if E.proofs.len > 1:
      E.proofs.delete(E.proofs.len - 1)
      check not groupMemberAllowed(R, "class-1", alice.signingKeys, E,
        nowUnix).ok
    else:
      check true

suite "group enrollment, the roster lists":
  # {.testKind: tkEdgeCase, covers: "addRosterKey".}
  test "a key id of the wrong shape is refused":
    var
      R = rosterOf(enrollerKey())
    check not addRosterKey(R, "too-short").ok
    check not addRosterKey(R, "").ok

  # {.testKind: tkEdgeCase, covers: "addRosterKey".}
  test "a key already in the roster is not added twice":
    var
      e = enrollerKey()
      bob = member("bob")
      id = ameIdentityKeyId(bob.signingKeys)
      R = rosterOf(e, [id])
    check not addRosterKey(R, id).ok

  # {.testKind: tkUnit, covers: "removeRosterKey".}
  test "the operator can remove an added key, not a predefined one":
    var
      e = enrollerKey()
      bob = member("bob")
      id = ameIdentityKeyId(bob.signingKeys)
      R = rosterOf(e, [id])
      carol = member("carol")
      cid = ameIdentityKeyId(carol.signingKeys)
    check not removeRosterKey(R, id).ok
    check not addRosterKey(R, id).ok
    check addRosterKey(R, cid).ok
    check removeRosterKey(R, cid).ok
    check not rosterHasKey(R, cid)

suite "group enrollment, hostile bytes":
  # {.testKind: tkFuzz, covers: "decodeGroupEnrollment".}
  test "a truncated or over-sized token is refused, never raised":
    var
      e = enrollerKey()
      alice = member("alice")
      wire = encodeGroupEnrollment(tokenFor(e, "class-1", alice))
      i: int = 0
    while i < wire.len:
      check not decodeGroupEnrollment(wire.toOpenArray(0, i - 1)).ok
      i = i + 1
    check not decodeGroupEnrollment(@[]).ok
    check not decodeGroupEnrollment(@[0xff'u8]).ok

  # {.testKind: tkFuzz, covers: "decodeGroupRoster".}
  test "a truncated or over-sized roster is refused, never raised":
    var
      e = enrollerKey()
      bob = member("bob")
      R = rosterOf(e, [ameIdentityKeyId(bob.signingKeys)])
      wire = encodeGroupRoster(R)
      i: int = 0
    while i < wire.len:
      check not decodeGroupRoster(wire.toOpenArray(0, i - 1)).ok
      i = i + 1
    check not decodeGroupRoster(@[]).ok
    check not decodeGroupRoster(@[0xff'u8]).ok

  # {.testKind: tkRegression, covers: "decodeGroupEnrollment|decodeGroupRoster", pins: "a claimed length past the end must be refused".}
  test "a field that claims to reach past the end is refused":
    var
      e = enrollerKey()
      alice = member("alice")
      wire = encodeGroupEnrollment(tokenFor(e, "class-1", alice))
    ## version byte, then a group length of 0xFFFFFFFF with no bytes behind it
    check not decodeGroupEnrollment(@[enrollmentVersion, 0xff'u8, 0xff, 0xff,
      0xff]).ok
    check not decodeGroupRoster(@[enrollmentVersion, 0xff'u8, 0xff, 0xff,
      0xff]).ok
    check wire.len > 0

suite "group enrollment, the wire form":
  # {.testKind: tkUnit, covers: "encodeGroupEnrollment|decodeGroupEnrollment".}
  test "a token survives encode and decode":
    var
      e = enrollerKey()
      alice = member("alice")
      E = tokenFor(e, "class-1", alice)
      back = decodeGroupEnrollment(encodeGroupEnrollment(E))
    check back.ok
    check back.enrollment == E

  # {.testKind: tkUnit, covers: "encodeGroupRoster|decodeGroupRoster".}
  test "a roster survives encode and decode":
    var
      e = enrollerKey()
      bob = member("bob")
      R = rosterOf(e, [ameIdentityKeyId(bob.signingKeys)])
      carol = member("carol")
      back: tuple[ok: bool, roster: GroupRoster, err: string] = (false,
        GroupRoster(), "")
    check addRosterKey(R, ameIdentityKeyId(carol.signingKeys)).ok
    back = decodeGroupRoster(encodeGroupRoster(R))
    check back.ok
    check back.roster == R

  # {.testKind: tkRegression, covers: "decodeGroupEnrollment|verifyGroupEnrollment", pins: "a re-encoded token must still verify".}
  test "a decoded token still admits its key":
    var
      e = enrollerKey()
      alice = member("alice")
      R = rosterOf(e)
      E = tokenFor(e, "class-1", alice)
      back = decodeGroupEnrollment(encodeGroupEnrollment(E))
    check back.ok
    check groupMemberAllowed(R, "class-1", alice.signingKeys, back.enrollment,
      nowUnix).ok

  # {.testKind: tkUnit, covers: "encodeGroupEnroller|decodeGroupEnroller".}
  test "an enroller key survives encode and decode":
    var
      e = enrollerKey()
      back = decodeGroupEnroller(encodeGroupEnroller(e))
    check back.ok
    check back.enroller.name == e.name
    check back.enroller.signingKeys == e.signingKeys
    check back.enroller.secretKeys == e.secretKeys

  # {.testKind: tkFuzz, covers: "decodeGroupEnroller".}
  test "a truncated enroller key is refused, never raised":
    var
      e = enrollerKey()
      wire = encodeGroupEnroller(e)
      i: int = 0
    while i < wire.len:
      check not decodeGroupEnroller(wire.toOpenArray(0, i - 1)).ok
      i = i + 1
    check not decodeGroupEnroller(@[]).ok