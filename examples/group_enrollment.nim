## -------------------------------------------------------------------------
## Group enrollment <- one enroller key lets other public keys into a group
## -------------------------------------------------------------------------
##
## Run from the repo root:
##   nim c -r examples/group_enrollment.nim
##
##   predefined list ─────────────┐
##   operator-added key ──────────┼──▶ a key is a member of the group
##   enroller-signed enrollment ──┘
##
## The enroller is one AME authority key. It signs an admission for a member's
## public key; the member is named by its keys (ameIdentityKeyId), not by any
## name it chose. The roster also admits a predefined list and keys the operator
## adds by hand. Nothing here touches a disk.

import ../src/protocols/ame/level3/handshake_identity
import ../src/protocols/enrollment

var
  enroller = initAmeAuthorityKey("class-enroller")
  alice = initAmeIdentityKey("alice")
  bob = initAmeIdentityKey("bob")
  stranger = initAmeIdentityKey("stranger")
  nowUnix = 1_800_000_000'i64
  ## bob is predefined; the enroller's public half is pinned in the roster
  roster = initGroupRoster(initAmeAuthorityRoot(enroller),
    [ameIdentityKeyId(bob.signingKeys)])
  ## the enroller admits alice into "class-1" for one hour
  aliceEnroll = issueGroupEnrollment(enroller, "class-1", alice, 1'u64,
    nowUnix - 60, nowUnix + 3600)
  noToken = GroupEnrollment()

# bob is in the predefined list: a member without any token
echo "bob predefined:      ",
  groupMemberAllowed(roster, "class-1", bob.signingKeys, noToken, nowUnix).ok

# alice holds a valid enroller-signed enrollment: a member
echo "alice enrolled:      ",
  groupMemberAllowed(roster, "class-1", alice.signingKeys, aliceEnroll, nowUnix).ok

# a stranger with no token and no list entry is refused
echo "stranger refused:    ",
  not groupMemberAllowed(roster, "class-1", stranger.signingKeys, noToken,
    nowUnix).ok

# alice's token does not open a DIFFERENT group
echo "wrong group refused: ",
  not groupMemberAllowed(roster, "class-2", alice.signingKeys, aliceEnroll,
    nowUnix).ok

# the operator adds the stranger's public key by hand: now a member
discard addRosterKey(roster, ameIdentityKeyId(stranger.signingKeys))
echo "operator added:      ",
  groupMemberAllowed(roster, "class-1", stranger.signingKeys, noToken, nowUnix).ok

# the enrollment and the roster both survive a trip through bytes
var
  wire = encodeGroupEnrollment(aliceEnroll)
  back = decodeGroupEnrollment(wire)
  rosterWire = encodeGroupRoster(roster)
  rosterBack = decodeGroupRoster(rosterWire)
echo "token round-trip:    ", back.ok and back.enrollment == aliceEnroll
echo "roster round-trip:   ", rosterBack.ok and rosterBack.roster == roster