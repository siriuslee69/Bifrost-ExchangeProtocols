## -------------------------------------------------------------------------
## Restriction, profile <- a predefined target set chosen by enum
## -------------------------------------------------------------------------
##
## Compiled only with the profile mode (see restriction_types.nim). The
## operator fixes a table of target sets at start-up. Each device carries one
## small index into that table on its connection, and may reach exactly the
## identities in the set it names. Profile 0 is the empty set, so a device that
## chose nothing reaches nobody. Moving a device to another set is one byte, which
## suits targets that change often.

import runePragmas
import ./restriction_types

when restrictionProfileBuilt:
  proc profileOfDevice(B: RestrictionBook, identity: string): int {.
      role: parser.} =
    ## The profile index that device chose, 0 when it chose none.
    var
      i: int = 0
    while i < B.profileOf.len:
      if B.profileOf[i].identity == identity:
        return int(B.profileOf[i].profile)
      i = i + 1
    result = 0

  proc profileAllows*(B: RestrictionBook, src, dst: string): bool {.
      role: parser.} =
    ## true when the profile src chose names dst.
    var
      p: int = profileOfDevice(B, src)
      i: int = 0
    if p <= 0 or p >= B.profiles.len:
      return false
    while i < B.profiles[p].len:
      if B.profiles[p][i] == dst:
        return true
      i = i + 1
    result = false

  proc setProfile*(B: var RestrictionBook, identity: string,
      profile: uint8): string {.role: actor.} =
    ## B/identity/profile: the profile a device chose. "" when applied, else
    ## why not: the operator defined no such profile.
    var
      i: int = 0
    if int(profile) >= B.profiles.len:
      return "no profile " & $profile & " is defined on this relay"
    while i < B.profileOf.len:
      if B.profileOf[i].identity == identity:
        B.profileOf[i].profile = profile
        return ""
      i = i + 1
    B.profileOf.add ProfileEntry(identity: identity, profile: profile)
