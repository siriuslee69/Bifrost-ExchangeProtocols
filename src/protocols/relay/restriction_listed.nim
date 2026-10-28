## -------------------------------------------------------------------------
## Restriction, listed <- accept and reject lists of source addresses
## -------------------------------------------------------------------------
##
## Compiled only with the listed mode (see restriction_types.nim). Each
## recipient keeps two lists of addresses. The address is the one a frame
## ARRIVED FROM at this relay, which the relay knows before it opens anything.
## Reject wins over accept. An empty accept list accepts every address that
## is not rejected. Versatile, but a list to keep up to date for each device.

import runePragmas
import ./restriction_types

when restrictionListedBuilt:
  import ../transport/types as transport_types

  proc ruleMatches*(r: FilterRule, src: transport_types.UdpAddress): bool {.
      role: parser.} =
    ## r/src: a rule and the address a datagram arrived from. Port 0 matches
    ## any port, and the host "*" matches any host.
    result = (r.host == restrictionAnyHost or r.host == src.host) and
      (r.port == 0'u16 or r.port == src.port)

  proc listedAllows*(F: ListedFilter, src: transport_types.UdpAddress): bool {.
      role: parser.} =
    ## F/src: true when a frame from `src` may reach the recipient F belongs to.
    var
      i: int = 0
    while i < F.reject.len:
      if ruleMatches(F.reject[i], src):
        return false
      i = i + 1
    if F.accept.len == 0:
      return true
    i = 0
    while i < F.accept.len:
      if ruleMatches(F.accept[i], src):
        return true
      i = i + 1
    result = false

  proc findListed(B: RestrictionBook, identity: string): int {.role: parser.} =
    ## B/identity: the index of that recipient's lists, or -1.
    var
      i: int = 0
    while i < B.listed.len:
      if B.listed[i].identity == identity:
        return i
      i = i + 1
    result = -1

  proc listedAllowsTo*(B: RestrictionBook, dst: string,
      src: transport_types.UdpAddress): bool {.role: parser.} =
    ## An identity with no lists accepts everything.
    var
      i: int = findListed(B, dst)
    if i < 0:
      return true
    result = listedAllows(B.listed[i].filter, src)

  proc setListed*(B: var RestrictionBook, identity: string,
      F: ListedFilter) {.role: actor.} =
    ## B/identity/F: replace the lists of one recipient.
    var
      i: int = findListed(B, identity)
    if i < 0:
      B.listed.add ListedEntry(identity: identity, filter: F)
    else:
      B.listed[i].filter = F
