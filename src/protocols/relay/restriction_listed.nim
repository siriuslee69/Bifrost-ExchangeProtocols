## -------------------------------------------------------------------------
## Restriction, listed <- accept and reject lists of source addresses
## -------------------------------------------------------------------------
##
## Compiled only with the listed mode (see restriction_types.nim). Each
## connection keeps two lists of addresses. The address is the one a frame
## ARRIVED FROM at this relay, converted once when the neighbour joined.
##
##   reject list   checked first    a match refuses the frame
##   accept list   checked second   empty accepts everything not rejected;
##                                  otherwise a match is needed
##
## Reject wins over accept. Versatile, but a list to keep up to date for
## each connection.

import runePragmas
import ./restriction_types
import ./restriction_address

when restrictionListedBuilt:
  proc listedAllows*(F: SourceRules, src: SourceAddr): bool {.role: parser.} =
    ## F/src: true when a frame from `src` may reach the connection F belongs to.
    var
      i: int = 0
    while i < F.reject.len:
      if sourceMatches(F.reject[i], src):
        return false
      i = i + 1
    if F.accept.len == 0:
      return true
    i = 0
    while i < F.accept.len:
      if sourceMatches(F.accept[i], src):
        return true
      i = i + 1
    result = false

  proc setListed*(B: var RestrictionBook, identity: string,
      accept, reject: seq[SourceAddr]): string {.role: actor.} =
    ## B/identity/accept/reject: replace the two lists of one connection.
    ## "" when applied, else why not.
    var
      i: int = 0
    if accept.len > restrictionMaxRules or reject.len > restrictionMaxRules:
      return "a list holds at most " & $restrictionMaxRules & " addresses"
    i = ensureReach(B, identity)
    B.reach[i].rules.accept = accept
    B.reach[i].rules.reject = reject
    result = ""
