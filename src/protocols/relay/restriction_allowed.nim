## -------------------------------------------------------------------------
## Restriction, allowed <- each connection names who may reach IT
## -------------------------------------------------------------------------
##
## Compiled only with the allowed mode (see restriction_types.nim). Each
## connection keeps ONE list of addresses: the senders allowed to reach it.
##
##   allowed list     who may send TO this connection
##   empty list       nobody may reach it (the default for a new connection)
##   outbound         unrestricted: a connection with an empty list can still
##                    send to any other connection that allows it
##
## Def. 1: a frame from S to D passes when S's address is in D's allowed list.
## The list names senders, never receivers, so changing it never touches
## anyone else's list.

import runePragmas
import ./restriction_types
import ./restriction_address

when restrictionAllowedBuilt:
  proc allowedAllows*(F: SourceRules, src: SourceAddr): bool {.role: parser.} =
    ## F/src: true when the connection's allowed list names the sender.
    ## An empty list names nobody, so it refuses everything.
    var
      i: int = 0
    while i < F.allowed.len:
      if sourceMatches(F.allowed[i], src):
        return true
      i = i + 1
    result = false

  proc setAllowed*(B: var RestrictionBook, identity: string,
      allowed: seq[SourceAddr]): string {.role: actor.} =
    ## B/identity/allowed: replace who may reach that connection.
    ## "" when applied, else why not.
    var
      i: int = 0
    if allowed.len > restrictionMaxRules:
      return "an allowed list holds at most " & $restrictionMaxRules & " addresses"
    i = ensureReach(B, identity)
    B.reach[i].rules.allowed = allowed
    result = ""
