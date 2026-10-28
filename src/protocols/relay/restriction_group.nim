## -------------------------------------------------------------------------
## Restriction, group <- one sequence of (member, server) pairs
## -------------------------------------------------------------------------
##
## Compiled only with the group mode (see restriction_types.nim). A device
## listed as a member may talk only to its server, and the server only to
## its members. Clients behind one server therefore never reach each other.
## One entry per member: memory is one short record per device.

import runePragmas
import ./restriction_types

when restrictionGroupBuilt:
  proc groupAllows*(B: RestrictionBook, src, dst: string): bool {.
      role: parser.} =
    ## Def. 1: true when one entry names the two as (member, server) in
    ## either order. The sequence is scanned once.
    var
      i: int = 0
    while i < B.groups.len:
      if (B.groups[i].member == src and B.groups[i].server == dst) or
          (B.groups[i].member == dst and B.groups[i].server == src):
        return true
      i = i + 1
    result = false

  proc setGroup*(B: var RestrictionBook, server: string,
      members: seq[string]): string {.role: actor.} =
    ## B/server/members: the server replaces ITS entries with exactly these.
    ## Returns "" when applied, else why nothing changed. Refused when a
    ## member already belongs to another server, or the server names itself.
    var
      kept: seq[GroupEntry] = @[]
      i: int = 0
      j: int = 0
      owned: bool = false
    for m in members:
      if m == server:
        return "a server names itself as a member"
    while i < B.groups.len:
      if B.groups[i].server != server:
        j = 0
        owned = false
        while j < members.len:
          if members[j] == B.groups[i].member:
            owned = true
          j = j + 1
        if owned:
          return "member " & B.groups[i].member &
            " already belongs to another server"
        kept.add B.groups[i]
      i = i + 1
    for m in members:
      kept.add GroupEntry(member: m, server: server)
    B.groups = kept
