## -------------------------------------------------------------------------
## Restriction, group <- one object: members, endpoints, and the links between
## -------------------------------------------------------------------------
##
## Compiled only with the group mode (see restriction_types.nim).
##
##   members   every device claimed by some endpoint      [alice, bob, carol]
##   endpoints every server that claimed devices           [server-a, server-b]
##   links     (member, endpoint) index pairs, both ways   (0,0) (1,0) (2,1)
##
## A member talks to an endpoint only over a link, and never to another
## member. Clients behind one server therefore cannot reach each other.
##
## One device may belong to one endpoint only: a claim that names a member
## already linked to another endpoint is refused, so a device cannot be
## spread across two servers by its own choice.

import runePragmas
import ./restriction_types

when restrictionGroupBuilt:
  proc memberIndex(G: GroupBook, identity: string): int {.role: parser.} =
    ## G/identity: the index of that member, or -1.
    var
      i: int = 0
    while i < G.members.len:
      if G.members[i] == identity:
        return i
      i = i + 1
    result = -1

  proc endpointIndex(G: GroupBook, identity: string): int {.role: parser.} =
    ## G/identity: the index of that endpoint, or -1.
    var
      i: int = 0
    while i < G.endpoints.len:
      if G.endpoints[i] == identity:
        return i
      i = i + 1
    result = -1

  proc groupAllows*(G: GroupBook, src, dst: string): bool {.role: parser.} =
    ## G/src/dst: true when one link names the two, member and endpoint, in
    ## either order. The links are scanned once.
    var
      i: int = 0
      m: int = 0
      e: int = 0
    while i < G.links.len:
      m = int(G.links[i].member)
      e = int(G.links[i].endpoint)
      if (G.members[m] == src and G.endpoints[e] == dst) or
          (G.members[m] == dst and G.endpoints[e] == src):
        return true
      i = i + 1
    result = false

  proc linkPair(G: var GroupBook, member, endpoint: string): string {.role: actor.} =
    ## G/member/endpoint: add the pair, adding either name when it is new.
    ## "" when added, else why not (the book is full).
    var
      m: int = memberIndex(G, member)
      e: int = endpointIndex(G, endpoint)
    if m < 0:
      if G.members.len >= restrictionMaxEntries:
        return "the group holds at most " & $restrictionMaxEntries & " members"
      G.members.add member
      m = G.members.len - 1
    if e < 0:
      if G.endpoints.len >= restrictionMaxEntries:
        return "the group holds at most " & $restrictionMaxEntries & " endpoints"
      G.endpoints.add endpoint
      e = G.endpoints.len - 1
    G.links.add GroupLink(member: uint16(m), endpoint: uint16(e))

  proc endpointOf(G: GroupBook, link: GroupLink): string {.role: parser.} =
    ## G/link: the endpoint's identity for one link.
    result = G.endpoints[int(link.endpoint)]

  proc memberOf(G: GroupBook, link: GroupLink): string {.role: parser.} =
    ## G/link: the member's identity for one link.
    result = G.members[int(link.member)]

  proc claimedByOther(B: RestrictionBook, endpoint: string,
      claimed: seq[string]): string {.role: parser.} =
    ## B/endpoint/claimed: the first claimed member linked to another endpoint,
    ## or "" when every claimed member is free or already this endpoint's.
    for link in B.group.links:
      if endpointOf(B.group, link) != endpoint and memberOf(B.group, link) in claimed:
        return memberOf(B.group, link)
    result = ""

  proc keepLink(kept: var GroupBook, G: GroupBook, link: GroupLink,
      endpoint: string): string {.role: actor.} =
    ## kept/G/link/endpoint: copy one link into `kept`, unless it belongs to
    ## `endpoint`, which is being replaced. "" when kept or skipped, else why not.
    if endpointOf(G, link) == endpoint:
      return ""
    result = linkPair(kept, memberOf(G, link), endpointOf(G, link))

  proc setGroup*(B: var RestrictionBook, endpoint: string,
      claimed: seq[string]): string {.role: actor.} =
    ## B/endpoint/claimed: the endpoint replaces ITS links with exactly these.
    ## "" when applied, else why nothing changed.
    var
      kept: GroupBook = GroupBook()
      taken: string = ""
      e: string = ""
    if claimed.len > restrictionMaxMembers:
      return "a group update claims at most " & $restrictionMaxMembers & " members"
    for m in claimed:
      if m == endpoint:
        return "an endpoint names itself as a member"
    taken = claimedByOther(B, endpoint, claimed)
    if taken.len > 0:
      return "member " & taken & " already belongs to another endpoint"
    for link in B.group.links:
      e = keepLink(kept, B.group, link, endpoint)
      if e.len > 0:
        return e
    for m in claimed:
      e = linkPair(kept, m, endpoint)
      if e.len > 0:
        return e
    B.group = kept
    result = ""
