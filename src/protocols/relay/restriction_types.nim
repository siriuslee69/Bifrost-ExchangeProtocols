## -------------------------------------------------------------------------
## Restriction types <- the shapes every restriction mode shares
## -------------------------------------------------------------------------
##
## No procedures that touch AME, so the modes and the super-fast relay can all
## import it without a cycle. Which modes are compiled in is decided by ONE
## define:
##
##   -d:bifrostRestriction=all              every mode (default)
##   -d:bifrostRestriction=group            only the group object
##   -d:bifrostRestriction=listed           only the accept and reject lists
##   -d:bifrostRestriction=allowed          only the allowed lists
##   -d:bifrostRestriction=group,allowed    any comma-separated set
##
## A mode that is not compiled in is not in the binary at all: its checks,
## its update procedure and its scan are behind a `when`. The codec is always
## there, so a relay built for one mode still reads every frame a neighbour
## sends and refuses the others by name.
##
## Def. 1 (SourceAddr): one address a frame can arrive from, in compact form.
## Def. 2 (SourceRules): the three address lists one connection keeps.
## Def. 3 (ReachEntry): the SourceRules of one connection, keyed by identity.
## Def. 4 (GroupBook): members, endpoints, and the pairs allowed between them.
##
##   GroupBook                       ReachEntry (one per connection)
##   ---------------------------     ---------------------------------
##   members:   [alice, bob]         identity: "nas"
##   endpoints: [server]             rules.accept:  [ ... ]   listed
##   links:     (0,0) (1,0)          rules.reject:  [ ... ]   listed
##                 |     |           rules.allowed: [ ... ]   allowed
##              alice  bob  <-> server

import std/strutils

import runePragmas
import ./restriction_address

const
  restrictionSelected* {.strdefine: "bifrostRestriction".}: string = "all"
    ## The define above, as a string. Read only at compile time.
  restrictionVersion*: uint8 = 1'u8
    ## The first byte of a control body and of a saved book.
  restrictionAckVersion*: uint8 = 2'u8
    ## A control body of only this byte: "applied".
  restrictionOpListed*: uint8 = 1'u8
  restrictionOpAllowed*: uint8 = 2'u8
  restrictionOpGroup*: uint8 = 3'u8
  restrictionMaxRules*: int = 32
    ## Most addresses in one list.
  restrictionMaxMembers*: int = 255
    ## Most identities one group update may claim.
  restrictionMaxEntries*: int = 4096
    ## Most members, or endpoints, or reach entries one book keeps.
  restrictionMaxIdentity*: int = 255
  restrictionAnswerDefaultMs*: uint32 = 1000'u32
    ## Default gap between two answers to one restricted neighbour. 0 means
    ## never answer. See RelayNode.restrictionAnswerMs.

  restrictionGroupBuilt* = restrictionSelected == "all" or
    restrictionSelected.contains("group")
  restrictionListedBuilt* = restrictionSelected == "all" or
    restrictionSelected.contains("listed")
  restrictionAllowedBuilt* = restrictionSelected == "all" or
    restrictionSelected.contains("allowed")

type
  ## RestrictionMode: the one way a relay decides (see restriction.nim).
  RestrictionMode* = enum
    rmOpen = 0'u8,
    rmGroup = 1'u8,
    rmListed = 2'u8,
    rmAllowed = 3'u8

  ## SourceRules: the address lists one connection keeps (Def. 2).
  ##   accept:  only these may reach it; empty accepts all not rejected (listed)
  ##   reject:  these may never reach it (listed)
  ##   allowed: these may reach it; empty means NOBODY may (allowed)
  SourceRules* {.role: truthState.} = object
    accept*: seq[SourceAddr]
    reject*: seq[SourceAddr]
    allowed*: seq[SourceAddr]

  ## ReachEntry: one connection's rules, keyed by its identity (Def. 3).
  ReachEntry* {.role: truthState.} = object
    identity*: string
    rules*: SourceRules

  ## GroupLink: one allowed pair. Both fields are indexes into GroupBook.
  GroupLink* {.role: truthState.} = object
    member*: uint16
    endpoint*: uint16

  ## GroupBook: the group object (Def. 4). A member and an endpoint may talk
  ## only when a link names them; members never talk to each other.
  GroupBook* {.role: truthState.} = object
    members*: seq[string]
    endpoints*: seq[string]
    links*: seq[GroupLink]

  ## RestrictionBook: everything the modes keep. One book per relay.
  RestrictionBook* {.role: truthState.} = object
    group*: GroupBook
    reach*: seq[ReachEntry]

  ## RestrictionUpdate: one decoded control frame, not yet applied.
  ## rules: accept and reject for op 1, allowed for op 2.
  ## members: the identities a group update claims (op 3).
  RestrictionUpdate* {.role: truthState.} = object
    ok*: bool
    ack*: bool
    op*: uint8
    rules*: SourceRules
    members*: seq[string]
    err*: string

proc restrictionBuiltModes*(): set[RestrictionMode] {.role: configurator.} =
  ## The modes this binary was compiled with. rmOpen is always there.
  result = {rmOpen}
  when restrictionGroupBuilt:
    result.incl rmGroup
  when restrictionListedBuilt:
    result.incl rmListed
  when restrictionAllowedBuilt:
    result.incl rmAllowed

proc restrictionBuilt*(mode: RestrictionMode): bool {.role: parser.} =
  ## mode: true when that mode's code is in this binary.
  result = mode in restrictionBuiltModes()

proc findReach*(B: RestrictionBook, identity: string): int {.role: parser.} =
  ## B/identity: the index of that connection's entry, or -1.
  var
    i: int = 0
  while i < B.reach.len:
    if B.reach[i].identity == identity:
      return i
    i = i + 1
  result = -1

proc ensureReach*(B: var RestrictionBook, identity: string): int {.role: actor.} =
  ## B/identity: the index of that connection's entry, made empty when new.
  result = findReach(B, identity)
  if result < 0:
    B.reach.add ReachEntry(identity: identity)
    result = B.reach.len - 1
