## -------------------------------------------------------------------------
## Restriction types <- the shapes every restriction mode shares
## -------------------------------------------------------------------------
##
## No procedures here, so the three modes and the frame codec can all import
## it without a cycle. Which modes are compiled in is decided by ONE define:
##
##   -d:bifrostRestriction=all              every mode (default)
##   -d:bifrostRestriction=group            only the group sequence
##   -d:bifrostRestriction=listed           only the accept and reject lists
##   -d:bifrostRestriction=profile          only the predefined profiles
##   -d:bifrostRestriction=group,profile    any comma-separated set
##
## A mode that is not compiled in is not in the binary at all: its checks,
## its update procedure and its rule scan are behind a `when`. What remains
## always is the data shape and the wire codec, so a relay built for one mode
## still reads every frame a neighbour sends and refuses the others by name.

import std/strutils

import runePragmas

const
  restrictionSelected* {.strdefine: "bifrostRestriction".}: string = "all"
    ## The define above, as a string. Read only at compile time.
  restrictionVersion*: uint8 = 1'u8
  restrictionAckVersion*: uint8 = 2'u8
  restrictionOpListed*: uint8 = 1'u8
  restrictionOpProfile*: uint8 = 2'u8
  restrictionOpGroup*: uint8 = 3'u8
  restrictionMaxRules*: int = 32
  restrictionMaxHost*: int = 255
  restrictionMaxMembers*: int = 255
  restrictionMaxProfiles*: int = 255
  restrictionAnyHost*: string = "*"

  restrictionGroupBuilt* = restrictionSelected == "all" or
    restrictionSelected.contains("group")
  restrictionListedBuilt* = restrictionSelected == "all" or
    restrictionSelected.contains("listed")
  restrictionProfileBuilt* = restrictionSelected == "all" or
    restrictionSelected.contains("profile")

type
  ## RestrictionMode: the one way a relay decides (Defs. 1 to 3 in restriction.nim).
  RestrictionMode* = enum
    rmOpen = 0'u8,
    rmGroup = 1'u8,
    rmListed = 2'u8,
    rmProfile = 3'u8

  ## FilterRule: one address for rmListed (host and port).
  FilterRule* {.role: configurator.} = object
    host*: string
    port*: uint16

  ## ListedFilter: the accept and reject lists of one recipient.
  ListedFilter* {.role: truthState.} = object
    accept*: seq[FilterRule]
    reject*: seq[FilterRule]

  ## GroupEntry: one member and the one server it may talk to.
  GroupEntry* {.role: truthState.} = object
    member*: string
    server*: string

  ## ListedEntry: one recipient's lists, keyed by its identity.
  ListedEntry* {.role: truthState.} = object
    identity*: string
    filter*: ListedFilter

  ## ProfileEntry: the profile a device chose, keyed by its identity.
  ProfileEntry* {.role: truthState.} = object
    identity*: string
    profile*: uint8

  ## RestrictionBook: everything the modes keep. One book per relay.
  RestrictionBook* {.role: truthState.} = object
    groups*: seq[GroupEntry]
    listed*: seq[ListedEntry]
    profileOf*: seq[ProfileEntry]
    profiles*: seq[seq[string]]
      ## predefined by the operator; profiles[0] is always the empty set

proc restrictionBuiltModes*(): set[RestrictionMode] {.role: configurator.} =
  ## The modes this binary was compiled with. rmOpen is always there.
  result = {rmOpen}
  when restrictionGroupBuilt:
    result.incl rmGroup
  when restrictionListedBuilt:
    result.incl rmListed
  when restrictionProfileBuilt:
    result.incl rmProfile

proc restrictionBuilt*(mode: RestrictionMode): bool {.role: parser.} =
  ## mode: true when that mode's code is in this binary.
  result = mode in restrictionBuiltModes()
