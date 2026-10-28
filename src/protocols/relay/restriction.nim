## -------------------------------------------------------------------------
## Restriction <- the frame, the one check every forward goes through, and
##                the book's persistent form
## -------------------------------------------------------------------------
##
## A relay decides, for each frame it would pass from one neighbour to
## another, whether it may. The relay operator picks ONE mode per relay; each
## device sets its own part by an AME control frame, kind 0x17, sealed on its
## link. Bifrost reads that frame itself. The three modes are described in
## restriction_types.nim; which of them are compiled in is decided there too.
##
##   mode        decides by                        cost             good for
##   ----------  --------------------------------  ---------------  -----------------
##   rmOpen      nothing: every pair may talk      none             a relay with no need
##   rmGroup     one sequence of (member, server)  one entry each   many clients, one
##                                                                   server behind it
##   rmListed    per recipient: accept and reject  a list each      versatile, costly
##               lists of source ADDRESSES                          to keep up to date
##   rmProfile   a profile index on the device,    one small index  targets that change
##               naming a predefined target set    per device       often
##
## The control frame body, every integer little-endian:
##
##   offset  field
##   ------  ---------------------------------------------------------------
##   0       version: 1 = update, 2 = acknowledgement
##   1       op (update only): 1 listed, 2 profile, 3 group
##   2...    the op's payload
##
##   listed:  u8 accept count | rules | u8 reject count | rules
##   profile: u8 index
##   group:   u8 count | (u16 len | member identity) each
##            the sender is the server; every member is claimed by it
##
##   rule = u16 host length | host bytes | u16 port
##
## A body cut short, with an unknown version or op, or a count above the
## limit, is refused with a reason. Nothing here raises for a neighbour.
## The codec is always compiled, so a relay built for one mode still reads
## what another mode's devices send, and says which mode it lacks.

import std/strutils

import ../types
import runePragmas
import ../transport/types as transport_types
import ../ame/types
import ../ame/level2/seal_open
import ../ame/level2/wire
import ./restriction_types
import ./restriction_group
import ./restriction_listed
import ./restriction_profile

export restriction_types, restriction_group, restriction_listed, restriction_profile

type
  ## RestrictionUpdate: one decoded control frame, not yet applied.
  RestrictionUpdate* {.role: truthState.} = object
    ok*: bool
    ack*: bool
    op*: uint8
    listed*: ListedFilter
    profile*: uint8
    members*: seq[string]
    err*: string

## ------------------------------ the check ------------------------------

proc restrictionAllows*(B: RestrictionBook, mode: RestrictionMode,
    src, dst: string, srcAddress: transport_types.UdpAddress): bool {.
    role: parser.} =
  ## B/mode: the book and the one mode in force.
  ## src/dst: the identities of the two neighbours; srcAddress: where the frame
  ## arrived from. The one check every forward goes through. A mode that is not
  ## compiled in refuses: a relay never passes what it cannot check.
  case mode
  of rmOpen:
    result = true
  of rmGroup:
    when restrictionGroupBuilt:
      result = groupAllows(B, src, dst)
    else:
      result = false
  of rmListed:
    when restrictionListedBuilt:
      result = listedAllowsTo(B, dst, srcAddress)
    else:
      result = false
  of rmProfile:
    when restrictionProfileBuilt:
      result = profileAllows(B, src, dst)
    else:
      result = false

proc checkRestrictionMode*(mode: RestrictionMode): string {.role: parser.} =
  ## mode: a mode a relay is about to switch on. "" when compiled in, else why not.
  if restrictionBuilt(mode):
    return ""
  result = "restriction mode " & $mode & " is not compiled into this relay"

proc applyRestrictionUpdate*(B: var RestrictionBook, identity: string,
    U: RestrictionUpdate): string {.role: actor.} =
  ## B/identity/U: the book, the neighbour that sent U, and the decoded update.
  ## "" when applied, else why not.
  if U.ack:
    return "an acknowledgement is not an update"
  case U.op
  of restrictionOpListed:
    when restrictionListedBuilt:
      setListed(B, identity, U.listed)
      result = ""
    else:
      result = checkRestrictionMode(rmListed)
  of restrictionOpProfile:
    when restrictionProfileBuilt:
      result = setProfile(B, identity, U.profile)
    else:
      result = checkRestrictionMode(rmProfile)
  of restrictionOpGroup:
    when restrictionGroupBuilt:
      result = setGroup(B, identity, U.members)
    else:
      result = checkRestrictionMode(rmGroup)
  else:
    result = "restriction op " & $U.op & " is not one of 1, 2, 3"

## ------------------------------ the frame ------------------------------

proc ruleError(r: FilterRule): string {.role: sanitizer.} =
  ## r: one rule. "" when it can be written and read back.
  if r.host.len == 0:
    return "a rule names no host (use \"*\" for any)"
  if r.host.len > restrictionMaxHost:
    return "a rule host is longer than " & $restrictionMaxHost & " bytes"
  if r.host != r.host.strip():
    return "a rule host has spaces around it"

proc putU16(B: var ByteSeq, v: int) {.role: helper.} =
  ## B/v: append v as two little-endian bytes.
  B.add uint8(v and 0xFF)
  B.add uint8((v shr 8) and 0xFF)

proc putText(B: var ByteSeq, s: string) {.role: helper.} =
  ## B/s: a u16 length, then the bytes.
  B.putU16(s.len)
  for c in s:
    B.add uint8(ord(c))

proc putRules(B: var ByteSeq, R: seq[FilterRule]): string {.role: helper.} =
  ## B/R: a count, then every rule. The error, or "".
  var
    i: int = 0
    e: string = ""
  if R.len > restrictionMaxRules:
    return "a list holds at most " & $restrictionMaxRules & " rules"
  B.add uint8(R.len)
  while i < R.len:
    e = ruleError(R[i])
    if e.len > 0:
      return e
    B.putText(R[i].host)
    B.putU16(int(R[i].port))
    i = i + 1

proc readU8(A: openArray[uint8], o: var int, v: var int): bool {.
    role: sanitizer.} =
  ## A/o/v: one byte at o. False when there is none.
  if o >= A.len:
    return false
  v = int(A[o])
  o = o + 1
  result = true

proc readText(A: openArray[uint8], o: var int, s: var string): string {.
    role: sanitizer.} =
  ## A/o/s: a u16 length and its bytes. "" when read whole.
  var
    n: int = 0
    i: int = 0
  if o + 2 > A.len:
    return "body ends inside a length"
  n = int(A[o]) or (int(A[o + 1]) shl 8)
  o = o + 2
  if n > restrictionMaxHost or o + n > A.len:
    return "body ends inside a text"
  s = newString(n)
  while i < n:
    s[i] = char(A[o + i])
    i = i + 1
  o = o + n

proc readRules(A: openArray[uint8], o: var int,
    L: var seq[FilterRule]): string {.role: sanitizer.} =
  ## A/o/L: a count, then that many rules. The error, or "".
  var
    n: int = 0
    i: int = 0
    r: FilterRule = FilterRule()
    e: string = ""
  if not readU8(A, o, n):
    return "body ends before a rule count"
  if n > restrictionMaxRules:
    return "body has more than " & $restrictionMaxRules & " rules"
  while i < n:
    e = readText(A, o, r.host)
    if e.len > 0:
      return e
    if o + 2 > A.len:
      return "body ends inside a rule port"
    r.port = uint16(int(A[o]) or (int(A[o + 1]) shl 8))
    o = o + 2
    L.add r
    i = i + 1

proc sealRestrictionFrame*(S: var AmeSession, carrier: AmeCarrier,
    body: ByteSeq): ByteSeq {.role: orchestrator, tag: "ame|wire".} =
  ## S/carrier/body: one control frame on kind 0x17. Raises when the link
  ## cannot seal it, which the caller turns into a failed request.
  result = sealControlFrame(S, ampkRestriction, carrier, body)

proc sealListedUpdate*(S: var AmeSession, carrier: AmeCarrier,
    F: ListedFilter): ByteSeq {.role: orchestrator, tag: "ame|wire".} =
  ## F: the lists THIS device accepts from and refuses. Raises when invalid.
  var
    body: ByteSeq = @[restrictionVersion, restrictionOpListed]
    e: string = putRules(body, F.accept)
  if e.len > 0:
    raise newException(ValueError, e)
  e = putRules(body, F.reject)
  if e.len > 0:
    raise newException(ValueError, e)
  result = sealRestrictionFrame(S, carrier, body)

proc sealProfileUpdate*(S: var AmeSession, carrier: AmeCarrier,
    profile: uint8): ByteSeq {.role: orchestrator, tag: "ame|wire".} =
  ## profile: the index of the predefined set this device reaches.
  result = sealRestrictionFrame(S, carrier,
    @[restrictionVersion, restrictionOpProfile, profile])

proc sealGroupUpdate*(S: var AmeSession, carrier: AmeCarrier,
    members: seq[string]): ByteSeq {.role: orchestrator, tag: "ame|wire".} =
  ## members: the identities this SERVER claims. Raises when too many or too
  ## long. The relay replaces this server's entries with exactly these.
  var
    body: ByteSeq = @[restrictionVersion, restrictionOpGroup]
    i: int = 0
  if members.len > restrictionMaxMembers:
    raise newException(ValueError, "a group holds at most " &
      $restrictionMaxMembers & " members")
  body.add uint8(members.len)
  while i < members.len:
    if members[i].len > restrictionMaxHost:
      raise newException(ValueError, "a member identity is too long")
    body.putText(members[i])
    i = i + 1
  result = sealRestrictionFrame(S, carrier, body)

proc sealRestrictionAck*(S: var AmeSession, carrier: AmeCarrier): ByteSeq {.
    role: orchestrator, tag: "ame|wire".} =
  ## The relay's answer: "applied".
  result = sealRestrictionFrame(S, carrier, @[restrictionAckVersion])

proc decodeRestrictionFrame*(A: openArray[uint8]): RestrictionUpdate {.
    role: sanitizer.} =
  ## A: the body of one kind-0x17 frame, already opened by the link.
  ## Nothing here raises: `ok` false and `err` say what was wrong.
  var
    o: int = 0
    v: int = 0
    e: string = ""
    n: int = 0
    i: int = 0
    s: string = ""
  if not readU8(A, o, v):
    result.err = "restriction body is empty"
    return
  if uint8(v) == restrictionAckVersion and A.len == 1:
    result.ack = true
    result.ok = true
    return
  if uint8(v) != restrictionVersion:
    result.err = "restriction body has version " & $v
    return
  if not readU8(A, o, v):
    result.err = "restriction body has no op"
    return
  result.op = uint8(v)
  case result.op
  of restrictionOpListed:
    e = readRules(A, o, result.listed.accept)
    if e.len == 0:
      e = readRules(A, o, result.listed.reject)
  of restrictionOpProfile:
    if not readU8(A, o, v):
      e = "profile body has no index"
    else:
      result.profile = uint8(v)
  of restrictionOpGroup:
    if not readU8(A, o, n):
      e = "group body has no member count"
    else:
      while i < n and e.len == 0:
        e = readText(A, o, s)
        if e.len == 0:
          result.members.add s
        i = i + 1
  else:
    e = "restriction op " & $result.op & " is not one of 1, 2, 3"
  if e.len > 0:
    result.err = e
    return
  if o != A.len:
    result.err = "restriction body has " & $(A.len - o) & " trailing bytes"
    return
  result.ok = true

proc openRestrictionFrame*(S: var AmeSession, carrier: AmeCarrier,
    frame: openArray[uint8]): RestrictionUpdate {.role: orchestrator,
    tag: "ame|wire".} =
  ## S/carrier/frame: one AME frame of kind 0x17 from the neighbour on this link.
  var
    opened: tuple[ok: bool, payload: ByteSeq, err: string] = (ok: false,
      payload: @[], err: "")
  try:
    opened = openControlFrame(S, frame, ampkRestriction, carrier)
    if not opened.ok:
      result.err = opened.err
      return
    result = decodeRestrictionFrame(opened.payload)
  except CatchableError as exc:
    result.err = exc.msg

proc openRestrictionAck*(S: var AmeSession, carrier: AmeCarrier,
    frame: openArray[uint8]): tuple[ok: bool, err: string] {.role: orchestrator,
    tag: "ame|wire".} =
  ## The relay's answer to an update: ok when it says applied.
  var
    u: RestrictionUpdate = openRestrictionFrame(S, carrier, frame)
  if not u.ok:
    result.err = u.err
    return
  if not u.ack:
    result.err = "the relay did not say the update was applied"
    return
  result.ok = true

## ------------------------------ persisting ------------------------------

proc encodeBook*(B: RestrictionBook): ByteSeq {.role: truthBuilder.} =
  ## B: the whole book, for a store to keep. decodeBook reads it back.
  var
    i: int = 0
    j: int = 0
    e: string = ""
  result.add restrictionVersion
  result.putU16(B.groups.len)
  for g in B.groups:
    result.putText(g.member)
    result.putText(g.server)
  result.putU16(B.listed.len)
  while i < B.listed.len:
    result.putText(B.listed[i].identity)
    e = putRules(result, B.listed[i].filter.accept)
    e = putRules(result, B.listed[i].filter.reject)
    i = i + 1
  result.putU16(B.profileOf.len)
  for p in B.profileOf:
    result.putText(p.identity)
    result.add p.profile
  result.add uint8(B.profiles.len)
  while j < B.profiles.len:
    result.add uint8(B.profiles[j].len)
    for name in B.profiles[j]:
      result.putText(name)
    j = j + 1

proc decodeBook*(A: openArray[uint8]): tuple[ok: bool, book: RestrictionBook,
    err: string] {.role: sanitizer.} =
  ## A: bytes written by encodeBook. Every count is checked against the bytes.
  ## The operator's profiles are read back too: the book is the whole state.
  var
    o: int = 1
    n: int = 0
    i: int = 0
    e: string = ""
    g: GroupEntry = GroupEntry()
    l: ListedEntry = ListedEntry()
    p: ProfileEntry = ProfileEntry()
    v: int = 0
    names: seq[string] = @[]
  if A.len < 1 or A[0] != restrictionVersion:
    result.err = "book has no version 1"
    return
  if o + 2 > A.len:
    result.err = "book ends before the group count"
    return
  n = int(A[o]) or (int(A[o + 1]) shl 8)
  o = o + 2
  while i < n:
    e = readText(A, o, g.member)
    if e.len == 0:
      e = readText(A, o, g.server)
    if e.len > 0:
      result.err = e
      return
    result.book.groups.add g
    i = i + 1
  if o + 2 > A.len:
    result.err = "book ends before the listed count"
    return
  n = int(A[o]) or (int(A[o + 1]) shl 8)
  o = o + 2
  i = 0
  while i < n:
    e = readText(A, o, l.identity)
    if e.len == 0:
      e = readRules(A, o, l.filter.accept)
    if e.len == 0:
      e = readRules(A, o, l.filter.reject)
    if e.len > 0:
      result.err = e
      return
    result.book.listed.add l
    l.filter = ListedFilter()
    i = i + 1
  if o + 2 > A.len:
    result.err = "book ends before the profile count"
    return
  n = int(A[o]) or (int(A[o + 1]) shl 8)
  o = o + 2
  i = 0
  while i < n:
    e = readText(A, o, p.identity)
    if e.len == 0 and readU8(A, o, v):
      p.profile = uint8(v)
    elif e.len == 0:
      e = "book ends inside a profile choice"
    if e.len > 0:
      result.err = e
      return
    result.book.profileOf.add p
    i = i + 1
  if not readU8(A, o, n):
    result.err = "book has no profile table"
    return
  i = 0
  while i < n:
    var count: int = 0
    if not readU8(A, o, count):
      result.err = "book ends inside the profile table"
      return
    names = @[]
    var j: int = 0
    while j < count:
      var name: string = ""
      e = readText(A, o, name)
      if e.len > 0:
        result.err = e
        return
      names.add name
      j = j + 1
    result.book.profiles.add names
    i = i + 1
  if o != A.len:
    result.err = "book has " & $(A.len - o) & " trailing bytes"
    return
  result.ok = true

proc isRestrictionFrame*(A: openArray[uint8]): bool {.role: parser.} =
  ## A: one datagram. True when its clear AME header says kind 0x17. Needs no
  ## key; the frame is still authenticated when it is opened.
  try:
    result = decodeAmeFrame(A).header.packetKind == ampkRestriction
  except CatchableError:
    result = false
