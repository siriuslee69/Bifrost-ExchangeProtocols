## -------------------------------------------------------------------------
## Restriction <- the frame, the one check every forward goes through, and
##                the book's persistent form
## -------------------------------------------------------------------------
##
## A relay decides, for each frame it would pass from one neighbour to
## another, whether it may. The relay operator picks ONE mode per relay; each
## device sets its own part by an AME control frame, kind 0x17, sealed on its
## link. Bifrost reads that frame itself. The modes are described in
## restriction_types.nim; which of them are compiled in is decided there too.
##
##   mode        decides by                          set by        cost
##   ----------  ----------------------------------  ------------  -------------
##   rmOpen      nothing: every pair may talk        operator      none
##   rmGroup     one group object: members, endpoints device        a link each
##               and the links between them
##   rmListed    the target's accept and reject      target device a list each
##               lists of source ADDRESSES
##   rmAllowed   the target's allowed list: who      target device a list each
##               may reach it (empty = nobody)
##
## THE CHECK RUNS AT EVERY HOP. Each relay tests the frame against the
## neighbour it is about to pass it to, so a restricted pair is stopped at the
## first relay that knows it, not at the end.
##
## The control frame body, every integer little-endian:
##
##   offset  field
##   ------  ---------------------------------------------------------------
##   0       version: 1 = update, 2 = acknowledgement
##   1       op (update only): 1 listed, 2 allowed, 3 group
##   2...    the op's payload
##
##   listed:  u8 accept count | addresses | u8 reject count | addresses
##   allowed: u8 count | addresses
##   group:   u8 count | (u16 length | identity) each
##
##   address = u8 family | bytes | u16 port
##     family 0: any host, no bytes      (text "*")
##     family 4: 4 bytes, the dotted quad
##     family 6: 16 bytes, network order
##     port 0 matches any port
##
## A body cut short, with an unknown version or op, or a count above the
## limit, is refused with a reason. Nothing here raises for a neighbour.

import ../types
import runePragmas
import ../ame/types
import ../ame/level2/seal_open
import ../ame/level2/wire
import ./restriction_types
import ./restriction_address
import ./restriction_group
import ./restriction_listed
import ./restriction_allowed
import ./restriction_filter

export restriction_types, restriction_address, restriction_group,
  restriction_listed, restriction_allowed, restriction_filter

## ------------------------------ the check ------------------------------

proc restrictionAllows*(B: RestrictionBook, mode: RestrictionMode,
    src, dst: string, srcAddress: SourceAddr): bool {.role: parser.} =
  ## B/mode: the book and the one mode in force.
  ## src/dst: the identities of the two neighbours; srcAddress: where the frame
  ## arrived from, already compact. The one check every forward goes through.
  ## A mode that is not compiled in refuses: a relay never passes what it
  ## cannot check.
  var
    i: int = findReach(B, dst)
    none: SourceRules = SourceRules()
  case mode
  of rmOpen:
    result = true
  of rmGroup:
    when restrictionGroupBuilt:
      result = groupAllows(B.group, src, dst)
    else:
      result = false
  of rmListed, rmAllowed:
    if i < 0:
      result = filterAllows(mode, none, srcAddress)
    else:
      result = filterAllows(mode, B.reach[i].rules, srcAddress)

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
      result = setListed(B, identity, U.rules.accept, U.rules.reject)
    else:
      result = checkRestrictionMode(rmListed)
  of restrictionOpAllowed:
    when restrictionAllowedBuilt:
      result = setAllowed(B, identity, U.rules.allowed)
    else:
      result = checkRestrictionMode(rmAllowed)
  of restrictionOpGroup:
    when restrictionGroupBuilt:
      result = setGroup(B, identity, U.members)
    else:
      result = checkRestrictionMode(rmGroup)
  else:
    result = "restriction op " & $U.op & " is not one of 1, 2, 3"

## ------------------------------ the bytes ------------------------------

proc putU16(B: var ByteSeq, v: int) {.role: helper.} =
  ## B/v: append v as two little-endian bytes.
  B.add uint8(v and 0xFF)
  B.add uint8((v shr 8) and 0xFF)

proc putText(B: var ByteSeq, s: string): string {.role: helper.} =
  ## B/s: a u16 length, then the bytes. "" when written, else why not.
  if s.len > restrictionMaxIdentity:
    return "an identity is longer than " & $restrictionMaxIdentity & " bytes"
  B.putU16(s.len)
  for c in s:
    B.add uint8(ord(c))
  result = ""

proc putAddress(B: var ByteSeq, a: SourceAddr) {.role: helper.} =
  ## B/a: family, the address bytes for that family, then the port.
  var
    i: int = 0
  B.add a.family
  case a.family
  of 4:
    B.add a.v4.a
    B.add a.v4.b
    B.add a.v4.c
    B.add a.v4.d
  of 6:
    while i < 16:
      B.add a.v6[i]
      i = i + 1
  else:
    discard
  B.putU16(int(a.port))

proc putAddresses(B: var ByteSeq, A: seq[SourceAddr]): string {.role: helper.} =
  ## B/A: a count, then every address. The error, or "".
  var
    i: int = 0
  if A.len > restrictionMaxRules:
    return "a list holds at most " & $restrictionMaxRules & " addresses"
  B.add uint8(A.len)
  while i < A.len:
    if A[i].family notin {0'u8, 4'u8, 6'u8}:
      return "an address family is not 0, 4 or 6"
    B.putAddress(A[i])
    i = i + 1
  result = ""

proc readU8(A: openArray[uint8], o: var int, v: var int): bool {.
    role: sanitizer.} =
  ## A/o/v: one byte at o. False when there is none.
  if o >= A.len:
    return false
  v = int(A[o])
  o = o + 1
  result = true

proc readU16(A: openArray[uint8], o: var int, v: var int): bool {.
    role: sanitizer.} =
  ## A/o/v: two little-endian bytes at o. False when there are not two.
  if o + 2 > A.len:
    return false
  v = int(A[o]) or (int(A[o + 1]) shl 8)
  o = o + 2
  result = true

proc readText(A: openArray[uint8], o: var int, s: var string): string {.
    role: sanitizer.} =
  ## A/o/s: a u16 length and its bytes. "" when read whole.
  var
    n: int = 0
    i: int = 0
  if not readU16(A, o, n):
    return "body ends inside a length"
  if n > restrictionMaxIdentity or o + n > A.len:
    return "body ends inside an identity"
  s = newString(n)
  while i < n:
    s[i] = char(A[o + i])
    i = i + 1
  o = o + n

proc readAddress(A: openArray[uint8], o: var int, a: var SourceAddr): string {.
    role: sanitizer.} =
  ## A/o/a: one address. The error, or "".
  var
    v: int = 0
    p: int = 0
    i: int = 0
  if not readU8(A, o, v):
    return "body ends before an address"
  case v
  of 0:
    a = SourceAddr(family: 0)
  of 4:
    if o + 4 > A.len:
      return "body ends inside an IPv4 address"
    a = SourceAddr(family: 4)
    a.v4 = (A[o], A[o + 1], A[o + 2], A[o + 3])
    o = o + 4
  of 6:
    if o + 16 > A.len:
      return "body ends inside an IPv6 address"
    a = SourceAddr(family: 6)
    while i < 16:
      a.v6[i] = A[o + i]
      i = i + 1
    o = o + 16
  else:
    return "address family " & $v & " is not 0, 4 or 6"
  if not readU16(A, o, p):
    return "body ends inside a port"
  a.port = uint16(p)

proc readIdentity(A: openArray[uint8], o: var int,
    L: var seq[string]): string {.role: sanitizer.} =
  ## A/o/L: one identity, added to L when read whole. The error, or "".
  var
    s: string = ""
  result = readText(A, o, s)
  if result.len == 0:
    L.add s

proc readMembers(A: openArray[uint8], o: var int,
    L: var seq[string]): string {.role: sanitizer.} =
  ## A/o/L: a count, then that many identities. The error, or "".
  var
    n: int = 0
    i: int = 0
  if not readU8(A, o, n):
    return "group body has no member count"
  while i < n:
    result = readIdentity(A, o, L)
    if result.len > 0:
      return
    i = i + 1

proc readAddresses(A: openArray[uint8], o: var int,
    L: var seq[SourceAddr]): string {.role: sanitizer.} =
  ## A/o/L: a count, then that many addresses. The error, or "".
  var
    n: int = 0
    i: int = 0
    a: SourceAddr = SourceAddr(family: 0)
    e: string = ""
  if not readU8(A, o, n):
    return "body ends before an address count"
  if n > restrictionMaxRules:
    return "body has more than " & $restrictionMaxRules & " addresses"
  while i < n:
    e = readAddress(A, o, a)
    if e.len > 0:
      return e
    L.add a
    i = i + 1
  result = ""

## ------------------------------ the frame ------------------------------

proc sealRestrictionFrame*(S: var AmeSession, carrier: AmeCarrier,
    body: ByteSeq): ByteSeq {.role: orchestrator, tag: "ame|wire".} =
  ## S/carrier/body: one control frame on kind 0x17. Raises when the link
  ## cannot seal it, which the caller turns into a failed request.
  result = sealControlFrame(S, ampkRestriction, carrier, body)

proc sealListedUpdate*(S: var AmeSession, carrier: AmeCarrier,
    accept, reject: seq[SourceAddr]): ByteSeq {.role: orchestrator,
    tag: "ame|wire".} =
  ## accept/reject: the addresses THIS device accepts from and refuses.
  ## Raises when a list is too long.
  var
    body: ByteSeq = @[restrictionVersion, restrictionOpListed]
    e: string = putAddresses(body, accept)
  if e.len > 0:
    raise newException(ValueError, e)
  e = putAddresses(body, reject)
  if e.len > 0:
    raise newException(ValueError, e)
  result = sealRestrictionFrame(S, carrier, body)

proc sealAllowedUpdate*(S: var AmeSession, carrier: AmeCarrier,
    allowed: seq[SourceAddr]): ByteSeq {.role: orchestrator, tag: "ame|wire".} =
  ## allowed: the addresses that may reach THIS device. An empty list
  ## closes it to everyone. Raises when the list is too long.
  var
    body: ByteSeq = @[restrictionVersion, restrictionOpAllowed]
    e: string = putAddresses(body, allowed)
  if e.len > 0:
    raise newException(ValueError, e)
  result = sealRestrictionFrame(S, carrier, body)

proc sealGroupUpdate*(S: var AmeSession, carrier: AmeCarrier,
    members: seq[string]): ByteSeq {.role: orchestrator, tag: "ame|wire".} =
  ## members: the identities this ENDPOINT claims. Raises when too many or too
  ## long. The relay replaces this endpoint's links with exactly these.
  var
    body: ByteSeq = @[restrictionVersion, restrictionOpGroup]
    i: int = 0
    e: string = ""
  if members.len > restrictionMaxMembers:
    raise newException(ValueError, "a group update claims at most " &
      $restrictionMaxMembers & " members")
  body.add uint8(members.len)
  while i < members.len:
    e = body.putText(members[i])
    if e.len > 0:
      raise newException(ValueError, e)
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
    e = readAddresses(A, o, result.rules.accept)
    if e.len == 0:
      e = readAddresses(A, o, result.rules.reject)
  of restrictionOpAllowed:
    e = readAddresses(A, o, result.rules.allowed)
  of restrictionOpGroup:
    e = readMembers(A, o, result.members)
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

proc putRules(B: var ByteSeq, R: ReachEntry): string {.role: helper.} =
  ## B/R: the three lists of one connection. The error, or "".
  result = putAddresses(B, R.rules.accept)
  if result.len == 0:
    result = putAddresses(B, R.rules.reject)
  if result.len == 0:
    result = putAddresses(B, R.rules.allowed)

proc encodeBook*(B: RestrictionBook): tuple[ok: bool, bytes: ByteSeq,
    err: string] {.role: truthBuilder.} =
  ## B: the whole book, for a store to keep. decodeBook reads it back.
  ## Refused only when a list is over its limit, which the setters never allow.
  var
    i: int = 0
    e: string = ""
  result.bytes.add restrictionVersion
  result.bytes.putU16(B.group.members.len)
  for m in B.group.members:
    e = result.bytes.putText(m)
    if e.len > 0:
      result.err = e
      return
  result.bytes.putU16(B.group.endpoints.len)
  for x in B.group.endpoints:
    e = result.bytes.putText(x)
    if e.len > 0:
      result.err = e
      return
  result.bytes.putU16(B.group.links.len)
  for l in B.group.links:
    result.bytes.putU16(int(l.member))
    result.bytes.putU16(int(l.endpoint))
  result.bytes.putU16(B.reach.len)
  while i < B.reach.len:
    e = result.bytes.putText(B.reach[i].identity)
    if e.len == 0:
      e = result.bytes.putRules(B.reach[i])
    if e.len > 0:
      result.err = e
      return
    i = i + 1
  result.ok = true

proc decodeBook*(A: openArray[uint8]): tuple[ok: bool, book: RestrictionBook,
    err: string] {.role: sanitizer.} =
  ## A: bytes written by encodeBook. Every count is checked against the bytes,
  ## and every link against the member and endpoint lists it points into.
  var
    o: int = 1
    n: int = 0
    i: int = 0
    e: string = ""
    s: string = ""
    m: int = 0
    x: int = 0
    link: GroupLink = GroupLink()
    entry: ReachEntry = ReachEntry()
  if A.len < 1 or A[0] != restrictionVersion:
    result.err = "book has no version 1"
    return
  if not readU16(A, o, n):
    result.err = "book ends before the member count"
    return
  while i < n and e.len == 0:
    e = readText(A, o, s)
    result.book.group.members.add s
    i = i + 1
  if e.len == 0 and not readU16(A, o, n):
    e = "book ends before the endpoint count"
  i = 0
  while i < n and e.len == 0:
    e = readText(A, o, s)
    result.book.group.endpoints.add s
    i = i + 1
  if e.len == 0 and not readU16(A, o, n):
    e = "book ends before the link count"
  i = 0
  while i < n and e.len == 0:
    if not readU16(A, o, m) or not readU16(A, o, x):
      e = "book ends inside a link"
    elif m >= result.book.group.members.len or
        x >= result.book.group.endpoints.len:
      e = "book has a link to a member or endpoint it does not hold"
    else:
      link = GroupLink(member: uint16(m), endpoint: uint16(x))
      result.book.group.links.add link
    i = i + 1
  if e.len == 0 and not readU16(A, o, n):
    e = "book ends before the connection count"
  i = 0
  while i < n and e.len == 0:
    entry = ReachEntry()
    e = readText(A, o, entry.identity)
    if e.len == 0:
      e = readAddresses(A, o, entry.rules.accept)
    if e.len == 0:
      e = readAddresses(A, o, entry.rules.reject)
    if e.len == 0:
      e = readAddresses(A, o, entry.rules.allowed)
    if e.len == 0:
      result.book.reach.add entry
    i = i + 1
  if e.len > 0:
    result.err = e
    return
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
