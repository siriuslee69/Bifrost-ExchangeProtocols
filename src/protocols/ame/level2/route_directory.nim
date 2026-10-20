## -------------------------------------------------------------------------
## AME Route Directory <- asking the router itself "whom may I reach?"
## -------------------------------------------------------------------------
##
## This is the one routing question a client puts to the router ITSELF, so
## it travels as an ordinary AME frame, sealed by the link's FOMKE ratchet
## like any message to the router. Routed traffic does not come through
## here; it uses outer "ART" frames (route_wire.nim).
##
##   phone -- AME kind 0x14 [ask, start 0] ---------------> router
##   phone <-- AME kind 0x14 [directory: 0x20 "nas", ...] -- router
##
## ╭─ ❧ Def. 1: the two bodies, inside the sealed plaintext 🌊
##
##   ask        01 | start u16
##   directory  02 | start u16 | total u16 | count u8 | count x entry
##                   entry = id u64 | name length u8 | name (<= 32 bytes)
##
## Every number is little-endian.
##
## Example 1. The router knows two targets the phone may see:
##
##   phone  -> router   01 00 00
##   router -> phone    02 00 00 02 00 02
##                      20 00 00 00 00 00 00 00 03 6e 61 73      0x20 "nas"
##                      21 00 00 00 00 00 00 00 03 63 61 6d      0x21 "cam"
##
## ╭─ ❧ Def. 2: pages 🐦‍🔥
##
## One frame holds at most 24 entries, so a directory fits one datagram:
## 24 x (8 + 1 + 32) + 6 = 990 bytes of body. A longer list is read page by
## page:
##
##   ask start=0   -> start 0,  total 50, 24 entries
##   ask start=24  -> start 24, total 50, 24 entries
##   ask start=48  -> start 48, total 50, 2 entries     <- done

import ../../types
import ../types
import ../level0/bytes
import ./seal_open
import runePragmas

const
  ameRouteNameMax* = 32
    ## Longest name a directory entry may carry, in bytes.
  ameRoutePageEntries* = 24
    ## Most directory entries in one frame (Def. 2).

proc requireRouteLen(n, minimum: int, what: string) {.role: parser,
    inline.} =
  ## n/minimum/what: refuse a body shorter than its fixed part.
  if n < minimum:
    raise newException(ValueError, "AME route " & what & " is truncated")

proc requireRouteName*(name: string) {.role: parser.} =
  ## name: one directory name, refused when it cannot be written.
  if name.len > ameRouteNameMax:
    raise newException(ValueError, "AME route name is longer than 32 bytes")

proc encodeRouteDirectory(D: AmeRouteDirectory): ByteSeq {.
    role: dataWriter.} =
  ## D: one question or one page of answer, as plaintext (Def. 1).
  result = @[uint8(ord(D.kind))]
  appendAmeU16(result, D.start)
  if D.kind == araAsk:
    return
  if D.kind != araDirectory:
    raise newException(ValueError, "AME route directory kind is unknown")
  if D.entries.len > ameRoutePageEntries:
    raise newException(ValueError, "AME route directory page is too long")
  if int(D.start) + D.entries.len > int(D.total):
    raise newException(ValueError, "AME route directory page passes its total")
  appendAmeU16(result, D.total)
  result.add(uint8(D.entries.len))
  for e in D.entries:
    requireRouteName(e.name)
    appendAmeU64(result, e.id)
    result.add(uint8(e.name.len))
    appendAmeLabel(result, e.name)

proc sealAmeRouteDirectory*(S: var AmeSession, carrier: AmeCarrier,
    D: AmeRouteDirectory): ByteSeq {.role: orchestrator,
    tag: "ame|wire".} =
  ## S/carrier: the link and its transport. D: a question or a page.
  result = sealControlFrame(S, ampkRoute, carrier, encodeRouteDirectory(D))

proc sealAmeRouteAsk*(S: var AmeSession, carrier: AmeCarrier,
    start: uint16 = 0'u16): ByteSeq {.role: orchestrator, tag: "appApi".} =
  ## S/carrier: session with the router. start: first entry wanted (Def. 2).
  result = sealAmeRouteDirectory(S, carrier,
    AmeRouteDirectory(kind: araAsk, start: start))

proc readRouteName(A: openArray[uint8], o, n: int): string {.role: parser.} =
  ## A/o/n: n name bytes starting at offset o, already length-checked.
  var
    i: int = 0
  result = newString(n)
  while i < n:
    result[i] = char(A[o + i])
    i = i + 1

proc decodeRouteEntries(A: openArray[uint8],
    D: var AmeRouteDirectory) {.role: parser.} =
  ## A: whole plaintext, kind byte first. D: filled with the page.
  var
    o: int = 6
    count: int = 0
    nameLen: int = 0
    e: AmeRouteEntry = default(AmeRouteEntry)
  requireRouteLen(A.len, 6, "directory")
  D.total = readAmeU16(A, 3)
  count = int(A[5])
  if count > ameRoutePageEntries or int(D.start) + count > int(D.total):
    raise newException(ValueError, "AME route directory page is invalid")
  while D.entries.len < count:
    requireRouteLen(A.len, o + 9, "directory entry")
    e.id = readAmeU64(A, o)
    nameLen = int(A[o + 8])
    if nameLen > ameRouteNameMax:
      raise newException(ValueError, "AME route name is longer than 32 bytes")
    requireRouteLen(A.len, o + 9 + nameLen, "directory name")
    e.name = readRouteName(A, o + 9, nameLen)
    D.entries.add(e)
    o = o + 9 + nameLen
  if o != A.len:
    raise newException(ValueError, "AME route directory has trailing bytes")

proc decodeRouteDirectory(A: openArray[uint8]): AmeRouteDirectory {.
    role: parser, tag: "ame|parsing|wire".} =
  ## A: opened plaintext of one kind-0x14 frame.
  requireRouteLen(A.len, 3, "directory message")
  result.start = readAmeU16(A, 1)
  case A[0]
  of uint8(ord(araAsk)):
    result.kind = araAsk
    if A.len != 3:
      raise newException(ValueError, "AME route ask has the wrong length")
  of uint8(ord(araDirectory)):
    result.kind = araDirectory
    decodeRouteEntries(A, result)
  else:
    raise newException(ValueError, "AME route directory kind is unknown")
  result.ok = true

proc openAmeRouteDirectory*(S: var AmeSession, carrier: AmeCarrier,
    frame: openArray[uint8]): AmeRouteDirectory {.role: orchestrator,
    tag: "appApi".} =
  ## S/carrier: the link and its transport. frame: one AME frame of kind
  ## 0x14. Nothing here raises: `ok` false and `err` say what was wrong.
  var
    opened: tuple[ok: bool, payload: ByteSeq, err: string] = (ok: false,
      payload: @[], err: "")
  try:
    opened = openControlFrame(S, frame, ampkRoute, carrier)
    if not opened.ok:
      return AmeRouteDirectory(err: opened.err)
    result = decodeRouteDirectory(opened.payload)
  except CatchableError as exc:
    result = AmeRouteDirectory(err: exc.msg)
