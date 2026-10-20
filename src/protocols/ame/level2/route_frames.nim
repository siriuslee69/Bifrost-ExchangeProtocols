## -------------------------------------------------------------------------
## AME Route Frames <- asking a router who is there, and sending through it
## -------------------------------------------------------------------------
##
## A client that shares a session with a router can do two things through
## it, without ever making a session with anyone else:
##
##   1. ask      "which targets may I reach?"     -> a list of ids + names
##   2. forward  "give these bytes to id 0x20"    -> the router passes them on
##
## The router reads the message (it holds the session key), re-seals it for
## the next link, and passes it on. Nothing is sealed end to end: each hop
## protects its own link. Use this when the router may read the traffic;
## put an end-to-end session INSIDE the payload when it may not.
##
## ╭─ ❧ Def. 1: one route frame on the wire 🌊
##
##   +----------------- what leaves the machine ------------------------+
##   | AME header (26) kind=0x14 | FOMKE envelope | tag | ciphertext    |
##   +-------------------------------------------------------------------+
##                                                      |
##                         opened by the session ratchet v
##   +-------------------------------------------------------------------+
##   | route kind (1) | body, depends on the kind (Def. 2)               |
##   +-------------------------------------------------------------------+
##
## An observer sees "a control frame of kind 0x14" and its length. Which of
## the five route messages it is, and for whom, is encrypted.
##
## ╭─ ❧ Def. 2: the five bodies 🐦‍🔥
##
##   ask        01 | start u16
##   directory  02 | start u16 | total u16 | count u8 | count x entry
##                   entry = id u64 | name length u8 | name (<= 32 bytes)
##   forward    03 | route block (24) | hops u8 | payload ...
##   deliver    04 | route block (24) | hops u8 | payload ...
##   refuse     05 | route block (24) | reason u8
##
## Every number is little-endian. The route block is the target and origin
## id, sealed with Gimli under the route key (level1/route_block.nim).
##
## Example 1. The phone (id 0x30) asks, and the router knows two targets:
##
##   phone  -> router   01 00 00
##   router -> phone    02 00 00 02 00 02
##                      20 00 00 00 00 00 00 00 03 6e 61 73      0x20 "nas"
##                      21 00 00 00 00 00 00 00 03 63 61 6d      0x21 "cam"
##
## Example 2. The phone sends "hi" to 0x20:
##
##   phone  -> router   03 [block: target 0x20, origin 0] 06 68 69
##   router -> nas      04 [block: target 0x20, origin 0x30] 05 68 69
##                         ^ new block, new key, new nonce    ^ hops - 1
##
## The phone writes origin 0. The router writes the id the HANDSHAKE proved,
## never one the sender claimed.
##
## ╭─ ❧ Def. 3: the directory in pages 🍣
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
import ../level1/route_block
import ./seal_open
import runePragmas

const
  ameRouteNameMax* = 32
    ## Longest name a directory entry may carry, in bytes.
  ameRoutePageEntries* = 24
    ## Most directory entries in one frame (Def. 3).
  ameRouteDefaultHops* = 6'u8
    ## How many routers a forward may still pass through when a client
    ## sends it. Each router takes one; at zero it is refused.
  ameRouteForwardOverhead* = 1 + ameRouteBlockLen + 1
    ## Route bytes in front of a forward's payload: kind, block, hops.

proc requireRouteLen(n, minimum: int, what: string) {.role: parser,
    inline.} =
  ## n/minimum/what: refuse a body shorter than its fixed part.
  if n < minimum:
    raise newException(ValueError, "AME route " & what & " is truncated")

proc routeKindFromId(id: uint8): AmeRouteKind {.role: parser.} =
  ## id: the first plaintext byte. Unknown values become arkUnknown.
  if id < uint8(ord(arkAsk)) or id > uint8(ord(high(AmeRouteKind))):
    return arkUnknown
  result = AmeRouteKind(id)

proc routeRefusalFromId(id: uint8): AmeRouteRefusal {.role: parser.} =
  ## id: a refusal byte; anything unknown is refused as a frame.
  if id < uint8(ord(arrNoRoute)) or id > uint8(ord(high(AmeRouteRefusal))):
    raise newException(ValueError, "AME route refusal reason is unknown")
  result = AmeRouteRefusal(id)

proc requireRouteName(name: string) {.role: parser.} =
  ## name: one directory name, refused when it cannot be written.
  if name.len > ameRouteNameMax:
    raise newException(ValueError, "AME route name is longer than 32 bytes")

proc encodeRouteDirectory(dst: var ByteSeq, m: AmeRouteMessage) {.
    role: dataWriter.} =
  ## dst: body after the kind byte. m: start, total and one page of entries.
  if m.entries.len > ameRoutePageEntries:
    raise newException(ValueError, "AME route directory page is too long")
  if int(m.start) + m.entries.len > int(m.total):
    raise newException(ValueError, "AME route directory page passes its total")
  appendAmeU16(dst, m.start)
  appendAmeU16(dst, m.total)
  dst.add(uint8(m.entries.len))
  for e in m.entries:
    requireRouteName(e.name)
    appendAmeU64(dst, e.id)
    dst.add(uint8(e.name.len))
    appendAmeLabel(dst, e.name)

proc encodeRouteBody(S: AmeSession, m: AmeRouteMessage,
    sequence: uint32): ByteSeq {.role: encryptor,
    tag: "ame|cryptoBoundary|wire".} =
  ## S: session whose send-side route key seals the block.
  ## m: the message. sequence: the frame counter it will be sealed at.
  result = @[uint8(ord(m.kind))]
  case m.kind
  of arkAsk:
    appendAmeU16(result, m.start)
  of arkDirectory:
    encodeRouteDirectory(result, m)
  of arkForward, arkDeliver:
    appendAmeBytes(result, sealAmeRouteBlock(S.routeKeySend, m.kind,
      sequence, m.target, m.origin))
    result.add(m.hopsLeft)
    appendAmeBytes(result, m.payload)
  of arkRefuse:
    appendAmeBytes(result, sealAmeRouteBlock(S.routeKeySend, m.kind,
      sequence, m.target, m.origin))
    result.add(uint8(ord(m.refusal)))
  of arkUnknown:
    raise newException(ValueError, "AME route message kind is unknown")

proc sealAmeRouteFrame*(S: var AmeSession, carrier: AmeCarrier,
    m: AmeRouteMessage): ByteSeq {.role: orchestrator,
    tag: "ame|cryptoBoundary|wire".} =
  ## S/carrier: the session and transport the frame leaves on.
  ## m: any of the five messages (see `AmeRouteMessage` for its fields).
  ## The block is sealed at `S.nextAmeSequence`, which is exactly the
  ## counter `sealControlFrame` gives the frame a line later.
  var
    body: ByteSeq = encodeRouteBody(S, m, S.nextAmeSequence)
  try:
    result = sealControlFrame(S, ampkRoute, carrier, body)
  finally:
    secureClearAmeBytes(body)

proc sealAmeRouteAsk*(S: var AmeSession, carrier: AmeCarrier,
    start: uint16 = 0'u16): ByteSeq {.role: orchestrator, tag: "appApi".} =
  ## S/carrier: session with the router. start: first entry wanted (Def. 3).
  result = sealAmeRouteFrame(S, carrier,
    AmeRouteMessage(kind: arkAsk, start: start))

proc sealAmeRouteForward*(S: var AmeSession, carrier: AmeCarrier,
    target: uint64, payload: openArray[uint8],
    hopsLeft: uint8 = ameRouteDefaultHops): ByteSeq {.role: orchestrator,
    tag: "appApi".} =
  ## S/carrier: session with the router.
  ## target: an id from the router's directory, or the origin of a delivery
  ##   being answered. payload: the bytes the target receives.
  ## hopsLeft: how many routers may still pass it on.
  result = sealAmeRouteFrame(S, carrier, AmeRouteMessage(kind: arkForward,
    target: target, hopsLeft: hopsLeft, payload: @payload))

proc readRouteName(A: openArray[uint8], o, n: int): string {.role: parser.} =
  ## A/o/n: n name bytes starting at offset o, already length-checked.
  var
    i: int = 0
  result = newString(n)
  while i < n:
    result[i] = char(A[o + i])
    i = i + 1

proc decodeRouteDirectory(A: openArray[uint8],
    m: var AmeRouteMessage) {.role: parser.} =
  ## A: whole plaintext, kind byte first. m: filled with the page.
  var
    o: int = 6
    count: int = 0
    nameLen: int = 0
    e: AmeRouteEntry = default(AmeRouteEntry)
  requireRouteLen(A.len, 6, "directory")
  m.start = readAmeU16(A, 1)
  m.total = readAmeU16(A, 3)
  count = int(A[5])
  if count > ameRoutePageEntries or int(m.start) + count > int(m.total):
    raise newException(ValueError, "AME route directory page is invalid")
  while m.entries.len < count:
    requireRouteLen(A.len, o + 9, "directory entry")
    e.id = readAmeU64(A, o)
    nameLen = int(A[o + 8])
    if nameLen > ameRouteNameMax:
      raise newException(ValueError, "AME route name is longer than 32 bytes")
    requireRouteLen(A.len, o + 9 + nameLen, "directory name")
    e.name = readRouteName(A, o + 9, nameLen)
    m.entries.add(e)
    o = o + 9 + nameLen
  if o != A.len:
    raise newException(ValueError, "AME route directory has trailing bytes")

proc decodeRouteBlock(S: AmeSession, A: openArray[uint8], sequence: uint32,
    m: var AmeRouteMessage) {.role: decryptor, tag: "ame|cryptoBoundary".} =
  ## S: session whose receive-side route key opens the block.
  ## A: whole plaintext. sequence: counter of the frame it arrived in.
  var
    ids: AmeRouteIds = default(AmeRouteIds)
  requireRouteLen(A.len, 2 + ameRouteBlockLen, "block")
  ids = openAmeRouteBlock(S.routeKeyRecv, m.kind, sequence,
    A.toOpenArray(1, ameRouteBlockLen))
  if not ids.ok:
    raise newException(ValueError, "AME route block did not authenticate")
  m.target = ids.target
  m.origin = ids.origin

proc decodeRouteBody(S: AmeSession, A: openArray[uint8],
    sequence: uint32): AmeRouteMessage {.role: parser,
    tag: "ame|parsing|wire".} =
  ## S/A/sequence: session, opened plaintext, and the frame's counter.
  requireRouteLen(A.len, 1, "message")
  result.kind = routeKindFromId(A[0])
  case result.kind
  of arkAsk:
    if A.len != 3:
      raise newException(ValueError, "AME route ask has the wrong length")
    result.start = readAmeU16(A, 1)
  of arkDirectory:
    decodeRouteDirectory(A, result)
  of arkForward, arkDeliver:
    decodeRouteBlock(S, A, sequence, result)
    result.hopsLeft = A[1 + ameRouteBlockLen]
    result.payload = @(A.toOpenArray(2 + ameRouteBlockLen, A.len - 1))
  of arkRefuse:
    if A.len != 2 + ameRouteBlockLen:
      raise newException(ValueError, "AME route refusal has the wrong length")
    decodeRouteBlock(S, A, sequence, result)
    result.refusal = routeRefusalFromId(A[1 + ameRouteBlockLen])
  of arkUnknown:
    raise newException(ValueError, "AME route message kind is unknown")
  result.ok = true

proc openAmeRouteFrame*(S: var AmeSession, carrier: AmeCarrier,
    frame: openArray[uint8]): AmeRouteMessage {.role: orchestrator,
    tag: "appApi".} =
  ## S/carrier: the session and transport the frame arrived on.
  ## frame: one whole AME frame of kind 0x14.
  ## Nothing here raises: `ok` false and `err` say what was wrong, and a
  ## frame that is not ok must not be acted on.
  var
    opened: AmeControlOpened = default(AmeControlOpened)
  try:
    opened = openControlFrame(S, frame, ampkRoute, carrier)
    if not opened.ok:
      result.err = opened.err
      return
    result = decodeRouteBody(S, opened.payload, opened.sequence)
  except CatchableError as exc:
    result = AmeRouteMessage(err: exc.msg)
  secureClearAmeBytes(opened.payload)
