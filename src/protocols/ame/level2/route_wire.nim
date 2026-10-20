## -------------------------------------------------------------------------
## AME Route Wire <- the outer "ART" frame: a sealed address, an open payload
## -------------------------------------------------------------------------
##
## A client has an AME session with a router. On that one link it can send
## two kinds of frame, and the first three bytes say which:
##
##   "AME"  an ordinary AME frame: for the router ITSELF (FOMKE-sealed)
##   "ART"  a route frame: for someone BEHIND the router
##
## A route frame encrypts only who it is for. The payload is passed on
## byte for byte, because it is already sealed -- it is the sender's own
## end-to-end AME frame (a handshake record, later a session frame) with
## the target, which no router holds a key for:
##
##   phone  ==link A==>  router  ==link B==>  nas
##     |                   |                   |
##     | ART[A: to 0x20]   | ART[B: to 0x20,   | target is me:
##     |   + E2E frame     |   from 0x30]      | hand the E2E frame to
##     |                   |   + same E2E frame| the phone<->nas session
##
## Each hop opens the 16-byte address with its incoming link's key and
## seals it again with the outgoing link's key and counter. A watcher on
## one link sees neither the target nor the origin.
##
## ╭─ ❧ Def. 1: the frame, byte by byte 🌊
##
##   offset  size  field
##   ------  ----  ---------------------------------------------------------
##   0       3     magic "ART" (AME RouTe; not "AMR", the hello-retry record)
##   3       1     version 0x01
##   4       1     kind: 0x01 forward, 0x02 refuse
##   5       1     forward: hops left    refuse: reason (0x01..0x03)
##   6       8     session id, u64 LE -- which link (same as the AME header)
##   14      4     route counter, u32 LE -- this link's, one per frame
##   18      16    target id + origin id, sealed (level1/route_block.nim)
##   34      8     tag
##   42      n     payload, forward only; a refusal has none
##
## ╭─ ❧ Def. 2: what the 8-byte tag covers 🐦‍🔥
##
## The Gimli nonce is built from the header itself:
##
##   nonce   "ART" 01 | kind | hops/reason | 00 00 | counter u32 | n u32
##   byte    0 ..... 3   4      5             6  7    8 ...... 11   12..15
##
## (n = payload length.) So the tag covers both ids, the kind, the hop count
## or reason, the counter and the payload LENGTH. It does not cover the
## payload's CONTENT: that is the end-to-end frame's job, and it does it
## with its own tag at the far end. The session id is checked against the
## link instead; an edited one makes the frame drop.
##
## ╭─ ❧ Def. 3: replay 🍣
##
## Every link side keeps the last 64 counters it accepted from its peer
## (`routeReplay`). The counter is in the nonce, so it cannot be edited
## without breaking the tag, and the window is only moved AFTER the tag
## checked out, so a forged counter cannot push honest frames out.
##
##   frame 41 arrives        -> accepted, 41 remembered
##   frame 41 arrives again  -> dropped: "AME route replay rejected"
##   frame 30 after 100      -> dropped: older than the window
##
## A replay is stopped at the first router it reaches. It never costs the
## next link anything, and never reaches the target.

import ../../types
import ../types
import ../level0/bytes
import ../level1/route_block
import ./seal_open
import runePragmas

const
  ameRouteMagic* = [uint8('A'), uint8('R'), uint8('T')]
  ameRouteVersion* = 0x01'u8
  ameRouteHeaderLen* = 18
  ameRouteOverhead* = ameRouteHeaderLen + ameRouteBlockLen
    ## 42: everything in front of the payload.
  ameRouteDefaultHops* = 6'u8
    ## Routers a forward may still pass when a client sends it. Each router
    ## takes one; at zero it is refused.

proc isAmeRouteFrame*(A: openArray[uint8]): bool {.role: parser,
    tag: "appApi".} =
  ## A: one datagram or stream frame. True when it starts with "ART" and
  ## version 1 -- the caller then hands it to the router, not to FOMKE.
  result = A.len >= ameRouteOverhead and A[0] == ameRouteMagic[0] and
    A[1] == ameRouteMagic[1] and A[2] == ameRouteMagic[2] and
    A[3] == ameRouteVersion

proc routeNonce(kind, fifth: uint8, counter: uint32,
    payloadLen: int): array[16, uint8] {.role: truthBuilder.} =
  ## kind/fifth/counter/payloadLen: the header fields the tag covers (Def. 2).
  result[0] = ameRouteMagic[0]
  result[1] = ameRouteMagic[1]
  result[2] = ameRouteMagic[2]
  result[3] = ameRouteVersion
  result[4] = kind
  result[5] = fifth
  result[8] = uint8(counter and 0xff'u32)
  result[9] = uint8((counter shr 8) and 0xff'u32)
  result[10] = uint8((counter shr 16) and 0xff'u32)
  result[11] = uint8((counter shr 24) and 0xff'u32)
  result[12] = uint8(payloadLen and 0xff)
  result[13] = uint8((payloadLen shr 8) and 0xff)
  result[14] = uint8((payloadLen shr 16) and 0xff)
  result[15] = uint8((payloadLen shr 24) and 0xff)

proc sealRouteWire(S: var AmeSession, kind: AmeRouteKind, fifth: uint8,
    target, origin: uint64, payload: openArray[uint8]): ByteSeq {.
    role: encryptor, tag: "ame|cryptoBoundary|wire".} =
  ## S: the link the frame leaves on; its send-side route key and counter.
  ## kind/fifth: header bytes 4 and 5. target/origin: the two ids.
  ## payload: passed through as it is.
  var
    counter: uint32 = S.nextRouteCounter
    nonce: array[16, uint8] = routeNonce(uint8(ord(kind)), fifth, counter,
      payload.len)
  requireAmeAuth(S.auth)
  requireAmePeerTrust(S)
  requireAmeMaySend(S, ampkRoute)
  if counter == high(uint32):
    raise newException(ValueError, "AME route counter is exhausted")
  if uint64(payload.len) > uint64(high(int32)):
    raise newException(ValueError, "AME route payload is too long")
  appendAmeBytes(result, ameRouteMagic)
  result.add(ameRouteVersion)
  result.add(uint8(ord(kind)))
  result.add(fifth)
  appendAmeU64(result, S.sessionId)
  appendAmeU32(result, counter)
  appendAmeBytes(result, sealAmeRouteBlock(S.routeKeySend, nonce, target,
    origin))
  appendAmeBytes(result, payload)
  S.nextRouteCounter = counter + 1'u32

proc sealAmeRouteForward*(S: var AmeSession, target: uint64,
    payload: openArray[uint8], hopsLeft: uint8 = ameRouteDefaultHops,
    origin: uint64 = 0'u64): ByteSeq {.role: orchestrator, tag: "appApi".} =
  ## S: the session with the next hop (for a client: its router).
  ## target: where it should end up. payload: usually an end-to-end AME frame.
  ## hopsLeft: routers it may still pass.
  ## origin: leave 0 as a client -- the first router writes the id the
  ##   handshake proved. Routers pass the origin they were given.
  result = sealRouteWire(S, arkForward, hopsLeft, target, origin, payload)

proc sealAmeRouteRefuse*(S: var AmeSession, target, origin: uint64,
    reason: AmeRouteRefusal): ByteSeq {.role: orchestrator.} =
  ## S: the link back toward the origin. target/origin: the refused forward.
  ## reason: why (never arrNone).
  if reason == arrNone:
    raise newException(ValueError, "AME route refusal needs a reason")
  result = sealRouteWire(S, arkRefuse, uint8(ord(reason)), target, origin,
    [])

proc routeHeaderError(S: AmeSession, A: openArray[uint8]): string {.
    role: parser.} =
  ## S/A: everything about the clear header that can be refused before any
  ## key is used. Empty when the header is acceptable.
  if not isAmeRouteFrame(A):
    return "not an AME route frame"
  if A[4] != uint8(ord(arkForward)) and A[4] != uint8(ord(arkRefuse)):
    return "AME route kind is unknown"
  if not acceptsSessionId(S, readAmeU64(A, 6)):
    return "AME route frame belongs to another session"
  if A[4] == uint8(ord(arkRefuse)) and A.len != ameRouteOverhead:
    return "AME route refusal carries a payload"
  if A[4] == uint8(ord(arkRefuse)) and
      (A[5] < uint8(ord(arrNoRoute)) or A[5] > uint8(ord(high(AmeRouteRefusal)))):
    return "AME route refusal reason is unknown"

proc openAmeRouteFrame*(S: var AmeSession,
    A: openArray[uint8]): AmeRouteFrame {.role: orchestrator,
    tag: "appApi".} =
  ## S: the session of the link the frame arrived on.
  ## A: one whole route frame (check `isAmeRouteFrame` first).
  ## Nothing here raises: `ok` false and `err` say what was wrong, and a
  ## frame that is not ok must not be acted on.
  var
    counter: uint32 = 0'u32
    nonce: array[16, uint8] = default(array[16, uint8])
    ids: AmeRouteIds = default(AmeRouteIds)
  result.err = amePeerTrustError(S)
  if result.err.len == 0:
    result.err = routeHeaderError(S, A)
  if result.err.len > 0:
    return
  counter = readU32(A, 14)
  nonce = routeNonce(A[4], A[5], counter, A.len - ameRouteOverhead)
  try:
    ids = openAmeRouteBlock(S.routeKeyRecv, nonce,
      A.toOpenArray(ameRouteHeaderLen, ameRouteOverhead - 1))
  except CatchableError as exc:
    result.err = exc.msg
    return
  if not ids.ok:
    result.err = "AME route block did not authenticate"
    return
  if not replayAccept(S.routeReplay, counter):
    result.err = "AME route replay rejected"
    return
  result.kind = AmeRouteKind(A[4])
  result.target = ids.target
  result.origin = ids.origin
  if result.kind == arkForward:
    result.hopsLeft = A[5]
    result.payload = @(A.toOpenArray(ameRouteOverhead, A.len - 1))
  else:
    result.refusal = AmeRouteRefusal(A[5])
  result.ok = true
