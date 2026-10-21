## -------------------------------------------------------------------------
## Slow Envelope <- the routing header relaySlowExtractEncrypt puts INSIDE
##                  an ordinary AME data frame
## -------------------------------------------------------------------------
##
## relayFastExtraFrame wraps an end-to-end frame in an outer "ART" frame and
## only ever touches the 16 address bytes. relaySlowExtractEncrypt does the
## opposite: every link carries an ordinary FOMKE-sealed AME data frame, and
## the routing header sits inside it, next to the payload. So each relay
## OPENS the whole thing, can read and judge the payload, and seals it again
## for the next link.
##
##   phone ==link A==> relay ==link B==> nas
##           |                |               |
##           AME frame (A)    open with A     open with B
##           [ RSE header |   payload clear   [ RSE header |
##             payload ]      seal with B       payload ]
##
## ╭─ ❧ Def. 1: the envelope (the plaintext of one AME data frame) 🍣
##
##   offset  size  field
##   ------  ----  ----------------------------------------------------
##   0       3     magic "RSE"
##   3       1     version 0x01
##   4       1     kind: 0x01 forward, 0x02 refuse   (as in ART)
##   5       1     forward: hops left    refuse: reason
##   6       8     target id, u64 LE
##   14      8     origin id, u64 LE    (0 from a client; the first relay
##                                       writes the proved one)
##   22      n     payload (forward only)
##
## No tag and no counter of its own: the AME frame around it already
## authenticates every byte, keeps its own replay window and its own
## ratchet. 22 bytes in front of the payload, plus the AME frame's overhead.
##
## Example 1. A forward from a phone (route id 0x30) to a nas (0x20), six
## hops left, payload "hi":
##
##   52 53 45 01 01 06 | 20 00 00 00 00 00 00 00 | 00 x8 | 68 69
##   R  S  E  v1 fwd 6   target 0x20               origin 0  "hi"
##
## The relay overwrites origin with 0x30 -- what the phone's HANDSHAKE
## proved -- before sealing it again for the nas.

import ../types
import ../ame/types
import ../ame/level0/bytes
import ../ame/level2/wire
import ../ame/level2/seal_open
import ../ame/level2/route_wire
import runePragmas

const
  relaySlowMagic* = [uint8('R'), uint8('S'), uint8('E')]
  relaySlowVersion* = 0x01'u8
  relaySlowOverhead* = 22
    ## Envelope bytes in front of the payload (Def. 1).

proc encodeSlowEnvelope*(kind: AmeRouteKind, fifth: uint8,
    target, origin: uint64, payload: openArray[uint8]): ByteSeq {.
    role: truthBuilder.} =
  ## kind/fifth: header bytes 4 and 5 (hops left, or the refusal reason).
  ## target/origin: the two ids. payload: carried as it is.
  appendAmeBytes(result, relaySlowMagic)
  result.add(relaySlowVersion)
  result.add(uint8(ord(kind)))
  result.add(fifth)
  appendAmeU64(result, target)
  appendAmeU64(result, origin)
  appendAmeBytes(result, payload)

proc decodeSlowEnvelope*(A: openArray[uint8]): AmeRouteFrame {.role: parser.} =
  ## A: the opened plaintext of one AME data frame. Never raises; `ok`
  ## false and `err` say what was wrong.
  if A.len < relaySlowOverhead or A[0] != relaySlowMagic[0] or
      A[1] != relaySlowMagic[1] or A[2] != relaySlowMagic[2] or
      A[3] != relaySlowVersion:
    return AmeRouteFrame(err: "relay envelope header is malformed")
  if A[4] != uint8(ord(arkForward)) and A[4] != uint8(ord(arkRefuse)):
    return AmeRouteFrame(err: "relay envelope kind is unknown")
  result.kind = AmeRouteKind(A[4])
  result.target = readAmeU64(A, 6)
  result.origin = readAmeU64(A, 14)
  if result.kind == arkForward:
    result.hopsLeft = A[5]
    result.payload = @(A.toOpenArray(relaySlowOverhead, A.high))
  if result.kind == arkRefuse and A[5] in {1'u8 .. 3'u8}:
    result.refusal = AmeRouteRefusal(A[5])
  if result.kind == arkRefuse and result.refusal == arrNone:
    return AmeRouteFrame(err: "relay envelope refusal names no reason")
  result.ok = true

proc sealSlowData(S: var AmeSession, carrier: AmeCarrier,
    body: openArray[uint8]): ByteSeq {.role: encryptor,
    tag: "cryptoBoundary".} =
  ## S/carrier: the link it leaves on. body: one envelope.
  if carrier == acrDac:
    return sealAmeDacFrame(S, body)
  result = sealAmeTcpFrame(S, body)

proc sealSlowForward*(S: var AmeSession, carrier: AmeCarrier, target: uint64,
    payload: openArray[uint8], hopsLeft: uint8 = ameRouteDefaultHops,
    origin: uint64 = 0'u64): ByteSeq {.role: encryptor,
    tag: "appApi|cryptoBoundary".} =
  ## S/carrier: the link to the next hop (for a client: its relay).
  ## target: where it should end up. payload: what the target receives;
  ## every relay on the way can READ it. hopsLeft/origin: as in ART.
  result = sealSlowData(S, carrier, encodeSlowEnvelope(arkForward, hopsLeft,
    target, origin, payload))

proc sealSlowRefuse*(S: var AmeSession, carrier: AmeCarrier,
    target, origin: uint64, reason: AmeRouteRefusal): ByteSeq {.
    role: encryptor, tag: "cryptoBoundary".} =
  ## S/carrier: the link back toward the origin. target/origin: the refused
  ## forward. reason: why (never arrNone).
  if reason == arrNone:
    raise newException(ValueError, "relay refusal needs a reason")
  result = sealSlowData(S, carrier, encodeSlowEnvelope(arkRefuse,
    uint8(ord(reason)), target, origin, []))

proc openSlowFrame*(S: var AmeSession, carrier: AmeCarrier,
    A: openArray[uint8]): AmeRouteFrame {.role: decryptor,
    tag: "appApi|cryptoBoundary".} =
  ## S/carrier: the link it arrived on. A: one whole AME data frame.
  ## Never raises.
  var
    opened: AmeOpenResult = default(AmeOpenResult)
  try:
    opened = if carrier == acrDac: openAmeDacFrame(S, A)
             else: openAmeTcpFrame(S, A)
  except CatchableError as exc:
    return AmeRouteFrame(err: exc.msg)
  if not opened.ok:
    return AmeRouteFrame(err: opened.err)
  result = decodeSlowEnvelope(opened.packet.payload)

proc isAmeRouteAsk*(A: openArray[uint8]): bool {.role: parser,
    tag: "appApi".} =
  ## A: one datagram on a relaySlowExtractEncrypt link. True when its clear
  ## AME header says kind 0x14 -- a directory question, not an envelope.
  ## Needs no key; the frame is still authenticated when it is opened.
  try:
    result = decodeAmeFrame(A).header.packetKind == ampkRoute
  except CatchableError:
    result = false
