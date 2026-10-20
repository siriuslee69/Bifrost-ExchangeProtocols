## -------------------------------------------------------------------------
## AME Lane Jump <- getting a stuck lane moving again, without a new session
## -------------------------------------------------------------------------
##
## FOMKE refuses a message that sits further ahead of its lane than the
## reorder window (fomke/level1/jump.nim explains why). After a burst of
## losses that wide, every later message on that lane is refused too. Each
## side has its OWN send lane, though, so the stuck side can still talk:
##
##   phone (receiver, stuck on the nas's lane)         nas (sender)
##   -----------------------------------------         ------------
##   frame refused, S.laneBehind = true
##   sealAmeJumpAsk ── AME 0x15, sealed on the ──────▶  answerAmeJumpAsk
##                    PHONE'S lane, which works           |
##                                                        v
##   openAmeJump  ◀── AME 0x16, proved with JK ──────── sealAmeJump
##   lane moved to the nas's next index
##   next nas frame ─────────────────────────────────▶ opens
##
## `laneBehind` is set BEFORE any tag is checked, so a forged frame can set
## it. That is harmless: the ask is authenticated, and the jump only moves
## the lane to where the real sender says it is. A sender may also send a
## jump without being asked (after a burst its transport reported).
##
## ╭─ ❧ Def. 1: the ask (kind 0x15), inside the sealed plaintext 🌊
##
##   offset  size  field
##   0       8     where the asker's copy of the peer's lane stands, u64 LE
##
## ╭─ ❧ Def. 2: the jump (kind 0x16), NOT sealed by the ratchet 🐦‍🔥
##
##   AME header (26, class Control, sequence masked as on every frame)
##   offset  size  field
##   0       4     epoch, u32 LE
##   4       1     lane (1 or 2) -- the SENDER's lane
##   5       4     jump number, u32 LE
##   9       8     next index on that lane, u64 LE
##   17      32    tag: BLAKE3-keyed under JK(epoch, lane, number) over
##                 the fields above AND the AME header (carrier byte + the
##                 26 header bytes with the true sequence)
##
## Nothing in it is secret -- it is a position -- so it is proved, not
## hidden. It cannot use the ratchet: the ratchet is what is stuck.
##
## Example 1. The nas has sent up to message 401 on lane 2; the phone stopped
## following at 100:
##
##   phone -> nas   AME 0x15 [ 64 00 00 00 00 00 00 00 ]        "I am at 100"
##   nas -> phone   AME 0x16 [ 01 00 00 00 | 02 | 00 00 00 00 |
##                             92 01 00 00 00 00 00 00 | tag ]  "next is 402"
##   phone          JK(epoch 1, lane 2, number 0) from TK, tag checks,
##                  lane 2: 100 -> 402, held keys dropped, JK erased

import ../../types
import ../types
import ../level0/bytes
import ../../fomke/types
import ../../fomke/level1/chain
import ../../fomke/level1/jump
import ./wire
import ./seal_open
import runePragmas

const
  ameJumpBodyLen* = 17 + fomkeJumpTagBytes
    ## epoch 4 + lane 1 + number 4 + index 8 + tag 32 = 49

proc ameSessionBehind*(S: AmeSession): bool {.role: parser, tag: "appApi".} =
  ## S: true when the last refused frame looked like a gap too wide for the
  ## reorder window. Time to `sealAmeJumpAsk`. A hint only (see above).
  result = S.laneBehind

proc inboundIndex(S: AmeSession): uint64 {.role: parser.} =
  ## S: where this side's copy of the peer's lane stands.
  if inboundFomkeLane(S.fomke.role) == flLane1:
    return S.fomke.lane1.nextIndex
  result = S.fomke.lane2.nextIndex

proc sealAmeJumpAsk*(S: var AmeSession, carrier: AmeCarrier): ByteSeq {.
    role: orchestrator, tag: "appApi".} =
  ## S/carrier: the stuck side asks the peer to prove where its lane is.
  ## Sealed on this side's own lane (Def. 1). Safe to send again if no
  ## jump came back.
  var
    body: ByteSeq = @[]
  appendAmeU64(body, inboundIndex(S))
  result = sealControlFrame(S, ampkJumpAsk, carrier, body)

proc encodeJumpBody(J: FomkeJump): ByteSeq {.role: dataWriter.} =
  ## J: Def. 2, without the header.
  appendAmeU32(result, J.epoch)
  result.add(uint8(ord(J.lane)))
  appendAmeU32(result, J.number)
  appendAmeU64(result, J.index)
  appendAmeBytes(result, J.tag)

proc decodeJumpBody(A: openArray[uint8]): FomkeJump {.role: parser.} =
  ## A: exactly 49 bytes (Def. 2).
  if A.len != ameJumpBodyLen:
    raise newException(ValueError, "AME jump has the wrong length")
  if A[4] != uint8(ord(flLane1)) and A[4] != uint8(ord(flLane2)):
    raise newException(ValueError, "AME jump names no lane")
  result.epoch = readU32(A, 0)
  result.lane = FomkeLane(A[4])
  result.number = readU32(A, 5)
  result.index = readAmeU64(A, 9)
  result.tag = @(A.toOpenArray(17, ameJumpBodyLen - 1))

proc sealAmeJump*(S: var AmeSession, carrier: AmeCarrier): ByteSeq {.
    role: orchestrator, tag: "appApi".} =
  ## S/carrier: the sender of a lane proves where that lane stands (Def. 2).
  ## Uses up one jump number whether or not it arrives.
  var
    h: AmeFrameHeader = default(AmeFrameHeader)
    aad: ByteSeq = @[]
    J: FomkeJump = default(FomkeJump)
  requireAmeAuth(S.auth)
  requireAmePeerTrust(S)
  requireAmeMaySend(S, ampkJump)
  if S.nextAmeSequence == high(uint32):
    raise newException(ValueError, "AME send sequence is exhausted")
  h = initAmeFrameHeader(ampkJump, amcControl, 0'u8, S.sessionId,
    S.rootLaneId, S.laneId, S.nextAmeSequence)
  aad = buildAad(carrier, h)
  J = sealFomkeJump(S.fomke, aad)
  result = encodeProtectedFrame(S, h, encodeJumpBody(J))
  S.nextAmeSequence = S.nextAmeSequence + 1'u32

proc answerAmeJumpAsk*(S: var AmeSession, carrier: AmeCarrier,
    frame: openArray[uint8]): ByteSeq {.role: orchestrator, tag: "appApi".} =
  ## S/carrier: the sender of the lane the peer cannot follow.
  ## frame: the peer's ask (kind 0x15). Returns the jump to send back.
  var
    opened: tuple[ok: bool, payload: ByteSeq, err: string] = (ok: false,
      payload: @[], err: "")
  opened = openControlFrame(S, frame, ampkJumpAsk, carrier)
  if not opened.ok:
    raise newException(ValueError, opened.err)
  if opened.payload.len != 8:
    raise newException(ValueError, "AME jump ask has the wrong length")
  result = sealAmeJump(S, carrier)

proc acceptJumpSequence(S: var AmeSession, carrier: AmeCarrier,
    sequence: uint32): string {.role: actor.} =
  ## S/carrier/sequence: the frame counter of a jump that already proved
  ## itself, run through the same order checks as every other frame.
  if carrier == acrTcp and sequence != S.tcpRecvSequence:
    return "AME jump receive sequence mismatch"
  if carrier == acrDac and not replayAccept(S.dacAmeReplay, sequence):
    return "AME jump replay rejected"
  if carrier == acrTcp:
    S.tcpRecvSequence = S.tcpRecvSequence + 1'u32

proc openAmeJump*(S: var AmeSession, carrier: AmeCarrier,
    frame: openArray[uint8]): FomkeJumpResult {.role: orchestrator,
    tag: "appApi".} =
  ## S/carrier: the side whose copy of the peer's lane is stuck.
  ## frame: one AME frame of kind 0x16. Nothing here raises; on `ok` the
  ## lane has moved and `gaveUp` messages can never be opened.
  var
    f: AmeDecodedFrame = default(AmeDecodedFrame)
    J: FomkeJump = default(FomkeJump)
    aad: ByteSeq = @[]
  try:
    result.err = amePeerTrustError(S)
    if result.err.len > 0:
      return
    f = decodeProtectedFrame(S, frame)
    result.err = controlBindingError(S, f, ampkJump)
    if result.err.len > 0:
      return
    J = decodeJumpBody(f.payload)
    aad = buildAad(carrier, f.header)
    result = openFomkeJump(S.fomke, J, aad, S.fomkeMaxJump)
    if not result.ok:
      return
    result.err = acceptJumpSequence(S, carrier, f.header.sequence)
    result.ok = result.err.len == 0
    S.laneBehind = false
  except CatchableError as exc:
    result = FomkeJumpResult(err: exc.msg)
