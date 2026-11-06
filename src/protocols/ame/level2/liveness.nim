## -------------------------------------------------------------------------
## AME Liveness <- "are you still there?", and closing a link that went quiet
## -------------------------------------------------------------------------
##
## A link stays open as long as both ends hold its keys. A phone that walked
## out of range never says goodbye, so the other end would hold those keys
## for ever. This file lets one end (usually the server) ask, and give up:
##
##   server                                          client
##   ------                                          ------
##   nothing heard for `quietMs`
##   ping n   ── AME 0x09, sealed by the ratchet ──▶  answerAmePing
##                                                     |
##   heard    ◀── AME 0x0A, sealed, same n ──────────  pong n
##
##   no answer, `missLimit` pings in a row
##   clearAmeSession: every key of the link erased, the link is closed
##
## ╭─ ❧ Def. 1: ping (kind 0x09) and pong (kind 0x0A) 🌊
##
##   inside the sealed plaintext, both kinds alike
##   offset  size  field
##   0       4     probe number, u32 LE. A pong repeats the number it answers.
##
## Both ride the session's ratchet like every other control frame, so a pong
## proves the peer still holds the keys. A forged pong does not open.
##
## ╭─ ❧ Def. 2: the timeline, quietMs = 15 000, missLimit = 3 🐦‍🔥
##
##   time (s)   0          15         30         45         60
##              |----------|----------|----------|----------|
##              last frame ping 0     ping 1     ping 2     close, keys erased
##              heard
##
##   Any frame that opens counts as heard, not only a pong: a busy link is
##   never probed. Hearing anything resets the count of unanswered pings.
##
## ╭─ ❧ Def. 3: who calls what 🍣
##
##   every authenticated frame from the peer   noteAmeHeard(L, now)
##   a timer, every second or so               stepAmeLiveness(S, L, ...)
##                                               -> send `frame` if not empty
##                                               -> on alsClose drop the socket
##   a frame of kind 0x09 or 0x0A arrives      handleAmeLivenessFrame(...)
##                                               -> send `reply` if not empty
##
## Nothing here touches a socket; the caller sends the bytes it is handed.
## Both ends may run the tracker. Usually only the server does, and the
## client just answers.

import ../../types
import ../../config
import ../types
import ../level0/bytes
import ./wire
import ./seal_open
import ./epochs
import runePragmas
import var_invariants

const
  ameLivenessBodyLen* = 4
    ## probe number u32 (Def. 1)

type
  AmeLivenessStep* = enum
    alsWait,
      ## nothing to do yet
    alsProbe,
      ## send the ping in `frame`
    alsClose
      ## too many pings went unanswered; the session's keys are erased

  AmeLiveness* {.role: truthState, tag: "ame|lifecycle|types",
      expectedCount: [0, -1], lifeCycle: lcSession.} = object
    ## The tracker for ONE link. One per open connection on a server.
    quietMs*: uint64
      ## how long nothing may be heard before a ping goes out
    missLimit*: int
      ## how many pings in a row may go unanswered before the link closes
    lastHeardMs*: uint64
    lastProbeMs*: uint64
    unanswered*: int
    nextNumber*: uint32

  AmeLivenessFrameStep* = enum
    alfNone,
      ## not a ping or a pong: open it as anything else
    alfAnswered,
      ## the peer asked; `reply` is the pong to send
    alfHeard,
      ## the peer answered our ping
    alfRefused
      ## a ping or pong that did not open; nothing changed

  AmeLivenessOutcome* {.role: preparedData, tag: "ame|lifecycle|types".} = tuple
    ## What one timer step did. `frame` is non-empty only on alsProbe.
    step: AmeLivenessStep
    frame: ByteSeq

  AmeLivenessFrameOutcome* {.role: preparedData,
      tag: "ame|lifecycle|types".} = tuple
    ## What one incoming ping or pong did. `reply` only on alfAnswered.
    step: AmeLivenessFrameStep
    reply: ByteSeq
    err: string

proc initAmeLiveness*(nowMs: uint64,
    quietMs: uint64 = currentBifrostConfig().ameLivenessQuietMs,
    missLimit: int = currentBifrostConfig().ameLivenessMisses): AmeLiveness {.
    role: configurator, tag: "appApi|lifecycle",
    needs: quietMs > 0'u64 and missLimit > 0.} =
  ## nowMs: the time the link opened, in milliseconds.
  ## quietMs/missLimit: Def. 2; the defaults come from [runtime.ame].
  result.quietMs = quietMs
  result.missLimit = missLimit
  result.lastHeardMs = nowMs
  result.lastProbeMs = 0'u64
  result.unanswered = 0
  result.nextNumber = 0'u32

proc noteAmeHeard*(L: var AmeLiveness, nowMs: uint64) {.role: actor,
    tag: "appApi|lifecycle".} =
  ## L/nowMs: a frame from the peer opened. The link is alive.
  L.lastHeardMs = nowMs
  L.unanswered = 0

proc lastAmeActivity(L: AmeLiveness): uint64 {.role: parser, inline.} =
  ## L: the later of "heard something" and "sent a ping".
  result = max(L.lastHeardMs, L.lastProbeMs)

proc tickAmeLiveness*(L: AmeLiveness, nowMs: uint64): AmeLivenessStep {.
    role: parser, tag: "appApi|lifecycle".} =
  ## L/nowMs: what the timer should do now (Def. 2). Changes nothing.
  ## A clock that went backwards counts as "no time passed".
  var
    quietFor: uint64 = 0'u64
  if nowMs > lastAmeActivity(L):
    quietFor = nowMs - lastAmeActivity(L)
  if quietFor < L.quietMs:
    return alsWait
  if L.unanswered >= L.missLimit:
    return alsClose
  result = alsProbe

proc sealAmePing*(S: var AmeSession, carrier: AmeCarrier,
    number: uint32): ByteSeq {.role: orchestrator, tag: "appApi|lifecycle".} =
  ## S/carrier/number: one ping (Def. 1). Raises while the session must stay
  ## silent (an exchange is half done); the caller simply tries later.
  var
    body: ByteSeq = @[]
  requireAmeMaySend(S, ampkPing)
  appendAmeU32(body, number)
  result = sealControlFrame(S, ampkPing, carrier, body)

proc sealAmePong(S: var AmeSession, carrier: AmeCarrier,
    number: uint32): ByteSeq {.role: orchestrator, tag: "lifecycle".} =
  ## S/carrier/number: the answer to ping `number`.
  var
    body: ByteSeq = @[]
  appendAmeU32(body, number)
  result = sealControlFrame(S, ampkPong, carrier, body)

proc openLivenessBody(S: var AmeSession, frame: openArray[uint8],
    kind: AmePacketKind, carrier: AmeCarrier): tuple[ok: bool,
    number: uint32, err: string] {.role: parser, tag: "lifecycle".} =
  ## S/frame/kind/carrier: one ping or pong opened; its probe number.
  var
    opened: tuple[ok: bool, payload: ByteSeq, err: string] = (ok: false,
      payload: @[], err: "")
  opened = openControlFrame(S, frame, kind, carrier)
  if not opened.ok:
    return (false, 0'u32, opened.err)
  if opened.payload.len != ameLivenessBodyLen:
    return (false, 0'u32, "AME ping or pong has the wrong length")
  result = (true, readU32(opened.payload, 0), "")

proc answerAmePing*(S: var AmeSession, carrier: AmeCarrier,
    frame: openArray[uint8]): ByteSeq {.role: orchestrator,
    tag: "appApi|lifecycle".} =
  ## S/carrier/frame: a ping from the peer. Returns the pong to send.
  ## Raises when the ping does not open.
  var
    opened: tuple[ok: bool, number: uint32, err: string] = (ok: false,
      number: 0'u32, err: "")
  opened = openLivenessBody(S, frame, ampkPing, carrier)
  if not opened.ok:
    raise newException(ValueError, opened.err)
  result = sealAmePong(S, carrier, opened.number)

proc pongAnswersAmeProbe(L: AmeLiveness, number: uint32): bool {.role: parser,
    inline.} =
  ## L/number: true when `number` is a ping this tracker has sent.
  result = number < L.nextNumber

proc openAmePong*(S: var AmeSession, L: var AmeLiveness, carrier: AmeCarrier,
    frame: openArray[uint8], nowMs: uint64): tuple[ok: bool, err: string] {.
    role: orchestrator, tag: "appApi|lifecycle".} =
  ## S/L/carrier/frame/nowMs: a pong from the peer. On `ok` the link counts
  ## as heard. A pong for a ping never sent is refused.
  var
    opened: tuple[ok: bool, number: uint32, err: string] = (ok: false,
      number: 0'u32, err: "")
  opened = openLivenessBody(S, frame, ampkPong, carrier)
  if not opened.ok:
    return (false, opened.err)
  if not pongAnswersAmeProbe(L, opened.number):
    return (false, "AME pong answers no ping that was sent")
  noteAmeHeard(L, nowMs)
  result = (true, "")

proc livenessPacketKind(A: openArray[uint8]): AmePacketKind {.role: parser.} =
  ## A: one frame; its packet kind, or ampkUnknown when it is not AME at all.
  try:
    result = decodeAmeFrameHeader(A).packetKind
  except CatchableError:
    result = ampkUnknown

proc answerOrRefuse(S: var AmeSession, carrier: AmeCarrier,
    frame: openArray[uint8]): AmeLivenessFrameOutcome {.role: orchestrator,
    tag: "lifecycle".} =
  ## S/carrier/frame: a ping; the pong, or why it was refused.
  try:
    result = (alfAnswered, answerAmePing(S, carrier, frame), "")
  except CatchableError as exc:
    result = (alfRefused, @[], exc.msg)

proc heardOrRefuse(S: var AmeSession, L: var AmeLiveness, carrier: AmeCarrier,
    frame: openArray[uint8], nowMs: uint64): AmeLivenessFrameOutcome {.
    role: orchestrator, tag: "lifecycle".} =
  ## S/L/carrier/frame/nowMs: a pong; heard, or why it was refused.
  var
    opened: tuple[ok: bool, err: string] = (ok: false, err: "")
  opened = openAmePong(S, L, carrier, frame, nowMs)
  if opened.ok:
    return (alfHeard, @[], "")
  result = (alfRefused, @[], opened.err)

proc handleAmeLivenessFrame*(S: var AmeSession, L: var AmeLiveness,
    carrier: AmeCarrier, frame: openArray[uint8],
    nowMs: uint64): AmeLivenessFrameOutcome {.role: orchestrator,
    tag: "appApi|lifecycle".} =
  ## S/L/carrier/frame/nowMs: one incoming frame. Returns alfNone for
  ## anything that is not a ping or a pong, so a caller can try this first
  ## and fall through to data. Nothing here raises.
  result = (alfNone, @[], "")
  case livenessPacketKind(frame)
  of ampkPing:
    result = answerOrRefuse(S, carrier, frame)
  of ampkPong:
    result = heardOrRefuse(S, L, carrier, frame, nowMs)
  else:
    discard

proc probeOrWait(S: var AmeSession, L: var AmeLiveness, carrier: AmeCarrier,
    nowMs: uint64): AmeLivenessOutcome {.role: orchestrator,
    tag: "lifecycle".} =
  ## S/L/carrier/nowMs: seal the next ping. A session that must stay silent
  ## right now (an exchange half done) is asked again on the next step; that
  ## ping is not counted as unanswered.
  try:
    result = (alsProbe, sealAmePing(S, carrier, L.nextNumber))
  except CatchableError:
    return (alsWait, @[])
  L.nextNumber = L.nextNumber + 1'u32
  L.unanswered = L.unanswered + 1
  L.lastProbeMs = nowMs

proc stepAmeLiveness*(S: var AmeSession, L: var AmeLiveness,
    carrier: AmeCarrier, nowMs: uint64): AmeLivenessOutcome {.
    role: orchestrator, tag: "appApi|lifecycle|cryptoBoundary".} =
  ## S/L/carrier/nowMs: one timer step (Def. 2 and 3). On alsProbe send
  ## `frame`; on alsClose the session's keys are already erased and the
  ## caller drops the connection.
  result = (alsWait, @[])
  case tickAmeLiveness(L, nowMs)
  of alsWait:
    discard
  of alsProbe:
    result = probeOrWait(S, L, carrier, nowMs)
  of alsClose:
    clearAmeSession(S)
    result = (alsClose, @[])
