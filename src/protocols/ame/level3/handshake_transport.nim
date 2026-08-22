## -------------------------------------------------------------------------
## AME Handshake Transport <- handshake records inside ordinary AME frames
## -------------------------------------------------------------------------
##
## The four handshake records need to reach the far side somehow. Before this
## file existed they had encoders and decoders and nothing that put them on a
## wire, so every caller had to invent its own framing -- and a caller that
## got that wrong (reading half a record, say) had a security bug, not a
## cosmetic one.
##
## They travel as ordinary AME frames. Same 34-byte header as everything
## else, with a packet kind that says which record this is:
##
##   +--------------------------+--------------------------------+
##   | AME header, kind = 0x0C  | "AMC1" client hello record     |
##   +--------------------------+--------------------------------+
##   | AME header, kind = 0x0D  | "AMR1" hello retry record      |
##   +--------------------------+--------------------------------+
##   | AME header, kind = 0x0E  | "AMS1" server hello record     |
##   +--------------------------+--------------------------------+
##   | AME header, kind = 0x0F  | "AMF1" client finish record    |
##   +--------------------------+--------------------------------+
##
## These frames are NOT encrypted -- there are no session keys yet, which is
## the whole point of a handshake. They do not need to be: the server hello
## and the client finish each carry their own sealed block, and the header
## fields are repeated inside the record, so a header edited in flight makes
## the record fail to open.
##
## The sequence field counts the handshake steps: hello is 0, a retry is 1,
## the retried hello is 2, server hello is 3, finish is 4. A record arriving
## with the wrong step number is refused before it is parsed.

import ../../types
import ../types
import ../level2/wire
import ./handshake
import ./handshake_wire
import ../../../analysis_pragmas

const
  ameHandshakeStepHello* = 0'u32
  ameHandshakeStepRetry* = 1'u32
  ameHandshakeStepRetriedHello* = 2'u32
  ameHandshakeStepServerHello* = 3'u32
  ameHandshakeStepFinish* = 4'u32
  ameHandshakeMaxRecordBytes* = 8_388_608
    ## A hello carrying eight Classic-McEliece public keys is genuinely large.
    ## This bounds it well above that and far below anything that could be
    ## used to make a peer allocate without limit.

type
  ## One decoded handshake frame: which record it is, and its bytes.
  AmeHandshakeFrame* {.role: truthState.} = object
    kind*: AmePacketKind
    sessionId*: uint64
    step*: uint32
    record*: ByteSeq

proc ameHandshakeKindValid*(k: AmePacketKind): bool {.role: parser.} =
  ## k: is this packet kind one of the four handshake records?
  result = k in {ampkClientHello, ampkHelloRetry, ampkServerHello,
    ampkClientFinish}

proc encodeAmeHandshakeFrame*(kind: AmePacketKind, sessionId: uint64,
    step: uint32, record: openArray[uint8]): ByteSeq {.
    role: stateController, tag: {tagAppApi, tagCodecBoundary, tagWrite}.} =
  ## kind/sessionId/step/record: wrap one handshake record in an AME frame.
  if not ameHandshakeKindValid(kind):
    raise newException(ValueError, "AME handshake packet kind is invalid")
  if sessionId == 0'u64:
    raise newException(ValueError, "AME handshake session id must be positive")
  if record.len == 0 or record.len > ameHandshakeMaxRecordBytes:
    raise newException(ValueError, "AME handshake record length is invalid")
  result = encodeAmeFrame(kind, amcControl, sessionId, 0'u32, 0'u32, 0'u32,
    step, record)

proc decodeAmeHandshakeFrame*(A: openArray[uint8]): AmeHandshakeFrame {.
    role: parser, tag: {tagAppApi, tagCodecBoundary, tagParsing}.} =
  ## A: one complete AME frame that should carry a handshake record.
  var
    f: AmeDecodedFrame = decodeAmeFrame(A)
  if not ameHandshakeKindValid(f.header.packetKind):
    raise newException(ValueError, "AME frame is not a handshake record")
  if f.header.messageClass != amcControl or f.header.sessionId == 0'u64 or
      f.header.rootLaneId != 0'u32 or f.header.parentLaneId != 0'u32 or
      f.header.laneId != 0'u32:
    raise newException(ValueError, "AME handshake frame binding is invalid")
  if f.payload.len == 0 or f.payload.len > ameHandshakeMaxRecordBytes:
    raise newException(ValueError, "AME handshake record length is invalid")
  result.kind = f.header.packetKind
  result.sessionId = f.header.sessionId
  result.step = f.header.sequence
  result.record = f.payload

proc requireHandshakeFrame*(f: AmeHandshakeFrame, kind: AmePacketKind,
    step: uint32, sessionId: uint64 = 0'u64) {.role: parser,
    tag: {tagValidation}.} =
  ## f/kind/step/sessionId: refuse a record that is not the one expected next.
  ## Passing sessionId 0 means "any", used for the very first frame a server
  ## sees, where the client picks the id.
  if f.kind != kind:
    raise newException(ValueError, "AME handshake record is out of order")
  if f.step != step:
    raise newException(ValueError, "AME handshake step number is wrong")
  if sessionId != 0'u64 and f.sessionId != sessionId:
    raise newException(ValueError, "AME handshake session id changed")

proc encodeAmeClientHelloFrame*(h: AmeClientHello,
    retried: bool = false): ByteSeq {.role: stateController,
    tag: {tagAppApi, tagWrite}.} =
  ## h/retried: the client's first frame, or the same hello sent again with
  ## the cookie the server asked for.
  var
    step: uint32 = ameHandshakeStepHello
  if retried:
    step = ameHandshakeStepRetriedHello
  result = encodeAmeHandshakeFrame(ampkClientHello, h.sessionId, step,
    encodeAmeClientHello(h))

proc encodeAmeHelloRetryFrame*(r: AmeHelloRetry): ByteSeq {.
    role: stateController, tag: {tagAppApi, tagWrite}.} =
  ## r: the server's cookie challenge.
  result = encodeAmeHandshakeFrame(ampkHelloRetry, r.sessionId,
    ameHandshakeStepRetry, encodeAmeHelloRetry(r))

proc encodeAmeServerHelloFrame*(sessionId: uint64,
    h: AmeServerHello): ByteSeq {.role: stateController,
    tag: {tagAppApi, tagWrite}.} =
  ## sessionId/h: the server's answer plus its sealed identity.
  result = encodeAmeHandshakeFrame(ampkServerHello, sessionId,
    ameHandshakeStepServerHello, encodeAmeServerHello(h))

proc encodeAmeClientFinishFrame*(sessionId: uint64,
    f: AmeClientFinish): ByteSeq {.role: stateController,
    tag: {tagAppApi, tagWrite}.} =
  ## sessionId/f: the client's sealed identity and transcript confirmation.
  result = encodeAmeHandshakeFrame(ampkClientFinish, sessionId,
    ameHandshakeStepFinish, encodeAmeClientFinish(f))
