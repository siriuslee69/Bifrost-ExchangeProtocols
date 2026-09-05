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
## They travel as ordinary AME frames. Same 26-byte header as everything
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
import ../level1/suites
import ../level2/wire
import ../level2/session
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
  ## No frame flags: a handshake record is not padded by the frame layer.
  ## Nothing is keyed yet at this point, so there is no epoch policy to obey
  ## -- the padding that hides identity sizes happens INSIDE the sealed block
  ## instead, under the tunables the responder names in its own record.
  result = encodeAmeFrame(kind, amcControl, 0'u8, sessionId, 0'u32, 0'u32,
    step, record)

proc decodeAmeHandshakeFrame*(A: openArray[uint8]): AmeHandshakeFrame {.
    role: parser, tag: {tagAppApi, tagCodecBoundary, tagParsing}.} =
  ## A: one complete AME frame that should carry a handshake record.
  var
    f: AmeDecodedFrame = decodeAmeFrame(A)
  if not ameHandshakeKindValid(f.header.packetKind):
    raise newException(ValueError, "AME frame is not a handshake record")
  if f.header.messageClass != amcControl or f.header.flags != 0'u8 or
      f.header.sessionId == 0'u64 or
      f.header.rootLaneId != 0'u32 or
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

## ╭⟢ what each side needs before it can talk
##
## None of this is carrier-specific. A responder needs the paths it accepts,
## its own identity, and how it decides whom to believe; an initiator needs
## the path it wants and the same identity material. Which socket carries the
## records is decided by the driver, not by the policy, so both drivers take
## these same two objects.

type
  ## What a responder needs before it can answer anybody.
  AmeResponderPolicy* {.role: configurator.} = object
    supported*: seq[AmeTierPath]
    descriptor*: AmeIdentityCertificate
    identity*: AmeIdentityKey
    cookieSecret*: AmeCookieSecret
    requireCookie*: bool
      ## When true, a hello without a valid cookie is answered with a retry
      ## instead of a key exchange. Leave it on for anything reachable from an
      ## untrusted network; the cost is one extra round trip per connection.
      ##
      ## On a datagram carrier this is not really optional. Nothing proves a
      ## source address there, so a responder without a cookie will happily do
      ## post-quantum key work for packets that never came from anyone.
    trustMode*: AmeTrustMode
    root*: AmeAuthorityRoot
    expectedPeer*: AmePinnedPeerIdentity
    revokedSerials*: seq[uint64]
    params*: AmeRuntimeParams
    authentication*: AmeAuthentication

  ## What an initiator needs.
  AmeInitiatorPolicy* {.role: configurator.} = object
    layout*: AmeSuiteLayout
    initialTier*: AmeMaskTier
    descriptor*: AmeIdentityCertificate
    identity*: AmeIdentityKey
    trustMode*: AmeTrustMode
    root*: AmeAuthorityRoot
    expectedPeer*: AmePinnedPeerIdentity
    revokedSerials*: seq[uint64]
    authentication*: AmeAuthentication

  ## How a completed handshake reports itself, whatever carried it.
  AmeHandshakeOutcome* {.role: truthState.} = object
    ok*: bool
    connection*: AmeSession
    peerTrust*: AmePeerTrustResult
    err*: string

proc initAmeResponderPolicy*(supported: openArray[AmeTierPath],
    descriptor: AmeIdentityCertificate, identity: AmeIdentityKey,
    trustMode: AmeTrustMode = atmAuthorityCertificate,
    requireCookie: bool = true,
    params: AmeRuntimeParams = AmeRuntimeParams(authTagLen: aatl32)):
    AmeResponderPolicy {.role: wrapper.} =
  ## supported/descriptor/identity/trustMode/requireCookie/params: responder
  ## policy with a freshly minted anti-flood secret.
  if supported.len == 0:
    raise newException(ValueError, "AME responder must support at least one path")
  result.supported = @supported
  result.descriptor = descriptor
  result.identity = identity
  result.trustMode = trustMode
  result.requireCookie = requireCookie
  result.params = params
  result.cookieSecret = initAmeCookieSecret()

proc initAmeInitiatorPolicy*(L: AmeSuiteLayout, initialTier: AmeMaskTier,
    descriptor: AmeIdentityCertificate, identity: AmeIdentityKey,
    trustMode: AmeTrustMode = atmAuthorityCertificate):
    AmeInitiatorPolicy {.role: wrapper.} =
  ## L/initialTier/descriptor/identity/trustMode: initiator policy.
  validateAmeTier(L, initialTier)
  result.layout = L
  result.initialTier = initialTier
  result.descriptor = descriptor
  result.identity = identity
  result.trustMode = trustMode
