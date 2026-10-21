## -------------------------------------------------------------------------
## AME Session <- starting a connection, and reading what it is
## -------------------------------------------------------------------------
##
## A session is one conversation's state. The state itself and how its keys
## change live in `epochs.nim`; this file is the rest:
##
##   starting       initAmeSession, from a finished handshake
##   reading        pending, info, stack depth, skipped messages
##   the path       what the DAC path profile says to send with
##   the settings   padding, tag length, runtime parameters
##
##   session.nim  --imports and passes on-->  epochs.nim
##
## What it does NOT own is what a message LOOKS LIKE: that is `framing.nim`.
## It opens no socket either. The two carrier modules under
## `level2/carriers/` do that, so a build keeps only the network stack it
## uses. See `protocols/ame` for the build flags.

import protocols/containers/circ_seq as circ_seq

import ../../types
import ../types
import ../level1/secret_stack
import ../level1/suites
import ../level1/path_triggers
import ../level1/padding
import ../../fomke/types
import ../../fomke/level0/xhkdf
import ../../fomke/level1/chain
import ../../fomke/level2/wire
import ../../config
import ../../dac/types
import ../../dac/level0/defaults as dac_defaults
import runePragmas
import ./epochs

export epochs

## ╭⟢ what the path profile says this session should send with
##
## The session records which DAC path profile it is running over. That byte
## used to be written and never read, which made it look as though the
## parameter feedback existed when it did not.
##
## What it decides, and what it must never decide:
##
##   follows the path   chunk size, repair mode and strength, ACK batching,
##                      repair timeouts -- how the bytes are shaped
##   never follows it   which algorithms are switched on, tag length,
##                      padding policy -- how the bytes are protected
##
## The second row is the important one. Loss is something an attacker on the
## path can cause at will. If padding switched off on a "thin" profile, an
## attacker would induce loss and get message lengths back -- exactly what
## the padding is there to hide. So cipher strength, tag length and padding
## stay where the handshake and the caller put them, whatever the link does.

proc dacTransferClassFor(c: AmeMessageClass): DacTransferClass {.role: parser.} =
  ## c: what the session says its traffic is, named the way DAC names it.
  case c
  of amcStatus, amcTelemetry: result = dtcStatus
  of amcControl, amcProfile: result = dtcControl
  else: result = dtcUserData

proc ameSessionPathDefaults*(S: AmeSession): DacScenarioDefaults {.
    role: parser, tag: "appApi|protocol".} =
  ## S: session whose recorded path profile becomes a full parameter set.
  ## One preset per lane, so reading this is a complete validated set rather
  ## than a handful of fields a caller has to keep consistent by hand.
  result = dac_defaults.dacDefaultsForPath(S.pathLane,
    dacTransferClassFor(S.messageClass))

proc ameSessionSkippedMessages*(S: AmeSession): int {.role: parser,
    tag: "appApi|fomke|protocol".} =
  ## S: how many jumped-over messages the ratchet is still holding keys for.
  result = fomkeSkippedMessages(S.fomke)

proc discardAmeSessionSkipped*(S: var AmeSession): int {.
    role: actor,
    tag: "appApi|cryptoBoundary|fomke|protocol".} =
  ## S: give up on the messages this side jumped over, and say how many.
  ##
  ## A rotation refuses to run while any of them are outstanding, so a link
  ## that loses packets for good will eventually be unable to rekey. Call
  ## this first when `ameSessionSkippedMessages` stops going down and the
  ## messages behind it are not worth waiting for any longer. The keys are
  ## erased, so those messages can never be opened afterwards.
  result = discardFomkeSkipped(S.fomke)
  clearFomkeSendCache(S.fomkeSendCache)
  restoreConfiguredAmeFomkeCache(S)

proc amePeerTrustError*(S: AmeSession): string {.role: parser.} =
  ## S: connection whose trust gate is checked.
  if not S.peerTrustRequired or S.peerTrust.ok:
    return ""
  if S.peerTrust.err.len > 0:
    return "AME peer trust not established: " & S.peerTrust.err
  result = "AME peer trust not established"

proc requireAmePeerTrust*(S: AmeSession) {.role: parser.} =
  ## S: connection whose required trust must be present.
  var err: string = amePeerTrustError(S)
  if err.len > 0:
    raise newException(ValueError, err)

proc setAmeInbox*(S: var AmeSession, capacity: int) {.role: actor,
    tag: "appApi".} =
  ## S: connection whose inbox is replaced; queued packets are dropped.
  ## capacity: n slots reserved, `ameInboxGrowing` (0) or `ameNoInbox` (-1).
  if capacity < ameNoInbox:
    raise newException(ValueError, "AME inbox capacity must be -1 or more")
  S.keepsInbox = capacity != ameNoInbox
  S.inbox = circ_seq.initCircSeq[AmePacket](max(capacity, 0))

proc initAmeSession*(a: AmeAuthPackage,
    path: AmeTierPath, sessionId: uint64 = 0'u64,
    rootLaneId: uint32 = 1'u32, laneId: uint32 = 5'u32,
    pathLane: DacPathLane = dplCleanPath,
    messageClass: AmeMessageClass = amcUserdata,
    inboxCapacity: int = currentBifrostConfig().defaultAmeInboxCapacity,
    peerTrustRequired: bool = currentBifrostConfig().peerTrustRequired,
    peerTrust: AmePeerTrustResult = default(AmePeerTrustResult)):
    AmeSession {.role: orchestrator.} =
  ## a/path/session/lane/runtime: exact connection configuration.
  var
    runtime: BifrostConfig = default(BifrostConfig)
  requireAmeAuth(a)
  if a.sessionId == 0'u64:
    raise newException(ValueError, "AME authenticated session id is missing")
  if a.current.transcriptSalt.len > 0 and sessionId != 0'u64 and
      sessionId != a.sessionId:
    raise newException(ValueError,
      "AME live session id differs from the authenticated session")
  if not layoutsEquivalent(a.current.layout, path.layout):
    raise newException(ValueError, "AME tier path layout differs from auth layout")
  result.auth = a
  result.pendingParams = a.current.params
  if sessionId != 0'u64:
    result.auth.sessionId = sessionId
  result.path = path
  result.sessionId = result.auth.sessionId
  result.rootLaneId = rootLaneId

  result.laneId = laneId
  result.pathLane = pathLane
  result.messageClass = messageClass
  result.peerTrustRequired = peerTrustRequired
  result.peerTrust = peerTrust
  setAmeInbox(result, inboxCapacity)
  setCurrentAmeTier(result.path, result.auth.current.tier)
  runtime = currentBifrostConfig()
  ## The ratchet is started here, from the finished exchange and from the
  ## handshake transcript that produced it. Binding the transcript means two
  ## sessions that negotiated different things can never derive the same keys
  ## even if every KEM secret somehow matched.
  ##
  ## How many out-of-order message keys a lane may hold comes from the config
  ## (`fomkeReorderCeiling`), so a lossy link can be given more room without
  ## a rebuild.
  result.fomke = initFomkeFromAme(result.auth.current.exchange,
    result.auth.current.layout, result.auth.current.tier,
    fomkeRoleFor(result.auth.endpointRole),
    result.auth.current.transcriptSalt,
    initXhkdfConfig(branches = xhkdfBranchesOf(result.auth.current.layout,
      result.auth.current.tier)), runtime.fomkeReorderCeiling,
    result.auth.current.params.authTagLen)
  refreshAmeFrameKeys(result)
  result.fomkePregenerationEnabled = fomkePregenerationEnabled(runtime)
  result.fomkePregenerationMessages = runtime.fomkePregenerationMessages
  result.fomkeMaxJump = runtime.fomkeMaxJump
  if result.fomkePregenerationEnabled:
    result.fomkeSendCache = prepareFomkeSendCache(result.fomke,
      result.fomkePregenerationMessages)

proc initAmeSession*(a: AmeAuthPackage,
    sessionId: uint64 = 0'u64, rootLaneId: uint32 = 1'u32,
    laneId: uint32 = 5'u32, pathLane: DacPathLane = dplCleanPath,
    messageClass: AmeMessageClass = amcUserdata,
    inboxCapacity: int = currentBifrostConfig().defaultAmeInboxCapacity,
    peerTrustRequired: bool = currentBifrostConfig().peerTrustRequired,
    peerTrust: AmePeerTrustResult = default(AmePeerTrustResult)):
    AmeSession {.role: configurator.} =
  ## a/session/lane/runtime: exact auth package with default AME triggers.
  var path: AmeTierPath = default(AmeTierPath)
  path = initAmeTierPath(a.current.layout, [a.current.tier])
  result = initAmeSession(a, path, sessionId, rootLaneId, laneId, pathLane,
    messageClass, inboxCapacity, peerTrustRequired, peerTrust)

proc ameSessionKey*(S: AmeSession): ByteSeq {.role: truthBuilder,
    tag: "appApi|cryptoBoundary".} =
  ## S: a live session. Returns the 32 bytes to keep for the NEXT AM1P
  ## handshake with the same peer (see `withAmeSessionKey`). Both sides
  ## call this at the same epoch and get the same bytes.
  ##
  ##   session A ends ──▶ keep ameSessionKey(A)
  ##   session B starts ──▶ withAmeSessionKey(auth, kept) ──▶ handshake
  result = fomkeSessionKey(S.fomke)

proc pending*(S: AmeSession): int {.role: parser.} =
  ## S: connection whose parsed inbox count is returned.
  result = circ_seq.len(S.inbox)

proc inboxCapacity*(S: AmeSession): int {.role: parser.} =
  ## S: connection whose inbox capacity is returned.
  result = circ_seq.capacity(S.inbox)

proc recv*(S: var AmeSession, p: var AmePacket): bool {.
    role: actor.} =
  ## S/p: connection inbox and destination packet.
  result = circ_seq.pop(S.inbox, p)

proc recordTransferredBytes*(S: var AmeSession, n: uint64): AmeTierStep {.
    role: actor.} =
  ## S/n: connection and newly successful plaintext transfer bytes.
  result = feedTransferredBytes(S.path, n)
  S.lastTrigger = result

proc feedAmeElapsedMs*(S: var AmeSession, elapsedMs: uint64): AmeTierStep {.
    role: actor.} =
  ## S/elapsedMs: connection and monotonic elapsed clock.
  result = feedElapsedMs(S.path, elapsedMs)
  S.lastTrigger = result

proc requestAmeTier*(S: var AmeSession, tierId: uint32,
    rekeyMask: int = -1): AmeTierStep {.
    role: actor, tag: "appApi|exchange".} =
  ## S/tierId: exact target tier.
  ## rekeyMask: which already-active KEM slots must run a NEW exchange. Left
  ## alone it is every slot the current tier uses, which is what makes the
  ## secret stack deeper; see `requestTier` for the three cases and for why the
  ## expensive one is the default.
  result = requestTier(S.path, tierId, rekeyMask)
  S.lastTrigger = result

proc ameSessionStackDepth*(S: AmeSession): uint32 {.role: parser,
    tag: "appApi|exchange".} =
  ## S: how many exchanges the SHALLOWEST KEM slot this session's tier uses has
  ## absorbed. One rotation with the default rekey mask raises it by one.
  ##
  ## The shallowest, not the average and not the deepest, because an attacker
  ## picks which slot to work on and the defender does not. A tier running a
  ## slot six exchanges deep beside one that has run once is one deep.
  ##
  ## Takes no mask, deliberately. `ameStackDepth` takes one because it has to,
  ## and handing it the wrong one gives a confident wrong answer rather than an
  ## error -- which is the wrong shape for a number somebody is going to trust.
  result = ameStackDepth(S.auth.current.exchange,
    S.auth.current.tier.masks.kem)

## ╭⟢ runtime parameters
##
## AME exposes its tunables here rather than holding a policy of its own.
## Something above it - the DAC observer, or a caller with its own opinion -
## writes them per connection. AME only enforces that both endpoints agree,
## which it gets for free by binding the values into every tag.

proc ameParams*(S: AmeSession): AmeRuntimeParams {.role: parser.} =
  ## S: session whose current epoch tunables are read back.
  result = S.auth.current.params

proc nextAmeParams*(S: AmeSession): AmeRuntimeParams {.role: parser.} =
  ## S: session whose STAGED tunables are read back. These are what the next
  ## exchange this endpoint initiates will ask the peer to adopt.
  result = S.pendingParams

proc setAmeAuthTagLen*(S: var AmeSession, n: AmeAuthTagLen) {.
    role: configurator.} =
  ## S/n: session and the tag length its next epoch should carry.
  ##
  ## Staged, not applied. A live epoch's tags are bound to the length it was
  ## created with, so switching underneath one would break every message
  ## until the peer caught up. The value rides in the next exchange request
  ## this endpoint sends; the responder adopts it, and both rotate together.
  ## Until then nothing changes on the wire.
  ##
  ## Shorter tags trade authentication strength for bytes. 32 is 256-bit and
  ## the default; 16 is the conventional 128-bit floor, worth it when a
  ## payload is a handful of bytes and the tag dominates the frame.
  S.pendingParams.authTagLen = n

proc setAmePadding*(S: var AmeSession, p: AmePaddingPolicy) {.
    role: configurator.} =
  ## S/p: session and the padding its next epoch should apply.
  ##
  ## Staged like the tag length, and for the same reason: the padded flag is
  ## bound into every tag, so a value that changed underneath a live epoch
  ## would fail to open rather than take effect.
  ##
  ## Off by default. Padding costs 1 to 64 bytes on EVERY frame, which is
  ## real money on a link that carries small messages, and the length of a
  ## frame that was never compressed is a weak signal on its own. Switch it
  ## on when traffic analysis is part of the threat -- when message sizes
  ## would say what a command was, or who is typing.
  S.pendingParams.padding = p

proc ameFrameOverheadBytes*(S: AmeSession): int {.role: parser.} =
  ## S: session whose worst-case per-frame overhead is returned: the fixed
  ## header, the ratchet envelope and tag, and the largest padding this
  ## epoch can add. A caller sizing datagrams against a link MTU subtracts
  ## this from the MTU to get the plaintext it may hand over at once.
  result = ameFrameHeaderLen + fomkeWireLen(0, S.fomke.tagLen) +
    amePaddingBlock(S.auth.current.params.padding)

proc info*(S: AmeSession): AmeSessionInfo {.role: truthBuilder.} =
  ## S: connection summarized by stable tier identity and masks.
  result.layoutBytes = encodeAmeSuiteLayout(S.auth.current.layout).len
  result.tierId = S.auth.current.tier.tierId
  result.tierMasks = S.auth.current.tier.masks
  result.activeKemMask = S.auth.current.exchange.activeMask
  result.epochId = S.auth.current.epochId
  result.sessionId = S.sessionId
  result.laneId = S.laneId
  result.pending = S.pending
  result.capacity = S.inboxCapacity
  result.transferredBytes = S.path.transferredBytes
  result.peerTrustRequired = S.peerTrustRequired
  result.peerTrusted = S.peerTrust.ok
  result.peerAuthority = S.peerTrust.authority

proc `$`*(i: AmeSessionInfo): string {.role: truthBuilder.} =
  ## i: mask-tier connection summary.
  result = "AME session=" & $i.sessionId & " lane=" & $i.laneId &
    " epoch=" & $i.epochId & " tier=" & $i.tierId &
    " activeMask=" & $i.activeKemMask &
    " layoutBytes=" & $i.layoutBytes & " transferred=" &
    $i.transferredBytes
