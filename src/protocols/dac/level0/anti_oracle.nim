## ----------------------------------------------------------------------
## DAC Anti Oracle <- repeated bad-request masking and delay state machine
## ----------------------------------------------------------------------

import std/[os, strutils]

import ../types
import ../../../analysis_pragmas

const
  dacAntiOracleAscii* = """
+------------------------ DAC Anti Oracle ------------------------+
| Same request + rotating keys  -> generic error-like answer      |
| Repeated bad probes           -> per-client random ms delay      |
| Delay memory kept by unix time and protected session counter     |
+----------------------------------------------------------------+
"""

  dacAntiOracleFnvOffset = 14695981039346656037'u64
  dacAntiOracleFnvPrime = 1099511628211'u64

proc defaultDacAntiOracleErrorReply*(): string {.role: wrapper.} =
  ## defaultDacAntiOracleErrorReply: default public error-like answer.
  result = "dac: request rejected"

proc initDacAntiOraclePolicy*(badWindowSec: uint32 = 300'u32,
    maskAfterBadCount: uint16 = 2'u16, maskAfterUniqueKeys: uint8 = 2'u8,
    delayAfterBadCount: uint16 = 6'u16, delayAfterUniqueKeys: uint8 = 4'u8,
    minDelayMs: uint16 = 3'u16, maxDelayMs: uint16 = 11'u16,
    protectForSec: uint32 = 5_184_000'u32, protectSessions: uint16 = 64'u16,
    maxTrackedClients: uint16 = 256'u16,
    maxTrackedRequestsPerClient: uint8 = 16'u8,
    maxTrackedKeysPerRequest: uint8 = 8'u8,
    maxTrackedErrorsPerRequest: uint8 = 8'u8,
    genericErrorReply: string = defaultDacAntiOracleErrorReply()):
    DacAntiOraclePolicy {.role: wrapper.} =
  ## badWindowSec: recent window where repeated failures are grouped.
  ## maskAfterBadCount/maskAfterUniqueKeys: when to collapse replies to the
  ## generic error text.
  ## delayAfterBadCount/delayAfterUniqueKeys: when to enable client-wide
  ## random-delay protection.
  ## minDelayMs/maxDelayMs: randomized delay range once protection is active.
  ## protectForSec/protectSessions: persistence after trigger.
  ## maxTrackedClients/maxTrackedRequestsPerClient: bounded memory caps.
  ## maxTrackedKeysPerRequest/maxTrackedErrorsPerRequest: bounded per-request
  ## fingerprint sets.
  ## genericErrorReply: constant outward reply for suspicious failures.
  result.badWindowSec = badWindowSec
  result.maskAfterBadCount = maskAfterBadCount
  result.maskAfterUniqueKeys = maskAfterUniqueKeys
  result.delayAfterBadCount = delayAfterBadCount
  result.delayAfterUniqueKeys = delayAfterUniqueKeys
  result.minDelayMs = minDelayMs
  result.maxDelayMs = maxDelayMs
  result.protectForSec = protectForSec
  result.protectSessions = protectSessions
  result.maxTrackedClients = maxTrackedClients
  result.maxTrackedRequestsPerClient = maxTrackedRequestsPerClient
  result.maxTrackedKeysPerRequest = maxTrackedKeysPerRequest
  result.maxTrackedErrorsPerRequest = maxTrackedErrorsPerRequest
  result.genericErrorReply = genericErrorReply

proc validateDacAntiOraclePolicy*(p: DacAntiOraclePolicy): bool {.role: parser.} =
  ## p: anti-oracle trigger policy.
  if p.badWindowSec == 0'u32:
    return false
  if p.maskAfterBadCount == 0'u16:
    return false
  if p.maskAfterUniqueKeys == 0'u8:
    return false
  if p.delayAfterBadCount < p.maskAfterBadCount:
    return false
  if p.delayAfterUniqueKeys < p.maskAfterUniqueKeys:
    return false
  if p.maxDelayMs < p.minDelayMs:
    return false
  if p.protectForSec == 0'u32 and p.protectSessions == 0'u16:
    return false
  if p.maxTrackedClients == 0'u16:
    return false
  if p.maxTrackedRequestsPerClient == 0'u8:
    return false
  if p.maxTrackedKeysPerRequest == 0'u8:
    return false
  if p.maxTrackedErrorsPerRequest == 0'u8:
    return false
  if p.genericErrorReply.len == 0:
    return false
  result = true

proc initDacAntiOracleTracker*(p: DacAntiOraclePolicy = initDacAntiOraclePolicy()):
    DacAntiOracleTracker {.role: wrapper.} =
  ## p: active anti-oracle policy.
  if not validateDacAntiOraclePolicy(p):
    raise newException(ValueError, "DAC anti-oracle policy is invalid")
  result.policy = p
  result.clients = @[]

proc mixDacAntiOracleSeed(x: uint64): uint64 {.role: math.} =
  ## x: raw seed before diffusion.
  var
    z: uint64 = x + 0x9E3779B97F4A7C15'u64
  z = (z xor (z shr 30)) * 0xBF58476D1CE4E5B9'u64
  z = (z xor (z shr 27)) * 0x94D049BB133111EB'u64
  result = z xor (z shr 31)

proc foldDacAntiOracleText(s: string): uint64 {.role: helper.} =
  ## s: raw text to bucket into a short stable fingerprint.
  var
    h: uint64 = dacAntiOracleFnvOffset
    i: int = 0
  while i < s.len:
    h = h xor uint64(ord(s[i]))
    h = h * dacAntiOracleFnvPrime
    i.inc
  result = h

proc foldDacAntiOracleBytes(A: openArray[uint8]): uint64 {.role: helper.} =
  ## A: raw bytes to bucket into a short stable fingerprint.
  var
    h: uint64 = dacAntiOracleFnvOffset
    i: int = 0
  while i < A.len:
    h = h xor uint64(A[i])
    h = h * dacAntiOracleFnvPrime
    i.inc
  result = h

proc fingerprintDacAntiOracle*(s: string): string {.role: helper.} =
  ## s: raw text that should not be stored verbatim in tracker state.
  result = toHex(foldDacAntiOracleText(s), 16)

proc fingerprintDacAntiOracle*(A: openArray[uint8]): string {.role: helper.} =
  ## A: raw bytes that should not be stored verbatim in tracker state.
  result = toHex(foldDacAntiOracleBytes(A), 16)

proc saturatingInc(v: var uint16) {.role: stateController.} =
  ## v: 16-bit counter.
  if v == high(uint16):
    return
  v.inc

proc saturatingInc(v: var uint32) {.role: stateController.} =
  ## v: 32-bit counter.
  if v == high(uint32):
    return
  v.inc

proc countToU8(n: int): uint8 {.role: parser.} =
  ## n: sequence length that should be rendered as a bounded u8.
  if n <= 0:
    return 0'u8
  if n >= int(high(uint8)):
    return high(uint8)
  result = uint8(n)

proc findTextIndex(A: seq[string], s: string): int {.role: parser.} =
  ## A: tracked fingerprint list.
  ## s: fingerprint to locate.
  var
    i: int = 0
  while i < A.len:
    if A[i] == s:
      return i
    i.inc
  result = -1

proc appendUniqueText(A: var seq[string], s: string, maxCount: int) {.
    role: stateController.} =
  ## A: tracked fingerprint list.
  ## s: new fingerprint.
  ## maxCount: bounded memory cap for the list.
  if s.len == 0:
    return
  if maxCount <= 0:
    return
  if findTextIndex(A, s) >= 0:
    return
  if A.len >= maxCount:
    A.del(0)
  A.add(s)

proc findClientIndex(S: DacAntiOracleTracker, clientFingerprint: string): int {.
    role: parser.} =
  ## S: whole tracker state.
  ## clientFingerprint: client bucket id.
  var
    i: int = 0
  while i < S.clients.len:
    if S.clients[i].clientFingerprint == clientFingerprint:
      return i
    i.inc
  result = -1

proc findOldestClientIndex(S: DacAntiOracleTracker): int {.role: parser.} =
  ## S: whole tracker state.
  var
    i: int = 1
    oldest: int = 0
  if S.clients.len == 0:
    return -1
  while i < S.clients.len:
    if S.clients[i].lastSeenUnix < S.clients[oldest].lastSeenUnix:
      oldest = i
    i.inc
  result = oldest

proc requestExpired(r: DacAntiOracleRequestState, p: DacAntiOraclePolicy,
    nowUnix: int64): bool {.role: parser.} =
  ## r: one request bucket.
  ## p: active anti-oracle policy.
  ## nowUnix: current unix time in seconds.
  if nowUnix <= r.lastBadUnix:
    return false
  result = nowUnix - r.lastBadUnix > int64(p.badWindowSec)

proc findRequestIndex(C: DacAntiOracleClientState, requestFingerprint: string):
    int {.role: parser.} =
  ## C: one tracked client.
  ## requestFingerprint: request bucket id.
  var
    i: int = 0
  while i < C.requests.len:
    if C.requests[i].requestFingerprint == requestFingerprint:
      return i
    i.inc
  result = -1

proc findOldestRequestIndex(C: DacAntiOracleClientState): int {.role: parser.} =
  ## C: one tracked client.
  var
    i: int = 1
    oldest: int = 0
  if C.requests.len == 0:
    return -1
  while i < C.requests.len:
    if C.requests[i].lastBadUnix < C.requests[oldest].lastBadUnix:
      oldest = i
    i.inc
  result = oldest

proc trimExpiredRequests(C: var DacAntiOracleClientState, p: DacAntiOraclePolicy,
    nowUnix: int64) {.role: stateController.} =
  ## C: one tracked client.
  ## p: active anti-oracle policy.
  ## nowUnix: current unix time in seconds.
  var
    i: int = 0
  while i < C.requests.len:
    if requestExpired(C.requests[i], p, nowUnix):
      C.requests.del(i)
      continue
    i.inc

proc ensureClientIndex(S: var DacAntiOracleTracker, clientFingerprint: string,
    nowUnix: int64): int {.role: truthBuilder.} =
  ## S: whole tracker state.
  ## clientFingerprint: client bucket id.
  ## nowUnix: current unix time in seconds.
  var
    i: int = -1
    oldest: int = -1
    C: DacAntiOracleClientState
  i = findClientIndex(S, clientFingerprint)
  if i >= 0:
    S.clients[i].lastSeenUnix = nowUnix
    return i
  if S.clients.len >= int(S.policy.maxTrackedClients):
    oldest = findOldestClientIndex(S)
    if oldest >= 0:
      S.clients.del(oldest)
  C.clientFingerprint = clientFingerprint
  C.lastSeenUnix = nowUnix
  C.lastSessionFingerprint = ""
  C.protectedUntilUnix = 0'i64
  C.protectedSessionsLeft = 0'u16
  C.badMessageCount = 0'u32
  C.maskedReplyCount = 0'u32
  C.delayCounter = 0'u32
  C.requests = @[]
  S.clients.add(C)
  result = S.clients.len - 1

proc ensureRequestIndex(C: var DacAntiOracleClientState, p: DacAntiOraclePolicy,
    requestFingerprint: string, nowUnix: int64): int {.role: truthBuilder.} =
  ## C: one tracked client.
  ## p: active anti-oracle policy.
  ## requestFingerprint: request bucket id.
  ## nowUnix: current unix time in seconds.
  var
    i: int = -1
    oldest: int = -1
    r: DacAntiOracleRequestState
  trimExpiredRequests(C, p, nowUnix)
  i = findRequestIndex(C, requestFingerprint)
  if i >= 0:
    return i
  if C.requests.len >= int(p.maxTrackedRequestsPerClient):
    oldest = findOldestRequestIndex(C)
    if oldest >= 0:
      C.requests.del(oldest)
  r.requestFingerprint = requestFingerprint
  r.badCount = 0'u16
  r.lastBadUnix = nowUnix
  r.keyFingerprints = @[]
  r.errorFingerprints = @[]
  C.requests.add(r)
  result = C.requests.len - 1

proc touchClientSession(C: var DacAntiOracleClientState,
    sessionFingerprint: string) {.role: stateController.} =
  ## C: one tracked client.
  ## sessionFingerprint: caller-defined session id/fingerprint for carry-over.
  if sessionFingerprint.len == 0:
    return
  if C.lastSessionFingerprint.len == 0:
    C.lastSessionFingerprint = sessionFingerprint
    return
  if C.lastSessionFingerprint == sessionFingerprint:
    return
  C.lastSessionFingerprint = sessionFingerprint
  if C.protectedSessionsLeft == 0'u16:
    return
  C.protectedSessionsLeft.dec

proc isDacAntiOracleProtectionActive*(C: DacAntiOracleClientState,
    nowUnix: int64): bool {.role: parser.} =
  ## C: one tracked client.
  ## nowUnix: current unix time in seconds.
  if C.protectedUntilUnix > nowUnix:
    return true
  result = C.protectedSessionsLeft > 0'u16

proc requestNeedsMaskedReply(p: DacAntiOraclePolicy,
    r: DacAntiOracleRequestState): bool {.role: parser.} =
  ## p: active anti-oracle policy.
  ## r: one request bucket.
  if r.badCount < p.maskAfterBadCount:
    return false
  if r.keyFingerprints.len < int(p.maskAfterUniqueKeys):
    return false
  result = true

proc requestNeedsDelayTrigger(p: DacAntiOraclePolicy,
    r: DacAntiOracleRequestState): bool {.role: parser.} =
  ## p: active anti-oracle policy.
  ## r: one request bucket.
  if r.badCount < p.delayAfterBadCount:
    return false
  if r.keyFingerprints.len < int(p.delayAfterUniqueKeys):
    return false
  result = true

proc activateDacAntiOracleProtection(C: var DacAntiOracleClientState,
    p: DacAntiOraclePolicy, sessionFingerprint: string, nowUnix: int64) {.
    role: actor.} =
  ## C: one tracked client.
  ## p: active anti-oracle policy.
  ## sessionFingerprint: current session id/fingerprint.
  ## nowUnix: current unix time in seconds.
  var
    untilUnix: int64 = nowUnix + int64(p.protectForSec)
  if C.protectedUntilUnix < untilUnix:
    C.protectedUntilUnix = untilUnix
  if C.protectedSessionsLeft < p.protectSessions:
    C.protectedSessionsLeft = p.protectSessions
  if sessionFingerprint.len > 0:
    C.lastSessionFingerprint = sessionFingerprint

proc nextDacAntiOracleDelayMs(C: var DacAntiOracleClientState,
    p: DacAntiOraclePolicy, clientFingerprint, sessionFingerprint: string,
    nowUnix: int64): uint16 {.role: actor.} =
  ## C: one tracked client.
  ## p: active anti-oracle policy.
  ## clientFingerprint/sessionFingerprint: stable caller-side ids.
  ## nowUnix: current unix time in seconds.
  var
    seed: uint64 = 0'u64
    span: uint64 = 0'u64
  if not isDacAntiOracleProtectionActive(C, nowUnix):
    return 0'u16
  if p.maxDelayMs < p.minDelayMs:
    return 0'u16
  saturatingInc(C.delayCounter)
  seed = foldDacAntiOracleText(clientFingerprint)
  seed = seed xor (foldDacAntiOracleText(sessionFingerprint) shl 1)
  seed = seed xor uint64(C.badMessageCount)
  seed = seed xor (uint64(C.delayCounter) shl 17)
  seed = seed xor cast[uint64](nowUnix)
  seed = mixDacAntiOracleSeed(seed)
  span = uint64(p.maxDelayMs - p.minDelayMs) + 1'u64
  result = p.minDelayMs + uint16(seed mod span)

proc finalizeDacAntiOracleDecision(C: var DacAntiOracleClientState,
    p: DacAntiOraclePolicy, clientFingerprint, sessionFingerprint: string,
    nowUnix: int64, protectionTriggered, maskReply: bool, badCount: uint16,
    uniqueKeyCount, uniqueErrorCount: uint8): DacAntiOracleDecision {.
    role: actor.} =
  ## C: one tracked client.
  ## p: active anti-oracle policy.
  ## clientFingerprint/sessionFingerprint: stable caller-side ids.
  ## nowUnix: current unix time in seconds.
  ## protectionTriggered/maskReply: state derived from the latest message.
  ## badCount/uniqueKeyCount/uniqueErrorCount: request-local counters to
  ## surface to the caller.
  result.protectionActive = isDacAntiOracleProtectionActive(C, nowUnix)
  result.protectionTriggered = protectionTriggered
  result.maskReply = maskReply
  result.badCount = badCount
  result.uniqueKeyCount = uniqueKeyCount
  result.uniqueErrorCount = uniqueErrorCount
  if maskReply:
    result.replyText = p.genericErrorReply
  if not result.protectionActive:
    return
  result.delayMs = nextDacAntiOracleDelayMs(C, p, clientFingerprint,
    sessionFingerprint, nowUnix)

proc triggerDacAntiOracleProtection*(S: var DacAntiOracleTracker,
    clientFingerprint, sessionFingerprint: string, nowUnix: int64):
    DacAntiOracleDecision {.role: orchestrator.} =
  ## S: whole tracker state.
  ## clientFingerprint/sessionFingerprint: stable caller-side ids.
  ## nowUnix: current unix time in seconds.
  var
    i: int = -1
  i = ensureClientIndex(S, clientFingerprint, nowUnix)
  touchClientSession(S.clients[i], sessionFingerprint)
  activateDacAntiOracleProtection(S.clients[i], S.policy, sessionFingerprint,
    nowUnix)
  result = finalizeDacAntiOracleDecision(S.clients[i], S.policy,
    clientFingerprint, sessionFingerprint, nowUnix, true, false, 0'u16, 0'u8,
    0'u8)

proc peekDacAntiOracleDecision*(S: var DacAntiOracleTracker,
    clientFingerprint, sessionFingerprint: string, nowUnix: int64):
    DacAntiOracleDecision {.role: orchestrator.} =
  ## S: whole tracker state.
  ## clientFingerprint/sessionFingerprint: stable caller-side ids.
  ## nowUnix: current unix time in seconds.
  var
    i: int = -1
  i = ensureClientIndex(S, clientFingerprint, nowUnix)
  touchClientSession(S.clients[i], sessionFingerprint)
  trimExpiredRequests(S.clients[i], S.policy, nowUnix)
  result = finalizeDacAntiOracleDecision(S.clients[i], S.policy,
    clientFingerprint, sessionFingerprint, nowUnix, false, false, 0'u16, 0'u8,
    0'u8)

proc recordDacAntiOracleBadMessage*(S: var DacAntiOracleTracker,
    clientFingerprint, sessionFingerprint, requestFingerprint, keyFingerprint,
    errorFingerprint: string, nowUnix: int64): DacAntiOracleDecision {.
    role: orchestrator.} =
  ## S: whole tracker state.
  ## clientFingerprint/sessionFingerprint: stable caller-side ids.
  ## requestFingerprint: stable bucket for the probed request shape.
  ## keyFingerprint: stable bucket for the key/auth material used.
  ## errorFingerprint: internal error bucket for diagnostics.
  ## nowUnix: current unix time in seconds.
  var
    i: int = -1
    r: int = -1
    protectionTriggered: bool = false
    maskReply: bool = false
    badCount: uint16 = 0'u16
    uniqueKeyCount: uint8 = 0'u8
    uniqueErrorCount: uint8 = 0'u8
  i = ensureClientIndex(S, clientFingerprint, nowUnix)
  touchClientSession(S.clients[i], sessionFingerprint)
  r = ensureRequestIndex(S.clients[i], S.policy, requestFingerprint, nowUnix)
  S.clients[i].requests[r].lastBadUnix = nowUnix
  saturatingInc(S.clients[i].requests[r].badCount)
  appendUniqueText(S.clients[i].requests[r].keyFingerprints, keyFingerprint,
    int(S.policy.maxTrackedKeysPerRequest))
  appendUniqueText(S.clients[i].requests[r].errorFingerprints, errorFingerprint,
    int(S.policy.maxTrackedErrorsPerRequest))
  saturatingInc(S.clients[i].badMessageCount)
  if requestNeedsDelayTrigger(S.policy, S.clients[i].requests[r]):
    activateDacAntiOracleProtection(S.clients[i], S.policy, sessionFingerprint,
      nowUnix)
    protectionTriggered = true
  maskReply = requestNeedsMaskedReply(S.policy, S.clients[i].requests[r]) or
    isDacAntiOracleProtectionActive(S.clients[i], nowUnix)
  if maskReply:
    saturatingInc(S.clients[i].maskedReplyCount)
  badCount = S.clients[i].requests[r].badCount
  uniqueKeyCount = countToU8(S.clients[i].requests[r].keyFingerprints.len)
  uniqueErrorCount = countToU8(S.clients[i].requests[r].errorFingerprints.len)
  result = finalizeDacAntiOracleDecision(S.clients[i], S.policy,
    clientFingerprint, sessionFingerprint, nowUnix, protectionTriggered,
    maskReply, badCount, uniqueKeyCount, uniqueErrorCount)

proc recordDacAntiOracleAcceptedMessage*(S: var DacAntiOracleTracker,
    clientFingerprint, sessionFingerprint, requestFingerprint: string,
    nowUnix: int64): DacAntiOracleDecision {.role: orchestrator.} =
  ## S: whole tracker state.
  ## clientFingerprint/sessionFingerprint: stable caller-side ids.
  ## requestFingerprint: request bucket that succeeded and can be cleared.
  ## nowUnix: current unix time in seconds.
  var
    i: int = -1
    r: int = -1
  i = ensureClientIndex(S, clientFingerprint, nowUnix)
  touchClientSession(S.clients[i], sessionFingerprint)
  trimExpiredRequests(S.clients[i], S.policy, nowUnix)
  r = findRequestIndex(S.clients[i], requestFingerprint)
  if r >= 0:
    S.clients[i].requests.del(r)
  result = finalizeDacAntiOracleDecision(S.clients[i], S.policy,
    clientFingerprint, sessionFingerprint, nowUnix, false, false, 0'u16, 0'u8,
    0'u8)

proc enforceDacAntiOracleDelay*(d: DacAntiOracleDecision) {.role: actor.} =
  ## d: one anti-oracle decision returned by `peek` or `record`.
  if d.delayMs == 0'u16:
    return
  sleep(int(d.delayMs))
