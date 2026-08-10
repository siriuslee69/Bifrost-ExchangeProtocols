## ----------------------------------------------------------------
## DAC Anti Oracle Tests <- generic error masking and delay triggers
## ----------------------------------------------------------------

import unittest

import ../src/protocols/dac/types
import ../src/protocols/dac/level0/anti_oracle

proc antiOraclePolicy(): DacAntiOraclePolicy =
  ## antiOraclePolicy: small deterministic test policy.
  result = initDacAntiOraclePolicy(
    badWindowSec = 60'u32,
    maskAfterBadCount = 2'u16,
    maskAfterUniqueKeys = 2'u8,
    delayAfterBadCount = 4'u16,
    delayAfterUniqueKeys = 3'u8,
    minDelayMs = 3'u16,
    maxDelayMs = 7'u16,
    protectForSec = 60'u32,
    protectSessions = 2'u16,
    maxTrackedClients = 8'u16,
    maxTrackedRequestsPerClient = 4'u8,
    maxTrackedKeysPerRequest = 4'u8,
    maxTrackedErrorsPerRequest = 4'u8)

suite "DAC anti-oracle":
  test "same request with different keys collapses to the generic error reply":
    var
      p: DacAntiOraclePolicy
      S: DacAntiOracleTracker
      d: DacAntiOracleDecision
    p = antiOraclePolicy()
    S = initDacAntiOracleTracker(p)
    d = recordDacAntiOracleBadMessage(S, "peer-a", "session-0", "request-a",
      "key-a", "bad-mac", 100'i64)
    check not d.maskReply
    check not d.protectionActive
    check d.delayMs == 0'u16
    d = recordDacAntiOracleBadMessage(S, "peer-a", "session-0", "request-a",
      "key-b", "unknown-key", 101'i64)
    check d.maskReply
    check d.replyText == defaultDacAntiOracleErrorReply()
    check not d.protectionActive
    check d.badCount == 2'u16
    check d.uniqueKeyCount == 2'u8
    check d.uniqueErrorCount == 2'u8
    check d.delayMs == 0'u16

  test "repeated bad probes trigger delay and stay active across later sessions":
    var
      p: DacAntiOraclePolicy
      S: DacAntiOracleTracker
      d: DacAntiOracleDecision
    p = antiOraclePolicy()
    S = initDacAntiOracleTracker(p)
    discard recordDacAntiOracleBadMessage(S, "peer-b", "session-0",
      "request-b", "key-a", "bad-mac", 100'i64)
    discard recordDacAntiOracleBadMessage(S, "peer-b", "session-0",
      "request-b", "key-b", "unknown-key", 101'i64)
    discard recordDacAntiOracleBadMessage(S, "peer-b", "session-0",
      "request-b", "key-c", "unknown-key", 102'i64)
    d = recordDacAntiOracleBadMessage(S, "peer-b", "session-0", "request-b",
      "key-d", "bad-mac", 103'i64)
    check d.protectionTriggered
    check d.protectionActive
    check d.maskReply
    check d.delayMs >= p.minDelayMs
    check d.delayMs <= p.maxDelayMs
    check S.clients.len == 1
    check S.clients[0].protectedUntilUnix == 163'i64
    check S.clients[0].protectedSessionsLeft == 2'u16
    d = peekDacAntiOracleDecision(S, "peer-b", "session-1", 104'i64)
    check d.protectionActive
    check d.delayMs >= p.minDelayMs
    check d.delayMs <= p.maxDelayMs
    check S.clients[0].protectedSessionsLeft == 1'u16
    d = peekDacAntiOracleDecision(S, "peer-b", "session-2", 105'i64)
    check d.protectionActive
    check d.delayMs >= p.minDelayMs
    check d.delayMs <= p.maxDelayMs
    check S.clients[0].protectedSessionsLeft == 0'u16
    d = peekDacAntiOracleDecision(S, "peer-b", "session-2", 200'i64)
    check not d.protectionActive
    check d.delayMs == 0'u16

  test "manual trigger enables delay and accepted messages can clear request buckets":
    var
      p: DacAntiOraclePolicy
      S: DacAntiOracleTracker
      d: DacAntiOracleDecision
    p = antiOraclePolicy()
    S = initDacAntiOracleTracker(p)
    discard recordDacAntiOracleBadMessage(S, "peer-c", "session-0",
      "request-c", "key-a", "bad-mac", 100'i64)
    check S.clients[0].requests.len == 1
    d = recordDacAntiOracleAcceptedMessage(S, "peer-c", "session-0",
      "request-c", 101'i64)
    check not d.maskReply
    check S.clients[0].requests.len == 0
    d = triggerDacAntiOracleProtection(S, "peer-c", "session-0", 102'i64)
    check d.protectionTriggered
    check d.protectionActive
    check d.delayMs >= p.minDelayMs
    check d.delayMs <= p.maxDelayMs
    check not d.maskReply
