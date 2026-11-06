## -------------------------------------------------------------------------
## AME Liveness Tests <- ping, pong, and closing a link that went quiet
## -------------------------------------------------------------------------
##
## The situation every test builds: a server (bob) runs the tracker, a
## client (alice) answers. The clock is a plain number of milliseconds.
##
##   what is checked                                   suite
##   ------------------------------------------------  --------------------
##   when the tracker waits, pings and closes          "AME liveness timer"
##   ping -> pong through real sealed frames           "AME liveness frames"
##   a link that never answers loses its keys          "AME liveness close"

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/config
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/secret_stack
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level2/seal_open
import ../../src/protocols/ame/level2/liveness
import runePragmas

const
  lKems: AmeKemAlgorithms = [akaX25519, akaFireSaber]

type
  LPair = object
    ## alice: initiator, the client. bob: responder, the server.
    alice: AmeSession
    bob: AmeSession

proc lAuth(role: AmeEndpointRole, seed: byte): AmeAuthPackage =
  var
    layout: AmeSuiteLayout = defaultAmeLayout(lKems)
    tier: AmeMaskTier = initAmeMaskTier(layout, 1'u32, initAmeTierMasks(
      0b11000000'u8, occupiedAmeMask(layout.ciphers.length),
      occupiedAmeMask(layout.macs.length), occupiedAmeMask(layout.hashes.length),
      occupiedAmeMask(layout.signatures.length),
      occupiedAmeMask(layout.kdfs.length)))
    state: AmeExchangeState = initAmeExchangeState(lKems)
  applyAmeExchange(state, layout, initAmeExchangeRequest(lKems, tier,
    0b11000000'u8), [@[seed, 2'u8, 3'u8, 4'u8], @[seed, 6'u8, 7'u8, 8'u8]])
  result = initAmeAuthPackage(layout, tier, state, endpointRole = role)

proc lPair(seed: byte): LPair =
  result.alice = initAmeSession(lAuth(aerInitiator, seed),
    peerTrustRequired = false)
  result.bob = initAmeSession(lAuth(aerResponder, seed),
    peerTrustRequired = false)

suite "AME liveness timer":
  # {.testKind: tkUnit, covers: "tickAmeLiveness".}
  test "quiet for less than quietMs: wait":
    var
      L: AmeLiveness = initAmeLiveness(1_000'u64, 15_000'u64, 3)
    check tickAmeLiveness(L, 1_000'u64) == alsWait
    check tickAmeLiveness(L, 15_999'u64) == alsWait
    check tickAmeLiveness(L, 16_000'u64) == alsProbe

  # {.testKind: tkUnit, covers: "noteAmeHeard".}
  test "hearing anything resets the count and the clock":
    var
      L: AmeLiveness = initAmeLiveness(0'u64, 10_000'u64, 2)
    L.unanswered = 2
    L.lastProbeMs = 20_000'u64
    noteAmeHeard(L, 25_000'u64)
    check L.unanswered == 0
    check tickAmeLiveness(L, 34_999'u64) == alsWait
    check tickAmeLiveness(L, 35_000'u64) == alsProbe

  # {.testKind: tkEdgeCase, covers: "tickAmeLiveness".}
  test "a clock that goes backwards counts as no time passed":
    var
      L: AmeLiveness = initAmeLiveness(50_000'u64, 1_000'u64, 1)
    check tickAmeLiveness(L, 10_000'u64) == alsWait

  # {.testKind: tkUnit, covers: "initAmeLiveness".}
  test "the defaults come from the config":
    var
      L: AmeLiveness = initAmeLiveness(0'u64)
    check L.quietMs == currentBifrostConfig().ameLivenessQuietMs
    check L.missLimit == currentBifrostConfig().ameLivenessMisses
    check L.quietMs == 15_000'u64
    check L.missLimit == 3

suite "AME liveness frames":
  # {.testKind: tkIntegration, covers: "stepAmeLiveness|answerAmePing|openAmePong".}
  test "the server pings, the client answers, the server has heard":
    var
      p: LPair = lPair(3'u8)
      L: AmeLiveness = initAmeLiveness(0'u64, 15_000'u64, 3)
      step: AmeLivenessOutcome = (alsWait, @[])
      answer: AmeLivenessFrameOutcome = (alfNone, @[], "")
      heard: AmeLivenessFrameOutcome = (alfNone, @[], "")
      idle: AmeLiveness = initAmeLiveness(0'u64)
    step = stepAmeLiveness(p.bob, L, acrDac, 15_000'u64)
    check step.step == alsProbe
    check step.frame.len > 0
    check L.unanswered == 1
    answer = handleAmeLivenessFrame(p.alice, idle, acrDac, step.frame, 15_010'u64)
    check answer.step == alfAnswered
    check answer.reply.len > 0
    heard = handleAmeLivenessFrame(p.bob, L, acrDac, answer.reply, 15_020'u64)
    check heard.step == alfHeard
    check L.unanswered == 0
    check L.lastHeardMs == 15_020'u64
    check stepAmeLiveness(p.bob, L, acrDac, 20_000'u64).step == alsWait

  # {.testKind: tkEdgeCase, covers: "handleAmeLivenessFrame".}
  test "a pong with one changed byte does not open and counts for nothing":
    var
      p: LPair = lPair(4'u8)
      L: AmeLiveness = initAmeLiveness(0'u64, 15_000'u64, 3)
      idle: AmeLiveness = initAmeLiveness(0'u64)
      step: AmeLivenessOutcome = stepAmeLiveness(p.bob, L, acrDac, 15_000'u64)
      answer: AmeLivenessFrameOutcome = handleAmeLivenessFrame(p.alice, idle,
        acrDac, step.frame, 15_001'u64)
      forged: ByteSeq = answer.reply
      heard: AmeLivenessFrameOutcome = (alfNone, @[], "")
    forged[^1] = forged[^1] xor 0x01'u8
    heard = handleAmeLivenessFrame(p.bob, L, acrDac, forged, 15_002'u64)
    check heard.step == alfRefused
    check L.unanswered == 1

  # {.testKind: tkEdgeCase, covers: "handleAmeLivenessFrame".}
  test "a data frame is not a liveness frame":
    var
      p: LPair = lPair(5'u8)
      L: AmeLiveness = initAmeLiveness(0'u64)
      data: ByteSeq = sealAmeDacFrame(p.alice, @[byte 1, 2, 3])
    check handleAmeLivenessFrame(p.bob, L, acrDac, data, 1'u64).step == alfNone

suite "AME liveness close":
  # {.testKind: tkIntegration, covers: "stepAmeLiveness".}
  test "three unanswered pings, one more quiet stretch, keys erased":
    var
      p: LPair = lPair(6'u8)
      L: AmeLiveness = initAmeLiveness(0'u64, 15_000'u64, 3)
      steps: seq[AmeLivenessStep] = @[]
      t: uint64 = 15_000'u64
    while t <= 60_000'u64:
      steps.add(stepAmeLiveness(p.bob, L, acrDac, t).step)
      t = t + 15_000'u64
    check steps == @[alsProbe, alsProbe, alsProbe, alsClose]
    check p.bob.fomke.tightKey.len == 0
    expect ValueError:
      discard sealAmeDacFrame(p.bob, @[byte 9])
