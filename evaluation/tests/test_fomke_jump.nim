## -------------------------------------------------------------------------
## FOMKE Jump Tests <- the tight key, its children, and a stuck lane freed
## -------------------------------------------------------------------------
##
## The situation every jump test builds:
##
##   alice seals 100 messages on lane 1     bob receives none of them
##   alice seals message 100                bob: 100 ahead of 0, window 16
##                                          -> refused unchecked, `behind`
##
## Before jumps existed, bob could never open anything on lane 1 again.
##
##   what is checked                                   suite
##   ------------------------------------------------  --------------------
##   NK, JK and CS are distinct children of TK         "FOMKE tight key"
##   a jump frees the lane; its rules hold             "FOMKE jump"
##   the same through AME frames, ask and answer       "AME lane jump"

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/secret_stack
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level2/seal_open
import ../../src/protocols/ame/level2/lane_jump
import ../../src/protocols/fomke/types
import ../../src/protocols/fomke/level1/chain
import ../../src/protocols/fomke/level1/jump
import ../../src/protocols/fomke/level2/state_codec
import runePragmas

const
  jKems: AmeKemAlgorithms = [akaX25519, akaFireSaber]

type
  JPair = object
    ## alice is the initiator (sends on lane 1), bob the responder.
    alice: AmeSession
    bob: AmeSession

proc jAuth(role: AmeEndpointRole, seed: byte): AmeAuthPackage =
  var
    layout: AmeSuiteLayout = defaultAmeLayout(jKems)
    tier: AmeMaskTier = initAmeMaskTier(layout, 1'u32, initAmeTierMasks(
      0b11000000'u8, occupiedAmeMask(layout.ciphers.length),
      occupiedAmeMask(layout.macs.length), occupiedAmeMask(layout.hashes.length),
      occupiedAmeMask(layout.signatures.length),
      occupiedAmeMask(layout.kdfs.length)))
    state: AmeExchangeState = initAmeExchangeState(jKems)
  applyAmeExchange(state, layout, initAmeExchangeRequest(jKems, tier,
    0b11000000'u8), [@[seed, 2'u8, 3'u8, 4'u8], @[seed, 6'u8, 7'u8, 8'u8]])
  result = initAmeAuthPackage(layout, tier, state, endpointRole = role)

proc jPair(seed: byte): JPair =
  result.alice = initAmeSession(jAuth(aerInitiator, seed),
    peerTrustRequired = false)
  result.bob = initAmeSession(jAuth(aerResponder, seed),
    peerTrustRequired = false)

proc loseMessages(S: var FomkeState, n: int) =
  ## S: sender; n messages sealed and never delivered.
  var
    i: int = 0
  while i < n:
    discard sealFomkeMessage(S, @[byte 0])
    i = i + 1

suite "FOMKE tight key":
  # {.testKind: tkUnit, covers: "deriveFomkeTightChild".}
  test "NK, JK and CS are three different children of TK":
    var
      p: JPair = jPair(1'u8)
      nk: ByteSeq = deriveFomkeTightChild(p.alice.fomke, "FOMKE-NEXT-KEY-v1")
      jk0: ByteSeq = deriveFomkeTightChild(p.alice.fomke, "FOMKE-JUMP-KEY-v1",
        @[byte 1, 0, 0, 0, 0])
      jk1: ByteSeq = deriveFomkeTightChild(p.alice.fomke, "FOMKE-JUMP-KEY-v1",
        @[byte 1, 1, 0, 0, 0])
      cs: ByteSeq = fomkeHandshakeSecret(p.alice.fomke)
    check p.alice.fomke.tightKey.len == fomkeTightKeyBytes
    check p.alice.fomke.tightKey == p.bob.fomke.tightKey
    check nk.len == fomkeTightKeyBytes
    check nk != jk0
    check jk0 != jk1
    check cs != nk
    check cs != jk0
    check nk != p.alice.fomke.tightKey
    check nk == deriveFomkeTightChild(p.bob.fomke, "FOMKE-NEXT-KEY-v1")

  # {.testKind: tkUnit, covers: "encodeFomkeState|decodeFomkeState".}
  test "a checkpoint keeps TK and both jump counters":
    var
      p: JPair = jPair(2'u8)
      back: FomkeState = default(FomkeState)
    discard sealFomkeJump(p.alice.fomke)
    discard sealFomkeJump(p.alice.fomke)
    p.alice.fomke.recvJumps = 5'u32
    back = decodeFomkeState(encodeFomkeState(p.alice.fomke))
    check back.tightKey == p.alice.fomke.tightKey
    check back.sendJumps == 2'u32
    check back.recvJumps == 5'u32

suite "FOMKE jump":
  setup:
    var
      p: JPair = jPair(3'u8)
      opened: FomkeOpenResult = default(FomkeOpenResult)
      jumped: FomkeJumpResult = default(FomkeJumpResult)
      J: FomkeJump = default(FomkeJump)
    loseMessages(p.alice.fomke, 100)

  # {.testKind: tkRegression, covers: "openFomkeJump|sealFomkeJump", pins: "a loss burst wider than the reorder window ended the lane for good".}
  test "a burst wider than the window is refused, then a jump frees the lane":
    opened = openFomkeMessage(p.bob.fomke, sealFomkeMessage(p.alice.fomke,
      @[byte 7]))
    check not opened.ok
    check opened.behind
    J = sealFomkeJump(p.alice.fomke)
    check J.index == 101'u64
    jumped = openFomkeJump(p.bob.fomke, J)
    check jumped.ok
    check jumped.gaveUp == 101'u64
    opened = openFomkeMessage(p.bob.fomke, sealFomkeMessage(p.alice.fomke,
      @[byte 8]))
    check opened.ok
    check opened.payload == @[byte 8]

  # {.testKind: tkEdgeCase, covers: "openFomkeMessage".}
  test "an ordinary bad tag is not mistaken for being behind":
    var
      m: FomkeMessage = default(FomkeMessage)
    discard openFomkeJump(p.bob.fomke, sealFomkeJump(p.alice.fomke))
    m = sealFomkeMessage(p.alice.fomke, @[byte 1])
    m.authTag[0] = m.authTag[0] xor 0x01'u8
    opened = openFomkeMessage(p.bob.fomke, m)
    check not opened.ok
    check not opened.behind

  # {.testKind: tkRegression, covers: "openFomkeJump", pins: "a captured jump could be replayed".}
  test "a jump is used once; a lost one costs nothing":
    var
      lost: FomkeJump = sealFomkeJump(p.alice.fomke)    # number 0, never sent
    J = sealFomkeJump(p.alice.fomke)                      # number 1
    check J.number == lost.number + 1'u32
    check openFomkeJump(p.bob.fomke, J).ok
    check openFomkeJump(p.bob.fomke, J).err == "FOMKE jump was already used"
    check openFomkeJump(p.bob.fomke, lost).err == "FOMKE jump was already used"
    check p.bob.fomke.recvJumps == 2'u32

  # {.testKind: tkEdgeCase, covers: "openFomkeJump".}
  test "an edited jump changes nothing":
    var
      before: uint64 = p.bob.fomke.lane1.nextIndex
    J = sealFomkeJump(p.alice.fomke)
    J.index = J.index + 1000'u64
    check openFomkeJump(p.bob.fomke, J).err == "FOMKE jump did not authenticate"
    check p.bob.fomke.lane1.nextIndex == before
    check p.bob.fomke.recvJumps == 0'u32
    J = sealFomkeJump(p.alice.fomke)
    check openFomkeJump(p.bob.fomke, J, aad = @[byte 1]).err ==
      "FOMKE jump did not authenticate"

  # {.testKind: tkEdgeCase, covers: "openFomkeJump".}
  test "the wrong lane, the wrong epoch and too long a jump are refused":
    J = sealFomkeJump(p.alice.fomke)
    check openFomkeJump(p.alice.fomke, J).err ==
      "FOMKE jump names the wrong lane"
    J.epoch = 2'u32
    check openFomkeJump(p.bob.fomke, J).err == "FOMKE jump is for another epoch"
    J = sealFomkeJump(p.alice.fomke)
    check openFomkeJump(p.bob.fomke, J, maxJump = 50'u32).err ==
      "FOMKE jump is longer than allowed"

  # {.testKind: tkEdgeCase, covers: "openFomkeJump".}
  test "no jump while a KEM upgrade is pending":
    J = sealFomkeJump(p.alice.fomke)
    p.bob.fomke.pending.active = true
    check openFomkeJump(p.bob.fomke, J).err == "FOMKE KEM upgrade is pending"
    p.bob.fomke.pending.active = false

  # {.testKind: tkEdgeCase, covers: "openFomkeJump".}
  test "a jump to where the lane already is moves nothing and keeps held keys":
    var
      q: JPair = jPair(4'u8)
      late: FomkeMessage = default(FomkeMessage)
    late = sealFomkeMessage(q.alice.fomke, @[byte 1])           # index 0
    check openFomkeMessage(q.bob.fomke, sealFomkeMessage(q.alice.fomke,
      @[byte 2])).ok                                            # index 1
    check fomkeSkippedMessages(q.bob.fomke) == 1
    jumped = openFomkeJump(q.bob.fomke, sealFomkeJump(q.alice.fomke))
    check jumped.ok
    check jumped.gaveUp == 0'u64
    check openFomkeMessage(q.bob.fomke, late).ok

  # {.testKind: tkEdgeCase, covers: "openFomkeJump".}
  test "a real jump drops the lane's held keys":
    var
      q: JPair = jPair(5'u8)
      late: FomkeMessage = sealFomkeMessage(q.alice.fomke, @[byte 1])
    check openFomkeMessage(q.bob.fomke, sealFomkeMessage(q.alice.fomke,
      @[byte 2])).ok
    loseMessages(q.alice.fomke, 40)
    jumped = openFomkeJump(q.bob.fomke, sealFomkeJump(q.alice.fomke))
    check jumped.gaveUp == 41'u64
    check fomkeSkippedMessages(q.bob.fomke) == 0
    check not openFomkeMessage(q.bob.fomke, late).ok

suite "AME lane jump":
  # {.testKind: tkIntegration, covers: "sealAmeJumpAsk|answerAmeJumpAsk|openAmeJump".}
  test "ask on the working lane, jump back, and the stuck lane opens again":
    var
      p: JPair = jPair(6'u8)
      i: int = 0
      res: FomkeJumpResult = default(FomkeJumpResult)
    while i < 100:
      discard sealAmeDacFrame(p.alice, @[byte 0])
      i = i + 1
    check not openAmeDacFrame(p.bob, sealAmeDacFrame(p.alice, @[byte 1])).ok
    check ameSessionBehind(p.bob)
    res = openAmeJump(p.bob, acrDac, answerAmeJumpAsk(p.alice, acrDac,
      sealAmeJumpAsk(p.bob, acrDac)))
    check res.ok
    check res.gaveUp == 101'u64
    check not ameSessionBehind(p.bob)
    check openAmeDacFrame(p.bob, sealAmeDacFrame(p.alice, @[byte 2])).ok
    check openAmeDacFrame(p.alice, sealAmeDacFrame(p.bob, @[byte 3])).ok

  # {.testKind: tkEdgeCase, covers: "openAmeJump".}
  test "an edited jump frame or one from another session is refused":
    var
      p: JPair = jPair(7'u8)
      other: JPair = jPair(8'u8)
      frame: ByteSeq = sealAmeJump(p.alice, acrDac)
      edited: ByteSeq = frame
    edited[26 + 9] = edited[26 + 9] xor 0x01'u8
    check not openAmeJump(p.bob, acrDac, edited).ok
    check not openAmeJump(other.bob, acrDac, frame).ok
    check openAmeJump(p.bob, acrDac, frame).ok
    check not openAmeJump(p.bob, acrDac, frame).ok
