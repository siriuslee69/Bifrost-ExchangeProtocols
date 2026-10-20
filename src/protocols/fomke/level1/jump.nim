## -------------------------------------------------------------------------
## FOMKE Jump <- moving a receiving lane forward when it can no longer follow
## -------------------------------------------------------------------------
##
## ╭─ ❧ The problem 🌊
##
## Every message carries its position on its lane (the index, envelope bytes
## 4..11), so a receiver always knows where a message claims to sit. It will
## step its chain forward to meet it -- but only up to the reorder window
## (16 at the start, at most the ceiling, 64 by default). Further than that
## is refused BEFORE the tag is checked, because checking it would mean
## deriving every key in between, and a forger could make it do that for
## free.
##
##   lane 1, receiver at 100, window 16
##   message 105 arrives   -> steps 100..105, opens        fine
##   message 400 arrives   -> 300 ahead, refused unchecked
##   message 401 arrives   -> refused, and so is every later one
##
## So a burst of losses wider than the window used to end the lane for good.
##
## ╭─ ❧ The cure: a jump the sender proves 🐦‍🔥
##
## The SENDER of that lane says where it is, and proves it with a key the
## receiver can check in one step -- no chain derivation first:
##
##   sender                                        receiver (stuck at 100)
##   ------                                        -----------------------
##   J = { epoch 1, lane 1, number 0, index 402 }
##   tag = BLAKE3-keyed( JK(0), J + binding )
##        ──────────────────── J, tag ─────────────────▶
##                                                 JK(0) from TK, check tag
##                                                 step lane 1: 100 -> 402
##                                                 drop its held keys
##                                                 erase JK(0); next: >= 1
##   message 402 ─────────────────────────────────▶ opens
##
## Messages 100..401 are given up; the carrier sends their content again in
## new messages, as it does for any loss.
##
## ╭─ ❧ Def. 1: the jump key JK, and why it advances 🍣
##
##   JK(number) = XHKDF( TK, "FOMKE-JUMP-KEY-v1" | epoch | lane | number )
##
## TK is the tight key every epoch already holds (see `fomkeTightKeyBytes`).
## JK is made only for one jump and erased right after, so a session holds
## nothing extra while its lanes are healthy.
##
## `number` is the advance. The sender counts its jumps (`sendJumps`), the
## receiver refuses any number below the next one it expects (`recvJumps`):
##
##   jump 0 accepted        -> receiver now wants >= 1
##   jump 0 replayed        -> refused: "FOMKE jump was already used"
##   jump 1 lost on the way -> jump 2 arrives, accepted; wants >= 3
##
## Every number gives a different JK, so a used key is never used again, and
## a lost jump costs nothing. Both counters start again at 0 in a new epoch:
## the epoch is part of JK, so jump 0 of epoch 2 is a different key from
## jump 0 of epoch 1.
##
## ╭─ ❧ Def. 2: the tag ⟡
##
##   tag = BLAKE3-keyed( JK, "FOMKE-JUMP-v1" | epoch u32 | lane u8 |
##                           number u32 | index u64 | len u32 | binding )
##
## `binding` is whatever the caller wraps the jump in -- AME binds its frame
## header, so a jump cannot be moved into another session or frame.
##
## ╭─ ❧ What a jump will not do ⌜guide⌟
##
##   during a KEM upgrade      refused: the upgrade has fixed both lanes'
##                             positions into its commit
##   further than `maxJump`    refused BEFORE the key is derived (default
##                             4096 positions); the session must be rebuilt
##   move a lane BACKWARDS     a jump to a position the lane already passed
##                             is accepted and changes nothing but `recvJumps`
##                             -- the receiver was not behind after all

import tyr/hashes/blake3 as tyr_blake3

import ../../types
import ../../ame/level0/bytes
import ../types
import runePragmas
import ./chain

const
  fomkeJumpKeyLabel = "FOMKE-JUMP-KEY-v1"
  fomkeJumpTagLabel = "FOMKE-JUMP-v1"

proc jumpKey(S: FomkeState, lane: FomkeLane, number: uint32): ByteSeq {.
    role: truthBuilder, tag: "cryptoBoundary|fomke|kdf".} =
  ## S/lane/number: JK(number) for that lane, a child of the tight key.
  var
    extra: ByteSeq = @[uint8(ord(lane))]
  appendAmeU32(extra, number)
  result = deriveFomkeTightChild(S, fomkeJumpKeyLabel, extra)

proc jumpTag(key: openArray[uint8], J: FomkeJump,
    aad: openArray[uint8]): ByteSeq {.role: math,
    tag: "cryptoBoundary|fomke".} =
  ## key/J/aad: Def. 2.
  var
    input: ByteSeq = @[]
  appendAmeLabel(input, fomkeJumpTagLabel)
  appendAmeU32(input, J.epoch)
  input.add(uint8(ord(J.lane)))
  appendAmeU32(input, J.number)
  appendAmeU64(input, J.index)
  appendFomkeField(input, aad)
  result = tyr_blake3.blake3KeyedHash(key, input, fomkeJumpTagBytes)

proc laneChain(S: FomkeState, lane: FomkeLane): FomkeChainState {.
    role: helper.} =
  ## S/lane: an owned copy of that lane's chain.
  if lane == flLane1:
    return cloneFomkeChain(S.lane1)
  result = cloneFomkeChain(S.lane2)

proc setLaneChain(S: var FomkeState, lane: FomkeLane,
    C: FomkeChainState) {.role: actor.} =
  ## S/lane/C: that lane's chain replaced, the old one erased.
  if lane == flLane1:
    clearFomkeChain(S.lane1)
    S.lane1 = C
    return
  clearFomkeChain(S.lane2)
  S.lane2 = C

proc sealFomkeJump*(S: var FomkeState,
    aad: openArray[uint8] = []): FomkeJump {.role: orchestrator,
    tag: "appApi|cryptoBoundary|fomke".} =
  ## S: the SENDER of a lane the peer can no longer follow.
  ## aad: binding bytes (AME passes its frame header).
  ## Returns "my next message on my lane is `index`", proved with the next
  ## unused jump key. The send counter moves whether or not this arrives.
  var
    lane: FomkeLane = flLane1
    key: ByteSeq = @[]
    C: FomkeChainState = default(FomkeChainState)
  requireFomkeQuiescent(S)
  if S.sendJumps == high(uint32):
    raise newException(ValueError, "FOMKE jump numbers are exhausted")
  lane = outboundFomkeLane(S.role)
  C = laneChain(S, lane)
  result = FomkeJump(epoch: S.epoch, lane: lane, number: S.sendJumps,
    index: C.nextIndex)
  clearFomkeChain(C)
  key = jumpKey(S, lane, result.number)
  result.tag = jumpTag(key, result, aad)
  secureClearAmeBytes(key)
  S.sendJumps = S.sendJumps + 1'u32

proc jumpRefusal(S: FomkeState, J: FomkeJump, maxJump: uint32): string {.
    role: parser, tag: "fomke|validation".} =
  ## S/J/maxJump: everything a jump can be refused for without a key.
  ## Empty when it may be checked.
  var
    C: FomkeChainState = default(FomkeChainState)
  if S.pending.active:
    return "FOMKE KEM upgrade is pending"
  if J.epoch != S.epoch:
    return "FOMKE jump is for another epoch"
  if J.lane != inboundFomkeLane(S.role):
    return "FOMKE jump names the wrong lane"
  if J.number < S.recvJumps or J.number == high(uint32):
    return "FOMKE jump was already used"
  if J.tag.len != fomkeJumpTagBytes:
    return "FOMKE jump tag is invalid"
  C = laneChain(S, J.lane)
  if J.index > C.nextIndex and J.index - C.nextIndex > uint64(maxJump):
    result = "FOMKE jump is longer than allowed"
  clearFomkeChain(C)

proc stepLaneTo(C: var FomkeChainState, lane: FomkeLane, epoch: uint32,
    c: XhkdfConfig, index: uint64) {.role: actor,
    tag: "cryptoBoundary|fomke|kdf".} =
  ## C: chain stepped forward to `index`, every key on the way erased at
  ## once -- those messages are given up, not held.
  var
    key: tuple[index: uint64, keyMaterial: ByteSeq] = (0'u64, @[])
  while C.nextIndex < index:
    key = advanceFomkeChain(C, lane, epoch, c)
    secureClearAmeBytes(key.keyMaterial)

proc dropLaneSkipped(S: var FomkeState, lane: FomkeLane): int {.
    role: actor, tag: "cryptoBoundary|fomke".} =
  ## S/lane: every held key of that lane erased; returns how many.
  var
    i: int = 0
  while i < S.skipped.len:
    if S.skipped[i].lane != lane:
      i = i + 1
      continue
    secureClearAmeBytes(S.skipped[i].keyMaterial)
    S.skipped.delete(i)
    result = result + 1

proc openFomkeJump*(S: var FomkeState, J: FomkeJump,
    aad: openArray[uint8] = [],
    maxJump: uint32 = fomkeDefaultMaxJump): FomkeJumpResult {.
    role: orchestrator, tag: "appApi|cryptoBoundary|fomke".} =
  ## S: the RECEIVER of the jumping lane.
  ## J: the jump. aad: the same binding bytes the sender used.
  ## maxJump: furthest this side lets one jump move its lane.
  ## Nothing changes unless the tag checks out.
  var
    key: ByteSeq = @[]
    expected: ByteSeq = @[]
    C: FomkeChainState = default(FomkeChainState)
  try:
    result.err = jumpRefusal(S, J, maxJump)
    if result.err.len > 0:
      return
    key = jumpKey(S, J.lane, J.number)
    expected = jumpTag(key, J, aad)
    secureClearAmeBytes(key)
    if not constantTimeEqualAme(expected, J.tag):
      result.err = "FOMKE jump did not authenticate"
      return
    C = laneChain(S, J.lane)
    if J.index > C.nextIndex:
      result.gaveUp = J.index - C.nextIndex
      stepLaneTo(C, J.lane, S.epoch, S.kdf, J.index)
      result.gaveUp = result.gaveUp + uint64(dropLaneSkipped(S, J.lane))
    setLaneChain(S, J.lane, C)
    S.recvJumps = J.number + 1'u32
    result.ok = true
  except ValueError as exc:
    secureClearAmeBytes(key)
    clearFomkeChain(C)
    result.err = exc.msg
