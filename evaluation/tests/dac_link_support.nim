## ---------------------------------------------------------------------
## DAC Link Support <- the hostile pipe two test files both drive
## ---------------------------------------------------------------------
##
## Two files ask different questions of the same loop:
##
##   test_dac_link         does a package survive loss, reordering and
##                         duplication, and come out byte for byte
##   test_dac_link_giveup  does a link that CANNOT finish say so, and let go
##
## The pipe and the two-ended runner below are what both of them need, so
## they live here rather than in whichever file happened to be written first.

import ../../src/protocols/types
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level3/link
import runePragmas

type
  ## Pipe: a deliberately hostile link between two DacLinks.
  ## dropEvery: drop one frame out of every n; 0 drops nothing.
  ## reorder: deliver in reverse batches instead of arrival order.
  ## duplicate: deliver every frame twice.
  Pipe* = object
    dropEvery*: int
    reorder*: bool
    duplicate*: bool
    sent*: int
    dropped*: int

proc rampBytes*(n: int): ByteSeq {.role: helper.} =
  ## n: payload length filled with a deterministic ramp.
  var
    i: int = 0
  result = newSeq[uint8](n)
  while i < n:
    result[i] = uint8((i * 7 + (i shr 3)) mod 251)
    i = i + 1

proc carry*(P: var Pipe, F: seq[DacTaggedMessage]): seq[DacTaggedMessage] {.
    role: dataWriter.} =
  ## P: pipe deciding what survives the trip.
  ## F: messages handed to the pipe.
  ##
  ## Messages, not frames. DAC does not frame anything itself any more -- what
  ## it hands out is a kind and a body, and AME is what puts those on a wire.
  ## The pipe drops, reorders and duplicates them exactly as it did the bytes,
  ## because none of those hazards care what the framing looks like.
  var
    i: int = 0
    kept: seq[DacTaggedMessage] = @[]
  while i < F.len:
    P.sent = P.sent + 1
    if P.dropEvery > 0 and P.sent mod P.dropEvery == 0:
      P.dropped = P.dropped + 1
    else:
      kept.add(F[i])
      if P.duplicate:
        kept.add(F[i])
    i = i + 1
  if not P.reorder:
    return kept
  i = kept.len - 1
  while i >= 0:
    result.add(kept[i])
    i = i - 1

proc runLink*(payload: ByteSeq, d: DacScenarioDefaults, P: var Pipe,
    maxTicks: int = 40): tuple[ok: bool, got: ByteSeq, ticks: int] {.role: orchestrator.} =
  ## payload: bytes the sender ships.
  ## d: scenario defaults both ends run on.
  ## P: pipe the frames cross.
  ## maxTicks: give-up bound so a broken loop fails instead of hanging.
  var
    sender: DacLink = initDacLink(d, 0xABCDEF'u64)
    receiver: DacLink = initDacLink(d, 0x123456'u64)
    toReceiver: seq[DacTaggedMessage] = @[]
    toSender: seq[DacTaggedMessage] = @[]
    step: DacLinkStep = default(DacLinkStep)
    nowMs: uint32 = 0'u32
    i: int = 0
    tick: int = 0
  toReceiver = carry(P, beginDacPackage(sender,
    77'u64, payload, nowMs))
  while tick < maxTicks:
    nowMs = nowMs + 60'u32
    i = 0
    while i < toReceiver.len:
      step = feedDacMessage(receiver, toReceiver[i].kind,
        toReceiver[i].body, nowMs)
      toSender.add(step.messages)
      if step.kind == dlkPackageComplete:
        return (true, step.payload, tick)
      i = i + 1
    toReceiver = @[]
    i = 0
    while i < toSender.len:
      step = feedDacMessage(sender, toSender[i].kind, toSender[i].body,
        nowMs)
      toReceiver.add(step.messages)
      i = i + 1
    toSender = @[]
    step = tickDacLink(receiver, nowMs)
    ## A package can finish on the receiver's OWN tick, not only while a
    ## message is being fed: that is what happens when the last hole is filled
    ## by rebuilding a group from parity already in hand. Watching only the
    ## feed loop misses it, and the run then burns every remaining tick and
    ## reports a failure for a payload that is sitting complete in the
    ## receiver. The loop reports the event; the harness has to read it.
    if step.kind == dlkPackageComplete:
      return (true, step.payload, tick)
    toSender.add(step.messages)
    step = tickDacLink(sender, nowMs)
    toReceiver.add(step.messages)
    toReceiver = carry(P, toReceiver)
    toSender = carry(P, toSender)
    tick = tick + 1
  result = (false, @[], tick)
