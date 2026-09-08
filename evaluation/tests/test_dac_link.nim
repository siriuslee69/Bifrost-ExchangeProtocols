## ---------------------------------------------------------------------
## DAC Link Tests <- the loop over a lossy, reordering, duplicating pipe
## ---------------------------------------------------------------------

import unittest

import ../../src/protocols/types
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/defaults
import ../../src/protocols/dac/level0/framing
import ../../src/protocols/dac/level2/package_transfer
import ../../src/protocols/dac/level3/link
import bifrostPragmas

type
  ## Pipe: a deliberately hostile link between two DacLinks.
  ## dropEvery: drop one frame out of every n; 0 drops nothing.
  ## reorder: deliver in reverse batches instead of arrival order.
  ## duplicate: deliver every frame twice.
  Pipe = object
    dropEvery: int
    reorder: bool
    duplicate: bool
    sent: int
    dropped: int

proc rampBytes(n: int): ByteSeq =
  ## n: payload length filled with a deterministic ramp.
  var
    i: int = 0
  result = newSeq[uint8](n)
  while i < n:
    result[i] = uint8((i * 7 + (i shr 3)) mod 251)
    i = i + 1

proc carry(P: var Pipe, F: seq[ByteSeq]): seq[ByteSeq] =
  ## P: pipe deciding what survives the trip.
  ## F: frames handed to the pipe.
  var
    i: int = 0
    kept: seq[ByteSeq] = @[]
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

proc runLink(payload: ByteSeq, d: DacScenarioDefaults, P: var Pipe,
    maxTicks: int = 40): tuple[ok: bool, got: ByteSeq, ticks: int] {.role: orchestrator.} =
  ## payload: bytes the sender ships.
  ## d: scenario defaults both ends run on.
  ## P: pipe the frames cross.
  ## maxTicks: give-up bound so a broken loop fails instead of hanging.
  var
    sender: DacLink = initDacLink(9'u64, 1'u32, d, 0xABCDEF'u64)
    receiver: DacLink = initDacLink(9'u64, 1'u32, d, 0x123456'u64)
    toReceiver: seq[ByteSeq] = @[]
    toSender: seq[ByteSeq] = @[]
    step: DacLinkStep
    nowMs: uint32 = 0'u32
    i: int = 0
    tick: int = 0
  toReceiver = carry(P, renderDacFrames(sender, beginDacPackage(sender,
    77'u64, payload, nowMs)))
  while tick < maxTicks:
    nowMs = nowMs + 60'u32
    i = 0
    while i < toReceiver.len:
      step = feedDacFrame(receiver, toReceiver[i], nowMs)
      toSender.add(renderDacFrames(receiver, step.messages))
      if step.kind == dlkPackageComplete:
        return (true, step.payload, tick)
      i = i + 1
    toReceiver = @[]
    i = 0
    while i < toSender.len:
      step = feedDacFrame(sender, toSender[i], nowMs)
      toReceiver.add(renderDacFrames(sender, step.messages))
      i = i + 1
    toSender = @[]
    step = tickDacLink(receiver, nowMs)
    toSender.add(renderDacFrames(receiver, step.messages))
    step = tickDacLink(sender, nowMs)
    toReceiver.add(renderDacFrames(sender, step.messages))
    toReceiver = carry(P, toReceiver)
    toSender = carry(P, toSender)
    tick = tick + 1
  result = (false, @[], tick)

suite "DAC link on a clean pipe":
  # {.testKind: tkUnit.}
  test "a package crosses and is committed":
    var
      payload: ByteSeq = rampBytes(20_000)
      P: Pipe
      outcome = runLink(payload, dacDefaultsFor(dscBadSignal), P)
    check outcome.ok
    check outcome.got == payload
    check P.dropped == 0

  # {.testKind: tkUnit.}
  test "the sender learns the package was committed":
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscBadSignal)
      sender: DacLink = initDacLink(4'u64, 2'u32, d, 1'u64)
      receiver: DacLink = initDacLink(4'u64, 2'u32, d, 2'u64)
      payload: ByteSeq = rampBytes(6_000)
      step: DacLinkStep
      back: seq[ByteSeq] = @[]
      frames: seq[ByteSeq] = renderDacFrames(sender,
        beginDacPackage(sender, 5'u64, payload, 0'u32))
      i: int = 0
    check sender.outgoing.active
    while i < frames.len:
      step = feedDacFrame(receiver, frames[i], 10'u32)
      back.add(renderDacFrames(receiver, step.messages))
      i = i + 1
    i = 0
    while i < back.len:
      discard feedDacFrame(sender, back[i], 20'u32)
      i = i + 1
    check dacLinkIdle(sender)
    check dacLinkIdle(receiver)

  # {.testKind: tkEdgeCase.}
  test "a second package cannot start while one is in flight":
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscBadSignal)
      sender: DacLink = initDacLink(4'u64, 2'u32, d, 1'u64)
    discard beginDacPackage(sender, 1'u64, rampBytes(4_000), 0'u32)
    expect ValueError:
      discard beginDacPackage(sender, 2'u64, rampBytes(4_000), 0'u32)

suite "DAC link under loss":
  # {.testKind: tkIntegration.}
  test "loss inside the parity budget is repaired without a round trip":
    var
      payload: ByteSeq = rampBytes(20_000)
      P: Pipe = Pipe(dropEvery: 9)
      outcome = runLink(payload, dacDefaultsFor(dscBadSignal), P)
    check outcome.ok
    check outcome.got == payload
    check P.dropped > 0

  # {.testKind: tkUnit.}
  test "loss past the parity budget still completes through exact repair":
    var
      payload: ByteSeq = rampBytes(30_000)
      P: Pipe = Pipe(dropEvery: 3)
      outcome = runLink(payload, dacDefaultsFor(dscBadSignal), P, 60)
    check outcome.ok
    check outcome.got == payload
    check P.dropped > 10

  # {.testKind: tkUnit.}
  test "heavy loss on a thin profile still completes":
    var
      payload: ByteSeq = rampBytes(9_000)
      P: Pipe = Pipe(dropEvery: 4)
      outcome = runLink(payload, dacDefaultsFor(dscHeavyLoss), P, 60)
    check outcome.ok
    check outcome.got == payload

suite "DAC link under reordering and duplication":
  # {.testKind: tkUnit.}
  test "reversed delivery order changes nothing":
    var
      payload: ByteSeq = rampBytes(20_000)
      P: Pipe = Pipe(reorder: true)
      outcome = runLink(payload, dacDefaultsFor(dscBadSignal), P)
    check outcome.ok
    check outcome.got == payload

  # {.testKind: tkUnit.}
  test "duplicated frames are absorbed":
    var
      payload: ByteSeq = rampBytes(12_000)
      P: Pipe = Pipe(duplicate: true)
      outcome = runLink(payload, dacDefaultsFor(dscBadSignal), P)
    check outcome.ok
    check outcome.got == payload

  # {.testKind: tkUnit.}
  test "loss plus reordering plus duplication together still complete":
    var
      payload: ByteSeq = rampBytes(20_000)
      P: Pipe = Pipe(dropEvery: 5, reorder: true, duplicate: true)
      outcome = runLink(payload, dacDefaultsFor(dscBadSignal), P, 60)
    check outcome.ok
    check outcome.got == payload

suite "DAC link gives up cleanly":
  # {.testKind: tkEdgeCase.}
  test "a link that can never complete reports failure instead of hanging":
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscBadSignal)
      sender: DacLink = initDacLink(1'u64, 1'u32, d, 1'u64)
      receiver: DacLink = initDacLink(1'u64, 1'u32, d, 2'u64)
      frames: seq[ByteSeq] = renderDacFrames(sender,
        beginDacPackage(sender, 3'u64, rampBytes(20_000), 0'u32))
      step: DacLinkStep
      nowMs: uint32 = 0'u32
      failed: bool = false
      tick: int = 0
    discard feedDacFrame(receiver, frames[0], nowMs)
    discard feedDacFrame(receiver, frames[1], nowMs)
    check dacLinkMissingCount(receiver) > 0
    check dacRepairRoundsLeft(receiver)
    while tick < 40:
      nowMs = nowMs + 400'u32
      step = tickDacLink(receiver, nowMs)
      if step.kind == dlkPackageFailed:
        failed = true
        break
      tick = tick + 1
    check failed
    check step.err.len > 0
    check not dacRepairRoundsLeft(receiver)
    check dacLinkIdle(receiver)

  # {.testKind: tkUnit.}
  test "the round budget is spent, not looped forever":
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscBadSignal)
      sender: DacLink = initDacLink(1'u64, 1'u32, d, 1'u64)
      receiver: DacLink = initDacLink(1'u64, 1'u32, d, 2'u64)
      frames: seq[ByteSeq] = renderDacFrames(sender,
        beginDacPackage(sender, 3'u64, rampBytes(20_000), 0'u32))
      hints: int = 0
      step: DacLinkStep
      nowMs: uint32 = 0'u32
      tick: int = 0
    discard feedDacFrame(receiver, frames[0], nowMs)
    discard feedDacFrame(receiver, frames[1], nowMs)
    while tick < 40:
      nowMs = nowMs + 400'u32
      step = tickDacLink(receiver, nowMs)
      if step.kind == dlkRepairRequested:
        hints = hints + 1
      if step.kind == dlkPackageFailed:
        break
      tick = tick + 1
    check hints == int(defaultDacPackageLimits().maxRepairRounds)

suite "DAC link refuses rubbish":
  # {.testKind: tkEdgeCase.}
  test "a malformed frame is reported, never raised":
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscBadSignal)
      S: DacLink = initDacLink(1'u64, 1'u32, d, 1'u64)
      step: DacLinkStep
    step = feedDacFrame(S, @[byte 0, 1, 2, 3], 0'u32)
    check step.kind == dlkIgnored
    check step.err.len > 0
    step = feedDacFrame(S, @[], 0'u32)
    check step.kind == dlkIgnored

  # {.testKind: tkUnit.}
  test "a frame for another session or lane is dropped":
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscBadSignal)
      mine: DacLink = initDacLink(1'u64, 1'u32, d, 1'u64)
      other: DacLink = initDacLink(2'u64, 1'u32, d, 1'u64)
      frames: seq[ByteSeq] = renderDacFrames(other,
        beginDacPackage(other, 3'u64, rampBytes(2_000), 0'u32))
      step: DacLinkStep = feedDacFrame(mine, frames[0], 0'u32)
    check step.kind == dlkIgnored
    check step.err.len > 0

  # {.testKind: tkUnit.}
  test "a truncated body is reported without ending the loop":
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscBadSignal)
      sender: DacLink = initDacLink(1'u64, 1'u32, d, 1'u64)
      receiver: DacLink = initDacLink(1'u64, 1'u32, d, 2'u64)
      frames: seq[ByteSeq] = renderDacFrames(sender,
        beginDacPackage(sender, 3'u64, rampBytes(2_000), 0'u32))
      broken: ByteSeq = frames[0]
      step: DacLinkStep
    broken.setLen(broken.len - 1)
    step = feedDacFrame(receiver, broken, 0'u32)
    check step.kind == dlkIgnored
    step = feedDacFrame(receiver, frames[0], 0'u32)
    check step.kind == dlkManifestAccepted

  # {.testKind: tkUnit.}
  test "chunks arriving before their manifest are ignored, not misfiled":
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscBadSignal)
      sender: DacLink = initDacLink(1'u64, 1'u32, d, 1'u64)
      receiver: DacLink = initDacLink(1'u64, 1'u32, d, 2'u64)
      frames: seq[ByteSeq] = renderDacFrames(sender,
        beginDacPackage(sender, 3'u64, rampBytes(6_000), 0'u32))
      step: DacLinkStep = feedDacFrame(receiver, frames[1], 0'u32)
    check step.kind == dlkIgnored
    check dacLinkMissingCount(receiver) == 0

  # {.testKind: tkUnit.}
  test "a repeated manifest does not restart a live receive":
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscBadSignal)
      sender: DacLink = initDacLink(1'u64, 1'u32, d, 1'u64)
      receiver: DacLink = initDacLink(1'u64, 1'u32, d, 2'u64)
      frames: seq[ByteSeq] = renderDacFrames(sender,
        beginDacPackage(sender, 3'u64, rampBytes(6_000), 0'u32))
      step: DacLinkStep
    discard feedDacFrame(receiver, frames[0], 0'u32)
    discard feedDacFrame(receiver, frames[1], 0'u32)
    check dacLinkMissingCount(receiver) > 0
    step = feedDacFrame(receiver, frames[0], 0'u32)
    check step.kind == dlkIgnored
    check dacLinkMissingCount(receiver) > 0
