## ---------------------------------------------------------------------
## DAC Link Tests <- the loop over a lossy, reordering, duplicating pipe
## ---------------------------------------------------------------------

import unittest

import ../../src/protocols/types
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/defaults
import ../../src/protocols/dac/level3/link
import ./dac_link_support

suite "DAC link on a clean pipe":
  # {.testKind: tkUnit.}
  test "a package crosses and is committed":
    var
      payload: ByteSeq = rampBytes(20_000)
      P: Pipe = Pipe(dropEvery: 0)
      outcome = runLink(payload, dacDefaultsFor(dscBadSignal), P)
    check outcome.ok
    check outcome.got == payload
    check P.dropped == 0

  # {.testKind: tkUnit.}
  test "the sender learns the package was committed":
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscBadSignal)
      sender: DacLink = initDacLink(d, 1'u64)
      receiver: DacLink = initDacLink(d, 2'u64)
      payload: ByteSeq = rampBytes(6_000)
      step: DacLinkStep = default(DacLinkStep)
      back: seq[DacTaggedMessage] = @[]
      frames: seq[DacTaggedMessage] = (
        beginDacPackage(sender, 5'u64, payload, 0'u32))
      i: int = 0
    check sender.outgoing.active
    while i < frames.len:
      step = feedDacMessage(receiver, frames[i].kind, frames[i].body,
        10'u32)
      back.add(step.messages)
      i = i + 1
    i = 0
    while i < back.len:
      discard feedDacMessage(sender, back[i].kind, back[i].body, 20'u32)
      i = i + 1
    check dacLinkIdle(sender)
    check dacLinkIdle(receiver)

  # {.testKind: tkEdgeCase.}
  test "a second package cannot start while one is in flight":
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscBadSignal)
      sender: DacLink = initDacLink(d, 1'u64)
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

suite "DAC link refuses rubbish":
  # {.testKind: tkEdgeCase.}
  test "a malformed body is reported, never raised":
    ## The loop is handed a kind and a body, both already authenticated by
    ## AME. It must still refuse a body that does not decode -- a peer who
    ## holds the keys can send nonsense, and nonsense must not end the loop.
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscBadSignal)
      S: DacLink = initDacLink(d, 1'u64)
      step: DacLinkStep = default(DacLinkStep)
    step = feedDacMessage(S, dmkPackageManifest, @[byte 0, 1, 2, 3], 0'u32)
    check step.kind == dlkIgnored
    check step.err.len > 0
    step = feedDacMessage(S, dmkPackageManifest, @[], 0'u32)
    check step.kind == dlkIgnored
    check step.err.len > 0

  # {.testKind: tkEdgeCase.}
  test "the byte no kind claims is ignored":
    ## `dmkUnknown` is what `dacMessageKindFromId` answers for a first byte
    ## outside the enum. It is the only kind the loop has no branch for, and
    ## after four unhandled kinds were deleted it is the only one there can be.
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscBadSignal)
      S: DacLink = initDacLink(d, 1'u64)
      step: DacLinkStep = feedDacMessage(S, dmkUnknown, @[byte 1], 0'u32)
    check step.kind == dlkIgnored

## The test that used to sit here -- "a frame for another session or lane is
## dropped" -- checked a session id the DAC header carried. There is no DAC
## header now, so that binding is AME's to enforce and it does: see
## test_attack_surface.nim, "a frame from another session is refused by this
## one". The check did not disappear, it moved to the layer that owns it.

