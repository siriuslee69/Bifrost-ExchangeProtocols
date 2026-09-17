## ---------------------------------------------------------------------
## DAC Link Give-Up Tests <- both ends letting go of what cannot finish
## ---------------------------------------------------------------------
##
## A transfer that cannot succeed has to END. Not quietly, and not by sitting
## there: a link holds one package in each direction, and a relay slot is only
## reclaimable while BOTH of them are free. So a package nobody lets go of is
## not one stuck transfer -- it is one permanently occupied slot in a table
## with a fixed number of them.
##
##   sender                                receiver
##   ------                                --------
##   rounds spent, nothing acknowledged    rounds spent, chunks still missing
##            |                                     |
##            +--> dacSenderGaveUp                  +--> "exhausted its repair
##                 abandonDacPackage                      rounds"
##            |                                     |
##            +------------ both directions idle ---+
##                              |
##                     the slot may be reused
##
## The receiver's half was always here. The sender's half was not, and a soak
## found the hole by filling every slot on a server in two minutes.

import unittest

import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/defaults
import ../../src/protocols/dac/level2/package_transfer
import ../../src/protocols/dac/level3/link
import ./dac_link_support

suite "DAC link gives up cleanly":
  # {.testKind: tkEdgeCase.}
  test "a link that can never complete reports failure instead of hanging":
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscBadSignal)
      sender: DacLink = initDacLink(d, 1'u64)
      receiver: DacLink = initDacLink(d, 2'u64)
      frames: seq[DacTaggedMessage] = (
        beginDacPackage(sender, 3'u64, rampBytes(20_000), 0'u32))
      step: DacLinkStep = default(DacLinkStep)
      nowMs: uint32 = 0'u32
      failed: bool = false
      tick: int = 0
    discard feedDacMessage(receiver, frames[0].kind, frames[0].body, nowMs)
    discard feedDacMessage(receiver, frames[1].kind, frames[1].body, nowMs)
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
      sender: DacLink = initDacLink(d, 1'u64)
      receiver: DacLink = initDacLink(d, 2'u64)
      frames: seq[DacTaggedMessage] = (
        beginDacPackage(sender, 3'u64, rampBytes(20_000), 0'u32))
      hints: int = 0
      step: DacLinkStep = default(DacLinkStep)
      nowMs: uint32 = 0'u32
      tick: int = 0
    discard feedDacMessage(receiver, frames[0].kind, frames[0].body, nowMs)
    discard feedDacMessage(receiver, frames[1].kind, frames[1].body, nowMs)
    while tick < 40:
      nowMs = nowMs + 400'u32
      step = tickDacLink(receiver, nowMs)
      if step.kind == dlkRepairRequested:
        hints = hints + 1
      if step.kind == dlkPackageFailed:
        break
      tick = tick + 1
    check hints == int(defaultDacPackageLimits().maxRepairRounds)


  # {.testKind: tkRegression, covers: "dacSenderGaveUp", pins: "a sender whose peer vanished pinned its relay slot for good".}
  test "a sender whose peer stopped answering gives the package up":
    ## What this pins.
    ##
    ## The receiver could always give up. The sender could not: once its repair
    ## rounds were spent it simply stopped speaking, and `outgoing.active`
    ## stayed true with nothing left that could ever clear it.
    ##
    ## That is not a stuck package, it is a stuck SLOT. `dacSlotReclaimable`
    ## refuses to take a slot whose link has either direction active, so one
    ## server reply to a peer that had gone held its place in the relay table
    ## until the process ended. A soak filled all sixty-four slots that way in
    ## two minutes and then refused every new peer.
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscBadSignal)
      sender: DacLink = initDacLink(d, 1'u64)
      step: DacLinkStep = default(DacLinkStep)
      nowMs: uint32 = 0'u32
      failed: bool = false
      tick: int = 0
    ## The package goes out and nothing ever comes back -- no receipt, no
    ## commit, not one datagram. That is a peer that closed its socket.
    discard beginDacPackage(sender, 7'u64, rampBytes(20_000), nowMs)
    check sender.outgoing.active
    check not dacLinkIdle(sender)
    while tick < 60:
      nowMs = nowMs + 400'u32
      step = tickDacLink(sender, nowMs)
      if step.kind == dlkPackageFailed:
        failed = true
        break
      tick = tick + 1
    check failed
    check step.err.len > 0
    ## The point of the whole thing: the link is idle again, so the table may
    ## have its slot back.
    check not sender.outgoing.active
    check dacLinkIdle(sender)

  # {.testKind: tkUnit, covers: "dacSenderGaveUp".}
  test "a sender still being acknowledged does not give up":
    ## The rule above must not fire on a link that is working. Every round the
    ## sender spends is answered here, so the package completes the ordinary
    ## way and nothing is ever called lost.
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscCleanLan)
      sender: DacLink = initDacLink(d, 1'u64)
      receiver: DacLink = initDacLink(d, 2'u64)
      frames: seq[DacTaggedMessage] = (
        beginDacPackage(sender, 9'u64, rampBytes(20_000), 0'u32))
      step: DacLinkStep = default(DacLinkStep)
      back: seq[DacTaggedMessage] = @[]
      nowMs: uint32 = 0'u32
      lost: bool = false
      i: int = 0
      tick: int = 0
    ## Everything arrives, and everything the receiver says back is carried --
    ## including what it says while being FED, which is where the receipt and
    ## the commit are produced.
    while i < frames.len:
      back.add(feedDacMessage(receiver, frames[i].kind, frames[i].body,
        nowMs).messages)
      i = i + 1
    while tick < 40 and sender.outgoing.active:
      i = 0
      while i < back.len:
        if feedDacMessage(sender, back[i].kind, back[i].body,
            nowMs).kind == dlkPackageFailed:
          lost = true
        i = i + 1
      nowMs = nowMs + 50'u32
      back = tickDacLink(receiver, nowMs).messages
      step = tickDacLink(sender, nowMs)
      if step.kind == dlkPackageFailed:
        lost = true
      tick = tick + 1
    ## The package finished the ordinary way, and the give-up rule stayed out
    ## of it.
    check not lost
    check not sender.outgoing.active


suite "DAC link goes quiet when it is done":
  # {.testKind: tkRegression, covers: "endDacIncoming", pins: "a finished package left its ACK batch open and the link chattered for ever".}
  test "a package repaired from parity leaves nothing still asking to be sent":
    ## What this pins.
    ##
    ## The ACK window slides over ARRIVALS only, never over a hole -- that is
    ## deliberate, because a sequence pushed below the base can never appear in
    ## a receipt again. But the window belonged to one package, and the package
    ## used to end without it:
    ##
    ##   base                    the package is complete, and yet
    ##    |  X  .  X  X          pending = 2, so the batch is still due
    ##          ^                -> a receipt every deadline
    ##          the hole that       -> the batch slides nowhere
    ##          parity filled       -> so it happens again, and again
    ##
    ## Every one of those was a sealed datagram to a peer that had stopped
    ## listening, about ten a second per link, for the life of the process --
    ## and each refreshed the link's `lastSeenMs`, so the relay slot never
    ## looked quiet and was never reclaimed. A soak filled every slot on two
    ## servers this way and then refused every peer that was still there.
    var
      d: DacScenarioDefaults = dacDefaultsFor(dscCleanLan)
      sender: DacLink = initDacLink(d, 5'u64)
      receiver: DacLink = initDacLink(d, 6'u64)
      frames: seq[DacTaggedMessage] = (
        beginDacPackage(sender, 4'u64, rampBytes(24_000), 0'u32))
      step: DacLinkStep = default(DacLinkStep)
      nowMs: uint32 = 0'u32
      done: bool = false
      after: int = 0
      i: int = 1
    ## The manifest, then everything except the FIRST chunk. That puts the hole
    ## at the very front of the window -- the one position the batch can never
    ## slide past. Parity fills it and the package completes anyway, which is
    ## the ordinary shape of a repaired delivery.
    step = feedDacMessage(receiver, frames[0].kind, frames[0].body, nowMs)
    while i < frames.len:
      nowMs = nowMs + 5'u32
      if i != 1:
        step = feedDacMessage(receiver, frames[i].kind, frames[i].body, nowMs)
      if step.kind == dlkPackageComplete:
        done = true
      i = i + 1
    while not done and i < 400:
      nowMs = nowMs + 200'u32
      step = tickDacLink(receiver, nowMs)
      if step.kind == dlkPackageComplete:
        done = true
      i = i + 1
    check done
    check dacLinkIdle(receiver)
    ## Now let a great deal of time pass. A finished link says nothing.
    i = 0
    while i < 200:
      nowMs = nowMs + 250'u32
      after = after + tickDacLink(receiver, nowMs).messages.len
      i = i + 1
    check after == 0
