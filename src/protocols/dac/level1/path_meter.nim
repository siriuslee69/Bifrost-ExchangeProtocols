## -------------------------------------------------------------------------
## DAC Path Meter <- what a RECEIVER can honestly say about the path
## -------------------------------------------------------------------------
##
## A receiver reports facts about itself. It cannot measure a round trip --
## nothing it holds was ever echoed back to it -- but it can measure two
## things nobody else can, and the lane policy reads both.
##
##   the clock, at each arrival
##
##      t0  t1  t2  t3  t4  ...
##       \__/\__/\__/         gap = this arrival - the one before
##        20  22  95          jitter = how much that gap KEEPS changing
##
##   how long this receive has been open
##
##      manifest arrives ......................... package completes
##      |<---------------- queue time ---------------->|
##
##      A receiver holding an unfinished package is holding memory. That
##      wait IS the pressure it is under, so it is the number it reports.
##
## ╭─ ❧ What is deliberately NOT measured here 🌊
##
## Reordering. It looks like the easiest of the three -- chunk ids arrive,
## count how far back they jump -- and it is the one a receiver cannot know:
##
##      the sender SHUFFLES on purpose      (dacChunkSendOrder, Fisher-Yates
##      across the whole package, on by default, so an observer cannot read
##      a file's shape out of the order its pieces cross the wire)
##
##      0  1  2 ... 33      what the package looks like
##      19 4 27 ... 8       the order the SENDER chose to emit it in
##      19 4 27 ... 8       the order it arrives in on a flawless wire
##
## Measured against chunk ids, a perfect 34-chunk delivery reports a reorder
## depth of 31 and `dacShouldEnterLossyPath` says yes on the strength of it.
## The number is real; it is just a measurement of the sender's shuffling and
## not of the path. So this meter does not produce one, `measureDacPath`
## leaves the wire field at zero, and the lane rule that reads it stays quiet.
## Measuring it properly needs the CARRIER's send counter -- AME stamps a
## monotonic sequence on every frame, and an inversion in THAT is the network's
## doing -- which means handing the sequence down into the loop. Worth doing
## the day the rule is wanted; not worth a wrong number in the meantime.
##
## Every field starts at zero and zero means "I did not measure this". The
## lane policy skips a rule whose input is missing rather than believing it.
## That rule exists because the opposite once happened: an unfilled credit
## field read as "the receiver is out of buffer" walked every link, however
## clean, down to the recovery lane one package at a time.

import ../build

when not dacAdaptiveBuilt:
  {.error: "This module is part of the DAC adaptive layer, which -d:bifrostDac=off removed from this build.".}

import runePragmas

const
  dacJitterSmoothingShift* = 2'u32
    ## New gaps count for a quarter, the running value for three quarters.
    ## The same 3:1 fold the sender's repair timer uses, so the two numbers
    ## move at a comparable speed and can be read side by side.

type
  ## DacArrivalMeter: one receive's arrival pattern, measured as it lands.
  ## startedMs: when the manifest opened this receive.
  ## lastMs: when the last chunk landed, for the next gap.
  ## lastGapMs: the gap before that chunk.
  ## jitterMs: smoothed change in that gap -- not the gap itself.
  ## samples: arrivals folded in, so a caller can tell "clean" from "silent".
  DacArrivalMeter* {.role: truthState,
      expectedCount: [0, 512], lifeCycle: lcSession.} = object
    startedMs*: uint32
    lastMs*: uint32
    lastGapMs*: uint16
    jitterMs*: uint16
    samples*: uint16

proc initDacArrivalMeter*(nowMs: uint32): DacArrivalMeter {.
    role: configurator.} =
  ## nowMs: caller's millisecond clock, taken as the moment this receive opened.
  result.startedMs = nowMs
  result.lastMs = nowMs

proc foldDacJitter(S: var DacArrivalMeter, gap: uint16) {.
    role: math, inline.} =
  ## S: meter whose jitter absorbs one inter-arrival gap.
  ## gap: milliseconds since the previous arrival.
  ## Jitter is how much the gap CHANGES, so the first gap teaches it nothing:
  ## a link delivering one chunk every 20ms forever has a gap of 20 and a
  ## jitter of 0, which is the honest reading of a perfectly steady path.
  var
    change: uint16 = 0'u16
  if S.samples >= 2'u16:
    change = if gap > S.lastGapMs: gap - S.lastGapMs else: S.lastGapMs - gap
    S.jitterMs = uint16((uint32(S.jitterMs) * ((1'u32 shl
      dacJitterSmoothingShift) - 1'u32) + uint32(change)) shr
      dacJitterSmoothingShift)
  S.lastGapMs = gap

proc observeDacChunkArrival*(S: var DacArrivalMeter, nowMs: uint32) {.
    role: actor.} =
  ## S: meter updated from one chunk landing.
  ## nowMs: caller's millisecond clock.
  ## The chunk's id is deliberately not taken: see the note at the top of this
  ## file about why a receiver cannot read reordering out of it.
  var
    gap: uint32 = nowMs - S.lastMs
  if S.samples < high(uint16):
    S.samples = S.samples + 1'u16
  foldDacJitter(S, uint16(min(gap, uint32(high(uint16)))))
  S.lastMs = nowMs

proc dacQueueMs*(S: DacArrivalMeter, nowMs: uint32): uint16 {.role: math.} =
  ## S: meter holding the moment this receive opened.
  ## nowMs: caller's millisecond clock.
  ## How long the receiver has been holding an unfinished package, saturated
  ## at the widest value the wire field can carry.
  result = uint16(min(nowMs - S.startedMs, uint32(high(uint16))))
