## -----------------------------------------------------------------------
## DAC Path Policy <- small path-lane recommendation helpers for DAC/AME
## -----------------------------------------------------------------------

import ../build

when not dacAdaptiveBuilt:
  {.error: "This module is part of the DAC adaptive layer, which -d:bifrostDac=off removed from this build.".}

import ../types
import ../level0/path_stats
import runePragmas

type
  ## DacPathRecommendation: one caller-facing path-lane suggestion.
  DacPathRecommendation* {.role: truthState.} = object
    ok*: bool
    path*: DacPathLane
    reason*: DacPathSwitchReason

proc pathRank(p: DacPathLane): int {.role: parser.} =
  ## p: DAC path lane to map into a monotone quality rank.
  case p
  of dplRecoveryPath:
    result = 0
  of dplLossyPath:
    result = 1
  of dplThinPath:
    result = 2
  of dplMobilePath:
    result = 3
  of dplCleanPath:
    result = 4
  of dplSuperCleanPath:
    result = 5
  of dplBlockedUdpPath:
    result = -1

proc pathFromRank(r: int): DacPathLane {.role: parser.} =
  ## r: monotone DAC path quality rank.
  case r
  of 0:
    result = dplRecoveryPath
  of 1:
    result = dplLossyPath
  of 2:
    result = dplThinPath
  of 3:
    result = dplMobilePath
  of 4:
    result = dplCleanPath
  else:
    result = dplSuperCleanPath

proc oneStepTowardPath(current, target: DacPathLane): DacPathLane {.role: parser.} =
  ## current/target: DAC paths whose next one-step move should be chosen.
  var
    currentRank: int = 0
    targetRank: int = 0
  currentRank = pathRank(current)
  targetRank = pathRank(target)
  if currentRank < 0 or targetRank < 0:
    return current
  if currentRank == targetRank:
    return current
  if currentRank < targetRank:
    return pathFromRank(currentRank + 1)
  result = pathFromRank(currentRank - 1)

proc initDacPathRecommendation*(path: DacPathLane,
    reason: DacPathSwitchReason): DacPathRecommendation {.role: configurator.} =
  ## path/reason: recommendation payload.
  result.ok = true
  result.path = path
  result.reason = reason

proc worseDacPath*(current: DacPathLane): DacPathLane {.role: parser.} =
  ## current: DAC path lane to degrade by one step when possible.
  if current == dplBlockedUdpPath:
    return dplBlockedUdpPath
  if pathRank(current) <= 0:
    return current
  result = pathFromRank(pathRank(current) - 1)

proc betterDacPath*(current: DacPathLane): DacPathLane {.role: parser.} =
  ## current: DAC path lane to strengthen by one step when possible.
  if current == dplBlockedUdpPath:
    return current
  if pathRank(current) >= 5:
    return current
  result = pathFromRank(pathRank(current) + 1)

proc dacStatReported(v: uint16): bool {.role: parser, inline.} =
  ## v: one field of a peer's path report.
  ##
  ## Zero means "I did not measure this", never "I measured zero". Only
  ## `lossPpm` is exempt, because a receiver that lost nothing really does
  ## mean it, and it is the one field every receiver can always fill in.
  ##
  ## This exists because of a bug worth remembering. `creditHint` was never
  ## filled in by anything, so every report carried a zero, and the rule below
  ## read `creditHint <= 32` as "the receiver is out of buffer". It is the
  ## FIRST rule, so it fired before loss, MTU or round trip were even looked
  ## at, on every report, on every link. A flawless LAN walked itself from the
  ## clean lane down to the recovery lane in four packages -- smaller chunks,
  ## six-way Reed-Solomon, four-chunk ACK batches -- and reported the reason
  ## as "receiver pressure" on a receiver that was completely idle.
  result = v > 0'u16

proc targetDacPathFromStats(stats: DacPathStats): tuple[path: DacPathLane,
    reason: DacPathSwitchReason] {.role: truthBuilder.} =
  ## stats: observed path metrics that should be mapped into a target lane.
  ##
  ## Each rule below is skipped when the number it reads was never measured,
  ## so a quiet field is treated as no opinion rather than as alarming news.
  ## The default when nothing has an opinion is the clean lane, which is the
  ## honest answer: a path that has shown no problem is not known to have one.
  if (dacStatReported(stats.queueMs) and stats.queueMs >= 1500'u16) or
      (dacStatReported(stats.creditHint) and stats.creditHint <= 32'u16):
    result.path = dplRecoveryPath
    result.reason = dpsrReceiverPressure
    return
  ## `dacShouldEnterLossyPath` also reads `reorderDepth`. Bifrost's own
  ## receiver never fills that in -- it shuffles its chunks on purpose, so
  ## chunk order measures the sender and not the wire (path_meter.nim spells
  ## this out) -- which leaves that half of the test permanently quiet here.
  ## It is kept because the field is on the wire and a carrier that DOES know
  ## its own send order could honestly fill it in one day. Loss is what
  ## actually drives this rule today.
  if dacShouldEnterLossyPath(stats) or
      (dacStatReported(stats.jitterMs) and stats.jitterMs >= 120'u16):
    result.path = dplLossyPath
    result.reason = dpsrLoss
    return
  if dacStatReported(stats.mtuHint) and stats.mtuHint < 700'u16:
    result.path = dplThinPath
    result.reason = dpsrMetered
    return
  if (dacStatReported(stats.rttMs) and stats.rttMs >= 180'u16) or
      (dacStatReported(stats.jitterMs) and stats.jitterMs >= 40'u16):
    result.path = dplMobilePath
    result.reason = dpsrMetered
    return
  ## The top lane is the one case where an unmeasured field must NOT be waved
  ## through: claiming a 32 KB path on the strength of numbers nobody took
  ## would be the same mistake in the opposite direction. Every input here has
  ## to have been measured AND be good.
  if stats.lossPpm <= 200'u32 and
      dacStatReported(stats.rttMs) and stats.rttMs <= 5'u16 and
      dacStatReported(stats.queueMs) and stats.queueMs <= 2'u16 and
      dacStatReported(stats.mtuHint) and stats.mtuHint >= 4096'u16 and
      stats.jitterMs <= 2'u16:
    result.path = dplSuperCleanPath
    result.reason = dpsrLoss
    return
  result.path = dplCleanPath
  result.reason = dpsrLoss

proc recommendDacPathFromStats*(current: DacPathLane,
    stats: DacPathStats): DacPathRecommendation {.role: truthBuilder.} =
  ## current: current DAC path lane.
  ## stats: observed path metrics.
  var
    target: tuple[path: DacPathLane, reason: DacPathSwitchReason] =
      (dplCleanPath, dpsrLoss)
    nextPath: DacPathLane = dplCleanPath
  if current == dplBlockedUdpPath:
    return
  target = targetDacPathFromStats(stats)
  nextPath = oneStepTowardPath(current, target.path)
  if nextPath == current:
    return
  result = initDacPathRecommendation(nextPath, target.reason)

proc recommendDacPathFromFailures*(current: DacPathLane,
    retryCount, authFailures: uint8): DacPathRecommendation {.role: truthBuilder.} =
  ## current: current DAC path lane.
  ## retryCount/authFailures: runtime failure pressure observed by the autopilot.
  if current == dplBlockedUdpPath:
    return
  if authFailures >= 3'u8:
    if current == dplRecoveryPath:
      return
    result = initDacPathRecommendation(worseDacPath(worseDacPath(current)),
      dpsrReceiverPressure)
    return
  if retryCount >= 2'u8:
    if current == dplRecoveryPath:
      return
    result = initDacPathRecommendation(worseDacPath(current), dpsrLoss)
