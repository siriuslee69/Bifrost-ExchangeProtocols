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

proc targetDacPathFromStats(stats: DacPathStats): tuple[path: DacPathLane,
    reason: DacPathSwitchReason] {.role: truthBuilder.} =
  ## stats: observed path metrics that should be mapped into a target lane.
  if stats.queueMs >= 1500'u16 or stats.creditHint <= 32'u16:
    result.path = dplRecoveryPath
    result.reason = dpsrReceiverPressure
    return
  if dacShouldEnterLossyPath(stats) or stats.jitterMs >= 120'u16:
    result.path = dplLossyPath
    result.reason = dpsrLoss
    return
  if stats.mtuHint > 0'u16 and stats.mtuHint < 700'u16:
    result.path = dplThinPath
    result.reason = dpsrMetered
    return
  if stats.rttMs >= 180'u16 or stats.jitterMs >= 40'u16:
    result.path = dplMobilePath
    result.reason = dpsrMetered
    return
  if stats.lossPpm <= 200'u32 and stats.rttMs <= 5'u16 and
      stats.jitterMs <= 2'u16 and stats.queueMs <= 2'u16 and
      stats.mtuHint >= 4096'u16:
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
    target: tuple[path: DacPathLane, reason: DacPathSwitchReason]
    nextPath: DacPathLane
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
