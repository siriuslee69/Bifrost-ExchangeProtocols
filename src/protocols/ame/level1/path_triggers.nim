## -------------------------------------------------------------------------
## AME Tier Path <- ordered mask tiers and automatic transition triggers
## -------------------------------------------------------------------------

import ../types
import ./exchange_paths
import ./suites
import ../../../analysis_pragmas

const
  defaultAmeDataStepMiB* = 200'u64

proc tierIndex(S: AmeTierPath, tierId: uint32): int {.role: parser.} =
  ## S/tierId: ordered path and stable tier identity to locate.
  var i: int = 0
  while i < int(S.tierCount):
    if S.tiers[i].tierId == tierId:
      return i
    i = i + 1
  result = -1

proc ameTierPathContains*(S: AmeTierPath, t: AmeMaskTier): bool {.
    role: parser.} =
  ## S/t: exact stable tier identity and masks allowed by this path.
  var i: int = tierIndex(S, t.tierId)
  result = i >= 0 and tiersEquivalent(S.tiers[i], t)

proc ameTierPathAllowsTransition*(S: AmeTierPath, current,
    target: AmeMaskTier): bool {.role: parser.} =
  ## S/current/target: exact configured transition that never moves backward.
  var
    currentIndex: int = tierIndex(S, current.tierId)
    targetIndex: int = tierIndex(S, target.tierId)
  result = currentIndex >= 0 and targetIndex >= currentIndex and
    tiersEquivalent(S.tiers[currentIndex], current) and
    tiersEquivalent(S.tiers[targetIndex], target)

proc validateAmeTierIndex(S: AmeTierPath, i: int) {.role: parser.} =
  ## S/i: ordered path and zero-based tier index.
  if i < 0 or i >= int(S.tierCount):
    raise newException(ValueError, "AME trigger tier is outside the tier path")

proc initAmeTierPath*(L: AmeSuiteLayout,
    T: openArray[AmeMaskTier]): AmeTierPath {.role: wrapper.} =
  ## L/T: immutable algorithm layout and ordered stable mask tiers.
  var
    i: int = 0
    j: int = 0
  if T.len == 0 or T.len > ameMaxAlgorithmSlots:
    raise newException(ValueError, "AME tier path must contain 1..8 tiers")
  result.layout = L
  result.tierCount = uint8(T.len)
  while i < T.len:
    validateAmeTier(L, T[i])
    j = 0
    while j < i:
      if T[j].tierId == T[i].tierId:
        raise newException(ValueError, "AME tier path contains duplicate ids")
      j = j + 1
    result.tiers[i] = T[i]
    result.triggers[i].kind = if i == 0: aptElapsedMs else: aptTransferredMiB
    result.triggers[i].threshold = if i == 0: 0'u64 else:
      defaultAmeDataStepMiB * uint64(i)
    result.triggers[i].enabled = true
    i = i + 1

proc ameInitTierPath*(A: AmeKemAlgorithms): AmeTierPath {.role: wrapper.} =
  ## A: immutable KEM layout expanded into progressive default mask tiers.
  var
    L: AmeSuiteLayout = defaultAmeLayout(A)
    T: array[ameMaxAlgorithmSlots, AmeMaskTier]
    masks: AmeTierMasks
    i: int = 0
  masks = initAmeTierMasks(0'u8, occupiedAmeMask(L.ciphers.length),
    occupiedAmeMask(L.macs.length), occupiedAmeMask(L.hashes.length),
    occupiedAmeMask(L.signatures.length), occupiedAmeMask(L.kdfs.length))
  while i < int(A.length):
    masks.kem = masks.kem or slotMask(i)
    T[i] = initAmeMaskTier(L, uint32(i + 1), masks)
    i = i + 1
  result = initAmeTierPath(L, T.toOpenArray(0, int(A.length) - 1))

proc setCurrentAmeTier*(S: var AmeTierPath, t: AmeMaskTier) {.
    role: stateController.} =
  ## S/t: path synchronized to the exact tier installed in the current epoch.
  var i: int = tierIndex(S, t.tierId)
  if i < 0 or not tiersEquivalent(S.tiers[i], t):
    raise newException(ValueError, "AME current tier is not in the tier path")
  S.currentTierId = t.tierId
  S.triggers[i].fired = true

proc setTrigger*(S: var AmeTierPath, i: int, transferredMiB: uint64) {.
    role: stateController.} =
  ## S/i/transferredMiB: path tier and cumulative successful plaintext MiB.
  validateAmeTierIndex(S, i)
  if transferredMiB > high(uint64) div ameBytesPerMiB:
    raise newException(ValueError, "AME transferred-MiB trigger is too large")
  S.triggers[i].kind = aptTransferredMiB
  S.triggers[i].threshold = transferredMiB
  S.triggers[i].enabled = true
  S.triggers[i].fired = false

proc setTimeTrigger*(S: var AmeTierPath, i: int, elapsedMs: uint64) {.
    role: stateController.} =
  ## S/i/elapsedMs: path tier and cumulative session-relative milliseconds.
  validateAmeTierIndex(S, i)
  S.triggers[i].kind = aptElapsedMs
  S.triggers[i].threshold = elapsedMs
  S.triggers[i].enabled = true
  S.triggers[i].fired = false

proc setManualTrigger*(S: var AmeTierPath, i: int) {.
    role: stateController.} =
  ## S/i: path tier made available only through requestTier.
  validateAmeTierIndex(S, i)
  S.triggers[i].kind = aptManual
  S.triggers[i].threshold = 0'u64
  S.triggers[i].enabled = true
  S.triggers[i].fired = false

proc disableTrigger*(S: var AmeTierPath, i: int) {.
    role: stateController.} =
  ## S/i: path tier whose automatic trigger is disabled.
  validateAmeTierIndex(S, i)
  S.triggers[i].enabled = false

proc dueAmeTierMask(S: var AmeTierPath): uint8 {.role: truthBuilder.} =
  ## S: trigger state whose newly due tiers are marked exactly once.
  var
    i: int = 0
    due: bool = false
  while i < int(S.tierCount):
    due = false
    if S.triggers[i].enabled and not S.triggers[i].fired:
      case S.triggers[i].kind
      of aptManual:
        discard
      of aptTransferredMiB:
        due = S.transferredBytes >= S.triggers[i].threshold * ameBytesPerMiB
      of aptElapsedMs:
        due = S.elapsedMs >= S.triggers[i].threshold
    if due:
      S.dueMask = S.dueMask or slotMask(i)
    i = i + 1
  result = S.dueMask

proc currentTier(S: AmeTierPath): AmeMaskTier {.role: parser.} =
  ## S: exact current tier, or an empty tier before initial establishment.
  var i: int = tierIndex(S, S.currentTierId)
  if i >= 0:
    result = S.tiers[i]

proc transitionExchangeMask(S: AmeTierPath, target: AmeMaskTier,
    rekeyMask: uint8): uint8 {.role: truthBuilder.} =
  ## S/target/rekeyMask: newly active KEM slots plus requested active rekeys.
  var current: AmeMaskTier = currentTier(S)
  if (rekeyMask and not target.masks.kem) != 0'u8:
    raise newException(ValueError, "AME rekey mask is outside the target tier")
  result = (target.masks.kem and not current.masks.kem) or rekeyMask

proc pathStep(S: AmeTierPath, i: int,
    rekeyMask: uint8 = 0'u8): AmeTierStep {.role: truthBuilder.} =
  ## S/i/rekeyMask: configured target tier and independent rekey selection.
  var m: uint8 = 0'u8
  if i < 0:
    return
  m = transitionExchangeMask(S, S.tiers[i], rekeyMask)
  result.available = true
  result.targetTier = S.tiers[i]
  result.exchangeMask = m
  result.request = initAmeExchangeRequest(S.layout.kems, result.targetTier, m)

proc nextDueTier(S: AmeTierPath): int {.role: parser.} =
  ## S: first ordered due tier after the current path position.
  var
    current: int = tierIndex(S, S.currentTierId)
    i: int = current + 1
  if current < 0:
    i = 0
  while i < int(S.tierCount):
    if algorithmSlotSelected(S.dueMask, i):
      return i
    i = i + 1
  result = -1

proc start*(S: var AmeTierPath): AmeTierStep {.role: orchestrator.} =
  ## S: path whose first immediate tier may become due before a handshake.
  discard dueAmeTierMask(S)
  result = pathStep(S, nextDueTier(S))

proc feedTransferredBytes*(S: var AmeTierPath,
    byteCount: uint64): AmeTierStep {.role: orchestrator.} =
  ## S/byteCount: successful plaintext accounting and next ordered tier.
  if high(uint64) - S.transferredBytes < byteCount:
    S.transferredBytes = high(uint64)
  else:
    S.transferredBytes = S.transferredBytes + byteCount
  discard dueAmeTierMask(S)
  result = pathStep(S, nextDueTier(S))

proc feedElapsedMs*(S: var AmeTierPath,
    elapsedMs: uint64): AmeTierStep {.role: orchestrator.} =
  ## S/elapsedMs: monotonic session-relative clock and next ordered tier.
  if elapsedMs > S.elapsedMs:
    S.elapsedMs = elapsedMs
  discard dueAmeTierMask(S)
  result = pathStep(S, nextDueTier(S))

proc requestTier*(S: var AmeTierPath, tierId: uint32,
    rekeyMask: uint8 = 0'u8): AmeTierStep {.role: orchestrator.} =
  ## S/tierId/rekeyMask: exact target tier and selected active KEM rekeys.
  ##
  ## The returned exchange mask covers only the KEM slots the target tier adds
  ## on top of the current one, plus whatever `rekeyMask` names. If the target
  ## tier selects the same KEM slots as the current tier, the mask is zero:
  ##
  ##   current tier kem = 1000_0000
  ##   target  tier kem = 1000_0000   rekeyMask = 0  ->  exchange mask = 0
  ##   target  tier kem = 1100_0000   rekeyMask = 0  ->  exchange mask = 0100_0000
  ##
  ## A zero mask still rotates the epoch and still changes every traffic key,
  ## because the new epoch mixes in a fresh transcript salt. It does NOT run a
  ## new KEM, so it does not advance forward secrecy: an attacker holding the
  ## current KEM secrets keeps reading traffic. Pass `rekeyMask` to force fresh
  ## key agreement on slots that are already active.
  var i: int = tierIndex(S, tierId)
  var current: int = tierIndex(S, S.currentTierId)
  if i < 0:
    raise newException(ValueError, "AME requested tier is outside the tier path")
  if current >= 0 and i < current:
    raise newException(ValueError, "AME tier path cannot move backward")
  S.dueMask = S.dueMask or slotMask(i)
  result = pathStep(S, i, rekeyMask)

proc claimAmeTier*(S: var AmeTierPath, step: AmeTierStep) {.
    role: stateController.} =
  ## S/step: one due tier moved into an active exchange transaction.
  var i: int = tierIndex(S, step.targetTier.tierId)
  if not step.available or i < 0 or
      not algorithmSlotSelected(S.dueMask, i) or S.inFlightTierId != 0'u32:
    raise newException(ValueError, "AME trigger tier is not available")
  S.dueMask = S.dueMask and not slotMask(i)
  S.inFlightTierId = step.targetTier.tierId

proc completeAmeTier*(S: var AmeTierPath, t: AmeMaskTier) {.
    role: stateController.} =
  ## S/t: authenticated target tier installed into the current epoch.
  var i: int = tierIndex(S, t.tierId)
  if i < 0 or S.inFlightTierId != t.tierId or
      not tiersEquivalent(S.tiers[i], t):
    raise newException(ValueError, "AME completed tier differs")
  S.triggers[i].fired = true
  S.currentTierId = t.tierId
  S.inFlightTierId = 0'u32

proc releaseAmeTier*(S: var AmeTierPath) {.role: stateController.} =
  ## S: failed in-flight tier returned to the due queue.
  var i: int = tierIndex(S, S.inFlightTierId)
  if i >= 0:
    S.dueMask = S.dueMask or slotMask(i)
  S.inFlightTierId = 0'u32
