## -------------------------------------------------------------------------
## DAC Link Table <- one process, many peers, a bounded amount of memory
## -------------------------------------------------------------------------

import ../build

when not dacAdaptiveBuilt:
  {.error: "This module is part of the DAC adaptive layer, which -d:bifrostDac=off removed from this build.".}

import ../types
import ../level0/framing
import ../level0/defaults
import ../level1/scramble
import ../level2/package_transfer
import ./link
import ../../../analysis_pragmas

const
  dacLinkTableAscii* = """
A DacLink is one conversation. A server holds many, so something has to say
which arriving datagram belongs to which one, and how much that is allowed
to cost.

   datagram + peer address
             |
             v
   peekDacFrameIdentity()      <- fixed prefix only, no body allocation
             |
             v
   find (host, port, carrier)  <- linear scan of a capped array
        |            |
     found        not found
        |            |
        v            v
   feedDacFrame   admit? -> a free slot, or an IDLE slot to reuse
                     |
                  neither: REFUSE. An established link is never evicted
                  to make room for a stranger.

Capacity is a hard number, not a hint. The table is an array the peer can
push on, so it is the one structure in DAC an attacker would try to grow:
every path that adds an entry is bounded, and the eviction rule only ever
takes from links that have finished their work and gone quiet.

Linear scan over a hash map is deliberate at these sizes. A few dozen slots
compare faster than they hash, and there is no key an attacker can choose to
force collisions with.
"""

  dacLinkTableCapacity* = 64
    ## Slots in a table built with the default. Chosen so the whole structure
    ## stays countable on a small device; a server passes its own number.

  dacLinkIdleSweepMs* = 30_000'u32
    ## How long a finished link may sit untouched before a sweep may take its
    ## slot. Only links that are idle in BOTH directions are ever candidates.

type
  ## DacLinkCarrier: which transport a peer was reached over. Two peers can
  ## share an address and still be different links, so the carrier is part of
  ## the key rather than a property hanging off it.
  DacLinkCarrier* = enum
    dlcDatagram,
    dlcStream,
    dlcLoopback

  ## DacLinkKey: what identifies one conversation to the table.
  DacLinkKey* {.role: truthState.} = object
    host*: string
    port*: uint16
    carrier*: DacLinkCarrier

  ## DacLinkSlot: one occupied or free position in the table.
  ## lastSeenMs: when this link last accepted a frame or emitted one.
  DacLinkSlot* {.role: truthState.} = object
    used*: bool
    key*: DacLinkKey
    link*: DacLink
    lastSeenMs*: uint32

  ## DacLinkAdmit: why a peer was or was not given a slot.
  DacLinkAdmit* = enum
    dlaExisting,
    dlaAdmitted,
    dlaReplacedIdle,
    dlaRefusedFull,
    dlaRefusedFrame,
    dlaRefusedKind

  ## DacLinkRoute: the result of routing one arriving datagram.
  ## slot: index into the table, valid only when `admit` is not a refusal.
  DacLinkRoute* {.role: truthState.} = object
    admit*: DacLinkAdmit
    slot*: int
    step*: DacLinkStep

  ## DacLinkTable: every live conversation this process holds.
  ## seed: base randomness; each link mixes the peer key into it so two peers
  ## never draw the same send delays or chunk order from one table.
  DacLinkTable* {.role: truthState.} = object
    slots*: seq[DacLinkSlot]
    defaults*: DacScenarioDefaults
    policy*: DacScramblePolicy
    limits*: DacPackageLimits
    seed*: uint64
    idleMs*: uint32
    live*: int
    refusals*: uint32

proc initDacLinkTable*(d: DacScenarioDefaults, seed: uint64,
    capacity: int = dacLinkTableCapacity,
    idleMs: uint32 = dacLinkIdleSweepMs,
    policy: DacScramblePolicy = initDacScramblePolicy(),
    limits: DacPackageLimits = defaultDacPackageLimits()): DacLinkTable {.
    role: configurator.} =
  ## d: scenario defaults every admitted link starts from.
  ## seed: base randomness for send delay and chunk order; feed it something a
  ## peer cannot guess, since every link's stream is derived from it.
  ## capacity: hard slot count, allocated once and never grown.
  ## idleMs: how long a finished link may sit before a sweep may reclaim it.
  ## policy/limits: scrambling policy and per-link receiver bounds.
  if capacity <= 0:
    raise newException(ValueError, "DAC link table capacity must be positive")
  if not validateDacDefaults(d):
    raise newException(ValueError, "DAC link table defaults are invalid")
  result.slots = newSeq[DacLinkSlot](capacity)
  result.defaults = d
  result.policy = policy
  result.limits = limits
  result.seed = seed
  result.idleMs = idleMs

proc initDacLinkKey*(host: string, port: uint16,
    carrier: DacLinkCarrier = dlcDatagram): DacLinkKey {.role: configurator.} =
  ## host/port: peer address as the transport reported it.
  ## carrier: which transport it arrived over.
  result.host = host
  result.port = port
  result.carrier = carrier

proc dacKeyEqual(a, b: DacLinkKey): bool {.role: parser.} =
  ## a/b: two peer keys compared field by field.
  result = a.port == b.port and a.carrier == b.carrier and a.host == b.host

proc dacKeySeed(base: uint64, k: DacLinkKey): uint64 {.role: math.} =
  ## base: the table's own seed.
  ## k: peer key mixed into it so two peers never share a scramble stream.
  ## A peer knowing its own address must not learn another link's ordering, so
  ## the address is stirred through splitmix64 rather than added to the base.
  var
    h: uint64 = base xor 0x9E3779B97F4A7C15'u64
  for c in k.host:
    h = (h xor uint64(uint8(c))) * 0x100000001B3'u64
  h = h xor (uint64(k.port) shl 17)
  h = h xor (uint64(ord(k.carrier)) shl 33)
  h = (h xor (h shr 30)) * 0xBF58476D1CE4E5B9'u64
  h = (h xor (h shr 27)) * 0x94D049BB133111EB'u64
  result = h xor (h shr 31)

proc findDacLinkSlot*(T: DacLinkTable, k: DacLinkKey): int {.role: parser.} =
  ## T: table to search.
  ## k: peer key looked for. Returns -1 when no live slot holds it.
  var
    i: int = 0
  result = -1
  while i < T.slots.len:
    if T.slots[i].used and dacKeyEqual(T.slots[i].key, k):
      return i
    i = i + 1

proc freeDacLinkSlot(T: DacLinkTable): int {.role: parser.} =
  ## T: table searched for an unoccupied slot. Returns -1 when full.
  var
    i: int = 0
  result = -1
  while i < T.slots.len:
    if not T.slots[i].used:
      return i
    i = i + 1

proc dacSlotReclaimable*(T: DacLinkTable, i: int, nowMs: uint32): bool {.
    role: parser.} =
  ## T/i: table and slot index.
  ## nowMs: caller's millisecond clock.
  ## A slot may be taken only when its link has finished both directions AND
  ## has then stayed quiet for the idle window. A link mid-transfer is never
  ## reclaimable, whatever pressure the table is under.
  if not T.slots[i].used:
    return false
  if not dacLinkIdle(T.slots[i].link):
    return false
  result = nowMs - T.slots[i].lastSeenMs >= T.idleMs

proc stalestDacLinkSlot(T: DacLinkTable, nowMs: uint32): int {.role: parser.} =
  ## T: table searched for the longest-quiet reclaimable slot.
  ## nowMs: caller's millisecond clock. Returns -1 when nothing may be taken.
  var
    i: int = 0
    best: int = -1
    bestAge: uint32 = 0'u32
    age: uint32 = 0'u32
  while i < T.slots.len:
    age = nowMs - T.slots[i].lastSeenMs
    if dacSlotReclaimable(T, i, nowMs) and (best < 0 or age > bestAge):
      best = i
      bestAge = age
    i = i + 1
  result = best

proc placeDacLink(T: var DacLinkTable, i: int, k: DacLinkKey,
    sessionId: uint64, laneId: uint32, epochId: uint16, nowMs: uint32) {.
    role: actor.} =
  ## T/i: table and the slot being filled.
  ## k/sessionId/laneId/epochId: peer key and the identity the link answers to.
  ## nowMs: caller's millisecond clock, recorded as first contact.
  if T.slots[i].used:
    T.live = T.live - 1
  T.slots[i].used = true
  T.slots[i].key = k
  T.slots[i].lastSeenMs = nowMs
  T.slots[i].link = initDacLink(sessionId, laneId, T.defaults,
    dacKeySeed(T.seed, k), epochId, T.policy, T.limits)
  T.live = T.live + 1

proc admitDacLink*(T: var DacLinkTable, k: DacLinkKey, sessionId: uint64,
    laneId: uint32, nowMs: uint32,
    epochId: uint16 = 0'u16): tuple[admit: DacLinkAdmit, slot: int] {.
    role: orchestrator.} =
  ## T/k: table and the peer asking for a slot.
  ## sessionId/laneId/epochId: identity the new link will answer to.
  ## nowMs: caller's millisecond clock.
  ## An existing link is returned unchanged. Otherwise a free slot is used, or
  ## a slot whose link finished and went quiet. With neither available the peer
  ## is refused: a stranger must never be able to displace a live conversation.
  var
    i: int = findDacLinkSlot(T, k)
  result.slot = i
  if i >= 0:
    result.admit = dlaExisting
    return
  i = freeDacLinkSlot(T)
  if i >= 0:
    placeDacLink(T, i, k, sessionId, laneId, epochId, nowMs)
    result.admit = dlaAdmitted
    result.slot = i
    return
  i = stalestDacLinkSlot(T, nowMs)
  if i >= 0:
    placeDacLink(T, i, k, sessionId, laneId, epochId, nowMs)
    result.admit = dlaReplacedIdle
    result.slot = i
    return
  T.refusals = T.refusals + 1'u32
  result.admit = dlaRefusedFull
  result.slot = -1

proc dacFrameOpensLink*(k: DacMessageKind): bool {.role: parser.} =
  ## k: message kind asked whether it may bring a brand new peer into the table.
  ## Only a frame the LOOP CAN ACT ON qualifies. Every other kind refers to
  ## state a new link does not have -- a chunk without its manifest, an ACK for
  ## a package never sent -- and the link would ignore it anyway. Spending a
  ## slot on one would let a stranger fill the table with frames that cannot
  ## do anything, so the table declines before the slot is touched.
  ##
  ## `dmkPathProbe` was on this list and should not have been. The loop has no
  ## branch for it, so a probe took a slot and was then ignored: 40 probes from
  ## 40 addresses filled a 4-slot table completely, which is exactly the flood
  ## this rule exists to stop. It belongs here again only once the loop
  ## answers a probe, and `dacLinkHandlesKind` is what decides that.
  result = k in {dmkPackageManifest}

proc dacLinkHandlesKind*(k: DacMessageKind): bool {.role: parser.} =
  ## k: message kind asked whether the link loop has a branch for it at all.
  ## Kept beside the admission rule so the two cannot drift: a kind that opens
  ## a link must be a kind the loop acts on, and a test asserts that.
  result = k in {dmkPackageManifest, dmkPackageChunk, dmkParityShard,
    dmkAckRange, dmkRepairHint, dmkRepairChunk, dmkPackageCommit,
    dmkPathStats}

proc routeDacFrame*(T: var DacLinkTable, k: DacLinkKey,
    A: openArray[uint8], nowMs: uint32): DacLinkRoute {.role: orchestrator.} =
  ## T/k: table and the peer the datagram came from.
  ## A: one arriving datagram, of any length and any content.
  ## nowMs: caller's millisecond clock.
  ## The identity is read from the fixed prefix before any slot is touched, so
  ## rubbish from an unknown address is dropped without allocating a body or
  ## consuming a slot. A frame that does decode is fed to the peer's link. A
  ## peer with no slot yet gets one only if the frame opens a conversation and
  ## the table can afford it.
  var
    id: DacFrameIdentity = peekDacFrameIdentity(A)
    a: tuple[admit: DacLinkAdmit, slot: int]
  result.slot = -1
  if not id.ok:
    result.admit = dlaRefusedFrame
    result.step.kind = dlkIgnored
    result.step.err = "DAC datagram is not a usable frame"
    return
  if findDacLinkSlot(T, k) < 0 and not dacFrameOpensLink(id.messageKind):
    result.admit = dlaRefusedKind
    result.step.kind = dlkIgnored
    result.step.err = "DAC frame from an unknown peer does not open a link"
    return
  a = admitDacLink(T, k, id.sessionId, id.laneId, nowMs, id.epochId)
  result.admit = a.admit
  result.slot = a.slot
  if a.slot < 0:
    result.step.kind = dlkIgnored
    result.step.err = "DAC link table is full of live links"
    return
  T.slots[a.slot].lastSeenMs = nowMs
  result.step = feedDacFrame(T.slots[a.slot].link, A, nowMs)

proc tickDacLinkTable*(T: var DacLinkTable, nowMs: uint32): seq[DacLinkRoute] {.
    role: orchestrator.} =
  ## T: table whose every live link is given a chance to act on elapsed time.
  ## nowMs: caller's millisecond clock.
  ## Only links that produced something are returned, so a quiet table costs
  ## one pass and no allocation beyond the empty result.
  var
    i: int = 0
    r: DacLinkRoute
  while i < T.slots.len:
    if T.slots[i].used:
      r.admit = dlaExisting
      r.slot = i
      r.step = tickDacLink(T.slots[i].link, nowMs)
      if r.step.kind != dlkNone or r.step.messages.len > 0:
        T.slots[i].lastSeenMs = nowMs
        result.add(r)
    i = i + 1

proc closeDacLink*(T: var DacLinkTable, k: DacLinkKey): bool {.
    role: actor.} =
  ## T/k: table and the peer whose slot is released now, whatever its state.
  ## Returns false when the peer held no slot.
  var
    i: int = findDacLinkSlot(T, k)
  if i < 0:
    return false
  T.slots[i] = default(DacLinkSlot)
  T.live = T.live - 1
  result = true

proc sweepDacLinkTable*(T: var DacLinkTable, nowMs: uint32): int {.
    role: orchestrator.} =
  ## T: table whose finished, quiet links are released.
  ## nowMs: caller's millisecond clock. Returns how many slots were freed.
  ## Call it on any convenient cadence; admission also reclaims on demand, so
  ## sweeping is about returning memory rather than about staying correct.
  var
    i: int = 0
  while i < T.slots.len:
    if dacSlotReclaimable(T, i, nowMs):
      T.slots[i] = default(DacLinkSlot)
      T.live = T.live - 1
      result = result + 1
    i = i + 1

proc dacLinkTableLive*(T: DacLinkTable): int {.role: parser.} =
  ## T: table whose occupied slot count is returned.
  result = T.live

proc dacLinkTableFull*(T: DacLinkTable): bool {.role: parser.} =
  ## T: table asked whether every slot is occupied.
  result = T.live >= T.slots.len

proc dacLinkFor*(T: var DacLinkTable, k: DacLinkKey): ptr DacLink {.
    role: parser.} =
  ## T/k: table and peer whose link the caller wants to drive directly, to
  ## begin a package toward it. Nil when the peer holds no slot.
  var
    i: int = findDacLinkSlot(T, k)
  if i < 0:
    return nil
  result = addr T.slots[i].link
