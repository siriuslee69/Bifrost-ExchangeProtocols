## -------------------------------------------------------------------------
## DAC Package Transfer <- chunk, recover, request repair, verify, commit
## -------------------------------------------------------------------------

from eir_compression_and_ecc import RsCodec, RsRecoverReport, initRsCodec,
  encodeRsShards, recoverRsShards

import ../build

when not dacAdaptiveBuilt:
  {.error: "This module is part of the DAC adaptive layer, which -d:bifrostDac=off removed from this build.".}

import tyr/hashes/blake3 as tyr_blake3

import ../../types
import ../types
import ../level0/package_commit
import ../level1/package_manifest
import ../level1/package_chunk
import ../level1/repair_hint
import ../level1/repair_chunk
import ../level1/parity_shard
import bifrostPragmas

const
  defaultDacPackageMaxBytes* = 16_777_216'u32
  dacRepairGroupAscii* = """
One repair group is `groupSize` shards wide: data chunks first, then the
parity shards the sender computed over them.

  groupSize = 6, parityCount = 2, so 4 data chunks carry 2 parity shards

  +------+------+------+------+  +------+------+
  | C0   | C1   | C2   | C3   |  | S0   | S1   |
  +------+------+------+------+  +------+------+
   \____________ data ________/   \__ parity __/

  drmXor          one parity shard, repairs exactly one loss
  drmReedSolomon  parityCount shards, repairs any parityCount losses
  drmTcpExact     no parity; missing chunks are re-sent verbatim
"""

type
  DacPackageLimits* {.role: configurator.} = object
    maxPackageBytes*: uint32
    maxChunks*: uint16
    maxRepairRounds*: uint8

  ## DacPackageGroupRepair: parity shards covering one repair group.
  ## shards: parity in shard order; an empty entry is one that did not arrive.
  DacPackageGroupRepair* {.role: truthState.} = object
    groupId*: uint32
    firstChunk*: uint16
    chunkCount*: uint16
    repairMode*: DacRepairMode
    shards*: seq[ByteSeq]

  ## DacGroupRepairReport: outcome of one repair-group rebuild.
  ## rebuilt: chunk ids restored, in ascending order.
  DacGroupRepairReport* {.role: truthState.} = object
    ok*: bool   ## otter:latest
    rebuilt*: seq[uint16]
    err*: string

  DacPackagePlan* {.role: truthState.} = object
    manifest*: DacPackageManifest
    chunks*: seq[DacPackageChunk]
    repairs*: seq[DacPackageGroupRepair]

  DacPackageReceiver* {.role: truthState.} = object
    manifest*: DacPackageManifest
    limits*: DacPackageLimits
    chunks*: seq[ByteSeq]
    received*: seq[bool]
    repairCount*: uint16
    repairRounds*: uint8

  DacPackageResult* {.role: truthState.} = object
    ok*: bool
    payload*: ByteSeq
    commit*: DacPackageCommit
    err*: string

proc defaultDacPackageLimits*(): DacPackageLimits {.role: configurator.} =
  ## Return bounded package receiver defaults.
  result.maxPackageBytes = defaultDacPackageMaxBytes
  result.maxChunks = high(uint16)
  result.maxRepairRounds = 4'u8

proc packageDigest(A: openArray[uint8]): array[32, uint8] {.
    role: truthBuilder.} =
  ## A: complete encoded package bytes hashed for manifest and commit.
  var
    d: ByteSeq = tyr_blake3.blake3Hash(A, 32)
    i: int = 0
  while i < result.len:
    result[i] = d[i]
    i = i + 1

proc xorChunkInto(A: var ByteSeq, B: openArray[uint8]) {.
    role: dataWriter.} =
  ## A/B: fixed-width XOR accumulator and one chunk.
  var
    i: int = 0
  while i < B.len:
    A[i] = A[i] xor B[i]
    i = i + 1

proc paddedChunk(A: openArray[uint8], n: int): ByteSeq {.role: helper.} =
  ## A: chunk payload, at most n bytes long.
  ## n: coding width every shard in a group is padded out to.
  var
    i: int = 0
  result = newSeq[uint8](n)
  while i < A.len:
    result[i] = A[i]
    i = i + 1

proc dacGroupDataWidth*(m: DacPackageManifest): uint16 {.role: parser.} =
  ## m: manifest whose data-chunk count per repair group is derived.
  if m.groupSize <= m.parityCount:
    raise newException(ValueError, "DAC manifest group carries no data shards")
  result = m.groupSize - m.parityCount

proc dacGroupFirstChunk*(m: DacPackageManifest,
    groupId: uint32): uint16 {.role: math.} =
  ## m: manifest holding the package geometry.
  ## groupId: repair group whose first data-chunk index is returned.
  var
    first: uint32 = groupId * uint32(dacGroupDataWidth(m))
  if first >= uint32(m.dataCount):
    raise newException(ValueError, "DAC repair group is past the package end")
  result = uint16(first)

proc dacGroupChunkCount*(m: DacPackageManifest,
    groupId: uint32): uint16 {.role: math.} =
  ## m: manifest holding the package geometry.
  ## groupId: repair group whose data-chunk count is returned. The final group
  ## of a package is short whenever the chunk count is not a whole multiple.
  var
    first: uint32 = uint32(dacGroupFirstChunk(m, groupId))
    width: uint32 = uint32(dacGroupDataWidth(m))
  result = uint16(min(width, uint32(m.dataCount) - first))

proc groupDataCount(d: DacScenarioDefaults): uint16 {.role: helper.} =
  ## d: scenario defaults whose data-shard count forms one repair group.
  if d.dataShards == 0'u16:
    raise newException(ValueError, "DAC package data-shard count must be positive")
  result = d.dataShards

proc buildXorShard(D: seq[ByteSeq], n: int): ByteSeq {.role: truthBuilder.} =
  ## D: padded data chunks of one repair group.
  ## n: coding width shared by every shard.
  var
    i: int = 0
  result = newSeq[uint8](n)
  while i < D.len:
    xorChunkInto(result, D[i])
    i = i + 1

proc buildRepairShards(D: seq[ByteSeq], mode: DacRepairMode,
    parityCount, n: int): seq[ByteSeq] {.role: truthBuilder.} =
  ## D: padded data chunks of one repair group.
  ## mode: parity codec this package declared.
  ## parityCount: parity shards the manifest promised.
  ## n: coding width shared by every shard.
  case mode
  of drmNone, drmTcpExact:
    result = @[]
  of drmXor:
    if parityCount != 1:
      raise newException(ValueError,
        "DAC xor repair carries exactly one parity shard")
    result = @[buildXorShard(D, n)]
  of drmReedSolomon:
    if parityCount <= 0:
      raise newException(ValueError,
        "DAC Reed-Solomon repair needs at least one parity shard")
    result = encodeRsShards(initRsCodec(D.len, parityCount, n), D)

proc buildGroupRepair(P: DacPackagePlan, first, count: int,
    groupId: uint32): DacPackageGroupRepair {.role: truthBuilder.} =
  ## P: package plan whose chunks back this group.
  ## first/count: half-open data-chunk range covered by the group.
  ## groupId: repair-group identity.
  var
    n: int = int(P.manifest.chunkBytes)
    D: seq[ByteSeq] = @[]
    i: int = 0
  result.groupId = groupId
  result.firstChunk = uint16(first)
  result.chunkCount = uint16(count)
  result.repairMode = P.manifest.repairMode
  while i < count:
    D.add(paddedChunk(P.chunks[first + i].payload, n))
    i = i + 1
  result.shards = buildRepairShards(D, result.repairMode,
    int(P.manifest.parityCount), n)

proc planDacPackage*(packageId: uint64, A: openArray[uint8],
    d: DacScenarioDefaults, c: DacTransferClass = dtcUserData,
    limits: DacPackageLimits = defaultDacPackageLimits()): DacPackagePlan {.
    role: orchestrator.} =
  ## packageId/A/d/c/limits: package identity, encoded bytes, path policy, class,
  ## and sender resource limits.
  var
    offset: int = 0
    n: int = 0
    groupWidth: int = int(groupDataCount(d))
    groupId: uint32 = 0'u32
    payload: ByteSeq = @[]
  if packageId == 0'u64 or uint64(A.len) > uint64(limits.maxPackageBytes):
    raise newException(ValueError, "DAC package identity or size is invalid")
  result.manifest = initDacPackageManifest(packageId, c, d, uint64(A.len),
    packageDigest(A))
  if result.manifest.dataCount > limits.maxChunks:
    raise newException(ValueError, "DAC package chunk count exceeds limit")
  while offset < A.len:
    n = min(int(result.manifest.chunkBytes), A.len - offset)
    payload = @A[offset ..< offset + n]
    result.chunks.add(initDacPackageChunk(packageId, groupId,
      uint16(result.chunks.len), uint32(offset), payload))
    offset = offset + n
    if result.chunks.len mod groupWidth == 0:
      groupId = groupId + 1'u32
  offset = 0
  groupId = 0'u32
  while offset < result.chunks.len:
    n = min(groupWidth, result.chunks.len - offset)
    result.repairs.add(buildGroupRepair(result, offset, n, groupId))
    offset = offset + n
    groupId = groupId + 1'u32

proc groupParityShards*(P: DacPackagePlan,
    groupId: uint32): seq[DacParityShard] {.role: actor.} =
  ## P: sender plan holding the computed parity.
  ## groupId: repair group whose parity shards become wire records.
  var
    i: int = 0
  if groupId >= uint32(P.repairs.len):
    raise newException(ValueError, "DAC repair group is not in this plan")
  while i < P.repairs[groupId].shards.len:
    result.add(initDacParityShard(P.manifest.packageId, groupId,
      uint16(i), P.repairs[groupId].repairMode,
      P.repairs[groupId].shards[i]))
    i = i + 1

proc collectGroupRepair*(m: DacPackageManifest, groupId: uint32,
    A: openArray[DacParityShard]): DacPackageGroupRepair {.role: truthBuilder.} =
  ## m: manifest holding the package geometry.
  ## groupId: repair group being reassembled on the receiving side.
  ## A: parity shards that arrived for this group, in any order.
  var
    i: int = 0
    id: int = 0
  result.groupId = groupId
  result.firstChunk = dacGroupFirstChunk(m, groupId)
  result.chunkCount = dacGroupChunkCount(m, groupId)
  result.repairMode = m.repairMode
  result.shards = newSeq[ByteSeq](int(m.parityCount))
  while i < A.len:
    id = int(A[i].shardId)
    if A[i].packageId != m.packageId or A[i].groupId != groupId or
        A[i].repairMode != m.repairMode or id >= result.shards.len:
      raise newException(ValueError, "DAC parity shard does not match the group")
    result.shards[id] = A[i].payload
    i = i + 1

proc initDacPackageReceiver*(m: DacPackageManifest,
    limits: DacPackageLimits = defaultDacPackageLimits()): DacPackageReceiver {.
    role: configurator.} =
  ## m/limits: validated manifest and receiver resource policy.
  if not validateDacPackageManifest(m) or m.totalLen > uint64(limits.maxPackageBytes) or
      m.dataCount > limits.maxChunks:
    raise newException(ValueError, "DAC package manifest exceeds receiver limits")
  result.manifest = m
  result.limits = limits
  result.chunks = newSeq[ByteSeq](int(m.dataCount))
  result.received = newSeq[bool](int(m.dataCount))

proc acceptDacPackageChunk*(S: var DacPackageReceiver,
    c: DacPackageChunk) {.role: actor.} =
  ## S/c: package receiver and one unordered data chunk.
  var
    i: int = int(c.chunkId)
    expectedOffset: uint64 = uint64(i) * uint64(S.manifest.chunkBytes)
    remaining: uint64 = 0'u64
    expectedLen: int = 0
  if c.packageId != S.manifest.packageId or i < 0 or i >= S.chunks.len or
      uint64(c.offset) != expectedOffset:
    raise newException(ValueError, "DAC package chunk identity is invalid")
  remaining = S.manifest.totalLen - expectedOffset
  expectedLen = int(min(uint64(S.manifest.chunkBytes), remaining))
  if c.payload.len != expectedLen:
    raise newException(ValueError, "DAC package chunk length is invalid")
  S.chunks[i] = c.payload & @[]
  S.received[i] = true

proc missingChunkIds*(S: DacPackageReceiver): seq[uint16] {.role: parser.} =
  ## S: receiver whose missing data-chunk identifiers are returned.
  var
    i: int = 0
  while i < S.received.len:
    if not S.received[i]:
      result.add(uint16(i))
    i = i + 1

proc expectedChunkLen(S: DacPackageReceiver, id: int): int {.role: math.} =
  ## S: receiver holding the package geometry.
  ## id: chunk index whose exact unpadded byte length is returned.
  result = int(min(uint64(S.manifest.chunkBytes),
    S.manifest.totalLen - uint64(id) * uint64(S.manifest.chunkBytes)))

proc groupChunkRange(S: DacPackageReceiver,
    r: DacPackageGroupRepair): bool {.role: parser.} =
  ## S/r: receiver and the repair record whose chunk range is bounds-checked.
  result = int(r.firstChunk) + int(r.chunkCount) <= S.chunks.len and
    r.chunkCount > 0'u16

proc storeRepairedChunk(S: var DacPackageReceiver, id: int, A: ByteSeq,
    R: var DacGroupRepairReport) {.role: dataWriter.} =
  ## S: receiver whose chunk slot is filled.
  ## id: chunk index being restored.
  ## A: padded coding shard the codec produced.
  ## R: report collecting the restored chunk ids.
  S.chunks[id] = A[0 ..< expectedChunkLen(S, id)]
  S.received[id] = true
  S.repairCount = S.repairCount + 1'u16
  R.rebuilt.add(uint16(id))

proc repairXorGroup(S: var DacPackageReceiver, r: DacPackageGroupRepair,
    R: var DacGroupRepairReport) {.role: orchestrator.} =
  ## S/r/R: receiver, one single-parity repair record, and the outcome report.
  ## XOR carries one parity shard, so it repairs exactly one loss and no more.
  var
    n: int = int(S.manifest.chunkBytes)
    missing: int = -1
    missingCount: int = 0
    recovered: ByteSeq = @[]
    i: int = 0
    id: int = 0
  if r.shards.len != 1 or r.shards[0].len != n:
    R.err = "DAC xor repair needs its one parity shard"
    return
  recovered = r.shards[0] & @[]
  while i < int(r.chunkCount):
    id = int(r.firstChunk) + i
    if not S.received[id]:
      missing = id
      missingCount = missingCount + 1
    else:
      xorChunkInto(recovered, paddedChunk(S.chunks[id], n))
    i = i + 1
  if missingCount == 0:
    R.ok = true
    return
  if missingCount > 1:
    R.err = "DAC xor repair cannot rebuild " & $missingCount & " losses"
    return
  storeRepairedChunk(S, missing, recovered, R)
  R.ok = true

proc rsShardTable(S: DacPackageReceiver, r: DacPackageGroupRepair,
    T: var seq[ByteSeq], present: var seq[bool]) {.role: truthBuilder.} =
  ## S/r: receiver and the repair record describing the group.
  ## T/present: shard slots and arrival flags built for the codec, data first.
  var
    n: int = int(S.manifest.chunkBytes)
    k: int = int(r.chunkCount)
    i: int = 0
    id: int = 0
  T = newSeq[ByteSeq](k + r.shards.len)
  present = newSeq[bool](k + r.shards.len)
  while i < k:
    id = int(r.firstChunk) + i
    present[i] = S.received[id]
    if present[i]:
      T[i] = paddedChunk(S.chunks[id], n)
    i = i + 1
  i = 0
  while i < r.shards.len:
    present[k + i] = r.shards[i].len == n
    if present[k + i]:
      T[k + i] = r.shards[i]
    i = i + 1

proc repairRsGroup(S: var DacPackageReceiver, r: DacPackageGroupRepair,
    R: var DacGroupRepairReport) {.role: orchestrator.} =
  ## S/r/R: receiver, one Reed-Solomon repair record, and the outcome report.
  ## Any `parityCount` losses across the whole group rebuild; one more does not.
  var
    n: int = int(S.manifest.chunkBytes)
    k: int = int(r.chunkCount)
    T: seq[ByteSeq] = @[]
    present: seq[bool] = @[]
    outcome: RsRecoverReport
    i: int = 0
  if r.shards.len == 0:
    R.err = "DAC Reed-Solomon repair carries no parity shards"
    return
  rsShardTable(S, r, T, present)
  outcome = recoverRsShards(initRsCodec(k, r.shards.len, n), T, present)
  if not outcome.ok:
    R.err = outcome.err
    return
  while i < k:
    if not present[i]:
      storeRepairedChunk(S, int(r.firstChunk) + i, T[i], R)
    i = i + 1
  R.ok = true

proc repairGroup*(S: var DacPackageReceiver,
    r: DacPackageGroupRepair): DacGroupRepairReport {.role: orchestrator.} =
  ## S: receiver whose missing chunks are rebuilt in place.
  ## r: one repair group's parity, as the sender computed it.
  ## A refusal is never a guess: the report says why and leaves S untouched.
  if not groupChunkRange(S, r):
    result.err = "DAC repair group is outside the package"
    return
  case r.repairMode
  of drmNone, drmTcpExact:
    result.err = "DAC repair mode carries no parity to rebuild from"
  of drmXor:
    repairXorGroup(S, r, result)
  of drmReedSolomon:
    repairRsGroup(S, r, result)

proc buildDacRepairHint*(S: var DacPackageReceiver): DacRepairHint {.
    role: truthBuilder.} =
  ## S: receiver whose missing chunks become an exact-repair request.
  var
    missing: seq[uint16] = missingChunkIds(S)
    gapMap: ByteSeq = newSeq[byte]((S.chunks.len + 7) div 8)
  if missing.len == 0:
    raise newException(ValueError, "DAC package has no missing chunks")
  if S.repairRounds >= S.limits.maxRepairRounds:
    raise newException(ValueError, "DAC package repair-round limit is exhausted")
  for id in missing:
    gapMap[int(id) div 8] = gapMap[int(id) div 8] or
      (1'u8 shl (7 - (int(id) mod 8)))
  S.repairRounds = S.repairRounds + 1'u8
  result = initDacRepairHint(S.manifest.packageId, 0'u32,
    uint16(missing.len), 0'u16, uint16(missing.len), gapMap,
    drmTcpExact, drrMissing)

proc answerDacRepairHint*(P: DacPackagePlan,
    h: DacRepairHint): seq[DacRepairChunk] {.role: actor.} =
  ## P/h: immutable sender plan and authenticated receiver repair request.
  var
    i: int = 0
    selected: bool = false
  if h.packageId != P.manifest.packageId or h.gapMap.len !=
      (P.chunks.len + 7) div 8:
    raise newException(ValueError, "DAC repair hint does not match the package")
  while i < P.chunks.len:
    selected = (h.gapMap[i div 8] and (1'u8 shl (7 - (i mod 8)))) != 0'u8
    if selected:
      result.add(initDacRepairChunk(P.manifest.packageId,
        P.chunks[i].groupId, uint16(i), drsTcpExactChunk,
        P.chunks[i].payload))
    i = i + 1
  if result.len != int(h.wantedCount):
    raise newException(ValueError, "DAC repair hint wanted count is inconsistent")

proc acceptDacRepairChunk*(S: var DacPackageReceiver,
    c: DacRepairChunk) {.role: actor.} =
  ## S/c: receiver and one exact repair response.
  var
    original: DacPackageChunk
  if c.source notin {drsTcpExactChunk, drsTcpFullFallback}:
    raise newException(ValueError, "DAC repair source is not exact data")
  original = initDacPackageChunk(c.packageId, c.groupId, c.chunkId,
    uint32(c.chunkId) * uint32(S.manifest.chunkBytes), c.payload)
  acceptDacPackageChunk(S, original)
  S.repairCount = S.repairCount + 1'u16

proc finishDacPackage*(S: DacPackageReceiver): DacPackageResult {.
    role: orchestrator.} =
  ## S: complete receiver state assembled and verified against the manifest.
  var
    d: array[32, uint8]
  if missingChunkIds(S).len != 0:
    result.err = "DAC package is incomplete"
    return
  for chunk in S.chunks:
    result.payload.add(chunk)
  if uint64(result.payload.len) != S.manifest.totalLen:
    result.err = "DAC package assembled length mismatch"
    return
  d = packageDigest(result.payload)
  if d != S.manifest.digest:
    result.err = "DAC package digest mismatch"
    return
  result.commit = initDacPackageCommit(S.manifest.packageId, d,
    S.manifest.dataCount, S.repairCount,
    if S.repairCount == 0'u16: dcsCommitted else: dcsCommittedWithRepair)
  result.ok = true

proc missingChunkCount*(S: DacPackageReceiver): int {.role: parser.} =
  ## S: receiver whose outstanding data-chunk count is returned without
  ## building a list, so a hot loop can ask on every frame.
  var
    i: int = 0
  while i < S.received.len:
    if not S.received[i]:
      result = result + 1
    i = i + 1
