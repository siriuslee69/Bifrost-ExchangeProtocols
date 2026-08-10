## -------------------------------------------------------------------------
## DAC Package Transfer <- chunk, recover, request repair, verify, commit
## -------------------------------------------------------------------------

import protocols/custom_crypto/blake3 as tyr_blake3

import ../../types
import ../types
import ../level0/package_commit
import ../level1/package_manifest
import ../level1/package_chunk
import ../level1/repair_hint
import ../level1/repair_chunk
import ../level1/eir_parity
import ../../../analysis_pragmas

const
  defaultDacPackageMaxBytes* = 16_777_216'u32

type
  DacPackageLimits* {.role: configurator.} = object
    maxPackageBytes*: uint32
    maxChunks*: uint16
    maxRepairRounds*: uint8

  DacPackageGroupRepair* {.role: truthState.} = object
    groupId*: uint32
    firstChunk*: uint16
    chunkCount*: uint16
    xorPayload*: ByteSeq
    eirPayload*: ByteSeq

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

proc defaultDacPackageLimits*(): DacPackageLimits {.role: wrapper.} =
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
    role: stateController.} =
  ## A/B: fixed-width XOR accumulator and one chunk.
  var
    i: int = 0
  while i < B.len:
    A[i] = A[i] xor B[i]
    i = i + 1

proc groupDataCount(d: DacScenarioDefaults): uint16 {.role: helper.} =
  ## d: scenario defaults whose data-shard count forms one repair group.
  if d.dataShards == 0'u16:
    raise newException(ValueError, "DAC package data-shard count must be positive")
  result = d.dataShards

proc buildGroupRepair(P: DacPackagePlan, first, count: int,
    groupId: uint32): DacPackageGroupRepair {.role: truthBuilder.} =
  ## P/first/count/groupId: package plan range and repair-group identity.
  var
    padded: ByteSeq = newSeq[byte](int(P.manifest.chunkBytes))
    concatenated: ByteSeq = @[]
    i: int = 0
    j: int = 0
  result.groupId = groupId
  result.firstChunk = uint16(first)
  result.chunkCount = uint16(count)
  result.xorPayload = newSeq[byte](int(P.manifest.chunkBytes))
  while i < count:
    padded = newSeq[byte](int(P.manifest.chunkBytes))
    j = 0
    while j < P.chunks[first + i].payload.len:
      padded[j] = P.chunks[first + i].payload[j]
      j = j + 1
    xorChunkInto(result.xorPayload, padded)
    concatenated.add(padded)
    i = i + 1
  result.eirPayload = encodeDacEirParityPayload(concatenated)

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

proc initDacPackageReceiver*(m: DacPackageManifest,
    limits: DacPackageLimits = defaultDacPackageLimits()): DacPackageReceiver {.
    role: wrapper.} =
  ## m/limits: validated manifest and receiver resource policy.
  if not validateDacPackageManifest(m) or m.totalLen > uint64(limits.maxPackageBytes) or
      m.dataCount > limits.maxChunks:
    raise newException(ValueError, "DAC package manifest exceeds receiver limits")
  result.manifest = m
  result.limits = limits
  result.chunks = newSeq[ByteSeq](int(m.dataCount))
  result.received = newSeq[bool](int(m.dataCount))

proc acceptDacPackageChunk*(S: var DacPackageReceiver,
    c: DacPackageChunk) {.role: stateController.} =
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

proc repairGroup*(S: var DacPackageReceiver,
    r: DacPackageGroupRepair): bool {.role: orchestrator.} =
  ## S/r: receiver and one XOR/Eir group recovery record.
  var
    missing: int = -1
    missingCount: int = 0
    recovered: ByteSeq = r.xorPayload & @[]
    concatenated: ByteSeq = @[]
    padded: ByteSeq = @[]
    i: int = 0
    id: int = 0
    expectedLen: int = 0
    verify: DacParityVerifyReport
  while i < int(r.chunkCount):
    id = int(r.firstChunk) + i
    if id >= S.chunks.len:
      return false
    if not S.received[id]:
      missing = id
      missingCount = missingCount + 1
    else:
      padded = newSeq[byte](int(S.manifest.chunkBytes))
      for j in 0 ..< S.chunks[id].len:
        padded[j] = S.chunks[id][j]
      xorChunkInto(recovered, padded)
    i = i + 1
  if missingCount != 1:
    return false
  expectedLen = int(min(uint64(S.manifest.chunkBytes),
    S.manifest.totalLen - uint64(missing) * uint64(S.manifest.chunkBytes)))
  recovered.setLen(expectedLen)
  S.chunks[missing] = recovered
  S.received[missing] = true
  i = 0
  while i < int(r.chunkCount):
    id = int(r.firstChunk) + i
    padded = newSeq[byte](int(S.manifest.chunkBytes))
    for j in 0 ..< S.chunks[id].len:
      padded[j] = S.chunks[id][j]
    concatenated.add(padded)
    i = i + 1
  verify = verifyDacEirParityPayload(concatenated, r.eirPayload)
  if not verify.ok:
    S.chunks[missing] = @[]
    S.received[missing] = false
    return false
  S.repairCount = S.repairCount + 1'u16
  result = true

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
    c: DacRepairChunk) {.role: stateController.} =
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
