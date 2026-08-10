## -------------------------------------------------------------------------
## DAC Eir Parity <- Eir-backed parity payloads for DAC parity-shard records
## -------------------------------------------------------------------------

from eir_compression_and_ecc import encodeParity, decodeParity,
  defaultParityBlockLen, EccDecodeReport

import ../../types
import ../types
import ./parity_shard
import ../../../analysis_pragmas

const
  dacEirParityHeaderLen* = 5

type
  ## DacParityVerifyReport: Bifrost-owned view of one parity verification run.
  DacParityVerifyReport* {.role: truthState.} = object
    ok*: bool
    correctedBits*: int
    err*: string

proc copyDacParityBytes(A: openArray[uint8]): ByteSeq {.role: helper.} =
  ## A: source bytes to copy into an owned sequence.
  var
    i: int = 0
  result = newSeq[uint8](A.len)
  while i < A.len:
    result[i] = A[i]
    i = i + 1

proc readDacParityU32Le(A: openArray[uint8], o: int): uint32 {.role: parser.} =
  ## A/o: little-endian u32 source bytes and starting offset.
  result = uint32(A[o]) or
    (uint32(A[o + 1]) shl 8) or
    (uint32(A[o + 2]) shl 16) or
    (uint32(A[o + 3]) shl 24)

proc requireDacEirParityPayload(A: openArray[uint8]) {.role: parser.} =
  ## A: DAC parity payload emitted by encodeDacEirParityPayload.
  if A.len < dacEirParityHeaderLen:
    raise newException(ValueError, "DAC Eir parity payload too short")
  if A[4] == 0'u8:
    raise newException(ValueError, "DAC Eir parity payload block length invalid")

proc parityVerifyReport(r: EccDecodeReport): DacParityVerifyReport {.role: wrapper.} =
  ## r: Eir parity decode report.
  result.ok = r.ok
  result.correctedBits = r.correctedBits
  result.err = r.err

proc encodeDacEirParityPayload*(groupBytes: openArray[uint8],
    blockLen: uint8 = uint8(defaultParityBlockLen)): ByteSeq {.role: orchestrator.} =
  ## groupBytes: concatenated repair-group bytes whose parity should be emitted.
  ## blockLen: Eir parity block width. The payload stores the same 5-byte header
  ## plus parity trailer, but not the original plaintext bytes.
  var
    encoded: ByteSeq = @[]
    parityOffset: int = 0
    i: int = 0
  if blockLen == 0'u8:
    raise newException(ValueError, "DAC Eir parity block length must be positive")
  encoded = encodeParity(copyDacParityBytes(groupBytes), int(blockLen))
  parityOffset = dacEirParityHeaderLen + groupBytes.len
  if encoded.len < parityOffset:
    raise newException(ValueError, "DAC Eir parity payload layout mismatch")
  result = newSeq[uint8](dacEirParityHeaderLen + (encoded.len - parityOffset))
  while i < dacEirParityHeaderLen:
    result[i] = encoded[i]
    i = i + 1
  while parityOffset < encoded.len:
    result[i] = encoded[parityOffset]
    i = i + 1
    parityOffset = parityOffset + 1

proc verifyDacEirParityPayload*(groupBytes, payload: openArray[uint8]):
    DacParityVerifyReport {.role: orchestrator.} =
  ## groupBytes: concatenated repair-group bytes to verify against the parity.
  ## payload: DAC Eir parity payload produced by encodeDacEirParityPayload.
  var
    expectedLen: int = 0
    encoded: ByteSeq = @[]
    i: int = 0
  requireDacEirParityPayload(payload)
  expectedLen = int(readDacParityU32Le(payload, 0))
  if expectedLen != groupBytes.len:
    result.ok = false
    result.err = "DAC Eir parity source length mismatch"
    return
  encoded = newSeq[uint8](dacEirParityHeaderLen + groupBytes.len +
    (payload.len - dacEirParityHeaderLen))
  while i < dacEirParityHeaderLen:
    encoded[i] = payload[i]
    i = i + 1
  while i < dacEirParityHeaderLen + groupBytes.len:
    encoded[i] = groupBytes[i - dacEirParityHeaderLen]
    i = i + 1
  while i < encoded.len:
    encoded[i] = payload[i - groupBytes.len]
    i = i + 1
  result = parityVerifyReport(decodeParity(encoded))

proc initDacEirParityShard*(packageId: uint64, groupId: uint32,
    shardId: uint16, groupBytes: openArray[uint8],
    blockLen: uint8 = uint8(defaultParityBlockLen)):
    DacParityShard {.role: orchestrator.} =
  ## packageId/groupId/shardId: parity-shard identity.
  ## groupBytes: concatenated repair-group bytes used to compute the parity.
  ## blockLen: Eir parity block width.
  result = initDacParityShard(packageId, groupId, shardId, drmXor,
    encodeDacEirParityPayload(groupBytes, blockLen))

proc verifyDacEirParityShard*(groupBytes: openArray[uint8],
    s: DacParityShard): DacParityVerifyReport {.role: orchestrator.} =
  ## groupBytes: concatenated repair-group bytes to verify.
  ## s: DAC parity-shard wrapper carrying an Eir parity payload.
  if s.repairMode != drmXor:
    result.ok = false
    result.err = "DAC Eir parity shard must use xor repair mode"
    return
  result = verifyDacEirParityPayload(groupBytes, s.payload)
