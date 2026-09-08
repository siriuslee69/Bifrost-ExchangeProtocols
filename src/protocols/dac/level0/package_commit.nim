## -------------------------------------------------------
## DAC Package Commit <- verified package delivery receipt
## -------------------------------------------------------

import ../../types
import ../types
import ./body_codec
import bifrostPragmas

const
  dacPackageCommitLen* = 45
  dacPackageCommitAscii* = """
+--------------- Common DAC1 Envelope ----------------+
| Kind = PackageCommit | Flags = NeedsAck              |
+----------+----------+----------+----------+----------+
| Package  | Digest   | DataCnt  | RepairCt | Status   |
| u64      | 32 byte  | u16      | u16      | u8       |
+----------+----------+----------+----------+----------+
"""

proc dacCommitDigestIsZero(digest: array[32, uint8]): bool {.role: parser.} =
  ## digest: package digest bytes.
  var
    i: int = 0
  result = true
  while i < digest.len:
    if digest[i] != 0'u8:
      return false
    i = i + 1

proc initDacPackageCommit*(packageId: uint64, digest: array[32, uint8],
    dataCount, repairCount: uint16,
    status: DacCommitStatus): DacPackageCommit {.role: configurator.} =
  ## packageId: committed package id.
  ## digest: package digest that was verified by the receiver.
  ## dataCount/repairCount: data and repair chunks used.
  ## status: final package status.
  if status in {dcsCommitted, dcsCommittedWithRepair} and
      dacCommitDigestIsZero(digest):
    raise newException(ValueError, "DAC committed digest must not be all zero")
  result.packageId = packageId
  result.digest = digest
  result.dataCount = dataCount
  result.repairCount = repairCount
  result.status = status

proc encodeDacPackageCommit*(c: DacPackageCommit): ByteSeq {.role: helper.} =
  ## c: package commit body to encode.
  appendDacU64(result, c.packageId)
  appendDacBytes(result, c.digest)
  appendDacU16(result, c.dataCount)
  appendDacU16(result, c.repairCount)
  result.add(uint8(ord(c.status)))

proc decodeDacPackageCommit*(A: openArray[uint8]): DacPackageCommit {.role: parser.} =
  ## A: package commit body bytes.
  var
    digest: array[32, uint8]
    i: int = 0
  if A.len != dacPackageCommitLen:
    raise newException(ValueError, "DAC package commit body length mismatch")
  while i < digest.len:
    digest[i] = A[8 + i]
    i = i + 1
  result = initDacPackageCommit(readDacU64(A, 0), digest, readDacU16(A, 40),
    readDacU16(A, 42), dacCommitStatusFromId(A[44]))
