## -------------------------------------------------------
## DAC Receive Budget <- receiver memory and credit schema
## -------------------------------------------------------

import ../../types
import ../types
import ./body_codec
import ../../../analysis_pragmas

const
  dacReceiveBudgetLen* = 24
  dacReceiveBudgetAscii* = """
+--------------- Common DAC1 Envelope ----------------+
| Kind = ReceiveBudget | Flags = CreditBound           |
+-------------+-------------+-------------+-------------+
| MaxBytes    | MaxPackages | MaxGroups   | MaxBurst    |
| u32         | u16         | u16         | u16         |
+-------------+-------------+-------------+-------------+
| AckBudget   | RepairBytes | HoldMs      | Reserved    |
| u16         | u32         | u16         | 6 bytes     |
+-------------+-------------+-------------+-------------+
"""

proc initDacReceiveBudget*(maxBytes: uint32, maxPackages, maxGroups,
    maxBurst, ackBudget: uint16, repairBytes: uint32,
    holdMs: uint16): DacReceiveBudget {.role: wrapper.} =
  ## maxBytes/maxPackages/maxGroups/maxBurst: receive budget.
  ## ackBudget/repairBytes/holdMs: ACK and repair budget.
  result.maxBytes = maxBytes
  result.maxPackages = maxPackages
  result.maxGroups = maxGroups
  result.maxBurst = maxBurst
  result.ackBudget = ackBudget
  result.repairBytes = repairBytes
  result.holdMs = holdMs

proc dacBudgetAllowsBulk*(b: DacReceiveBudget): bool {.role: parser.} =
  ## b: receive budget to inspect.
  result = b.maxBytes > 0'u32 and b.maxPackages > 0'u16 and
    b.maxGroups > 0'u16 and b.maxBurst > 0'u16 and
    b.ackBudget > 0'u16 and b.repairBytes > 0'u32 and b.holdMs > 0'u16

proc encodeDacReceiveBudget*(b: DacReceiveBudget): ByteSeq {.role: wrapper.} =
  ## b: receive budget body to encode.
  appendDacU32(result, b.maxBytes)
  appendDacU16(result, b.maxPackages)
  appendDacU16(result, b.maxGroups)
  appendDacU16(result, b.maxBurst)
  appendDacU16(result, b.ackBudget)
  appendDacU32(result, b.repairBytes)
  appendDacU16(result, b.holdMs)
  appendDacZeroBytes(result, 6)

proc decodeDacReceiveBudget*(A: openArray[uint8]): DacReceiveBudget {.role: parser.} =
  ## A: receive budget body bytes.
  if A.len != dacReceiveBudgetLen:
    raise newException(ValueError, "DAC receive budget body length mismatch")
  if not rangeIsZero(A, 18, 6):
    raise newException(ValueError, "DAC receive budget reserved bytes mismatch")
  result = initDacReceiveBudget(readDacU32(A, 0), readDacU16(A, 4),
    readDacU16(A, 6), readDacU16(A, 8), readDacU16(A, 10),
    readDacU32(A, 12), readDacU16(A, 16))
