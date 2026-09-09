## ------------------------------------------------------------
## DAC Path Switch <- horizontal path lane epoch transition data
## ------------------------------------------------------------

import ../../types
import ../types
import ../level0/body_codec
import runePragmas

const
  dacPathSwitchLen* = 12
  dacPathSwitchAscii* = """
+--------------- Common DAC1 Envelope ----------------+
| Kind = PathSwitchRequest/Ack | Flags = NeedsAck       |
+-------------+-------------+-------------+-------------+
| OldEpoch    | NewEpoch    | OldPath     | NewPath     |
| u16         | u16         | u8          | u8          |
+-------------+-------------+-------------+-------------+
| Reason      | Reserved                                  |
| u8          | 5 bytes                                   |
+-------------+-------------------------------------------+
"""

proc initDacPathSwitch*(oldEpoch, newEpoch: uint16, oldPath,
    newPath: DacPathLane, reason: DacPathSwitchReason): DacPathSwitch {.role: configurator.} =
  ## oldEpoch/newEpoch: path epoch transition.
  ## oldPath/newPath: horizontal path lane transition.
  ## reason: switch reason.
  if newEpoch <= oldEpoch:
    raise newException(ValueError, "DAC path switch epoch must increase")
  if newPath == oldPath:
    raise newException(ValueError, "DAC path switch must change path")
  result.oldEpoch = oldEpoch
  result.newEpoch = newEpoch
  result.oldPath = oldPath
  result.newPath = newPath
  result.reason = reason

proc validateDacPathSwitch*(s: DacPathSwitch): bool {.role: parser.} =
  ## s: path switch object to validate.
  result = s.newEpoch > s.oldEpoch and s.newPath != s.oldPath

proc encodeDacPathSwitch*(s: DacPathSwitch): ByteSeq {.role: helper.} =
  ## s: path switch body to encode.
  if not validateDacPathSwitch(s):
    raise newException(ValueError, "DAC path switch is invalid")
  appendDacU16(result, s.oldEpoch)
  appendDacU16(result, s.newEpoch)
  result.add(uint8(ord(s.oldPath)))
  result.add(uint8(ord(s.newPath)))
  result.add(uint8(ord(s.reason)))
  appendDacZeroBytes(result, 5)

proc decodeDacPathSwitch*(A: openArray[uint8]): DacPathSwitch {.role: parser.} =
  ## A: path switch body bytes.
  if A.len != dacPathSwitchLen:
    raise newException(ValueError, "DAC path switch body length mismatch")
  if not rangeIsZero(A, 7, 5):
    raise newException(ValueError, "DAC path switch reserved bytes mismatch")
  result = initDacPathSwitch(readDacU16(A, 0), readDacU16(A, 2),
    dacPathLaneFromId(A[4]), dacPathLaneFromId(A[5]),
    dacPathSwitchReasonFromId(A[6]))
