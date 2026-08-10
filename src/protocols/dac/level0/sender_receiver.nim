## ---------------------------------------------------------------------
## DAC Sender Receiver <- sender and receiver runtime state initializers
## ---------------------------------------------------------------------

import ../types
import ../../../analysis_pragmas

const
  dacSenderSchemaAscii* = """
+----------------------+-----------------------------------------------+
| Sender field         | Purpose                                       |
+----------------------+-----------------------------------------------+
| SessionId            | AME/DAC session binding                     |
| LaneId               | vertical data lane being transported          |
| PathLane             | horizontal network condition profile          |
| NextSequence         | next DAC frame sequence                      |
| OutstandingPackages  | packages not yet committed                    |
| CreditBytes          | receiver-advertised send credit               |
| ActiveGroups         | repair groups currently in flight             |
+----------------------+-----------------------------------------------+
"""

  dacReceiverSchemaAscii* = """
+----------------------+-----------------------------------------------+
| Receiver field       | Purpose                                       |
+----------------------+-----------------------------------------------+
| SessionId            | AME/DAC session binding                     |
| LaneId               | vertical data lane being received             |
| PathLane             | horizontal network condition profile          |
| ReceiveWindowStart   | first sequence in active receive window       |
| ReceiveWindowSpan    | accepted sequence span                        |
| BufferedBytes        | receive memory used by chunks/parity          |
| OpenPackages         | packages not yet committed or rejected        |
| RepairHintsSent      | repair hints emitted in current epoch         |
+----------------------+-----------------------------------------------+
"""

proc initDacSenderState*(sessionId: uint64, laneId: uint32,
    p: DacPathLane, creditBytes: uint32): DacSenderState {.role: wrapper.} =
  ## sessionId/laneId: DAC lane binding.
  ## p: horizontal path condition.
  ## creditBytes: initial receiver credit.
  result.sessionId = sessionId
  result.laneId = laneId
  result.pathLane = p
  result.nextSequence = 0'u32
  result.outstandingPackages = 0'u16
  result.creditBytes = creditBytes
  result.activeGroups = 0'u8

proc initDacReceiverState*(sessionId: uint64, laneId: uint32,
    p: DacPathLane, windowSpan: uint16): DacReceiverState {.role: wrapper.} =
  ## sessionId/laneId: DAC lane binding.
  ## p: horizontal path condition.
  ## windowSpan: accepted receive sequence span.
  result.sessionId = sessionId
  result.laneId = laneId
  result.pathLane = p
  result.receiveWindowStart = 0'u32
  result.receiveWindowSpan = windowSpan
  result.bufferedBytes = 0'u32
  result.openPackages = 0'u16
  result.repairHintsSent = 0'u16
