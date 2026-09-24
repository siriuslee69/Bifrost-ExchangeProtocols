## ----------------------------------------------------------------------
## DAC Wire Helpers <- message-kind names and ids
## ----------------------------------------------------------------------

import ../types
import runePragmas

proc dacMessageKindFromId*(id: uint8): DacMessageKind {.role: parser.} =
  ## id: the first byte of a DAC body, exactly as it came off the wire.
  ##
  ## An id no kind claims reads as `dmkUnknown`. It does NOT raise: this runs
  ## on a byte a peer chose, and the caller's answer to "I do not know this
  ## word" is to drop the message, not to unwind.
  ##
  ## The enum states every value, so the byte IS the kind and there is nothing
  ## to keep in step. This used to be a twenty-two line case that listed each
  ## id a second time, and it had already drifted from the enum once.
  if id > uint8(ord(high(DacMessageKind))):
    return dmkUnknown
  result = DacMessageKind(id)

proc dacTransferClassName*(c: DacTransferClass): string {.role: truthBuilder.} =
  ## c: transfer class to render.
  case c
  of dtcStatus:
    result = "Status"
  of dtcControl:
    result = "Control"
  of dtcUserData:
    result = "UserData"
  of dtcArchive:
    result = "Archive"
  of dtcRecovery:
    result = "Recovery"
  of dtcRealtime:
    result = "Realtime"

