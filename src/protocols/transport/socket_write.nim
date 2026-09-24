## -------------------------------------------------------------------------
## Socket Write <- every byte out, or an error; never a silent retry loop
## -------------------------------------------------------------------------
##
## Replaces Nim's `send(Socket, string)` (std/net, Nim 2.2) for our writes.
## That routine has two faults that matter here:
##
##   fault                                   what it did to us
##   --------------------------------------  --------------------------------
##   with the default flag `SafeDisconn` a   a peer that went away made the
##   broken connection (EPIPE, ECONNRESET)   send loop forever at full CPU:
##   is swallowed and the loop tries again   the call never returned
##   after a partial write it sends again    the start of the frame twice on
##   from byte 0, not from where it stopped  the stream: every later frame is
##                                           misread
##
## `writeAllSocket` sends from where the last write stopped, retries only an
## interrupted call (EINTR), and raises `OSError` on anything else. A caller
## that has sealed the bytes then knows the write failed and decides what a
## failure means (see ame/level2/framing.nim, "sending one frame").

import std/[net, os]
when not defined(windows):
  import std/posix
import runePragmas

proc writeInterrupted(e: OSErrorCode): bool {.role: parser.} =
  ## e: the error of a failed write -> true when it only means "try again".
  when defined(windows):
    result = false
  else:
    result = e.int32 == EINTR

proc writeAllSocket*(sock: Socket, data: string) {.role: dataWriter.} =
  ## sock/data: every byte of `data` written in order, or OSError.
  var
    written: int = 0
    sent: int = 0
    e: OSErrorCode = OSErrorCode(0)
  while written < data.len:
    sent = sock.send(unsafeAddr data[written], data.len - written)
    if sent < 0:
      e = osLastError()
    if sent < 0 and not writeInterrupted(e):
      raiseOSError(e, "socket write failed")
    if sent == 0:
      raise newException(OSError, "socket write made no progress")
    if sent > 0:
      written = written + sent

proc closeSocketQuietly*(sock: Socket) {.role: actor.} =
  ## sock: closed, ignoring an error while closing -- used on a path that is
  ## already failing, where the first error is the one worth reporting.
  try:
    sock.close()
  except CatchableError:
    discard
