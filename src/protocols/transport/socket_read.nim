## -------------------------------------------------------------------------
## Socket Read <- whatever has arrived, up to a limit, within a time
## -------------------------------------------------------------------------
##
## Nim's `recv(sock, n, timeout)` (std/net, Nim 2.2) keeps reading until it
## has ALL `n` bytes, buffered socket or not. A caller that wants "the next
## chunk, however big" waits the whole timeout instead:
##
##   asked for    peer sent            std recv(4096, 15000)   readAvailable
##   ----------   ------------------   ---------------------   -------------
##   4096 bytes   one 300-byte hello   waits 15 s, times out   300 bytes, now
##
## That stalled every TLS handshake in `tls13/socket_server.nim`.
##
## `readAvailableSocket` hands back what is there:
##
##   1. bytes the Socket already holds in its own buffer come first. After
##      a line read (`STARTTLS\r\n`) the next bytes -- a ClientHello -- may
##      already sit there; reading the OS socket directly would skip them.
##   2. otherwise it waits until the OS socket is readable, then reads once.

import std/[net, nativesockets]
when defined(windows):
  import std/winlean
else:
  import std/posix
import runePragmas

type
  SocketReadResult* {.role: preparedData,
      expectedCount: [0, 1024], lifeCycle: lcJob.} = object
    ok*: bool          ## false: the peer closed, the time ran out, or an error
    timedOut*: bool
    data*: string

proc takeSocketBuffer(sock: Socket, maxBytes: int): string {.
    role: dataFetcher.} =
  ## sock/maxBytes: what the Socket already buffered, at most `maxBytes`.
  result = ""
  while result.len < maxBytes and sock.hasDataBuffered():
    result.add(sock.recv(1, 1))

proc socketReadable(sock: Socket, timeoutMs: int): bool {.role: dataFetcher.} =
  ## sock/timeoutMs: true once the OS socket has bytes (or was closed).
  ## timeoutMs <= 0 waits without limit.
  var
    fds: seq[SocketHandle] = @[sock.getFd()]
  if timeoutMs <= 0:
    return selectRead(fds, -1) > 0
  result = selectRead(fds, timeoutMs) > 0

proc readOnce(sock: Socket, maxBytes: int): string {.role: dataFetcher.} =
  ## sock/maxBytes: one OS read. "" means the peer closed or it failed.
  var
    n: int = 0
  result = newString(maxBytes)
  when defined(windows):
    n = int(winlean.recv(sock.getFd(), addr result[0], cint(maxBytes), 0))
  else:
    n = int(posix.recv(sock.getFd(), addr result[0], maxBytes, 0'i32))
  if n < 0:
    n = 0
  result.setLen(n)

proc readAvailableSocket*(sock: Socket, maxBytes: int,
    timeoutMs: int): SocketReadResult {.role: dataFetcher.} =
  ## sock: connected socket   maxBytes: most bytes to hand back (> 0)
  ## timeoutMs: how long to wait for the first byte; <= 0 waits forever.
  result = SocketReadResult(ok: false, timedOut: false, data: "")
  if maxBytes <= 0:
    return
  result.data = takeSocketBuffer(sock, maxBytes)
  if result.data.len > 0:
    result.ok = true
    return
  if not socketReadable(sock, timeoutMs):
    result.timedOut = true
    return
  result.data = readOnce(sock, maxBytes)
  result.ok = result.data.len > 0
