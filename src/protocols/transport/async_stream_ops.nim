## ------------------------------------------------------------------
## Async Stream Ops <- bounded AsyncSocket reads, writes, and relays
## ------------------------------------------------------------------

import std/[asyncdispatch, asyncnet, importutils]

import runePragmas

type
  AsyncStreamRead* {.role: truthState, tag: "transport|networkSurface|types".} = object
    ok*: bool
    timedOut*: bool
    data*: string
    err*: string

proc closeAsyncSocket*(s: AsyncSocket) {.role: helper,
    tag: "transport|networkSurface".} =
  ## s: socket to close when it is present and still usable.
  if s.isNil:
    return
  try:
    s.close()
  except CatchableError:
    discard

proc readAsyncLine*(s: AsyncSocket; m, t: int): Future[AsyncStreamRead] {.async,
    role: dataFetcher, tag: "transport|networkSurface|read".} =
  ## s: connected socket to read.
  ## m: maximum accepted line length.
  ## t: timeout in milliseconds; zero disables the timeout.
  var
    f: Future[string]
    done: bool = false
  if s.isNil:
    result.err = "socket is nil"
    return
  if m <= 0:
    result.err = "maximum line length must be positive"
    return
  try:
    f = s.recvLine(maxLength = m)
    if t > 0:
      done = await withTimeout(f, t)
    else:
      done = true
    if not done:
      result.timedOut = true
      result.err = "async line read timed out"
      return
    result.data = await f
    result.ok = true
  except CatchableError as e:
    result.err = e.msg

proc bufferedBytes(s: AsyncSocket): int {.role: parser,
    tag: "transport".} =
  ## s: how many bytes the socket's own buffer holds right now; -1 when it
  ## keeps no buffer.
  privateAccess(typeof(s[]))   # asyncnet keeps its buffer cursor private
  result = -1
  if s.isBuffered:
    result = s.bufLen - s.currPos

proc recvAvailable(s: AsyncSocket; m: int): Future[string] {.async,
    role: dataFetcher, tag: "transport|networkSurface|read".} =
  ## s/m: up to `m` bytes, as soon as ANY have arrived.
  ##
  ## `asyncnet.recv(m)` on a buffered socket waits for all `m` bytes, so a
  ## relay asking for 8192 forwarded nothing until 8192 had piled up:
  ##
  ##   buffer holds k > 0     take min(k, m) from it, no waiting
  ##   buffer empty           wait for ONE byte (this refills the buffer
  ##                          with whatever arrived), then take the rest
  ##   no buffer at all       plain recv(m), which already returns early
  var
    k: int = bufferedBytes(s)
  if k < 0:
    return await s.recv(m)
  if k == 0:
    result = await s.recv(1)
    k = bufferedBytes(s)
  if result.len > 0 or k > 0:
    result.add(await s.recv(min(k, m - result.len)))

proc readAsyncChunk*(s: AsyncSocket; m, t: int): Future[AsyncStreamRead] {.async,
    role: dataFetcher, tag: "transport|networkSurface|read".} =
  ## s: connected socket to read.
  ## m: maximum bytes requested from the socket.
  ## t: timeout in milliseconds; zero disables the timeout.
  var
    f: Future[string]
    done: bool = false
  if s.isNil:
    result.err = "socket is nil"
    return
  if m <= 0:
    result.err = "maximum chunk length must be positive"
    return
  try:
    f = recvAvailable(s, m)
    if t > 0:
      done = await withTimeout(f, t)
    else:
      done = true
    if not done:
      result.timedOut = true
      result.err = "async chunk read timed out"
      return
    result.data = await f
    result.ok = result.data.len > 0
    if result.data.len == 0:
      result.err = "peer closed the stream"
  except CatchableError as e:
    result.err = e.msg

proc writeAsync*(s: AsyncSocket; d: string): Future[bool] {.async,
    role: dataWriter, tag: "transport|networkSurface|write".} =
  ## s: connected socket to write.
  ## d: bytes to send without framing changes.
  if s.isNil:
    return false
  try:
    # No `SafeDisconn`: with it, a peer that went away is swallowed and
    # this would report a write that never happened as done.
    await s.send(d, flags = {})
    result = true
  except CatchableError:
    result = false

proc writeAsyncLine*(s: AsyncSocket; d: string): Future[bool] {.async,
    role: dataWriter, tag: "transport|networkSurface|write".} =
  ## s: connected socket to write.
  ## d: line payload written with one CRLF terminator.
  result = await writeAsync(s, d & "\r\n")

proc copyAsyncStream*(s, d: AsyncSocket; c: int = 8192): Future[void] {.async,
    role: orchestrator, tag: "transport|networkSurface|read|write".} =
  ## s: connected source socket.
  ## d: connected destination socket.
  ## c: bounded bytes requested per read.
  var
    r: AsyncStreamRead
    sent: bool = false
  if c <= 0:
    return
  while true:
    r = await readAsyncChunk(s, c, 0)
    if not r.ok:
      break
    sent = await writeAsync(d, r.data)
    if not sent:
      break

proc relayAsyncStreams*(a, b: AsyncSocket; c: int = 8192): Future[void] {.async,
    role: orchestrator, tag: "transport|networkSurface|read|write".} =
  ## a: first connected socket.
  ## b: second connected socket.
  ## c: bounded bytes requested per directional read.
  ##
  ## Ends as soon as EITHER direction ends, then closes both sockets; the
  ## other direction's pending read then finishes on the closed socket.
  ## (Awaiting only one direction left the relay hanging when the other
  ## side was the one to leave.)
  var
    ab: Future[void] = copyAsyncStream(a, b, c)
    ba: Future[void] = copyAsyncStream(b, a, c)
  await ab or ba
  closeAsyncSocket(a)
  closeAsyncSocket(b)
