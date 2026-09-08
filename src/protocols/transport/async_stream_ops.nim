## ------------------------------------------------------------------
## Async Stream Ops <- bounded AsyncSocket reads, writes, and relays
## ------------------------------------------------------------------

import std/[asyncdispatch, asyncnet]

import bifrostPragmas

type
  AsyncStreamRead* {.role: truthState, metaTags: {tagTransport, tagNetworkSurface,
      tagTypes}.} = object
    ok*: bool
    timedOut*: bool
    data*: string
    err*: string

proc closeAsyncSocket*(s: AsyncSocket) {.role: helper,
    metaTags: {tagTransport, tagNetworkSurface}.} =
  ## s: socket to close when it is present and still usable.
  if s.isNil:
    return
  try:
    s.close()
  except CatchableError:
    discard

proc readAsyncLine*(s: AsyncSocket; m, t: int): Future[AsyncStreamRead] {.async,
    role: dataFetcher, metaTags: {tagTransport, tagNetworkSurface, tagRead}.} =
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

proc readAsyncChunk*(s: AsyncSocket; m, t: int): Future[AsyncStreamRead] {.async,
    role: dataFetcher, metaTags: {tagTransport, tagNetworkSurface, tagRead}.} =
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
    f = s.recv(m)
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
    role: dataWriter, metaTags: {tagTransport, tagNetworkSurface, tagWrite}.} =
  ## s: connected socket to write.
  ## d: bytes to send without framing changes.
  if s.isNil:
    return false
  try:
    await s.send(d)
    result = true
  except CatchableError:
    result = false

proc writeAsyncLine*(s: AsyncSocket; d: string): Future[bool] {.async,
    role: dataWriter, metaTags: {tagTransport, tagNetworkSurface, tagWrite}.} =
  ## s: connected socket to write.
  ## d: line payload written with one CRLF terminator.
  result = await writeAsync(s, d & "\r\n")

proc copyAsyncStream*(s, d: AsyncSocket; c: int = 8192): Future[void] {.async,
    role: orchestrator, metaTags: {tagTransport, tagNetworkSurface, tagRead,
      tagWrite}.} =
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
    role: orchestrator, metaTags: {tagTransport, tagNetworkSurface, tagRead,
      tagWrite}.} =
  ## a: first connected socket.
  ## b: second connected socket.
  ## c: bounded bytes requested per directional read.
  asyncCheck copyAsyncStream(a, b, c)
  await copyAsyncStream(b, a, c)
  closeAsyncSocket(a)
  closeAsyncSocket(b)
