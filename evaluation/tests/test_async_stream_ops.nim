## -------------------------------------------------------------------
## Async Stream Ops Tests <- bounded line, chunk, and timeout behavior
## -------------------------------------------------------------------

import std/[asyncdispatch, asyncnet, net, unittest]

import runePragmas
import ../../src/protocols/transport/async_stream_ops

proc runAsyncStreamChecks() {.async, role: orchestrator,
    tag: "transport|networkSurface".} =
  ## Runs one localhost exchange through the shared async stream helpers.
  var
    listener: AsyncSocket
    client: AsyncSocket
    server: AsyncSocket
    accepted: Future[AsyncSocket]
    bound: tuple[address: string, port: Port]
    line: AsyncStreamRead
    chunk: AsyncStreamRead
    sent: bool = false
  listener = newAsyncSocket()
  listener.setSockOpt(OptReuseAddr, true)
  listener.bindAddr(Port(0), "127.0.0.1")
  listener.listen()
  bound = listener.getLocalAddr()
  accepted = listener.accept()
  client = newAsyncSocket()
  await client.connect("127.0.0.1", bound.port)
  server = await accepted

  sent = await writeAsyncLine(client, "hello")
  check sent
  line = await readAsyncLine(server, 64, 1000)
  check line.ok
  check line.data == "hello"

  sent = await writeAsync(server, "bytes")
  check sent
  chunk = await readAsyncChunk(client, 5, 1000)
  check chunk.ok
  check chunk.data == "bytes"

  line = await readAsyncLine(server, 64, 20)
  check not line.ok
  check line.timedOut

  closeAsyncSocket(client)
  closeAsyncSocket(server)
  closeAsyncSocket(listener)

suite "async stream ops":
  # {.testKind: tkEdgeCase.}
  test "bounded async helpers exchange lines and bytes":
    waitFor runAsyncStreamChecks()

proc asyncPair(): Future[tuple[a, b, listener: AsyncSocket]] {.async,
    role: configurator.} =
  ## Two ends of one loopback connection, plus the listener.
  var
    accepted: Future[AsyncSocket] = nil
    bound: tuple[address: string, port: Port] = ("", Port(0))
  result.listener = newAsyncSocket()
  result.listener.setSockOpt(OptReuseAddr, true)
  result.listener.bindAddr(Port(0), "127.0.0.1")
  result.listener.listen()
  bound = result.listener.getLocalAddr()
  accepted = result.listener.accept()
  result.a = newAsyncSocket()
  await result.a.connect("127.0.0.1", bound.port)
  result.b = await accepted

proc runRelayChecks() {.async, role: orchestrator.} =
  ## left.a <-> left.b ==relay== right.a <-> right.b
  var
    left: tuple[a, b, listener: AsyncSocket] = await asyncPair()
    right: tuple[a, b, listener: AsyncSocket] = await asyncPair()
    relay: Future[void] = nil
    got: AsyncStreamRead = AsyncStreamRead()
  relay = relayAsyncStreams(left.b, right.a)
  check await writeAsync(left.a, "ping")
  got = await readAsyncChunk(right.b, 4, 1000)
  check got.data == "ping"
  check await writeAsync(right.b, "pong")
  got = await readAsyncChunk(left.a, 4, 1000)
  check got.data == "pong"
  ## One end leaving ends the relay, and the relay closes the other side.
  closeAsyncSocket(left.a)
  check await withTimeout(relay, 2000)
  got = await readAsyncChunk(right.b, 4, 1000)
  check not got.ok
  closeAsyncSocket(right.b)
  closeAsyncSocket(left.listener)
  closeAsyncSocket(right.listener)

proc runClosedPeerWrite() {.async, role: orchestrator.} =
  ## A write to a peer that went away must say so, not report success.
  var
    p: tuple[a, b, listener: AsyncSocket] = await asyncPair()
    failed: bool = false
    i: int = 0
  closeAsyncSocket(p.b)
  while i < 200 and not failed:
    failed = not await writeAsync(p.a, "x")
    i = i + 1
  check failed
  closeAsyncSocket(p.a)
  closeAsyncSocket(p.listener)

suite "async stream ops: relay and a vanished peer":
  # {.testKind: tkIntegration, covers: "relayAsyncStreams".}
  test "a relay carries both directions and ends when one side leaves":
    waitFor runRelayChecks()

  # {.testKind: tkRegression, covers: "writeAsync", pins: "SafeDisconn swallowed a broken connection, so a lost write read as sent".}
  test "writing to a vanished peer fails":
    waitFor runClosedPeerWrite()
