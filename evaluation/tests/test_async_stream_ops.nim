## -------------------------------------------------------------------
## Async Stream Ops Tests <- bounded line, chunk, and timeout behavior
## -------------------------------------------------------------------

import std/[asyncdispatch, asyncnet, net, unittest]

import ../../src/analysis_pragmas
import ../../src/protocols/transport/async_stream_ops

proc runAsyncStreamChecks() {.async, role: orchestrator,
    metaTags: {tagTransport, tagNetworkSurface}.} =
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
