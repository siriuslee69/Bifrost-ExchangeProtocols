## -------------------------------------------------------------------------
## TLS 1.3 Socket Server <- the blocking driver, over a real socket
## -------------------------------------------------------------------------
##
## `socket_server.nim` moves the bytes of a server session over a plain
## socket and offers a line view on top. Here a server thread runs that
## driver, and the test drives a client session by hand on the other end:
##
##   test (client session)                 server thread (socket driver)
##   ---------------------                 -----------------------------
##   ClientHello           ------------->  startTls13ServerSocket
##                         <-------------  ServerHello .. Finished
##   Finished + "hello\r\n" ------------>  tls13SocketReadLine -> "hello"
##                         <-------------  tls13SocketWriteLine("got hello")
##                         <-------------  tls13SocketClose (close_notify)

import std/[net, options, unittest]

import tyr/certs/[pem, keys]
import tyr/signatures/ed25519

import ../../src/protocols/types
import ../../src/protocols/tls13
import ../../src/protocols/tls13/socket_server
import ../../src/protocols/transport/socket_write
import ../../src/protocols/transport/socket_read
import runePragmas

const
  fixtureCertificate = """-----BEGIN CERTIFICATE-----
MIIBPDCB76ADAgECAhQkqENccCvOQyI4iKFuuOKwl860bTAFBgMrZXAwFDESMBAG
A1UEAwwJbG9jYWxob3N0MB4XDTIxMDcyNjE0MjcwN1oXDTIxMDgyNTE0MjcwN1ow
FDESMBAGA1UEAwwJbG9jYWxob3N0MCowBQYDK2VwAyEA1KMGmAZealfgakBuCx/E
n69fo072qm90eM40ulGex0ajUzBRMB0GA1UdDgQWBBTHKWv5l/SxnkkYJhh5r3Pv
ESAh1DAfBgNVHSMEGDAWgBTHKWv5l/SxnkkYJhh5r3PvESAh1DAPBgNVHRMBAf8E
BTADAQH/MAUGAytlcANBAF/vSBfOHAdRl29sWDTkuqy1dCuSf7j7jKE/Be8Fk7xs
WteXJmIa0HlRAZjxNfWbsSGLnTYbsGTbxKx3QU9H9g0=
-----END CERTIFICATE-----"""
  fixturePrivateKey = """-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAjtEwCECqbot5RZxSmiNDWcPp+Xc9Y9WJcUhti3JgSP
-----END PRIVATE KEY-----"""

type
  ServerArgs = object
    listener: Socket
    cfg: Tls13ServerConfig

var
  serverLine: Channel[string] = default(Channel[string])
    ## What the server thread read, or "error: ..." when it failed.

proc serverConfig(): Tls13ServerConfig {.role: configurator.} =
  ## The fixture certificate and its Ed25519 key.
  var
    certPem: PemReadResult = readPemBlock(fixtureCertificate, "CERTIFICATE")
    key = parseEd25519PrivateKeyPem(fixturePrivateKey)
  result.certificateChainDer = @[certPem.pemBlock.der]
  result.ed25519SecretKey = ed25519TyrKeypairFromSeed(key.seed).secretKey

proc clientSession(): Tls13ClientSession {.role: configurator.} =
  ## A client that trusts the fixture certificate at a time it was valid.
  var
    c: Tls13ClientConfig = Tls13ClientConfig()
    certPem: PemReadResult = readPemBlock(fixtureCertificate, "CERTIFICATE")
    i: int = 0
  c.pinnedRootCertificateDer = certPem.pemBlock.der
  c.nowUnix = 1_627_310_000'i64
  c.x25519Seed = newSeq[byte](32)
  while i < 32:
    c.x25519Seed[i] = byte(i + 1)
    i = i + 1
  result = initTls13ClientSession(c)

proc serveOneLine(a: ServerArgs) {.thread, role: orchestrator.} =
  ## a: listener and config. Accepts one peer, answers one line, closes.
  var
    client: Socket = nil
    S: Tls13SocketSession = initTls13SocketSession()
    started: Tls13SocketResult = Tls13SocketResult()
    line: Option[string] = none(string)
  a.listener.accept(client)
  started = startTls13ServerSocket(client, S, a.cfg, 5000)
  if not started.ok:
    serverLine.send("error: " & started.err)
    client.close()
    return
  line = tls13SocketReadLine(client, S, 5000, 1024)
  serverLine.send(line.get("error: no line"))
  discard tls13SocketWriteLine(client, S, "got " & line.get(""))
  tls13SocketClose(client, S)
  client.close()

proc asString(A: openArray[byte]): string {.role: helper.} =
  ## A: bytes viewed as text.
  for b in A:
    result.add(char(b))

proc feedUntil(sock: Socket, C: var Tls13ClientSession,
    done: proc (o: Tls13ClientOutput): bool): Tls13ClientOutput {.
    role: dataFetcher.} =
  ## sock/C/done: read and feed until `done` says the output is enough.
  ## Everything the client produced on the way is kept in `result`.
  var
    chunk: string = ""
    r: SocketReadResult = SocketReadResult()
    o: Tls13ClientOutput = Tls13ClientOutput()
  while not done(result):
    r = readAvailableSocket(sock, 4096, 5000)
    if not r.ok:
      return
    chunk = r.data
    o = feedTls13Client(C, chunk.toOpenArrayByte(0, chunk.high))
    result.outbound.add(o.outbound)
    result.applicationData.add(o.applicationData)
    result.connected = result.connected or o.connected
    result.closed = result.closed or o.closed
    if o.err.len > 0:
      result.err = o.err
      return

suite "TLS 1.3 socket server":
  # {.testKind: tkIntegration, covers: "startTls13ServerSocket|tls13SocketReadLine|tls13SocketWriteLine|tls13SocketClose|initTls13SocketSession".}
  test "a handshake, one line each way, then a clean close":
    var
      listener: Socket = newSocket()
      th: Thread[ServerArgs] = default(Thread[ServerArgs])
      sock: Socket = newSocket()
      C: Tls13ClientSession = clientSession()
      o: Tls13ClientOutput = Tls13ClientOutput()
      wire: ByteSeq = @[]
    serverLine.open()
    listener.setSockOpt(OptReuseAddr, true)
    listener.bindAddr(Port(0), "127.0.0.1")
    listener.listen()
    createThread(th, serveOneLine, ServerArgs(listener: listener,
      cfg: serverConfig()))
    sock.connect("127.0.0.1", listener.getLocalAddr()[1])
    writeAllSocket(sock, asString(startTls13Client(C)))
    o = feedUntil(sock, C, proc (x: Tls13ClientOutput): bool = x.connected)
    check o.err.len == 0
    check o.connected
    for r in o.outbound:
      wire.add(r)
    wire.add(encodeTls13ClientApplication(C, @(toOpenArrayByte("hello\r\n",
      0, 6))))
    writeAllSocket(sock, asString(wire))
    o = feedUntil(sock, C, proc (x: Tls13ClientOutput): bool = x.closed)
    joinThread(th)
    check serverLine.recv() == "hello"
    check o.applicationData.len == 1
    check asString(o.applicationData[0]) == "got hello\r\n"
    check o.closed
    sock.close()
    listener.close()
    serverLine.close()

  # {.testKind: tkEdgeCase, covers: "tls13SocketReadLine|tls13SocketWriteLine".}
  test "an inactive session reads nothing and writes nothing":
    var
      sock: Socket = newSocket()
      S: Tls13SocketSession = initTls13SocketSession()
    check not tls13SocketActive(S)
    check tls13SocketReadLine(sock, S).isNone
    check not tls13SocketWriteLine(sock, S, "x")
    sock.close()
