## -------------------------------------------------------------------------
## TLS 1.3 Big Reply <- application data longer than one record
## -------------------------------------------------------------------------
##
## One TLS record holds at most 16384 bytes in all, the hidden type byte
## included (RFC 8446, 5.1). A web server that sends a 40 KB picture must
## therefore send several records:
##
##   server writes 40000 bytes
##        |
##        v   encodeTls13ServerApplication
##   [hdr|16383 bytes] [hdr|16383 bytes] [hdr|7234 bytes]   <- three records
##        |
##        v   client.feedTls13Client, 8192 bytes of the wire at a time
##   40000 bytes, the same ones, in the same order
##
## Before the cut existed, 16383 bytes or more raised an error, the web server
## caught it and closed the connection: the visitor saw the headers and then
## nothing. Every test below holds one size of that story down.

import std/unittest

import tyr/certs/[pem, keys]
import tyr/signatures/ed25519

import ../../src/protocols/types
import ../../src/protocols/tls13
import runePragmas

const
  readSlice = 8192
    ## How much of the wire one socket read hands over. The reader keeps at
    ## most four records of unfinished input, so one 200 KB gulp is refused
    ## by design; a real server never offers one.
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
  Heard = tuple[data: ByteSeq, err: string]
    ## What one side read from a wire: the application bytes in order, and
    ## the first error ("" = none).

proc joinAll(P: seq[ByteSeq]): ByteSeq {.role: helper.} =
  ## P: pieces -> all of them back to back.
  var
    i: int = 0
  while i < P.len:
    result.add(P[i])
    i = i + 1

proc sameBytes(a, b: ByteSeq): bool {.role: helper.} =
  ## a/b -> equal or not. A bool, so a failed check prints one line and not
  ## 200 KB of numbers.
  result = a == b

proc connect(client: var Tls13ClientSession,
    server: var Tls13ServerSession): bool {.role: orchestrator.} =
  ## client/server: fresh sessions -> both connected after one handshake.
  var
    certPem: PemReadResult = readPemBlock(fixtureCertificate, "CERTIFICATE")
    key = parseEd25519PrivateKeyPem(fixturePrivateKey)
    pair: Ed25519Keypair = ed25519TyrKeypairFromSeed(key.seed)
    clientConfig: Tls13ClientConfig = default(Tls13ClientConfig)
    serverConfig: Tls13ServerConfig = default(Tls13ServerConfig)
    clientOutput: Tls13ClientOutput = default(Tls13ClientOutput)
    serverOutput: Tls13ServerOutput = default(Tls13ServerOutput)
    wire: ByteSeq = @[]
    i: int = 0
  clientConfig.pinnedRootCertificateDer = certPem.pemBlock.der
  clientConfig.alpn = @["http/1.1"]
  clientConfig.nowUnix = 1_627_310_000'i64
  clientConfig.x25519Seed = newSeq[byte](32)
  while i < clientConfig.x25519Seed.len:
    clientConfig.x25519Seed[i] = byte(i + 1)
    i = i + 1
  serverConfig.certificateChainDer = @[certPem.pemBlock.der]
  serverConfig.ed25519SecretKey = pair.secretKey
  serverConfig.alpn = @["http/1.1"]
  client = initTls13ClientSession(clientConfig)
  server = initTls13ServerSession(serverConfig)
  serverOutput = server.feedTls13Server(client.startTls13Client())
  clientOutput = client.feedTls13Client(joinAll(serverOutput.outbound))
  wire = joinAll(clientOutput.outbound)
  serverOutput = server.feedTls13Server(wire)
  result = clientOutput.connected and serverOutput.connected

proc clientHears(client: var Tls13ClientSession, W: ByteSeq): Heard {.
    role: actor.} =
  ## client/W: a session and the wire from the server -> what it reads,
  ## handing it `readSlice` bytes at a time.
  var
    o: Tls13ClientOutput = default(Tls13ClientOutput)
    i: int = 0
    j: int = 0
  while i < W.len and result.err.len == 0:
    j = min(i + readSlice, W.len) - 1
    o = client.feedTls13Client(W.toOpenArray(i, j))
    result.data.add(joinAll(o.applicationData))
    result.err = o.err
    i = j + 1

proc serverHears(server: var Tls13ServerSession, W: ByteSeq): Heard {.
    role: actor.} =
  ## server/W: a session and the wire from the client -> what it reads,
  ## handing it `readSlice` bytes at a time.
  var
    o: Tls13ServerOutput = default(Tls13ServerOutput)
    i: int = 0
    j: int = 0
  while i < W.len and result.err.len == 0:
    j = min(i + readSlice, W.len) - 1
    o = server.feedTls13Server(W.toOpenArray(i, j))
    result.data.add(joinAll(o.applicationData))
    result.err = o.err
    i = j + 1

proc recordSizes(W: ByteSeq): seq[int] {.role: parser.} =
  ## W: bytes holding whole TLS records -> the length field of each one.
  ## An unfinished record at the end is ignored.
  var
    i: int = 0
    n: int = 0
  while i + 5 <= W.len:
    n = (int(W[i + 3]) shl 8) or int(W[i + 4])
    if i + 5 + n > W.len:
      break
    result.add(n)
    i = i + 5 + n

proc patterned(n: int): ByteSeq {.role: helper.} =
  ## n -> n bytes that differ from place to place, so a swapped or lost
  ## piece is seen.
  var
    i: int = 0
  result = newSeq[byte](n)
  while i < n:
    result[i] = byte((i * 7 + i div 251) and 0xFF)
    i = i + 1

suite "TLS 1.3 replies longer than one record":
  # {.testKind: tkRegression, covers: "encodeTls13Application", pins: "a reply of 16383 bytes or more could not be sent".}
  test "the server's reply is cut into records and read back whole":
    var
      client: Tls13ClientSession = default(Tls13ClientSession)
      server: Tls13ServerSession = default(Tls13ServerSession)
      sizes: array[7, int] = [0, 1, 16382, 16383, 16384, 40000, 200_000]
      body, wire: ByteSeq = @[]
      heard: Heard = (@[], "")
      records: seq[int] = @[]
      expectCount: int = 0
      i: int = 0
    check connect(client, server)
    while i < sizes.len:
      body = patterned(sizes[i])
      wire = server.encodeTls13ServerApplication(body)
      records = recordSizes(wire)
      expectCount = max(1, (sizes[i] + 16382) div 16383)
      check records.len == expectCount
      check records.max <= 16384 + 16
      heard = client.clientHears(wire)
      check heard.err.len == 0
      check heard.data.len == body.len
      check sameBytes(heard.data, body)
      i = i + 1

  # {.testKind: tkRegression, covers: "encodeTls13Application", pins: "a reply of 16383 bytes or more could not be sent".}
  test "the client's request is cut the same way":
    var
      client: Tls13ClientSession = default(Tls13ClientSession)
      server: Tls13ServerSession = default(Tls13ServerSession)
      body, wire: ByteSeq = @[]
      heard: Heard = (@[], "")
    check connect(client, server)
    body = patterned(50_000)
    wire = client.encodeTls13ClientApplication(body)
    check recordSizes(wire).len == 4    ## 50000 / 16383 = 3.05
    heard = server.serverHears(wire)
    check heard.err.len == 0
    check sameBytes(heard.data, body)

  # {.testKind: tkEdgeCase, covers: "encodeTls13Application".}
  test "records after a cut keep their order and keys: a small reply follows a big one":
    var
      client: Tls13ClientSession = default(Tls13ClientSession)
      server: Tls13ServerSession = default(Tls13ServerSession)
      wire: ByteSeq = @[]
      heard: Heard = (@[], "")
    check connect(client, server)
    wire = server.encodeTls13ServerApplication(patterned(70_000))
    wire.add(server.encodeTls13ServerApplication(@[byte 9, 9, 9]))
    heard = client.clientHears(wire)
    check heard.err.len == 0
    check heard.data.len == 70_003
    check heard.data[^3 .. ^1] == @[byte 9, 9, 9]
