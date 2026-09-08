## -------------------------------------------------------------------------
## TLS 1.3 OpenSSL Client <- one-connection native interoperability harness
## -------------------------------------------------------------------------

import std/[net, os, parseopt, strutils, times]

import tyr/certs/[der, pem, oid, keys, x509, verify, chain]

import ../src/protocols/types
import ../src/protocols/tls13
import ../src/analysis_pragmas

type
  HarnessConfig = object
    rootCertificatePath: string
    host: string
    serverName: string
    port: Port

proc parsePort(s: string): Port {.role: parser, metaTags: {tagTls, tagInterop}.} =
  var v: int = 0
  try:
    v = parseInt(s)
  except ValueError:
    raise newException(ValueError, "TLS harness port is invalid")
  if v < 1 or v > 65535:
    raise newException(ValueError, "TLS harness port is invalid")
  result = Port(v)

proc parseHarnessConfig(): HarnessConfig {.role: configurator,
    metaTags: {tagTls, tagInterop}.} =
  var P: OptParser = initOptParser(commandLineParams())
  result.host = "127.0.0.1"
  result.serverName = "localhost"
  result.port = Port(19444)
  while true:
    P.next()
    case P.kind
    of cmdEnd:
      break
    of cmdLongOption, cmdShortOption:
      case P.key
      of "root": result.rootCertificatePath = P.val
      of "host": result.host = P.val
      of "name": result.serverName = P.val
      of "port": result.port = parsePort(P.val)
      else:
        raise newException(ValueError, "unknown TLS harness option: " & P.key)
    of cmdArgument:
      raise newException(ValueError, "unexpected TLS harness argument")
  if result.rootCertificatePath.len == 0:
    raise newException(ValueError, "TLS harness requires --root")

proc bytesFromString(s: string): ByteSeq {.role: helper,
    metaTags: {tagTls, tagInterop}.} =
  var i: int = 0
  result = newSeq[byte](s.len)
  while i < s.len:
    result[i] = byte(ord(s[i]))
    i = i + 1

proc stringFromBytes(A: openArray[byte]): string {.role: helper,
    metaTags: {tagTls, tagInterop}.} =
  var i: int = 0
  result = newString(A.len)
  while i < A.len:
    result[i] = char(A[i])
    i = i + 1

proc connectWithRetry(C: HarnessConfig): Socket {.role: dataFetcher,
    metaTags: {tagTls, tagInterop, tagNetworkSurface}.} =
  var
    i: int = 0
    lastError: string = ""
  while i < 50:
    result = newSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, buffered = false)
    try:
      result.connect(C.host, C.port, 1000)
      return
    except CatchableError as e:
      lastError = e.msg
      result.close()
      sleep(20)
    i = i + 1
  raise newException(IOError, "TLS harness connect failed: " & lastError)

proc sendClientOutput(c: Socket, O: Tls13ClientOutput) {.role: dataWriter,
    metaTags: {tagTls, tagInterop}.} =
  var i: int = 0
  while i < O.outbound.len:
    c.send(stringFromBytes(O.outbound[i]))
    i = i + 1

proc runHarness(C: HarnessConfig) {.role: metaOrchestrator,
    metaTags: {tagTls, tagInterop}.} =
  const request = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
  var
    root: PemReadResult = readPemBlock(readFile(C.rootCertificatePath),
      "CERTIFICATE")
    config: Tls13ClientConfig
    S: Tls13ClientSession
    O: Tls13ClientOutput
    client: Socket
    wire: ByteSeq = @[]
    chunk, response: string = ""
    requestSent: bool = false
  if not root.ok:
    raise newException(ValueError, root.err)
  config.pinnedRootCertificateDer = root.pemBlock.der
  config.serverName = C.serverName
  config.alpn = @["http/1.1"]
  config.nowUnix = getTime().toUnix()
  S = initTls13ClientSession(config)
  client = connectWithRetry(C)
  defer:
    client.close()
  wire = S.startTls13Client()
  client.send(stringFromBytes(wire))
  while S.state notin {tcsClosed, tcsFailed}:
    chunk = client.recv(16 * 1024)
    if chunk.len == 0:
      break
    O = S.feedTls13Client(bytesFromString(chunk))
    client.sendClientOutput(O)
    if O.err.len > 0:
      raise newException(IOError, O.err)
    if O.connected and not requestSent:
      wire = S.encodeTls13ClientApplication(bytesFromString(request))
      client.send(stringFromBytes(wire))
      requestSent = true
    for A in O.applicationData:
      response.add(stringFromBytes(A))
    if "</HTML>" in response or "</html>" in response:
      wire = S.closeTls13Client()
      client.send(stringFromBytes(wire))
      break
  if S.state == tcsFailed:
    raise newException(IOError, "TLS client session failed")
  if not requestSent or "HTTP/1.0 200 ok" notin response:
    raise newException(IOError,
      "TLS client received no complete OpenSSL HTTP response:\n" & response)
  stdout.write(response)

when isMainModule:
  runHarness(parseHarnessConfig())
