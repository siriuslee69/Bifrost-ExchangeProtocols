## -------------------------------------------------------------------------
## TLS 1.3 OpenSSL Server <- one-connection native interoperability harness
## -------------------------------------------------------------------------

import std/[net, os, parseopt, strutils]

import tyr/certs/[der, pem, oid, keys, x509, verify, chain]
import tyr/signatures/ed25519

import ../src/protocols/types
import ../src/protocols/tls13
import ../src/analysis_pragmas

type
  HarnessConfig = object
    certificatePath: string
    privateKeyPath: string
    host: string
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
  var
    P: OptParser = initOptParser(commandLineParams())
  result.host = "127.0.0.1"
  result.port = Port(9443)
  while true:
    P.next()
    case P.kind
    of cmdEnd:
      break
    of cmdLongOption, cmdShortOption:
      case P.key
      of "cert": result.certificatePath = P.val
      of "key": result.privateKeyPath = P.val
      of "host": result.host = P.val
      of "port": result.port = parsePort(P.val)
      else:
        raise newException(ValueError, "unknown TLS harness option: " & P.key)
    of cmdArgument:
      raise newException(ValueError, "unexpected TLS harness argument")
  if result.certificatePath.len == 0 or result.privateKeyPath.len == 0:
    raise newException(ValueError, "TLS harness requires --cert and --key")

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

proc loadServerConfig(C: HarnessConfig): Tls13ServerConfig {.
    role: truthBuilder, metaTags: {tagTls, tagInterop}.} =
  var
    cert: PemReadResult = readPemBlock(readFile(C.certificatePath),
      "CERTIFICATE")
    key = parseEd25519PrivateKeyPem(readFile(C.privateKeyPath))
    keypair: Ed25519Keypair
  if not cert.ok:
    raise newException(ValueError, cert.err)
  if not key.ok:
    raise newException(ValueError, key.err)
  keypair = ed25519TyrKeypairFromSeed(key.seed)
  result.certificateChainDer = @[cert.pemBlock.der]
  result.ed25519SecretKey = keypair.secretKey
  result.alpn = @["http/1.1"]

proc sendServerOutput(c: Socket, O: Tls13ServerOutput) {.role: dataWriter,
    metaTags: {tagTls, tagInterop}.} =
  var i: int = 0
  while i < O.outbound.len:
    c.send(stringFromBytes(O.outbound[i]))
    i = i + 1

proc sendHttpResponse(c: Socket, S: var Tls13ServerSession) {.
    role: dataWriter, metaTags: {tagTls, tagInterop}.} =
  const response = "HTTP/1.1 200 OK\r\nContent-Length: 18\r\nConnection: close\r\n\r\nnative tls13 ok\r\n"
  var
    wire: ByteSeq = S.encodeTls13ServerApplication(bytesFromString(response))
  c.send(stringFromBytes(wire))
  wire = S.closeTls13Server()
  c.send(stringFromBytes(wire))

proc runHarness(C: HarnessConfig) {.role: metaOrchestrator,
    metaTags: {tagTls, tagInterop}.} =
  var
    listener, client: Socket
    S: Tls13ServerSession = initTls13ServerSession(loadServerConfig(C))
    O: Tls13ServerOutput
    chunk: string = ""
    replied: bool = false
  listener = newSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, buffered = false)
  defer:
    listener.close()
  listener.setSockOpt(OptReuseAddr, true)
  listener.bindAddr(C.port, C.host)
  listener.listen()
  stdout.writeLine("ready " & C.host & ":" & $int(C.port))
  stdout.flushFile()
  listener.accept(client)
  defer:
    client.close()
  while S.state notin {tssClosed, tssFailed}:
    chunk = client.recv(16 * 1024)
    if chunk.len == 0:
      break
    O = S.feedTls13Server(bytesFromString(chunk))
    client.sendServerOutput(O)
    if O.err.len > 0:
      raise newException(IOError, O.err)
    if O.applicationData.len > 0 and not replied:
      client.sendHttpResponse(S)
      replied = true
  if S.state == tssFailed:
    raise newException(IOError, "TLS server session failed")
  if not replied:
    raise newException(IOError, "TLS client sent no application request")

when isMainModule:
  runHarness(parseHarnessConfig())
