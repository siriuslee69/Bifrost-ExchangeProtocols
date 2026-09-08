## ----------------------------------------------------------------------
## TLS Test Support <- shared ephemeral localhost certificate helpers
## ----------------------------------------------------------------------

import std/net

when defined(ssl):
  import std/os

import ../../src/protocols/transport/types
import ../../src/protocols/transport/tcp_ops
import bifrostPragmas

proc nextUnusedTcpAddress*(host: string): TcpAddress {.role: dataFetcher.} =
  ## host: bind host used to reserve a likely-free TCP port for a test thread.
  var
    sock: Socket
    bound: tuple[host: string, port: Port]
  sock = listenTcp(initTcpAddress(host, 0'u16))
  bound = sock.getLocalAddr()
  close(sock)
  result = initTcpAddress(bound.host, uint16(bound.port))

when defined(ssl):
  import std/osproc

  var tlsTestCertificateReady = false

  proc ensureTlsTestCertificate*(): tuple[certFile: string, keyFile: string] =
    ## ensureTlsTestCertificate: generate an ephemeral localhost cert on demand.
    let dir = joinPath("build", "transport_tls")
    result.certFile = joinPath(dir, "localhost-cert.pem")
    result.keyFile = joinPath(dir, "localhost-key.pem")
    if tlsTestCertificateReady:
      return
    createDir(dir)
    if fileExists(result.certFile):
      removeFile(result.certFile)
    if fileExists(result.keyFile):
      removeFile(result.keyFile)
    let gen = execCmdEx("openssl req -x509 -newkey rsa:2048 -keyout " &
      quoteShell(result.keyFile) & " -out " & quoteShell(result.certFile) &
      " -sha256 -days 30 -nodes -subj /CN=localhost " &
      "-addext subjectAltName=DNS:localhost")
    doAssert gen.exitCode == 0, gen.output
    tlsTestCertificateReady = true

  proc initTlsTestServerConfig*(certFile, keyFile: string): TlsConfig =
    ## certFile/keyFile: PEM certificate pair for the server endpoint.
    result = defaultTlsConfig()
    result.enabled = true
    result.verifyMode = tvmDisabled
    result.certFile = certFile
    result.keyFile = keyFile
    result.sessionIdContext = "ame-tests"

  proc initTlsTestClientConfig*(verifyMode: TlsVerifyMode, serverName = "",
      caFile = ""): TlsConfig =
    ## verifyMode/serverName/caFile: client verification knobs for TLS tests.
    result = defaultTlsConfig()
    result.enabled = true
    result.verifyMode = verifyMode
    result.serverName = serverName
    result.caFile = caFile
