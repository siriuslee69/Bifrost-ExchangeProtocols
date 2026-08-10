## ----------------------------------------------------------------------
## TLS 1.3 OpenSSL Interop <- reproducible external native-server gate
## ----------------------------------------------------------------------

import std/[os, osproc, streams, strutils]
import ../src/analysis_pragmas

const
  interopHost = "127.0.0.1"
  interopPort = "19443"
  expectedBody = "native tls13 ok"

proc runChecked(command: string, args: openArray[string]): string {.
    role: orchestrator, tag: {tagTls, tagInterop}.} =
  var
    P: Process = startProcess(command, args = @args,
      options = {poUsePath, poStdErrToStdOut})
    code: int = 0
  result = P.outputStream.readAll()
  code = P.waitForExit()
  P.close()
  if code != 0:
    raise newException(IOError, command & " failed:\n" & result)

proc writeClientRequest(P: Process) {.role: dataWriter,
    tag: {tagTls, tagInterop}.} =
  P.inputStream.write(
    "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
  P.inputStream.flush()
  P.inputStream.close()

proc runClient(certPath: string): string {.role: orchestrator,
    tag: {tagTls, tagInterop}.} =
  var
    P: Process = startProcess("openssl", args = @[
      "s_client",
      "-connect", interopHost & ":" & interopPort,
      "-servername", "localhost",
      "-tls1_3",
      "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256",
      "-groups", "X25519",
      "-sigalgs", "ed25519",
      "-alpn", "http/1.1",
      "-CAfile", certPath,
      "-verify_hostname", "localhost",
      "-verify_return_error",
      "-ign_eof",
      "-brief"
    ], options = {poUsePath, poStdErrToStdOut})
    code: int = 0
  P.writeClientRequest()
  result = P.outputStream.readAll()
  code = P.waitForExit()
  P.close()
  if code != 0:
    raise newException(IOError, "OpenSSL TLS client failed:\n" & result)

proc runInterop() {.role: metaOrchestrator, tag: {tagTls, tagInterop}.} =
  var
    root: string = joinPath(getTempDir(), "bifrost_tls13_openssl_interop")
    certPath: string = joinPath(root, "certificate.pem")
    keyPath: string = joinPath(root, "private_key.pem")
    serverPath: string = joinPath(root,
      when defined(windows): "tls13_server.exe" else: "tls13_server")
    server: Process
    ready, clientOutput, serverOutput: string = ""
    serverCode: int = 0
  if findExe("openssl").len == 0:
    raise newException(IOError, "OpenSSL executable is required")
  if dirExists(root):
    removeDir(root)
  createDir(root)
  defer:
    if dirExists(root):
      removeDir(root)
  discard runChecked("openssl", @[
    "req", "-x509", "-newkey", "ed25519", "-noenc",
    "-keyout", keyPath,
    "-out", certPath,
    "-days", "2",
    "-set_serial", "1",
    "-subj", "/CN=localhost",
    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    "-addext", "basicConstraints=critical,CA:FALSE",
    "-addext", "keyUsage=critical,digitalSignature",
    "-addext", "extendedKeyUsage=serverAuth"
  ])
  discard runChecked("nim", @[
    "c", "--out:" & serverPath, "tools/test_tls13_openssl_server.nim"
  ])
  server = startProcess(serverPath, args = @[
    "--cert:" & certPath,
    "--key:" & keyPath,
    "--host:" & interopHost,
    "--port:" & interopPort
  ], options = {poStdErrToStdOut})
  if not server.outputStream.readLine(ready) or
      ready != "ready " & interopHost & ":" & interopPort:
    serverOutput = server.outputStream.readAll()
    server.terminate()
    discard server.waitForExit()
    server.close()
    raise newException(IOError,
      "native TLS server did not become ready:\n" & ready & serverOutput)
  clientOutput = runClient(certPath)
  serverOutput = server.outputStream.readAll()
  serverCode = server.waitForExit()
  server.close()
  if serverCode != 0:
    raise newException(IOError, "native TLS server failed:\n" & serverOutput)
  if expectedBody notin clientOutput or "Verification: OK" notin clientOutput or
      "TLSv1.3" notin clientOutput or
      "TLS_CHACHA20_POLY1305_SHA256" notin clientOutput:
    raise newException(IOError,
      "OpenSSL interoperability evidence is incomplete:\n" & clientOutput)
  stdout.writeLine("TLS 1.3 OpenSSL interoperability passed")

when isMainModule:
  runInterop()
