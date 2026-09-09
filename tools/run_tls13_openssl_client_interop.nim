## ----------------------------------------------------------------------
## TLS 1.3 OpenSSL Client Interop <- reproducible native-client gate
## ----------------------------------------------------------------------

import std/[os, osproc, streams, strutils]
import runePragmas

const
  interopHost = "127.0.0.1"
  interopPort = "19444"

proc runChecked(command: string, args: openArray[string]): string {.
    role: orchestrator, tag: "tls|interop".} =
  var
    P: Process = startProcess(command, args = @args,
      options = {poUsePath, poStdErrToStdOut})
    code: int = 0
  result = P.outputStream.readAll()
  code = P.waitForExit()
  P.close()
  if code != 0:
    raise newException(IOError, command & " failed:\n" & result)

proc runInterop() {.role: metaOrchestrator, tag: "tls|interop".} =
  var
    root: string = joinPath(getTempDir(), "bifrost_tls13_client_interop")
    caCert: string = joinPath(root, "ca_certificate.pem")
    caKey: string = joinPath(root, "ca_private_key.pem")
    leafCert: string = joinPath(root, "server_certificate.pem")
    leafKey: string = joinPath(root, "server_private_key.pem")
    leafCsr: string = joinPath(root, "server_request.pem")
    extensions: string = joinPath(root, "server_extensions.cnf")
    clientPath: string = joinPath(root,
      when defined(windows): "tls13_client.exe" else: "tls13_client")
    server: Process
    clientOutput, serverOutput: string = ""
    serverCode: int = 0
  if findExe("openssl").len == 0:
    raise newException(IOError, "OpenSSL executable is required")
  if dirExists(root):
    removeDir(root)
  createDir(root)
  defer:
    if dirExists(root):
      removeDir(root)
  writeFile(extensions, """basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
""")
  discard runChecked("openssl", @[
    "req", "-x509", "-newkey", "ed25519", "-noenc",
    "-keyout", caKey,
    "-out", caCert,
    "-days", "2",
    "-set_serial", "1",
    "-subj", "/CN=Bifrost TLS Test Root",
    "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign"
  ])
  discard runChecked("openssl", @[
    "req", "-new", "-newkey", "ed25519", "-noenc",
    "-keyout", leafKey,
    "-out", leafCsr,
    "-subj", "/CN=localhost"
  ])
  discard runChecked("openssl", @[
    "x509", "-req",
    "-in", leafCsr,
    "-CA", caCert,
    "-CAkey", caKey,
    "-set_serial", "2",
    "-days", "2",
    "-extfile", extensions,
    "-out", leafCert
  ])
  discard runChecked("nim", @[
    "c", "--out:" & clientPath, "tools/test_tls13_openssl_client.nim"
  ])
  server = startProcess("openssl", args = @[
    "s_server",
    "-accept", interopHost & ":" & interopPort,
    "-4",
    "-tls1_3",
    "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256",
    "-groups", "X25519",
    "-sigalgs", "ed25519",
    "-alpn", "http/1.1",
    "-cert", leafCert,
    "-key", leafKey,
    "-naccept", "1",
    "-www"
  ], options = {poUsePath, poStdErrToStdOut})
  clientOutput = runChecked(clientPath, @[
    "--root:" & caCert,
    "--host:" & interopHost,
    "--name:localhost",
    "--port:" & interopPort
  ])
  serverOutput = server.outputStream.readAll()
  serverCode = server.waitForExit()
  server.close()
  if serverCode != 0:
    raise newException(IOError, "OpenSSL TLS server failed:\n" & serverOutput)
  if "HTTP/1.0 200 ok" notin clientOutput or
      "TLS_CHACHA20_POLY1305_SHA256" notin clientOutput:
    raise newException(IOError,
      "native TLS client interoperability evidence is incomplete:\n" &
      clientOutput)
  stdout.writeLine("TLS 1.3 OpenSSL client interoperability passed")

when isMainModule:
  runInterop()
