## ------------------------------------------------------
## TLS Ops <- optional TLS wrappers for TCP socket usage
## ------------------------------------------------------

import std/net

import ./types
import runePragmas

when defined(ssl):
  import std/openssl

  proc toSslVerifyMode(v: TlsVerifyMode): SslCVerifyMode {.role: helper.} =
    ## toSslVerifyMode: build to ssl verify mode.
    case v
    of tvmDisabled:
      result = CVerifyNone
    of tvmPeer:
      result = CVerifyPeer
    of tvmPeerUseEnv:
      result = CVerifyPeerUseEnvVars

  proc buildTlsContext*(t: TlsConfig, r: TlsRole): SslContext {.role: truthBuilder.} =
    ## t: TLS runtime settings.
    ## r: TLS role for session policy.
    result = newContext(verifyMode = toSslVerifyMode(t.verifyMode),
      certFile = t.certFile, keyFile = t.keyFile, caDir = t.caDir,
      caFile = t.caFile)
    if r == trServer and t.sessionIdContext.len > 0:
      result.sessionIdContext = t.sessionIdContext

  proc resolveTlsHostName(t: TlsConfig, h: string): string {.role: helper.} =
    ## t: TLS runtime settings.
    ## h: fallback transport host name.
    result = t.serverName
    if result.len == 0:
      result = h

  proc wrapClientSocketTls(sock: Socket, t: TlsConfig, h: string) {.role: orchestrator.} =
    ## sock: already-connected TCP socket.
    ## t: TLS runtime settings.
    ## h: fallback hostname when client-side `serverName` is empty.
    var
      ctx: SslContext
      hostName: string
      ret: int
    ctx = buildTlsContext(t, trClient)
    hostName = resolveTlsHostName(t, h)
    if t.verifyMode == tvmDisabled:
      wrapSocket(ctx, sock)
      if hostName.len > 0 and not isIpAddress(hostName):
        discard SSL_set_tlsext_host_name(sock.sslHandle, hostName.cstring)
      ErrClearError()
      ret = SSL_connect(sock.sslHandle)
      socketError(sock, ret)
      return
    wrapConnectedSocket(ctx, sock, handshakeAsClient, hostName)

  proc wrapSocketTls*(sock: Socket, t: TlsConfig, r: TlsRole,
      h: string = "") {.role: orchestrator.} =
    ## sock: already-connected TCP socket.
    ## t: TLS runtime settings.
    ## r: TLS role for handshake.
    ## h: fallback hostname when client-side `serverName` is empty.
    var
      ctx: SslContext
    if not t.enabled:
      return
    case r
    of trClient:
      wrapClientSocketTls(sock, t, h)
    of trServer:
      ctx = buildTlsContext(t, r)
      wrapConnectedSocket(ctx, sock, handshakeAsServer)
else:
  proc buildTlsContext*(t: TlsConfig, r: TlsRole): SslContext {.role: truthBuilder.} =
    ## t/r: unused without `-d:ssl`.
    raise newException(IOError, "TLS support requires compiling with -d:ssl")

  proc wrapSocketTls*(sock: Socket, t: TlsConfig, r: TlsRole,
      h: string = "") {.role: orchestrator.} =
    ## sock/t/r/h: unused without `-d:ssl`.
    discard sock
    discard t
    discard r
    discard h
    raise newException(IOError, "TLS support requires compiling with -d:ssl")
