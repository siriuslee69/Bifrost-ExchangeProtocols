## -------------------------------------------------------------------------
## AME Handshake over TCP <- the one place that owns a socket and a clock
## -------------------------------------------------------------------------
##
## Everything below this file decides WHAT to send. This file decides when to
## read and when to give up, so it is the only part that has to be trusted
## about blocking and partial reads.
##
##   client                                            server
##   ------                                            ------
##   ameTcpClientHandshake()                           ameTcpServerHandshake()
##       |  send hello                                     |  read hello
##       |                                                 |  cookie ok? ---> no: send retry
##       |  <-- maybe a retry, then send the hello again   |
##       |                                                 |  send server hello
##       |  read server hello, check who the server is     |
##       |  send finish                                    |  read finish, check the client
##       |                                                 |
##       +-------- both return a ready AmeSession ---------+
##
## Records ride the length-prefixed TCP framing already used for data frames,
## so a short read can never be mistaken for a complete record.
##
## Note on the clock: certificate validity is judged against `nowUnix`, which
## the CALLER supplies. This file does not read the system clock, because a
## library that silently trusts an unset clock is worse than one that makes
## the caller say where the time came from.

import std/net

import ../../types
import ../types
import ../../transport/types as transport_types
import ../../transport/tcp_ops
import ../level1/suites
import ../level2/session
import ./handshake
import ./handshake_wire
import ./handshake_transport
import ../../../analysis_pragmas

export handshake_transport

proc peerIdBytes(a: transport_types.TcpAddress): ByteSeq {.role: helper.} =
  ## a: the remote address turned into stable bytes for the cookie.
  var
    text: string = formatTcpAddress(a)
    i: int = 0
  result.setLen(text.len)
  while i < text.len:
    result[i] = uint8(ord(text[i]))
    i = i + 1

proc readHandshakeFrame(sock: Socket, timeoutMs: int): tuple[ok: bool,
    frame: AmeHandshakeFrame, err: string] {.role: dataFetcher.} =
  ## sock/timeoutMs: read exactly one length-prefixed handshake frame.
  var
    got = recvTcpFrame(sock, timeoutMs, uint32(ameHandshakeMaxRecordBytes))
  if not got.ok:
    result.err = got.err
    if result.err.len == 0:
      result.err = "AME handshake peer closed the connection"
    return
  try:
    result.frame = decodeAmeHandshakeFrame(got.payload)
    result.ok = true
  except CatchableError as e:
    result.err = e.msg

proc ameTcpServerHandshake*(sock: Socket, c: AmeResponderPolicy,
    remote: transport_types.TcpAddress, nowUnix: int64,
    timeoutMs: int = 4000,
    sessionId: uint64 = 0'u64): AmeHandshakeOutcome {.role: orchestrator,
    tag: {tagAppApi, tagNetworkSurface}.} =
  ## sock/c/remote/nowUnix/timeoutMs/sessionId: run the responder side to
  ## completion and hand back a session that is ready to carry data.
  ##
  ## `nowUnix` is the trusted wall clock certificates are judged against.
  ## `sessionId` overrides the id the client proposed; 0 keeps the client's.
  var
    got: tuple[ok: bool, frame: AmeHandshakeFrame, err: string]
    hello: AmeClientHello
    retry: AmeHelloRetry
    answered: tuple[ok: bool, state: AmeServerHandshake, err: string]
    finish: AmeClientFinish
    accepted: AmeHandshakeResult
    step: uint32 = ameHandshakeStepHello
    peerId: ByteSeq = peerIdBytes(remote)
  got = readHandshakeFrame(sock, timeoutMs)
  if not got.ok:
    result.err = got.err
    return
  try:
    requireHandshakeFrame(got.frame, ampkClientHello, step)
    hello = decodeAmeClientHello(got.frame.record)
  except CatchableError as e:
    result.err = e.msg
    return
  ## The cookie round trip happens before ANY key work, so a flood of holds
  ## from forged addresses costs one small tag computation each.
  if c.requireCookie and
      not ameCookieValid(c.cookieSecret, peerId, nowUnix, hello):
    retry.sessionId = hello.sessionId
    retry.cookie = issueAmeCookie(c.cookieSecret, peerId, nowUnix, hello)
    try:
      sendTcpFrame(sock, encodeAmeHelloRetryFrame(retry))
    except CatchableError as e:
      result.err = "AME hello retry send failed: " & e.msg
      return
    got = readHandshakeFrame(sock, timeoutMs)
    if not got.ok:
      result.err = got.err
      return
    try:
      requireHandshakeFrame(got.frame, ampkClientHello,
        ameHandshakeStepRetriedHello, hello.sessionId)
      hello = decodeAmeClientHello(got.frame.record)
    except CatchableError as e:
      result.err = e.msg
      return
    if not ameCookieValid(c.cookieSecret, peerId, nowUnix, hello):
      result.err = "AME hello retry cookie is invalid"
      return
  answered = answerAmeHandshake(hello, c.supported, c.descriptor, c.identity,
    c.params)
  if not answered.ok:
    result.err = answered.err
    return
  try:
    sendTcpFrame(sock, encodeAmeServerHelloFrame(hello.sessionId,
      answered.state.serverHello))
  except CatchableError as e:
    clearAmeServerHandshake(answered.state)
    result.err = "AME server hello send failed: " & e.msg
    return
  got = readHandshakeFrame(sock, timeoutMs)
  if not got.ok:
    clearAmeServerHandshake(answered.state)
    result.err = got.err
    return
  try:
    requireHandshakeFrame(got.frame, ampkClientFinish,
      ameHandshakeStepFinish, hello.sessionId)
    finish = decodeAmeClientFinish(got.frame.record)
  except CatchableError as e:
    clearAmeServerHandshake(answered.state)
    result.err = e.msg
    return
  if c.trustMode == atmAuthorityCertificate:
    accepted = acceptAmeHandshake(answered.state, finish, c.root, nowUnix,
      c.revokedSerials)
  else:
    accepted = acceptAmePinnedHandshake(answered.state, finish,
      c.expectedPeer, nowUnix)
  if not accepted.ok:
    result.err = accepted.err
    result.peerTrust = accepted.peerTrust
    return
  result.peerTrust = accepted.peerTrust
  result.connection = initAmeSession(accepted.auth, sessionId,
    peerTrust = accepted.peerTrust)
  result.ok = true

proc ameTcpClientHandshake*(sock: Socket, c: AmeInitiatorPolicy,
    sessionId: uint64, nowUnix: int64,
    timeoutMs: int = 4000): AmeHandshakeOutcome {.role: orchestrator,
    tag: {tagAppApi, tagNetworkSurface}.} =
  ## sock/c/sessionId/nowUnix/timeoutMs: run the initiator side to completion.
  var
    state: AmeClientHandshake
    got: tuple[ok: bool, frame: AmeHandshakeFrame, err: string]
    retry: AmeHelloRetry
    serverHello: AmeServerHello
    finished: AmeHandshakeResult

  if sessionId == 0'u64:
    result.err = "AME client session id must be positive"
    return
  try:
    state = beginAmeHandshake(sessionId, c.layout, c.initialTier)
    sendTcpFrame(sock, encodeAmeClientHelloFrame(state.hello))
  except CatchableError as e:
    clearAmeClientHandshake(state)
    result.err = "AME client hello send failed: " & e.msg
    return
  got = readHandshakeFrame(sock, timeoutMs)
  if not got.ok:
    clearAmeClientHandshake(state)
    result.err = got.err
    return
  if got.frame.kind == ampkHelloRetry:
    ## The server wants proof we can receive at the address we claimed. Build
    ## a fresh hello -- fresh KEM keys and all -- carrying its cookie.
    try:
      requireHandshakeFrame(got.frame, ampkHelloRetry,
        ameHandshakeStepRetry, sessionId)
      retry = decodeAmeHelloRetry(got.frame.record)
      clearAmeClientHandshake(state)
      state = beginAmeHandshake(sessionId, c.layout, c.initialTier, 1'u32,
        retry.cookie)
      sendTcpFrame(sock, encodeAmeClientHelloFrame(state.hello,
        retried = true))
    except CatchableError as e:
      clearAmeClientHandshake(state)
      result.err = "AME hello retry failed: " & e.msg
      return

    got = readHandshakeFrame(sock, timeoutMs)
    if not got.ok:
      clearAmeClientHandshake(state)
      result.err = got.err
      return
  try:
    requireHandshakeFrame(got.frame, ampkServerHello,
      ameHandshakeStepServerHello, sessionId)
    serverHello = decodeAmeServerHello(c.layout, got.frame.record)
  except CatchableError as e:
    clearAmeClientHandshake(state)
    result.err = e.msg
    return
  if c.trustMode == atmAuthorityCertificate:
    finished = finishAmeHandshake(state, serverHello, c.root, c.descriptor,
      c.identity, nowUnix, c.revokedSerials)
  else:
    finished = finishAmePinnedHandshake(state, serverHello, c.expectedPeer,
      c.descriptor, c.identity, nowUnix)
  if not finished.ok:
    result.err = finished.err
    result.peerTrust = finished.peerTrust
    return
  try:
    sendTcpFrame(sock, encodeAmeClientFinishFrame(sessionId, finished.finish))
  except CatchableError as e:
    result.err = "AME client finish send failed: " & e.msg
    return
  result.peerTrust = finished.peerTrust
  result.connection = initAmeSession(finished.auth, sessionId,
    peerTrust = finished.peerTrust)
  result.ok = true
