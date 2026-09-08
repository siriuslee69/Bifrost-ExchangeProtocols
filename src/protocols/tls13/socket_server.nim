## ---------------------------------------------------------------------
## TLS 1.3 Socket Server <- blocking-socket driver for the server session
## ---------------------------------------------------------------------
##
## The session engines in `server_session` are pure byte pumps: they take
## inbound bytes and hand back outbound bytes. Protocols that own a plain
## blocking socket -- SMTP's STARTTLS being the motivating case -- need a
## small driver that moves those bytes and exposes a line-oriented view.
##
## Keeping the driver in Bifrost means mail transports get TLS 1.3 on Tyr's
## native crypto without linking OpenSSL and without reimplementing record
## plumbing per protocol.

import std/[net, options, times]

import ../types

import ./server_session
import bifrostPragmas

const
  tls13SocketReadChunk* = 4096
  tls13SocketHandshakeTimeoutMs* = 15_000

type
  Tls13SocketSession* {.role: memory,
      metaTags: {tagTls, tagTransport, tagCryptoBoundary}.} = object
    session*: Tls13ServerSession
    plaintext: string   ## decrypted application bytes not yet consumed
    active*: bool
    closed*: bool

  Tls13SocketResult* {.role: truthState, metaTags: {tagTls, tagTransport}.} = object
    ok*: bool
    err*: string

proc initTls13SocketSession*(): Tls13SocketSession {.role: truthBuilder,
    metaTags: {tagTls, tagTransport}.} =
  ## Return an inactive socket session.
  result.plaintext = ""
  result.active = false
  result.closed = false

proc tls13SocketActive*(S: Tls13SocketSession): bool {.role: helper,
    metaTags: {tagTls}.} =
  ## S: socket session to test.
  result = S.active and not S.closed

proc toStr(b: openArray[byte]): string {.role: helper, metaTags: {tagTls}.} =
  ## b: bytes to view as a string.
  result = newString(b.len)
  for i, v in b:
    result[i] = char(v)

proc toBytes(s: string): ByteSeq {.role: helper, metaTags: {tagTls}.} =
  ## s: string to view as bytes.
  result = newSeq[byte](s.len)
  for i, c in s:
    result[i] = byte(c)

proc sendAll(sock: var Socket, data: openArray[byte]): bool {.role: dataWriter,
    metaTags: {tagTls, tagTransport, tagWrite}.} =
  ## sock/data: connected socket and record bytes to write.
  if data.len == 0:
    return true
  try:
    sock.send(toStr(data))
    result = true
  except CatchableError:
    result = false

proc flushOutbound(sock: var Socket, O: Tls13ServerOutput): bool {.
    role: dataWriter, metaTags: {tagTls, tagTransport, tagWrite}.} =
  ## sock/O: socket and the records the session produced.
  var i: int = 0
  while i < O.outbound.len:
    if not sendAll(sock, O.outbound[i]):
      return false
    i = i + 1
  result = true

proc readChunk(sock: var Socket, timeoutMs: int): tuple[ok: bool, data: string] {.
    role: dataFetcher, metaTags: {tagTls, tagTransport, tagRead}.} =
  ## sock/timeoutMs: socket and per-read timeout; zero blocks indefinitely.
  var buf: string = newString(tls13SocketReadChunk)
  try:
    var n: int = 0
    if timeoutMs > 0:
      n = sock.recv(buf, tls13SocketReadChunk, timeoutMs)
    else:
      n = sock.recv(buf, tls13SocketReadChunk)
    if n <= 0:
      return (ok: false, data: "")
    buf.setLen(n)
    result = (ok: true, data: buf)
  except CatchableError:
    result = (ok: false, data: "")

proc startTls13ServerSocket*(sock: var Socket, S: var Tls13SocketSession,
    cfg: Tls13ServerConfig,
    timeoutMs: int = tls13SocketHandshakeTimeoutMs): Tls13SocketResult {.
    role: orchestrator, metaTags: {tagTls, tagTransport, tagCryptoBoundary}.} =
  ## sock: connected plaintext socket to upgrade in place.
  ## S: socket session receiving the established TLS state.
  ## cfg: server certificate chain and matching private key.
  ## timeoutMs: overall handshake deadline.
  ##
  ## Drives the handshake to completion, then leaves the session ready for
  ## line-oriented application traffic.
  var
    O: Tls13ServerOutput
    chunk: tuple[ok: bool, data: string]
    deadline: float = epochTime() + float(timeoutMs) / 1000.0
  try:
    S.session = initTls13ServerSession(cfg)
  except CatchableError as e:
    result.err = "TLS server configuration is invalid: " & e.msg
    return
  S.plaintext = ""
  while true:
    if timeoutMs > 0 and epochTime() > deadline:
      result.err = "TLS handshake timed out"
      return
    chunk = readChunk(sock, timeoutMs)
    if not chunk.ok:
      result.err = "TLS peer closed during the handshake"
      return
    O = feedTls13Server(S.session, toBytes(chunk.data))
    when defined(tls13SocketDebug):
      echo "   [drv] read ", chunk.data.len, " bytes, outbound=",
        O.outbound.len, " err=", O.err, " connected=", O.connected
    if not flushOutbound(sock, O):
      result.err = "TLS handshake write failed"
      return
    if O.err.len > 0:
      result.err = O.err
      return
    if O.closed:
      result.err = "TLS peer closed during the handshake"
      return
    for entry in O.applicationData:
      S.plaintext.add(toStr(entry))
    if O.connected:
      S.active = true
      result.ok = true
      return

proc pumpPlaintext(sock: var Socket, S: var Tls13SocketSession,
    timeoutMs: int): bool {.role: dataFetcher,
    metaTags: {tagTls, tagTransport, tagRead}.} =
  ## sock/S/timeoutMs: socket, session, and read timeout.
  ## Reads one ciphertext chunk and appends whatever plaintext it yields.
  var
    chunk: tuple[ok: bool, data: string] = readChunk(sock, timeoutMs)
    O: Tls13ServerOutput
  if not chunk.ok:
    return false
  O = feedTls13Server(S.session, toBytes(chunk.data))
  if not flushOutbound(sock, O):
    return false
  if O.err.len > 0:
    S.closed = true
    return false
  for entry in O.applicationData:
    S.plaintext.add(toStr(entry))
  if O.closed:
    S.closed = true
  result = true

proc takeLine(S: var Tls13SocketSession): Option[string] {.role: parser,
    metaTags: {tagTls, tagRead}.} =
  ## S: session whose buffered plaintext is scanned for one complete line.
  var idx: int = S.plaintext.find('\l')
  if idx < 0:
    return none(string)
  var line: string = S.plaintext[0 ..< idx]
  S.plaintext = S.plaintext[idx + 1 .. ^1]
  if line.len > 0 and line[^1] == '\r':
    line.setLen(line.len - 1)
  result = some(line)

proc tls13SocketReadLine*(sock: var Socket, S: var Tls13SocketSession,
    timeoutMs: int = 0; maxLineLength: int = 0): Option[string] {.
    role: dataFetcher, metaTags: {tagTls, tagTransport, tagRead}.} =
  ## sock/S: socket and established TLS session.
  ## timeoutMs: per-read timeout; zero blocks indefinitely.
  ## maxLineLength: refuse a line longer than this; zero disables the bound.
  ## Returns one CRLF-terminated line without its terminator.
  var buffered: Option[string]
  if not tls13SocketActive(S):
    return none(string)
  while true:
    buffered = takeLine(S)
    if buffered.isSome:
      return buffered
    if maxLineLength > 0 and S.plaintext.len > maxLineLength:
      # A peer that never sends a terminator must not grow this buffer without
      # bound.
      S.closed = true
      return none(string)
    if S.closed:
      return none(string)
    if not pumpPlaintext(sock, S, timeoutMs):
      return none(string)

proc tls13SocketWriteLine*(sock: var Socket, S: var Tls13SocketSession,
    line: string): bool {.role: dataWriter,
    metaTags: {tagTls, tagTransport, tagWrite}.} =
  ## sock/S/line: socket, established session, and payload without CRLF.
  if not tls13SocketActive(S):
    return false
  try:
    result = sendAll(sock, encodeTls13ServerApplication(S.session,
      toBytes(line & "\r\n")))
  except CatchableError:
    result = false

proc tls13SocketClose*(sock: var Socket, S: var Tls13SocketSession) {.
    role: orchestrator, metaTags: {tagTls, tagTransport}.} =
  ## sock/S: socket and session to shut down cleanly.
  if S.active and not S.closed:
    try:
      discard sendAll(sock, closeTls13Server(S.session))
    except CatchableError:
      discard
  S.active = false
  S.closed = true
  S.plaintext = ""
