## -------------------------------------------------------------------------
## SMTP server with STARTTLS <- one conversation, plain first, then TLS 1.3
## -------------------------------------------------------------------------
##
## No socket in here. A daemon holds one `SmtpTlsServer` per connection, hands
## it the bytes that arrive, and puts the bytes it answers on the wire.
## The tests hold the SAME object (WORKFLOW 4).
##
##   wire bytes in                                       wire bytes out
##        │                                                    ▲
##        ▼                                                    │
##   ┌─ swPlain ───────────────────┐   "STARTTLS"    ┌─ swHandshake ─┐
##   │ SmtpServer reads lines      │ ──────────────▶ │ TLS 1.3 reads │
##   │ replies in the clear        │  "220 go ahead" │ the handshake │
##   └─────────────────────────────┘  goes out plain └──────┬────────┘
##                                                           │ connected
##                                                           ▼
##                                                   ┌─ swSecure ─────────┐
##                                                   │ TLS opens the bytes│
##                                                   │ SmtpServer reads   │
##                                                   │ replies are sealed │
##                                                   └────────────────────┘
##
## ╭─ ❧ What the switch forgets 🔒
##
## Everything said BEFORE the switch is dropped (`resetSmtpServer`), also what
## sat in the same burst of bytes behind the STARTTLS line:
##
##   one burst from a stranger:  EHLO a\r\nSTARTTLS\r\nMAIL FROM:<x@y>\r\n
##   the server answers:         250 ... / 220 go ahead
##   the MAIL line:              never seen. After the switch the server is as
##                               if nothing was said (phase: hello).
##
## Without that, a man in the middle could slip a command into the clear text
## that the server then runs as if it came through the protected channel
## ("STARTTLS command injection", CVE-2011-0411 and its many cousins).
##
## ╭─ ❧ Two steps for a reply ✉️
##
##   step = feedSmtpTlsServer(C, bytes, isMine)
##   ...the caller keeps step.mails and may change step.reply (a mail that
##      could not be stored turns "250 kept" into "451 try again")...
##   send(step.send & sealSmtpTlsReply(C, step.reply))
##
## `send` holds what goes out as it is (handshake records, the plain
## "220 go ahead"); `reply` is SMTP text that `sealSmtpTlsReply` wraps in TLS
## once the switch has happened, and leaves alone before it.

import ../types
import ../level1/server
import ../../types as bfx_types
import ../../byte_codec
import ../../tls13/server_session
import runePragmas
import var_invariants

type
  SmtpWireMode* = enum
    swPlain,
      ## bytes are SMTP lines
    swHandshake,
      ## bytes are the TLS handshake
    swSecure,
      ## bytes are TLS records holding SMTP lines
    swDead
      ## finished or failed; nothing more is read

  SmtpTlsServer* {.role: truthState, tag: "smtp|tls|types",
      expectedCount: [0, 1024], lifeCycle: lcSession.} = object
    ## One incoming conversation that may switch to TLS.
    smtp*: SmtpServer
    mode*: SmtpWireMode
    tlsConfig: Tls13ServerConfig
    tls: Tls13ServerSession

  SmtpTlsStep* {.role: preparedData, tag: "smtp|tls|types".} = object
    ## What one `feedSmtpTlsServer` produced.
    send*: string
      ## bytes for the wire exactly as they are
    reply*: string
      ## SMTP text still to be sealed with `sealSmtpTlsReply`
    mails*: seq[SmtpMail]
    closed*: bool
      ## after sending, close the connection
    err*: string
      ## why a handshake or a record failed; "" otherwise

proc offersTls(C: Tls13ServerConfig): bool {.role: parser, inline.} =
  ## C: true when a certificate chain was given.
  result = C.certificateChainDer.len > 0

proc checkSmtpTlsConfig*(C: Tls13ServerConfig): tuple[ok: bool, err: string] {.
    role: sanitizer, tag: "smtp|tls|cryptoBoundary".} =
  ## C: the certificate chain and key. Run once when the daemon starts, so a
  ## wrong file stops the program there and not at the first stranger.
  ## An empty config is fine: it means "no STARTTLS".
  if not offersTls(C):
    return (true, "")
  try:
    discard initTls13ServerSession(C)
    result = (true, "")
  except CatchableError as e:
    result = (false, e.msg)

proc initSmtpTlsServer*(hostname: string, tls: Tls13ServerConfig = Tls13ServerConfig(),
    maxBytes: int = smtpDefaultMaxBytes,
    maxRecipients: int = smtpDefaultMaxRecipients): SmtpTlsServer {.
    role: configurator, tag: "smtp|tls|appApi",
    needs: maxBytes > 0 and maxRecipients > 0.} =
  ## hostname: the name this server greets with. tls: the certificate chain and
  ## key; an empty one means STARTTLS is not offered. maxBytes/maxRecipients:
  ## limits of one mail.
  result.smtp = initSmtpServer(hostname, maxBytes, maxRecipients, offersTls(tls))
  result.mode = swPlain
  result.tlsConfig = tls

proc greetSmtpTls*(C: SmtpTlsServer): string {.role: helper, tag: "smtp|tls|appApi".} =
  ## C: the first line this side sends (in the clear).
  result = greetSmtp(C.smtp)

proc smtpTlsSecure*(C: SmtpTlsServer): bool {.role: parser, tag: "smtp|tls".} =
  ## C: true once the switch to TLS has finished.
  result = C.mode == swSecure

proc concatBytes(A: seq[ByteSeq]): string {.role: helper.} =
  ## A: byte chunks joined into one text.
  for a in A:
    result.add(bytesToString(a))

proc startSwitch(C: var SmtpTlsServer, R: var SmtpTlsStep) {.role: actor,
    tag: "smtp|tls|cryptoBoundary".} =
  ## C/R: the client said STARTTLS and was told "220". That answer goes out in
  ## the clear, everything said so far is forgotten, and the handshake begins.
  R.send.add(R.reply)
  R.reply = ""
  C.smtp.resetSmtpServer()
  C.smtp.offerTls = false
  try:
    C.tls = initTls13ServerSession(C.tlsConfig)
    C.mode = swHandshake
  except CatchableError as e:
    R.err = "TLS could not start: " & e.msg
    R.closed = true
    C.mode = swDead

proc feedPlain(C: var SmtpTlsServer, bytes: string,
    isMine: proc (a: string): bool {.gcsafe.}, R: var SmtpTlsStep) {.
    role: actor, tag: "smtp|tls".} =
  ## C/bytes/isMine/R: SMTP lines, in the clear or already opened by TLS.
  var
    s: SmtpServerStep = C.smtp.feedSmtpServer(bytes, isMine)
  R.reply.add(s.reply)
  for m in s.mails:
    R.mails.add(m)
  if s.closed:
    R.closed = true
  if s.startTls:
    C.startSwitch(R)

proc feedTls(C: var SmtpTlsServer, bytes: string,
    isMine: proc (a: string): bool {.gcsafe.}, R: var SmtpTlsStep) {.
    role: actor, tag: "smtp|tls|cryptoBoundary".} =
  ## C/bytes/isMine/R: TLS records from the wire: the handshake, then SMTP.
  var
    O: Tls13ServerOutput = default(Tls13ServerOutput)
    plain: string = ""
  O = C.tls.feedTls13Server(stringToBytes(bytes))
  R.send.add(concatBytes(O.outbound))
  if O.err.len > 0:
    R.err = O.err
    R.closed = true
    C.mode = swDead
    return
  if C.tls.state == tssConnected and C.mode == swHandshake:
    C.mode = swSecure
  plain = concatBytes(O.applicationData)
  if plain.len > 0 and C.mode == swSecure:
    C.feedPlain(plain, isMine, R)
  if O.closed:
    R.closed = true
    C.mode = swDead

proc feedSmtpTlsServer*(C: var SmtpTlsServer, bytes: string,
    isMine: proc (a: string): bool {.gcsafe.}): SmtpTlsStep {.
    role: orchestrator, tag: "smtp|tls|appApi|cryptoBoundary".} =
  ## C: the conversation. bytes: what just arrived on the wire. isMine: true for
  ## an address this server takes mail for. Nothing here raises.
  try:
    case C.mode
    of swPlain:
      C.feedPlain(bytes, isMine, result)
    of swHandshake, swSecure:
      C.feedTls(bytes, isMine, result)
    of swDead:
      result.closed = true
  except CatchableError as e:
    result.err = "SMTP over TLS failed: " & e.msg
    result.closed = true
    C.mode = swDead
  if result.closed and C.mode != swDead and C.mode != swSecure:
    C.mode = swDead

proc sealSmtpTlsReply*(C: var SmtpTlsServer, reply: string): string {.
    role: encryptor, tag: "smtp|tls|cryptoBoundary".} =
  ## C/reply: SMTP text to put on the wire. Once TLS runs it is sealed; before
  ## that it goes as it is. "" stays "".
  if reply.len == 0:
    return ""
  if C.mode != swSecure:
    return reply
  try:
    result = bytesToString(C.tls.encodeTls13ServerApplication(stringToBytes(reply)))
  except CatchableError:
    C.mode = swDead
    result = ""

proc closeSmtpTlsServer*(C: var SmtpTlsServer): string {.
    role: encryptor, tag: "smtp|tls|cryptoBoundary".} =
  ## C: the bytes to send before the socket is closed (TLS "close_notify"); ""
  ## when TLS never ran. The conversation is over afterwards.
  if C.mode == swSecure:
    try:
      result = bytesToString(C.tls.closeTls13Server())
    except CatchableError:
      result = ""
  C.mode = swDead
