## -------------------------------------------------------------------------
## SMTP Server <- the receiving side of a conversation, bytes in, bytes out
## -------------------------------------------------------------------------
##
##   var S = initSmtpServer("mx.example")
##   send(greetSmtp(S))
##   loop:
##     step = S.feedSmtpServer(bytesFromSocket, isMine)
##     send(step.reply)
##     for m in step.mails: keep(m)
##
## `isMine(address)` is asked for each recipient: a server must not take mail
## for strangers, or it becomes a relay for anybody's spam.
##
## ╭─ ❧ Only CRLF ends a line ⚠️
##
## A line ends with the two bytes CR LF and nothing else. A bare LF stays inside
## the line. That is what stops "SMTP smuggling": hiding a second mail behind
## "LF . LF", which some servers read as the end of the first. Here it is text.

import std/strutils

import ../types
import ../level0/lines
import runePragmas
import var_invariants

const
  smtpSizeReply = "552 5.3.4 message too large\r\n"
  smtpDataDiscardBytes = 1024 * 1024

proc initSmtpServer*(hostname: string, maxBytes: int = smtpDefaultMaxBytes,
    maxRecipients: int = smtpDefaultMaxRecipients,
    offerTls: bool = false): SmtpServer {.role: configurator,
    tag: "smtp|appApi", needs: maxBytes > 0 and maxRecipients > 0.} =
  ## hostname: the name this server greets with. maxBytes/maxRecipients: limits
  ## of one mail. offerTls: say STARTTLS; the caller must then be able to do it.
  result.hostname = hostname
  result.maxBytes = maxBytes
  result.maxRecipients = maxRecipients
  result.offerTls = offerTls

proc greetSmtp*(S: SmtpServer): string {.role: helper, tag: "smtp|appApi".} =
  ## S: the first line this side sends.
  result = "220 " & S.hostname & " ESMTP\r\n"

proc clearEnvelope(S: var SmtpServer) {.role: actor, inline.} =
  ## S: forgets the mail under way, keeps the connection.
  S.mailFrom = ""
  S.recipients = @[]
  S.dataBlocks = @[]
  S.dataLen = 0
  S.tooLarge = false
  S.dataDiscarded = 0

proc resetSmtpServer*(S: var SmtpServer) {.role: actor, tag: "smtp|appApi".} =
  ## S: after STARTTLS. Everything said before the switch is forgotten, so
  ## words injected in the clear cannot reach the protected part.
  S.clearEnvelope()
  S.pending = ""
  S.phase = sspHello

proc ehloReply(S: SmtpServer, arg: string): string {.role: helper.} =
  ## S/arg: the EHLO answer with what this side can do.
  result = "250-" & S.hostname & " greets " & arg & "\r\n250-SIZE " &
    $S.maxBytes & "\r\n250-8BITMIME\r\n"
  if S.offerTls:
    result.add("250-STARTTLS\r\n")
  result.add("250 PIPELINING\r\n")

proc onHello(S: var SmtpServer, verb, arg: string): string {.role: actor.} =
  ## S/verb/arg: EHLO or HELO.
  S.clearEnvelope()
  S.phase = sspReady
  if verb == "HELO":
    return "250 " & S.hostname & "\r\n"
  result = S.ehloReply(arg)

proc onMail(S: var SmtpServer, arg: string): string {.role: actor.} =
  ## S/arg: MAIL FROM.
  var
    got: tuple[ok: bool, address: string] = parseSmtpPath("FROM:", arg)
    size: tuple[ok, tooLarge: bool] = (false, false)
  if S.phase != sspReady:
    return "503 say hello first, one mail at a time\r\n"
  if not got.ok:
    return "501 bad sender address\r\n"
  size = smtpMailSize(arg, S.maxBytes)
  if not size.ok:
    return "501 bad SIZE parameter\r\n"
  if size.tooLarge:
    return smtpSizeReply
  S.mailFrom = got.address
  S.phase = sspRecipients
  result = "250 ok\r\n"

proc onRcpt(S: var SmtpServer, arg: string,
    isMine: proc (a: string): bool {.gcsafe.}): string {.role: actor.} =
  ## S/arg/isMine: RCPT TO, one recipient.
  var
    got: tuple[ok: bool, address: string] = parseSmtpPath("TO:", arg)
  if S.phase != sspRecipients:
    return "503 say MAIL first\r\n"
  if not got.ok or got.address.len == 0:
    return "501 bad recipient address\r\n"
  if S.recipients.len >= S.maxRecipients:
    return "452 too many recipients\r\n"
  if not isMine(got.address):
    return "550 no such mailbox here\r\n"
  S.recipients.add(got.address)
  result = "250 ok\r\n"

proc onCommand(S: var SmtpServer, line: string, R: var SmtpServerStep,
    isMine: proc (a: string): bool {.gcsafe.}) {.role: orchestrator.} =
  ## S/line/R/isMine: one command line.
  var
    c: tuple[verb, arg: string] = parseSmtpCommand(line)
  case c.verb
  of "EHLO", "HELO": R.reply.add(S.onHello(c.verb, c.arg))
  of "MAIL": R.reply.add(S.onMail(c.arg))
  of "RCPT": R.reply.add(S.onRcpt(c.arg, isMine))
  of "NOOP": R.reply.add("250 ok\r\n")
  of "RSET":
    S.clearEnvelope()
    if S.phase != sspHello: S.phase = sspReady
    R.reply.add("250 ok\r\n")
  of "DATA":
    if S.phase != sspRecipients or S.recipients.len == 0:
      R.reply.add("503 no recipients yet\r\n")
    else:
      S.phase = sspData
      R.reply.add("354 end with a line holding only a dot\r\n")
  of "STARTTLS":
    if not S.offerTls or S.phase == sspRecipients:
      R.reply.add("502 not available now\r\n")
    else:
      R.reply.add("220 go ahead\r\n")
      R.startTls = true
  of "QUIT":
    R.reply.add("221 bye\r\n")
    R.closed = true
    S.phase = sspClosed
  else:
    R.reply.add("500 what?\r\n")

proc joinedData(S: SmtpServer): string {.role: truthBuilder.} =
  ## S: the message text, the blocks joined into exactly one string.
  result = newStringOfCap(S.dataLen)
  for b in S.dataBlocks:
    result.add(b)

proc addData(S: var SmtpServer, text: string) {.role: actor.} =
  ## S/text: appended to the message text, in blocks of about 64 KB.
  if S.dataBlocks.len == 0 or S.dataBlocks[S.dataBlocks.high].len + text.len > smtpDataBlockBytes:
    S.dataBlocks.add(newStringOfCap(max(smtpDataBlockBytes, text.len)))
  S.dataBlocks[S.dataBlocks.high].add(text)
  S.dataLen = S.dataLen + text.len

proc finishMail(S: var SmtpServer, R: var SmtpServerStep) {.role: actor.} =
  ## S/R: the line holding only a dot arrived.
  if not S.tooLarge:
    R.mails.add(SmtpMail(mailFrom: S.mailFrom, recipients: S.recipients,
      data: S.joinedData()))
    R.reply.add("250 kept\r\n")
  S.clearEnvelope()
  S.phase = sspReady

proc closeSmtpInput(S: var SmtpServer, R: var SmtpServerStep) {.role: actor.} =
  ## S/R: release buffers and tell the caller to close the conversation.
  S.clearEnvelope()
  S.pending = ""
  S.phase = sspClosed
  R.closed = true

proc rejectDataSize(S: var SmtpServer, R: var SmtpServerStep) {.role: actor.} =
  ## S/R: send one refusal and free the body. Keep reading DATA up to the cap.
  if S.tooLarge:
    return
  S.tooLarge = true
  S.dataBlocks = @[]
  R.reply.add(smtpSizeReply)

proc dataLineBytes(s: string): int {.role: parser, inline.} =
  ## s: DATA bytes with the transparency dot still present, if any.
  result = s.len - ord(s.len > 0 and s[0] == '.')

proc onDataLine(S: var SmtpServer, line: string, R: var SmtpServerStep) {.
    role: actor.} =
  ## S/line/R: one line of the message text.
  var
    l: int = dataLineBytes(line)
    room: int = S.maxBytes - S.dataLen
    excess: int = 0
  if line == ".":
    S.finishMail(R)
    return
  if S.tooLarge or l > room - 2:
    S.rejectDataSize(R)
    excess = (if S.dataDiscarded > 0: line.len else: l) - (room - 2)
    if excess >= smtpDataDiscardBytes - S.dataDiscarded:
      S.closeSmtpInput(R)
      return
    S.dataDiscarded = S.dataDiscarded + excess
    S.dataLen = S.maxBytes
    return
  if l < line.len:
    S.addData(line[1 .. ^1] & "\r\n")
  else:
    S.addData(line & "\r\n")

proc takeSmtpLine*(pending: var string): tuple[ok: bool, line: string] {.
    role: parser, tag: "smtp|wire".} =
  ## pending: bytes received so far. The first whole line, without its CRLF, cut
  ## off the front. Only CR LF ends a line (see the top of this file).
  var
    cut: int = pending.find("\r\n")
  if cut < 0:
    return
  result = (true, pending[0 ..< cut])
  pending = pending[cut + 2 .. ^1]

proc checkPendingData(S: var SmtpServer, R: var SmtpServerStep) {.role: actor.} =
  ## S/R: apply the same limit before a long, unfinished DATA line ends.
  var
    l: int = if S.dataDiscarded > 0: S.pending.len else: dataLineBytes(S.pending)
    excess: int = l - (S.maxBytes - S.dataLen)
  if excess <= 0 or S.pending == ".\r":
    return
  S.rejectDataSize(R)
  if excess >= smtpDataDiscardBytes - S.dataDiscarded:
    S.closeSmtpInput(R)

proc feedSmtpServer*(S: var SmtpServer, bytes: string,
    isMine: proc (a: string): bool {.gcsafe.}): SmtpServerStep {.
    role: orchestrator, tag: "smtp|appApi".} =
  ## S: the conversation. bytes: what just arrived. isMine: true for an address
  ## this server takes mail for.
  var
    got: tuple[ok: bool, line: string] = (false, "")
  if S.phase == sspClosed:
    return SmtpServerStep(closed: true)
  S.pending.add(bytes)
  while S.phase != sspClosed and not result.startTls:
    got = takeSmtpLine(S.pending)
    if not got.ok:
      break
    if S.phase == sspData:
      S.onDataLine(got.line, result)
    else:
      S.onCommand(got.line, result, isMine)
  if S.phase == sspData:
    S.checkPendingData(result)
  elif S.phase != sspClosed and not result.startTls and S.pending.len > smtpMaxLineBytes:
    result.reply.add("500 line too long\r\n")
    S.closeSmtpInput(result)
