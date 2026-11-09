## -------------------------------------------------------------------------
## SMTP Client <- the sending side of one delivery, bytes in, bytes out
## -------------------------------------------------------------------------
##
##   var C = initSmtpClient("mx.mine", "a@mine", @["b@there"], mailText)
##   loop:
##     step = C.feedSmtpClient(bytesFromSocket)
##     send(step.send)
##     if step.done: break
##
##   them                 this side sends next
##   -------------------  --------------------
##   220 greeting         EHLO
##   250 (EHLO)           STARTTLS, when wanted and offered; else MAIL FROM
##   250 (MAIL)           RCPT TO, one at a time
##   250 or 550 (RCPT)    the next RCPT, then DATA
##   354                  the message
##   250 (end of text)    QUIT
##
## A 4xx or 5xx ends the delivery; `err` holds what the other side said.

import std/strutils

import ../types
import ../level0/lines
import ./server
import runePragmas

proc initSmtpClient*(hostname, mailFrom: string, recipients: seq[string],
    message: string, wantTls: bool = true, needTls: bool = false): SmtpClient {.
    role: configurator, tag: "smtp|appApi".} =
  ## hostname: the name this side says in EHLO. mailFrom/recipients/message: the
  ## mail. wantTls: use STARTTLS when offered. needTls: refuse to go on without it.
  result.hostname = hostname
  result.mailFrom = mailFrom
  result.recipients = recipients
  result.text = stuffSmtpData(message)
  result.wantTls = wantTls or needTls
  result.needTls = needTls

proc failed(C: var SmtpClient, R: var SmtpClientStep, why: string) {.role: actor.} =
  ## C/R/why: the delivery is over and did not work.
  C.phase = scpDone
  R.done = true
  R.err = why

proc afterEhlo(C: var SmtpClient, R: var SmtpClientStep) {.role: actor.} =
  ## C/R: EHLO was answered: STARTTLS, or go on to the mail itself.
  if C.wantTls and C.sawTlsOffer and not C.usingTls:
    C.phase = scpStartTls
    R.send.add("STARTTLS\r\n")
    return
  if C.needTls and not C.usingTls:
    C.failed(R, "the other server offers no TLS and this delivery needs it")
    return
  C.phase = scpMail
  R.send.add("MAIL FROM:<" & C.mailFrom & ">\r\n")

proc nextRcptOrData(C: var SmtpClient, R: var SmtpClientStep) {.role: actor.} =
  ## C/R: the next recipient, or DATA when none are left.
  if C.nextRecipient < C.recipients.len:
    C.phase = scpRcpt
    R.send.add("RCPT TO:<" & C.recipients[C.nextRecipient] & ">\r\n")
    return
  if C.accepted.len == 0:
    C.failed(R, "no recipient was accepted")
    return
  C.phase = scpData
  R.send.add("DATA\r\n")

proc noteRcpt(C: var SmtpClient, code: int) {.role: actor, inline.} =
  ## C/code: the answer to one RCPT.
  if code div 100 == 2:
    C.accepted.add(C.recipients[C.nextRecipient])
  else:
    C.refused.add(C.recipients[C.nextRecipient])
  C.nextRecipient = C.nextRecipient + 1

proc onReply(C: var SmtpClient, code: int, text: string, R: var SmtpClientStep) {.
    role: orchestrator.} =
  ## C/code/text/R: one complete reply, last line.
  if C.phase == scpRcpt:
    C.noteRcpt(code)
    C.nextRcptOrData(R)
    return
  if code div 100 != 2 and code != 354:
    C.failed(R, $code & " " & text)
    return
  case C.phase
  of scpGreeting:
    C.phase = scpEhlo
    R.send.add("EHLO " & C.hostname & "\r\n")
  of scpEhlo: C.afterEhlo(R)
  of scpStartTls: R.startTls = true
  of scpMail: C.nextRcptOrData(R)
  of scpData:
    C.phase = scpBody
    R.send.add(C.text)
  of scpBody:
    C.phase = scpQuit
    R.send.add("QUIT\r\n")
    R.done = true
    R.ok = true
  else: discard

proc noteOffer(C: var SmtpClient, text: string) {.role: actor, inline.} =
  ## C/text: one line of the EHLO answer.
  if C.phase == scpEhlo and text.toUpperAscii().startsWith("STARTTLS"):
    C.sawTlsOffer = true

proc feedSmtpClient*(C: var SmtpClient, bytes: string): SmtpClientStep {.
    role: orchestrator, tag: "smtp|appApi".} =
  ## C: the delivery. bytes: what the other side sent since the last call.
  var
    got: tuple[ok: bool, line: string] = (false, "")
    r: tuple[ok: bool, code: int, more: bool, text: string] = (false, 0, false, "")
  C.pending.add(bytes)
  while not result.done and not result.startTls:
    got = takeSmtpLine(C.pending)
    if not got.ok:
      break
    r = parseSmtpReply(got.line)
    if not r.ok:
      C.failed(result, "the other server said something that is not SMTP")
      break
    C.noteOffer(r.text)
    if not r.more:
      C.onReply(r.code, r.text, result)

proc resumeSmtpClient*(C: var SmtpClient): SmtpClientStep {.role: actor,
    tag: "smtp|appApi".} =
  ## C: TLS is up now. Says EHLO again: nothing said in the clear still counts.
  C.usingTls = true
  C.sawTlsOffer = false
  C.pending = ""
  C.phase = scpEhlo
  result.send = "EHLO " & C.hostname & "\r\n"
