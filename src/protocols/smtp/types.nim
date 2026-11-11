## -------------------------------------------------------------------------
## SMTP Types <- a conversation between two mail servers, as plain objects
## -------------------------------------------------------------------------
##
##   them                                 this side
##   ----                                 ---------
##   EHLO a.example      ───────────▶     250
##   MAIL FROM:<x@a>     ───────────▶     250
##   RCPT TO:<y@b>       ───────────▶     250 (or 550)
##   DATA                ───────────▶     354
##   text ... CRLF.CRLF  ───────────▶     250 and one finished mail
##
## No socket in here. Bytes go in, bytes to send and finished mails come out.

import runePragmas

const
  smtpMaxLineBytes* = 4096
    ## a command line; a line of the message text is limited by maxBytes
  smtpDefaultMaxBytes* = 25 * 1024 * 1024
  smtpDefaultMaxRecipients* = 100

type
  SmtpMail* {.role: preparedData, tag: "smtp|types",
      expectedCount: [0, 64], lifeCycle: lcJob.} = object
    ## One finished mail.
    mailFrom*: string
      ## "" for the null sender (a bounce)
    recipients*: seq[string]
    data*: string
      ## headers and body, CRLF line ends, the dots already un-stuffed

  SmtpServerPhase* = enum
    sspHello,
      ## nothing said yet
    sspReady,
      ## EHLO was said; waiting for MAIL
    sspRecipients,
      ## MAIL was said; waiting for RCPT or DATA
    sspData,
      ## reading the message text
    sspClosed

  SmtpServer* {.role: truthState, tag: "smtp|types",
      expectedCount: [0, 1024], lifeCycle: lcSession.} = object
    ## One incoming conversation.
    hostname*: string
    offerTls*: bool
      ## say STARTTLS in the EHLO answer
    maxBytes*: int
    maxRecipients*: int
    phase*: SmtpServerPhase
    pending*: string
      ## bytes received that do not end in a whole line yet
    mailFrom*: string
    recipients*: seq[string]
    data*: string
    tooLarge*: bool

  SmtpServerStep* {.role: preparedData, tag: "smtp|types".} = object
    ## What one `feedSmtpServer` produced.
    reply*: string
      ## bytes to send back
    mails*: seq[SmtpMail]
    startTls*: bool
      ## send `reply`, then switch this connection to TLS, then `resetSmtpServer`
    closed*: bool

  SmtpClientPhase* = enum
    scpGreeting,
    scpEhlo,
    scpStartTls,
    scpMail,
    scpRcpt,
    scpData,
    scpBody,
    scpQuit,
    scpDone

  SmtpClient* {.role: truthState, tag: "smtp|types",
      expectedCount: [0, 64], lifeCycle: lcSession.} = object
    ## One outgoing delivery of one mail.
    hostname*: string
    mailFrom*: string
    recipients*: seq[string]
    text*: string
      ## already dot-stuffed and ending in CRLF.CRLF
    phase*: SmtpClientPhase
    pending*: string
    nextRecipient*: int
    accepted*: seq[string]
    refused*: seq[string]
    wantTls*: bool
      ## ask for STARTTLS when the other side offers it
    needTls*: bool
      ## give up when the other side does not offer it
    usingTls*: bool
    sawTlsOffer*: bool
    badInput*: string
      ## why this mail can never be sent (a bad address); "" when it can

  SmtpClientStep* {.role: preparedData, tag: "smtp|types".} = object
    ## What one `feedSmtpClient` produced.
    send*: string
    startTls*: bool
      ## switch to TLS now, then call `resumeSmtpClient`
    done*: bool
    ok*: bool
      ## done, and the other side accepted the mail for at least one recipient
    err*: string
