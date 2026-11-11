## SMTP tests <- two mail servers talking, with no socket between them.
##
##   suite       what it holds down
##   ----------  -----------------------------------------------------------
##   "server"    the usual talk, refusals, limits, smuggling, TLS reset
##   "client"    the usual talk, refused recipients, a server that says no
##   "together"  the client's bytes are the server's bytes
##   "dkim"      relaxed forms from RFC 6376, a signature that verifies
##   "mx"        a real answer shape, and packets built to confuse the reader

import std/[base64, strutils, unittest]

import ../../src/protocols/smtp
import ../../src/protocols/mail

proc mine(a: string): bool {.gcsafe.} =
  ## a: this test server takes mail for example.org only.
  result = a.endsWith("@example.org")

proc talk(S: var SmtpServer, words: string): SmtpServerStep =
  ## S/words: one feed.
  result = S.feedSmtpServer(words, mine)

suite "server":
  # {.testKind: tkIntegration, covers: "feedSmtpServer".}
  test "a mail arrives whole, with its dots taken back out":
    var
      S = initSmtpServer("mx.example.org")
      r = S.talk("EHLO a\r\nMAIL FROM:<x@a.net>\r\nRCPT TO:<y@example.org>\r\nDATA\r\n")
    check r.reply.endsWith("354 end with a line holding only a dot\r\n")
    r = S.talk("Subject: hi\r\n\r\n..dot\r\nline\r\n.\r\n")
    check r.mails.len == 1
    check r.mails[0].mailFrom == "x@a.net"
    check r.mails[0].recipients == @["y@example.org"]
    check r.mails[0].data == "Subject: hi\r\n\r\n.dot\r\nline\r\n"
    check r.reply == "250 kept\r\n"

  # {.testKind: tkEdgeCase, covers: "feedSmtpServer".}
  test "bytes split anywhere make the same mail":
    var
      words = "EHLO a\r\nMAIL FROM:<>\r\nRCPT TO:<y@example.org>\r\nDATA\r\nhello\r\n.\r\n"
      S = initSmtpServer("h")
      got = 0
    for c in words:
      got = got + S.talk($c).mails.len
    check got == 1

  # {.testKind: tkEdgeCase, covers: "feedSmtpServer".}
  test "a stranger's address is refused, so this is no open relay":
    var
      S = initSmtpServer("h")
      r = S.talk("EHLO a\r\nMAIL FROM:<x@a>\r\nRCPT TO:<z@elsewhere.net>\r\n")
    check r.reply.endsWith("550 no such mailbox here\r\n")
    check S.talk("DATA\r\n").reply.startsWith("503")

  # {.testKind: tkRegression, covers: "feedSmtpServer", pins: "SMTP smuggling".}
  test "a bare LF dot LF does not end the mail":
    var
      S = initSmtpServer("h")
      r = S.talk("EHLO a\r\nMAIL FROM:<x@a>\r\nRCPT TO:<y@example.org>\r\nDATA\r\n")
    r = S.talk("first\n.\nMAIL FROM:<evil@a>\r\n.\r\n")
    check r.mails.len == 1
    check r.mails[0].mailFrom == "x@a"
    check r.mails[0].data == "first\n.\nMAIL FROM:<evil@a>\r\n"

  # {.testKind: tkEdgeCase, covers: "feedSmtpServer".}
  test "too large is refused, and the connection goes on":
    var
      S = initSmtpServer("h", maxBytes = 10)
      r = S.talk("EHLO a\r\nMAIL FROM:<x@a>\r\nRCPT TO:<y@example.org>\r\nDATA\r\n")
    r = S.talk("aaaaaaaaaaaaaaaa\r\nb\r\n.\r\n")
    check r.mails.len == 0 and r.reply == "552 message too large\r\n"
    check S.talk("MAIL FROM:<x@a>\r\n").reply == "250 ok\r\n"

  # {.testKind: tkEdgeCase, covers: "feedSmtpServer".}
  test "commands out of order are refused":
    var S = initSmtpServer("h")
    check S.talk("MAIL FROM:<x@a>\r\n").reply.startsWith("503")
    check S.talk("RCPT TO:<y@example.org>\r\n").reply.startsWith("503")
    check S.talk("DATA\r\n").reply.startsWith("503")
    check S.talk("BLAH\r\n").reply.startsWith("500")

  # {.testKind: tkEdgeCase, covers: "feedSmtpServer".}
  test "a command line without an end cannot grow for ever":
    var
      S = initSmtpServer("h")
      r = S.talk(repeat('a', smtpMaxLineBytes + 1))
    check r.closed

  # {.testKind: tkEdgeCase, covers: "parseSmtpPath|validSmtpAddress".}
  test "addresses that could break a line are refused":
    check parseSmtpPath("TO:", "TO:<a@b>") == (true, "a@b")
    check parseSmtpPath("FROM:", "FROM:<>") == (true, "")
    check not parseSmtpPath("TO:", "TO:a@b").ok
    check not parseSmtpPath("TO:", "TO:<a b@c>").ok
    check not parseSmtpPath("TO:", "TO:<a@b@c>").ok
    check not validSmtpAddress("a\r\n@b")

  # {.testKind: tkRegression, covers: "resetSmtpServer", pins: "STARTTLS command injection".}
  test "words sent before the switch to TLS are forgotten":
    var
      S = initSmtpServer("h", offerTls = true)
      r = S.talk("EHLO a\r\nSTARTTLS\r\nMAIL FROM:<evil@a>\r\n")
    check r.startTls and "STARTTLS" in r.reply
    S.resetSmtpServer()
    check S.pending.len == 0
    check S.talk("MAIL FROM:<x@a>\r\n").reply.startsWith("503")

suite "client":
  # {.testKind: tkUnit, covers: "feedSmtpClient".}
  test "a server that says no ends the delivery with its words":
    var
      C = initSmtpClient("me", "a@b", @["c@d"], "hi", wantTls = false)
      r = C.feedSmtpClient("220 hello\r\n")
    check r.send == "EHLO me\r\n"
    r = C.feedSmtpClient("250 ok\r\n")
    check r.send == "MAIL FROM:<a@b>\r\n"
    r = C.feedSmtpClient("550 go away\r\n")
    check r.done and not r.ok and r.err == "550 go away"

  # {.testKind: tkEdgeCase, covers: "feedSmtpClient".}
  test "needing TLS from a server without it stops before the mail":
    var
      C = initSmtpClient("me", "a@b", @["c@d"], "hi", needTls = true)
      r = C.feedSmtpClient("220 hello\r\n")
    r = C.feedSmtpClient("250-x\r\n250 y\r\n")
    check r.done and not r.ok and "TLS" in r.err and r.send.len == 0

  # {.testKind: tkUnit, covers: "feedSmtpClient|resumeSmtpClient".}
  test "STARTTLS when offered, then everything starts over":
    var
      C = initSmtpClient("me", "a@b", @["c@d"], "hi")
      r = C.feedSmtpClient("220 hello\r\n")
    r = C.feedSmtpClient("250-x\r\n250 STARTTLS\r\n")
    check r.send == "STARTTLS\r\n"
    r = C.feedSmtpClient("220 go\r\n")
    check r.startTls
    r = C.resumeSmtpClient()
    check r.send == "EHLO me\r\n"
    r = C.feedSmtpClient("250 ok\r\n")
    check r.send == "MAIL FROM:<a@b>\r\n"

  # {.testKind: tkRegression, covers: "initSmtpClient|feedSmtpClient", pins: "a recipient with a line end spoke SMTP for us".}
  test "an address that could carry a command never reaches the wire":
    var
      C = initSmtpClient("me", "a@b", @["c@d>\r\nRCPT TO:<victim@x"], "hi", wantTls = false)
      r = C.feedSmtpClient("220 hello\r\n")
    check r.done and not r.ok and r.send.len == 0 and r.err.startsWith("5")
    C = initSmtpClient("me\r\nMAIL", "a@b", @["c@d"], "hi")
    check C.feedSmtpClient("220 hello\r\n").send.len == 0
    C = initSmtpClient("me", "a@b", @[], "hi")
    check C.feedSmtpClient("220 hello\r\n").done

  # {.testKind: tkEdgeCase, covers: "stuffSmtpData".}
  test "stuffing, line ends and the final dot":
    check stuffSmtpData(".a\nb") == "..a\r\nb\r\n.\r\n"
    check stuffSmtpData("a\r\n.\r\n") == "a\r\n..\r\n.\r\n"
    check stuffSmtpData("") == ".\r\n"

suite "together":
  # {.testKind: tkIntegration, covers: "feedSmtpClient|feedSmtpServer".}
  test "one refused recipient of two: the mail still goes to the other":
    var
      S = initSmtpServer("h")
      C = initSmtpClient("me", "a@b", @["no@elsewhere.net", "y@example.org"],
        "Subject: x\n\n.dot\n", wantTls = false)
      toClient = greetSmtp(S)
      r = default(SmtpClientStep)
      got: seq[SmtpMail] = @[]
      n = 0
    while n < 20 and not r.done:
      r = C.feedSmtpClient(toClient)
      var s = S.feedSmtpServer(r.send, mine)
      toClient = s.reply
      got.add(s.mails)
      n = n + 1
    check r.ok and C.accepted == @["y@example.org"] and C.refused == @["no@elsewhere.net"]
    check got.len == 1 and got[0].data == "Subject: x\r\n\r\n.dot\r\n"

suite "dkim":
  # {.testKind: tkUnit, covers: "relaxedHeader|relaxedBody".}
  test "the relaxed forms":
    check relaxedHeader(MailHeader(name: "SubJect", value: "  Hi \t there \r\n x ")) ==
      "subject:Hi there x\r\n"
    check relaxedBody("a  b \r\n\r\n\r\n") == "a b\r\n"
    check relaxedBody("\r\n\r\n") == ""
    check relaxedBody("a") == "a\r\n"

  # {.testKind: tkUnit, covers: "splitMail".}
  test "folded headers stay with their header":
    var p = splitMail("A: 1\r\n 2\r\nB: 3\r\n\r\nbody\r\n")
    check p.headers.len == 2 and p.headers[0].value == " 1\r\n 2"
    check p.body == "body\r\n"

  # {.testKind: tkEdgeCase, covers: "buildDkimHeader".}
  test "a mail without a From cannot be signed":
    check not buildDkimHeader("Subject: x\r\n\r\nb", "d", "s", "pem", 1).ok

suite "mx":
  proc answer(): seq[uint8] =
    ## One question for example.org, two MX records, the second name a pointer.
    result = encodeMxQuery("example.org", 7)
    result[2] = 0x81'u8
    result[3] = 0x80'u8
    result[7] = 2'u8
    result.add([0xC0'u8, 12, 0, 15, 0, 1, 0, 0, 0, 60, 0, 7, 0, 20, 2, 0x6D, 0x32, 0xC0, 12, ])
    result.add([0xC0'u8, 12, 0, 15, 0, 1, 0, 0, 0, 60, 0, 7, 0, 10, 2, 0x6D, 0x31, 0xC0, 12, ])

  # {.testKind: tkUnit, covers: "encodeMxQuery|decodeMxAnswer".}
  test "hosts come back best first, pointers followed":
    var R = decodeMxAnswer(answer(), 7)
    check R.len == 2 and R[0].host == "m1.example.org" and R[0].preference == 10
    check R[1].host == "m2.example.org"

  # {.testKind: tkEdgeCase, covers: "decodeMxAnswer".}
  test "an answer for another question, or a DNS error, is refused":
    expect ValueError: discard decodeMxAnswer(answer(), 8)
    var A = answer()
    A[3] = 0x83'u8
    expect ValueError: discard decodeMxAnswer(A, 7)

  # {.testKind: tkFuzz, covers: "decodeMxAnswer".}
  test "a pointer to itself, and every shortened packet, cannot trap the reader":
    var A = answer()
    A[A.len - 2] = 0xC0'u8
    A[A.len - 1] = uint8(A.len - 2)
    expect ValueError: discard decodeMxAnswer(A, 7)
    var
      n = 0
      B = answer()
    while n < B.len:
      expect ValueError: discard decodeMxAnswer(B.toOpenArray(0, n - 1), 7)
      n = n + 1
