## SMTP server <- the message text is collected in blocks, and comes out exactly as sent

import std/[unittest, strutils]
import protocols/smtp
import runePragmas

proc mineAll(a: string): bool {.gcsafe, role: parser.} =
  result = true

proc conversation(body: string, maxBytes: int): tuple[mails: seq[SmtpMail], reply: string] {.
    role: orchestrator.} =
  ## one whole conversation, the body sent in 16 KB reads (like the daemon)
  var
    S: SmtpServer = initSmtpServer("mine.example", maxBytes)
    step: SmtpServerStep = SmtpServerStep()
    text: string = "EHLO a.example\r\nMAIL FROM:<a@b.example>\r\nRCPT TO:<me@mine.example>\r\nDATA\r\n" &
      body & ".\r\nQUIT\r\n"
    at: int = 0
  while at < text.len:
    step = feedSmtpServer(S, text[at ..< min(text.len, at + 16384)], mineAll)
    result.mails.add(step.mails)
    result.reply.add(step.reply)
    at = at + 16384

suite "message text in blocks":
  # {.testKind: tkRegression, covers: "feedSmtpServer",
  #   pins: "one growing string cost about 6 times the mail while it arrived".}
  test "a 6 MB mail with long, short, empty and dot-led lines arrives byte for byte":
    var
      body: string = ""
      want: string = ""
      r: tuple[mails: seq[SmtpMail], reply: string] = (@[], "")
    for i in 0 ..< 6000:
      body.add(repeat(char(ord('a') + i mod 26), 998) & "\r\n")
      want.add(repeat(char(ord('a') + i mod 26), 998) & "\r\n")
    body.add("\r\n..led line\r\nlast\r\n")
    want.add("\r\n.led line\r\nlast\r\n")
    r = conversation(body, 8 * 1024 * 1024)
    check r.mails.len == 1
    check r.mails[0].data == want
    check "250 kept" in r.reply

  # {.testKind: tkEdgeCase, covers: "feedSmtpServer".}
  test "a line longer than one block, and a mail of exactly one block":
    var
      big: string = repeat('x', 70_000) & "\r\n"
      r: tuple[mails: seq[SmtpMail], reply: string] = conversation(big, 1024 * 1024)
    check r.mails.len == 1 and r.mails[0].data == big
    r = conversation(repeat('y', 65534) & "\r\n", 1024 * 1024)
    check r.mails.len == 1 and r.mails[0].data.len == 65536

  # {.testKind: tkEdgeCase, covers: "feedSmtpServer".}
  test "a mail past the limit is refused with 552 and nothing is kept; the next mail works":
    var
      r: tuple[mails: seq[SmtpMail], reply: string] = conversation(
        repeat(repeat('z', 998) & "\r\n", 3000), 1024 * 1024)
    check r.mails.len == 0
    check "552" in r.reply
