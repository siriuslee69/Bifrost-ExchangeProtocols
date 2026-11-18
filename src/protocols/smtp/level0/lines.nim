## -------------------------------------------------------------------------
## SMTP Lines <- one command, one reply, one address, one dot
## -------------------------------------------------------------------------
##
##   parseSmtpCommand("MAIL FROM:<a@b> SIZE=9")  -> verb "MAIL", arg "FROM:<a@b> SIZE=9"
##   parseSmtpPath("FROM:", "FROM:<a@b> SIZE=9") -> "a@b"
##   parseSmtpReply("250-PIPELINING")            -> code 250, more lines follow
##
## Def. 1 (stuffing): a text line that starts with a dot gets one more dot on
##   the wire, because a line holding only a dot ends the message.
##
##   text ".hello"  wire "..hello"
##   text "."       wire ".."

import std/strutils

import runePragmas

proc parseSmtpCommand*(line: string): tuple[verb, arg: string] {.role: parser,
    tag: "smtp|wire".} =
  ## line: one command without its line end.
  var
    cut: int = line.find(' ')
  if cut < 0:
    return (line.toUpperAscii(), "")
  result = (line[0 ..< cut].toUpperAscii(), line[cut + 1 .. ^1].strip())

proc validSmtpAddress*(s: string): bool {.role: sanitizer, tag: "smtp".} =
  ## s: an address without its brackets. One @, both sides filled, no blanks or
  ## control characters, nothing that could end a line or a command.
  var
    cut: int = s.find('@')
  if cut <= 0 or cut != s.rfind('@') or cut == s.len - 1 or s.len > 320:
    return false
  for c in s:
    if c <= ' ' or c == '\x7f' or c in {'<', '>', ',', ';', ':', '\\', '"'}:
      return false
  result = true

proc parseSmtpPath*(prefix, arg: string): tuple[ok: bool, address: string] {.
    role: parser, tag: "smtp|wire".} =
  ## prefix: "FROM:" or "TO:". arg: what followed the verb. An empty path <> is
  ## ok (the null sender) and gives address "".
  var
    open: int = 0
    close: int = 0
    inner: string = ""
  if not arg.toUpperAscii().startsWith(prefix):
    return
  open = arg.find('<')
  close = arg.find('>')
  if open != prefix.len or close < open:
    return
  inner = arg[open + 1 ..< close]
  if inner.len == 0:
    return (true, "")
  if not validSmtpAddress(inner):
    return
  result = (true, inner)

proc smtpMailSize*(a: string, m: int): tuple[ok, tooLarge: bool] {.
    role: parser, tag: "smtp|wire".} =
  ## a: MAIL argument with an already parsed path. m: maximum message bytes.
  var
    limit: string = $m
    value: string = ""
    size: string = ""
  for p in a[a.find('>') + 1 .. ^1].splitWhitespace():
    if not p.toUpperAscii().startsWith("SIZE="):
      continue
    value = p[5 .. ^1]
    if size.len > 0 or value.len notin 1 .. 20 or not value.allCharsInSet(Digits):
      return
    size = value.strip(leading = true, trailing = false, chars = {'0'})
    if size.len == 0:
      size = "0"
  result = (true, size.len > limit.len or (size.len == limit.len and size > limit))

proc parseSmtpReply*(line: string): tuple[ok: bool, code: int, more: bool,
    text: string] {.role: parser, tag: "smtp|wire".} =
  ## line: one reply line. `more` is true for "250-..." (another line follows).
  var
    code: int = 0
  if line.len < 3 or line[0] notin Digits or line[1] notin Digits or
      line[2] notin Digits:
    return
  code = (ord(line[0]) - 48) * 100 + (ord(line[1]) - 48) * 10 + ord(line[2]) - 48
  result = (true, code, line.len > 3 and line[3] == '-',
    if line.len > 4: line[4 .. ^1] else: "")

proc stuffSmtpData*(text: string): string {.role: sanitizer, tag: "smtp|wire".} =
  ## text: a whole message. Returns it with bare line ends made CRLF, Def. 1
  ## applied, and the final CRLF.CRLF, ready to send after DATA.
  var
    i: int = 0
    atStart: bool = true
  result = newStringOfCap(text.len + 16)
  while i < text.len:
    if atStart and text[i] == '.':
      result.add('.')
    atStart = false
    if text[i] == '\r' and i + 1 < text.len and text[i + 1] == '\n':
      result.add("\r\n")
      i = i + 2
      atStart = true
      continue
    if text[i] == '\n' or text[i] == '\r':
      result.add("\r\n")
      i = i + 1
      atStart = true
      continue
    result.add(text[i])
    i = i + 1
  if not atStart:
    result.add("\r\n")
  result.add(".\r\n")
