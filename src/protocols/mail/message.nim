## -------------------------------------------------------------------------
## Mail Message <- headers of one mail, and its DKIM signature
## -------------------------------------------------------------------------
##
## DKIM: the sending domain signs a mail, and publishes the public key in DNS.
##
##   relaxed header   lower-case name, runs of blanks become one, no trailing blank
##                    "Subject:  Hi  there " -> "subject:Hi there"
##   relaxed body     runs of blanks become one, no blanks at line ends, no
##                    empty lines at the end; a non-empty body ends in CRLF
##
##   bh= hash of the relaxed body
##   b=  signature over the relaxed signed headers, then the DKIM-Signature
##       header itself with b= empty and no line end
##
## Example 1. buildDkimHeader for domain "mine", selector "s1", headers
## From + Subject gives one header line:
##
##   DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=mine; s=s1;
##    t=<unix time>; h=from:subject; bh=<base64>; b=<base64>

import std/[base64, strutils]

import ./dkim_crypto
import runePragmas

type
  MailHeader* {.role: preparedData, tag: "mail|types".} = object
    ## One header. `value` keeps its folded lines, without the final CRLF.
    name*: string
    value*: string

proc addHeaderLine(H: var seq[MailHeader], line: string): bool {.role: parser.} =
  ## H/line: one line of the headers. False when it is not one, which ends them.
  var
    cut: int = line.find(':')
  if line[0] in {' ', '\t'} and H.len > 0:
    H[^1].value.add("\r\n" & line)
    return true
  if cut <= 0:
    return false
  H.add(MailHeader(name: line[0 ..< cut], value: line[cut + 1 .. ^1]))
  result = true

proc splitMail*(data: string): tuple[headers: seq[MailHeader], body: string] {.
    role: parser, tag: "mail|wire".} =
  ## data: a whole mail, CRLF line ends. A line starting with a blank continues
  ## the header before it. A line without a colon ends the headers.
  var
    i: int = 0
    e: int = 0
    line: string = ""
  while i < data.len:
    e = data.find("\r\n", i)
    if e < 0:
      e = data.len
    line = data[i ..< e]
    if line.len == 0:
      i = min(data.len, e + 2)
      break
    if not addHeaderLine(result.headers, line):
      break
    i = e + 2
  if i < data.len:
    result.body = data[i .. ^1]

proc squeezeBlanks(s: string): string {.role: sanitizer, inline.} =
  ## s: every run of spaces and tabs becomes one space.
  var
    inRun: bool = false
  for c in s:
    if c notin {' ', '\t'}:
      result.add(c)
      inRun = false
      continue
    if not inRun: result.add(' ')
    inRun = true

proc relaxedHeader*(H: MailHeader): string {.role: sanitizer, tag: "mail".} =
  ## H: one header, relaxed, with CRLF.
  result = H.name.strip().toLowerAscii() & ":" &
    squeezeBlanks(H.value.replace("\r\n", "")).strip() & "\r\n"

proc relaxedBody*(body: string): string {.role: sanitizer, tag: "mail".} =
  ## body: the text after the headers, relaxed.
  var
    lines: seq[string] = body.split("\r\n")
    i: int = 0
  while i < lines.len:
    lines[i] = squeezeBlanks(lines[i]).strip(leading = false)
    i = i + 1
  while lines.len > 0 and lines[^1].len == 0:
    discard lines.pop()
  if lines.len > 0:
    result = lines.join("\r\n") & "\r\n"

proc pickHeader(H: seq[MailHeader], name: string): int {.role: parser.} =
  ## H/name: the last header of this name, or -1 (DKIM signs from the bottom).
  var
    i: int = H.len - 1
  result = -1
  while i >= 0:
    if cmpIgnoreCase(H[i].name.strip(), name) == 0:
      return i
    i = i - 1

proc signingInput(H: seq[MailHeader], names: openArray[string], dkimValue: string): string {.
    role: truthBuilder.} =
  ## H/names/dkimValue: what is signed, the DKIM header last and without CRLF.
  var
    at: int = 0
  for n in names:
    at = pickHeader(H, n)
    if at >= 0:
      result.add(relaxedHeader(H[at]))
  result.add(relaxedHeader(MailHeader(name: "DKIM-Signature",
    value: dkimValue)).strip(leading = false, chars = {'\r', '\n'}))

proc buildDkimHeader*(data, domain, selector, privateKeyPem: string,
    unixTime: int64, names: openArray[string] = ["From", "To", "Subject", "Date",
    "Message-ID"]): tuple[ok: bool, header, err: string] {.role: truthBuilder,
    tag: "mail|appApi|cryptoBoundary".} =
  ## data: the mail. domain/selector: where the public key is published.
  ## privateKeyPem/unixTime: the signing key and the clock. names: which headers
  ## to sign, those that exist. Returns the header line, ending in CRLF.
  var
    parts: tuple[headers: seq[MailHeader], body: string] = splitMail(data)
    bh: string = encode(dkimSha256(relaxedBody(parts.body)))
    present: seq[string] = @[]
    v: string = ""
    signed: DkimSignResult = DkimSignResult()
  for n in names:
    if pickHeader(parts.headers, n) >= 0:
      present.add(n.toLowerAscii())
  if "from" notin present:
    return (false, "", "a mail without a From header cannot be signed")
  v = " v=1; a=rsa-sha256; c=relaxed/relaxed; d=" & domain & "; s=" & selector &
    "; t=" & $unixTime & "; h=" & present.join(":") & "; bh=" & bh & "; b="
  signed = dkimSignRsaSha256(signingInput(parts.headers, present, v), privateKeyPem)
  if not signed.ok:
    return (false, "", signed.err)
  result = (true, "DKIM-Signature:" & v & encode(signed.signature) & "\r\n", "")
