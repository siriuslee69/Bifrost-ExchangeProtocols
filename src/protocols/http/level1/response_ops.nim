## ------------------------------------------------------------------
## HTTP Response Ops <- status phrases and response head serialisation
## ------------------------------------------------------------------
##
## A response on the wire is a status line, headers, a blank line, then
## the body:
##
##   HTTP/1.1 200 OK\r\n
##   Content-Type: text/html\r\n
##   Content-Length: 12\r\n
##   \r\n
##   hello world\n
##
## `encodeResponseHead` builds everything above the body. The body is
## sent separately so a large file never has to sit in memory next to a
## second copy of itself.
##
## Framing is decided here and nowhere else: exactly one of
## `Content-Length` or `Transfer-Encoding: chunked` is emitted, never
## both, and never neither.

import std/times
import ../../types
import ../types
import ../level0/header_ops
import runePragmas

proc httpReasonPhrase*(s: int): string {.role: parser,
    tag: "protocol|formatting".} =
  ## s: status code to name.
  case s
  of 100: "Continue"
  of 101: "Switching Protocols"
  of 200: "OK"
  of 201: "Created"
  of 202: "Accepted"
  of 204: "No Content"
  of 206: "Partial Content"
  of 301: "Moved Permanently"
  of 302: "Found"
  of 303: "See Other"
  of 304: "Not Modified"
  of 307: "Temporary Redirect"
  of 308: "Permanent Redirect"
  of 400: "Bad Request"
  of 401: "Unauthorized"
  of 403: "Forbidden"
  of 404: "Not Found"
  of 405: "Method Not Allowed"
  of 406: "Not Acceptable"
  of 408: "Request Timeout"
  of 409: "Conflict"
  of 410: "Gone"
  of 411: "Length Required"
  of 412: "Precondition Failed"
  of 413: "Content Too Large"
  of 414: "URI Too Long"
  of 415: "Unsupported Media Type"
  of 416: "Range Not Satisfiable"
  of 421: "Misdirected Request"
  of 426: "Upgrade Required"
  of 429: "Too Many Requests"
  of 431: "Request Header Fields Too Large"
  of 500: "Internal Server Error"
  of 501: "Not Implemented"
  of 502: "Bad Gateway"
  of 503: "Service Unavailable"
  of 504: "Gateway Timeout"
  of 505: "HTTP Version Not Supported"
  else: "Unknown"

proc httpStatusAllowsBody*(s: int): bool {.role: parser,
    tag: "protocol|validation".} =
  ## s: status code to test.
  ##
  ## 1xx, 204, and 304 must not carry a body. Sending one anyway makes
  ## the client read into the next response and desynchronises the
  ## connection, so the writer suppresses it.
  if s >= 100 and s < 200:
    return false
  if s == 204 or s == 304:
    return false
  result = true

proc httpDateNow*(): string {.role: dataFetcher,
    tag: "protocol|formatting".} =
  ## Current time as an RFC 7231 IMF-fixdate in GMT.
  ##
  ##   Sun, 27 Jul 2026 21:51:03 GMT
  result = utc(now()).format("ddd, dd MMM yyyy HH:mm:ss") & " GMT"

proc httpDateFromTime*(t: Time): string {.role: parser,
    tag: "protocol|formatting".} =
  ## t: instant to render as an IMF-fixdate in GMT.
  result = utc(t).format("ddd, dd MMM yyyy HH:mm:ss") & " GMT"

proc appendStatusLine(B: var ByteSeq; v: HttpVersion; s: int;
    reason: string) {.role: dataWriter, tag: "protocol|write".} =
  ## B/v/s/reason: output buffer, version, status code, reason phrase.
  var
    t: string = ""
  t = (if v == hv10: "HTTP/1.0" else: "HTTP/1.1")
  t.add(' ')
  t.add($s)
  t.add(' ')
  t.add(if reason.len > 0: reason else: httpReasonPhrase(s))
  t.add("\r\n")
  B.add(toHttpBytes(t))

proc appendHeaderLine(B: var ByteSeq; n: string; v: string) {.
    role: dataWriter, tag: "protocol|write".} =
  ## B/n/v: output buffer, field name, field value.
  ##
  ## Silently drops a field that would inject a line break. A caller that
  ## builds a header from user input cannot turn it into two headers.
  var
    t: string = ""
  if not isValidHeaderName(n) or not isValidHeaderValue(v):
    return
  t = n
  t.add(": ")
  t.add(v)
  t.add("\r\n")
  B.add(toHttpBytes(t))

proc encodeResponseHead*(R: HttpResponse; v: HttpVersion; keepAlive: bool;
    bodyLen: int64; chunked: bool; headOnly: bool): ByteSeq {.
    role: dataWriter, tag: "protocol|write|networkSurface".} =
  ## R/v/keepAlive/bodyLen/chunked/headOnly: response, negotiated
  ## version, whether the connection survives, body size when known,
  ## whether chunked framing is used, and whether this answers a HEAD.
  ##
  ## Framing headers are written here rather than trusted from `R`, so a
  ## handler cannot set a `Content-Length` that disagrees with what is
  ## actually sent.
  var
    i: int = 0
    n: string = ""
  result = @[]
  appendStatusLine(result, v, R.status, R.reason)
  while i < R.headers.len:
    n = R.headers[i].name
    if not httpNamesEqual(n, "content-length") and
        not httpNamesEqual(n, "transfer-encoding") and
        not httpNamesEqual(n, "connection"):
      appendHeaderLine(result, n, R.headers[i].value)
    i = i + 1
  if not hasHeader(R.headers, "date"):
    appendHeaderLine(result, "Date", httpDateNow())
  if httpStatusAllowsBody(R.status):
    if chunked:
      appendHeaderLine(result, "Transfer-Encoding", "chunked")
    else:
      appendHeaderLine(result, "Content-Length", $bodyLen)
  elif headOnly and bodyLen > 0:
    # A HEAD reply keeps the Content-Length it would have had, but sends
    # no bytes after the blank line.
    appendHeaderLine(result, "Content-Length", $bodyLen)
  appendHeaderLine(result, "Connection",
    if keepAlive: "keep-alive" else: "close")
  result.add(toHttpBytes("\r\n"))

proc newHttpResponse*(status: int; body: ByteSeq = @[];
    contentType: string = ""): HttpResponse {.role: truthBuilder,
    tag: "protocol|write".} =
  ## status/body/contentType: status code, body bytes, media type.
  result.status = status
  result.body = body
  result.headers = @[]
  if contentType.len > 0:
    result.headers.add(HttpHeader(name: "Content-Type", value: contentType))

proc textResponse*(status: int; s: string;
    contentType: string = "text/plain; charset=utf-8"): HttpResponse {.
    role: truthBuilder, tag: "protocol|write".} =
  ## status/s/contentType: status code, text body, media type.
  result = newHttpResponse(status, toHttpBytes(s), contentType)

proc errorResponse*(status: int; detail: string = ""): HttpResponse {.
    role: truthBuilder, tag: "protocol|write".} =
  ## status/detail: status code and an optional short explanation.
  ##
  ## Produces a small plain-text page. `detail` is echoed only when the
  ## caller supplies it, so parser internals never reach the client by
  ## accident.
  var
    t: string = ""
  t = $status & " " & httpReasonPhrase(status) & "\n"
  if detail.len > 0:
    t.add(detail)
    t.add('\n')
  result = textResponse(status, t)
  result.closeAfter = status >= 400 and status != 404 and status != 405
