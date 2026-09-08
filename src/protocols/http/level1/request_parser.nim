## ------------------------------------------------------------------
## HTTP Request Parser <- incremental, fail-closed HTTP/1.1 request reader
## ------------------------------------------------------------------
##
## Feed it whatever bytes arrive. It keeps its place between calls and
## reports when one complete request is ready:
##
##   feed(P, bytes) -> (ok, consumed, complete)
##       complete = false, ok = true   -> need more bytes, call again
##       complete = true               -> P.request is filled in
##       ok = false                    -> P.err says what broke
##
## Two messages can share one TCP read, so `consumed` tells the caller
## how many bytes this request used; the rest belong to the next one.
##
## ## Why it is strict
##
## Every rule below exists because a disagreement about where a message
## ends lets one request be read as two. The classic form:
##
##   POST / HTTP/1.1
##   Content-Length: 6
##   Transfer-Encoding: chunked      <- two answers to "how long is it?"
##
## A reader trusting Content-Length sees a 6-byte body. One trusting
## chunked sees a different body, and treats the leftovers as a whole new
## request that never came from the client. We refuse the message rather
## than pick a winner, and we close the connection afterwards, because
## once the stream is ambiguous no later boundary can be trusted either.

import std/strutils
import ../types
import ../level0/[header_ops, target_ops]
import ./chunked_ops
import bifrostPragmas

const
  httpDefaultMaxBodyBytes*: int64 = 8'i64 * 1024 * 1024
    ## Default ceiling for a single request body (8 MiB).

type
  HttpRequestParser* {.role: memory,
      metaTags: {tagProtocol, tagParsing, tagNetworkSurface}.} = object
    state*: HttpParseState
    request*: HttpRequest
    err*: HttpParseError
    errMsg*: string
    head: string
      ## Head bytes accumulated until the blank-line terminator.
    bodyMode: HttpBodyMode
    contentLength: int64
    bodyRead: int64
    chunked: ChunkedDecoder
    maxBodyBytes: int64

  HttpFeedResult* {.role: truthState, metaTags: {tagProtocol, tagParsing}.} = object
    ok*: bool
    consumed*: int
    complete*: bool
    err*: HttpParseError
    errMsg*: string

proc initHttpRequestParser*(maxBodyBytes: int64 = httpDefaultMaxBodyBytes):
    HttpRequestParser {.role: truthBuilder, metaTags: {tagProtocol, tagParsing}.} =
  ## maxBodyBytes: largest request body accepted before a 413.
  result.state = hpsRequestLine
  result.err = hpeNone
  result.errMsg = ""
  result.head = ""
  result.bodyMode = hbmNone
  result.contentLength = 0
  result.bodyRead = 0
  result.chunked = initChunkedDecoder()
  result.maxBodyBytes = maxBodyBytes
  result.request = HttpRequest(version: hv11, keepAlive: true)

proc failParse(P: var HttpRequestParser; e: HttpParseError;
    m: string): HttpFeedResult {.role: actor,
    metaTags: {tagProtocol, tagValidation}.} =
  ## P/e/m: parser to move into the error state, reason code, message.
  P.state = hpsError
  P.err = e
  P.errMsg = m
  result = HttpFeedResult(ok: false, consumed: 0, complete: false,
    err: e, errMsg: m)

proc parseContentLengthValue(v: string): tuple[ok: bool, n: int64] {.
    role: parser, metaTags: {tagProtocol, tagValidation}.} =
  ## v: raw `Content-Length` value to read as a plain decimal count.
  ##
  ## No sign, no whitespace, no hex, at least one digit. `+0` and ` 5`
  ## are the shapes that get read differently by different stacks.
  var
    i: int = 0
    n: int64 = 0
  if v.len == 0 or v.len > 19:
    return (false, 0'i64)
  while i < v.len:
    if v[i] < '0' or v[i] > '9':
      return (false, 0'i64)
    n = n * 10 + int64(ord(v[i]) - ord('0'))
    if n < 0:
      return (false, 0'i64)
    i = i + 1
  result = (true, n)

proc splitHeadLines(head: string): seq[string] {.role: parser,
    metaTags: {tagProtocol, tagParsing}.} =
  ## head: head block without its trailing blank line.
  ##
  ## Splits on CRLF only. A bare LF is left inside the line, where the
  ## field-value validator will reject it, rather than silently becoming
  ## a line break that only we can see.
  var
    i: int = 0
    start: int = 0
  result = @[]
  while i + 1 < head.len:
    if head[i] == '\r' and head[i + 1] == '\n':
      result.add(head[start ..< i])
      i = i + 2
      start = i
    else:
      i = i + 1
  if start < head.len:
    result.add(head[start .. ^1])

proc parseRequestLine(P: var HttpRequestParser; l: string): HttpParseError {.
    role: parser, metaTags: {tagProtocol, tagParsing, tagValidation}.} =
  ## P/l: parser to fill and the first line of the request.
  var
    sp1: int = 0
    sp2: int = 0
    verb: string = ""
    target: string = ""
    ver: string = ""
    parsed: tuple[ok: bool, path: string, query: string,
      params: seq[HttpQueryParam]]
  if l.len > httpMaxRequestLineLen:
    return hpeRequestLineTooLong
  sp1 = l.find(' ')
  if sp1 <= 0:
    return hpeMalformedRequestLine
  sp2 = l.find(' ', sp1 + 1)
  if sp2 <= sp1 + 1:
    return hpeMalformedRequestLine
  verb = l[0 ..< sp1]
  target = l[sp1 + 1 ..< sp2]
  ver = l[sp2 + 1 .. ^1]
  if not isValidHeaderName(verb):
    return hpeMalformedRequestLine
  if ver.find(' ') >= 0:
    return hpeMalformedRequestLine
  P.request.rawMethod = verb
  P.request.verb = httpMethodFromString(verb)
  P.request.version = httpVersionFromString(ver)
  if P.request.version == hvUnknown:
    return hpeUnsupportedVersion
  P.request.target = target
  parsed = parseHttpTarget(target)
  if not parsed.ok:
    return hpeInvalidTarget
  P.request.path = parsed.path
  P.request.query = parsed.query
  P.request.params = parsed.params
  result = hpeNone

proc parseHeaderLines(P: var HttpRequestParser;
    L: seq[string]): HttpParseError {.role: parser,
    metaTags: {tagProtocol, tagParsing, tagValidation}.} =
  ## P/L: parser to fill and the header lines after the request line.
  var
    i: int = 1
    colon: int = 0
    n: string = ""
    v: string = ""
  if L.len - 1 > httpMaxHeaderCount:
    return hpeTooManyHeaders
  while i < L.len:
    if L[i].len == 0:
      return hpeMalformedHeader
    if L[i][0] == ' ' or L[i][0] == '\t':
      # Obsolete line folding. RFC 9112 tells servers to reject it, and
      # it is a reliable way to smuggle a value past a simple filter.
      return hpeMalformedHeader
    colon = L[i].find(':')
    if colon <= 0:
      return hpeMalformedHeader
    n = L[i][0 ..< colon]
    v = trimFieldValue(L[i][colon + 1 .. ^1])
    if not isValidHeaderName(n):
      # Catches a space before the colon, which some stacks accept and
      # others do not.
      return hpeMalformedHeader
    if not isValidHeaderValue(v):
      return hpeMalformedHeader
    P.request.headers.add(HttpHeader(name: n, value: v))
    i = i + 1
  result = hpeNone

proc resolveBodyFraming(P: var HttpRequestParser): HttpParseError {.
    role: truthBuilder, metaTags: {tagProtocol, tagValidation}.} =
  ## P: parser whose headers are loaded and whose body mode is unknown.
  ##
  ## Decides, once and unambiguously, how long the body is.
  var
    hasCl: int = 0
    hasTe: int = 0
    te: string = ""
    cl: tuple[ok: bool, n: int64]
  hasCl = countHeader(P.request.headers, "content-length")
  hasTe = countHeader(P.request.headers, "transfer-encoding")
  if hasCl > 1:
    return hpeDuplicateContentLength
  if hasTe > 1:
    return hpeConflictingFraming
  if hasCl == 1 and hasTe == 1:
    return hpeConflictingFraming
  if hasTe == 1:
    te = getHeader(P.request.headers, "transfer-encoding")
    # Only bare `chunked` is served. `gzip, chunked` and any encoding we
    # do not implement would leave the body framed in a way we cannot
    # verify, so it is refused rather than guessed at.
    if not httpNamesEqual(trimFieldValue(te), "chunked"):
      return hpeConflictingFraming
    P.bodyMode = hbmChunked
    return hpeNone
  if hasCl == 1:
    cl = parseContentLengthValue(getHeader(P.request.headers, "content-length"))
    if not cl.ok:
      return hpeInvalidContentLength
    if cl.n > P.maxBodyBytes:
      return hpeBodyTooLarge
    if cl.n == 0:
      P.bodyMode = hbmNone
      return hpeNone
    if not httpMethodAllowsBody(P.request.verb):
      # A body on a verb that should not have one is exactly how a
      # smuggled second request is hidden.
      return hpeConflictingFraming
    P.contentLength = cl.n
    P.bodyMode = hbmContentLength
    return hpeNone
  P.bodyMode = hbmNone
  result = hpeNone

proc resolveConnectionPolicy(P: var HttpRequestParser) {.role: truthBuilder,
    metaTags: {tagProtocol, tagValidation}.} =
  ## P: parser whose headers are loaded.
  ##
  ## HTTP/1.1 keeps the connection open unless told otherwise; HTTP/1.0
  ## closes it unless `Connection: keep-alive` says otherwise.
  var
    upgrade: string = ""
  if P.request.version == hv11:
    P.request.keepAlive = not headerHasToken(P.request.headers,
      "connection", "close")
  else:
    P.request.keepAlive = headerHasToken(P.request.headers,
      "connection", "keep-alive")
  P.request.expectContinue = httpNamesEqual(
    getHeader(P.request.headers, "expect"), "100-continue")
  upgrade = getHeader(P.request.headers, "upgrade")
  if upgrade.len > 0 and headerHasToken(P.request.headers, "connection",
      "upgrade"):
    P.request.isUpgrade = true
    P.request.upgradeProtocol = trimFieldValue(upgrade)

proc validateHost(P: var HttpRequestParser): HttpParseError {.role: sanitizer,
    metaTags: {tagProtocol, tagValidation}.} =
  ## P: parser whose headers are loaded.
  ##
  ## HTTP/1.1 requires exactly one Host. Zero makes virtual hosting
  ## ambiguous; two lets a client aim different parts of the stack at
  ## different sites.
  var
    n: int = 0
    h: string = ""
    i: int = 0
    c: char = '\0'
  n = countHeader(P.request.headers, "host")
  if n > 1:
    return hpeInvalidHost
  if n == 0:
    if P.request.version == hv11:
      return hpeMissingHost
    return hpeNone
  h = getHeader(P.request.headers, "host")
  if h.len == 0 or h.len > 255:
    return hpeInvalidHost
  while i < h.len:
    c = h[i]
    if c == ' ' or c == '\t' or c == '/' or c == '?' or c == '#' or c == '@':
      return hpeInvalidHost
    i = i + 1
  result = hpeNone

proc parseHead(P: var HttpRequestParser): HttpParseError {.
    role: orchestrator, metaTags: {tagProtocol, tagParsing, tagValidation}.} =
  ## P: parser holding a complete head block in `P.head`.
  var
    L: seq[string] = @[]
    e: HttpParseError = hpeNone
  L = splitHeadLines(P.head)
  if L.len == 0:
    return hpeMalformedRequestLine
  e = parseRequestLine(P, L[0])
  if e != hpeNone:
    return e
  e = parseHeaderLines(P, L)
  if e != hpeNone:
    return e
  e = validateHost(P)
  if e != hpeNone:
    return e
  e = resolveBodyFraming(P)
  if e != hpeNone:
    return e
  resolveConnectionPolicy(P)
  result = hpeNone

proc feedHead(P: var HttpRequestParser; A: openArray[byte];
    i: var int): HttpFeedResult {.role: orchestrator,
    metaTags: {tagProtocol, tagParsing}.} =
  ## P/A/i: parser, input bytes, and read cursor advanced in place.
  ##
  ## Accumulates until the blank line that ends the head, then parses it.
  var
    marker: int = -1
    e: HttpParseError = hpeNone
    room: int = 0
    take: int = 0
    scanFrom: int = 0
    k: int = 0
  result.ok = true
  room = httpMaxHeaderBlockLen - P.head.len
  take = A.len - i
  if take > room:
    take = room
  # Only the last three bytes of what we already held can start a
  # terminator that completes inside the new bytes, so the scan never
  # re-reads the whole head on every feed.
  scanFrom = P.head.len - 3
  if scanFrom < 0:
    scanFrom = 0
  if take > 0:
    k = 0
    while k < take:
      P.head.add(char(A[i + k]))
      k = k + 1
    i = i + take
  marker = P.head.find("\r\n\r\n", scanFrom)
  if marker < 0:
    if P.head.len >= httpMaxHeaderBlockLen:
      return failParse(P, hpeHeaderTooLarge, "request head exceeds limit")
    return result
  # Anything past the terminator is body, and must be handed back so the
  # body reader sees it. Rewind the cursor by that amount.
  i = i - (P.head.len - (marker + 4))
  P.head.setLen(marker)
  e = parseHead(P)
  if e != hpeNone:
    return failParse(P, e, "invalid request head")
  P.state = hpsBody
  if P.bodyMode == hbmNone:
    P.state = hpsComplete
  result.ok = true

proc feedBody(P: var HttpRequestParser; A: openArray[byte];
    i: var int): HttpFeedResult {.role: orchestrator,
    metaTags: {tagProtocol, tagParsing}.} =
  ## P/A/i: parser, input bytes, and read cursor advanced in place.
  var
    take: int = 0
    ch: ChunkedFeedResult
  result.ok = true
  case P.bodyMode
  of hbmContentLength:
    take = A.len - i
    if int64(take) > P.contentLength - P.bodyRead:
      take = int(P.contentLength - P.bodyRead)
    if take > 0:
      P.request.body.add(A[i ..< i + take])
      i = i + take
      P.bodyRead = P.bodyRead + int64(take)
    if P.bodyRead >= P.contentLength:
      P.state = hpsComplete
  of hbmChunked:
    ch = feedChunked(P.chunked, A.toOpenArray(i, A.len - 1), P.maxBodyBytes)
    i = i + ch.consumed
    if not ch.ok:
      return failParse(P, hpeInvalidChunk, ch.err)
    if ch.data.len > 0:
      P.request.body.add(ch.data)
      if int64(P.request.body.len) > P.maxBodyBytes:
        return failParse(P, hpeBodyTooLarge, "request body exceeds limit")
    if ch.done:
      P.state = hpsComplete
  else:
    P.state = hpsComplete

proc feedHttpRequest*(P: var HttpRequestParser;
    A: openArray[byte]): HttpFeedResult {.role: metaOrchestrator,
    metaTags: {tagProtocol, tagParsing, tagNetworkSurface}.} =
  ## P/A: parser state and the next bytes read from the transport.
  ##
  ## Returns how many bytes were used and whether a whole request is
  ## ready. Bytes left over belong to the next request on the connection.
  var
    i: int = 0
    step: HttpFeedResult
  if P.state == hpsError:
    return HttpFeedResult(ok: false, consumed: 0, complete: false,
      err: P.err, errMsg: P.errMsg)
  if P.state == hpsComplete:
    return HttpFeedResult(ok: true, consumed: 0, complete: true,
      err: hpeNone, errMsg: "")
  while i < A.len and P.state notin {hpsComplete, hpsError}:
    if P.state in {hpsRequestLine, hpsHeaders}:
      step = feedHead(P, A, i)
    else:
      step = feedBody(P, A, i)
    if not step.ok:
      step.consumed = i
      return step
  # An empty-bodied request can finish without the loop running at all.
  if P.state == hpsBody and P.bodyMode == hbmNone:
    P.state = hpsComplete
  result = HttpFeedResult(
    ok: true,
    consumed: i,
    complete: P.state == hpsComplete,
    err: hpeNone,
    errMsg: ""
  )

proc httpParserHasPartialHead*(P: HttpRequestParser): bool {.role: parser,
    metaTags: {tagProtocol, tagRead}.} =
  ## P: parser to ask whether a half-received head is buffered.
  ##
  ## True when head bytes have arrived but the blank-line terminator has
  ## not. A client sitting in this state indefinitely is trickling a
  ## request head, which is what a head deadline exists to cut off.
  P.head.len > 0 and P.state in {hpsRequestLine, hpsHeaders}

proc resetHttpRequestParser*(P: var HttpRequestParser) {.role: actor,
    metaTags: {tagProtocol, tagParsing}.} =
  ## P: parser to return to a clean state for the next keep-alive request.
  ##
  ## The body cap is carried over; everything else starts empty so no
  ## header from the previous message can leak into the next one.
  var
    cap: int64 = P.maxBodyBytes
  P = initHttpRequestParser(cap)
