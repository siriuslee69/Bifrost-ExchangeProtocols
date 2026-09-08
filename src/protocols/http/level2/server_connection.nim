## ------------------------------------------------------------------
## HTTP Server Connection <- sans-io keep-alive connection state machine
## ------------------------------------------------------------------
##
## This module owns the lifetime of one client connection, without ever
## touching a socket. The caller does all the reading and writing:
##
##   bytes from socket  ->  feedHttpConnection  ->  events
##   events             ->  caller builds an HttpResponse
##   HttpResponse       ->  respondHttpConnection  ->  bytes to socket
##
## Keeping it sans-io means the same state machine drives a plain TCP
## socket and a TLS session with no changes, and the whole thing can be
## tested by feeding it strings.
##
## ## Why every request is re-parsed
##
## On a keep-alive connection several requests share one TCP stream:
##
##   +-------- one TCP connection --------------------------+
##   | GET /a  Host: x | GET /b  Host: y | GET /c  Host: z   |
##   +------------------------------------------------------+
##        ^                 ^                  ^
##        parsed            parsed             parsed
##
## Each one gets a fresh parser, so routing, host checks, and header
## policy are applied to all of them and not just the first. Carrying a
## decision from request 1 into request 2 is how a shared-port server
## ends up serving site `x` to a request that asked for site `y`.

import ../../types
import ../types
import ../level1/[request_parser, response_ops, chunked_ops]
import ../../../analysis_pragmas

type
  HttpConnectionState* = enum
    ## Where the connection currently is.
    hcsReading,      ## accumulating a request
    hcsDispatched,   ## request handed to the caller, awaiting a response
    hcsUpgraded,     ## left HTTP; caller owns the raw byte stream now
    hcsClosing,      ## response flushed, connection must shut down
    hcsClosed

  HttpEventKind* = enum
    ## What the caller must react to after a feed.
    hekNone,          ## nothing yet, read more bytes
    hekRequest,       ## a full request is ready in `request`
    hekContinue,      ## client wants a `100 Continue` interim reply
    hekError,         ## malformed input; `response` holds what to send
    hekUpgrade        ## request asked to switch protocols

  HttpEvent* {.role: truthState, metaTags: {tagProtocol, tagNetworkSurface}.} =
      object
    kind*: HttpEventKind
    request*: HttpRequest
    response*: HttpResponse
      ## Pre-built reply for `hekError` and `hekContinue`.

  HttpServerLimits* {.role: configurator, metaTags: {tagProtocol}.} = object
    maxBodyBytes*: int64
      ## Largest single request body.
    maxRequestsPerConnection*: int
      ## Requests served before the connection is retired. `0` means no
      ## limit. A finite value keeps one client from pinning a worker
      ## slot forever.

  HttpServerConnection* {.role: memory,
      metaTags: {tagProtocol, tagNetworkSurface}.} = ref object
    ## A reference type on purpose: an async server holds one of these
    ## across every suspension point, and a `var` parameter cannot cross
    ## an `await`.
    state*: HttpConnectionState
    parser: HttpRequestParser
    limits: HttpServerLimits
    served*: int
      ## Requests completed on this connection so far.
    keepAlive*: bool
    version*: HttpVersion
    headOnly: bool
      ## Current request was a HEAD, so the body must be suppressed.

  HttpFeedOutcome* {.role: truthState, metaTags: {tagProtocol, tagParsing}.} =
      object
    events*: seq[HttpEvent]
    consumed*: int
      ## Input bytes used. Leftovers belong to the next feed.

proc defaultHttpServerLimits*(): HttpServerLimits {.role: configurator,
    metaTags: {tagProtocol}.} =
  ## Conservative limits suitable for a public listener.
  result.maxBodyBytes = httpDefaultMaxBodyBytes
  result.maxRequestsPerConnection = 1000

proc initHttpServerConnection*(L: HttpServerLimits =
    defaultHttpServerLimits()): HttpServerConnection {.role: truthBuilder,
    metaTags: {tagProtocol, tagNetworkSurface}.} =
  ## L: size and count limits applied to every request on this connection.
  result = HttpServerConnection()
  result.state = hcsReading
  result.limits = L
  result.parser = initHttpRequestParser(L.maxBodyBytes)
  result.served = 0
  result.keepAlive = true
  result.version = hv11
  result.headOnly = false

proc feedHttpConnection*(C: HttpServerConnection;
    A: openArray[byte]): HttpFeedOutcome {.role: metaOrchestrator,
    metaTags: {tagProtocol, tagParsing, tagNetworkSurface}.} =
  ## C/A: connection state and the next bytes read from the transport.
  ##
  ## Drains as many complete requests out of `A` as it holds. Pipelined
  ## requests therefore surface as several events from one feed.
  var
    i: int = 0
    step: HttpFeedResult
    ev: HttpEvent
  result.events = @[]
  result.consumed = 0
  if C.state in {hcsClosing, hcsClosed, hcsUpgraded}:
    return
  while i < A.len and C.state == hcsReading:
    step = feedHttpRequest(C.parser, A.toOpenArray(i, A.len - 1))
    i = i + step.consumed
    if not step.ok:
      ev = HttpEvent(kind: hekError)
      ev.response = errorResponse(httpStatusForParseError(step.err),
        step.errMsg)
      ev.response.closeAfter = true
      C.state = hcsClosing
      result.events.add(ev)
      result.consumed = i
      return
    if not step.complete:
      break
    # A client waiting on `100 Continue` gets it before we look at the
    # body, otherwise both sides sit waiting for the other.
    if C.parser.request.expectContinue:
      ev = HttpEvent(kind: hekContinue)
      ev.response = newHttpResponse(100)
      result.events.add(ev)
    C.version = C.parser.request.version
    C.keepAlive = C.parser.request.keepAlive
    C.headOnly = C.parser.request.verb == hmHead
    if C.limits.maxRequestsPerConnection > 0 and
        C.served + 1 >= C.limits.maxRequestsPerConnection:
      C.keepAlive = false
    if C.parser.request.isUpgrade:
      ev = HttpEvent(kind: hekUpgrade, request: C.parser.request)
      C.state = hcsDispatched
      result.events.add(ev)
      result.consumed = i
      return
    ev = HttpEvent(kind: hekRequest, request: C.parser.request)
    C.state = hcsDispatched
    result.events.add(ev)
    result.consumed = i
    return
  result.consumed = i

proc respondHttpConnection*(C: HttpServerConnection;
    R: HttpResponse): ByteSeq {.role: dataWriter,
    metaTags: {tagProtocol, tagWrite, tagNetworkSurface}.} =
  ## C/R: connection awaiting a reply, and the reply to serialise.
  ##
  ## Returns the complete bytes to write. Afterwards the connection is
  ## either ready for the next request or marked closing, which the
  ## caller checks with `httpConnectionShouldClose`.
  var
    bodyLen: int64 = 0
    sendBody: bool = false
  if C.state == hcsUpgraded:
    return @[]
  bodyLen = int64(R.body.len)
  sendBody = httpStatusAllowsBody(R.status) and not C.headOnly
  if R.closeAfter:
    C.keepAlive = false
  result = encodeResponseHead(R, C.version, C.keepAlive, bodyLen, false,
    C.headOnly)
  if sendBody and R.body.len > 0:
    result.add(R.body)
  C.served = C.served + 1
  if C.keepAlive:
    C.state = hcsReading
    resetHttpRequestParser(C.parser)
  else:
    C.state = hcsClosing

proc respondHttpInterim*(C: HttpServerConnection;
    R: HttpResponse): ByteSeq {.role: dataWriter,
    metaTags: {tagProtocol, tagWrite}.} =
  ## C/R: connection and an interim 1xx reply such as `100 Continue`.
  ##
  ## Interim replies do not end the message, so the connection stays
  ## exactly where it was.
  var
    t: string = ""
  t = "HTTP/1.1 " & $R.status & " " & httpReasonPhrase(R.status) & "\r\n\r\n"
  result = toHttpBytes(t)

proc beginHttpStreamResponse*(C: HttpServerConnection;
    R: HttpResponse): ByteSeq {.role: dataWriter,
    metaTags: {tagProtocol, tagWrite}.} =
  ## C/R: connection and the head of a response whose body is streamed.
  ##
  ## Use when the body length is not known up front. The head declares
  ## chunked framing; push pieces with `streamHttpChunk` and finish with
  ## `endHttpStreamResponse`.
  if R.closeAfter:
    C.keepAlive = false
  result = encodeResponseHead(R, C.version, C.keepAlive, 0, true, C.headOnly)

proc streamHttpChunk*(C: HttpServerConnection;
    A: openArray[byte]): ByteSeq {.role: dataWriter,
    metaTags: {tagProtocol, tagWrite}.} =
  ## C/A: connection mid-stream and the next body piece.
  if C.headOnly or A.len == 0:
    return @[]
  result = encodeChunk(A)

proc endHttpStreamResponse*(C: HttpServerConnection): ByteSeq {.
    role: dataWriter, metaTags: {tagProtocol, tagWrite}.} =
  ## C: connection whose streamed body is finished.
  result = (if C.headOnly: @[] else: encodeLastChunk())
  C.served = C.served + 1
  if C.keepAlive:
    C.state = hcsReading
    resetHttpRequestParser(C.parser)
  else:
    C.state = hcsClosing

proc beginHttpFixedResponse*(C: HttpServerConnection; R: HttpResponse;
    bodyLen: int64): ByteSeq {.role: dataWriter,
    metaTags: {tagProtocol, tagWrite}.} =
  ## C/R/bodyLen: connection, response head, and exact body size.
  ##
  ## For a large file whose size is known: the head is written now and
  ## the caller streams `bodyLen` raw bytes itself, then calls
  ## `finishHttpFixedResponse`.
  if R.closeAfter:
    C.keepAlive = false
  result = encodeResponseHead(R, C.version, C.keepAlive, bodyLen, false,
    C.headOnly)

proc finishHttpFixedResponse*(C: HttpServerConnection) {.role: actor,
    metaTags: {tagProtocol, tagWrite}.} =
  ## C: connection whose fixed-length body has been fully written.
  C.served = C.served + 1
  if C.keepAlive:
    C.state = hcsReading
    resetHttpRequestParser(C.parser)
  else:
    C.state = hcsClosing

proc acceptHttpUpgrade*(C: HttpServerConnection) {.role: actor,
    metaTags: {tagProtocol, tagNetworkSurface}.} =
  ## C: connection whose upgrade the caller accepted.
  ##
  ## After this the state machine stops interpreting bytes entirely and
  ## the caller owns the raw stream, which is what WebSocket needs.
  C.state = hcsUpgraded

proc httpConnectionAwaitingBody*(C: HttpServerConnection): bool {.
    role: parser, metaTags: {tagProtocol, tagRead}.} =
  ## C: connection to ask about the message currently being read.
  ##
  ## True once the head is parsed and only body bytes are outstanding.
  ## A server uses this to switch from a short head deadline to a longer
  ## body deadline: a slow upload is normal, a slow *head* is not.
  C.state == hcsReading and C.parser.state == hpsBody

proc httpConnectionInMessage*(C: HttpServerConnection): bool {.role: parser,
    metaTags: {tagProtocol, tagRead}.} =
  ## C: connection to ask whether a partial message is buffered.
  ##
  ## True when some bytes of a request have arrived but it is not yet
  ## complete, which is the window a head-trickling client sits in.
  C.state == hcsReading and
    (httpParserHasPartialHead(C.parser) or C.parser.state == hpsBody)

proc httpConnectionShouldClose*(C: HttpServerConnection): bool {.role: parser,
    metaTags: {tagProtocol, tagRead}.} =
  ## C: connection to test after a response was flushed.
  C.state in {hcsClosing, hcsClosed}

proc httpConnectionIsUpgraded*(C: HttpServerConnection): bool {.role: parser,
    metaTags: {tagProtocol, tagRead}.} =
  ## C: connection to test for a completed protocol switch.
  C.state == hcsUpgraded
