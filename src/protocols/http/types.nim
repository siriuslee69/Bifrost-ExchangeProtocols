## ------------------------------------------------------------------
## HTTP Types <- shared request/response shapes for the HTTP/1.1 stack
## ------------------------------------------------------------------
##
## Everything below is plain data. No sockets, no files, no clock.
## The parser fills these in; the writer turns them back into bytes.
##
##   bytes in  ->  HttpRequest   (parser)
##   HttpResponse  ->  bytes out (writer)
##
## Header storage is a flat list, not a table, because HTTP allows the
## same name twice (`Set-Cookie:` most often) and order must survive a
## round trip. Lookup helpers in `level0/header_ops.nim` do the
## case-insensitive matching.

import ../types
import ../../analysis_pragmas

const
  httpMaxRequestLineLen* = 8_192
    ## Longest `GET /path HTTP/1.1` line accepted. Anything above this
    ## earns a 414 rather than a buffer that grows without limit.
  httpMaxHeaderBlockLen* = 65_536
    ## Longest complete header block accepted, terminator included.
  httpMaxHeaderCount* = 128
    ## Most header lines accepted in one request.
  httpMaxChunkLineLen* = 1_024
    ## Longest chunk-size line accepted in a chunked body.

type
  HttpMethod* = enum
    ## Request verbs. `hmUnknown` carries anything we parsed but do not
    ## recognise, so a handler may still answer 405 instead of 400.
    hmUnknown = "UNKNOWN",
    hmGet = "GET",
    hmHead = "HEAD",
    hmPost = "POST",
    hmPut = "PUT",
    hmPatch = "PATCH",
    hmDelete = "DELETE",
    hmOptions = "OPTIONS",
    hmTrace = "TRACE",
    hmConnect = "CONNECT"

  HttpVersion* = enum
    ## Only the 1.x line is served. HTTP/2 and HTTP/3 need their own
    ## framing layer and are deliberately absent rather than faked.
    hvUnknown = "HTTP/0.0",
    hv10 = "HTTP/1.0",
    hv11 = "HTTP/1.1"

  HttpBodyMode* = enum
    ## How the message body length is determined.
    ##   hbmNone          <- no body at all
    ##   hbmContentLength <- exactly `contentLength` bytes follow
    ##   hbmChunked       <- `Transfer-Encoding: chunked` framing
    ##   hbmUntilClose    <- read until the peer closes (responses only)
    hbmNone,
    hbmContentLength,
    hbmChunked,
    hbmUntilClose

  HttpHeader* {.role: truthState, tag: {tagProtocol, tagTypes}.} = object
    name*: string
      ## Field name exactly as it arrived on the wire.
    value*: string
      ## Field value, leading and trailing whitespace already trimmed.

  HttpHeaders* = seq[HttpHeader]

  HttpQueryParam* {.role: truthState, tag: {tagProtocol, tagTypes}.} = object
    key*: string
    value*: string

  HttpRequest* {.role: truthState,
      tag: {tagProtocol, tagParsing, tagNetworkSurface}.} = object
    ## One fully parsed request. `body` is present only once the parser
    ## reports the message complete.
    verb*: HttpMethod
      ## Recognised verb, or `hmUnknown`.
    rawMethod*: string
      ## Verb exactly as received, so 405 replies can echo it safely.
    target*: string
      ## Raw request-target, undecoded (`/a%20b?x=1`).
    path*: string
      ## Percent-decoded, normalised path (`/a b`). Never contains `..`.
    query*: string
      ## Raw query string without the `?`.
    params*: seq[HttpQueryParam]
      ## Decoded query parameters, in arrival order.
    version*: HttpVersion
    headers*: HttpHeaders
    body*: ByteSeq
    keepAlive*: bool
      ## Whether the connection may be reused after this message.
    expectContinue*: bool
      ## Client sent `Expect: 100-continue` and is waiting for our go-ahead.
    isUpgrade*: bool
      ## Client asked to leave HTTP behind (WebSocket and friends).
    upgradeProtocol*: string
      ## Lowercased value of the `Upgrade` header when `isUpgrade` is set.

  HttpResponse* {.role: truthState,
      tag: {tagProtocol, tagNetworkSurface}.} = object
    ## One response to serialise. Either set `body`, or set
    ## `streamBody` and push chunks yourself.
    status*: int
    reason*: string
      ## Left empty to use the standard reason phrase for `status`.
    headers*: HttpHeaders
    body*: ByteSeq
    streamBody*: bool
      ## True when the body is written separately after the head.
    closeAfter*: bool
      ## Force the connection shut once this response is flushed.

  HttpParseState* = enum
    ## Where the incremental request parser currently sits.
    hpsRequestLine,
    hpsHeaders,
    hpsBody,
    hpsComplete,
    hpsError

  HttpParseError* = enum
    ## Why a parse failed. Each maps onto exactly one status code so the
    ## server never has to guess what to send back.
    hpeNone,
    hpeMalformedRequestLine,
    hpeUnsupportedVersion,
    hpeRequestLineTooLong,
    hpeHeaderTooLarge,
    hpeTooManyHeaders,
    hpeMalformedHeader,
    hpeDuplicateContentLength,
    hpeConflictingFraming,
    hpeInvalidContentLength,
    hpeInvalidChunk,
    hpeBodyTooLarge,
    hpeMissingHost,
    hpeInvalidHost,
    hpeInvalidTarget

proc toHttpBytes*(s: string): ByteSeq {.role: helper,
    tag: {tagProtocol, tagCodecBoundary}.} =
  ## s: text to copy into a byte sequence.
  ##
  ## An explicit copy rather than a cast: `string` and `seq[byte]` happen
  ## to share a layout today, but relying on that turns a future runtime
  ## change into silent memory corruption.
  var
    i: int = 0
  result = newSeq[byte](s.len)
  while i < s.len:
    result[i] = byte(s[i])
    i = i + 1

proc fromHttpBytes*(A: openArray[byte]): string {.role: helper,
    tag: {tagProtocol, tagCodecBoundary}.} =
  ## A: bytes to copy into text.
  var
    i: int = 0
  result = newString(A.len)
  while i < A.len:
    result[i] = char(A[i])
    i = i + 1

proc httpStatusForParseError*(e: HttpParseError): int {.role: parser,
    tag: {tagProtocol, tagValidation}.} =
  ## e: parser failure to translate into a response status code.
  ##
  ## Framing disagreements are answered with 400 and a forced close,
  ## because once the byte stream is ambiguous nothing after it can be
  ## trusted to line up on a message boundary.
  case e
  of hpeNone: 200
  of hpeRequestLineTooLong: 414
  of hpeHeaderTooLarge, hpeTooManyHeaders: 431
  of hpeUnsupportedVersion: 505
  of hpeBodyTooLarge: 413
  else: 400

proc httpMethodFromString*(s: string): HttpMethod {.role: parser,
    tag: {tagProtocol, tagParsing}.} =
  ## s: verb token taken from the request line.
  case s
  of "GET": hmGet
  of "HEAD": hmHead
  of "POST": hmPost
  of "PUT": hmPut
  of "PATCH": hmPatch
  of "DELETE": hmDelete
  of "OPTIONS": hmOptions
  of "TRACE": hmTrace
  of "CONNECT": hmConnect
  else: hmUnknown

proc httpVersionFromString*(s: string): HttpVersion {.role: parser,
    tag: {tagProtocol, tagParsing}.} =
  ## s: version token taken from the request line.
  case s
  of "HTTP/1.1": hv11
  of "HTTP/1.0": hv10
  else: hvUnknown

proc httpMethodAllowsBody*(m: HttpMethod): bool {.role: parser,
    tag: {tagProtocol, tagValidation}.} =
  ## m: verb to check for body-carrying capability.
  ##
  ## GET/HEAD/DELETE/OPTIONS/TRACE may legally carry a body, but almost
  ## no real client sends one, and accepting it widens the smuggling
  ## surface for no gain. We accept a body only where it is expected.
  m in {hmPost, hmPut, hmPatch}
