## ------------------------------------------------------------------
## HTTP protocol suite <- parsing, framing, and connection-state checks
## ------------------------------------------------------------------
##
## Most of these are refusal tests. A web server is judged less by what
## it accepts than by what it declines to guess about, so each case here
## names the ambiguity it is closing.

import std/[unittest, strutils]
import protocols/http

proc bytesOf(s: string): seq[byte] =
  ## s: text to feed the parser as raw transport bytes.
  toHttpBytes(s)

proc parseOne(s: string): HttpFeedResult =
  ## s: whole request text to push through a fresh parser in one go.
  var
    P: HttpRequestParser = initHttpRequestParser()
  result = feedHttpRequest(P, bytesOf(s))

proc parseInto(s: string; P: var HttpRequestParser): HttpFeedResult =
  ## s/P: request text and the parser to drive with it.
  result = feedHttpRequest(P, bytesOf(s))

suite "http header ops":
  test "field name lookup ignores case but values do not":
    var
      H: HttpHeaders = @[]
    H.addHeader("Content-Type", "TEXT/HTML")
    check H.getHeader("content-type") == "TEXT/HTML"
    check H.getHeader("CONTENT-TYPE") == "TEXT/HTML"
    check H.getHeader("missing", "fallback") == "fallback"

  test "setHeader collapses duplicates to a single field":
    var
      H: HttpHeaders = @[]
    H.addHeader("X-A", "1")
    H.addHeader("X-A", "2")
    H.addHeader("X-B", "keep")
    H.setHeader("X-A", "3")
    check H.countHeader("X-A") == 1
    check H.getHeader("X-A") == "3"
    check H.getHeader("X-B") == "keep"

  test "header names and values reject injection bytes":
    check isValidHeaderName("X-Fine")
    check not isValidHeaderName("X Bad")
    check not isValidHeaderName("X:Bad")
    check not isValidHeaderName("")
    check isValidHeaderValue("plain value")
    check not isValidHeaderValue("a\r\nX-Admin: yes")
    check not isValidHeaderValue("a\nb")

  test "comma lists match whole tokens only":
    var
      H: HttpHeaders = @[]
    H.addHeader("Connection", "keep-alive, Upgrade")
    check H.headerHasToken("connection", "upgrade")
    check H.headerHasToken("connection", "keep-alive")
    check not H.headerHasToken("connection", "grade")

suite "http target ops":
  test "percent decoding fails closed on bad escapes":
    check percentDecode("/a%20b").value == "/a b"
    check not percentDecode("/a%2").ok
    check not percentDecode("/a%zz").ok
    check not percentDecode("/a%00b").ok

  test "traversal is rejected after decoding, not before":
    # The encoded form is what a naive filter misses.
    var
      r = parseHttpTarget("/files/%2e%2e%2f%2e%2e%2fetc/passwd")
    check not r.ok
    check not parseHttpTarget("/../secret").ok
    check not parseHttpTarget("/a/../../b").ok

  test "backslashes are refused so windows cannot be traversed":
    check not parseHttpTarget("/a\\..\\b").ok

  test "normalisation collapses separators and dot segments":
    check normalizeHttpPath("/a//b/./c").path == "/a/b/c"
    check normalizeHttpPath("/a/b/../c").path == "/a/c"
    check normalizeHttpPath("/").path == "/"
    check normalizeHttpPath("/a/").path == "/a/"

  test "absolute-form targets keep only the path":
    check parseHttpTarget("http://host.example/a/b").path == "/a/b"
    check parseHttpTarget("http://host.example").path == "/"

  test "query parameters decode independently of the path":
    var
      r = parseHttpTarget("/s?q=hello+world&lang=en")
    check r.ok
    check r.path == "/s"
    check r.params.getQueryParam("q") == "hello world"
    check r.params.getQueryParam("lang") == "en"
    check r.params.getQueryParam("absent", "none") == "none"

suite "http request parsing":
  test "a plain GET parses into its parts":
    var
      r = parseOne("GET /index.html HTTP/1.1\r\nHost: a.example\r\n\r\n")
      P: HttpRequestParser = initHttpRequestParser()
    check r.ok
    check r.complete
    discard parseInto("GET /index.html HTTP/1.1\r\nHost: a.example\r\n\r\n", P)
    check P.request.verb == hmGet
    check P.request.path == "/index.html"
    check P.request.version == hv11
    check P.request.keepAlive

  test "a body arriving in pieces is reassembled":
    var
      P: HttpRequestParser = initHttpRequestParser()
      a = parseInto("POST /submit HTTP/1.1\r\nHost: a\r\nContent-Length: 11" &
        "\r\n\r\nhel", P)
      b = parseInto("lo world", P)
    check a.ok
    check not a.complete
    check b.ok
    check b.complete
    check fromHttpBytes(P.request.body) == "hello world"

  test "chunked bodies decode across feed boundaries":
    var
      P: HttpRequestParser = initHttpRequestParser()
      a = parseInto("POST /u HTTP/1.1\r\nHost: a\r\n" &
        "Transfer-Encoding: chunked\r\n\r\n5\r\nhel", P)
      b = parseInto("lo\r\n6\r\n world\r\n0\r\n\r\n", P)
    check a.ok
    check b.ok
    check b.complete
    check fromHttpBytes(P.request.body) == "hello world"

  test "HTTP/1.1 without Host is refused":
    var
      P: HttpRequestParser = initHttpRequestParser()
      r = parseInto("GET / HTTP/1.1\r\n\r\n", P)
    check not r.ok
    check P.err == hpeMissingHost

  test "two Host headers are refused":
    var
      P: HttpRequestParser = initHttpRequestParser()
      r = parseInto("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", P)
    check not r.ok
    check P.err == hpeInvalidHost

suite "http request smuggling defences":
  test "Content-Length together with Transfer-Encoding is refused":
    var
      P: HttpRequestParser = initHttpRequestParser()
      r = parseInto("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\n" &
        "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n", P)
    check not r.ok
    check P.err == hpeConflictingFraming
    check httpStatusForParseError(P.err) == 400

  test "two Content-Length headers are refused":
    var
      P: HttpRequestParser = initHttpRequestParser()
      r = parseInto("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\n" &
        "Content-Length: 7\r\n\r\nabcdef", P)
    check not r.ok
    check P.err == hpeDuplicateContentLength

  test "a signed or padded Content-Length is refused":
    var
      P1: HttpRequestParser = initHttpRequestParser()
      P2: HttpRequestParser = initHttpRequestParser()
    check not parseInto("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +6" &
      "\r\n\r\nabcdef", P1).ok
    check not parseInto("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0x6" &
      "\r\n\r\nabcdef", P2).ok

  test "an encoding list ending in chunked is refused, not guessed":
    var
      P: HttpRequestParser = initHttpRequestParser()
      r = parseInto("POST / HTTP/1.1\r\nHost: a\r\n" &
        "Transfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n", P)
    check not r.ok
    check P.err == hpeConflictingFraming

  test "obsolete line folding is refused":
    var
      P: HttpRequestParser = initHttpRequestParser()
      r = parseInto("GET / HTTP/1.1\r\nHost: a\r\nX-A: one\r\n  two\r\n\r\n", P)
    check not r.ok
    check P.err == hpeMalformedHeader

  test "whitespace before the colon is refused":
    var
      P: HttpRequestParser = initHttpRequestParser()
      r = parseInto("GET / HTTP/1.1\r\nHost: a\r\nX-A : v\r\n\r\n", P)
    check not r.ok
    check P.err == hpeMalformedHeader

  test "a body on a verb that should not carry one is refused":
    var
      P: HttpRequestParser = initHttpRequestParser()
      r = parseInto("GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n" &
        "\r\nhello", P)
    check not r.ok
    check P.err == hpeConflictingFraming

  test "a malformed chunk size is refused":
    var
      P: HttpRequestParser = initHttpRequestParser()
      r = parseInto("POST / HTTP/1.1\r\nHost: a\r\n" &
        "Transfer-Encoding: chunked\r\n\r\n-5\r\nhello\r\n0\r\n\r\n", P)
    check not r.ok
    check P.err == hpeInvalidChunk

  test "an oversized body is refused with 413":
    var
      P: HttpRequestParser = initHttpRequestParser(8)
      r = parseInto("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4096" &
        "\r\n\r\n", P)
    check not r.ok
    check P.err == hpeBodyTooLarge
    check httpStatusForParseError(P.err) == 413

  test "an oversized head is refused with 431":
    var
      P: HttpRequestParser = initHttpRequestParser()
      big: string = "GET / HTTP/1.1\r\nHost: a\r\n"
      i: int = 0
    while i < 4000:
      big.add("X-Pad-" & $i & ": 0123456789012345678901234567890123456789\r\n")
      i = i + 1
    check not parseInto(big, P).ok
    check httpStatusForParseError(P.err) == 431

suite "http chunked codec":
  test "encode and decode round-trip":
    var
      D: ChunkedDecoder = initChunkedDecoder()
      wire: seq[byte] = @[]
      r: ChunkedFeedResult
    wire.add(encodeChunk(toHttpBytes("hello ")))
    wire.add(encodeChunk(toHttpBytes("world")))
    wire.add(encodeLastChunk())
    r = feedChunked(D, wire, 1024)
    check r.ok
    check r.done
    check fromHttpBytes(r.data) == "hello world"

  test "the decoder enforces the size cap mid-stream":
    var
      D: ChunkedDecoder = initChunkedDecoder()
      r = feedChunked(D, toHttpBytes("10\r\n0123456789abcdef\r\n0\r\n\r\n"), 4)
    check not r.ok

suite "http response writing":
  test "framing headers are written by the writer, not the handler":
    var
      R: HttpResponse = textResponse(200, "hi")
      head: string = ""
    R.headers.addHeader("Content-Length", "999")
    R.headers.addHeader("Transfer-Encoding", "chunked")
    head = fromHttpBytes(encodeResponseHead(R, hv11, true, 2, false, false))
    check head.contains("Content-Length: 2\r\n")
    check not head.contains("999")
    check not head.contains("Transfer-Encoding")

  test "statuses that forbid a body get no Content-Length":
    var
      head = fromHttpBytes(encodeResponseHead(newHttpResponse(204), hv11,
        true, 0, false, false))
    check not head.contains("Content-Length")
    check head.startsWith("HTTP/1.1 204 No Content\r\n")

  test "a header value carrying a line break is dropped":
    var
      R: HttpResponse = textResponse(200, "hi")
      head: string = ""
    R.headers.addHeader("X-Evil", "a\r\nX-Admin: yes")
    head = fromHttpBytes(encodeResponseHead(R, hv11, true, 2, false, false))
    check not head.contains("X-Admin")

suite "http connection state machine":
  test "each pipelined request is parsed on its own":
    var
      C: HttpServerConnection = initHttpServerConnection()
      first = feedHttpConnection(C, bytesOf(
        "GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: y\r\n\r\n"))
      rest: seq[byte] = @[]
      second: HttpFeedOutcome
      whole: seq[byte] = bytesOf(
        "GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: y\r\n\r\n")
    check first.events.len == 1
    check first.events[0].request.path == "/a"
    check first.events[0].request.headers.getHeader("host") == "x"
    # The second request keeps its own Host; nothing carries over.
    rest = whole[first.consumed .. ^1]
    discard respondHttpConnection(C, textResponse(200, "a"))
    second = feedHttpConnection(C, rest)
    check second.events.len == 1
    check second.events[0].request.path == "/b"
    check second.events[0].request.headers.getHeader("host") == "y"

  test "Connection: close retires the connection after one reply":
    var
      C: HttpServerConnection = initHttpServerConnection()
      o = feedHttpConnection(C, bytesOf(
        "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
      wire: string = ""
    check o.events[0].kind == hekRequest
    wire = fromHttpBytes(respondHttpConnection(C, textResponse(200, "bye")))
    check wire.contains("Connection: close")
    check C.httpConnectionShouldClose()

  test "HTTP/1.0 closes unless keep-alive is asked for":
    var
      C1: HttpServerConnection = initHttpServerConnection()
      C2: HttpServerConnection = initHttpServerConnection()
    discard feedHttpConnection(C1, bytesOf("GET / HTTP/1.0\r\n\r\n"))
    discard respondHttpConnection(C1, textResponse(200, "x"))
    check C1.httpConnectionShouldClose()
    discard feedHttpConnection(C2, bytesOf(
      "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n"))
    discard respondHttpConnection(C2, textResponse(200, "x"))
    check not C2.httpConnectionShouldClose()

  test "an upgrade request surfaces as its own event":
    var
      C: HttpServerConnection = initHttpServerConnection()
      o = feedHttpConnection(C, bytesOf(
        "GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\n" &
        "Upgrade: websocket\r\n\r\n"))
    check o.events.len == 1
    check o.events[0].kind == hekUpgrade
    check o.events[0].request.upgradeProtocol == "websocket"
    C.acceptHttpUpgrade()
    check C.httpConnectionIsUpgraded()

  test "HEAD gets the head but no body bytes":
    var
      C: HttpServerConnection = initHttpServerConnection()
      wire: string = ""
    discard feedHttpConnection(C, bytesOf("HEAD /x HTTP/1.1\r\nHost: x\r\n\r\n"))
    wire = fromHttpBytes(respondHttpConnection(C, textResponse(200, "body")))
    check wire.contains("Content-Length: 4")
    check not wire.contains("body")

  test "Expect: 100-continue produces an interim reply first":
    var
      C: HttpServerConnection = initHttpServerConnection()
      o = feedHttpConnection(C, bytesOf(
        "POST /u HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n" &
        "Content-Length: 2\r\n\r\nhi"))
    check o.events.len == 2
    check o.events[0].kind == hekContinue
    check o.events[1].kind == hekRequest
    check fromHttpBytes(respondHttpInterim(C, o.events[0].response)) ==
      "HTTP/1.1 100 Continue\r\n\r\n"

  test "a malformed request yields a ready-made error response":
    var
      C: HttpServerConnection = initHttpServerConnection()
      o = feedHttpConnection(C, bytesOf(
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\n" &
        "Transfer-Encoding: chunked\r\n\r\nx"))
    check o.events.len == 1
    check o.events[0].kind == hekError
    check o.events[0].response.status == 400
    check C.httpConnectionShouldClose()

  test "the per-connection request budget retires the connection":
    var
      L: HttpServerLimits = defaultHttpServerLimits()
      C: HttpServerConnection
    L.maxRequestsPerConnection = 1
    C = initHttpServerConnection(L)
    discard feedHttpConnection(C, bytesOf("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
    discard respondHttpConnection(C, textResponse(200, "x"))
    check C.httpConnectionShouldClose()

  test "a streamed response uses chunked framing end to end":
    var
      C: HttpServerConnection = initHttpServerConnection()
      wire: string = ""
    discard feedHttpConnection(C, bytesOf("GET /s HTTP/1.1\r\nHost: x\r\n\r\n"))
    wire = fromHttpBytes(beginHttpStreamResponse(C, newHttpResponse(200)))
    check wire.contains("Transfer-Encoding: chunked")
    check not wire.contains("Content-Length")
    wire = fromHttpBytes(streamHttpChunk(C, toHttpBytes("abc")))
    check wire == "3\r\nabc\r\n"
    check fromHttpBytes(endHttpStreamResponse(C)) == "0\r\n\r\n"
    check not C.httpConnectionShouldClose()
