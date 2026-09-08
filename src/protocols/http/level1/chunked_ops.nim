## ------------------------------------------------------------------
## HTTP Chunked Ops <- incremental decoder and encoder for chunked bodies
## ------------------------------------------------------------------
##
## `Transfer-Encoding: chunked` sends a body as a run of length-prefixed
## pieces, ended by a zero-length piece:
##
##   1a\r\n                  <- 0x1a = 26 bytes follow
##   <26 bytes of data>\r\n
##   0\r\n                   <- zero length: body is over
##   \r\n                    <- optional trailers, then a blank line
##
## The decoder below is fed whatever bytes happen to arrive and keeps its
## place between calls, so a chunk split across three TCP reads costs
## nothing extra. It never buffers a whole body just to find the end.
##
## Two things it refuses outright:
##   - a chunk-size line longer than `httpMaxChunkLineLen`
##   - a chunk-size with a leading `+`/`-` or non-hex digits
## Both are how a request gets framed one way by us and another way by an
## upstream, which is the whole basis of request smuggling.

import ../../types
import ../types
import bifrostPragmas

type
  ChunkedDecodeState* = enum
    ## Position inside the chunked grammar.
    cdsSize,        ## reading the `1a;ext\r\n` line
    cdsData,        ## copying `remaining` payload bytes
    cdsDataCrLf,    ## consuming the `\r\n` that closes a chunk
    cdsTrailer,     ## reading trailer lines after the final chunk
    cdsDone,        ## body complete
    cdsError        ## framing broken; connection must close

  ChunkedDecoder* {.role: memory, metaTags: {tagProtocol, tagParsing}.} = object
    state*: ChunkedDecodeState
    remaining*: int64
      ## Payload bytes still owed for the chunk being read.
    line*: string
      ## Partial size or trailer line held across feeds.
    totalBytes*: int64
      ## Decoded payload bytes produced so far, for the size cap.
    err*: string

  ChunkedFeedResult* {.role: truthState, metaTags: {tagProtocol, tagParsing}.} =
      object
    ok*: bool
    consumed*: int
      ## Input bytes taken from this feed.
    data*: ByteSeq
      ## Decoded payload produced by this feed.
    done*: bool
      ## Final chunk and trailers have been seen.
    err*: string

proc initChunkedDecoder*(): ChunkedDecoder {.role: truthBuilder,
    metaTags: {tagProtocol, tagParsing}.} =
  ## Build a decoder sitting at the first chunk-size line.
  result.state = cdsSize
  result.remaining = 0
  result.line = ""
  result.totalBytes = 0
  result.err = ""

proc parseChunkSize(l: string): tuple[ok: bool, size: int64] {.role: parser,
    metaTags: {tagProtocol, tagParsing, tagValidation}.} =
  ## l: one chunk-size line, `\r\n` already removed.
  ##
  ## Anything after a `;` is a chunk extension and is ignored. The size
  ## itself must be plain hex with at least one digit and no sign.
  var
    i: int = 0
    stop: int = 0
    v: int64 = 0
    d: int = 0
    seen: int = 0
  stop = l.find(';')
  if stop < 0:
    stop = l.len
  while i < stop and (l[i] == ' ' or l[i] == '\t'):
    i = i + 1
  while i < stop:
    case l[i]
    of '0'..'9': d = ord(l[i]) - ord('0')
    of 'a'..'f': d = ord(l[i]) - ord('a') + 10
    of 'A'..'F': d = ord(l[i]) - ord('A') + 10
    of ' ', '\t':
      # Trailing spaces before the extension separator are tolerated,
      # but a digit may never follow them.
      while i < stop:
        if l[i] != ' ' and l[i] != '\t':
          return (false, 0'i64)
        i = i + 1
      break
    else:
      return (false, 0'i64)
    if seen > 15:
      return (false, 0'i64)
    v = v * 16 + int64(d)
    seen = seen + 1
    i = i + 1
  if seen == 0:
    return (false, 0'i64)
  result = (true, v)

proc takeLine(D: var ChunkedDecoder; A: openArray[byte]; i: var int;
    maxLen: int): tuple[have: bool, bad: bool] {.role: parser,
    metaTags: {tagProtocol, tagParsing}.} =
  ## D/A/i/maxLen: decoder, input, read cursor, and line length cap.
  ##
  ## Accumulates bytes into `D.line` until a `\n` is reached. A `\r`
  ## immediately before it is dropped. Returns `bad` once the cap is
  ## passed so a peer cannot stall us with an endless size line.
  var
    c: byte = 0
  while i < A.len:
    c = A[i]
    i = i + 1
    if c == byte('\n'):
      if D.line.len > 0 and D.line[^1] == '\r':
        D.line.setLen(D.line.len - 1)
      return (true, false)
    D.line.add(char(c))
    if D.line.len > maxLen:
      return (false, true)
  result = (false, false)

proc feedChunked*(D: var ChunkedDecoder; A: openArray[byte];
    maxBodyBytes: int64): ChunkedFeedResult {.role: orchestrator,
    metaTags: {tagProtocol, tagParsing, tagValidation}.} =
  ## D/A/maxBodyBytes: decoder state, next input bytes, decoded size cap.
  ##
  ## Consumes as much of `A` as the grammar allows and returns whatever
  ## payload that produced. Call again with more bytes while `done` is
  ## false and `ok` is true.
  var
    i: int = 0
    line: tuple[have: bool, bad: bool]
    size: tuple[ok: bool, size: int64]
    take: int = 0
  result.ok = true
  result.data = @[]
  if D.state == cdsDone:
    return ChunkedFeedResult(ok: true, consumed: 0, data: @[], done: true,
      err: "")
  if D.state == cdsError:
    return ChunkedFeedResult(ok: false, consumed: 0, data: @[], done: false,
      err: D.err)

  while i < A.len and D.state notin {cdsDone, cdsError}:
    case D.state
    of cdsSize:
      line = takeLine(D, A, i, httpMaxChunkLineLen)
      if line.bad:
        D.state = cdsError
        D.err = "chunk size line too long"
        break
      if not line.have:
        break
      size = parseChunkSize(D.line)
      D.line = ""
      if not size.ok:
        D.state = cdsError
        D.err = "malformed chunk size"
        break
      if size.size == 0:
        D.state = cdsTrailer
      else:
        if D.totalBytes + size.size > maxBodyBytes:
          D.state = cdsError
          D.err = "chunked body exceeds limit"
          break
        D.remaining = size.size
        D.state = cdsData
    of cdsData:
      take = A.len - i
      if int64(take) > D.remaining:
        take = int(D.remaining)
      if take > 0:
        result.data.add(A[i ..< i + take])
        i = i + take
        D.remaining = D.remaining - int64(take)
        D.totalBytes = D.totalBytes + int64(take)
      if D.remaining == 0:
        D.state = cdsDataCrLf
    of cdsDataCrLf:
      line = takeLine(D, A, i, 4)
      if line.bad:
        D.state = cdsError
        D.err = "missing chunk terminator"
        break
      if not line.have:
        break
      if D.line.len != 0:
        D.state = cdsError
        D.err = "malformed chunk terminator"
        D.line = ""
        break
      D.line = ""
      D.state = cdsSize
    of cdsTrailer:
      line = takeLine(D, A, i, httpMaxChunkLineLen)
      if line.bad:
        D.state = cdsError
        D.err = "trailer line too long"
        break
      if not line.have:
        break
      if D.line.len == 0:
        D.state = cdsDone
      D.line = ""
    else:
      break

  result.consumed = i
  result.done = D.state == cdsDone
  if D.state == cdsError:
    result.ok = false
    result.err = D.err

proc encodeChunk*(A: openArray[byte]): ByteSeq {.role: dataWriter,
    metaTags: {tagProtocol, tagWrite}.} =
  ## A: payload bytes to wrap as one chunk.
  ##
  ## An empty input would encode as the terminating chunk by accident,
  ## so it returns nothing instead; use `encodeLastChunk` to finish.
  const
    hex: string = "0123456789abcdef"
  var
    n: int = 0
    shift: int = 0
    started: bool = false
    d: int = 0
  result = @[]
  if A.len == 0:
    return
  n = A.len
  shift = 28
  while shift >= 0:
    d = (n shr shift) and 0xF
    if d != 0 or started or shift == 0:
      started = true
      result.add(byte(hex[d]))
    shift = shift - 4
  result.add(byte('\r'))
  result.add(byte('\n'))
  result.add(A)
  result.add(byte('\r'))
  result.add(byte('\n'))

proc encodeLastChunk*(): ByteSeq {.role: dataWriter,
    metaTags: {tagProtocol, tagWrite}.} =
  ## Terminating zero-length chunk plus the empty trailer line.
  result = @[byte('0'), byte('\r'), byte('\n'), byte('\r'), byte('\n')]
