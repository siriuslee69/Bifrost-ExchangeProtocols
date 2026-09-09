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
import runePragmas

type
  ChunkedDecodeState* = enum
    ## Position inside the chunked grammar.
    cdsSize,        ## reading the `1a;ext\r\n` line
    cdsData,        ## copying `remaining` payload bytes
    cdsDataCrLf,    ## consuming the `\r\n` that closes a chunk
    cdsTrailer,     ## reading trailer lines after the final chunk
    cdsDone,        ## body complete
    cdsError        ## framing broken; connection must close

  ChunkedDecoder* {.role: memory, tag: "protocol|parsing".} = object
    state*: ChunkedDecodeState
    remaining*: int64
      ## Payload bytes still owed for the chunk being read.
    line*: string
      ## Partial size or trailer line held across feeds.
    totalBytes*: int64
      ## Decoded payload bytes produced so far, for the size cap.
    err*: string

  ChunkedFeedResult* {.role: truthState, tag: "protocol|parsing".} =
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
    tag: "protocol|parsing".} =
  ## Build a decoder sitting at the first chunk-size line.
  result.state = cdsSize
  result.remaining = 0
  result.line = ""
  result.totalBytes = 0
  result.err = ""

proc onlyBlanksLeft(l: string, start, stop: int): bool {.inline,
    role: parser, tag: "protocol|parsing|validation".} =
  ## l/start/stop: is everything from `start` to `stop` a space or a tab?
  var
    i: int = start
  while i < stop:
    if l[i] != ' ' and l[i] != '\t':
      return false
    i = i + 1
  result = true

proc parseChunkSize(l: string): tuple[ok: bool, size: int64] {.role: parser,
    tag: "protocol|parsing|validation".} =
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
      ## Trailing spaces before the extension separator are tolerated, but a
      ## digit may never follow them -- otherwise "1 2" would read as 0x12.
      if not onlyBlanksLeft(l, i, stop):
        return (false, 0'i64)
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
    tag: "protocol|parsing".} =
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

## ╭⟢ one state at a time
##
## The decoder is a four-state machine, and it used to be written as one
## loop holding a case holding the whole of every state. Each state is now
## its own step. Every one returns "stop reading" -- because the input ran
## out mid-item, or because the stream is bad -- so the loop below is only
## the walk between states.

proc failChunked(D: var ChunkedDecoder, why: string) {.inline,
    role: actor, tag: "protocol|validation".} =
  ## D/why: end the stream, and say why once rather than at five sites.
  D.state = cdsError
  D.err = why

proc stepChunkSize(D: var ChunkedDecoder; A: openArray[byte]; i: var int;
    maxBodyBytes: int64): bool {.inline, role: parser,
    tag: "protocol|parsing|validation".} =
  ## D/A/i/maxBodyBytes: read one chunk-size line and size the next chunk.
  var
    line: tuple[have: bool, bad: bool] = takeLine(D, A, i, httpMaxChunkLineLen)
    size: tuple[ok: bool, size: int64] = (ok: false, size: 0'i64)
  if line.bad:
    failChunked(D, "chunk size line too long")
    return true
  if not line.have:
    return true
  size = parseChunkSize(D.line)
  D.line = ""
  if not size.ok:
    failChunked(D, "malformed chunk size")
    return true
  if size.size == 0:
    D.state = cdsTrailer
    return false
  ## The running total is checked BEFORE the bytes are taken, so a declared
  ## size that would cross the cap never reserves anything.
  if D.totalBytes + size.size > maxBodyBytes:
    failChunked(D, "chunked body exceeds limit")
    return true
  D.remaining = size.size
  D.state = cdsData

proc stepChunkData(D: var ChunkedDecoder; A: openArray[byte]; i: var int;
    R: var ChunkedFeedResult): bool {.inline, role: parser,
    tag: "protocol|parsing".} =
  ## D/A/i/R: take as much of the current chunk as this input holds.
  var
    take: int = A.len - i
  if int64(take) > D.remaining:
    take = int(D.remaining)
  if take > 0:
    R.data.add(A[i ..< i + take])
    i = i + take
    D.remaining = D.remaining - int64(take)
    D.totalBytes = D.totalBytes + int64(take)
  if D.remaining == 0:
    D.state = cdsDataCrLf

proc stepChunkCrLf(D: var ChunkedDecoder; A: openArray[byte];
    i: var int): bool {.inline, role: parser,
    tag: "protocol|parsing|validation".} =
  ## D/A/i: the empty line that must follow a chunk's bytes.
  var
    line: tuple[have: bool, bad: bool] = takeLine(D, A, i, 4)
  if line.bad:
    failChunked(D, "missing chunk terminator")
    return true
  if not line.have:
    return true
  if D.line.len != 0:
    D.line = ""
    failChunked(D, "malformed chunk terminator")
    return true
  D.line = ""
  D.state = cdsSize

proc stepChunkTrailer(D: var ChunkedDecoder; A: openArray[byte];
    i: var int): bool {.inline, role: parser,
    tag: "protocol|parsing|validation".} =
  ## D/A/i: trailer lines, ending at the first empty one.
  var
    line: tuple[have: bool, bad: bool] = takeLine(D, A, i, httpMaxChunkLineLen)
  if line.bad:
    failChunked(D, "trailer line too long")
    return true
  if not line.have:
    return true
  if D.line.len == 0:
    D.state = cdsDone
  D.line = ""

proc feedChunked*(D: var ChunkedDecoder; A: openArray[byte];
    maxBodyBytes: int64): ChunkedFeedResult {.role: orchestrator,
    tag: "protocol|parsing|validation".} =
  ## D/A/maxBodyBytes: decoder state, next input bytes, decoded size cap.
  ##
  ## Consumes as much of `A` as the grammar allows and returns whatever
  ## payload that produced. Call again with more bytes while `done` is
  ## false and `ok` is true.
  var
    i: int = 0
    stop: bool = false
  result.ok = true
  result.data = @[]
  if D.state == cdsDone:
    return ChunkedFeedResult(ok: true, consumed: 0, data: @[], done: true,
      err: "")
  if D.state == cdsError:
    return ChunkedFeedResult(ok: false, consumed: 0, data: @[], done: false,
      err: D.err)
  while i < A.len and D.state notin {cdsDone, cdsError} and not stop:
    case D.state
    of cdsSize: stop = stepChunkSize(D, A, i, maxBodyBytes)
    of cdsData: stop = stepChunkData(D, A, i, result)
    of cdsDataCrLf: stop = stepChunkCrLf(D, A, i)
    of cdsTrailer: stop = stepChunkTrailer(D, A, i)
    else: stop = true
  result.consumed = i
  result.done = D.state == cdsDone
  if D.state == cdsError:
    result.ok = false
    result.err = D.err

proc encodeChunk*(A: openArray[byte]): ByteSeq {.role: dataWriter,
    tag: "protocol|write".} =
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
    tag: "protocol|write".} =
  ## Terminating zero-length chunk plus the empty trailer line.
  result = @[byte('0'), byte('\r'), byte('\n'), byte('\r'), byte('\n')]
