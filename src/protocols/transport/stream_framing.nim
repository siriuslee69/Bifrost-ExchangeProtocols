## -----------------------------------------------------------------------
## Stream Framing <- bounded length-prefix helpers for protocol payloads
## -----------------------------------------------------------------------

import ../types
import ./types
import bifrostPragmas

const
  defaultStreamFrameBytes* = 16_777_216'u32
  streamFrameHeaderLen* = 4

proc appendStreamU32(dst: var ByteSeq, v: uint32) {.role: dataWriter.} =
  ## dst: destination byte sequence.
  ## v: little-endian frame length.
  dst.add(uint8(v and 0xff'u32))
  dst.add(uint8((v shr 8) and 0xff'u32))
  dst.add(uint8((v shr 16) and 0xff'u32))
  dst.add(uint8((v shr 24) and 0xff'u32))

proc readStreamU32(A: openArray[uint8], offset: int): uint32 {.role: parser.} =
  ## A: source byte buffer.
  ## offset: first length byte.
  if offset < 0 or offset > A.len - streamFrameHeaderLen:
    raise newException(ValueError, "stream frame length header is incomplete")
  result = uint32(A[offset]) or (uint32(A[offset + 1]) shl 8) or
    (uint32(A[offset + 2]) shl 16) or (uint32(A[offset + 3]) shl 24)

proc copyStreamSpan(A: openArray[uint8], offset, count: int): ByteSeq {.role: helper.} =
  ## A: source byte buffer.
  ## offset/count: span to copy.
  var
    i: int = 0
  if offset < 0 or count < 0 or offset > A.len or count > A.len - offset:
    raise newException(ValueError, "stream frame slice is out of bounds")
  result = newSeq[uint8](count)
  while i < count:
    result[i] = A[offset + i]
    i = i + 1

proc encodeProtocolStreamFrame*(payload: openArray[uint8],
    maxFrameBytes: uint32 = defaultStreamFrameBytes): ByteSeq {.role: helper.} =
  ## payload: protocol bytes to frame for a TCP/TLS byte stream.
  ## maxFrameBytes: caller-side maximum accepted payload length.
  if uint64(payload.len) > uint64(high(uint32)):
    raise newException(ValueError, "stream frame payload exceeds uint32 length")
  if uint64(payload.len) > uint64(maxFrameBytes):
    raise newException(ValueError, "stream frame payload exceeds maximum")
  appendStreamU32(result, uint32(payload.len))
  for b in payload:
    result.add(b)

proc decodeProtocolStreamFrame*(A: openArray[uint8],
    maxFrameBytes: uint32 = defaultStreamFrameBytes): ProtocolStreamFrameResult {.
    role: parser.} =
  ## A: stream buffer beginning at a frame boundary.
  ## maxFrameBytes: maximum accepted payload length.
  var
    n: uint32 = 0
    total: int = 0
  if A.len < streamFrameHeaderLen:
    result.needMore = true
    result.err = "need stream frame length"
    return
  n = readStreamU32(A, 0)
  if n > maxFrameBytes:
    result.ok = false
    result.needMore = false
    result.err = "stream frame length exceeds maximum"
    return
  total = streamFrameHeaderLen + int(n)
  if A.len < total:
    result.needMore = true
    result.err = "need full stream frame payload"
    return
  result.ok = true
  result.needMore = false
  result.consumed = total
  result.payload = copyStreamSpan(A, streamFrameHeaderLen, int(n))
  result.err = ""

proc decodeProtocolStreamFrames*(A: openArray[uint8],
    maxFrameBytes: uint32 = defaultStreamFrameBytes): ProtocolStreamBatchResult {.
    role: parser.} =
  ## A: stream buffer that may hold zero, one, or many frames.
  ## maxFrameBytes: maximum accepted payload length.
  var
    offset: int = 0
    one: ProtocolStreamFrameResult
  result.ok = true
  result.frames = @[]
  while offset < A.len:
    one = decodeProtocolStreamFrame(copyStreamSpan(A, offset, A.len - offset),
      maxFrameBytes)
    if one.ok:
      result.frames.add(one.payload)
      offset = offset + one.consumed
    elif one.needMore:
      result.needMore = true
      result.consumed = offset
      result.err = one.err
      return
    else:
      result.ok = false
      result.consumed = offset
      result.err = one.err
      return
  result.consumed = offset
  result.err = ""
