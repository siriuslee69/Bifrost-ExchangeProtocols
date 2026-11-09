## -------------------------------------------------------------------------
## Archive Body <- what is inside one sealed log record, as bytes
## -------------------------------------------------------------------------
##
## ╭─ ❧ Def. 1: the body 🌊
##
##   offset 0      1          9       10
##          +------+----------+-------+-----------------------------+
##          | kind | timeMs   | flags | content (depends on kind)   |
##          | u8   | u64      | u8    |                             |
##          +------+----------+-------+-----------------------------+
##
##   flags bit 0: padded. The body was filled up to whole 64-byte blocks; the
##   last byte says how many filler bytes there are, 1 to 64.
##
## ╭─ ❧ Def. 2: the kinds 🍣
##
##   kind  name        content
##   ----  ----------  ------------------------------------------------------
##   1     text        UTF-8 text, the rest of the body
##   2     attachment  fileId 16 | fileKey 32 | size u64 | u16+name | u16+media
##   3     edit        position 12 | new UTF-8 text
##   4     delete      position 12
##   5     seen        count u8 | count x position 12
##   6     lanes       count u8 | count x lane u32
##
##   `position` is level0/records.nim Def. 4.
##
## Example 1. The text "hi" at timeMs 1, not padded:
##
##   01 | 01 00 00 00 00 00 00 00 | 00 | 68 69

import ../../types
import ../../ame/level0/bytes
import ../types
import ./records
import runePragmas

const
  archivePadBlock* = 64
  archiveBodyHeaderBytes* = 10
  archiveFileIdBytes* = 16

type
  ArchiveBodyKind* = enum
    abkText = 1,
    abkAttachment = 2,
    abkEdit = 3,
    abkDelete = 4,
    abkSeen = 5,
    abkLanes = 6

  ArchiveAttachment* {.role: preparedData, tag: "archive|types".} = object
    ## Where a file lies and the key that opens it (level2/files.nim).
    fileId*: ByteSeq
    fileKey*: ByteSeq
    size*: uint64
    name*: string
    media*: string

  ArchiveBody* {.role: preparedData, tag: "archive|types".} = object
    ## One opened message. Which fields mean anything depends on `kind`.
    kind*: ArchiveBodyKind
    timeMs*: uint64
    text*: string
    target*: ArchivePosition
      ## edit and delete: the message they change
    seen*: seq[ArchivePosition]
    lanes*: seq[uint32]
    file*: ArchiveAttachment

proc textBytesOf(s: string): ByteSeq {.role: helper, inline.} =
  ## s: its bytes.
  result = @(toOpenArrayByte(s, 0, s.len - 1))

proc textOfBytes(A: openArray[uint8]): string {.role: helper.} =
  ## A: the same bytes as text.
  result = newString(A.len)
  if A.len > 0:
    copyMem(addr result[0], unsafeAddr A[0], A.len)

proc appendSizedText(A: var ByteSeq, s: string) {.role: dataWriter, inline.} =
  ## A/s: s with its u16 length in front.
  requireAmeU16Len(s.len, "archive text field")
  appendAmeU16(A, uint16(s.len))
  appendAmeBytes(A, textBytesOf(s))

proc takeSizedText(A: openArray[uint8], o: var int): string {.role: parser.} =
  ## A/o: a u16-sized text at o; o moves past it. Raises when it runs out.
  var
    n: int = 0
  if o + 2 > A.len:
    raise newException(ValueError, "archive body is short")
  n = int(readAmeU16(A, o))
  if o + 2 + n > A.len:
    raise newException(ValueError, "archive body is short")
  result = textOfBytes(A.toOpenArray(o + 2, o + 2 + n - 1))
  o = o + 2 + n

proc appendBodyContent(A: var ByteSeq, B: ArchiveBody) {.role: dataWriter.} =
  ## A/B: Def. 2, the content of this kind.
  case B.kind
  of abkText:
    appendAmeBytes(A, textBytesOf(B.text))
  of abkAttachment:
    if B.file.fileId.len != archiveFileIdBytes or
        B.file.fileKey.len != archiveKeyBytes:
      raise newException(ValueError, "archive attachment needs a file id and key")
    appendAmeBytes(A, B.file.fileId)
    appendAmeBytes(A, B.file.fileKey)
    appendAmeU64(A, B.file.size)
    appendSizedText(A, B.file.name)
    appendSizedText(A, B.file.media)
  of abkEdit:
    appendAmeBytes(A, encodeArchivePosition(B.target))
    appendAmeBytes(A, textBytesOf(B.text))
  of abkDelete:
    appendAmeBytes(A, encodeArchivePosition(B.target))
  of abkSeen:
    if B.seen.len > 255:
      raise newException(ValueError, "archive seen list holds at most 255")
    A.add(uint8(B.seen.len))
    for p in B.seen: appendAmeBytes(A, encodeArchivePosition(p))
  of abkLanes:
    if B.lanes.len > 255:
      raise newException(ValueError, "archive lane list holds at most 255")
    A.add(uint8(B.lanes.len))
    for l in B.lanes: appendAmeU32(A, l)

proc encodeArchiveBody*(B: ArchiveBody, padded: bool = true): ByteSeq {.
    role: dataWriter, tag: "archive|wire".} =
  ## B: the message. padded: Def. 1, so the server sees sizes in 64-byte steps.
  var
    fill: int = 0
    i: int = 0
  result.add(uint8(ord(B.kind)))
  appendAmeU64(result, B.timeMs)
  result.add(if padded: 1'u8 else: 0'u8)
  appendBodyContent(result, B)
  if not padded:
    return
  fill = archivePadBlock - (result.len mod archivePadBlock)
  while i < fill - 1:
    result.add(0'u8)
    i = i + 1
  result.add(uint8(fill))

proc positionAt(A: openArray[uint8], o: int): ArchivePosition {.role: parser.} =
  ## A/o: one position at o. Raises when it runs out.
  if o + archivePositionBytes > A.len:
    raise newException(ValueError, "archive body is short")
  result = decodeArchivePosition(A.toOpenArray(o, o + archivePositionBytes - 1))

proc countedPart(A: openArray[uint8], width: int): int {.role: parser.} =
  ## A/width: the count byte of a seen or lanes body, checked against what follows.
  if A.len < 1 or 1 + int(A[0]) * width > A.len:
    raise newException(ValueError, "archive body is short")
  result = int(A[0])

proc readAttachment(C: openArray[uint8]): ArchiveAttachment {.role: parser.} =
  ## C: the content of an attachment body.
  var
    o: int = archiveFileIdBytes + archiveKeyBytes + 8
  if C.len < o:
    raise newException(ValueError, "archive body is short")
  result.fileId = @(C.toOpenArray(0, archiveFileIdBytes - 1))
  result.fileKey = @(C.toOpenArray(archiveFileIdBytes, o - 9))
  result.size = readAmeU64(C, o - 8)
  result.name = takeSizedText(C, o)
  result.media = takeSizedText(C, o)

proc readBodyContent(R: var ArchiveBody, C: openArray[uint8]) {.role: parser.} =
  ## R: kind already set. C: the content.
  var
    i: int = 0
    n: int = 0
  case R.kind
  of abkText: R.text = textOfBytes(C)
  of abkAttachment: R.file = readAttachment(C)
  of abkEdit:
    R.target = positionAt(C, 0)
    R.text = textOfBytes(C.toOpenArray(archivePositionBytes, C.len - 1))
  of abkDelete: R.target = positionAt(C, 0)
  of abkSeen:
    n = countedPart(C, archivePositionBytes)
    while i < n:
      R.seen.add(positionAt(C, 1 + i * archivePositionBytes))
      i = i + 1
  of abkLanes:
    n = countedPart(C, 4)
    while i < n:
      R.lanes.add(uint32(C[1 + i * 4]) or (uint32(C[2 + i * 4]) shl 8) or
        (uint32(C[3 + i * 4]) shl 16) or (uint32(C[4 + i * 4]) shl 24))
      i = i + 1

proc bodyEnd(A: openArray[uint8]): int {.role: parser.} =
  ## A: a body. Where its content ends once the padding of Def. 1 is gone.
  var
    fill: int = 0
  result = A.len
  if (A[9] and 1'u8) == 0'u8:
    return
  fill = int(A[^1])
  if fill < 1 or fill > archivePadBlock or A.len - fill < archiveBodyHeaderBytes:
    raise newException(ValueError, "archive body has bad padding")
  result = A.len - fill

proc decodeArchiveBody*(A: openArray[uint8]): ArchiveBody {.role: parser,
    tag: "archive|wire".} =
  ## A: an opened body. Raises on anything malformed.
  if A.len < archiveBodyHeaderBytes or int(A[0]) < ord(low(ArchiveBodyKind)) or
      int(A[0]) > ord(high(ArchiveBodyKind)):
    raise newException(ValueError, "archive body has an unknown kind")
  result.kind = ArchiveBodyKind(A[0])
  result.timeMs = readAmeU64(A, 1)
  readBodyContent(result, A.toOpenArray(archiveBodyHeaderBytes, bodyEnd(A) - 1))
