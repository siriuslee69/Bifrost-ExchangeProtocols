## -------------------------------------------------------------------------
## Restriction store <- the restriction book, saved and read back through Geist
## -------------------------------------------------------------------------
##
## The book is small and changes only when a device sends an update, so it is
## kept as ONE row in a Geist store: key "book", body the encoded book. Every
## save rewrites that row and publishes a new generation, so a crash leaves
## the previous book in place. A relay opened on a folder that was never
## written starts from an empty book, which is the rmOpen default.

import std/os

import runePragmas
import geist
import ./restriction

type
  ## BookRow: the one row a store holds for a relay.
  BookRow* {.role: truthState.} = object
    key*: string
    body*: string

const
  bookRowKey* = "book"

proc bytesText(A: ByteSeq): string {.role: helper.} =
  ## A: bytes as text, for the row. Geist stores text as raw bytes.
  result = newString(A.len)
  var
    i: int = 0
  while i < A.len:
    result[i] = char(A[i])
    i = i + 1

proc textBytes(s: string): ByteSeq {.role: helper.} =
  ## s: the stored text as bytes again.
  result = newSeq[uint8](s.len)
  var
    i: int = 0
  while i < s.len:
    result[i] = uint8(ord(s[i]))
    i = i + 1

proc saveRestrictionBook*(dir: string, B: RestrictionBook): tuple[ok: bool,
    err: string] {.role: dataWriter, tag: "storageIo|write".} =
  ## dir/B: the folder the relay keeps its state in, and the book to keep.
  var
    db: Session = openGeist[BookRow](dir, appConfig())
    row: BookRow = BookRow(key: bookRowKey, body: bytesText(encodeBook(B)))
    ids: seq[RowId] = db.findIds("key", bookRowKey)
    saved: tuple[ok: bool, err: string] = (false, "")
  try:
    if ids.len > 0:
      discard db.set(ids[0], row)
    else:
      discard db.put(row)
    saved = db.save()
    if not saved.ok:
      result.err = saved.err
    else:
      result.ok = true
  except CatchableError as e:
    result.err = e.msg
  db.close()

proc loadRestrictionBook*(dir: string): tuple[ok: bool, found: bool,
    book: RestrictionBook, err: string] {.role: parser, tag: "storageIo|read".} =
  ## dir: the folder the relay keeps its state in. found false when nothing
  ## was ever saved there; the book is then empty and the relay starts open.
  var
    db: Session
    rows: seq[BookRow] = @[]
    got: tuple[ok: bool, book: RestrictionBook, err: string] = (false,
      RestrictionBook(), "")
  result.ok = true
  if not dirExists(dir):
    return
  try:
    db = openGeist[BookRow](dir, appConfig())
    rows = find[BookRow](db, "key", bookRowKey)
    db.close()
  except CatchableError as e:
    result.ok = false
    result.err = e.msg
    return
  if rows.len == 0:
    return
  got = decodeBook(textBytes(rows[0].body))
  if not got.ok:
    result.ok = false
    result.err = "saved restriction book is damaged: " & got.err
    return
  result.found = true
  result.book = got.book
