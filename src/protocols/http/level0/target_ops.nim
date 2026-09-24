## ------------------------------------------------------------------
## HTTP Target Ops <- request-target split, percent-decode, normalise
## ------------------------------------------------------------------
##
## The request-target is the middle field of `GET /a/b?x=1 HTTP/1.1`.
## Turning it into a safe path takes three steps, in this exact order:
##
##   1. split off the query at the first `?`
##   2. percent-decode  (`%2e` -> `.`,  `%2f` -> `/`)
##   3. normalise       (collapse `//`, resolve `.` and `..`)
##
## Doing step 3 before step 2 is the classic traversal hole: `/a/%2e%2e/b`
## looks harmless until it is decoded into `/a/../b`. Decoding first and
## normalising after means there is no encoding left to hide behind.
##
##   /files/%2e%2e%2f%2e%2e%2fetc/passwd
##        decode ->  /files/../../etc/passwd
##     normalise ->  /etc/passwd          <- escapes, so it is rejected
##
## `normalizeHttpPath` reports that escape instead of silently clamping,
## because a request that tried to climb out of the tree is a request we
## want to answer with 400, not quietly serve something else for.

import std/strutils
import ../types
import runePragmas

proc hexDigitValue(c: char): int {.inline, role: parser,
    tag: "protocol|parsing".} =
  ## c: single hex digit; returns -1 when it is not one.
  case c
  of '0'..'9': ord(c) - ord('0')
  of 'a'..'f': ord(c) - ord('a') + 10
  of 'A'..'F': ord(c) - ord('A') + 10
  else: -1

proc decodedByteAt(s: string, i: int): tuple[value, step: int] {.inline,
    role: parser, tag: "protocol|parsing|validation".} =
  ## s/i: the byte the text at `i` stands for, and how many characters it
  ## took. `value = -1` refuses it:
  ##
  ##   "%41"   -> 65, 3        "%4"  or "%zz" -> -1 (truncated, not hex)
  ##   "a"     -> 97, 1        "%00" or a NUL -> -1 (truncates C paths)
  var
    hi: int = -1
    lo: int = -1
  if s[i] == '\0':
    return (-1, 1)
  if s[i] != '%':
    return (ord(s[i]), 1)
  if i + 2 < s.len:
    hi = hexDigitValue(s[i + 1])
    lo = hexDigitValue(s[i + 2])
  if hi < 0 or lo < 0 or (hi == 0 and lo == 0):
    return (-1, 3)
  result = (hi * 16 + lo, 3)

proc percentDecode*(s: string): tuple[ok: bool, value: string] {.
    role: sanitizer, tag: "protocol|parsing|validation".} =
  ## s: percent-encoded text to decode.
  ##
  ## Fails closed on a truncated or non-hex escape rather than passing
  ## the raw `%` through, so `%` can never survive into a filesystem path.
  ## A decoded NUL byte is also refused: it truncates C-side path handling.
  ## `+` stays `+` here; only form decoding turns it into a space.
  var
    i: int = 0
    b: tuple[value, step: int] = (0, 0)
    t: string = ""
  while i < s.len:
    b = decodedByteAt(s, i)
    if b.value < 0:
      return (false, "")
    t.add(char(b.value))
    i = i + b.step
  result = (true, t)

proc percentDecodeForm*(s: string): tuple[ok: bool, value: string] {.
    role: sanitizer, tag: "protocol|parsing".} =
  ## s: `application/x-www-form-urlencoded` text to decode.
  ##
  ## Same as `percentDecode` except `+` means a space, which is true in
  ## query strings and form bodies but never in a path segment.
  var
    i: int = 0
    swapped: string = ""
  while i < s.len:
    if s[i] == '+':
      swapped.add(' ')
    else:
      swapped.add(s[i])
    i = i + 1
  result = percentDecode(swapped)

proc splitHttpTarget*(t: string): tuple[path: string, query: string] {.
    role: parser, tag: "protocol|parsing".} =
  ## t: raw request-target to split at its first `?`.
  ##
  ## A `#fragment` never reaches a server, but a hostile client can send
  ## one anyway, so anything from `#` onward is discarded here.
  var
    i: int = 0
    cut: int = -1
    hash: int = -1
  while i < t.len:
    if t[i] == '?' and cut < 0:
      cut = i
    if t[i] == '#':
      hash = i
      break
    i = i + 1
  if hash >= 0:
    if cut >= 0 and cut < hash:
      return (t[0 ..< cut], t[cut + 1 ..< hash])
    return (t[0 ..< hash], "")
  if cut < 0:
    return (t, "")
  result = (t[0 ..< cut], t[cut + 1 .. ^1])

proc stripAbsoluteForm*(p: string): string {.role: sanitizer,
    tag: "protocol|parsing".} =
  ## p: target path that may be in absolute form.
  ##
  ## Proxies receive `GET http://host/path HTTP/1.1`. An origin server
  ## must still cope with it, so the scheme and authority are removed and
  ## only the path is kept.
  var
    i: int = 0
    slash: int = 0
  if p.len == 0:
    return p
  if p[0] == '/':
    return p
  i = p.find("://")
  if i < 0:
    return p
  slash = p.find('/', i + 3)
  if slash < 0:
    return "/"
  result = p[slash .. ^1]

proc foldPathSegment(S: var seq[string], seg: string): bool {.role: actor,
    tag: "protocol|validation".} =
  ## S/seg: fold one segment into the path so far. False means the path
  ## climbed above the root.
  ##
  ##   ""  "."   nothing       ".."   drop the last one   else  append
  if seg.len == 0 or seg == ".":
    return true
  if seg != "..":
    S.add(seg)
    return true
  if S.len == 0:
    return false
  S.setLen(S.len - 1)
  result = true

proc normalizeHttpPath*(p: string): tuple[ok: bool, path: string] {.
    role: sanitizer, tag: "protocol|validation".} =
  ## p: already percent-decoded path to normalise.
  ##
  ## Collapses repeated separators, drops `.`, and pops one segment for
  ## each `..`. Reports `ok = false` when a `..` would climb above the
  ## root, and when a backslash appears (Windows treats `\` as a
  ## separator, so allowing it would reopen traversal on that platform).
  ##
  ##   "/a//b/./c/../d/"  ->  "/a/b/d/"      "/../x"  ->  refused
  var
    S: seq[string] = @[]
  if p.len == 0:
    return (true, "/")
  if '\\' in p:
    return (false, "")
  for seg in p.split('/'):
    if not foldPathSegment(S, seg):
      return (false, "")
  if S.len == 0:
    return (true, "/")
  result = (true, "/" & S.join("/"))
  if p[^1] == '/':
    result.path.add('/')

proc addQueryPair(P: var seq[HttpQueryParam], piece: string) {.inline,
    role: dataWriter, tag: "protocol|parsing".} =
  ## P/piece: one `key=value` (or bare `key`) between two separators.
  ##
  ## A pair that fails to decode is skipped rather than failing the whole
  ## request: one bad parameter should not cost the client its page. An
  ## empty key is skipped too, since nothing could ask for it afterwards.
  var
    eq: int = piece.find('=')
    k: tuple[ok: bool, value: string] = (ok: false, value: "")
    v: tuple[ok: bool, value: string] = (ok: true, value: "")
  if eq < 0:
    k = percentDecodeForm(piece)
  else:
    k = percentDecodeForm(piece[0 ..< eq])
    v = percentDecodeForm(piece[eq + 1 .. ^1])
  if k.ok and v.ok and k.value.len > 0:
    P.add(HttpQueryParam(key: k.value, value: v.value))

proc parseQueryParams*(q: string): seq[HttpQueryParam] {.role: parser,
    tag: "protocol|parsing".} =
  ## q: the raw query string, without the leading `?`.
  ##
  ## A key with no `=` yields an empty value. Pairs that fail to decode
  ## are skipped rather than failing the whole request, because one bad
  ## parameter should not cost the client its page.
  result = @[]
  for piece in q.split('&'):
    if piece.len > 0:
      addQueryPair(result, piece)

proc getQueryParam*(P: seq[HttpQueryParam]; k: string;
    d: string = ""): string {.role: parser, tag: "protocol|read".} =
  ## P/k/d: parsed parameters, key to find, value returned when absent.
  var
    i: int = 0
  while i < P.len:
    if P[i].key == k:
      return P[i].value
    i = i + 1
  result = d

proc parseHttpTarget*(t: string): tuple[ok: bool, path: string, query: string,
    params: seq[HttpQueryParam]] {.role: orchestrator,
    tag: "protocol|parsing|validation".} =
  ## t: raw request-target from the request line.
  ##
  ## Runs the whole split -> decode -> normalise pipeline and returns the
  ## safe path plus decoded parameters. `ok = false` means the target was
  ## hostile or malformed and the caller should answer 400.
  var
    split: tuple[path: string, query: string]
    decoded: tuple[ok: bool, value: string]
    normalized: tuple[ok: bool, path: string]
    stripped: string = ""
  if t.len == 0:
    return (false, "", "", @[])
  if t == "*":
    return (true, "*", "", @[])
  stripped = stripAbsoluteForm(t)
  if stripped.len == 0 or stripped[0] != '/':
    return (false, "", "", @[])
  split = splitHttpTarget(stripped)
  decoded = percentDecode(split.path)
  if not decoded.ok:
    return (false, "", "", @[])
  normalized = normalizeHttpPath(decoded.value)
  if not normalized.ok:
    return (false, "", "", @[])
  result = (true, normalized.path, split.query, parseQueryParams(split.query))
