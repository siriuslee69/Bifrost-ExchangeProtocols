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
import ../../../analysis_pragmas

proc hexDigitValue(c: char): int {.inline, role: parser,
    tag: {tagProtocol, tagParsing}.} =
  ## c: single hex digit; returns -1 when it is not one.
  case c
  of '0'..'9': ord(c) - ord('0')
  of 'a'..'f': ord(c) - ord('a') + 10
  of 'A'..'F': ord(c) - ord('A') + 10
  else: -1

proc percentDecode*(s: string): tuple[ok: bool, value: string] {.
    role: sanitizer, tag: {tagProtocol, tagParsing, tagValidation}.} =
  ## s: percent-encoded text to decode.
  ##
  ## Fails closed on a truncated or non-hex escape rather than passing
  ## the raw `%` through, so `%` can never survive into a filesystem path.
  ## A decoded NUL byte is also refused: it truncates C-side path handling.
  var
    i: int = 0
    hi: int = 0
    lo: int = 0
    t: string = ""
  while i < s.len:
    if s[i] == '%':
      if i + 2 >= s.len:
        return (false, "")
      hi = hexDigitValue(s[i + 1])
      lo = hexDigitValue(s[i + 2])
      if hi < 0 or lo < 0:
        return (false, "")
      if hi == 0 and lo == 0:
        return (false, "")
      t.add(char(hi * 16 + lo))
      i = i + 3
    elif s[i] == '+':
      t.add('+')
      i = i + 1
    else:
      if s[i] == '\0':
        return (false, "")
      t.add(s[i])
      i = i + 1
  result = (true, t)

proc percentDecodeForm*(s: string): tuple[ok: bool, value: string] {.
    role: sanitizer, tag: {tagProtocol, tagParsing}.} =
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
    role: parser, tag: {tagProtocol, tagParsing}.} =
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
    tag: {tagProtocol, tagParsing}.} =
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

proc normalizeHttpPath*(p: string): tuple[ok: bool, path: string] {.
    role: sanitizer, tag: {tagProtocol, tagValidation}.} =
  ## p: already percent-decoded path to normalise.
  ##
  ## Collapses repeated separators, drops `.`, and pops one segment for
  ## each `..`. Reports `ok = false` when a `..` would climb above the
  ## root, and when a backslash appears (Windows treats `\` as a
  ## separator, so allowing it would reopen traversal on that platform).
  var
    S: seq[string] = @[]
    seg: string = ""
    i: int = 0
    c: char = '\0'
    trailing: bool = false

  proc flushSegment(): bool {.closure.} =
    ## Fold one finished segment into the stack. False means escape.
    if seg.len == 0 or seg == ".":
      seg = ""
      return true
    if seg == "..":
      if S.len == 0:
        return false
      S.setLen(S.len - 1)
      seg = ""
      return true
    S.add(seg)
    seg = ""
    result = true

  if p.len == 0:
    return (true, "/")
  while i < p.len:
    c = p[i]
    if c == '\\':
      return (false, "")
    if c == '/':
      if not flushSegment():
        return (false, "")
    else:
      seg.add(c)
    i = i + 1
  trailing = p.len > 0 and p[^1] == '/'
  if not flushSegment():
    return (false, "")
  if S.len == 0:
    return (true, "/")
  i = 0
  seg = ""
  while i < S.len:
    seg.add('/')
    seg.add(S[i])
    i = i + 1
  if trailing:
    seg.add('/')
  result = (true, seg)

proc parseQueryParams*(q: string): seq[HttpQueryParam] {.role: parser,
    tag: {tagProtocol, tagParsing}.} =
  ## q: raw query string, `?` already removed.
  ##
  ## A key with no `=` yields an empty value. Pairs that fail to decode
  ## are skipped rather than failing the whole request, because one bad
  ## parameter should not cost the client its page.
  var
    i: int = 0
    start: int = 0
    piece: string = ""
    eq: int = 0
    k: tuple[ok: bool, value: string]
    v: tuple[ok: bool, value: string]
  result = @[]
  if q.len == 0:
    return
  while i <= q.len:
    if i == q.len or q[i] == '&':
      if i > start:
        piece = q[start ..< i]
        eq = piece.find('=')
        if eq < 0:
          k = percentDecodeForm(piece)
          if k.ok and k.value.len > 0:
            result.add(HttpQueryParam(key: k.value, value: ""))
        else:
          k = percentDecodeForm(piece[0 ..< eq])
          v = percentDecodeForm(piece[eq + 1 .. ^1])
          if k.ok and v.ok and k.value.len > 0:
            result.add(HttpQueryParam(key: k.value, value: v.value))
      start = i + 1
    i = i + 1

proc getQueryParam*(P: seq[HttpQueryParam]; k: string;
    d: string = ""): string {.role: parser, tag: {tagProtocol, tagRead}.} =
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
    tag: {tagProtocol, tagParsing, tagValidation}.} =
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
