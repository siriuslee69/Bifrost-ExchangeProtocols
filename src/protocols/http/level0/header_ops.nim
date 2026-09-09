## -----------------------------------------------------------------
## HTTP Header Ops <- case-insensitive lookup and strict field checks
## -----------------------------------------------------------------
##
## HTTP field names ignore case, so `Content-Type` and `content-type`
## are the same field. Values do not ignore case. Every helper here
## folds the name and leaves the value alone.
##
##   headers = [ ("Host", "a.example"), ("Accept", "*/*") ]
##            getHeader(headers, "HOST")  -> "a.example"
##            hasHeader(headers, "accept") -> true
##
## The validators exist because a header name containing a colon, or a
## value containing a newline, lets an attacker inject a second header
## or a second whole message into whatever we forward or log.

import std/strutils
import ../types
import runePragmas

proc lowerAscii(c: char): char {.inline, role: helper,
    tag: "protocol|formatting".} =
  ## c: single byte to fold to lowercase.
  if c >= 'A' and c <= 'Z': char(ord(c) + 32) else: c

proc httpNamesEqual*(a: string; b: string): bool {.role: parser,
    tag: "protocol|validation".} =
  ## a/b: two field names to compare ignoring ASCII case.
  var
    i: int = 0
  if a.len != b.len:
    return false
  while i < a.len:
    if lowerAscii(a[i]) != lowerAscii(b[i]):
      return false
    i = i + 1
  result = true

proc getHeader*(H: HttpHeaders; n: string; d: string = ""): string {.
    role: parser, tag: "protocol|read".} =
  ## H/n/d: header list, field name to find, value returned when absent.
  ##
  ## Returns the first match. Use `getHeaderAll` when a field may
  ## legitimately repeat.
  var
    i: int = 0
  while i < H.len:
    if httpNamesEqual(H[i].name, n):
      return H[i].value
    i = i + 1
  result = d

proc getHeaderAll*(H: HttpHeaders; n: string): seq[string] {.role: parser,
    tag: "protocol|read".} =
  ## H/n: header list and field name to collect every value for.
  var
    i: int = 0
  result = @[]
  while i < H.len:
    if httpNamesEqual(H[i].name, n):
      result.add(H[i].value)
    i = i + 1

proc hasHeader*(H: HttpHeaders; n: string): bool {.role: parser,
    tag: "protocol|read".} =
  ## H/n: header list and field name to test for presence.
  var
    i: int = 0
  while i < H.len:
    if httpNamesEqual(H[i].name, n):
      return true
    i = i + 1
  result = false

proc countHeader*(H: HttpHeaders; n: string): int {.role: parser,
    tag: "protocol|read".} =
  ## H/n: header list and field name to count occurrences of.
  var
    i: int = 0
  result = 0
  while i < H.len:
    if httpNamesEqual(H[i].name, n):
      result = result + 1
    i = i + 1

proc addHeader*(H: var HttpHeaders; n: string; v: string) {.role: dataWriter,
    tag: "protocol|write".} =
  ## H/n/v: header list to append to, field name, field value.
  ##
  ## Appends without touching any existing field of the same name.
  H.add(HttpHeader(name: n, value: v))

proc setHeader*(H: var HttpHeaders; n: string; v: string) {.role: dataWriter,
    tag: "protocol|write".} =
  ## H/n/v: header list to update, field name, replacement value.
  ##
  ## Replaces the first match in place and drops any later duplicates,
  ## so the field is left appearing exactly once.
  var
    i: int = 0
    found: bool = false
    keep: HttpHeaders = @[]
  while i < H.len:
    if httpNamesEqual(H[i].name, n):
      if not found:
        found = true
        keep.add(HttpHeader(name: n, value: v))
    else:
      keep.add(H[i])
    i = i + 1
  if not found:
    keep.add(HttpHeader(name: n, value: v))
  H = keep

proc delHeader*(H: var HttpHeaders; n: string) {.role: dataWriter,
    tag: "protocol|write".} =
  ## H/n: header list to prune and field name to remove entirely.
  var
    i: int = 0
    keep: HttpHeaders = @[]
  while i < H.len:
    if not httpNamesEqual(H[i].name, n):
      keep.add(H[i])
    i = i + 1
  H = keep

proc isTokenChar(c: char): bool {.inline, role: parser,
    tag: "protocol|validation".} =
  ## c: byte to test against the RFC 9110 `tchar` set.
  case c
  of 'a'..'z', 'A'..'Z', '0'..'9',
     '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.',
     '^', '_', '`', '|', '~':
    true
  else:
    false

proc isValidHeaderName*(n: string): bool {.role: sanitizer,
    tag: "protocol|validation".} =
  ## n: candidate field name to validate.
  ##
  ## A name is a non-empty run of token characters. Rejecting anything
  ## else is what stops `X-Evil: a\r\nX-Admin` from ever becoming two
  ## headers downstream.
  var
    i: int = 0
  if n.len == 0:
    return false
  while i < n.len:
    if not isTokenChar(n[i]):
      return false
    i = i + 1
  result = true

proc isValidHeaderValue*(v: string): bool {.role: sanitizer,
    tag: "protocol|validation".} =
  ## v: candidate field value to validate.
  ##
  ## Printable bytes, horizontal tab, and high-range bytes are allowed.
  ## CR, LF, and NUL are not, at any position.
  var
    i: int = 0
    c: char = '\0'
  while i < v.len:
    c = v[i]
    if c == '\r' or c == '\n' or c == '\0':
      return false
    if ord(c) < 32 and c != '\t':
      return false
    i = i + 1
  result = true

proc trimFieldValue*(v: string): string {.role: sanitizer,
    tag: "protocol|formatting".} =
  ## v: raw field value to strip of surrounding spaces and tabs.
  var
    a: int = 0
    b: int = v.len - 1
  while a <= b and (v[a] == ' ' or v[a] == '\t'):
    a = a + 1
  while b >= a and (v[b] == ' ' or v[b] == '\t'):
    b = b - 1
  if a > b:
    return ""
  result = v[a .. b]

proc headerHasToken*(H: HttpHeaders; n: string; t: string): bool {.
    role: parser, tag: "protocol|validation".} =
  ## H/n/t: header list, field name, and comma-separated token to find.
  ##
  ## `Connection: keep-alive, Upgrade` holds two tokens; this finds
  ## either one without matching a longer word that merely contains it.
  var
    A: seq[string] = @[]
    P: seq[string] = @[]
    i: int = 0
    j: int = 0
  A = getHeaderAll(H, n)
  while i < A.len:
    P = A[i].split(',')
    j = 0
    while j < P.len:
      if httpNamesEqual(trimFieldValue(P[j]), t):
        return true
      j = j + 1
    i = i + 1
  result = false
