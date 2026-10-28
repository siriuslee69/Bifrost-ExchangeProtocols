## -------------------------------------------------------------------------
## Restriction address <- one source address in as few bytes as it needs
## -------------------------------------------------------------------------
##
## Every restriction mode compares source addresses, so they are kept in a
## compact form. The relay converts a neighbour's address ONCE, when the
## neighbour is admitted, and compares bytes after that:
##
##   IPv4   a packed tuple of four uint8:  (10, 0, 0, 49)          4 bytes
##   IPv6   sixteen uint8, network order:  2001:db8::1             16 bytes
##   port   uint16; 0 matches any port
##   family 0 matches any host (text "*"), 4 is IPv4, 6 is IPv6
##
## SourceAddr is a variant object: the family picks which address field exists,
## so an IPv4 entry carries no unused IPv6 bytes. A list of them is a seq of
## fixed-width records, the smallest form that stays a plain sequence.
##
## Def. 1: a text address is written as dotted quad for IPv4 and as the usual
##   colon form for IPv6, with "::" for one run of zero groups. An IPv6 address
##   with an IPv4 tail (::ffff:10.0.0.1) is accepted.

import std/strutils

import runePragmas
import ../transport/types as transport_types

type
  Ipv4* = tuple[a, b, c, d: uint8]
  Ipv6* = array[16, uint8]

  SourceAddr* {.role: truthState.} = object
    port*: uint16
    case family*: uint8
    of 4: v4*: Ipv4
    of 6: v6*: Ipv6
    else: discard

proc `==`*(a, b: SourceAddr): bool {.role: parser.} =
  ## Equal when the family, the port, and the one address field that family
  ## uses all match. Nim does not derive `==` for variant objects.
  if a.family != b.family or a.port != b.port:
    return false
  case a.family
  of 4: result = a.v4 == b.v4
  of 6: result = a.v6 == b.v6
  else: result = true

proc anySource*(port: uint16 = 0'u16): SourceAddr {.role: configurator.} =
  ## Matches every address (and port, when port is 0).
  result = SourceAddr(family: 0, port: port)

proc parseIpv4*(s: string): tuple[ok: bool, ip: Ipv4] {.role: sanitizer.} =
  ## s: "a.b.c.d", each part 0 to 255. Anything else is not ok.
  var
    parts: seq[string] = s.split('.')
    vals: array[4, int] = [0, 0, 0, 0]
    i: int = 0
  if parts.len != 4:
    return
  while i < 4:
    if parts[i].len == 0 or parts[i].len > 3 or not parts[i].allCharsInSet(Digits):
      return
    vals[i] = parseInt(parts[i])
    if vals[i] > 255:
      return
    i = i + 1
  result.ip = (uint8(vals[0]), uint8(vals[1]), uint8(vals[2]), uint8(vals[3]))
  result.ok = true

proc parseHextet(s: string): tuple[ok: bool, v: uint16] {.role: sanitizer.} =
  ## s: one group of 1 to 4 hex digits.
  var
    n: int = 0
  if s.len == 0 or s.len > 4 or not s.allCharsInSet(HexDigits):
    return
  for c in s:
    n = n * 16 + (if c in Digits: ord(c) - ord('0') else: ord(toLowerAscii(c)) - ord('a') + 10)
  result.v = uint16(n)
  result.ok = true

proc parseIpv6*(s: string): tuple[ok: bool, ip: Ipv6] {.role: sanitizer.} =
  ## s: an IPv6 address in text form. Not ok when it does not parse.
  var
    groups: array[8, uint16] = [0'u16, 0, 0, 0, 0, 0, 0, 0]
    head: seq[string] = @[]
    tail: seq[string] = @[]
    dbl: int = s.find("::")
    left: string = if dbl >= 0: s[0 ..< dbl] else: s
    right: string = if dbl >= 0: s[dbl + 2 .. ^1] else: ""
    headN: int = 0
    tailN: int = 0
    hx: tuple[ok: bool, v: uint16] = (false, 0'u16)
    v4: tuple[ok: bool, ip: Ipv4] = (false, (0'u8, 0'u8, 0'u8, 0'u8))
    k: int = 0
  if dbl >= 0 and s.find("::", dbl + 1) >= 0:
    return
  if left.len > 0:
    head = left.split(':')
  if right.len > 0:
    tail = right.split(':')
  # An IPv4 tail counts as two groups, and only at the very end.
  if tail.len > 0 and tail[^1].contains('.'):
    v4 = parseIpv4(tail[^1])
    if not v4.ok:
      return
    tail[^1] = "0"
    tail.add "0"
  elif dbl < 0 and head.len > 0 and head[^1].contains('.'):
    v4 = parseIpv4(head[^1])
    if not v4.ok:
      return
    head[^1] = "0"
    head.add "0"
  headN = head.len
  tailN = tail.len
  if dbl < 0 and headN != 8:
    return
  if dbl >= 0 and headN + tailN > 7:
    return
  for g in head:
    hx = parseHextet(g)
    if not hx.ok:
      return
    groups[k] = hx.v
    k = k + 1
  if dbl >= 0:
    k = 8 - tailN
  for g in tail:
    hx = parseHextet(g)
    if not hx.ok:
      return
    groups[k] = hx.v
    k = k + 1
  if v4.ok:
    groups[6] = (uint16(v4.ip.a) shl 8) or uint16(v4.ip.b)
    groups[7] = (uint16(v4.ip.c) shl 8) or uint16(v4.ip.d)
  k = 0
  while k < 8:
    result.ip[2 * k] = uint8(groups[k] shr 8)
    result.ip[2 * k + 1] = uint8(groups[k] and 0xFF'u16)
    k = k + 1
  result.ok = true

proc sourceOf*(host: string, port: uint16): tuple[ok: bool, src: SourceAddr,
    err: string] {.role: sanitizer.} =
  ## host/port: a rule or neighbour address as text. The text "*" is any host.
  ## A host with a colon is IPv6, otherwise it must be dotted-quad IPv4.
  if host == "*":
    result.ok = true
    result.src = SourceAddr(family: 0, port: port)
    return
  if host.contains(':'):
    var v6 = parseIpv6(host)
    if not v6.ok:
      result.err = "not an IPv6 address: " & host
      return
    result.src = SourceAddr(family: 6, port: port, v6: v6.ip)
    result.ok = true
    return
  var v4 = parseIpv4(host)
  if not v4.ok:
    result.err = "not an IPv4 address: " & host
    return
  result.src = SourceAddr(family: 4, port: port, v4: v4.ip)
  result.ok = true

proc sourceOfAddress*(a: transport_types.UdpAddress): tuple[ok: bool,
    src: SourceAddr, err: string] {.role: sanitizer.} =
  ## a: the address a neighbour's datagrams arrive from.
  result = sourceOf(a.host, a.port)

proc sourceMatches*(rule, src: SourceAddr): bool {.role: parser.} =
  ## rule/src: true when the rule names the address a datagram came from.
  ## Family 0 matches any host. Port 0 matches any port.
  case rule.family
  of 0:
    discard
  of 4:
    if src.family != 4'u8:
      return false
    if rule.v4 != src.v4:
      return false
  of 6:
    if src.family != 6'u8:
      return false
    if rule.v6 != src.v6:
      return false
  else:
    return false
  if rule.port != 0'u16 and rule.port != src.port:
    return false
  result = true

proc formatIpv6(A: Ipv6): string {.role: helper.} =
  ## A: the sixteen bytes as eight groups of four lower-case hex digits. Written
  ## out in full, so nothing is compressed and two addresses compare by eye.
  var
    parts: seq[string] = @[]
    i: int = 0
  while i < 8:
    parts.add toHex((int(A[2 * i]) shl 8) or int(A[2 * i + 1]), 4).toLowerAscii()
    i = i + 1
  result = parts.join(":")

proc formatSource*(s: SourceAddr): string {.role: helper.} =
  ## s: the address as text, for an error message or a log line.
  case s.family
  of 0: result = "*"
  of 4: result = $s.v4.a & "." & $s.v4.b & "." & $s.v4.c & "." & $s.v4.d
  of 6: result = formatIpv6(s.v6)
  else: result = "?"
  if s.port != 0'u16:
    result = (if s.family == 6: "[" & result & "]" else: result) & ":" & $s.port
