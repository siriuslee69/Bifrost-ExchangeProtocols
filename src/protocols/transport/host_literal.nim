## -------------------------------------------------------------------
## Host Literal <- host text as the TCP and UDP helpers both read it
## -------------------------------------------------------------------
##
## One copy for both `tcp_ops` and `udp_ops`.
##
##   normalizeHostLiteral("  [::1] ")  ->  "::1"      brackets and blanks go
##   normalizeHostLiteral("10.0.0.7")  ->  "10.0.0.7" nothing to remove
##
## A listener on "::" (every IPv6 address) can also take IPv4 clients, when
## the system is asked to: `maybeEnableDualStackWildcard`. The two sockets
## below are the same socket seen twice:
##
##   [ listener on "::" ] <- IPv6 client
##   [ dual-stack on    ] <- IPv4 client, shown as ::ffff:a.b.c.d

import std/[net, nativesockets, strutils]
when not defined(windows):
  import std/posix

import runePragmas

proc normalizeHostLiteral*(h: string): string {.role: parser.} =
  ## h: a host text, maybe with blanks or the [ ] of an IPv6 literal.
  ## Returns the host with both removed.
  result = h.strip()
  if result.len >= 2 and result[0] == '[' and result[^1] == ']':
    result = result[1 .. ^2]

proc maybeEnableDualStackWildcard*(sock: Socket, host: string) {.role: helper.} =
  ## sock: IPv6 listener candidate whose wildcard bind may need dual-stack mode.
  ## host: normalized bind host literal.
  if host != "::":
    return
  when not defined(windows):
    try:
      setSockOptInt(sock.getFd(), int(toInt(IPPROTO_IPV6)), int(posix.IPV6_V6ONLY),
        0)
    except CatchableError:
      discard
