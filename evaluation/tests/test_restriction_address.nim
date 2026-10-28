## -------------------------------------------------------------------------
## Restriction address tests <- the compact address form, both families
## -------------------------------------------------------------------------
##
## Every restriction list is made of SourceAddr values, so the text forms have
## to read back exactly, and the matching rule has to be the same everywhere:
##
##   suite                       what it holds down
##   --------------------------  ----------------------------------------------
##   "IPv4 text"                 dotted quad: four parts, 0 to 255
##   "IPv6 text"                 colon form, "::" once, IPv4 tail allowed
##   "a source address"          the host and port rules, "*" and port 0
##   "matching"                  which rule matches which arrival

import std/[unittest, strutils]

import ../../src/protocols/relay/restriction_address
import runePragmas

suite "IPv4 text":

  # {.testKind: tkUnit, covers: "parseIpv4".}
  test "four parts of 0 to 255 read as a packed tuple":
    var
      p = parseIpv4("10.0.0.49")
    check p.ok
    check p.ip == (10'u8, 0'u8, 0'u8, 49'u8)
    check parseIpv4("255.255.255.255").ok

  # {.testKind: tkEdgeCase, covers: "parseIpv4".}
  test "anything else is refused, never raised":
    check not parseIpv4("256.0.0.1").ok
    check not parseIpv4("10.0.0").ok
    check not parseIpv4("10.0.0.1.2").ok
    check not parseIpv4("a.0.0.1").ok
    check not parseIpv4("10..0.1").ok
    check not parseIpv4("").ok

suite "IPv6 text":

  # {.testKind: tkUnit, covers: "parseIpv6".}
  test "the full form and the compressed form give the same sixteen bytes":
    var
      full = parseIpv6("2001:0db8:0000:0000:0000:0000:0000:0001")
      short = parseIpv6("2001:db8::1")
    check full.ok
    check short.ok
    check full.ip == short.ip
    check short.ip[0] == 0x20'u8
    check short.ip[1] == 0x01'u8
    check short.ip[2] == 0x0d'u8
    check short.ip[3] == 0xb8'u8
    check short.ip[15] == 0x01'u8

  # {.testKind: tkUnit, covers: "parseIpv6".}
  test "a bare :: is all zeros, and ::1 is the loopback":
    var
      z = parseIpv6("::")
      lo = parseIpv6("::1")
    check z.ok
    check z.ip == default(Ipv6)
    check lo.ok
    check lo.ip[15] == 1'u8
    check lo.ip[0] == 0'u8

  # {.testKind: tkUnit, covers: "parseIpv6".}
  test "an IPv4 tail takes the last four bytes":
    var
      mapped = parseIpv6("::ffff:10.0.0.49")
    check mapped.ok
    check mapped.ip[10] == 0xff'u8
    check mapped.ip[11] == 0xff'u8
    check mapped.ip[12] == 10'u8
    check mapped.ip[15] == 49'u8

  # {.testKind: tkEdgeCase, covers: "parseIpv6".}
  test "a malformed address is refused, never raised":
    check not parseIpv6("1:2:3").ok
    check not parseIpv6("1::2::3").ok
    check not parseIpv6("12345::1").ok
    check not parseIpv6("g::1").ok
    check not parseIpv6("1:2:3:4:5:6:7:8:9").ok
    check not parseIpv6("1:2:3:4:5:6:7::8").ok

suite "a source address":

  # {.testKind: tkUnit, covers: "sourceOf".}
  test "text becomes the right family, and * is any host":
    var
      v4 = sourceOf("10.0.0.49", 47656'u16)
      v6 = sourceOf("::1", 0'u16)
      any = sourceOf("*", 9'u16)
    check v4.ok
    check v4.src.family == 4
    check v6.ok
    check v6.src.family == 6
    check any.ok
    check any.src.family == 0
    check any.src.port == 9'u16

  # {.testKind: tkEdgeCase, covers: "sourceOf".}
  test "a host that is neither IPv4 nor IPv6 is refused with its text":
    var
      bad = sourceOf("example.org", 1'u16)
    check not bad.ok
    check bad.err.contains("example.org")

  # {.testKind: tkUnit, covers: "formatSource".}
  test "it reads back as text, IPv4 short and IPv6 in full":
    check formatSource(sourceOf("10.0.0.49", 47656'u16).src) ==
      "10.0.0.49:47656"
    check formatSource(sourceOf("::1", 0'u16).src) ==
      "0000:0000:0000:0000:0000:0000:0000:0001"
    check formatSource(sourceOf("*", 0'u16).src) == "*"

suite "matching":

  # {.testKind: tkUnit, covers: "sourceMatches".}
  test "port 0 matches any port, and a port must be equal when given":
    var
      rule = sourceOf("10.0.0.49", 0'u16).src
      exact = sourceOf("10.0.0.49", 47656'u16).src
      other = sourceOf("10.0.0.49", 9'u16).src
    check sourceMatches(rule, exact)
    check sourceMatches(rule, other)
    check sourceMatches(exact, exact)
    check not sourceMatches(exact, other)

  # {.testKind: tkUnit, covers: "sourceMatches".}
  test "the any-host rule matches every family, a family rule only its own":
    var
      any = anySource(47656'u16)
      v4 = sourceOf("10.0.0.49", 47656'u16).src
      v6 = sourceOf("::1", 47656'u16).src
    check sourceMatches(any, v4)
    check sourceMatches(any, v6)
    check not sourceMatches(v4, v6)
    check not sourceMatches(v6, v4)
    check sourceMatches(anySource(), v6)
