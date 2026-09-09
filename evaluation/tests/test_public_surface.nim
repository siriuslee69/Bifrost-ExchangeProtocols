## -------------------------------------------------------------------------
## Public Surface Tests <- the exported routines nothing else exercised
## -------------------------------------------------------------------------
##
## Otter reported these as unused public routines. They are not shims left
## behind by a refactor -- they are implemented features that no caller in
## this tree happened to reach, which is normal for a protocol library and
## invisible to a tool that can only see callers it can find.
##
## The useful answer to "nothing calls this" is therefore not always to
## delete it. It is to say what it should do and check that it does, so the
## next reader knows the routine works rather than merely compiling.

import std/[times, unittest]

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level0/protocols as ame_protocols
import ../../src/protocols/ame/level2/trust
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/framing
import ../../src/protocols/dac/level0/protocols as dac_protocols
import ../../src/protocols/dac/level1/path_policy
import ../../src/protocols/http/types
import ../../src/protocols/http/level0/header_ops
import ../../src/protocols/http/level1/response_ops
import ../../src/protocols/transport/protocols as transport_protocols
import runePragmas

suite "protocol descriptors name themselves":
  ## Four descriptors, one per protocol. Only FOMKE's was reached by a test,
  ## so the other three were reported unused while being the same shape.
  # {.testKind: tkUnit.}
  test "each descriptor carries its own id and name":
    var
      ame: ProtocolDescriptor = initAmeDescriptor()
      session: ProtocolDescriptor = initAmeSessionDescriptor()
      dac: ProtocolDescriptor = initDacDescriptor()
    check ame.name == "AME"
    check ame.protocolId == ameProtocolId
    check session.protocolId == ameSessionProtocolId
    ## The live session speaks a different protocol id from the record
    ## layer, so a peer cannot answer one with the other.
    check session.protocolId != ame.protocolId
    check dac.protocolId != ame.protocolId

suite "DAC body length and class naming":
  # {.testKind: tkUnit.}
  test "the body length mode decides the maximum body":
    ## This reports what the LENGTH FIELD can express, which is not the same
    ## as what any profile will actually send: the super-clean preset caps
    ## itself at dacSuperCleanMaxBodyLen, well below the field is capable of.
    ## Two different limits, and confusing them is how a body larger than a
    ## policy allows would still look encodable.
    check dacMaxBodyLenForMode(dblU16) == uint32(high(uint16))
    check dacMaxBodyLenForMode(dblU32) == high(uint32)
    check dacMaxBodyLenForMode(dblU32) > dacMaxBodyLenForMode(dblU16)
    check dacSuperCleanMaxBodyLen < dacMaxBodyLenForMode(dblU32)

  # {.testKind: tkUnit.}
  test "every transfer class renders a distinct name":
    var
      seen: seq[string] = @[]
      n: string = ""
    for c in DacTransferClass:
      n = dacTransferClassName(c)
      check n.len > 0
      check n notin seen
      seen.add(n)

suite "the path ladder moves one step at a time":
  ## `worseDacPath` was exercised; `betterDacPath` is its other half and was
  ## not. A ladder that only goes down is not a ladder.
  # {.testKind: tkUnit.}
  test "a path can be strengthened and weakened again":
    var
      lane: DacPathLane = dplLossyPath
    check betterDacPath(lane) != lane
    check worseDacPath(betterDacPath(lane)) == lane

  # {.testKind: tkEdgeCase.}
  test "the blocked-UDP lane is not on the ladder":
    ## It does not mean "a worse datagram path"; it means datagrams do not
    ## work here at all, and the answer is the TCP carrier. So neither
    ## direction moves it.
    check betterDacPath(dplBlockedUdpPath) == dplBlockedUdpPath
    check worseDacPath(dplBlockedUdpPath) == dplBlockedUdpPath

suite "a rejected peer trust carries its reason":
  # {.testKind: tkEdgeCase.}
  test "an external verifier's refusal survives into the trust gate":
    var
      t: AmePeerTrustResult = initRejectedAmePeerTrust("verifier said no")
    check not t.ok
    check t.err == "verifier said no"

  # {.testKind: tkEdgeCase.}
  test "a refusal with no reason is refused itself":
    ## A rejection nobody can explain is worse than no rejection: it would
    ## reach a log as an empty string.
    expect ValueError:
      discard initRejectedAmePeerTrust("")

suite "HTTP header and date helpers":
  # {.testKind: tkUnit.}
  test "deleting a header removes every copy of it":
    var
      H: HttpHeaders = @[]
    H.setHeader("X-A", "1")
    H.setHeader("X-B", "2")
    H.add(HttpHeader(name: "X-A", value: "3"))
    check H.len == 3
    H.delHeader("x-a")
    check H.len == 1
    check H[0].name == "X-B"

  # {.testKind: tkUnit.}
  test "a time renders as an IMF-fixdate in GMT":
    var
      s: string = httpDateFromTime(fromUnix(784111777))
    ## 1994-11-06T08:49:37Z, the example in the HTTP specification itself.
    check s == "Sun, 06 Nov 1994 08:49:37 GMT"

suite "transport descriptors":
  # {.testKind: tkUnit.}
  test "the basic transport list names each transport once":
    var
      D: seq[ProtocolDescriptor] = listBasicTransportDescriptors()
      seen: seq[ProtocolId] = @[]
      i: int = 0
    check D.len > 0
    while i < D.len:
      check D[i].name.len > 0
      check D[i].protocolId notin seen
      seen.add(D[i].protocolId)
      i = i + 1
