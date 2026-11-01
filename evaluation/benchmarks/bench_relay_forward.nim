## -------------------------------------------------------------------------
## Relay forwarding time <- relaySuperFastUDP against relayFastExtraFrame
## -------------------------------------------------------------------------
##
## ONE question: how long does the relay itself hold a datagram?
##
##   datagram handed to the relay ──► relay decides ──► frame ready to send
##   |<------------------- this is what is timed -------------------->|
##
## Everything else is OUT of the number:
##
##   - the sender's sealing and the receiver's opening. Every ART frame is
##     built BEFORE the clock starts (`prebuilt` below), so no client or server
##     encryption time is in it;
##   - sockets. Both relays are the decision half only (no syscalls), so the
##     kernel's receive and send cost, which is the same for both, is not in it;
##   - the timer itself, which is measured on an empty loop and subtracted.
##
## What stays in, per relay:
##
##   relaySuperFastUDP    size check, client table lookup, one copy of the
##                        datagram, the send list
##   relayFastExtraFrame  neighbour lookup, replay check, the header-protection
##                        and AEAD work on the 16 address bytes (open), the
##                        return note, the directory permission, sealing the
##                        16 address bytes again for the next hop (re-seal)
##
## A plain copy of the same bytes is printed as the floor: nothing can be
## faster than moving the datagram once.
##
## Run: nim c -d:release -r evaluation/benchmarks/bench_relay_forward.nim
##      flags: --n=20000 --payload=1200

import std/[algorithm, monotimes, os, strutils, times]

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level2/route_wire
import ../../src/protocols/transport/types as transport_types
import ../../src/protocols/relay/relay_node
import ../../src/protocols/relay/fast_extra_frame
import ../../src/protocols/relay/super_fast_udp
import ../tests/relay_fixtures

type
  ## Timing: what one relay measured over n datagrams, in nanoseconds.
  Timing = object
    name: string
    totalNs: int64
    samples: seq[int64]
    sink: uint64

proc nsOf(a, b: MonoTime): int64 =
  ## a/b: two clock readings; the gap in nanoseconds.
  result = (b - a).inNanoseconds

proc percentile(S: seq[int64], p: float): int64 =
  ## S: sorted samples; p in 0..1.
  result = S[min(S.len - 1, int(float(S.len) * p))]

proc timerCostNs(n: int): int64 =
  ## n: samples. What reading the clock twice costs, found on an empty body.
  var
    A: seq[int64] = newSeq[int64](n)
    a: MonoTime = getMonoTime()
    b: MonoTime = getMonoTime()
    i: int = 0
  while i < n:
    a = getMonoTime()
    b = getMonoTime()
    A[i] = nsOf(a, b)
    i = i + 1
  A.sort()
  result = percentile(A, 0.5)

proc report(t: Timing, n: int, timer: int64) =
  ## t/n/timer: print one line; per-call numbers have the timer taken off.
  var
    S: seq[int64] = t.samples
  S.sort()
  echo alignLeft(t.name, 34), " mean ", align($(t.totalNs div int64(n)), 6),
    " ns   median ", align($max(0'i64, percentile(S, 0.5) - timer), 6),
    " ns   p99 ", align($max(0'i64, percentile(S, 0.99) - timer), 6), " ns"

proc benchCopy(payload: int, n: int): Timing =
  ## The floor: copy the datagram once, nothing else.
  var
    src: ByteSeq = newSeq[uint8](payload)
    dst: ByteSeq = @[]
    a: MonoTime = getMonoTime()
    b: MonoTime = getMonoTime()
    t0: MonoTime = getMonoTime()
    i: int = 0
  result.name = "plain copy (the floor)"
  result.samples = newSeq[int64](n)
  t0 = getMonoTime()
  while i < n:
    a = getMonoTime()
    dst = @src
    b = getMonoTime()
    result.samples[i] = nsOf(a, b)
    result.sink = result.sink + uint64(dst.len)
    i = i + 1
  result.totalNs = nsOf(t0, getMonoTime())

proc benchSuperFast(payload: int, n: int): Timing =
  ## relaySuperFastUDP: client datagram in, datagram for the NAS out.
  var
    F: RelaySuperFastUdp = initRelaySuperFastUdp(
      initUdpAddress("10.0.0.2", 9000'u16))
    D: ByteSeq = newSeq[uint8](payload)
    C: seq[transport_types.UdpAddress] = @[]
    s: UdpForwardStep = default(UdpForwardStep)
    a: MonoTime = getMonoTime()
    b: MonoTime = getMonoTime()
    t0: MonoTime = getMonoTime()
    i: int = 0
  result.name = "relaySuperFastUDP"
  result.samples = newSeq[int64](n)
  while i < 50:
    C.add(initUdpAddress("203.0.113." & $(i + 1), 40000'u16))
    discard fromClient(F, C[i], D, 1000'u64)
    i = i + 1
  i = 0
  t0 = getMonoTime()
  while i < n:
    a = getMonoTime()
    s = fromClient(F, C[i mod 50], D, 1000'u64)
    b = getMonoTime()
    result.samples[i] = nsOf(a, b)
    result.sink = result.sink + uint64(s.send.len)
    i = i + 1
  result.totalNs = nsOf(t0, getMonoTime())

proc benchFastExtraFrame(payload: int, n: int): Timing =
  ## relayFastExtraFrame: a sealed ART frame in, the re-sealed frame out.
  ## Every frame is built first, in sequence, so the clock sees only the relay.
  var
    phone: RtPair = rtPair(7'u8)
    nas: RtPair = rtPair(8'u8)
    R: RelayFastExtraFrame = initRelayFastExtraFrame(idR1, 4)
    sPhone: int = 0
    body: ByteSeq = newSeq[uint8](payload)
    prebuilt: seq[ByteSeq] = @[]
    step: RelayStep = default(RelayStep)
    a: MonoTime = getMonoTime()
    b: MonoTime = getMonoTime()
    t0: MonoTime = getMonoTime()
    i: int = 0
  result.name = "relayFastExtraFrame (frames prebuilt)"
  result.samples = newSeq[int64](n)
  R.addRelayTarget(idNas, "nas", ["phone"])
  sPhone = R.admitRelayNeighbour(phone.right, idPhone, "phone", at(idPhone),
    acrDac).slot
  discard R.admitRelayNeighbour(nas.right, idNas, "nas", at(idNas), acrDac)
  while i < n:
    prebuilt.add(sealAmeRouteForward(phone.left, idNas, body))
    i = i + 1
  i = 0
  t0 = getMonoTime()
  while i < n:
    a = getMonoTime()
    step = R.feedRelayFastExtraFrame(sPhone, prebuilt[i], 0'u32)
    b = getMonoTime()
    result.samples[i] = nsOf(a, b)
    result.sink = result.sink + uint64(step.send.len)
    if step.event != reForwarded:
      quit("the relay did not forward frame " & $i & ": " & step.err, 1)
    i = i + 1
  result.totalNs = nsOf(t0, getMonoTime())

proc main() =
  var
    n: int = 20000
    payload: int = 1200
    timer: int64 = 0
    T: seq[Timing] = @[]
    arg: string = ""
  for a in commandLineParams():
    arg = a
    if arg.startsWith("--n="):
      n = parseInt(arg[4 .. ^1])
    elif arg.startsWith("--payload="):
      payload = parseInt(arg[10 .. ^1])
  timer = timerCostNs(100_000)
  echo "datagrams: ", n, "   payload: ", payload, " bytes   timer cost taken off: ",
    timer, " ns"
  echo ""
  T.add(benchCopy(payload, n))
  T.add(benchSuperFast(payload, n))
  T.add(benchFastExtraFrame(payload, n))
  for t in T:
    t.report(n, timer)
  echo ""
  echo "extra time per datagram, relayFastExtraFrame over relaySuperFastUDP:"
  echo "  mean   ", T[2].totalNs div int64(n) - T[1].totalNs div int64(n), " ns"
  echo "  ratio  ", formatFloat(float(T[2].totalNs) / float(T[1].totalNs),
    ffDecimal, 1), "x"
  echo "(sink ", T[0].sink + T[1].sink + T[2].sink, ")"

main()
