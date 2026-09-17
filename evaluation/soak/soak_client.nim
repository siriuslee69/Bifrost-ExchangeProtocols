## -------------------------------------------------------------------------
## Soak Client <- the traffic, and the losses
## -------------------------------------------------------------------------
##
## One thread per peer. Each peer owns one UDP socket, binds it to its own
## loopback address, does a real handshake against a server worker, and then
## sends packages forever:
##
##   peer p  ── bind 127.0.0.(1 + p mod 8):0
##      |
##      ├─ handshake  ──>  server accept port  (port + 2*(p mod workers))
##      |
##      └─ packages   <->  server data   port  (port + 2*(p mod workers) + 1)
##             |
##             +-- every datagram this side sends may be DROPPED
##             +-- every datagram this side reads may be DISCARDED
##             +-- every `--churn` packages, tear the session down and do a
##                 completely fresh handshake on a fresh socket
##
## ╭─ ❧ why the client does its own socket writes 🌊
##
## `AmeDacEndpoint` flushes what the relay produces straight to the socket,
## which is exactly right for a server. A traffic generator needs a wire that
## loses things, so the client keeps the relay and the socket side by side and
## writes them itself. The server stays on the untouched endpoint API -- it is
## the thing being measured, so nothing about it is special-cased here.
##
## ╭─ ❧ what churn is for 🐦‍🔥
##
## A session that lives for the whole run rotates nothing. Tearing one down
## and building another means: a new epoch, a new FOMKE root, a new session
## id, a new source port, a new relay slot -- and, because the server's
## capacity is deliberately smaller than the peer count, a slot that somebody
## else has to give up first. That is the reclamation path, driven from
## outside, at the rate `--churn` asks for.

import std/[atomics, os, strutils]

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level2/session
import ../../src/protocols/ame/level3/dac_relay
import ../../src/protocols/ame/level3/dac_endpoint
import ../../src/protocols/ame/level3/handshake_dac
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/defaults
import ../../src/protocols/dac/level0/transport
import ../../src/protocols/dac/level3/link
import ../../src/protocols/dac/level3/link_table
import ./soak_common
import runePragmas

const
  soakClientHosts = 8
    ## How many distinct loopback addresses the peers spread over. The whole
    ## 127.0.0.0/8 is local, so these are real, different IP addresses that
    ## the kernel routes separately -- not one address wearing many ports.
  soakClientRecvBurst = 32
  soakClientRecvBufferBytes = 1024 * 1024
    ## Smaller than the server's: one peer reads one conversation. Still well
    ## above the default, because a package arrives as a burst of chunks and
    ## the whole point of the burst is that it does not wait for this side.
  soakClientSettleMs = 25
    ## How long to wait after a handshake before sending anything. See
    ## `openPeer` -- this closes a race that exists only because the handshake
    ## and the data live on two different sockets.
  soakClientStrikes = 2
  soakClientBackoffMs = 200
    ## How long to wait before knocking again after a refused handshake, plus
    ## up to three times that at random so a crowd of peers does not come back
    ## together and refill the relay in one instant.
    ## Packages that may time out back to back before the peer gives up on the
    ## session and builds a new one.
  soakClientHandshakeMs = 800
    ## Four attempts at this, so a peer that cannot get in costs about three
    ## seconds before it backs off and knocks again. The default two seconds
    ## would make a churning peer spend most of the run inside one retry.

type
  ## SoakPeer: one client's whole state. Never shared with another thread.
  SoakPeer {.role: truthState, expectedCount: [1, 256], lifeCycle: lcSession.} = object
    sock: DacSocket
    relay: AmeDacRelay
    server: DacAddress
    key: DacLinkKey
    rng: SoakRng
    tag: uint32
    open: bool
    lossPpm: uint32
    nextId: uint64
    sinceChurn: int
    strikes: int
      ## Packages that timed out back to back. A peer whose slot the server
      ## reclaimed is SILENT about it: nothing on the wire says "that session
      ## is gone", so from here it looks exactly like a path that started
      ## losing everything. Either way the answer is the same -- stop talking
      ## into it and handshake again.

  ## SoakClientArgs: one peer's configuration, in value types only.
  SoakClientArgs {.role: configurator, expectedCount: [1, 256],
      lifeCycle: lcForever.} = object
    bindHost: array[48, char]
    serverHost: array[48, char]
    index: int
    basePort: int
    workers: int
    seconds: int
    lossPpm: int
    minBytes: int
    maxBytes: int
    churn: int
    packageTimeoutMs: int
    scenario: DacScenario

## As on the server: an `Atomic` refuses to be copied, so it cannot be given a
## starting value here. Nim zeroes it.
var
  clientDeadline: Atomic[int64]
  clientStop: Atomic[bool]

proc clientPastDeadline(): bool {.role: parser, inline.} =
  ## True once the run has used up the seconds it was given.
  result = clientStop.load() or
    int64(soakElapsedSeconds()) >= clientDeadline.load()

proc sendOneDatagram(P: var SoakPeer, A: ByteSeq) {.role: dataWriter.} =
  ## P/A: one datagram put on the wire, with a failed send counted rather than
  ## raised. One unreachable peer must not end the run for every other peer.
  try:
    sendDacFrameBytes(P.sock, P.server, A)
    bumpSoak(scDatagramsSent)
  except CatchableError:
    bumpSoak(scSendFailures)

proc flushLossy(P: var SoakPeer, step: AmeDacRelayStep) {.role: dataWriter.} =
  ## P/step: transmit the relay's datagrams, losing some of them on purpose.
  ## A drop here is indistinguishable from a real one: the bytes simply never
  ## reach the far side, and nothing tells it they existed.
  var
    i: int = 0
  while i < step.send.len:
    if soakChance(P.rng, P.lossPpm):
      bumpSoak(scDatagramsDropped)
    else:
      sendOneDatagram(P, step.send[i])
    i = i + 1

proc absorbEcho(step: AmeDacRelayStep) {.role: parser.} =
  ## step: a finished package coming back the other way, checked the same way
  ## the server checks the ones going out.
  var
    checked: SoakPayloadCheck = checkSoakPayload(step.payload)
  if checked.ok:
    bumpSoak(scEchoDone)
    return
  bumpSoak(scEchoMismatched)
  echo "ECHO MISMATCH: ", checked.err

proc pumpLossy(P: var SoakPeer, nowMs: uint32,
    waitMs: int): bool {.role: orchestrator.} =
  ## P/nowMs/waitMs: read one datagram, maybe throw it away, otherwise feed it
  ## to the relay and transmit whatever the relay answers. Returns false when
  ## nothing was waiting, so the caller knows to stop draining.
  var
    got: DacFrameBytesResult = recvDacFrameBytes(P.sock,
      ameDacEndpointMaxDatagram, waitMs)
    step: AmeDacRelayStep = default(AmeDacRelayStep)
  if not got.ok:
    return false
  result = true
  bumpSoak(scDatagramsRecv)
  if soakChance(P.rng, P.lossPpm):
    bumpSoak(scDatagramsDropped)
    return
  step = feedAmeDacDatagram(P.relay, dacKeyFromAddress(got.remote),
    got.payload, nowMs)
  if step.kind == adrPackageComplete:
    absorbEcho(step)
  elif step.kind == adrDropped:
    bumpSoak(scRelayDropped)
  flushLossy(P, step)

proc drainLossy(P: var SoakPeer, nowMs: uint32,
    waitMs: int) {.role: orchestrator.} =
  ## P/nowMs/waitMs: take up to a burst off the socket. Only the first read
  ## waits; the rest poll, so a quiet peer sleeps and a busy one does not.
  var
    i: int = 0
  while i < soakClientRecvBurst:
    if not pumpLossy(P, nowMs, (if i == 0: waitMs else: 0)):
      return
    i = i + 1

proc tickLossy(P: var SoakPeer, nowMs: uint32) {.role: orchestrator.} =
  ## P/nowMs: let elapsed time speak, and transmit what it said.
  var
    steps: seq[AmeDacRelayStep] = tickAmeDacRelay(P.relay, nowMs)
    i: int = 0
  while i < steps.len:
    flushLossy(P, steps[i])
    i = i + 1

proc peerLinkSlot(P: var SoakPeer): int {.role: parser, inline.} =
  ## P: which relay slot this peer's one server link sits in, or -1.
  result = ameDacPeerSlot(P.relay, P.key)

proc outgoingActive(P: var SoakPeer): bool {.role: parser.} =
  ## P: true while a package this side sent is still unacknowledged. This is
  ## the only honest completion signal a SENDER has: the relay reports what
  ## arrives, and a receipt is not an arrival.
  var
    slot: int = peerLinkSlot(P)
  if slot < 0:
    return false
  result = P.relay.table.slots[slot].link.outgoing.active

proc giveUpPackage(P: var SoakPeer) {.role: actor.} =
  ## P: release a package that never finished, so the link can send again.
  var
    slot: int = peerLinkSlot(P)
  if slot < 0:
    return
  if abandonDacPackage(P.relay.table.slots[slot].link):
    bumpSoak(scPackagesTimedOut)

proc closePeer(P: var SoakPeer) {.role: actor.} =
  ## P: drop the session and the socket together.
  if not P.open:
    return
  discard releaseAmeDacPeer(P.relay, P.key)
  closeDac(P.sock)
  P.relay = default(AmeDacRelay)
  P.open = false
  bumpSoak(scPeerClosed)

proc openPeer(P: var SoakPeer, a: SoakClientArgs): bool {.
    role: orchestrator.} =
  ## P/a: bind a fresh socket, run a real handshake against the worker this
  ## peer belongs to, and admit the session it produced. Everything about the
  ## previous life of this peer is gone by the time this returns.
  var
    bindHost: string = unpackSoakHost(a.bindHost)
    serverHost: string = unpackSoakHost(a.serverHost)
    worker: int = a.index mod max(1, a.workers)
    acceptAddr: DacAddress = initDacAddress(serverHost,
      uint16(a.basePort + worker * 2))
    outcome: AmeHandshakeOutcome = default(AmeHandshakeOutcome)
  P.server = initDacAddress(serverHost, uint16(a.basePort + worker * 2 + 1))
  P.key = dacKeyFromAddress(P.server)
  try:
    P.sock = openDacListener(initDacAddress(bindHost, 0'u16),
      soakClientRecvBufferBytes)
  except CatchableError as e:
    bumpSoak(scExceptions)
    echo "peer ", a.index, " could not bind ", bindHost, ": ", e.msg
    return false
  outcome = ameDacClientHandshake(P.sock, acceptAddr,
    soakInitiatorPolicy(), 0x5A00_0000'u64 + uint64(a.index) + 1'u64,
    500'i64, soakClientHandshakeMs)
  if not outcome.ok:
    bumpSoak(scHandshakeFail)
    closeDac(P.sock)
    return false
  bumpSoak(scHandshakeOk)
  bumpSoak(scPeerOpened)
  P.relay = initAmeDacRelay(dacDefaultsFor(a.scenario),
    0x5EED_0000'u64 + uint64(a.index), capacity = 2)
  if not admitAmeDacPeer(P.relay, P.key, outcome.connection, soakElapsedMs()).ok:
    bumpSoak(scAdmitFailed)
    closeDac(P.sock)
    return false
  P.open = true
  P.sinceChurn = 0
  P.strikes = 0
  ## Let the server put the session in its table before the first package
  ## lands on the data port. The handshake finished on a DIFFERENT socket, and
  ## the thread that serves this peer only learns about it on its next pass.
  sleep(soakClientSettleMs)
  result = true

proc sendOnePackage(P: var SoakPeer, a: SoakClientArgs): bool {.
    role: orchestrator.} =
  ## P/a: build one self-describing package, hand it to the relay, and put the
  ## datagrams on the wire with losses. Returns false when the relay refused,
  ## which is a real answer -- a link already holding a package says so.
  var
    span: int = max(1, a.maxBytes - a.minBytes)
    bodyLen: int = a.minBytes + int(nextSoakRng(P.rng) mod uint64(span))
    payload: ByteSeq = buildSoakPayload(P.tag, P.nextId, bodyLen)
    step: AmeDacRelayStep = default(AmeDacRelayStep)
  step = sendAmeDacPackage(P.relay, P.key, P.nextId, payload, soakElapsedMs())
  if step.kind == adrDropped:
    bumpSoak(scSendRefused)
    return false
  bumpSoak(scPackagesSent)
  bumpSoak(scBytesSent, uint64(payload.len))
  flushLossy(P, step)
  result = true

proc awaitPackage(P: var SoakPeer, a: SoakClientArgs) {.role: orchestrator.} =
  ## P/a: drive the loop until the package this side sent is acknowledged, the
  ## deadline passes, or the run ends. Nothing sleeps: the receive wait IS the
  ## sleep, so a peer waiting on repair costs no processor time.
  var
    startedMs: uint32 = soakElapsedMs()
    nowMs: uint32 = startedMs
    timedOut: bool = false
    acked: bool = false
  while outgoingActive(P) and not timedOut and not clientPastDeadline():
    nowMs = soakElapsedMs()
    timedOut = nowMs - startedMs > uint32(a.packageTimeoutMs)
    drainLossy(P, nowMs, 5)
    tickLossy(P, nowMs)
  ## Read the answer BEFORE giving the package up, because giving it up is
  ## itself what makes the link look finished.
  acked = not outgoingActive(P)
  if timedOut:
    giveUpPackage(P)
  if acked:
    bumpSoak(scPackagesAcked)
    P.strikes = 0
    return
  P.strikes = P.strikes + 1

proc runOnePackage(P: var SoakPeer, a: SoakClientArgs) {.role: orchestrator.} =
  ## P/a: one package, sent and then waited on. A relay that refuses the send
  ## is not an error and not a strike -- it means the link is still holding the
  ## last one, which the wait below is about to resolve either way.
  if not sendOnePackage(P, a):
    return
  awaitPackage(P, a)
  P.nextId = P.nextId + 1'u64
  P.sinceChurn = P.sinceChurn + 1

proc reconnectPeer(P: var SoakPeer, a: SoakClientArgs): bool {.
    role: orchestrator.} =
  ## P/a: knock again, backing off first when the server had no room. Hammering
  ## a full relay would keep it full; waiting a moment is what lets a slot be
  ## reclaimed and handed to somebody.
  result = openPeer(P, a)
  if result:
    return
  sleep(soakClientBackoffMs + int(nextSoakRng(P.rng) mod
    uint64(soakClientBackoffMs * 3)))

proc soakClientThread(a: SoakClientArgs) {.thread.} =
  ## a: one peer, from its first handshake to the end of the run.
  var
    P: SoakPeer = default(SoakPeer)
  P.tag = uint32(a.index)
  P.rng = initSoakRng(0xC0FFEE00'u64 + uint64(a.index) * 7919'u64)
  P.lossPpm = uint32(max(0, a.lossPpm))
  P.nextId = 1'u64
  while not clientPastDeadline():
    setSoakLevel(a.index, (if P.open: 1'u64 else: 0'u64))
    if not P.open and not reconnectPeer(P, a):
      continue
    try:
      runOnePackage(P, a)
    except CatchableError as e:
      bumpSoak(scExceptions)
      echo "peer ", a.index, " raised: ", e.msg
      closePeer(P)
      continue
    if P.strikes >= soakClientStrikes:
      closePeer(P)
      continue
    if a.churn > 0 and P.sinceChurn >= a.churn:
      closePeer(P)
  closePeer(P)
  setSoakLevel(a.index, 0'u64)

proc buildArgs(index: int): SoakClientArgs {.role: configurator.} =
  ## index: which peer these arguments describe.
  result.bindHost = packSoakHost("127.0.0." & $(1 + index mod soakClientHosts))
  result.serverHost = packSoakHost(soakArg("server-host", "127.0.0.1"))
  result.index = index
  result.basePort = soakArgInt("port", 41000)
  result.workers = max(1, soakArgInt("workers", 2))
  result.seconds = soakArgInt("seconds", 120)
  result.lossPpm = soakArgInt("loss", 20000)
  result.minBytes = max(1, soakArgInt("min-size", 256))
  result.maxBytes = max(result.minBytes + 1, soakArgInt("size", 24000))
  result.churn = soakArgInt("churn", 12)
  result.packageTimeoutMs = soakArgInt("pkg-timeout", 4000)
  result.scenario = soakScenario(soakArg("lane", "cleanLan"))

proc runSoakClient() {.role: metaOrchestrator.} =
  ## Start every peer, print a line every `--report` seconds, stop on the
  ## clock. As on the server, the main thread only reports.
  var
    peers: int = max(1, min(256, soakArgInt("peers", 16)))
    seconds: int = soakArgInt("seconds", 120)
    reportEvery: int = max(1, soakArgInt("report", 10))
    threads: seq[Thread[SoakClientArgs]] = newSeq[Thread[SoakClientArgs]](peers)
    args: SoakClientArgs = default(SoakClientArgs)
    i: int = 0
  clientDeadline.store(int64(seconds))
  echo "soak client: ", peers, " peer(s) over ", soakClientHosts,
    " loopback address(es), loss ", soakArgInt("loss", 20000),
    " ppm each way, churn every ", soakArgInt("churn", 12), " package(s), ",
    seconds, "s"
  while i < peers:
    args = buildArgs(i)
    createThread(threads[i], soakClientThread, args)
    i = i + 1
  while not clientPastDeadline():
    sleep(reportEvery * 1000)
    echo soakReportLine("client")
  clientStop.store(true)
  joinThreads(threads)
  echo soakReportLine("client", final = true)
  if soakValue(scEchoMismatched) > 0'u64 or soakValue(scExceptions) > 0'u64:
    quit(1)

when isMainModule:
  runSoakClient()
