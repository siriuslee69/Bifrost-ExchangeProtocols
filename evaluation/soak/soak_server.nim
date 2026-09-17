## -------------------------------------------------------------------------
## Soak Server <- the side that is being measured
## -------------------------------------------------------------------------
##
## One process, N workers, two threads and two sockets per worker:
##
##   worker i
##   ├─ accept thread ── socket on  port + 2i      ── ameDacServerHandshake()
##   │                      |                          gives a live AmeSession
##   │                      v
##   │                  handover queue (one lock)
##   │                      |
##   └─ serve thread ─── socket on  port + 2i + 1  ── admitAmeDacPeer()
##                          |                         pumpAmeDacEndpoint()
##                          |                         tickAmeDacEndpoint()
##                          v                         sweepAmeDacRelay()
##                      verify the package, echo a receipt back
##
## ╭─ ❧ why two sockets 🌊
##
## `ameDacServerHandshake` owns the socket while it runs: it reads datagrams
## and throws away anything that is not the record it is waiting for. Pointing
## it at the same socket that carries live DAC traffic would silently eat that
## traffic. Bifrost has no demultiplexer that would let one socket do both, so
## the soak does the honest thing and gives the handshake its own port. A
## client therefore knocks on `port + 2i` and then talks to `port + 2i + 1`,
## from the SAME client socket -- the relay keys peers by the client's
## address, so the session the handshake produced is the session the data
## socket finds.
##
## ╭─ ❧ why the capacity is deliberately too small 🐦‍🔥
##
## `--capacity` is meant to be BELOW the number of clients. A relay that is
## never full never reclaims a slot, and slot reclamation -- erasing the
## session before handing the slot to somebody else -- is the path that has
## never run outside a unit test. Running short of slots on purpose is what
## makes `sweepAmeDacRelay` do work.

import std/[atomics, locks, os, strutils]

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level2/session
import ../../src/protocols/ame/level3/dac_relay
import ../../src/protocols/ame/level3/dac_endpoint
import ../../src/protocols/ame/level3/handshake_dac
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/defaults
import ../../src/protocols/dac/level0/transport
import ../../src/protocols/dac/level3/link_table
import ./soak_common
import runePragmas

const
  soakServerEchoBytes = 512
    ## A receipt is small on purpose. The point of echoing is to make the
    ## server SEND as well as receive, so both directions of the ratchet turn.
  soakServerPumpBurst = 64
    ## How many datagrams one pass may take off the socket before the clock
    ## and the tick get a turn. Without a bound a busy socket starves them.
  soakServerDropSamples = 12
    ## How many distinct drop reasons a worker prints before going quiet. A
    ## drop is a one-line fact -- "this datagram did not open, and here is
    ## why" -- and the first few are worth far more than a count, because a
    ## count cannot tell a stranger from a session that stopped working.
  soakServerAcceptTimeoutMs = 300
  soakServerFullWaitMs = 100
    ## How long an accept thread waits before looking again at a relay that
    ## had no room. Long enough that a full worker is not spinning, short
    ## enough that a slot freed by a sweep is used within a tenth of a second.
  soakServerStepTimeoutMs = 700

type
  ## SoakAdmission: one finished handshake travelling from an accept thread to
  ## the serve thread beside it.
  SoakAdmission {.role: preparedData, expectedCount: [0, 256],
      lifeCycle: lcJob.} = object
    session: AmeSession
    remote: DacAddress

  ## SoakHandover: the one place two threads touch the same memory.
  ## Everything else in this program is share-nothing.
  SoakHandover {.role: truthState, expectedCount: [1, 32],
      lifeCycle: lcForever.} = object
    lock: Lock
    pending: seq[SoakAdmission]

  ## SoakServerArgs: one worker's whole configuration, in value types only,
  ## because a thread argument may hold no managed memory.
  SoakServerArgs {.role: configurator, expectedCount: [1, 32],
      lifeCycle: lcForever.} = object
    host: array[48, char]
    index: int
    basePort: int
    capacity: int
    idleMs: int
    seconds: int
    scenario: DacScenario
    echoBack: bool

## Neither an `Atomic` nor a `Lock` may be given a starting value where it is
## declared -- both refuse to be copied, which is the whole point of them. Nim
## zeroes them, and `initLock` finishes the job for the locks before any
## thread is started.
var
  dropSamples: Atomic[int]
  handovers: array[32, SoakHandover]
  handoverReady: array[32, Atomic[bool]]
  serverDeadline: Atomic[int64]
  serverStop: Atomic[bool]

proc pushAdmission(slot: int, a: sink SoakAdmission) {.role: dataWriter.} =
  ## slot/a: which worker's queue, and the session being handed over.
  ## The lock is held for exactly one append. Nothing is parsed or sealed
  ## inside it, so an accept thread can never stall a serve thread for longer
  ## than a sequence grow.
  {.gcsafe.}:
    acquire(handovers[slot].lock)
    handovers[slot].pending.add(a)
    release(handovers[slot].lock)

proc takeAdmissions(slot: int): seq[SoakAdmission] {.role: dataFetcher.} =
  ## slot: which worker's queue is emptied in one move.
  {.gcsafe.}:
    acquire(handovers[slot].lock)
    result = move(handovers[slot].pending)
    handovers[slot].pending = @[]
    release(handovers[slot].lock)

proc soakPastDeadline(): bool {.role: parser, inline.} =
  ## True once the run has used up the seconds it was given.
  result = serverStop.load() or
    int64(soakElapsedSeconds()) >= serverDeadline.load()

proc soakAcceptThread(a: SoakServerArgs) {.thread.} =
  ## a: the worker whose accept socket this thread owns for the whole run.
  ## One handshake at a time, on its own port, so nothing it reads could have
  ## been live traffic for somebody else.
  var
    host: string = unpackSoakHost(a.host)
    sock: DacSocket = default(DacSocket)
    done: tuple[outcome: AmeHandshakeOutcome, remote: DacAddress] =
      default(tuple[outcome: AmeHandshakeOutcome, remote: DacAddress])
    adm: SoakAdmission = default(SoakAdmission)
  try:
    sock = openDacListener(initDacAddress(host, uint16(a.basePort + a.index * 2)))
  except CatchableError as e:
    echo "worker ", a.index, " could not bind its accept port: ", e.msg
    bumpSoak(scExceptions)
    handoverReady[a.index].store(true)
    return
  handoverReady[a.index].store(true)
  while not soakPastDeadline():
    ## Ask BEFORE doing the key work, not after.
    ##
    ## `admitAmeDacPeer` can refuse -- the relay holds a fixed number of live
    ## links and that is the whole point of it. But by then the handshake has
    ## already run: two round trips, a KEM exchange, and a session that is now
    ## thrown away. Worse, the CLIENT does not know: its handshake returned a
    ## working session, so it starts sending into a relay that has no slot for
    ## it and waits out its own timeout to find out.
    ##
    ## So the accept side reads the live count its serve thread publishes and
    ## simply does not answer when there is no room. A client that gets no
    ## answer retries, which is the behaviour it already has for a lost record.
    if int(soakLevels[a.index].load()) >= a.capacity:
      sleep(soakServerFullWaitMs)
      continue
    try:
      done = ameDacServerHandshake(sock, soakResponderPolicy(), 500'i64,
        soakServerStepTimeoutMs, acceptTimeoutMs = soakServerAcceptTimeoutMs)
    except CatchableError as e:
      bumpSoak(scExceptions)
      echo "worker ", a.index, " handshake raised: ", e.msg
      continue
    if not done.outcome.ok:
      ## A responder that simply saw nobody knock is the common case here,
      ## not a failure -- only count the ones that started and broke.
      ## "timed out waiting for datagram" means nobody knocked, which is the
      ## common case on an idle accept port and not a failure of anything.
      if done.outcome.err.find("timed out") < 0 and
          done.outcome.err.find("did not arrive") < 0:
        bumpSoak(scHandshakeFail)
      continue
    bumpSoak(scHandshakeOk)
    adm.session = done.outcome.connection
    adm.remote = done.remote
    pushAdmission(a.index, adm)
  closeDac(sock)

proc drainAdmissions(E: var AmeDacEndpoint, slot: int,
    nowMs: uint32) {.role: orchestrator.} =
  ## E/slot/nowMs: hand every finished handshake to the relay. A relay that is
  ## full refuses, and that refusal is counted rather than retried -- the
  ## client will knock again, which is exactly what a real one does.
  var
    A: seq[SoakAdmission] = takeAdmissions(slot)
    i: int = 0
    r: tuple[ok: bool, slot: int, err: string] = (false, -1, "")
  while i < A.len:
    r = admitAmeDacPeer(E.relay, dacKeyFromAddress(A[i].remote), A[i].session,
      nowMs)
    if not r.ok:
      bumpSoak(scAdmitFailed)
    i = i + 1

proc echoReceipt(E: var AmeDacEndpoint, key: DacLinkKey, packageId: uint64,
    nowMs: uint32) {.role: orchestrator.} =
  ## E/key/packageId/nowMs: send a small package the other way.
  ## A link carries one outgoing package at a time, so a receipt that arrives
  ## while the previous one is still in flight is simply skipped. That is not
  ## an error: the soak is measuring the loop, not queueing for it.
  var
    step: AmeDacRelayStep = sendAmeDacEndpointPackage(E, key, packageId,
      buildSoakPayload(0xE0E0'u32, packageId, soakServerEchoBytes), nowMs)
  if step.kind == adrDropped:
    return

proc handleComplete(E: var AmeDacEndpoint, step: AmeDacRelayStep,
    echoBack: bool, nowMs: uint32) {.role: orchestrator.} =
  ## E/step/echoBack/nowMs: one finished package, checked against its own
  ## header and acknowledged with a receipt if receipts are switched on.
  var
    checked: SoakPayloadCheck = checkSoakPayload(step.payload)
  if not checked.ok:
    bumpSoak(scMismatched)
    echo "PAYLOAD MISMATCH from ", step.peer.host, ":", step.peer.port, "  ",
      checked.err
    return
  bumpSoak(scPackagesDone)
  bumpSoak(scBytesDone, uint64(step.payload.len))
  if echoBack:
    echoReceipt(E, step.peer, checked.packageId, nowMs)

proc absorbStep(E: var AmeDacEndpoint, step: AmeDacRelayStep,
    echoBack: bool, nowMs: uint32, worker: int) {.role: orchestrator.} =
  ## E/step/echoBack/nowMs/worker: turn one relay outcome into counters and
  ## replies. The worker number rides along only so a printed drop says WHICH
  ## socket refused the datagram -- every worker shares one terminal, and a
  ## drop on the wrong port reads exactly like a drop on the right one.
  case step.kind
  of adrPackageComplete:
    handleComplete(E, step, echoBack, nowMs)
  of adrPackageFailed:
    bumpSoak(scPackagesFailed)
  of adrDropped:
    bumpSoak(scRelayDropped)
    if dropSamples.fetchAdd(1) < soakServerDropSamples:
      echo "w", worker, " drop from ", step.peer.host, ":", step.peer.port,
        "  ", step.err
  else:
    discard

proc pumpBurst(E: var AmeDacEndpoint, echoBack: bool,
    nowMs: uint32, worker: int) {.role: orchestrator.} =
  ## E/echoBack/nowMs: take up to a burst of datagrams off the socket.
  ## The first read waits briefly so an idle worker does not spin; every read
  ## after it is a poll, so a busy worker never pays that wait twice.
  var
    i: int = 0
    step: AmeDacRelayStep = default(AmeDacRelayStep)
  while i < soakServerPumpBurst:
    step = pumpAmeDacEndpoint(E, nowMs, timeoutMs = (if i == 0: 2 else: 0))
    if step.kind == adrNone and step.send.len == 0:
      return
    absorbStep(E, step, echoBack, nowMs, worker)
    i = i + 1

proc reportSweep(E: AmeDacEndpoint, nowMs: uint32, worker: int) {.role: parser.} =
  ## E/nowMs/worker: name every slot about to be reclaimed, with how long it
  ## has been quiet. A sweep that takes a slot from a peer still using it looks
  ## exactly like a sweep that takes a dead one, unless the age is printed.
  var
    i: int = 0
  while i < E.relay.table.slots.len:
    if E.relay.table.slots[i].used and
        dacSlotReclaimable(E.relay.table, i, nowMs) and
        dropSamples.fetchAdd(1) < soakServerDropSamples:
      echo "w", worker, " sweep slot ", i, " ", E.relay.table.slots[i].key.host, ":",
        E.relay.table.slots[i].key.port, "  quiet ",
        nowMs - E.relay.table.slots[i].lastSeenMs, "ms"
    i = i + 1

proc tickAll(E: var AmeDacEndpoint, echoBack: bool,
    nowMs: uint32, worker: int) {.role: orchestrator.} =
  ## E/echoBack/nowMs/worker: let elapsed time speak on every live link.
  var
    steps: seq[AmeDacRelayStep] = tickAmeDacEndpoint(E, nowMs)
    i: int = 0
  while i < steps.len:
    absorbStep(E, steps[i], echoBack, nowMs, worker)
    i = i + 1

proc soakServeThread(a: SoakServerArgs) {.thread.} =
  ## a: the worker whose data socket, relay and clock this thread owns.
  var
    host: string = unpackSoakHost(a.host)
    sock: DacSocket = default(DacSocket)
    E: AmeDacEndpoint = default(AmeDacEndpoint)
    nowMs: uint32 = 0'u32
    lastSweepMs: uint32 = 0'u32
    lastSent: uint64 = 0'u64
    lastRecv: uint64 = 0'u64
  try:
    sock = openDacListener(initDacAddress(host,
      uint16(a.basePort + a.index * 2 + 1)))
  except CatchableError as e:
    echo "worker ", a.index, " could not bind its data port: ", e.msg
    bumpSoak(scExceptions)
    return
  echo "w", a.index, " accept ", a.basePort + a.index * 2, " data ",
    a.basePort + a.index * 2 + 1
  E = initAmeDacEndpoint(sock, initAmeDacRelay(dacDefaultsFor(a.scenario),
    0xA5A5_0000'u64 + uint64(a.index), a.capacity, uint32(a.idleMs)))
  while not soakPastDeadline():
    nowMs = soakElapsedMs()
    ## Published every pass, not once a second: the accept thread beside this
    ## one reads it to decide whether to answer at all, so a stale reading
    ## costs either a refused client or a wasted handshake.
    setSoakLevel(a.index, uint64(ameDacRelayLive(E.relay)))
    try:
      ## Twice, deliberately. A client starts sending the instant its handshake
      ## returns, and a burst can take ten milliseconds -- long enough for a
      ## whole first package to arrive at a slot that has not been filled in
      ## yet and be dropped for having no session.
      drainAdmissions(E, a.index, nowMs)
      pumpBurst(E, a.echoBack, nowMs, a.index)
      drainAdmissions(E, a.index, nowMs)
      tickAll(E, a.echoBack, nowMs, a.index)
    except CatchableError as e:
      bumpSoak(scExceptions)
      echo "worker ", a.index, " serve loop raised: ", e.msg
    if nowMs - lastSweepMs < 1000'u32:
      continue
    lastSweepMs = nowMs
    reportSweep(E, nowMs, a.index)
    bumpSoak(scSlotsSwept, uint64(sweepAmeDacRelay(E.relay, nowMs)))
    ## Endpoint totals are published as DIFFERENCES, not as the totals. Each
    ## worker holds its own endpoint, so storing a total would leave the last
    ## worker to write standing for all of them.
    bumpSoak(scDatagramsSent, E.sent - lastSent)
    bumpSoak(scDatagramsRecv, E.received - lastRecv)
    lastSent = E.sent
    lastRecv = E.received
    setSoak(scSendFailures, uint64(E.sendFailures))
  setSoakLevel(a.index, 0'u64)
  closeAmeDacEndpoint(E)

proc buildArgs(index: int): SoakServerArgs {.role: configurator.} =
  ## index: which worker these arguments describe.
  result.host = packSoakHost(soakArg("host", "127.0.0.1"))
  result.index = index
  result.basePort = soakArgInt("port", 41000)
  result.capacity = soakArgInt("capacity", 8)
  result.idleMs = soakArgInt("idle", 12000)
  result.seconds = soakArgInt("seconds", 120)
  result.scenario = soakScenario(soakArg("lane", "cleanLan"))
  result.echoBack = soakArgInt("echo", 1) != 0

proc runSoakServer() {.role: metaOrchestrator.} =
  ## Start every worker, print a line every `--report` seconds, and stop when
  ## the clock says so. The main thread does nothing but report, so a slow
  ## terminal can never hold up the loop being measured.
  var
    workers: int = max(1, min(32, soakArgInt("workers", 2)))
    seconds: int = soakArgInt("seconds", 120)
    reportEvery: int = max(1, soakArgInt("report", 10))
    accepts: seq[Thread[SoakServerArgs]] = newSeq[Thread[SoakServerArgs]](workers)
    serves: seq[Thread[SoakServerArgs]] = newSeq[Thread[SoakServerArgs]](workers)
    args: SoakServerArgs = default(SoakServerArgs)
    i: int = 0
  serverDeadline.store(int64(seconds))
  echo "soak server: ", workers, " worker(s), accept ports ",
    soakArgInt("port", 41000), "..", soakArgInt("port", 41000) + workers * 2 - 1,
    ", capacity ", soakArgInt("capacity", 8), " per worker, ", seconds, "s"
  while i < workers:
    initLock(handovers[i].lock)
    args = buildArgs(i)
    createThread(accepts[i], soakAcceptThread, args)
    createThread(serves[i], soakServeThread, args)
    i = i + 1
  while not soakPastDeadline():
    sleep(reportEvery * 1000)
    echo soakReportLine("server")
  serverStop.store(true)
  joinThreads(accepts)
  joinThreads(serves)
  echo soakReportLine("server", final = true)
  if soakValue(scMismatched) > 0'u64 or soakValue(scExceptions) > 0'u64:
    quit(1)

when isMainModule:
  runSoakServer()
