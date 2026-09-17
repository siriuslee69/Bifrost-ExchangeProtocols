## -------------------------------------------------------------------------
## Soak Runner <- starts the processes and waits
## -------------------------------------------------------------------------
##
## The soak is deliberately not one program. A server and a client in one
## process share a heap, a scheduler and a garbage collector, and any of the
## three can hide a fault that two real machines would show. So this starts
## SEPARATE PROCESSES and lets the operating system carry the bytes between
## them:
##
##   soak_run
##     ├─ soak_server  on 127.0.0.10  ports 41000, 41001, 41002, ...
##     ├─ soak_server  on 127.0.0.11  ports 42000, 42001, 42002, ...
##     ├─ soak_client  peers bound across 127.0.0.1 .. 127.0.0.8
##     └─ soak_client  the same, a second process
##
## ╭─ ❧ these are addresses, not aliases 🌊
##
## The whole of 127.0.0.0/8 is local on Linux, and the kernel routes each
## address separately. So 127.0.0.10 and 127.0.0.1 are two different IP
## addresses with their own routing decision, their own socket table entries
## and their own source address on every datagram -- which is what the relay
## keys peers by. What this does NOT give is a separate kernel, a separate
## network stack, or a real link with a real queue on it. A run here proves
## the protocol, the processes and the addressing; it does not prove anything
## about a driver, an MTU, or a switch.
##
## ╭─ ❧ what a pass looks like 🐦‍🔥
##
## Every child prints one tagged line per report interval, and the last line
## each of them prints is the one that matters:
##
##   MISMATCH        must be absent. One is a failure of the whole run.
##   EXCEPTION       must be absent. Nothing may escape a loop.
##   pkg-done        must keep climbing on the server, to the last line.
##   rss             must not climb without end. It settles, or it leaks.
##
## The runner returns non-zero when any child does, and a child returns
## non-zero when it saw a mismatch or an escaped exception.

import std/[os, osproc, strutils]

import ./soak_common
import runePragmas

const
  soakRunServerHostBase = 10
    ## Server processes bind 127.0.0.10 upwards, clients 127.0.0.1 upwards,
    ## so the two never collide and a datagram's source address says which
    ## side sent it.
  soakRunPortStride = 1000
    ## Port room per server process. A server takes two ports per worker, so
    ## this is generous on purpose: a run that is restarted immediately should
    ## not trip over its own sockets still sitting in the kernel.
  soakRunSettleMs = 1200
    ## How long the clients wait for the servers to bind and generate keys.

type
  ## SoakRunPlan: the whole run, decided once from the command line.
  SoakRunPlan {.role: configurator, expectedCount: 1, lifeCycle: lcForever.} = object
    servers: int
    clients: int
    workers: int
    peers: int
    capacity: int
    seconds: int
    reportEvery: int
    basePort: int
    idleMs: int
    lossPpm: int
    maxBytes: int
    minBytes: int
    churn: int
    lane: string
    binDir: string

proc planFromArgs(): SoakRunPlan {.role: configurator.} =
  ## Every knob, with defaults that make a short run useful on one machine.
  result.servers = max(1, soakArgInt("servers", 1))
  result.clients = max(1, soakArgInt("clients", 2))
  result.workers = max(1, soakArgInt("workers", 4))
  result.peers = max(1, soakArgInt("peers", 12))
  result.capacity = max(1, soakArgInt("capacity", 8))
  result.seconds = max(5, soakArgInt("seconds", 120))
  result.reportEvery = max(1, soakArgInt("report", 15))
  result.basePort = soakArgInt("port", 41000)
  result.idleMs = soakArgInt("idle", 15000)
  result.lossPpm = soakArgInt("loss", 20000)
  result.maxBytes = soakArgInt("size", 32000)
  result.minBytes = soakArgInt("min-size", 256)
  result.churn = soakArgInt("churn", 40)
  result.lane = soakArg("lane", "cleanLan")
  result.binDir = soakArg("bin", getAppDir())

proc soakBinary(P: SoakRunPlan, name: string): string {.role: parser.} =
  ## P/name: where the runner expects to find one of the two programs. They
  ## are built beside it, so a run never picks up a stale copy from a path.
  result = P.binDir / name
  when defined(windows):
    result = result & ".exe"

proc serverHost(i: int): string {.role: parser, inline.} =
  ## i: which server process, turned into its own loopback address.
  result = "127.0.0." & $(soakRunServerHostBase + i)

proc serverArgs(P: SoakRunPlan, i: int): seq[string] {.role: truthBuilder.} =
  ## P/i: the command line for one server process.
  ## Its clock runs a little longer than the clients', so it is still
  ## answering while the last client is finishing.
  result = @[
    "--tag=srv" & $i,
    "--host=" & serverHost(i),
    "--port=" & $(P.basePort + i * soakRunPortStride),
    "--workers=" & $P.workers,
    "--capacity=" & $P.capacity,
    "--idle=" & $P.idleMs,
    "--lane=" & P.lane,
    "--report=" & $P.reportEvery,
    "--seconds=" & $(P.seconds + 8)
  ]

proc clientArgs(P: SoakRunPlan, j: int): seq[string] {.role: truthBuilder.} =
  ## P/j: the command line for one client process, aimed at the server it
  ## belongs to. Clients are shared out over the servers round-robin.
  result = @[
    "--tag=cli" & $j,
    "--server-host=" & serverHost(j mod P.servers),
    "--port=" & $(P.basePort + (j mod P.servers) * soakRunPortStride),
    "--workers=" & $P.workers,
    "--peers=" & $P.peers,
    "--capacity=" & $P.capacity,
    "--loss=" & $P.lossPpm,
    "--size=" & $P.maxBytes,
    "--min-size=" & $P.minBytes,
    "--churn=" & $P.churn,
    "--lane=" & P.lane,
    "--report=" & $P.reportEvery,
    "--seconds=" & $P.seconds
  ]

proc startChild(path: string, args: seq[string]): Process {.
    role: orchestrator.} =
  ## path/args: one child, sharing the runner's terminal so its report lines
  ## land in the same place as everything else. Every line a child prints is
  ## tagged, so interleaving costs nothing.
  result = startProcess(path, args = args,
    options = {poParentStreams, poStdErrToStdOut})

proc describe(P: SoakRunPlan) {.role: parser.} =
  ## P: say out loud what is about to run, so a log has its own settings in it.
  echo "soak: ", P.servers, " server process(es) x ", P.workers,
    " worker(s) x ", P.capacity, " slot(s) = ", P.servers * P.workers *
    P.capacity, " peer slots"
  echo "soak: ", P.clients, " client process(es) x ", P.peers, " peer(s) = ",
    P.clients * P.peers, " peers wanting them"
  echo "soak: ", P.lossPpm, " ppm loss each way, packages ", P.minBytes, "..",
    P.maxBytes, " bytes, churn every ", P.churn, ", lane ", P.lane
  echo "soak: ", P.seconds, "s, reporting every ", P.reportEvery, "s"

proc waitAll(A: var seq[Process]): int {.role: orchestrator.} =
  ## A: every child waited on, with the worst exit code returned. Waiting on
  ## all of them rather than stopping at the first failure means a run always
  ## ends with every process reaped.
  var
    i: int = 0
    code: int = 0
  while i < A.len:
    code = waitForExit(A[i])
    if code != 0:
      result = code
    close(A[i])
    i = i + 1

proc runSoak() {.role: metaOrchestrator.} =
  ## Start the servers, let them bind, start the clients, wait for everybody.
  var
    P: SoakRunPlan = planFromArgs()
    children: seq[Process] = @[]
    serverPath: string = ""
    clientPath: string = ""
    code: int = 0
    i: int = 0
  serverPath = soakBinary(P, "soak_server")
  clientPath = soakBinary(P, "soak_client")
  if not fileExists(serverPath) or not fileExists(clientPath):
    echo "soak: build soak_server and soak_client into ", P.binDir, " first"
    quit(2)
  describe(P)
  while i < P.servers:
    children.add(startChild(serverPath, serverArgs(P, i)))
    i = i + 1
  sleep(soakRunSettleMs)
  i = 0
  while i < P.clients:
    children.add(startChild(clientPath, clientArgs(P, i)))
    i = i + 1
  code = waitAll(children)
  if code == 0:
    echo "soak: every process finished clean"
    return
  echo "soak: a process ended with ", code,
    " -- look for MISMATCH or EXCEPTION above"
  quit(code)

when isMainModule:
  runSoak()
