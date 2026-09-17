## -------------------------------------------------------------------------
## Soak Common <- the parts both soak processes need to agree on
## -------------------------------------------------------------------------
##
## A soak is not a test. A test asks "does this work once"; a soak asks "does
## this still work after an hour, with dozens of peers, on a wire that loses
## things". Nothing here is protocol code. It is the scaffolding two separate
## programs need in order to say the same words to each other:
##
##   the payload    a package that carries its own name, so the RECEIVER can
##                  check it without sharing memory with the sender
##   the identity   both sides rebuild the same shared secret from a seed, so
##                  no key file has to travel between the two processes
##   the tally      counters every thread may add to at once
##   the clock      one millisecond number, taken from a monotonic source
##   the memory     how many bytes this process actually holds, from the OS
##
## ╭─ ❧ why the payload names itself 🌊
##
## The server verifies what arrives. It has never met the sender's variables,
## so "is this the right payload" cannot be answered by comparing against a
## copy. Instead every package states who sent it and which package it is, and
## the rest is a ramp computed from those two numbers:
##
##   byte:   0    1    2    3    4       8            16          20
##          +----+----+----+----+--------+------------+-----------+--------
##          | S  | O  | A  | K  | peerTag| packageId  |  bodyLen  | ramp...
##          +----+----+----+----+--------+------------+-----------+--------
##           magic, 4 bytes      u32 LE   u64 LE       u32 LE      bodyLen
##
## The receiver reads the header, recomputes the ramp from `peerTag` and
## `packageId`, and compares. A single flipped byte anywhere in the package
## fails that comparison, and so does a package that was assembled out of the
## wrong chunks. That is the whole integrity claim of the soak, and it costs
## one pass over the bytes.

import std/[atomics, monotimes, os, strutils, times]

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/path_triggers
import ../../src/protocols/ame/level3/handshake_identity
import ../../src/protocols/ame/level3/handshake_transport
import ../../src/protocols/dac/level0/defaults
import runePragmas

const
  soakMagic0* = 'S'.uint8
  soakMagic1* = 'O'.uint8
  soakMagic2* = 'A'.uint8
  soakMagic3* = 'K'.uint8
  soakHeaderBytes* = 20
    ## Magic, peer tag, package id and body length. Everything after this is
    ## the ramp the receiver recomputes.

  soakPskId* = "bifrost-soak"
  soakPskSecretLen* = 32
    ## AM1M provisioning. A soak is not proving that certificates work -- the
    ## handshake suite already does that -- so it uses the cheap mode and
    ## spends its time on the thing being measured.

  soakKems*: AmeKemAlgorithms = [akaX25519, akaFireSaber]

type
  ## SoakCounter: one number every thread may add to.
  ## Kept as one enum so a report never forgets to print a column.
  SoakCounter* = enum
    scHandshakeOk,
    scHandshakeFail,
    scPackagesSent,
    scPackagesDone,
    scPackagesFailed,
    scPackagesTimedOut,
    scBytesSent,
    scBytesDone,
    scMismatched,
    scDatagramsSent,
    scDatagramsRecv,
    scDatagramsDropped,
    scSendFailures,
    scRelayDropped,
    scSlotsSwept,
    scAdmitFailed,
    scExceptions,
    scPeersLive,
    scEchoDone,
    scEchoMismatched,
    scPeerOpened,
    scPeerClosed,
    scSendRefused,
    scPackagesAcked

  ## SoakPayloadCheck: what a receiver learned from one finished package.
  ## Named rather than written out at each call site, because the answer is
  ## read in two programs and a four-field tuple spelled twice drifts.
  SoakPayloadCheck* {.role: preparedData, expectedCount: [0, 64],
      lifeCycle: lcScratch.} = object
    ok*: bool
    peerTag*: uint32
    packageId*: uint64
    err*: string

  ## SoakRng: one thread's own stream. Never shared, so it needs no lock.
  SoakRng* {.role: truthState, expectedCount: [1, 64], lifeCycle: lcSession.} = object
    state*: uint64

var
  soakTally*: array[SoakCounter, Atomic[uint64]]
    ## Every worker adds here. Reading a single counter while another thread
    ## writes it is fine -- the number is a rate, not a receipt.
  soakStart: MonoTime = getMonoTime()
  soakLevels*: array[256, Atomic[uint64]]
    ## One reading per worker, rather than one shared number. A level is a
    ## SNAPSHOT -- "how many peers are live right now" -- and several threads
    ## storing their own snapshot into one slot would leave the last writer's
    ## answer standing for everybody. Each worker owns an index; the report
    ## adds them up.

proc soakCounterName*(c: SoakCounter): string {.role: parser.} =
  ## c: counter turned into the short word a report column uses.
  case c
  of scHandshakeOk: result = "handshakes"
  of scHandshakeFail: result = "hs-failed"
  of scPackagesSent: result = "pkg-sent"
  of scPackagesDone: result = "pkg-done"
  of scPackagesFailed: result = "pkg-failed"
  of scPackagesTimedOut: result = "pkg-timeout"
  of scBytesSent: result = "bytes-sent"
  of scBytesDone: result = "bytes-done"
  of scMismatched: result = "MISMATCH"
  of scDatagramsSent: result = "dg-sent"
  of scDatagramsRecv: result = "dg-recv"
  of scDatagramsDropped: result = "dg-dropped"
  of scSendFailures: result = "send-fail"
  of scRelayDropped: result = "relay-drop"
  of scSlotsSwept: result = "swept"
  of scAdmitFailed: result = "admit-fail"
  of scExceptions: result = "EXCEPTION"
  of scPeersLive: result = "peers-live"
  of scEchoDone: result = "echo-done"
  of scEchoMismatched: result = "ECHO-MISMATCH"
  of scPeerOpened: result = "peer-open"
  of scPeerClosed: result = "peer-close"
  of scSendRefused: result = "send-refused"
  of scPackagesAcked: result = "pkg-acked"

proc bumpSoak*(c: SoakCounter, n: uint64 = 1'u64): uint64 {.role: actor,
    discardable, inline.} =
  ## c/n: counter and how much to add to it. Returns what it held BEFORE the
  ## add, which is what the atomic hands back anyway and is occasionally worth
  ## reading -- a caller that wants to print only the first few of something
  ## can test it without a second counter.
  result = soakTally[c].fetchAdd(n)

proc setSoak*(c: SoakCounter, v: uint64) {.role: actor, inline.} =
  ## c/v: counter overwritten rather than added to, for a level like
  ## "peers live" that is a reading, not a running total.
  soakTally[c].store(v)

proc soakValue*(c: SoakCounter): uint64 {.role: parser, inline.} =
  ## c: counter read back.
  result = soakTally[c].load()

proc setSoakLevel*(i: int, v: uint64) {.role: actor, inline.} =
  ## i/v: which worker is reporting, and what it currently holds.
  if i >= 0 and i < soakLevels.len:
    soakLevels[i].store(v)

proc soakLevelSum*(): uint64 {.role: parser.} =
  ## Every worker's latest reading, added together.
  var
    i: int = 0
  while i < soakLevels.len:
    result = result + soakLevels[i].load()
    i = i + 1

proc soakElapsedMs*(): uint32 {.role: parser.} =
  ## Milliseconds since this process started, wrapped into the width the DAC
  ## and AME clocks use. Monotonic, so a system clock step cannot make a
  ## repair timer fire in the past.
  result = uint32((getMonoTime() - soakStart).inMilliseconds and 0xFFFFFFFF'i64)

proc soakElapsedSeconds*(): float {.role: parser.} =
  ## Seconds since start, for the report's rate columns.
  result = float((getMonoTime() - soakStart).inMilliseconds) / 1000.0

proc initSoakRng*(seed: uint64): SoakRng {.role: configurator.} =
  ## seed: anything non-zero; zero is replaced, because the generator below
  ## has zero as a fixed point and would then return it forever.
  result.state = seed
  if result.state == 0'u64:
    result.state = 0x9E3779B97F4A7C15'u64

proc nextSoakRng*(S: var SoakRng): uint64 {.role: math, inline.} =
  ## S: generator advanced one step. xorshift64*, which is enough to decide
  ## which datagram to drop and nothing more -- no secret depends on it.
  S.state = S.state xor (S.state shr 12)
  S.state = S.state xor (S.state shl 25)
  S.state = S.state xor (S.state shr 27)
  result = S.state * 0x2545F4914F6CDD1D'u64

proc soakChance*(S: var SoakRng, ppm: uint32): bool {.role: math, inline.} =
  ## S/ppm: true about `ppm` times in every million draws. Parts per million
  ## rather than a percentage so a one-in-ten-thousand loss rate is sayable.
  if ppm == 0'u32:
    return false
  result = (nextSoakRng(S) mod 1_000_000'u64) < uint64(ppm)

proc soakRampByte*(peerTag: uint32, packageId: uint64,
    i: int): uint8 {.role: math, inline.} =
  ## peerTag/packageId/i: the byte this package must hold at offset `i`.
  ## Every input is in the header, so a receiver can recompute it alone.
  result = uint8((uint64(i) * 31'u64 + uint64(peerTag) * 17'u64 +
    packageId * 7'u64) mod 251'u64)

proc appendLe32(A: var ByteSeq, v: uint32) {.role: dataWriter, inline.} =
  ## A/v: four bytes, least significant first.
  A.add(uint8(v and 0xFF'u32))
  A.add(uint8((v shr 8) and 0xFF'u32))
  A.add(uint8((v shr 16) and 0xFF'u32))
  A.add(uint8((v shr 24) and 0xFF'u32))

proc appendLe64(A: var ByteSeq, v: uint64) {.role: dataWriter, inline.} =
  ## A/v: eight bytes, least significant first.
  appendLe32(A, uint32(v and 0xFFFFFFFF'u64))
  appendLe32(A, uint32((v shr 32) and 0xFFFFFFFF'u64))

proc readLe32(A: openArray[uint8], at: int): uint32 {.role: parser, inline.} =
  ## A/at: four bytes read back out, least significant first.
  result = uint32(A[at]) or (uint32(A[at + 1]) shl 8) or
    (uint32(A[at + 2]) shl 16) or (uint32(A[at + 3]) shl 24)

proc readLe64(A: openArray[uint8], at: int): uint64 {.role: parser, inline.} =
  ## A/at: eight bytes read back out, least significant first.
  result = uint64(readLe32(A, at)) or (uint64(readLe32(A, at + 4)) shl 32)

proc buildSoakPayload*(peerTag: uint32, packageId: uint64,
    bodyLen: int): ByteSeq {.role: truthBuilder.} =
  ## peerTag/packageId: who is sending and which package this is.
  ## bodyLen: how many ramp bytes follow the twenty-byte header.
  var
    i: int = 0
  result = newSeqOfCap[uint8](soakHeaderBytes + bodyLen)
  result.add(soakMagic0)
  result.add(soakMagic1)
  result.add(soakMagic2)
  result.add(soakMagic3)
  appendLe32(result, peerTag)
  appendLe64(result, packageId)
  appendLe32(result, uint32(bodyLen))
  while i < bodyLen:
    result.add(soakRampByte(peerTag, packageId, i))
    i = i + 1

proc checkSoakPayload*(A: openArray[uint8]): SoakPayloadCheck {.role: parser.} =
  ## A: a package that arrived whole, checked against what its own header says
  ## it should contain. A single wrong byte is a failure, and so is a header
  ## that does not describe the length that arrived.
  var
    bodyLen: int = 0
    i: int = 0
  if A.len < soakHeaderBytes:
    result.err = "package shorter than the soak header"
    return
  if A[0] != soakMagic0 or A[1] != soakMagic1 or A[2] != soakMagic2 or
      A[3] != soakMagic3:
    result.err = "package does not start with the soak magic"
    return
  result.peerTag = readLe32(A, 4)
  result.packageId = readLe64(A, 8)
  bodyLen = int(readLe32(A, 16))
  if bodyLen != A.len - soakHeaderBytes:
    result.err = "package says " & $bodyLen & " body bytes but carries " &
      $(A.len - soakHeaderBytes)
    return
  while i < bodyLen:
    if A[soakHeaderBytes + i] != soakRampByte(result.peerTag,
        result.packageId, i):
      result.err = "package body differs at offset " & $i
      return
    i = i + 1
  result.ok = true

proc soakPskSecret*(tag: uint32): ByteSeq {.role: truthBuilder.} =
  ## tag: which shared secret this is. Every peer gets its own so the sessions
  ## are genuinely distinct rather than one key wearing many addresses.
  var
    i: int = 0
  result = newSeq[uint8](soakPskSecretLen)
  while i < soakPskSecretLen:
    result[i] = uint8((i * 13 + int(tag) * 47 + 5) mod 251)
    i = i + 1

proc soakLayout*(): AmeSuiteLayout {.role: configurator.} =
  ## The algorithm layout both processes build independently.
  result = defaultAmeLayout(soakKems)

proc soakTier*(L: AmeSuiteLayout): AmeMaskTier {.role: configurator.} =
  ## L: layout whose every occupied slot is switched on for the soak.
  result = initAmeMaskTier(L, 1'u32, initAmeTierMasks(0b11000000'u8,
    occupiedAmeMask(L.ciphers.length), occupiedAmeMask(L.macs.length),
    occupiedAmeMask(L.hashes.length), occupiedAmeMask(L.signatures.length),
    occupiedAmeMask(L.kdfs.length)))

proc soakResponderPolicy*(): AmeResponderPolicy {.
    role: configurator.} =
  ## ONE shared secret, for every peer, on purpose.
  ##
  ## A responder picks its policy BEFORE it knows who is knocking: the
  ## handshake hands it a socket, not a name. So a per-peer secret would need
  ## a lookup keyed on something in the hello, and this API has no such hook.
  ## Distinct sessions do not depend on distinct secrets anyway -- every
  ## handshake runs its own key exchange with its own nonces, so two peers
  ## sharing provisioning still end up with unrelated traffic keys.
  var
    layout: AmeSuiteLayout = soakLayout()
  result = initAmeResponderPolicy([initAmeTierPath(layout, [soakTier(layout)])],
    initAmePskAuthentication(soakPskId, soakPskSecret(0'u32)),
    requireCookie = true)

proc soakInitiatorPolicy*(): AmeInitiatorPolicy {.
    role: configurator.} =
  ## The matching side of the one shared secret described above.
  var
    layout: AmeSuiteLayout = soakLayout()
  result = initAmeInitiatorPolicy(layout, soakTier(layout),
    initAmePskAuthentication(soakPskId, soakPskSecret(0'u32)))

proc soakRssKib*(): int {.role: dataFetcher.} =
  ## How many kibibytes of real memory this process is holding, straight from
  ## the operating system. A soak that leaks shows up here long before it
  ## shows up anywhere else. Returns -1 where the file does not exist.
  var
    text: string = ""
    fields: seq[string] = @[]
  try:
    text = readFile("/proc/self/statm")
  except CatchableError:
    return -1
  fields = text.strip().split(' ')
  if fields.len < 2:
    return -1
  try:
    result = parseInt(fields[1]) * 4
  except ValueError:
    result = -1

proc soakArg*(name: string, fallback: string = ""): string {.role: parser.} =
  ## name/fallback: read `--name=value` off the command line, or the fallback.
  var
    prefix: string = "--" & name & "="
    args: seq[string] = commandLineParams()
    i: int = 0
  result = fallback
  while i < args.len:
    if args[i].startsWith(prefix):
      result = args[i][prefix.len .. ^1]
    i = i + 1

proc soakArgInt*(name: string, fallback: int): int {.role: parser.} =
  ## name/fallback: the same, parsed as a whole number.
  var
    text: string = soakArg(name, "")
  result = fallback
  if text.len == 0:
    return
  try:
    result = parseInt(text)
  except ValueError:
    result = fallback

proc soakReportLine*(label: string, final: bool = false): string {.
    role: parser.} =
  ## label: what this line is about, used when `--tag` names nothing better.
  ## final: mark the last line of a run, so a log can be searched for it.
  ## The counters follow in a fixed order, so two lines an hour apart line up
  ## column for column.
  var
    c: SoakCounter = low(SoakCounter)
    rss: int = soakRssKib()
    parts: seq[string] = @[]
  parts.add(soakArg("tag", label) & (if final: " FINAL" else: ""))
  parts.add("t=" & formatFloat(soakElapsedSeconds(), ffDecimal, 1) & "s")
  while true:
    if soakValue(c) > 0'u64:
      parts.add(soakCounterName(c) & "=" & $soakValue(c))
    if c == high(SoakCounter):
      break
    c = succ(c)
  parts.add("live=" & $soakLevelSum())
  parts.add("rss=" & $rss & "K")
  parts.add("heap=" & $(getOccupiedMem() div 1024) & "K")
  result = parts.join("  ")

proc soakScenario*(name: string): DacScenario {.role: parser.} =
  ## name: a scenario named on the command line, or `cleanLan` when the word
  ## is not one of them. The lane still adapts from what the path reports say;
  ## this only decides where the link starts.
  case name.toLowerAscii()
  of "sameroom": result = dscSameRoom
  of "cleanlan": result = dscCleanLan
  of "mobile": result = dscMobile
  of "metered": result = dscMetered
  of "thin": result = dscThin
  of "badsignal": result = dscBadSignal
  of "heavyloss": result = dscHeavyLoss
  of "jitter": result = dscJitter
  of "unstablepath": result = dscUnstablePath
  of "overloaded": result = dscOverloaded
  of "batterysaver": result = dscBatterySaver
  of "weakrecovery": result = dscWeakRecovery
  else: result = dscCleanLan

proc packSoakHost*(host: string): array[48, char] {.role: helper.} =
  ## host: a dotted address copied into plain storage, because a thread
  ## argument may hold no managed memory.
  var
    i: int = 0
    n: int = min(host.len, 47)
  while i < n:
    result[i] = host[i]
    i = i + 1

proc unpackSoakHost*(A: array[48, char]): string {.role: helper.} =
  ## A: the same storage read back into a string on the thread that owns it.
  var
    i: int = 0
  while i < 48 and A[i] != '\0':
    result.add(A[i])
    i = i + 1
