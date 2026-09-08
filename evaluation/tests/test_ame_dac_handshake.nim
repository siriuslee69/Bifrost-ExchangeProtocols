## -------------------------------------------------------------------------
## AME Handshake over DAC <- two real UDP sockets, one of them losing things
## -------------------------------------------------------------------------
##
## The TCP driver gets a stream that does not lose, duplicate or reorder. This
## one gets none of that, so the interesting cases are not "does it work" but
## "does it still work when a datagram goes missing".
##
##   server thread                       main thread
##   -------------                       -----------
##   openDacListener, publish port  -->  openDacListener
##   (optionally swallow one datagram)   ameDacClientHandshake
##   ameDacServerHandshake          <->      hello, maybe retransmitted
##                                           cookie retry
##                                           server hello
##                                           finish, sent twice
##   sealAmeDacFrame echo           <->  sealAmeDacFrame / openAmeDacFrame
##
## As in the TCP suite, nothing crosses the thread boundary but plain values
## and bytes on a socket: both sides rebuild the same authority from seeds.

import std/[atomics, os, strutils, unittest]

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/signatures
import ../../src/protocols/ame/level1/path_triggers
import ../../src/protocols/ame/level2/session
import ../../src/protocols/ame/level2/carriers
import ../../src/protocols/ame/level3/handshake
import ../../src/protocols/ame/level3/handshake_dac
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/transport
import ../../src/analysis_pragmas

const
  handshakeKems: AmeKemAlgorithms = [akaX25519, akaFireSaber]
  nowUnix: int64 = 500'i64
  validFrom: int64 = 100'i64
  validUntil: int64 = 1000'i64
  serverErrMax = 192
  handshakeTimeoutMs = 4000

proc slotSeeds(tag: int): seq[ByteSeq] =
  ## tag: which identity these seeds belong to.
  var
    algorithms: AmeSignatureAlgorithms = initAmeSignatureAlgorithms(
      defaultAmeSigSlots())
    seed: ByteSeq = @[]
    i: int = 0
    j: int = 0
  while i < int(algorithms.length):
    seed = newSeq[byte](32)
    j = 0
    while j < 32:
      seed[j] = uint8((j * 5 + i * 29 + tag * 97) mod 251)
      j = j + 1
    result.add(seed)
    i = i + 1

proc sigAlgorithms(): AmeSignatureAlgorithms =
  result = initAmeSignatureAlgorithms(defaultAmeSigSlots())

proc authorityFor(tag: int): AmeAuthorityKey =
  result = initAmeAuthorityKey("dac-root-" & $tag, sigAlgorithms(),
    slotSeeds(tag))

proc identityFor(subject: string, tag: int): AmeIdentityKey =
  result = initAmeIdentityKey(subject, sigAlgorithms(), slotSeeds(tag))

proc dacLayout(): AmeSuiteLayout =
  result = defaultAmeLayout(handshakeKems)

proc dacTier(L: AmeSuiteLayout): AmeMaskTier =
  result = initAmeMaskTier(L, 1'u32, initAmeTierMasks(0b11000000'u8,
    occupiedAmeMask(L.ciphers.length), occupiedAmeMask(L.macs.length),
    occupiedAmeMask(L.hashes.length), occupiedAmeMask(L.signatures.length),
    occupiedAmeMask(L.kdfs.length)))

type
  DacServerArgs = object
    requireCookie: bool
    swallowFirst: bool
      ## Read one datagram and throw it away before starting. That is a lost
      ## hello, produced deterministically instead of hoped for.

  DacServerReport = object
    ok: bool
    echoed: bool
    trusted: bool
    errLen: int
    err: array[serverErrMax, char]

var
  serverReport: DacServerReport
  serverReady: Atomic[bool]
  serverPort: Atomic[int]

proc reportErr(text: string) =
  ## text: failure text copied into the shared fixed buffer.
  var i: int = 0
  serverReport.errLen = min(text.len, serverErrMax)
  while i < serverReport.errLen:
    serverReport.err[i] = text[i]
    i = i + 1

proc serverError(): string =
  ## The server thread's error text, read only after the join.
  var i: int = 0
  result = newString(serverReport.errLen)
  while i < serverReport.errLen:
    result[i] = serverReport.err[i]
    i = i + 1

proc waitForServer(): uint16 =
  ## Block until the responder has bound a port and finished generating keys.
  while not serverReady.load():
    sleep(10)
  result = uint16(serverPort.load())

proc runDacServer(a: DacServerArgs) {.thread.} =
  ## a: responder behaviour, as plain values.
  var
    sock: DacSocket = openDacListener(initDacAddress("127.0.0.1", 0'u16))
    bound: tuple[ok: bool, port: uint16] = dacLocalPort(sock)
    layout: AmeSuiteLayout = dacLayout()
    tier: AmeMaskTier = dacTier(layout)
    authority: AmeAuthorityKey = authorityFor(1)
    serverKey: AmeIdentityKey = identityFor("dac-server", 3)
    config: AmeResponderPolicy
    done: tuple[outcome: AmeHandshakeOutcome, remote: DacAddress]
    got: DacFrameBytesResult
    session: AmeSession
    opened: AmeOpenResult
  defer:
    closeDac(sock)
  if not bound.ok:
    reportErr("responder could not learn its own port")
    serverReady.store(true)
    return
  config = initAmeResponderPolicy([initAmeTierPath(layout, [tier])],
    initAmeCertificateAuthentication(initAmeAuthorityRoot(authority)),
    issueAmeIdentityCertificate(authority, serverKey, 22'u64, validFrom,
      validUntil), serverKey, a.requireCookie)
  ## Publish the port only once the slow key work is done, so the initiator's
  ## first hello is not lost to nothing more interesting than startup order.
  serverPort.store(int(bound.port))
  serverReady.store(true)
  if a.swallowFirst:
    got = recvDacFrameBytes(sock, 65535, handshakeTimeoutMs)
    if not got.ok:
      reportErr("responder saw no datagram to drop")
      return
  done = ameDacServerHandshake(sock, config, nowUnix, handshakeTimeoutMs)
  serverReport.ok = done.outcome.ok
  serverReport.trusted = done.outcome.peerTrust.ok
  if not done.outcome.ok:
    reportErr(done.outcome.err)
    return
  session = done.outcome.connection
  got = recvDacFrameBytes(sock, 65535, handshakeTimeoutMs)
  if not got.ok:
    reportErr("responder receive failed: " & got.err)
    clearAmeSession(session)
    return
  opened = openAmeDacFrame(session, got.payload)
  if not opened.ok:
    reportErr("responder open failed: " & opened.err)
    clearAmeSession(session)
    return
  try:
    sendDacFrameBytes(sock, done.remote,
      sealAmeDacFrame(session, opened.packet.payload))
    serverReport.echoed = true
  except CatchableError as e:
    reportErr("responder send failed: " & e.msg)
  clearAmeSession(session)

proc clientPolicy(): AmeInitiatorPolicy =
  ## The initiator side of the same provisioned pair.
  var
    layout: AmeSuiteLayout = dacLayout()
    clientKey: AmeIdentityKey = identityFor("dac-client", 2)
    authority: AmeAuthorityKey = authorityFor(1)
  result = initAmeInitiatorPolicy(layout, dacTier(layout),
    initAmeCertificateAuthentication(initAmeAuthorityRoot(authority)),
    issueAmeIdentityCertificate(authority, clientKey, 11'u64, validFrom,
      validUntil), clientKey)

proc rampBytes(n: int): ByteSeq =
  ## n: payload length filled with a deterministic ramp.
  var i: int = 0
  result = newSeq[uint8](n)
  while i < n:
    result[i] = uint8((i * 23 + 3) mod 251)
    i = i + 1

## One complete client run against a responder started with `args`.
proc runClientAgainst(args: DacServerArgs, payload: ByteSeq):
    tuple[outcome: AmeHandshakeOutcome, echoed: AmeOpenResult] {.role: orchestrator.} =
  var
    th: Thread[DacServerArgs]
    sock: DacSocket
    peer: DacAddress
    got: DacFrameBytesResult
  serverReport = default(DacServerReport)
  serverReady.store(false)
  serverPort.store(0)
  createThread(th, runDacServer, args)
  peer = initDacAddress("127.0.0.1", waitForServer())
  sock = openDacListener(initDacAddress("127.0.0.1", 0'u16))
  result.outcome = ameDacClientHandshake(sock, peer, clientPolicy(), 7'u64,
    nowUnix, handshakeTimeoutMs)
  if result.outcome.ok:
    sendDacFrameBytes(sock, peer,
      sealAmeDacFrame(result.outcome.connection, payload))
    got = recvDacFrameBytes(sock, 65535, handshakeTimeoutMs)
    if got.ok:
      result.echoed = openAmeDacFrame(result.outcome.connection, got.payload)
  joinThread(th)
  closeDac(sock)

suite "AME handshake over real UDP sockets":
  test "a certified handshake survives the cookie retry and carries data":
    var
      payload: ByteSeq = rampBytes(512)
      run = runClientAgainst(DacServerArgs(requireCookie: true), payload)
    check run.outcome.err == ""
    check run.outcome.ok
    check run.outcome.peerTrust.ok
    check run.outcome.peerTrust.subjectKeyId == "dac-server"
    check serverError() == ""
    check serverReport.ok
    check serverReport.trusted
    check serverReport.echoed
    check run.echoed.ok
    check run.echoed.packet.payload == payload
    clearAmeSession(run.outcome.connection)

  test "a responder that wants no cookie answers the first hello":
    var
      payload: ByteSeq = rampBytes(64)
      run = runClientAgainst(DacServerArgs(requireCookie: false), payload)
    check run.outcome.err == ""
    check run.outcome.ok
    check serverError() == ""
    check run.echoed.ok
    check run.echoed.packet.payload == payload
    clearAmeSession(run.outcome.connection)

  test "a lost hello is recovered by retransmission":
    var
      payload: ByteSeq = rampBytes(200)
      run = runClientAgainst(DacServerArgs(requireCookie: true,
        swallowFirst: true), payload)
    ## The responder threw the first datagram away. Nothing else changes, so
    ## anything that completes here completed because the initiator sent its
    ## hello again rather than because the wire was kind.
    check run.outcome.err == ""
    check run.outcome.ok
    check serverError() == ""
    check serverReport.ok
    check run.echoed.ok
    check run.echoed.packet.payload == payload
    clearAmeSession(run.outcome.connection)

suite "records that no datagram can carry":
  test "a record over the datagram limit is refused at the sender":
    var
      sock: DacSocket = openDacListener(initDacAddress("127.0.0.1", 0'u16))
      outcome: AmeHandshakeOutcome
    defer:
      closeDac(sock)
    ## 64 bytes cannot hold a hello, so the driver has to say so rather than
    ## hand the socket something that would be dropped somewhere out on the
    ## path with no error anybody could act on.
    outcome = ameDacClientHandshake(sock,
      initDacAddress("127.0.0.1", 9'u16), clientPolicy(), 7'u64, nowUnix,
      200, 64)
    check not outcome.ok
    check outcome.err.len > 0
    check outcome.err.contains("datagram limit")

  test "an unanswered hello gives up instead of retrying forever":
    var
      sock: DacSocket = openDacListener(initDacAddress("127.0.0.1", 0'u16))
      silent: DacSocket = openDacListener(initDacAddress("127.0.0.1", 0'u16))
      bound: tuple[ok: bool, port: uint16] = dacLocalPort(silent)
      outcome: AmeHandshakeOutcome
    defer:
      closeDac(sock)
      closeDac(silent)
    check bound.ok
    ## A bound port that never answers, so the datagrams arrive and are simply
    ## ignored. The driver must exhaust its retries and return an error.
    outcome = ameDacClientHandshake(sock,
      initDacAddress("127.0.0.1", bound.port), clientPolicy(), 7'u64,
      nowUnix, 60)
    check not outcome.ok
    check outcome.err.len > 0
