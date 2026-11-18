## -------------------------------------------------------------------------
## AME Handshake over DAC <- the same records, on a wire that loses things
## -------------------------------------------------------------------------
##
## The TCP driver next door can assume that what it sends arrives, once, in
## order. None of that is true here. A datagram carrier gives three problems
## the stream one never had, and this file exists to solve exactly those:
##
##   loss         a record that vanishes must be sent again, so the initiator
##                keeps the last record it sent and repeats it on a timeout
##   duplication  a repeated record must not be answered twice, so the
##                responder answers from what it already computed rather than
##                starting over
##   reordering   a record from the wrong step is dropped rather than parsed,
##                which the step field already makes cheap
##
##   client                                          server
##   ------                                          ------
##   ameDacClientHandshake()                         ameDacServerHandshake()
##       |  send address probe ---X (lost)               |  waiting
##       |  ...timeout, send probe again --------------> |  read probe
##       |                                               |  mint cookie
##       |  <------------------------------------------- |
##       |  send hello + cookie -----------------------> |  read, cookie ok
##       |  <-------------------------- send server hello|
##       |  send finish -------------------------------> |  read finish
##       |                                               |
##       +--------- both return a ready AmeSession ------+
##
## Who retransmits: the initiator, always. The responder answers what it is
## asked and never speaks first, so a lost server hello is recovered by the
## initiator repeating its hello and the responder repeating its answer. That
## keeps all the timers on one side, and it means a responder holds no timer
## state per peer -- which is what lets it survive being shouted at.
##
## In this driver, one record uses one datagram. A record can be large when the
## layout carries several FrodoKEM-1344 keys, and this file will not silently hand
## that to a socket that cannot carry it. `maxDatagramBytes` bounds what it
## will send, and a record that does not fit is an error at the sender rather
## than a black hole at the receiver.
##
## Note on the clock: as with TCP, `nowUnix` is supplied by the caller. The
## retransmission timers are a different clock entirely -- they are relative
## milliseconds handed to the socket, and never touch certificate validity.

import std/[monotimes, times]

import ../../types
import ../types
import ../../dac/types as dac_types
import ../../dac/level0/transport as dac_transport
import ../level2/session
import ./handshake
import ./handshake_wire
import ./handshake_transport
import runePragmas

export handshake_transport

const
  ameDacHandshakeMaxDatagram* = 60_000
    ## What one handshake record may occupy. IP will fragment up to 64 KiB,
    ## and a handshake is a handful of datagrams that happen once, so paying
    ## for fragmentation here is cheaper than inventing a second reassembly
    ## layer beside DAC's own. Below that ceiling by enough to leave room for
    ## the UDP and IP headers.

  ameDacHandshakeRetries* = 4
    ## How many times the initiator repeats a record before giving up. Four
    ## attempts over the default timeout is roughly eight seconds, which is
    ## long enough to ride out a transient loss and short enough that a peer
    ## that is simply gone does not hold the caller forever.

  ameDacHandshakeAcceptMs* = 30_000
    ## How long a responder waits for a first hello before returning. This is
    ## an idle socket, not a stalled handshake, so it is generous: the caller
    ## decides when to stop listening, and the natural way to say "stop" is a
    ## short value here rather than a lost record.

  ameDacHandshakeMaxStray* = 32
    ## How many datagrams that are not the record being waited for may arrive
    ## before a wait gives up. Without a bound, anybody who can reach the
    ## socket could hold a handshake open forever by sending noise.

type
  ## One record a driver is prepared to accept at this point in the exchange.
  AmeHandshakeExpect {.role: configurator.} = object
    kind: AmePacketKind
    step: uint32

proc peerIdBytes(a: DacAddress): ByteSeq {.role: helper.} =
  ## a: the remote address turned into stable bytes for the cookie.
  var
    text: string = formatDacAddress(a)
    i: int = 0
  result.setLen(text.len)
  while i < text.len:
    result[i] = uint8(ord(text[i]))
    i = i + 1

proc requireDatagramFits(frame: openArray[uint8], maxDatagramBytes: int) {.
    role: helper.} =
  ## frame/maxDatagramBytes: refuse to send a record no datagram can carry.
  if frame.len > maxDatagramBytes:
    raise newException(ValueError,
      "AME handshake record is " & $frame.len &
      " bytes, over the " & $maxDatagramBytes &
      "-byte datagram limit; use a layout with smaller KEM keys or the TCP carrier")

proc readHandshakeFrame(sock: DacSocket, timeoutMs: int,
    maxDatagramBytes: int): tuple[ok: bool, frame: AmeHandshakeFrame,
    remote: DacAddress, err: string] {.role: dataFetcher.} =
  ## sock/timeoutMs/maxDatagramBytes: read one datagram and parse it as a
  ## handshake record. A datagram that is not one is reported, not raised,
  ## because on this carrier anybody can send anything at any time.
  var
    got = recvDacFrameBytes(sock, maxDatagramBytes, timeoutMs)
  if not got.ok:
    result.err = got.err
    if result.err.len == 0:
      result.err = "AME handshake datagram did not arrive"
    return
  result.remote = got.remote
  try:
    result.frame = decodeAmeHandshakeFrame(got.payload)
    result.ok = true
  except CatchableError as e:
    result.err = e.msg

proc matchesExpected(f: AmeHandshakeFrame,
    wanted: openArray[AmeHandshakeExpect]): bool {.inline, role: parser,
    tag: "validation".} =
  ## f/wanted: is this frame one of the records this step was waiting for?
  ## Both possible answers to a hello are awaited at once, so this is a list
  ## rather than a single comparison.
  var
    i: int = 0
  while i < wanted.len:
    if f.kind == wanted[i].kind and f.step == wanted[i].step:
      return true
    i = i + 1

proc awaitStep(sock: DacSocket, wanted: openArray[AmeHandshakeExpect],
    sessionId: uint64, timeoutMs, maxDatagramBytes: int,
    remote: DacAddress):
    tuple[ok: bool, frame: AmeHandshakeFrame, err: string] {.
    role: dataFetcher.} =
  ## Read until one of the wanted records arrives, a read times out, or too
  ## many datagrams turn up that are none of them.
  ##
  ## Two things make this different from the TCP driver's single read. One is
  ## that a stray datagram must not end a handshake, or anybody able to send
  ## one packet could stop every handshake on the machine -- so anything
  ## unwanted is dropped and the read repeated. The source address and
  ## proposed session ID must both match.
  ##
  ## Skipping is bounded. An attacker who can reach the socket can otherwise
  ## keep this loop alive indefinitely by sending noise.
  var
    got: tuple[ok: bool, frame: AmeHandshakeFrame, remote: DacAddress,
      err: string] = (false, default(AmeHandshakeFrame), default(DacAddress), "")
    skipped: int = 0
  while skipped <= ameDacHandshakeMaxStray:
    got = readHandshakeFrame(sock, timeoutMs, maxDatagramBytes)
    if not got.ok:
      result.err = got.err
      return
    skipped = skipped + 1
    if formatDacAddress(got.remote) != formatDacAddress(remote):
      continue
    if sessionId != 0'u64 and got.frame.sessionId != sessionId:
      continue
    if not matchesExpected(got.frame, wanted):
      continue
    return (true, got.frame, "")
  result.err = "AME handshake saw only unrelated datagrams"

proc sendRecord(sock: DacSocket, remote: DacAddress, frame: ByteSeq,
    maxDatagramBytes: int) {.role: dataWriter.} =
  ## sock/remote/frame/maxDatagramBytes: one record as one datagram.
  requireDatagramFits(frame, maxDatagramBytes)
  sendDacFrameBytes(sock, remote, frame)

proc validClientHello(f: AmeHandshakeFrame, c: AmeResponderPolicy,
    A: openArray[uint8], now: int64): AmeClientHello {.role: parser.} =
  ## f/c/A/now: validate a hello and its cookie for this source address.
  if f.kind != ampkClientHello:
    return
  if f.step == ameHandshakeStepHello and c.requireCookie:
    return
  if f.step != ameHandshakeStepHello and f.step != ameHandshakeStepRetriedHello:
    return
  result = decodeAmeClientHello(f.record)
  if result.sessionId != f.sessionId or (f.step == ameHandshakeStepRetriedHello and
      not ameCookieValid(c.cookieSecret, A, now, f.sessionId, result.cookie)):
    result = default(AmeClientHello)

proc admitClientHello(sock: DacSocket, c: AmeResponderPolicy, f: AmeHandshakeFrame,
    remote: DacAddress, maxDatagramBytes: int): AmeClientHello {.role: orchestrator.} =
  ## Answer the probe or return a hello from a peer that proved its address.
  var
    peer: ByteSeq = peerIdBytes(remote)
    now: int64 = getTime().toUnix()
  try:
    if f.kind == ampkHandshakeProbe:
      sendRecord(sock, remote, answerAmeHandshakeProbe(f, c.cookieSecret, peer, now),
        maxDatagramBytes)
      return
    result = validClientHello(f, c, peer, now)
  except CatchableError:
    discard

proc awaitClientHello(sock: DacSocket, c: AmeResponderPolicy,
    timeoutMs, maxDatagramBytes, acceptTimeoutMs: int): tuple[
    hello: AmeClientHello, remote: DacAddress] {.role: dataFetcher.} =
  ## Answer probes without reserving a responder or waiting on that address.
  var
    deadline: MonoTime = getMonoTime() + initDuration(milliseconds = acceptTimeoutMs)
    remaining: int = 0
    got: tuple[ok: bool, frame: AmeHandshakeFrame, remote: DacAddress, err: string] =
      (false, default(AmeHandshakeFrame), default(DacAddress), "")
  while getMonoTime() < deadline:
    remaining = max(1, int((deadline - getMonoTime()).inMilliseconds))
    got = readHandshakeFrame(sock, min(max(1, timeoutMs), remaining), maxDatagramBytes)
    if not got.ok:
      continue
    result.hello = admitClientHello(sock, c, got.frame, got.remote, maxDatagramBytes)
    if result.hello.sessionId != 0:
      result.remote = got.remote
      return

proc ameDacServerHandshake*(sock: DacSocket, c: AmeResponderPolicy,
    nowUnix: int64, timeoutMs: int = 2000,
    sessionId: uint64 = 0'u64,
    maxDatagramBytes: int = ameDacHandshakeMaxDatagram,
    acceptTimeoutMs: int = ameDacHandshakeAcceptMs):
    tuple[outcome: AmeHandshakeOutcome, remote: DacAddress] {.
    role: orchestrator, tag: "appApi|networkSurface".} =
  ## sock/c/nowUnix/timeoutMs/sessionId/maxDatagramBytes/acceptTimeoutMs: run
  ## the responder side to completion and hand back a session plus the address
  ## it belongs to. The address is a return value rather than an argument
  ## because on a datagram socket the responder learns who it is talking to by
  ## listening.
  ##
  ## Two timeouts, because they answer different questions. `acceptTimeoutMs`
  ## is how long to sit waiting for anybody at all; `timeoutMs` is how long to
  ## wait for the next record of a handshake already under way. Collapsing
  ## them would mean a responder gives up on an idle socket as fast as it
  ## gives up on a peer that stopped mid-exchange -- and since the initiator
  ## only retransmits AFTER its own timeout expires, a responder waiting one
  ## `timeoutMs` for a first hello is very likely to have already left by the
  ## time the retransmission arrives.
  ##
  ## `nowUnix` is the trusted wall clock certificates are judged against.
  ## `sessionId` overrides the id the client proposed; 0 keeps the client's.
  var
    got: tuple[ok: bool, frame: AmeHandshakeFrame, err: string] =
      (false, default(AmeHandshakeFrame), "")
    incoming = awaitClientHello(sock, c, timeoutMs, maxDatagramBytes,
      acceptTimeoutMs)
    hello: AmeClientHello = move(incoming.hello)
    answered: tuple[ok: bool, state: AmeServerHandshake, err: string] =
      (false, default(AmeServerHandshake), "")
    finish: AmeClientFinish = default(AmeClientFinish)
    accepted: AmeHandshakeResult = default(AmeHandshakeResult)
    serverHelloFrame: ByteSeq = @[]
  if hello.sessionId == 0:
    result.outcome.err = "AME handshake got no admitted client hello"
    return
  result.remote = incoming.remote
  answered = answerAmeHandshake(hello, c.supported, c.authentication, c.descriptor,
    c.identity,
    c.params)
  if not answered.ok:
    result.outcome.err = answered.err
    return
  serverHelloFrame = encodeAmeServerHelloFrame(hello.sessionId,
    answered.state.serverHello)
  try:
    sendRecord(sock, result.remote, serverHelloFrame, maxDatagramBytes)
  except CatchableError as e:
    clearAmeServerHandshake(answered.state)
    result.outcome.err = "AME server hello send failed: " & e.msg
    return
  ## If the server hello was lost the initiator repeats its hello. Answering
  ## that with the SAME server hello is what makes the exchange idempotent:
  ## recomputing it would pick fresh key material and orphan the transcript
  ## the initiator is already committed to.
  while true:
    got = awaitStep(sock, [AmeHandshakeExpect(kind: ampkClientFinish,
      step: ameHandshakeStepFinish)], hello.sessionId, timeoutMs,
      maxDatagramBytes, result.remote)
    if got.ok:
      break
    ## Nothing arrived. Repeat the answer once in case it was the answer that
    ## went missing rather than the finish, then give up.
    try:
      sendRecord(sock, result.remote, serverHelloFrame, maxDatagramBytes)
    except CatchableError:
      discard
    got = awaitStep(sock, [AmeHandshakeExpect(kind: ampkClientFinish,
      step: ameHandshakeStepFinish)], hello.sessionId, timeoutMs,
      maxDatagramBytes, result.remote)
    if not got.ok:
      clearAmeServerHandshake(answered.state)
      result.outcome.err = got.err
      return
    break
  try:
    finish = decodeAmeClientFinish(got.frame.record)
  except CatchableError as e:
    clearAmeServerHandshake(answered.state)
    result.outcome.err = e.msg
    return
  accepted = acceptAmeHandshake(answered.state, finish,
    nowUnix, c.revokedSerials)
  if not accepted.ok:
    result.outcome.err = accepted.err
    result.outcome.peerTrust = accepted.peerTrust
    return
  result.outcome.peerTrust = accepted.peerTrust
  result.outcome.connection = initAmeSession(accepted.auth, sessionId,
    peerTrust = accepted.peerTrust)
  result.outcome.ok = true

proc awaitWithResend(sock: DacSocket, peer: DacAddress, frame: ByteSeq,
    wanted: openArray[AmeHandshakeExpect], sessionId: uint64,
    timeoutMs, maxDatagramBytes: int, noAnswer, resendFailed: string):
    tuple[ok: bool, frame: AmeHandshakeFrame, err: string] {.
    role: orchestrator.} =
  ## Wait for one of `wanted`; after each silent wait send `frame` again,
  ## byte for byte, up to `ameDacHandshakeRetries` waits in all.
  ## noAnswer/resendFailed: the error for each way of giving up.
  var
    attempts: int = 1
  result = awaitStep(sock, wanted, sessionId, timeoutMs, maxDatagramBytes,
    peer)
  while not result.ok and attempts < ameDacHandshakeRetries:
    try:
      sendRecord(sock, peer, frame, maxDatagramBytes)
    except CatchableError as e:
      return (false, default(AmeHandshakeFrame), resendFailed & e.msg)
    attempts = attempts + 1
    result = awaitStep(sock, wanted, sessionId, timeoutMs, maxDatagramBytes,
      peer)
  if not result.ok:
    result.err = noAnswer

proc ameDacClientHandshake*(sock: DacSocket, remote: DacAddress,
    c: AmeInitiatorPolicy, sessionId: uint64, nowUnix: int64,
    timeoutMs: int = 2000,
    maxDatagramBytes: int = ameDacHandshakeMaxDatagram):
    AmeHandshakeOutcome {.role: orchestrator,
    tag: "appApi|networkSurface".} =
  ## sock/remote/c/sessionId/nowUnix/timeoutMs/maxDatagramBytes: run the
  ## initiator side to completion against one known responder address.
  var
    state: AmeClientHandshake = default(AmeClientHandshake)
    cookie: ByteSeq = @[]
    got: tuple[ok: bool, frame: AmeHandshakeFrame, err: string] =
      (false, default(AmeHandshakeFrame), "")
    pending: ByteSeq = @[]
      ## The record the initiator may have to send again, kept byte for byte:
      ## rebuilding a hello would make fresh keys and void its cookie.
    serverHello: AmeServerHello = default(AmeServerHello)
    finished: AmeHandshakeResult = default(AmeHandshakeResult)
    peer: DacAddress = remote

  if sessionId == 0'u64:
    result.err = "AME client session id must be positive"
    return
  try:
    pending = encodeAmeHandshakeProbe(sessionId)
    sendRecord(sock, peer, pending, maxDatagramBytes)
  except CatchableError as e:
    result.err = "AME address probe send failed: " & e.msg
    return
  got = awaitWithResend(sock, peer, pending, [AmeHandshakeExpect(
    kind: ampkHelloRetry, step: ameHandshakeStepRetry)], sessionId, timeoutMs,
    maxDatagramBytes, "AME handshake got no address cookie",
    "AME address probe resend failed: ")
  if not got.ok:
    result.err = got.err
    return
  try:
    cookie = readAmeHandshakeCookie(got.frame, sessionId)
    state = beginAmeHandshake(sessionId, c.layout, c.initialTier, 1'u32,
      cookie, c.authentication)
    pending = encodeAmeClientHelloFrame(state.hello, retried = true)
    sendRecord(sock, peer, pending, maxDatagramBytes)
  except CatchableError as e:
    clearAmeClientHandshake(state)
    result.err = "AME client hello send failed: " & e.msg
    return
  got = awaitWithResend(sock, peer, pending, [AmeHandshakeExpect(
    kind: ampkServerHello, step: ameHandshakeStepServerHello)], sessionId,
    timeoutMs, maxDatagramBytes, "AME handshake got no server hello",
    "AME client hello resend failed: ")
  if not got.ok:
    clearAmeClientHandshake(state)
    result.err = got.err
    return
  try:
    serverHello = decodeAmeServerHello(c.layout, got.frame.record)
  except CatchableError as e:
    clearAmeClientHandshake(state)
    result.err = e.msg
    return
  finished = finishAmeHandshake(state, serverHello, c.authentication,
    c.descriptor, c.identity, nowUnix, c.revokedSerials)
  if not finished.ok:
    result.err = finished.err
    result.peerTrust = finished.peerTrust
    return
  ## The finish is the last thing this side sends, and it is sent ONCE.
  ##
  ## Nothing acknowledges it at this layer, so there is nothing to retransmit
  ## against: this side returns immediately afterwards and stops reading. A
  ## second copy would not make the handshake more reliable, and it would
  ## leave a stray record sitting in the responder's socket for whatever
  ## reads next -- which is the application, expecting data.
  ##
  ## A finish that is genuinely lost is the responder's problem to notice:
  ## it fails, and this side discovers it when its first data frame goes
  ## unanswered. Every handshake with a one-flight ending behaves this way.
  try:
    pending = encodeAmeClientFinishFrame(sessionId, finished.finish)
    sendRecord(sock, peer, pending, maxDatagramBytes)
  except CatchableError as e:
    result.err = "AME client finish send failed: " & e.msg
    return
  result.peerTrust = finished.peerTrust
  result.connection = initAmeSession(finished.auth, sessionId,
    peerTrust = finished.peerTrust)
  result.ok = true
