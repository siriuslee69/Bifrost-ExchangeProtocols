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
##       |  send hello -----------X (lost)               |  waiting
##       |  ...timeout, send hello again --------------> |  read hello
##       |                                               |  no cookie: retry
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
## One record, one datagram. A handshake record can be megabytes when the
## layout carries Classic-McEliece keys, and this file will not silently hand
## that to a socket that cannot carry it. `maxDatagramBytes` bounds what it
## will send, and a record that does not fit is an error at the sender rather
## than a black hole at the receiver.
##
## Note on the clock: as with TCP, `nowUnix` is supplied by the caller. The
## retransmission timers are a different clock entirely -- they are relative
## milliseconds handed to the socket, and never touch certificate validity.

import ../../types
import ../types
import ../../dac/types as dac_types
import ../../dac/level0/transport as dac_transport
import ../level2/session
import ./handshake
import ./handshake_wire
import ./handshake_transport
import ../../../analysis_pragmas

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
  ## One record the initiator may have to send again, kept so a timeout does
  ## not have to reconstruct it -- rebuilding a hello would generate fresh
  ## keys and invalidate the cookie it was answering.
  AmeDacRetransmit {.role: memory.} = object
    frame: ByteSeq
    step: uint32

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

proc sendRecord(sock: DacSocket, remote: DacAddress, frame: ByteSeq,
    maxDatagramBytes: int) {.role: dataWriter.} =
  ## sock/remote/frame/maxDatagramBytes: one record as one datagram.
  requireDatagramFits(frame, maxDatagramBytes)
  sendDacFrameBytes(sock, remote, frame)

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

proc awaitStep(sock: DacSocket, wanted: openArray[AmeHandshakeExpect],
    sessionId: uint64, timeoutMs, maxDatagramBytes: int,
    remote: var DacAddress, matchRemote: bool):
    tuple[ok: bool, frame: AmeHandshakeFrame, err: string] {.
    role: dataFetcher.} =
  ## Read until one of the wanted records arrives, a read times out, or too
  ## many datagrams turn up that are none of them.
  ##
  ## Two things make this different from the TCP driver's single read. One is
  ## that a stray datagram must not end a handshake, or anybody able to send
  ## one packet could stop every handshake on the machine -- so anything
  ## unwanted is dropped and the read repeated. The other is that the caller
  ## usually has to accept MORE THAN ONE record: an initiator that waits only
  ## for a cookie retry will read the server hello, find it is not a retry,
  ## and throw away the very record it was about to need.
  ##
  ## Skipping is bounded. An attacker who can reach the socket can otherwise
  ## keep this loop alive indefinitely by sending noise.
  var
    got: tuple[ok: bool, frame: AmeHandshakeFrame, remote: DacAddress,
      err: string]
    skipped: int = 0
    i: int = 0
  while skipped <= ameDacHandshakeMaxStray:
    got = readHandshakeFrame(sock, timeoutMs, maxDatagramBytes)
    if not got.ok:
      result.err = got.err
      return
    skipped = skipped + 1
    if matchRemote and formatDacAddress(got.remote) != formatDacAddress(remote):
      continue
    if sessionId != 0'u64 and got.frame.sessionId != sessionId:
      continue
    i = 0
    while i < wanted.len:
      if got.frame.kind == wanted[i].kind and got.frame.step == wanted[i].step:
        if not matchRemote:
          remote = got.remote
        result.frame = got.frame
        result.ok = true
        return
      i = i + 1
  result.err = "AME handshake saw only unrelated datagrams"

proc ameDacServerHandshake*(sock: DacSocket, c: AmeResponderPolicy,
    nowUnix: int64, timeoutMs: int = 2000,
    sessionId: uint64 = 0'u64,
    maxDatagramBytes: int = ameDacHandshakeMaxDatagram,
    acceptTimeoutMs: int = ameDacHandshakeAcceptMs):
    tuple[outcome: AmeHandshakeOutcome, remote: DacAddress] {.
    role: orchestrator, tag: {tagAppApi, tagNetworkSurface}.} =
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
    got: tuple[ok: bool, frame: AmeHandshakeFrame, err: string]
    hello: AmeClientHello
    retry: AmeHelloRetry
    answered: tuple[ok: bool, state: AmeServerHandshake, err: string]
    finish: AmeClientFinish
    accepted: AmeHandshakeResult
    peerId: ByteSeq = @[]
    serverHelloFrame: ByteSeq = @[]
    listens: int = 0
    maxListens: int = max(1, acceptTimeoutMs div max(1, timeoutMs))
  while true:
    listens = listens + 1
    got = awaitStep(sock, [AmeHandshakeExpect(kind: ampkClientHello,
      step: ameHandshakeStepHello)], 0'u64, timeoutMs, maxDatagramBytes,
      result.remote, false)
    if got.ok:
      break
    if listens >= maxListens:
      result.outcome.err = got.err
      return
  try:
    hello = decodeAmeClientHello(got.frame.record)
  except CatchableError as e:
    result.outcome.err = e.msg
    return
  peerId = peerIdBytes(result.remote)
  ## The cookie round trip happens before ANY key work. On a datagram carrier
  ## this is the only thing standing between the responder and a stranger who
  ## can make it do post-quantum key exchanges by spoofing a source address.
  if c.requireCookie and
      not ameCookieValid(c.cookieSecret, peerId, nowUnix, hello):
    retry.sessionId = hello.sessionId
    retry.cookie = issueAmeCookie(c.cookieSecret, peerId, nowUnix, hello)
    try:
      sendRecord(sock, result.remote, encodeAmeHelloRetryFrame(retry),
        maxDatagramBytes)
    except CatchableError as e:
      result.outcome.err = "AME hello retry send failed: " & e.msg
      return
    got = awaitStep(sock, [AmeHandshakeExpect(kind: ampkClientHello,
      step: ameHandshakeStepRetriedHello)], hello.sessionId, timeoutMs,
      maxDatagramBytes, result.remote, true)
    if not got.ok:
      result.outcome.err = got.err
      return
    try:
      hello = decodeAmeClientHello(got.frame.record)
    except CatchableError as e:
      result.outcome.err = e.msg
      return
    if not ameCookieValid(c.cookieSecret, peerId, nowUnix, hello):
      result.outcome.err = "AME hello retry cookie is invalid"
      return
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
      maxDatagramBytes, result.remote, true)
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
      maxDatagramBytes, result.remote, true)
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
  accepted = acceptAmeHandshake(answered.state, finish, c.authentication,
    nowUnix, c.revokedSerials)
  if not accepted.ok:
    result.outcome.err = accepted.err
    result.outcome.peerTrust = accepted.peerTrust
    return
  result.outcome.peerTrust = accepted.peerTrust
  result.outcome.connection = initAmeSession(accepted.auth, sessionId,
    peerTrust = accepted.peerTrust)
  result.outcome.ok = true

proc ameDacClientHandshake*(sock: DacSocket, remote: DacAddress,
    c: AmeInitiatorPolicy, sessionId: uint64, nowUnix: int64,
    timeoutMs: int = 2000,
    maxDatagramBytes: int = ameDacHandshakeMaxDatagram):
    AmeHandshakeOutcome {.role: orchestrator,
    tag: {tagAppApi, tagNetworkSurface}.} =
  ## sock/remote/c/sessionId/nowUnix/timeoutMs/maxDatagramBytes: run the
  ## initiator side to completion against one known responder address.
  var
    state: AmeClientHandshake
    got: tuple[ok: bool, frame: AmeHandshakeFrame, err: string]
    pending: AmeDacRetransmit
    retry: AmeHelloRetry
    serverHello: AmeServerHello
    finished: AmeHandshakeResult
    peer: DacAddress = remote
    attempts: int = 0

  if sessionId == 0'u64:
    result.err = "AME client session id must be positive"
    return
  try:
    state = beginAmeHandshake(sessionId, c.layout, c.initialTier,
      mode = c.authentication.mode)
    pending.frame = encodeAmeClientHelloFrame(state.hello)
    pending.step = ameHandshakeStepHello
    sendRecord(sock, peer, pending.frame, maxDatagramBytes)
  except CatchableError as e:
    clearAmeClientHandshake(state)
    result.err = "AME client hello send failed: " & e.msg
    return

  ## Repeat the hello until something answers it. The stored frame is sent
  ## byte for byte, because a rebuilt hello would carry new keys and a new
  ## transcript, and the responder would be answering a different question.
  ##
  ## Both possible answers are accepted in ONE wait. A responder that wants a
  ## cookie sends a retry; one that does not sends its hello straight away.
  ## Waiting for only the first would read the second, decide it was not what
  ## was asked for, and discard the record the handshake depends on.
  while true:
    attempts = attempts + 1
    got = awaitStep(sock, [
      AmeHandshakeExpect(kind: ampkHelloRetry, step: ameHandshakeStepRetry),
      AmeHandshakeExpect(kind: ampkServerHello,
        step: ameHandshakeStepServerHello)], sessionId, timeoutMs,
      maxDatagramBytes, peer, true)
    if got.ok:
      break
    if attempts >= ameDacHandshakeRetries:
      clearAmeClientHandshake(state)
      result.err = "AME handshake got no answer to the client hello"
      return
    try:
      sendRecord(sock, peer, pending.frame, maxDatagramBytes)
    except CatchableError as e:
      clearAmeClientHandshake(state)
      result.err = "AME client hello resend failed: " & e.msg
      return

  if got.frame.kind == ampkHelloRetry:
    ## The responder wants proof this address can receive. Build a fresh
    ## hello -- fresh KEM keys and all -- carrying its cookie.
    try:
      retry = decodeAmeHelloRetry(got.frame.record)
      clearAmeClientHandshake(state)
      state = beginAmeHandshake(sessionId, c.layout, c.initialTier, 1'u32,
        retry.cookie, c.authentication.mode)
      pending.frame = encodeAmeClientHelloFrame(state.hello, retried = true)
      pending.step = ameHandshakeStepRetriedHello
      sendRecord(sock, peer, pending.frame, maxDatagramBytes)
    except CatchableError as e:
      clearAmeClientHandshake(state)
      result.err = "AME hello retry failed: " & e.msg
      return
    attempts = 0
    while true:
      attempts = attempts + 1
      got = awaitStep(sock, [AmeHandshakeExpect(kind: ampkServerHello,
        step: ameHandshakeStepServerHello)], sessionId, timeoutMs,
        maxDatagramBytes, peer, true)
      if got.ok:
        break
      if attempts >= ameDacHandshakeRetries:
        clearAmeClientHandshake(state)
        result.err = "AME handshake got no server hello"
        return
      try:
        sendRecord(sock, peer, pending.frame, maxDatagramBytes)
      except CatchableError as e:
        clearAmeClientHandshake(state)
        result.err = "AME retried hello resend failed: " & e.msg
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
    pending.frame = encodeAmeClientFinishFrame(sessionId, finished.finish)
    pending.step = ameHandshakeStepFinish
    sendRecord(sock, peer, pending.frame, maxDatagramBytes)
  except CatchableError as e:
    result.err = "AME client finish send failed: " & e.msg
    return
  result.peerTrust = finished.peerTrust
  result.connection = initAmeSession(finished.auth, sessionId,
    peerTrust = finished.peerTrust)
  result.ok = true
