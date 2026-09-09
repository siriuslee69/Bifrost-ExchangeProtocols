## -------------------------------------------------------------------------
## AME over a real TCP socket <- the driver, the carrier, and a live peer
## -------------------------------------------------------------------------
##
## Every other AME test hands records from one variable to another. That
## proves the records are right; it proves nothing about the file that owns
## the socket. `handshake_tcp.nim` decides when to read, when a short read is
## not a record yet, and when to give up -- and none of that is visible to a
## test that never blocks on anything.
##
##   main thread                       server thread
##   -----------                       -------------
##   connectTcp ------------------->   acceptTcpClient
##   ameTcpClientHandshake  <----->    ameTcpServerHandshake
##       |  hello                          |  cookie retry, then the real one
##       |  server hello                   |
##       |  finish                         |
##   sendAmeTcp    ---------------->    recvAmeTcp
##   recvAmeTcp    <----------------    sendAmeTcp
##
## The two sides never share a variable. Both rebuild the same authority from
## the same seeds, exactly as two provisioned machines would, so the only
## thing that crosses between them is bytes on a socket.

import std/[atomics, net, os, unittest]

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/signatures
import ../../src/protocols/ame/level1/path_triggers
import ../../src/protocols/ame/level2/session
import ../../src/protocols/ame/level2/carriers
import ../../src/protocols/ame/level3/handshake
import ../../src/protocols/ame/level3/handshake_tcp
import ../../src/protocols/transport/types as transport_types
import ../../src/protocols/transport/tcp_ops
import runePragmas

const
  handshakeKems: AmeKemAlgorithms = [akaX25519, akaFireSaber]
  nowUnix: int64 = 500'i64
  validFrom: int64 = 100'i64
  validUntil: int64 = 1000'i64
  echoPort: uint16 = 49010'u16
  pinnedPort: uint16 = 49011'u16
  pskPort: uint16 = 49014'u16
  tcpPskId: string = "tcp-site"
  rejectPort: uint16 = 49012'u16
  carrierPort: uint16 = 49013'u16
  serverErrMax = 192

## ╭⟢ identities both sides can rebuild from nothing but a number
##
## The thread argument has to stay free of heap memory, so no key, no
## certificate and no config may cross the thread boundary. Seeds make that
## easy: give both sides the same small integers and they derive byte-equal
## authority keys independently.

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
      seed[j] = uint8((j * 7 + i * 31 + tag * 101) mod 251)
      j = j + 1
    result.add(seed)
    i = i + 1

proc sigAlgorithms(): AmeSignatureAlgorithms =
  result = initAmeSignatureAlgorithms(defaultAmeSigSlots())

proc authorityFor(tag: int): AmeAuthorityKey =
  result = initAmeAuthorityKey("tcp-root-" & $tag, sigAlgorithms(),
    slotSeeds(tag))

proc tcpPsk(): ByteSeq =
  ## The shared secret both ends of the AM1M variant are provisioned with.
  ## A test value, built from a ramp so the two threads agree without one
  ## having to send it to the other.
  var i: int = 0
  result = newSeq[byte](32)
  while i < result.len:
    result[i] = byte(i * 7 + 3)
    i = i + 1

proc identityFor(subject: string, tag: int): AmeIdentityKey =
  result = initAmeIdentityKey(subject, sigAlgorithms(), slotSeeds(tag))

proc tcpLayout(): AmeSuiteLayout =
  result = defaultAmeLayout(handshakeKems)

proc tcpTier(L: AmeSuiteLayout): AmeMaskTier =
  result = initAmeMaskTier(L, 1'u32, initAmeTierMasks(0b11000000'u8,
    occupiedAmeMask(L.ciphers.length), occupiedAmeMask(L.macs.length),
    occupiedAmeMask(L.hashes.length), occupiedAmeMask(L.signatures.length),
    occupiedAmeMask(L.kdfs.length)))

## ╭⟢ what the server thread reports back
##
## Plain values only, read after joinThread and never during. A fixed buffer
## carries the error text so no string is shared between threads.

type
  AmeTcpServerArgs = object
    port: uint16
    requireCookie: bool
    mode: AmeTrustMode
    authorityTag: int

  AmeTcpServerReport = object
    ok: bool
    echoed: bool
    trusted: bool
    errLen: int
    err: array[serverErrMax, char]

var
  serverReport: AmeTcpServerReport
  serverReady: Atomic[bool]

proc waitForServer() =
  ## Block until the server thread has bound its socket and finished the
  ## post-quantum key generation that precedes it. A fixed sleep cannot do
  ## this job: pure-Nim Falcon keygen takes seconds on a cold thread, and any
  ## constant short enough to keep the suite quick is too short to be true.
  while not serverReady.load():
    sleep(10)

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

proc runAmeTcpServer(a: AmeTcpServerArgs) {.thread.} =
  ## a: everything the responder needs, as plain values.
  ##
  ## The socket is bound BEFORE any key is generated. Falcon keygen in pure
  ## Nim takes long enough that a client which slept and then connected would
  ## be refused outright, and the test would be measuring startup order
  ## rather than the handshake.
  var
    listener: Socket = listenTcp(initTcpAddress("127.0.0.1", a.port))
    layout: AmeSuiteLayout = tcpLayout()
    tier: AmeMaskTier = tcpTier(layout)
    authority: AmeAuthorityKey = authorityFor(a.authorityTag)
    serverKey: AmeIdentityKey = identityFor("tcp-server", 3)
    clientKey: AmeIdentityKey = identityFor("tcp-client", 2)
    descriptor: AmeIdentityCertificate = default(AmeIdentityCertificate)
    responderAuth: AmeAuthentication = default(AmeAuthentication)
    config: AmeResponderPolicy
    peer: Socket
    outcome: AmeHandshakeOutcome
    got: AmeOpenResult
  case a.mode
  of atmPinnedPeerKey:
    descriptor = pinnedIdentityDescriptor(serverKey, validFrom, validUntil)
    responderAuth = initAmePinnedAuthentication(pinnedPeerIdentity(clientKey))
  of atmPskMac:
    responderAuth = initAmePskAuthentication(tcpPskId, tcpPsk())
  of atmAuthorityCertificate:
    descriptor = issueAmeIdentityCertificate(authority, serverKey, 22'u64,
      validFrom, validUntil)
    responderAuth = initAmeCertificateAuthentication(
      initAmeAuthorityRoot(authority))
  config = initAmeResponderPolicy([initAmeTierPath(layout, [tier])],
    responderAuth, descriptor, serverKey, a.requireCookie)
  defer:
    listener.close()
  serverReady.store(true)
  try:
    peer = acceptTcpClient(listener)
  except CatchableError as e:
    reportErr("accept failed: " & e.msg)
    return
  defer:
    peer.close()
  outcome = ameTcpServerHandshake(peer, config,
    initTcpAddress("127.0.0.1", a.port), nowUnix, 20000)
  serverReport.ok = outcome.ok
  serverReport.trusted = outcome.peerTrust.ok
  if not outcome.ok:
    reportErr(outcome.err)
    return
  ## One echo, so the client's assertions cover a session that really works
  ## rather than one that merely finished a handshake.
  got = recvAmeTcp(peer, outcome.connection)
  if not got.ok:
    reportErr("server receive failed: " & got.err)
    clearAmeSession(outcome.connection)
    return
  try:
    sendAmeTcp(peer, outcome.connection, got.packet.payload)
    serverReport.echoed = true
  except CatchableError as e:
    reportErr("server send failed: " & e.msg)
  clearAmeSession(outcome.connection)

proc clientConfig(mode: AmeTrustMode, authorityTag: int): AmeInitiatorPolicy =
  ## mode/authorityTag: initiator policy matching one server variant.
  var
    layout: AmeSuiteLayout = tcpLayout()
    clientKey: AmeIdentityKey = identityFor("tcp-client", 2)
    serverKey: AmeIdentityKey = identityFor("tcp-server", 3)
    authority: AmeAuthorityKey = authorityFor(authorityTag)
  case mode
  of atmPinnedPeerKey:
    result = initAmeInitiatorPolicy(layout, tcpTier(layout),
      initAmePinnedAuthentication(pinnedPeerIdentity(serverKey)),
      pinnedIdentityDescriptor(clientKey, validFrom, validUntil), clientKey)
  of atmPskMac:
    result = initAmeInitiatorPolicy(layout, tcpTier(layout),
      initAmePskAuthentication(tcpPskId, tcpPsk()))
  of atmAuthorityCertificate:
    result = initAmeInitiatorPolicy(layout, tcpTier(layout),
      initAmeCertificateAuthentication(initAmeAuthorityRoot(authority)),
      issueAmeIdentityCertificate(authority, clientKey, 11'u64, validFrom,
        validUntil), clientKey)

proc rampBytes(n: int): ByteSeq =
  ## n: payload length filled with a deterministic ramp.
  var i: int = 0
  result = newSeq[uint8](n)
  while i < n:
    result[i] = uint8((i * 13 + 5) mod 251)
    i = i + 1

suite "AME handshake over a real TCP socket":
  # {.testKind: tkIntegration.}
  test "a certified handshake survives the cookie retry and carries data":
    var
      th: Thread[AmeTcpServerArgs]
      args: AmeTcpServerArgs = AmeTcpServerArgs(port: echoPort,
        requireCookie: true, mode: atmAuthorityCertificate, authorityTag: 1)
      sock: Socket
      outcome: AmeHandshakeOutcome
      payload: ByteSeq = rampBytes(700)
      echoed: AmeOpenResult
    serverReport = default(AmeTcpServerReport)
    serverReady.store(false)
    createThread(th, runAmeTcpServer, args)
    waitForServer()
    sock = connectTcp(initTcpAddress("127.0.0.1", echoPort), 4000)
    outcome = ameTcpClientHandshake(sock, clientConfig(atmAuthorityCertificate, 1),
      7'u64,
      nowUnix, 20000)
    check outcome.err == ""
    check outcome.ok
    check outcome.peerTrust.ok
    ## The certificate rode inside a sealed block, so the trust result is the
    ## only place the server's name ever appears in the clear.
    check outcome.peerTrust.subjectKeyId == "tcp-server"
    sendAmeTcp(sock, outcome.connection, payload)
    echoed = recvAmeTcp(sock, outcome.connection)
    joinThread(th)
    check serverError() == ""
    check serverReport.ok
    check serverReport.trusted
    check serverReport.echoed
    check echoed.ok
    check echoed.packet.payload == payload
    clearAmeSession(outcome.connection)
    sock.close()


  ## The same driver, the same four records, and no certificate anywhere.
  # {.testKind: tkIntegration.}
  test "a shared secret authenticates the same driver with no certificates":
    var
      th: Thread[AmeTcpServerArgs]
      args: AmeTcpServerArgs = AmeTcpServerArgs(port: pskPort,
        requireCookie: true, mode: atmPskMac, authorityTag: 1)
      sock: Socket
      outcome: AmeHandshakeOutcome
      payload: ByteSeq = rampBytes(200)
      echoed: AmeOpenResult
    serverReport = default(AmeTcpServerReport)
    serverReady.store(false)
    createThread(th, runAmeTcpServer, args)
    waitForServer()
    sock = connectTcp(initTcpAddress("127.0.0.1", pskPort), 4000)
    outcome = ameTcpClientHandshake(sock, clientConfig(atmPskMac, 1),
      10'u64, nowUnix, 20000)
    check outcome.err == ""
    check outcome.ok
    check outcome.peerTrust.ok
    ## The verdict names the shape it came from and the secret it used, and
    ## the mode the session records is the mode that actually ran.
    check outcome.peerTrust.mode == am1m
    check outcome.peerTrust.authority == "shared-secret"
    check outcome.peerTrust.subjectKeyId == tcpPskId
    check outcome.connection.auth.authenticationMode == am1m
    check outcome.connection.auth.peerSignaturePublicKeys.len == 0
    sendAmeTcp(sock, outcome.connection, payload)
    echoed = recvAmeTcp(sock, outcome.connection)
    joinThread(th)
    check serverError() == ""
    check serverReport.ok
    check serverReport.trusted
    check serverReport.echoed
    check echoed.ok
    check echoed.packet.payload == payload
    clearAmeSession(outcome.connection)
    sock.close()
  # {.testKind: tkIntegration.}
  test "reciprocal pins authenticate the same driver":
    var
      th: Thread[AmeTcpServerArgs]
      args: AmeTcpServerArgs = AmeTcpServerArgs(port: pinnedPort,
        requireCookie: false, mode: atmPinnedPeerKey, authorityTag: 1)
      sock: Socket
      outcome: AmeHandshakeOutcome
      payload: ByteSeq = rampBytes(64)
      echoed: AmeOpenResult
    serverReport = default(AmeTcpServerReport)
    serverReady.store(false)
    createThread(th, runAmeTcpServer, args)
    waitForServer()
    sock = connectTcp(initTcpAddress("127.0.0.1", pinnedPort), 4000)
    outcome = ameTcpClientHandshake(sock, clientConfig(atmPinnedPeerKey, 1),
      8'u64,
      nowUnix, 20000)
    check outcome.err == ""
    check outcome.ok
    ## A pin has no issuing authority, so the trust result names the pinned
    ## shape itself and carries the peer under subjectKeyId.
    check outcome.peerTrust.authority == "pinned-peer"
    check outcome.peerTrust.subjectKeyId == "tcp-server"
    sendAmeTcp(sock, outcome.connection, payload)
    echoed = recvAmeTcp(sock, outcome.connection)
    joinThread(th)
    check serverError() == ""
    check serverReport.ok
    check echoed.ok
    check echoed.packet.payload == payload
    clearAmeSession(outcome.connection)
    sock.close()

  # {.testKind: tkEdgeCase.}
  test "a client trusting the wrong authority is refused on the wire":
    var
      th: Thread[AmeTcpServerArgs]
      args: AmeTcpServerArgs = AmeTcpServerArgs(port: rejectPort,
        requireCookie: false, mode: atmAuthorityCertificate, authorityTag: 1)
      sock: Socket
      outcome: AmeHandshakeOutcome
    serverReport = default(AmeTcpServerReport)
    serverReady.store(false)
    createThread(th, runAmeTcpServer, args)
    waitForServer()
    sock = connectTcp(initTcpAddress("127.0.0.1", rejectPort), 4000)
    ## Authority 4 never signed the server's certificate, so the client stops
    ## at the identity block and never sends a finish.
    outcome = ameTcpClientHandshake(sock, clientConfig(atmAuthorityCertificate, 4),
      9'u64,
      nowUnix, 20000)
    check not outcome.ok
    check outcome.err.len > 0
    check not outcome.peerTrust.ok
    sock.close()
    joinThread(th)
    ## The server was left waiting for a finish that never came, so it must
    ## report a failure rather than a session.
    check not serverReport.ok

## ╭⟢ the carrier, without a handshake in front of it
##
## `connectAmeTcpClient` is for a session that already exists -- one restored
## from a checkpoint, or handed over by something else. It never runs the
## handshake, so it needs its own peer.

const carrierKems: AmeKemAlgorithms = [akaFireSaber, akaX25519]

proc carrierAuth(role: AmeEndpointRole): AmeAuthPackage =
  ## role: one established epoch, identical on both sides.
  var
    layout: AmeSuiteLayout = defaultAmeLayout(carrierKems)
    tier: AmeMaskTier = initAmeMaskTier(layout, 1'u32,
      initAmeTierMasks(0b10000000'u8,
        occupiedAmeMask(layout.ciphers.length),
        occupiedAmeMask(layout.macs.length),
        occupiedAmeMask(layout.hashes.length),
        occupiedAmeMask(layout.signatures.length),
        occupiedAmeMask(layout.kdfs.length)))
    state: AmeExchangeState = initAmeExchangeState(carrierKems)
  applyAmeExchange(state, initAmeExchangeRequest(carrierKems, tier,
    0b10000000'u8), [@[byte 3, 1, 4, 1, 5, 9, 2, 6]])
  result = initAmeAuthPackage(layout, tier, state, endpointRole = role)

proc runCarrierServer(a: AmeTcpServerArgs) {.thread.} =
  ## a: port only. The epoch is rebuilt from the same fixed material.
  var
    session: AmeSession = initAmeSession(carrierAuth(aerResponder), 5'u64,
      peerTrustRequired = false)
    listener: Socket
    peer: Socket
    got: AmeOpenResult
  listener = listenTcp(initTcpAddress("127.0.0.1", a.port))
  defer:
    listener.close()
  serverReady.store(true)
  try:
    peer = acceptTcpClient(listener)
  except CatchableError as e:
    reportErr("carrier accept failed: " & e.msg)
    return
  defer:
    peer.close()
  got = recvAmeTcp(peer, session)
  if not got.ok:
    reportErr("carrier receive failed: " & got.err)
    clearAmeSession(session)
    return
  try:
    ## Answered through the carrier-agnostic entry point rather than the TCP
    ## one, so the runtime `case` is what actually seals this reply.
    sendTcpFrame(peer, sealAmeFrame(session, acrTcp, got.packet.payload))
    serverReport.echoed = true
    serverReport.ok = true
  except CatchableError as e:
    reportErr("carrier send failed: " & e.msg)
  clearAmeSession(session)

suite "AME TCP carrier over a real socket":
  # {.testKind: tkIntegration.}
  test "connectAmeTcpClient carries a pre-negotiated session both ways":
    var
      th: Thread[AmeTcpServerArgs]
      args: AmeTcpServerArgs = AmeTcpServerArgs(port: carrierPort)
      client: AmeTcpClient
      payload: ByteSeq = rampBytes(300)
      echoed: AmeOpenResult
    serverReport = default(AmeTcpServerReport)
    serverReady.store(false)
    createThread(th, runCarrierServer, args)
    waitForServer()
    client = connectAmeTcpClient(initTcpAddress("127.0.0.1", carrierPort),
      initAmeSession(carrierAuth(aerInitiator), 5'u64,
        peerTrustRequired = false))
    check client.socket != nil
    check client.remote.port == carrierPort
    client.send(payload)
    echoed = client.receive()
    joinThread(th)
    check serverError() == ""
    check serverReport.ok
    check echoed.ok
    check echoed.packet.payload == payload
    client.close()
    check client.socket == nil

  # {.testKind: tkEdgeCase.}
  test "the carrier refuses a carrier this build does not have":
    ## Both are compiled here, so both must answer. The point is that the
    ## runtime `case` reaches a real implementation for each.
    check ameCarrierBuilt(acrTcp)
    check ameCarrierBuilt(acrDac)
