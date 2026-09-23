## -------------------------------------------------------------------------
## AME Pre-shared Modes + FOMKE Next Secret <- AM1P, AM1P+S, and NS carry
## -------------------------------------------------------------------------
##
## What these tests hold down, in one picture:
##
##   session 1 (AM1P)                        session 2 (AM1P + next secret)
##   ─────────────────                       ───────────────────────────────
##   hello  sealed under psk          ──▶    hello sealed under psk ‖ NS-out
##   ISS ─▶ [ LK1 | LK2 | NS ]               binder takes psk ‖ NS-out too
##   rotation: NS + new KEM ─▶ NS'
##   end: ameNextHandshakeSecret ─▶ NS-out ──┘
##
## and the combined mode AM1P+S, where the shared secret AND a pinned
## signature key must both check out.

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/config
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/path_triggers
import ../../src/protocols/ame/level2/session
import ../../src/protocols/ame/level2/framing
import ../../src/protocols/ame/level3/handshake
import ../../src/protocols/ame/level3/handshake_wire
import ../../src/protocols/fomke/types
import ../../src/protocols/fomke/level1/chain
import ../../src/protocols/fomke/level2/state_codec
import runePragmas

const
  pskKems: AmeKemAlgorithms = [akaX25519, akaFireSaber]
  nowUnix: int64 = 500'i64
  validFrom: int64 = 100'i64
  validUntil: int64 = 1000'i64

type
  PskRun = object
    ## Both finished sides of one handshake, plus what the hello looked like.
    ok: bool
    err: string
    hello: AmeClientHello
    client: AmeHandshakeResult
    server: AmeHandshakeResult

  PinnedPeers = object
    ## Two identities that pin each other, for AM1P+S.
    clientKey: AmeIdentityKey
    serverKey: AmeIdentityKey
    clientDesc: AmeIdentityCertificate
    serverDesc: AmeIdentityCertificate

proc pskLayout(): AmeSuiteLayout {.role: configurator.} =
  result = defaultAmeLayout(pskKems)

proc pskTier(L: AmeSuiteLayout): AmeMaskTier {.role: configurator.} =
  result = initAmeMaskTier(L, 1'u32, initAmeTierMasks(0b11000000'u8,
    occupiedAmeMask(L.ciphers.length), occupiedAmeMask(L.macs.length),
    occupiedAmeMask(L.hashes.length), occupiedAmeMask(L.signatures.length),
    occupiedAmeMask(L.kdfs.length)))

proc pskSecret(seed: byte): ByteSeq {.role: helper.} =
  ## seed: makes two provisioned secrets differ without being random.
  var
    i: int = 0
  result = newSeq[byte](32)
  while i < result.len:
    result[i] = byte(i + int(seed))
    i = i + 1

proc newPinnedPeers(name: string): PinnedPeers {.role: configurator.} =
  result.clientKey = initAmeIdentityKey(name & "-client")
  result.serverKey = initAmeIdentityKey(name & "-server")
  result.clientDesc = pinnedIdentityDescriptor(result.clientKey, validFrom,
    validUntil)
  result.serverDesc = pinnedIdentityDescriptor(result.serverKey, validFrom,
    validUntil)

proc runHandshake(sessionId: uint64, clientAuth, serverAuth: AmeAuthentication,
    clientDesc: AmeIdentityCertificate = default(AmeIdentityCertificate),
    clientKey: AmeIdentityKey = default(AmeIdentityKey),
    serverDesc: AmeIdentityCertificate = default(AmeIdentityCertificate),
    serverKey: AmeIdentityKey = default(AmeIdentityKey)): PskRun {.
    role: orchestrator.} =
  ## sessionId/clientAuth/serverAuth/...: one whole handshake, every record
  ## taken through its wire codec, stopping at the first side that refuses.
  var
    L: AmeSuiteLayout = pskLayout()
    t: AmeMaskTier = pskTier(L)
    client: AmeClientHandshake = beginAmeHandshake(sessionId, L, t,
      a = clientAuth)
    wireHello: AmeClientHello = default(AmeClientHello)
    answered: tuple[ok: bool, state: AmeServerHandshake, err: string] = (
      ok: false, state: default(AmeServerHandshake), err: "")
  result.hello = client.hello
  wireHello = decodeAmeClientHello(encodeAmeClientHello(client.hello))
  answered = answerAmeHandshake(wireHello, [initAmeTierPath(L, [t])],
    serverAuth, serverDesc, serverKey)
  if not answered.ok:
    result.err = answered.err
    return
  result.client = finishAmeHandshake(client, decodeAmeServerHello(L,
    encodeAmeServerHello(answered.state.serverHello)), clientAuth, clientDesc,
    clientKey, nowUnix)
  if not result.client.ok:
    result.err = result.client.err
    return
  result.server = acceptAmeHandshake(answered.state, decodeAmeClientFinish(
    encodeAmeClientFinish(result.client.finish)), nowUnix)
  result.err = result.server.err
  result.ok = result.server.ok

proc containsWindow(A, B: openArray[byte]): bool {.role: parser.} =
  ## A/B: true when B appears anywhere inside A.
  var
    i: int = 0
  while i + B.len <= A.len:
    if A[i ..< i + B.len] == B:
      return true
    i = i + 1

proc sessionPair(r: PskRun, sessionId: uint64): tuple[a, b: AmeSession] {.
    role: configurator.} =
  ## r/sessionId: the two live sessions a finished handshake opens.
  var
    L: AmeSuiteLayout = pskLayout()
    path: AmeTierPath = initAmeTierPath(L, [pskTier(L)])
  result.a = initAmeSession(r.client.auth, path, sessionId,
    peerTrust = r.client.peerTrust)
  result.b = initAmeSession(r.server.auth, path, sessionId,
    peerTrust = r.server.peerTrust)

proc rotateOnce(a, b: var AmeSession) {.role: orchestrator.} =
  ## a/b: one complete epoch rotation, initiator a, responder b.
  var
    L: AmeSuiteLayout = pskLayout()
    t: AmeMaskTier = pskTier(L)
    offer: AmeExchangeOffer = beginAmeSessionExchange(a,
      initAmeExchangeRequest(L.kems, t, t.masks.kem))
    reply: AmeExchangeReply = answerAmeSessionExchange(b, offer)
    commit: FomkeUpgradeCommit = default(FomkeUpgradeCommit)
  stageAmeSessionFomkeUpgrade(b)
  finishAmeSessionExchange(a, reply)
  commit = a.fomke.pending.commit
  confirmFomkeUpgrade(a.fomke, commit)
  confirmAmeSessionExchange(b, offer.requestId,
    b.pendingIncoming.candidate.epochId, reply.request.targetTier, commit)

suite "AM1P: the sealed hello":
  # {.testKind: tkUnit, covers: "sealAmeHelloOffer".}
  test "no KEM public key crosses the wire in the clear":
    var
      auth: AmeAuthentication = initAmePskAuthentication("site", pskSecret(1))
      L: AmeSuiteLayout = pskLayout()
      h: AmeClientHandshake = beginAmeHandshake(11'u64, L, pskTier(L),
        a = auth)
      wire: ByteSeq = encodeAmeClientHello(h.hello)
      i: int = 0
    check h.hello.offer.publicKeys.len == 2
    while i < h.hello.offer.publicKeys.len:
      check not containsWindow(wire,
        h.hello.offer.publicKeys[i][0 ..< 24])
      i = i + 1
    ## And the certificate mode, for contrast, does carry them openly.
    h = beginAmeHandshake(12'u64, L, pskTier(L))
    wire = encodeAmeClientHello(h.hello)
    check containsWindow(wire, h.hello.offer.publicKeys[0][0 ..< 24])

  # {.testKind: tkEdgeCase, covers: "sealAmeHelloOffer".}
  test "two hellos under one secret never share a salt or a ciphertext":
    var
      auth: AmeAuthentication = initAmePskAuthentication("site", pskSecret(1))
      L: AmeSuiteLayout = pskLayout()
      h1: AmeClientHandshake = beginAmeHandshake(13'u64, L, pskTier(L),
        a = auth)
      h2: AmeClientHandshake = beginAmeHandshake(13'u64, L, pskTier(L),
        a = auth)
    check h1.hello.offerSalt.len == 32
    check h1.hello.offerSalt != h2.hello.offerSalt
    check h1.hello.sealedOffer != h2.hello.sealedOffer
    check h1.hello.offerTag.len == 32

  # {.testKind: tkEdgeCase, covers: "openAmeHelloOffer".}
  test "a responder with another secret cannot even open the hello":
    var
      r: PskRun = runHandshake(14'u64,
        initAmePskAuthentication("site", pskSecret(1)),
        initAmePskAuthentication("site", pskSecret(9)))
    check not r.ok
    check r.err == "client hello did not open under the shared secret"

  # {.testKind: tkEdgeCase, covers: "openAmeHelloOffer".}
  test "an edited clear field breaks the seal":
    var
      auth: AmeAuthentication = initAmePskAuthentication("site", pskSecret(1))
      L: AmeSuiteLayout = pskLayout()
      h: AmeClientHandshake = beginAmeHandshake(15'u64, L, pskTier(L),
        a = auth)
      edited: AmeClientHello = default(AmeClientHello)
    edited = decodeAmeClientHello(encodeAmeClientHello(h.hello))
    check openAmeHelloOffer(edited, auth) == ""
    edited = decodeAmeClientHello(encodeAmeClientHello(h.hello))
    edited.sessionId = 16'u64
    check openAmeHelloOffer(edited, auth) != ""
    edited = decodeAmeClientHello(encodeAmeClientHello(h.hello))
    edited.offerSalt[0] = edited.offerSalt[0] xor 1'u8
    check openAmeHelloOffer(edited, auth) != ""

suite "AM1P+S: shared secret AND pinned signature":
  # {.testKind: tkIntegration, covers: "initAmePskPinnedAuthentication".}
  test "a full handshake names both halves and signs its rotations":
    var
      peers: PinnedPeers = newPinnedPeers("ps")
      clientAuth: AmeAuthentication = initAmePskPinnedAuthentication("ps",
        pskSecret(2), pinnedPeerIdentity(peers.serverKey))
      serverAuth: AmeAuthentication = initAmePskPinnedAuthentication("ps",
        pskSecret(2), pinnedPeerIdentity(peers.clientKey))
      r: PskRun = runHandshake(21'u64, clientAuth, serverAuth,
        peers.clientDesc, peers.clientKey, peers.serverDesc, peers.serverKey)
      live: tuple[a, b: AmeSession] = (default(AmeSession),
        default(AmeSession))
    check r.err == ""
    check r.ok
    check r.client.peerTrust.mode == am1ps
    check r.server.peerTrust.mode == am1ps
    check r.client.auth.authenticationMode == am1ps
    ## Signature keys exist, so rotations are signed, not MAC'd.
    check r.client.auth.peerSignaturePublicKeys.len > 0
    check r.client.auth.exchangeAuthenticationKey.len == 0
    ## The shared secret still joins the key schedule.
    check r.client.auth.exchangeBinder.len == 32
    check r.client.auth.exchangeBinder == r.server.auth.exchangeBinder
    live = sessionPair(r, 21'u64)
    rotateOnce(live.a, live.b)
    check live.a.auth.current.epochId == 2'u32
    check live.b.auth.current.epochId == 2'u32

  # {.testKind: tkEdgeCase, covers: "peerVerdict".}
  test "the right secret with the wrong pin fails, and so does the reverse":
    var
      peers: PinnedPeers = newPinnedPeers("ps-wrong")
      stranger: AmeIdentityKey = initAmeIdentityKey("ps-wrong-server")
      right: AmeAuthentication = initAmePskPinnedAuthentication("ps",
        pskSecret(2), pinnedPeerIdentity(peers.clientKey))
      wrongPin: AmeAuthentication = initAmePskPinnedAuthentication("ps",
        pskSecret(2), pinnedPeerIdentity(stranger))
      rightPin: AmeAuthentication = initAmePskPinnedAuthentication("ps",
        pskSecret(2), pinnedPeerIdentity(peers.serverKey))
      wrongSecret: AmeAuthentication = initAmePskPinnedAuthentication("ps",
        pskSecret(7), pinnedPeerIdentity(peers.serverKey))
      r: PskRun = default(PskRun)
    ## Same name, different key: the shared secret is right, the pin is not.
    r = runHandshake(22'u64, wrongPin, right, peers.clientDesc,
      peers.clientKey, peers.serverDesc, peers.serverKey)
    check not r.ok
    ## Right pin, wrong secret: the hello does not even open.
    r = runHandshake(23'u64, wrongSecret, right, peers.clientDesc,
      peers.clientKey, peers.serverDesc, peers.serverKey)
    check not r.ok
    check r.err == "client hello did not open under the shared secret"
    ## Both right: through.
    r = runHandshake(24'u64, rightPin, right, peers.clientDesc,
      peers.clientKey, peers.serverDesc, peers.serverKey)
    check r.ok

suite "carrying the next secret into the next handshake":
  # {.testKind: tkIntegration, covers: "ameNextHandshakeSecret|withAmeNextSecret".}
  test "session 1 hands out a secret session 2 is keyed with":
    var
      psk: ByteSeq = pskSecret(3)
      first: PskRun = runHandshake(31'u64,
        initAmePskAuthentication("carry", psk),
        initAmePskAuthentication("carry", psk))
      live: tuple[a, b: AmeSession] = (default(AmeSession),
        default(AmeSession))
      kept: ByteSeq = @[]
      second: PskRun = default(PskRun)
      again: tuple[a, b: AmeSession] = (default(AmeSession),
        default(AmeSession))
      opened: AmeOpenResult = default(AmeOpenResult)
    check first.ok
    live = sessionPair(first, 31'u64)
    kept = ameNextHandshakeSecret(live.a)
    check kept.len == 32
    check kept == ameNextHandshakeSecret(live.b)
    second = runHandshake(32'u64,
      initAmePskAuthentication("carry", psk).withAmeNextSecret(kept),
      initAmePskAuthentication("carry", psk).withAmeNextSecret(kept))
    check second.err == ""
    check second.ok
    check second.hello.usesNextSecret
    ## The next secret changed the key schedule, not only the hello.
    check second.client.auth.exchangeBinder != first.client.auth.exchangeBinder
    again = sessionPair(second, 32'u64)
    opened = openAmeTcpFrame(again.b, sealAmeTcpFrame(again.a, @[byte 1, 2]))
    check opened.ok
    check opened.packet.payload == @[byte 1, 2]

  # {.testKind: tkEdgeCase, covers: "nextSecretPolicyError".}
  test "missing, required, wrong, and a visible fallback":
    var
      psk: ByteSeq = pskSecret(4)
      kept: ByteSeq = pskSecret(40)
      other: ByteSeq = pskSecret(41)
      plain: AmeAuthentication = initAmePskAuthentication("policy", psk)
      carrying: AmeAuthentication = plain.withAmeNextSecret(kept)
      demanding: AmeAuthentication = plain.withAmeNextSecret(kept,
        required = true)
      r: PskRun = default(PskRun)
    ## The client used one; the responder has none to match it with.
    r = runHandshake(41'u64, carrying, plain)
    check r.err == "client used a next secret this side does not hold"
    ## The responder requires one; the client came without.
    r = runHandshake(42'u64, plain, demanding)
    check r.err == "client hello did not carry the required next secret"
    ## Both carry one, but not the same one: nothing opens.
    r = runHandshake(43'u64, plain.withAmeNextSecret(other), carrying)
    check r.err == "client hello did not open under the shared secret"
    ## Not required: psk only goes through, and the hello SAYS so.
    r = runHandshake(44'u64, plain, carrying)
    check r.ok
    check not r.hello.usesNextSecret

  # {.testKind: tkEdgeCase, covers: "withAmeNextSecret".}
  test "only pre-shared modes take one, and only 32 bytes of it":
    var
      pinned: AmeAuthentication = initAmePinnedAuthentication(
        pinnedPeerIdentity(initAmeIdentityKey("np")))
    expect ValueError:
      discard pinned.withAmeNextSecret(pskSecret(5))
    expect ValueError:
      discard initAmePskAuthentication("np", pskSecret(5)).withAmeNextSecret(
        pskSecret(5)[0 ..< 16])

suite "FOMKE next secret":
  # {.testKind: tkUnit, covers: "initFomke".}
  test "both sides hold the same NS, and it is not a lane key":
    var
      psk: ByteSeq = pskSecret(6)
      r: PskRun = runHandshake(51'u64, initAmePskAuthentication("ns", psk),
        initAmePskAuthentication("ns", psk))
      live: tuple[a, b: AmeSession] = (default(AmeSession),
        default(AmeSession))
    check r.ok
    live = sessionPair(r, 51'u64)
    check live.a.fomke.nextSecret.len == fomkeNextSecretBytes
    check live.a.fomke.nextSecret == live.b.fomke.nextSecret
    check live.a.fomke.nextSecret !=
      live.a.fomke.lane1.chainKey[0 ..< fomkeNextSecretBytes]
    check live.a.fomke.nextSecret !=
      live.a.fomke.lane2.chainKey[0 ..< fomkeNextSecretBytes]
    ## What leaves for the next handshake is a derivation, not NS itself.
    check fomkeHandshakeSecret(live.a.fomke) != live.a.fomke.nextSecret

  # {.testKind: tkRegression, covers: "prepareFomkeUpgrade", pins: "a rotation that fed the live lane keys into the next epoch needed both lanes at the same position".}
  test "a rotation replaces NS on both sides, whatever the lanes have done":
    var
      psk: ByteSeq = pskSecret(7)
      r: PskRun = runHandshake(52'u64, initAmePskAuthentication("rot", psk),
        initAmePskAuthentication("rot", psk))
      live: tuple[a, b: AmeSession] = (default(AmeSession),
        default(AmeSession))
      before: ByteSeq = @[]
    check r.ok
    live = sessionPair(r, 52'u64)
    before = live.a.fomke.nextSecret
    rotateOnce(live.a, live.b)
    check live.a.fomke.nextSecret.len == fomkeNextSecretBytes
    check live.a.fomke.nextSecret == live.b.fomke.nextSecret
    check live.a.fomke.nextSecret != before

  # {.testKind: tkUnit, covers: "encodeFomkeState|decodeFomkeState".}
  test "a checkpoint keeps NS":
    var
      psk: ByteSeq = pskSecret(8)
      r: PskRun = runHandshake(53'u64, initAmePskAuthentication("cp", psk),
        initAmePskAuthentication("cp", psk))
      live: tuple[a, b: AmeSession] = (default(AmeSession),
        default(AmeSession))
      restored: FomkeState = default(FomkeState)
    check r.ok
    live = sessionPair(r, 53'u64)
    restored = decodeFomkeState(encodeFomkeState(live.a.fomke))
    check restored.nextSecret == live.a.fomke.nextSecret

suite "reorder ceiling from config":
  # {.testKind: tkUnit, covers: "parseBifrostConfigText|initAmeSession".}
  test "fomkeReorderCeiling is read, checked, and reaches the session":
    var
      psk: ByteSeq = pskSecret(9)
      saved: BifrostConfig = currentBifrostConfig()
      r: PskRun = runHandshake(61'u64, initAmePskAuthentication("cfg", psk),
        initAmePskAuthentication("cfg", psk))
      live: tuple[a, b: AmeSession] = (default(AmeSession),
        default(AmeSession))
    check r.ok
    check parseBifrostConfigText("fomkeReorderCeiling = 256").
      fomkeReorderCeiling == 256'u32
    expect ValueError:
      discard parseBifrostConfigText("fomkeReorderCeiling = 2")
    expect ValueError:
      discard parseBifrostConfigText("fomkeReorderCeiling = 5000")
    applyBifrostConfig(parseBifrostConfigText("fomkeReorderCeiling = 256"))
    live = sessionPair(r, 61'u64)
    check live.a.fomke.reorderCeiling == 256'u32
    applyBifrostConfig(saved)
