## -------------------------------------------------------------------------
## AME Router Example <- one link handshake, then end to end through it
## -------------------------------------------------------------------------
##
##   phone (0x30) ==link A==> router (0x10) ==link B==> nas (0x20)
##
##   1. phone asks the router who it may reach   (AME frame, FOMKE-sealed)
##   2. phone and nas run an AM1P handshake       (inside ART route frames)
##   3. phone sends "hello nas" on that session   (inside an ART route frame)
##
## The router opens and re-seals only the 16-byte address of each route
## frame. It never holds the phone<->nas key, so it cannot read step 2 or 3.
##
## The two LINK sessions are made by a KEM exchange here, without sockets.
## In a program they come out of the ordinary AME handshake with the
## router, and every hand-over below is a datagram on a socket.

import std/strutils

import bifrost_exchange_protocols

const
  kems: AmeKemAlgorithms = [akaX25519, akaX25519]
  idRouter: uint64 = 0x10'u64
  idNas: uint64 = 0x20'u64
  idPhone: uint64 = 0x30'u64
  e2eSession: uint64 = 0x5151'u64

proc linkPair(): tuple[left, right: AmeSession] =
  ## Both ends of one fresh link, as a finished handshake leaves them.
  var
    layout: AmeSuiteLayout = defaultAmeLayout(kems)
    tier: AmeMaskTier = fullAmeMaskTier(layout, 1'u32)
    request: AmeExchangeRequest = initAmeExchangeRequest(kems, tier,
      0b11000000'u8)
    keys: AmeExchangeKeys = generateAmeExchangeKeys(kems, request)
    sealed: AmeExchangeResult = sealAmeExchange(kems, request, keys.publicKeys)
    leftState: AmeExchangeState = initAmeExchangeState(kems)
    rightState: AmeExchangeState = initAmeExchangeState(kems)
  applyAmeExchange(leftState, layout, request, sealed.sharedSecrets)
  applyAmeExchange(rightState, layout, request, openAmeExchange(kems,
    request, sealed.envelopes, keys.secretKeys))
  result.left = initAmeSession(initAmeAuthPackage(layout, tier, leftState,
    endpointRole = aerInitiator), peerTrustRequired = false)
  result.right = initAmeSession(initAmeAuthPackage(layout, tier, rightState,
    endpointRole = aerResponder), peerTrustRequired = false)

proc text(A: openArray[uint8]): string =
  ## A: bytes shown as text.
  result = newString(A.len)
  for i, b in A:
    result[i] = char(b)

when isMainModule:
  var
    a: tuple[left, right: AmeSession] = linkPair()   # phone <-> router
    b: tuple[left, right: AmeSession] = linkPair()   # nas   <-> router
    router: AmeRouter = initAmeRouter(idRouter)
    phoneNode: AmeRouter = initAmeRouter(idPhone, 1)
    nasNode: AmeRouter = initAmeRouter(idNas, 1)
    slotPhone: int = -1
    slotNas: int = -1
    step: AmeRouteStep = default(AmeRouteStep)
    dir: AmeRouteDirectory = default(AmeRouteDirectory)
    layout: AmeSuiteLayout = defaultAmeLayout(kems)
    tier: AmeMaskTier = fullAmeMaskTier(layout, 1'u32)
    psk: seq[byte] = newSeq[byte](32)
    e2eAuth: AmeAuthentication = default(AmeAuthentication)
    client: AmeClientHandshake = default(AmeClientHandshake)
    server: tuple[ok: bool, state: AmeServerHandshake, err: string] = (
      ok: false, state: default(AmeServerHandshake), err: "")
    clientDone: AmeHandshakeResult = default(AmeHandshakeResult)
    serverDone: AmeHandshakeResult = default(AmeHandshakeResult)
    e2ePhone: AmeSession = default(AmeSession)
    e2eNas: AmeSession = default(AmeSession)

  proc phoneToNas(payload: openArray[uint8]): ByteSeq =
    ## phone -> router -> nas. Returns what the nas node received.
    step = router.feedAmeRouteFrame(slotPhone,
      a.left.sealAmeRouteForward(idNas, payload), 0'u32)
    step = nasNode.feedAmeRouteFrame(0, step.send[0].frame, 0'u32)
    doAssert step.event == areDelivered and step.frame.origin == idPhone
    result = step.frame.payload

  proc nasToPhone(payload: openArray[uint8]): ByteSeq =
    ## nas -> router -> phone. Returns what the phone node received.
    step = router.feedAmeRouteFrame(slotNas,
      b.left.sealAmeRouteForward(idPhone, payload), 0'u32)
    step = phoneNode.feedAmeRouteFrame(0, step.send[0].frame, 0'u32)
    doAssert step.event == areDelivered and step.frame.origin == idNas
    result = step.frame.payload

  ## The router's directory, and its two links. Each endpoint holds the
  ## other end of its link, marked as a router.
  router.addAmeRouteTarget(idNas, "nas", ["phone"])
  slotPhone = router.admitAmeRoutePeer(a.right, idPhone, "phone", acrDac).slot
  slotNas = router.admitAmeRoutePeer(b.right, idNas, "nas", acrDac).slot
  discard phoneNode.admitAmeRoutePeer(a.left, idRouter, "router", acrDac,
    router = true)
  discard nasNode.admitAmeRoutePeer(b.left, idRouter, "router", acrDac,
    router = true)

  ## 1. Who may I reach? (an ordinary AME frame, for the router itself)
  step = router.feedAmeRouteAsk(slotPhone, a.left.sealAmeRouteAsk(acrDac))
  dir = a.left.openAmeRouteDirectory(acrDac, step.send[0].frame)
  for e in dir.entries:
    echo "phone sees     0x", toHex(e.id, 2), " ", e.name

  ## 2. An AM1P handshake with the nas, carried through the router.
  psk[0] = 0x42'u8
  e2eAuth = initAmePskAuthentication("phone-nas", psk)
  client = beginAmeHandshake(e2eSession, layout, tier, a = e2eAuth)
  server = answerAmeHandshake(decodeAmeClientHello(phoneToNas(
    encodeAmeClientHello(client.hello))), [initAmeTierPath(layout, [tier])],
    e2eAuth)
  clientDone = finishAmeHandshake(client, decodeAmeServerHello(layout,
    nasToPhone(encodeAmeServerHello(server.state.serverHello))), e2eAuth)
  serverDone = acceptAmeHandshake(server.state, decodeAmeClientFinish(
    phoneToNas(encodeAmeClientFinish(clientDone.finish))))
  doAssert clientDone.ok and serverDone.ok
  e2ePhone = initAmeSession(clientDone.auth, initAmeTierPath(layout, [tier]),
    e2eSession, peerTrust = clientDone.peerTrust)
  e2eNas = initAmeSession(serverDone.auth, initAmeTierPath(layout, [tier]),
    e2eSession, peerTrust = serverDone.peerTrust)
  echo "end to end     AM1P handshake done through the router"

  ## 3. A message on the end-to-end session, through the router.
  echo "nas got        \"", text(e2eNas.openAmeDacFrame(phoneToNas(
    e2ePhone.sealAmeDacFrame("hello nas".toOpenArrayByte(0, 8)))).packet.payload),
    "\" from 0x", toHex(idPhone, 2)
