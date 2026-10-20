## -------------------------------------------------------------------------
## AME Router Example <- one handshake with a router, then reach the nas
## -------------------------------------------------------------------------
##
##   phone (0x30) ==session A==> router ==session B==> nas (0x20)
##
##   1. phone asks the router who it may reach      -> [0x20 "nas"]
##   2. phone forwards "hello nas" to 0x20          -> nas gets it, from 0x30
##   3. nas answers 0x30                            -> phone gets it, from 0x20
##
## The sessions are made by a real KEM exchange here, without sockets. In a
## program they come out of the AME handshake (see the README, "Initial
## Trust"), and every `send`/`recv` below is a datagram on a socket.

import std/strutils

import bifrost_exchange_protocols

const
  kems: AmeKemAlgorithms = [akaX25519, akaX25519]
  idNas: uint64 = 0x20'u64
  idPhone: uint64 = 0x30'u64

proc sessionPair(): tuple[left, right: AmeSession] =
  ## Both ends of one fresh session, as a finished handshake leaves them.
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
    a: tuple[left, right: AmeSession] = sessionPair()   # phone <-> router
    b: tuple[left, right: AmeSession] = sessionPair()   # nas   <-> router
    phone: AmeSession = a.left
    nas: AmeSession = b.left
    router: AmeRouter = initAmeRouter()
    slotPhone: int = -1
    slotNas: int = -1
    step: AmeRouteStep = default(AmeRouteStep)
    got: AmeRouteMessage = default(AmeRouteMessage)

  ## The router's directory: one line, shown to the identity "phone".
  router.addAmeRouteTarget(idNas, "nas", ["phone"])
  ## After each handshake, the router takes the session it holds.
  slotPhone = router.admitAmeRoutePeer(a.right, idPhone, "phone", acrDac).slot
  slotNas = router.admitAmeRoutePeer(b.right, idNas, "nas", acrDac).slot

  ## 1. Who may I reach?
  step = router.feedAmeRouteFrame(slotPhone,
    phone.sealAmeRouteAsk(acrDac), 0'u32)
  got = phone.openAmeRouteFrame(acrDac, step.send[0].frame)
  for e in got.entries:
    echo "phone sees    0x", toHex(e.id, 2), " ", e.name

  ## 2. Send through the router.
  step = router.feedAmeRouteFrame(slotPhone,
    phone.sealAmeRouteForward(acrDac, idNas, "hello nas".toOpenArrayByte(0, 8)),
    0'u32)
  doAssert step.event == areDelivered and step.send[0].slot == slotNas
  got = nas.openAmeRouteFrame(acrDac, step.send[0].frame)
  echo "nas got       \"", text(got.payload), "\" from 0x", toHex(got.origin, 2)

  ## 3. Answer the origin.
  step = router.feedAmeRouteFrame(slotNas,
    nas.sealAmeRouteForward(acrDac, got.origin, "hi phone".toOpenArrayByte(0, 7)),
    0'u32)
  got = phone.openAmeRouteFrame(acrDac, step.send[0].frame)
  echo "phone got     \"", text(got.payload), "\" from 0x", toHex(got.origin, 2)
