## -------------------------------------------------------------------------
## Relay Links <- one fresh AME link pair, shared by the two relay examples
## -------------------------------------------------------------------------
##
## In a program a link comes out of the ordinary AME handshake between two
## neighbours. The examples skip the sockets and make the pair directly
## from one KEM exchange: `left` is held by one end, `right` by the other.

import bifrost_exchange_protocols

const
  kems*: AmeKemAlgorithms = [akaX25519, akaX25519]

proc linkPair*(): tuple[left, right: AmeSession] =
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
