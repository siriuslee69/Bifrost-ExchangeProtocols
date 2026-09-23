## -------------------------------------------------------------------------
## FOMKE AME Chain Example <- exchange, message ratchet, and KEM upgrade
## -------------------------------------------------------------------------

import bifrost_exchange_protocols

const
  kems: AmeKemAlgorithms = [akaX25519, akaX25519]

when isMainModule:
  var
    layout: AmeSuiteLayout = defaultAmeLayout(kems)
    initialTier: AmeMaskTier = initAmeMaskTier(layout, 1'u32,
      initAmeTierMasks(0b10000000'u8, 0b10000000'u8, 0b10000000'u8,
        0b10000000'u8, 0b11000000'u8, 0b11000000'u8))
    upgradeTier: AmeMaskTier = fullAmeMaskTier(layout, 2'u32)
    initialRequest: AmeExchangeRequest
    initialKeys: AmeExchangeKeys
    initialSender: AmeExchangeResult
    initialReceiver: seq[ByteSeq] = @[]
    aliceAme: AmeExchangeState
    bobAme: AmeExchangeState
    alice: FomkeState
    bob: FomkeState
    message: FomkeMessage
    opened: FomkeOpenResult
    upgradeRequest: AmeExchangeRequest
    upgradeKeys: AmeExchangeKeys
    upgradeSender: AmeExchangeResult
    upgradeReceiver: seq[ByteSeq] = @[]
    aliceCommit: FomkeUpgradeCommit
    bobCommit: FomkeUpgradeCommit

  initialRequest = initAmeExchangeRequest(kems, initialTier, 0b10000000'u8)
  initialKeys = generateAmeExchangeKeys(kems, initialRequest)
  initialSender = sealAmeExchange(kems, initialRequest, initialKeys.publicKeys)
  initialReceiver = openAmeExchange(kems, initialRequest, initialSender.envelopes,
    initialKeys.secretKeys)

  aliceAme = initAmeExchangeState(kems)
  bobAme = initAmeExchangeState(kems)
  applyAmeExchange(aliceAme, layout, initialRequest, initialSender.sharedSecrets)
  applyAmeExchange(bobAme, layout, initialRequest, initialReceiver)
  ## One GB3HKDF call absorbs EVERY KEM slot the tier switches on, not just
  ## one, so a hybrid exchange is a hybrid in fact. Its output is cut into
  ## [ lane 1 key | lane 2 key | next secret ] -- no root key in between.
  alice = initFomkeFromAme(aliceAme, layout, initialTier, frInitiator)
  bob = initFomkeFromAme(bobAme, layout, initialTier, frResponder)

  message = sealFomkeMessage(alice, @[byte 70, 79, 77, 75, 69])
  opened = openFomkeMessage(bob, message)
  doAssert opened.ok

  upgradeRequest = initAmeExchangeRequest(kems, upgradeTier, 0b01000000'u8)
  upgradeKeys = generateAmeExchangeKeys(kems, upgradeRequest)
  upgradeSender = sealAmeExchange(kems, upgradeRequest, upgradeKeys.publicKeys)
  upgradeReceiver = openAmeExchange(kems, upgradeRequest, upgradeSender.envelopes,
    upgradeKeys.secretKeys)
  applyAmeExchange(aliceAme, layout, upgradeRequest, upgradeSender.sharedSecrets)
  applyAmeExchange(bobAme, layout, upgradeRequest, upgradeReceiver)
  aliceCommit = prepareFomkeUpgrade(alice, 1'u32, 2'u32, upgradeRequest,
    aliceAme)
  bobCommit = prepareFomkeUpgrade(bob, 1'u32, 2'u32, upgradeRequest, bobAme)
  doAssert fomkeUpgradeCommitsEqual(aliceCommit, bobCommit)
  confirmFomkeUpgrade(alice, bobCommit)
  confirmFomkeUpgrade(bob, aliceCommit)

  message = sealFomkeMessage(bob, @[byte 79, 75])
  opened = openFomkeMessage(alice, message)
  doAssert opened.ok
  ## The rotation replaced the next secret on both sides, from the old one
  ## plus the fresh KEM result.
  doAssert alice.nextSecret == bob.nextSecret
  echo "FOMKE epoch ", alice.epoch, " exchanged both directions"
