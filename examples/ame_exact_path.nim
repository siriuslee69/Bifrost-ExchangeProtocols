## -------------------------------------------------------------------------
## AME Mask Tier Example <- immutable slots, tier masks, and data trigger
## -------------------------------------------------------------------------

import bifrost_exchange_protocols

const
  myAlgos: AmeKemAlgorithms = [
    akaMcEliece6688,
    akaFireSaber,
    akaFireSaber,
    akaX25519
  ]

var
  layout: AmeSuiteLayout = defaultAmeLayout(myAlgos)
  initial: AmeMaskTier = initAmeMaskTier(layout, 10'u32,
    initAmeTierMasks(0b10000000'u8, 0b10000000'u8, 0b10000000'u8,
      0b10000000'u8, 0b10000000'u8, 0b10000000'u8))
  stronger: AmeMaskTier = initAmeMaskTier(layout, 20'u32,
    initAmeTierMasks(0b11110000'u8, 0b10000000'u8, 0b10000000'u8,
      0b10000000'u8, 0b11000000'u8, 0b11000000'u8))
  upgradePath: AmeTierPath = initAmeTierPath(layout, [initial, stronger])
  afterData: AmeTierStep

upgradePath.setCurrentAmeTier(initial)
upgradePath.setTrigger(1, 200'u64)
afterData = upgradePath.feedTransferredBytes(200'u64 * ameBytesPerMiB)

echo "target tier: ", afterData.targetTier.tierId
echo "KEM exchange:", afterData.exchangeMask
echo "layout bytes:", encodeAmeSuiteLayout(upgradePath.layout).len
