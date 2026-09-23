## -------------------------------------------------------------------------
## AME Saber <- the Saber KEM slots, mapped onto Tyr
## -------------------------------------------------------------------------

import tyr/kems/saber as tyr_saber

import ../../../types
import ../../types
import ./types
import runePragmas

proc saberVariant(a: AmeKemAlgorithm): tyr_saber.SaberVariant {.role: parser.} =
  ## a: AME slot resolved to the Tyr variant that executes it.
  case a
  of akaFireSaber: result = tyr_saber.fireSaber
  of akaSaber: result = tyr_saber.saber
  of akaLightSaber: result = tyr_saber.lightSaber
  else:
    raise newException(ValueError, "AME KEM slot is not Saber: " & ameKemName(a))

proc saberSlotBuilt*(a: AmeKemAlgorithm): bool {.role: parser.} =
  ## a: Saber slot. Tyr's `-d:saberMaxRank` can leave the larger parameter
  ## sets out, so the family being built does not mean every slot is:
  ##
  ##   -d:saberMaxRank   LightSaber   Saber   FireSaber
  ##   ---------------   ----------   -----   ---------
  ##   4 (default)       yes          yes     yes
  ##   3                 yes          yes     no
  ##   2                 yes          no      no
  result = tyr_saber.saberVariantBuilt(saberVariant(a))

proc strongestSaberSlot*(): AmeKemAlgorithm {.role: configurator.} =
  ## The largest Saber slot this build can run: FireSaber unless Tyr's
  ## `-d:saberMaxRank` cut it off.
  when tyr_saber.saberMaxRank >= 4: result = akaFireSaber
  elif tyr_saber.saberMaxRank == 3: result = akaSaber
  else: result = akaLightSaber

proc saberAmeKeypair*(a: AmeKemAlgorithm): AmeKemKeypair {.role: truthBuilder.} =
  ## a: Saber slot to key independently.
  assignAmeKeypair(tyr_saber.saberTyrKeypair(saberVariant(a)))

proc saberAmeSeal*(a: AmeKemAlgorithm,
    publicKey: openArray[byte]): AmeKemCipher {.role: encryptor.} =
  ## a/publicKey: Saber slot and the receiver's public key.
  assignAmeCipher(tyr_saber.saberTyrEncaps(saberVariant(a), publicKey))

proc saberAmeOpen*(a: AmeKemAlgorithm, env: AmeKemCipher,
    secretKey: openArray[byte]): ByteSeq {.role: decryptor.} =
  ## a/env/secretKey: Saber slot, received envelope, and our secret key.
  result = tyr_saber.saberTyrDecaps(saberVariant(a), secretKey,
    env.envelope.ciphertext)
