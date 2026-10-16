## -------------------------------------------------------------------------
## AME HQC <- the HQC KEM slots, mapped onto Tyr
## -------------------------------------------------------------------------
##
## Code-based like the Classic McEliece family it replaced on these wire ids
## (2026-10-16), but built on quasi-cyclic codes, which the 2026 Goppa-code
## key-recovery papers do not touch (BSI note, 29 Sep 2026). Keys stay small
## enough for one DAC frame:
##
##   slot    wire id   public key   ciphertext   NIST category
##   HQC-1   0x0E      2241 B       4433 B       1
##   HQC-3   0x0A      4514 B       8978 B       3
##   HQC-5   0x05      7237 B      14421 B       5

import tyr/kems/hqc as tyr_hqc

import ../../../types
import ../../types
import ./types
import runePragmas

proc hqcVariant(a: AmeKemAlgorithm): tyr_hqc.HqcVariant {.role: parser.} =
  ## a: AME slot resolved to the Tyr variant that executes it.
  case a
  of akaHqc5: result = tyr_hqc.hqc5
  of akaHqc3: result = tyr_hqc.hqc3
  of akaHqc1: result = tyr_hqc.hqc1
  else:
    raise newException(ValueError, "AME KEM slot is not HQC: " & ameKemName(a))

proc hqcAmeKeypair*(a: AmeKemAlgorithm): AmeKemKeypair {.role: truthBuilder.} =
  ## a: HQC slot to key independently.
  assignAmeKeypair(tyr_hqc.hqcTyrKeypair(hqcVariant(a)))

proc hqcAmeSeal*(a: AmeKemAlgorithm,
    publicKey: openArray[byte]): AmeKemCipher {.role: encryptor.} =
  ## a/publicKey: HQC slot and the receiver's public key.
  assignAmeCipher(tyr_hqc.hqcTyrEncaps(hqcVariant(a), publicKey))

proc hqcAmeOpen*(a: AmeKemAlgorithm, env: AmeKemCipher,
    secretKey: openArray[byte]): ByteSeq {.role: decryptor.} =
  ## a/env/secretKey: HQC slot, received envelope, and our secret key.
  result = tyr_hqc.hqcTyrDecaps(hqcVariant(a), secretKey,
    env.envelope.ciphertext)
