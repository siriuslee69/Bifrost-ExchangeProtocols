## -------------------------------------------------------------------------
## AME ChaCha20 <- the ChaCha20 and XChaCha20 cipher slots
## -------------------------------------------------------------------------
##
## Same core, two nonce sizes: ChaCha20 takes 12 bytes, XChaCha20 takes 24
## and folds the extra into a derived subkey. One primitive, both slots.

import tyr/ciphers/chacha20 as tyr_chacha
import tyr/ciphers/xchacha20 as tyr_xchacha

import ../../../types
import ../../types
import runePragmas

proc chachaAmeXor*(a: AmeCipherAlgorithm,
    key, nonce, msg: openArray[byte]): ByteSeq {.role: encryptor.} =
  ## a/key/nonce/msg: which of the two slots, plus stream-cipher inputs.
  ## XOR is its own inverse, so this seals and opens with the same call.
  case a
  of acaXChaCha20: result = tyr_xchacha.xchacha20Xor(key, nonce, msg)
  of acaChaCha20: result = tyr_chacha.chacha20Xor(key, nonce, msg)
  else:
    raise newException(ValueError, "AME cipher slot is not ChaCha20")
