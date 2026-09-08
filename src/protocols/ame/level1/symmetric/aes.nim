## -------------------------------------------------------------------------
## AME AES <- the AES-CTR cipher slot
## -------------------------------------------------------------------------

import tyr/ciphers/aes_ctr as tyr_aes

import ../../../types
import bifrostPragmas

proc aesAmeXor*(key, nonce, msg: openArray[byte]): ByteSeq {.
    role: encryptor.} =
  ## key/nonce/msg: counter-mode inputs. XOR is its own inverse, so this
  ## seals and opens with the same call.
  result = tyr_aes.aesCtrXor(key, nonce, msg, tyr_aes.acbAuto)
