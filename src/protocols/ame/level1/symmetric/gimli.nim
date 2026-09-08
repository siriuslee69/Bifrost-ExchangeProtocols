## -------------------------------------------------------------------------
## AME Gimli <- the cipher, MAC and XOF slots the Gimli sponge serves
## -------------------------------------------------------------------------
##
## One permutation covering three families at once, which is why it is the
## primitive to keep on the smallest targets.

import tyr/ciphers/gimli_sponge as tyr_gimli
import tyr/macs/hmac as tyr_hmac

import ../../../types
import bifrostPragmas

proc gimliAmeXor*(key, nonce, msg: openArray[byte]): ByteSeq {.
    role: encryptor.} =
  ## key/nonce/msg: stream-cipher inputs. XOR is its own inverse, so this
  ## seals and opens with the same call.
  result = tyr_gimli.gimliStreamXor(key, nonce, msg)

proc gimliAmeMac*(key, data: openArray[byte], outLen: int): ByteSeq {.
    role: helper.} =
  ## key/data/outLen: MAC key, authenticated bytes, requested tag length.
  result = tyr_hmac.gimliCustomHmac(key, data, outLen)

proc gimliAmeXof*(data: openArray[byte], outLen: int): ByteSeq {.
    role: helper.} =
  ## data/outLen: bytes to absorb and any requested output length.
  result = tyr_gimli.gimliXof(@[], @[], data, outLen)
