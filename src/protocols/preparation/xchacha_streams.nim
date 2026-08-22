## -------------------------------------------------------------------------
## XChaCha Streams <- Tyr batch selection with an older-Tyr scalar fallback
## -------------------------------------------------------------------------

when defined(bifrostTyrXChaChaBatch):
  import tyr/ciphers/xchacha20_batch as tyr_xchacha_batch
else:
  import tyr/ciphers/xchacha20 as tyr_xchacha

import ../types
import ../../analysis_pragmas

proc preparedXChaChaWidth*(): int {.role: configurator,
    tag: {tagAppApi, tagCryptoBoundary}.} =
  ## Return Tyr's compiled batch width, or one for an older scalar-only Tyr.
  when defined(bifrostTyrXChaChaBatch):
    result = tyr_xchacha_batch.xchacha20BatchWidth()
  else:
    result = 1

proc prepareXChaChaStreamRows*(K, N: openArray[ByteSeq], outputBytes: int,
    counter: uint32 = 0'u32): seq[ByteSeq] {.role: truthBuilder,
    tag: {tagAppApi, tagCryptoBoundary}.} =
  ## K/N/outputBytes/counter: independent Tyr XChaCha20 stream requests.
  if K.len != N.len:
    raise newException(ValueError,
      "XChaCha stream key and nonce counts differ")
  if outputBytes < 0:
    raise newException(ValueError,
      "XChaCha stream output length must not be negative")
  when defined(bifrostTyrXChaChaBatch):
    result = tyr_xchacha_batch.xchacha20BatchStreams(K, N, outputBytes,
      counter)
  else:
    var
      i: int = 0
    result.setLen(K.len)
    while i < K.len:
      result[i] = tyr_xchacha.xchacha20Stream(K[i], N[i], outputBytes,
        counter)
      i = i + 1
