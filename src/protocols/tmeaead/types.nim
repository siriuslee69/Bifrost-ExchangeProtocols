## -------------------------------------------------------------------------
## TMEAEAD Types <- five-key composite envelope sizes and detached ciphertext
## -------------------------------------------------------------------------

import ../types
import ../../analysis_pragmas

const
  tmeAeadKeyMaterialBytes* = 160
  tmeAeadNonceBytes* = 24
  tmeAeadTagBytes* = 32

type
  TmeAeadCiphertext* {.role: truthState, tag: {tagCryptoBoundary,
      tagTmeAead, tagTypes}.} = object
    ciphertext*: ByteSeq
    authTag*: ByteSeq
