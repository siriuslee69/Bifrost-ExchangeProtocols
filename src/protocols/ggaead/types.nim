## -------------------------------------------------------------------------
## GGAEAD Types <- compact two-key envelope sizes and detached ciphertext
## -------------------------------------------------------------------------

import ../types
import ../../analysis_pragmas

const
  ggAeadKeyMaterialBytes* = 64
  ggAeadNonceBytes* = 24
  ggAeadTagBytes* = 32

type
  GgAeadCiphertext* {.role: truthState, tag: {tagCryptoBoundary,
      tagGgAead, tagTypes}.} = object
    ciphertext*: ByteSeq
    authTag*: ByteSeq
