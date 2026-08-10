## -------------------------------------------------------------------------
## Prepared Streams <- key-bound future-message stream bytes
## -------------------------------------------------------------------------

import ../types
import ../../analysis_pragmas

type
  PreparedStream* {.role: memory, tag: {tagCryptoBoundary, tagTypes}.} = object
    key*: ByteSeq
    nonce*: ByteSeq
    bytes*: ByteSeq
