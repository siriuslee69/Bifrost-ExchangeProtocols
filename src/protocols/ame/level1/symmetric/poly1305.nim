## -------------------------------------------------------------------------
## AME Poly1305 <- the Poly1305 MAC slot
## -------------------------------------------------------------------------
##
## A ONE-TIME authenticator. AME never hands it a long-lived key: every tag
## is taken under a key freshly derived per message, layer and slot by
## `deriveAmeLayerKey`, so no key ever covers two messages.

import tyr/macs/poly1305 as tyr_poly1305

import ../../../types
import runePragmas

proc poly1305AmeMac*(key, data: openArray[byte]): ByteSeq {.role: helper.} =
  ## key/data: the per-message key and the authenticated bytes. The tag is
  ## always 16 bytes; AME normalizes it to the common length above.
  result = tyr_poly1305.poly1305Tag(key, data)
