## -------------------------------------------------------------------------
## AME Argon2 <- the Argon2id KDF slot
## -------------------------------------------------------------------------
##
## Memory-hard by design: one call wants tens of megabytes of working
## memory. That is the point for password stretching and the reason a small
## device should leave this primitive out of the build.

import tyr/kdfs/argon2 as tyr_argon2

import ../../../types
import runePragmas

proc argon2AmeKdf*(seed, salt: openArray[byte], outLen: int): ByteSeq {.
    role: helper.} =
  ## seed/salt/outLen: bound seed, derived salt, and requested key length.
  result = tyr_argon2.argon2idTyrHash(seed, salt, 3, 65_536, 1, outLen)
