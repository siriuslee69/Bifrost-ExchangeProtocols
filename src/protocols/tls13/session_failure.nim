## ---------------------------------------------------------------------
## TLS 1.3 Session Failure <- what client AND server do when a handshake fails
## ---------------------------------------------------------------------
##
## One copy for `client_session` and `server_session`. A failed handshake
## does two things, in this order:
##
##   1. say why, with ONE alert record      (not the internal reason: that
##                                            stays on this side, see alerts.nim)
##   2. wipe every secret the session holds (key exchange key, handshake and
##                                            traffic secrets, record keys)
##
##   before the write keys exist   alert goes out as plain bytes
##   after the write keys exist    alert goes out sealed with them
##
## The session keeps its own "failed" state and its own error text; this
## module only has the part that is the same on both sides.

import tyr/helpers/secure_memory

import ../types
import ./[types, connection, key_schedule, alerts]
import runePragmas

proc failTls13Handshake*(C: var Tls13Connection, outbound: var seq[ByteSeq],
    x25519SecretKey: var ByteSeq, handshakeSecrets: var Tls13HandshakeSecrets,
    applicationSecrets: var Tls13ApplicationSecrets, e: string) {.
    role: actor, tag: "tls|validation|cryptoBoundary".} =
  ## C: the session's record connection (its write keys decide how the alert
  ##   is sent). outbound: where the alert record is appended.
  ## x25519SecretKey/handshakeSecrets/applicationSecrets: the session's secrets,
  ##   wiped here. e: the internal reason, reduced to a plain alert code.
  try:
    if not C.tls13WriteKeysInstalled():
      outbound.add(encodeTls13PlainAlert(talFatal, tls13AlertForError(e)))
    else:
      outbound.add(C.encodeTls13Protected(tctAlert,
        [byte 2, byte(ord(tls13AlertForError(e)))]))
  except CatchableError:
    discard
  secureClearBytes(x25519SecretKey)
  clearTls13HandshakeSecrets(handshakeSecrets)
  clearTls13ApplicationSecrets(applicationSecrets)
  C.clearTls13ConnectionSecrets()
