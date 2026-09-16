## -------------------------------------------------------------------------
## AME Handshake Records <- the shape of the four messages, and only that
## -------------------------------------------------------------------------
##
## Four messages cross the wire, and this file says what is IN each one.
## Nothing here does anything: no keys, no checks, no bytes. It is the
## vocabulary three other files share, which is why it is its own file --
## `handshake_wire.nim` used to import the whole thousand-line handshake
## just to learn what a client hello has in it.
##
##   handshake_records.nim    the SHAPE of a message   <- you are here
##   handshake_wire.nim       that shape, as BYTES
##   handshake_transcript.nim the running record of everything said
##   handshake.nim            what each side DOES with them
##
## ╭─ ❧ what is in the clear and what is not 🌊
##
## Read the two hellos side by side and the rule falls out: everything needed
## to work out the temporary key travels in the open, and everything that
## says WHO is talking goes in the sealed block behind it.
##
##   AmeClientHello     nonce, slot layout, KEM public keys   <- open
##                      (no identity at all -- deliberately)
##   AmeServerHello     nonce, KEM answer, chosen params      <- open
##                      sealed: certificate + proofs          <- hidden
##   AmeClientFinish    params                                <- open
##                      sealed: certificate + proofs + the
##                              hash of everything said       <- hidden
##
## So an observer sees two nonces and some key material, and never learns who
## the two endpoints are. Only they do.

import ../../types
import ../types
import ./handshake_identity
import runePragmas

## A record CONTAINS an `AmeTrustMode` and an `AmeIdentityCertificate`, so
## anyone holding the shape needs the vocabulary its fields are written in.
export handshake_identity

type
  ## The cleartext half of a client hello. No identity here on purpose.
  AmeClientHello* {.role: truthState.} = object
    sessionId*: uint64
    mode*: AmeTrustMode
    nonce*: ByteSeq
    layout*: AmeSuiteLayout
    initialTier*: AmeMaskTier
    cookie*: ByteSeq
    offer*: AmeExchangeOffer

  AmeHelloRetry* {.role: truthState.} = object
    sessionId*: uint64
    cookie*: ByteSeq

  ## The server hello: nonce and KEM answer in the clear, everything that
  ## says who the server is inside the sealed block.
  AmeServerHello* {.role: truthState.} = object
    nonce*: ByteSeq
    mode*: AmeTrustMode
    reply*: AmeExchangeReply
    params*: AmeRuntimeParams
      ## The tunables the responder picked for the first epoch. In the clear,
      ## because the client needs them to open the sealed block below, and
      ## bound into that block's tag so they cannot be edited in flight.
    authTag*: ByteSeq
    sealed*: ByteSeq

  ## What the server's sealed block decrypts to. Which half is filled in
  ## depends on the mode the hello named:
  ##
  ##   AM1C / AM1S : certificate + one proof per signature slot
  ##   AM1M        : pskId + exactly one shared-secret proof
  AmeServerIdentityBlock* {.role: truthState.} = object
    certificate*: AmeIdentityCertificate
    pskId*: string
    proofs*: seq[ByteSeq]

  AmeClientFinish* {.role: truthState.} = object
    params*: AmeRuntimeParams
    authTag*: ByteSeq
    sealed*: ByteSeq

  ## What the client's sealed block decrypts to. Split the same way as the
  ## server's block above, and always carrying the transcript hash.
  AmeClientIdentityBlock* {.role: truthState.} = object
    certificate*: AmeIdentityCertificate
    pskId*: string
    transcriptHash*: ByteSeq
    proofs*: seq[ByteSeq]

  AmeClientHandshake* {.role: truthState.} = object
    hello*: AmeClientHello
    secretKeys*: seq[ByteSeq]

  AmeServerHandshake* {.role: truthState.} = object
    clientHello*: AmeClientHello
    serverHello*: AmeServerHello
    sharedSecrets*: seq[ByteSeq]
    localSignatureSecretKeys*: seq[ByteSeq]

  AmeHandshakeResult* {.role: truthState.} = object
    ok*: bool
    auth*: AmeAuthPackage
    peerTrust*: AmePeerTrustResult
    finish*: AmeClientFinish
    err*: string
