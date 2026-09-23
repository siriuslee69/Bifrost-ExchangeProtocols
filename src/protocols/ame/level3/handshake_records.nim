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
import ./handshake_authentication
import runePragmas

## A record CONTAINS an `AmeTrustMode` and an `AmeIdentityCertificate`, so
## anyone holding the shape needs the vocabulary its fields are written in.
export handshake_authentication

type
  ## The client hello. No identity here on purpose.
  ##
  ## In the pre-shared modes (AM1P, AM1P+S) the offer -- the KEM public keys
  ## -- does not travel in the clear. It is sealed under a key taken from the
  ## shared secret, and `offer` is only filled in once it has been opened:
  ##
  ##   AM1A / AM1S          offer          in the clear
  ##   AM1P / AM1P+S        offerSalt      in the clear, fresh per hello
  ##                        usesNextSecret in the clear, one flag
  ##                        sealedOffer    ciphertext of the offer
  ##                        offerTag       its 32-byte tag
  AmeClientHello* {.role: truthState.} = object
    sessionId*: uint64
    mode*: AmeTrustMode
    nonce*: ByteSeq
    layout*: AmeSuiteLayout
    initialTier*: AmeMaskTier
    cookie*: ByteSeq
    offer*: AmeExchangeOffer
    offerSalt*: ByteSeq
      ## 32 random bytes. The shared secret is the same for every hello, so
      ## without a fresh salt two hellos would be sealed under one key and
      ## one keystream -- XOR the two and both offers fall out.
    usesNextSecret*: bool
      ## True when the seal key (and the key schedule) also took the next
      ## secret from the previous session. In the clear so a responder that
      ## lacks it can refuse at once, and so a fallback is never silent.
    sealedOffer*: ByteSeq
    offerTag*: ByteSeq

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
  ##   AM1A / AM1S : certificate + one proof per signature slot
  ##   AM1P        : pskId + exactly one shared-secret proof
  ##   AM1P+S      : pskId + one shared-secret proof, THEN the certificate
  ##                 and one proof per signature slot -- both halves
  AmeServerIdentityBlock* {.role: truthState.} = object
    certificate*: AmeIdentityCertificate
    pskId*: string
    pskProofs*: seq[ByteSeq]
      ## The shared-secret proof (exactly one) in AM1P and AM1P+S.
    proofs*: seq[ByteSeq]
      ## One signature per active slot in AM1A, AM1S and AM1P+S.

  AmeClientFinish* {.role: truthState.} = object
    params*: AmeRuntimeParams
    authTag*: ByteSeq
    sealed*: ByteSeq

  ## What the client's sealed block decrypts to. Split the same way as the
  ## server's block above, and always carrying the transcript hash.
  AmeClientIdentityBlock* {.role: truthState.} = object
    certificate*: AmeIdentityCertificate
    pskId*: string
    pskProofs*: seq[ByteSeq]
      ## The shared-secret proof (exactly one) in AM1P and AM1P+S.
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
    authentication*: AmeAuthentication
      ## What this side answered the hello with, AFTER it was matched to the
      ## hello's next-secret flag. The finish is opened with exactly this,
      ## never with a fresh copy the caller might hand in differently.

  AmeHandshakeResult* {.role: truthState.} = object
    ok*: bool
    auth*: AmeAuthPackage
    peerTrust*: AmePeerTrustResult
    finish*: AmeClientFinish
    err*: string
