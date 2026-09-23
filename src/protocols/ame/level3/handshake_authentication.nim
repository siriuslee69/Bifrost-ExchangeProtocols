## -------------------------------------------------------------------------
## AME Handshake Authentication <- WHOM this side believes, chosen once
## -------------------------------------------------------------------------
##
## `handshake_identity.nim` next door says what an identity IS: keys,
## certificates, and how to check one. This file says which of those a
## connection demands, and holds the one object every handshake step reads:
##
##   handshake_identity.nim        identities and certificates
##   handshake_authentication.nim  the mode + AmeAuthentication  <- you are here
##
## Importing this file gives you the identity vocabulary as well.
##
## ╭─ ❧ the three ways to be believed 🌊
##
## There are three, plus one that combines two of them. You pick one when you
## build the connection, and every later step reads it from the same place:
##
##   AM1A    atmAuthorityCertificate  an Authority you trust vouches for them
##   AM1S    atmPinnedPeerKey         you hold their Signature key already
##   AM1P    atmPreSharedKey          you share a Pre-shared key already
##   AM1P+S  atmPreSharedPinned       BOTH: the shared key and their pinned
##                                    signature key must check out
##
## What each one proves, and what a thief of it can do:
##
##   mode     proof                          someone who STEALS it can ...
##   -------  -----------------------------  ------------------------------
##   AM1A     "an authority vouched for me"  whatever the authority signs
##   AM1S     "I own this pinned key"        pretend to be that one side
##   AM1P     "I know the shared secret"     pretend to be EITHER side
##   AM1P+S   both of the above              needs to steal BOTH
##
## The pre-shared modes also ENCRYPT the client hello (its KEM public keys)
## under a key taken from the shared secret, so an observer cannot even see
## which keys were offered. A quantum computer that breaks every signature
## still cannot forge AM1P, because it is purely symmetric; AM1P+S keeps that
## property and adds a signature for the day the shared secret leaks.
##
## The constructors that say which are at the bottom of this file, side by
## side, so the choice is one place and not four.

import ../../types
import ../types
import ../level0/bytes
import ./handshake_identity
import runePragmas

## An `AmeAuthentication` names a pinned identity, so anyone holding one
## needs the identity vocabulary too.
export handshake_identity

type
  ## How this side decides whom to believe. One value, chosen once, and every
  ## step of the handshake reads it from the same place.
  ## The number of each value is the mode byte on the wire.
  AmeTrustMode* = enum
    atmAuthorityCertificate,
      ## AM1A -- a certificate signed by a pinned authority.
    atmPinnedPeerKey,
      ## AM1S -- the peer's own public key, provisioned in advance.
    atmPreSharedKey,
      ## AM1P -- a shared secret, provisioned in advance. No certificates and
      ## no signature keys are involved on either side.
    atmPreSharedPinned
      ## AM1P+S -- the shared secret of AM1P AND the pinned key of AM1S.

  ## Which end of the exchange a shared-secret proof belongs to. Without this
  ## the two proofs would be tags over different byte strings and nothing
  ## more; with it they are tags over byte strings that cannot be confused,
  ## so a responder's proof can never be replayed as an initiator's.
  AmePskProofDirection* = enum
    apdResponder,
    apdInitiator

  ## Everything one endpoint needs in order to judge the other. Which of the
  ## groups below is filled in is chosen by `mode`:
  ##
  ##   mode     pskId+psk   root   expectedPeer   nextSecret
  ##   -------  ---------   ----   ------------   ----------
  ##   AM1A        -         yes        -             -
  ##   AM1S        -          -        yes            -
  ##   AM1P       yes         -         -         optional
  ##   AM1P+S     yes         -        yes        optional
  AmeAuthentication* {.role: configurator.} = object
    mode*: AmeTrustMode
    pskId*: string
      ## AM1P / AM1P+S. Names WHICH shared secret this is, so a machine
      ## holding several does not have to guess. Travels sealed, never in the
      ## clear.
    psk*: ByteSeq
      ## AM1P / AM1P+S. Never leaves this machine; only tags, keys and one
      ## derived binder computed from it ever reach the exchange.
    root*: AmeAuthorityRoot
      ## AM1A only.
    expectedPeer*: AmePinnedPeerIdentity
      ## AM1S and AM1P+S.
    nextSecret*: ByteSeq
      ## AM1P / AM1P+S, optional. The 32 bytes the PREVIOUS session with this
      ## peer handed out (`ameNextHandshakeSecret`). When present it keys the
      ## sealed hello together with the psk AND joins the key schedule, so
      ## this session needs both. Empty = first contact, psk alone.
    nextSecretRequired*: bool
      ## Responder policy. True refuses any hello that does NOT carry the
      ## next secret, so an attacker cannot quietly fall this side back to
      ## psk-only by breaking a handshake on purpose. False accepts both, and
      ## the fallback is still visible: the hello's flag says which it was.

## ╭⟢ the three ways to say whom you believe
##
## All three live here, side by side. Two of them used to sit 1500 lines
## below the third, which made "what are my options" a search rather than a
## glance.
##
## The wire path is the same in all three modes:
##
##   hello(KEM public keys) -> answer(KEM ciphertext) -> finish(transcript)
##
## Only the authentication input differs, and it is chosen once, by building
## one `AmeAuthentication` and handing it to every call below. There is no
## second way to say the same thing.
##
##   what you provision            what you build                     mode
##   ---------------------------   ---------------------------------  ------
##   an authority's public keys    initAmeCertificateAuthentication   AM1A
##   the peer's own public key     initAmePinnedAuthentication        AM1S
##   a shared secret               initAmePskAuthentication           AM1P
##   a shared secret AND the       initAmePskPinnedAuthentication     AM1P+S
##     peer's own public key
##
## And for a pre-shared mode that met this peer before:
##
##   the next secret the last      withAmeNextSecret(a, kept)
##     session handed out

proc ameModeUsesPsk*(m: AmeTrustMode): bool {.role: parser, inline.} =
  ## m: true for the modes that hold a pre-shared key (AM1P, AM1P+S). Those
  ## are the ones whose hello is encrypted and whose key schedule takes a
  ## binder from the shared secret.
  result = m == atmPreSharedKey or m == atmPreSharedPinned

proc ameModeUsesSignatures*(m: AmeTrustMode): bool {.role: parser, inline.} =
  ## m: true for the modes whose sealed blocks carry a certificate and one
  ## signature per active slot (AM1A, AM1S, AM1P+S).
  result = m != atmPreSharedKey

proc initAmeCertificateAuthentication*(root: AmeAuthorityRoot): AmeAuthentication {.
    role: configurator, tag: "appApi".} =
  ## root: authority key stack used to validate certificates (AM1A).
  if root.authority.len == 0 or root.signingKeys.len == 0:
    raise newException(ValueError, "AME certificate authentication is incomplete")
  result.mode = atmAuthorityCertificate
  result.root = root

proc initAmePinnedAuthentication*(peer: AmePinnedPeerIdentity): AmeAuthentication {.
    role: configurator, tag: "appApi".} =
  ## peer: public key expected from the remote endpoint (AM1S).
  if peer.subject.len == 0 or peer.signingKeys.len == 0:
    raise newException(ValueError, "AME pinned authentication is incomplete")
  result.mode = atmPinnedPeerKey
  result.expectedPeer = peer

proc initAmePskAuthentication*(identifier: string,
    secret: openArray[uint8]): AmeAuthentication {.role: configurator,
    tag: "appApi".} =
  ## identifier/secret: AM1P provisioning material -- a name for the shared
  ## secret, and the secret itself (at least 16 bytes, 32 recommended).
  if identifier.len == 0 or secret.len < 16:
    raise newException(ValueError, "AME PSK authentication is incomplete")
  result.mode = atmPreSharedKey
  result.pskId = identifier
  result.psk = @secret

proc initAmePskPinnedAuthentication*(identifier: string,
    secret: openArray[uint8],
    peer: AmePinnedPeerIdentity): AmeAuthentication {.role: configurator,
    tag: "appApi".} =
  ## identifier/secret/peer: AM1P+S -- the shared secret of AM1P plus the
  ## peer's pinned public key of AM1S. Both must check out:
  ##
  ##   shared secret stolen, signing key safe   -> still secure
  ##   signatures broken, shared secret safe    -> still secure
  ##   both lost                                -> broken
  ##
  ## Costs one signature and one verification per side, once per handshake.
  ## This side must also hand its own identity key to the handshake calls,
  ## exactly as in AM1S.
  result = initAmePskAuthentication(identifier, secret)
  if peer.subject.len == 0 or peer.signingKeys.len == 0:
    raise newException(ValueError, "AME pinned authentication is incomplete")
  result.mode = atmPreSharedPinned
  result.expectedPeer = peer

proc withAmeNextSecret*(a: AmeAuthentication, nextSecret: openArray[uint8],
    required: bool = false): AmeAuthentication {.role: configurator,
    tag: "appApi|cryptoBoundary".} =
  ## a: a pre-shared authentication (AM1P or AM1P+S).
  ## nextSecret: the 32 bytes the last session handed out
  ##   (`ameNextHandshakeSecret`). Empty removes it again.
  ## required: responder policy -- refuse hellos that do not carry it.
  ##
  ##   first session:   initAmePskAuthentication(id, psk)
  ##   later sessions:  initAmePskAuthentication(id, psk).withAmeNextSecret(ns)
  ##
  ## The hello is then sealed under psk + next secret, and the next secret
  ## joins the key schedule. A stolen psk alone no longer opens the hello.
  if not ameModeUsesPsk(a.mode):
    raise newException(ValueError,
      "AME next secret only applies to the pre-shared modes")
  if nextSecret.len != 0 and nextSecret.len != 32:
    raise newException(ValueError, "AME next secret must be 32 bytes")
  result = a
  result.nextSecret = @nextSecret
  result.nextSecretRequired = required

proc clearAmeAuthentication*(A: var AmeAuthentication) {.
    role: actor, tag: "appApi|cryptoBoundary".} =
  ## A: erase provisioned shared-secret material once it is finished with.
  secureClearAmeBytes(A.psk)
  secureClearAmeBytes(A.nextSecret)
  A = default(AmeAuthentication)

