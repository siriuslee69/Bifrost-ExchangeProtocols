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

import std/strutils

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

## ╭⟢ which modes this build carries
##
## Like -d:bifrostKems for algorithms, one flag decides which modes exist:
##
##   nim c -d:bifrostHandshakes=am1p app.nim          AM1P only
##   nim c -d:bifrostHandshakes=am1p,am1ps app.nim    AM1P and AM1P+S
##
##   -d:bifrostHandshakes=<list>   what drops out of the program
##   ---------------------------   --------------------------------------
##   (omitted)                     nothing; all four modes
##   am1p                          certificates, signatures, authority
##                                 checks: every signature routine
##   am1s / am1ps                  authority checks (AM1A)
##   am1a                          the sealed hello and the PSK binder
##
## How the code drops out: the two questions every handshake step asks,
## "does this mode use a PSK?" and "does it sign?", become fixed answers
## when every built mode answers alike. The C compiler then removes the
## branch that can no longer run. Calling the constructor of a mode that is
## left out does not compile, and the error names the flag. A mode that
## arrives from the wire, or sits in a default-built value, is refused while
## running.

proc parseAmeTrustModes(s: string): set[AmeTrustMode] {.role: parser.} =
  ## s: comma-separated mode names from `-d:bifrostHandshakes=`. Empty is
  ## all four. Runs while compiling; an unknown name stops the build.
  var
    t: string = ""
  if s.strip().len == 0:
    return {atmAuthorityCertificate .. atmPreSharedPinned}
  for raw in s.split(','):
    t = raw.strip().toLowerAscii()
    case t
    of "am1a": result.incl(atmAuthorityCertificate)
    of "am1s": result.incl(atmPinnedPeerKey)
    of "am1p": result.incl(atmPreSharedKey)
    of "am1ps", "am1p+s": result.incl(atmPreSharedPinned)
    else:
      raise newException(ValueError, "unknown -d:bifrostHandshakes entry '" &
        t & "' (expected: am1a, am1s, am1p, am1ps, or omit the flag for all)")

const
  bifrostHandshakes* {.strdefine.}: string = ""
    ## Comma-separated AM1 modes to compile. Empty (the default) is all four.
  ameModesBuilt* = parseAmeTrustModes(bifrostHandshakes)
    ## The modes this build actually carries.
  amePskModes: set[AmeTrustMode] = {atmPreSharedKey, atmPreSharedPinned}
  ameSignatureModes: set[AmeTrustMode] = {atmAuthorityCertificate,
    atmPinnedPeerKey, atmPreSharedPinned}

when ameModesBuilt == {}:
  {.error: "-d:bifrostHandshakes= selected no mode; omit the flag to keep all".}

## The gates on the four constructors below: empty when the mode is built,
## a compile error naming the flag when it is not.
when atmAuthorityCertificate in ameModesBuilt:
  {.pragma: am1aGate.}
else:
  {.pragma: am1aGate, error: "AM1A is not in this build; add am1a to " &
    "-d:bifrostHandshakes= or omit the flag".}
when atmPinnedPeerKey in ameModesBuilt:
  {.pragma: am1sGate.}
else:
  {.pragma: am1sGate, error: "AM1S is not in this build; add am1s to " &
    "-d:bifrostHandshakes= or omit the flag".}
when atmPreSharedKey in ameModesBuilt:
  {.pragma: am1pGate.}
else:
  {.pragma: am1pGate, error: "AM1P is not in this build; add am1p to " &
    "-d:bifrostHandshakes= or omit the flag".}
when atmPreSharedPinned in ameModesBuilt:
  {.pragma: am1psGate.}
else:
  {.pragma: am1psGate, error: "AM1P+S is not in this build; add am1ps to " &
    "-d:bifrostHandshakes= or omit the flag".}

proc ameModeBuilt*(m: AmeTrustMode): bool {.role: parser, inline.} =
  ## m: true when this build can run that mode.
  result = m in ameModesBuilt

proc ameModeBuiltError*(m: AmeTrustMode): string {.role: parser.} =
  ## m: "" when the mode is built, otherwise the refusal to report. Callers
  ## ask this first, so a mode left out never reaches the two fixed answers
  ## below (which would otherwise speak for a mode they were not built for).
  if m notin ameModesBuilt:
    result = "AME authentication mode " & $m & " is not in this build " &
      "(-d:bifrostHandshakes)"

proc ameModeUsesPsk*(m: AmeTrustMode): bool {.role: parser, inline.} =
  ## m: true for the modes that hold a pre-shared key (AM1P, AM1P+S). Those
  ## are the ones whose hello is encrypted and whose key schedule takes a
  ## binder from the shared secret. Fixed while compiling when every built
  ## mode answers alike.
  when ameModesBuilt <= amePskModes: result = true
  elif (ameModesBuilt * amePskModes) == {}: result = false
  else: result = m in amePskModes

proc ameModeUsesSignatures*(m: AmeTrustMode): bool {.role: parser, inline.} =
  ## m: true for the modes whose sealed blocks carry a certificate and one
  ## signature per active slot (AM1A, AM1S, AM1P+S). Fixed while compiling
  ## when every built mode answers alike.
  when ameModesBuilt <= ameSignatureModes: result = true
  elif (ameModesBuilt * ameSignatureModes) == {}: result = false
  else: result = m in ameSignatureModes

proc ameModeUsesAuthority*(m: AmeTrustMode): bool {.role: parser, inline.} =
  ## m: true for AM1A, the one mode that checks an authority's signature on
  ## the peer's certificate. False for every mode when AM1A is left out.
  when atmAuthorityCertificate notin ameModesBuilt: result = false
  elif ameModesBuilt == {atmAuthorityCertificate}: result = true
  else: result = m == atmAuthorityCertificate

proc initAmeCertificateAuthentication*(root: AmeAuthorityRoot): AmeAuthentication {.
    role: configurator, tag: "appApi", am1aGate.} =
  ## root: authority key stack used to validate certificates (AM1A).
  if root.authority.len == 0 or root.signingKeys.len == 0:
    raise newException(ValueError, "AME certificate authentication is incomplete")
  result.mode = atmAuthorityCertificate
  result.root = root

proc initAmePinnedAuthentication*(peer: AmePinnedPeerIdentity): AmeAuthentication {.
    role: configurator, tag: "appApi", am1sGate.} =
  ## peer: public key expected from the remote endpoint (AM1S).
  if peer.subject.len == 0 or peer.signingKeys.len == 0:
    raise newException(ValueError, "AME pinned authentication is incomplete")
  result.mode = atmPinnedPeerKey
  result.expectedPeer = peer

proc initAmePskAuthentication*(identifier: string,
    secret: openArray[uint8]): AmeAuthentication {.role: configurator,
    tag: "appApi", am1pGate.} =
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
    tag: "appApi", am1psGate.} =
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
  if identifier.len == 0 or secret.len < 16:
    raise newException(ValueError, "AME PSK authentication is incomplete")
  if peer.subject.len == 0 or peer.signingKeys.len == 0:
    raise newException(ValueError, "AME pinned authentication is incomplete")
  result.mode = atmPreSharedPinned
  result.pskId = identifier
  result.psk = @secret
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

