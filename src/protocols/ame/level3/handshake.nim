## -------------------------------------------------------------------------
## AME Handshake <- who you are, agreed in private, then the first epoch
## -------------------------------------------------------------------------
##
## Four messages, at most. Reading left to right is the whole protocol:
##
##   client                                                   server
##     |                                                         |
##     |--- hello: nonce, slot layout, KEM public keys ---------->|
##     |                                                         |  (optional)
##     |<-- retry: "prove you are really at that address" -------|
##     |--- hello again, now carrying the cookie ---------------->|
##     |                                                         |
##     |<-- server hello: nonce, KEM answer, THEN a sealed block -|
##     |        the sealed block holds the server's certificate   |
##     |                                                         |
##     |--- finish: a sealed block holding the client's ---------->|
##     |        certificate and its proof of the whole exchange   |
##     |                                                         |
##   both sides now hold the same keys, and start the ratchet
##
## Why the certificates are sealed
## -------------------------------
## The KEM answer in the server hello is enough for both sides to work out a
## temporary key. Everything after that point is encrypted with it. So an
## observer watching the wire sees two nonces and some key material, and never
## learns WHO is talking to whom. Only the two endpoints do.
##
## What the cookie is for
## ----------------------
## Answering a hello costs real work: a key encapsulation per slot, plus
## verifying and producing signatures. A machine that sends holds forged
## return addresses could make a server do that work all day. The cookie is a
## short tag the server computes from the sender's address with a secret only
## it knows. It keeps no record of having issued one -- it simply recomputes
## the tag when the cookie comes back. Someone who cannot receive at the
## address they claimed never gets a valid cookie back, so the expensive work
## only ever runs for a peer that is really there.

import tyr/helpers/random as tyr_random
import tyr/helpers/tiers as tyr_alg
import ../level1/signatures

import ../../types
import ../types
import ../level0/bytes
import ../level1/exchange_paths
import ../level1/suites
import ../level1/symmetric
import ../level1/tier_aead
import ../level1/padding
import ../level1/path_triggers
import ../level2/session
import ../../fomke/level0/gb3hkdf
import ../../../analysis_pragmas

const
  ameCookieSecretLen* = 32
  ameCookieLifetimeSeconds* = 30'i64
    ## How long a cookie stays good. Long enough to survive one round trip on
    ## a slow link, short enough that a captured cookie is worthless later.
  ameHandshakeTextMax* = 4096'u32
  ameIdentityKeyMax* = 1_048_576'u32
  ameSignatureProofMax* = 1_048_576'u32
  ameMaxCertificateSkewSeconds* = 86_400'i64
    ## How far the caller's clock may sit outside a certificate's window
    ## before this side refuses to judge it at all. A machine whose clock is
    ## a year out would otherwise silently accept expired certificates.

type
  AmeTrustMode* = enum
    atmAuthorityCertificate,
    atmPinnedPeerKey

  AmePinnedPeerIdentity* {.role: configurator.} = object
    subject*: string
    signingKeys*: seq[AmeIdentitySigningKey]

  ## An authority that issues certificates. Its keys are a STACK, exactly like
  ## the identities it signs for: breaking one algorithm is not enough to mint
  ## a certificate, because every slot has to produce a valid proof.
  AmeAuthorityKey* {.role: configurator.} = object
    name*: string
    signingKeys*: seq[AmeIdentitySigningKey]
    secretKeys*: seq[ByteSeq]

  AmeIdentityKey* {.role: configurator.} = object
    subject*: string
    signingKeys*: seq[AmeIdentitySigningKey]
    secretKeys*: seq[ByteSeq]

  AmeIdentityCertificate* {.role: truthState.} = object
    serial*: uint64
      ## Names this certificate, not its holder. Revoking a serial takes one
      ## certificate out of use; the same subject can be issued a fresh one.
      ## Revoking by name instead would burn the name forever.
    authority*: string
    subject*: string
    signingKeys*: seq[AmeIdentitySigningKey]
    validFromUnix*: int64
    validUntilUnix*: int64
    authorityProofs*: seq[ByteSeq]
      ## One proof per authority slot, in the authority's own key order.
      ## Empty for a directly pinned identity, which carries no authority.

  ## The cleartext half of a client hello. No identity here on purpose.
  AmeClientHello* {.role: truthState.} = object
    sessionId*: uint64
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
    reply*: AmeExchangeReply
    params*: AmeRuntimeParams
      ## The tunables the responder picked for the first epoch. In the clear,
      ## because the client needs them to open the sealed block below, and
      ## bound into that block's tag so they cannot be edited in flight.
    authTag*: ByteSeq
    sealed*: ByteSeq

  ## What the server's sealed block decrypts to.
  AmeServerIdentityBlock* {.role: truthState.} = object
    certificate*: AmeIdentityCertificate
    proofs*: seq[ByteSeq]

  AmeClientFinish* {.role: truthState.} = object
    params*: AmeRuntimeParams
    authTag*: ByteSeq
    sealed*: ByteSeq

  ## What the client's sealed block decrypts to.
  AmeClientIdentityBlock* {.role: truthState.} = object
    certificate*: AmeIdentityCertificate
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

  ## A server's stateless anti-flood secret. Rotate it whenever convenient;
  ## the only cost of rotating is that cookies in flight stop verifying and
  ## those clients retry once.
  AmeCookieSecret* {.role: configurator.} = object
    key*: ByteSeq

proc appendHandshakeString(A: var ByteSeq, s: string) {.
    role: stateController.} =
  ## A/s: destination and length-framed UTF-8 identity text.
  requireAmeU32Len(s.len, "handshake string")
  appendAmeU32(A, uint32(s.len))
  appendAmeLabel(A, s)

proc appendHandshakeBytes(A: var ByteSeq, B: openArray[uint8]) {.
    role: stateController.} =
  ## A/B: destination and length-framed bytes.
  requireAmeU32Len(B.len, "handshake bytes")
  appendAmeU32(A, uint32(B.len))
  appendAmeBytes(A, B)

proc appendHandshakeProofs(A: var ByteSeq, P: openArray[ByteSeq]) {.
    role: stateController.} =
  ## A/P: destination and ordered signature proof stack.
  var
    i: int = 0
  requireAmeU32Len(P.len, "handshake proof count")
  appendAmeU32(A, uint32(P.len))
  while i < P.len:
    appendHandshakeBytes(A, P[i])
    i = i + 1

proc appendHandshakeI64(A: var ByteSeq, v: int64) {.role: stateController.} =
  ## A/v: destination and two's-complement little-endian timestamp.
  appendAmeU64(A, cast[uint64](v))

proc appendIdentitySigningKeys(A: var ByteSeq,
    K: openArray[AmeIdentitySigningKey]) {.role: stateController.} =
  ## A/K: destination and complete ordered identity signature-key stack.
  var
    i: int = 0
  if K.len == 0 or K.len > ameMaxAlgorithmSlots:
    raise newException(ValueError, "AME identity signing-key count is invalid")
  A.add(uint8(K.len))
  while i < K.len:
    if K[i].publicKey.len == 0:
      raise newException(ValueError, "AME identity signing key is empty")
    A.add(uint8(ord(K[i].algorithm)))
    appendHandshakeBytes(A, K[i].publicKey)
    i = i + 1

proc identityKeysEqual*(A, B: openArray[AmeIdentitySigningKey]): bool {.
    role: parser.} =
  ## A/B: ordered algorithms and public keys compared without short-circuiting
  ## on the key bytes, so a near-miss key does not leak how near it was.
  var
    i: int = 0
  if A.len != B.len:
    return false
  result = true
  while i < A.len:
    if A[i].algorithm != B[i].algorithm or
        not constantTimeEqualAme(A[i].publicKey, B[i].publicKey):
      result = false
    i = i + 1

proc copyByteStack(K: openArray[ByteSeq]): seq[ByteSeq] {.role: helper.} =
  ## K: byte rows copied so session erasure cannot alter provisioned identities.
  var
    i: int = 0
  while i < K.len:
    result.add(K[i] & @[])
    i = i + 1

proc copyIdentitySigningKeys(K: openArray[AmeIdentitySigningKey]):
    seq[AmeIdentitySigningKey] {.role: helper.} =
  ## K: public identity rows copied into independently owned storage.
  var
    i: int = 0
    key: AmeIdentitySigningKey
  while i < K.len:
    key.algorithm = K[i].algorithm
    key.publicKey = K[i].publicKey & @[]
    result.add(key)
    i = i + 1

proc identityAlgorithms(K: openArray[AmeIdentitySigningKey]):
    seq[AmeSignatureAlgorithm] {.role: parser.} =
  ## K: the algorithms a key stack covers, in slot order.
  var
    i: int = 0
  while i < K.len:
    result.add(K[i].algorithm)
    i = i + 1

proc requireIdentityLayout(L: AmeSuiteLayout, i: AmeIdentityKey) {.
    role: parser.} =
  ## L/i: immutable signature slots and matching complete private identity stack.
  var
    j: int = 0
  if i.subject.len == 0 or i.signingKeys.len != int(L.signatures.length) or
      i.secretKeys.len != int(L.signatures.length):
    raise newException(ValueError,
      "AME identity does not cover the signature layout")
  while j < int(L.signatures.length):
    if i.signingKeys[j].algorithm != L.signatures.algorithms[j] or
        i.signingKeys[j].publicKey.len == 0 or i.secretKeys[j].len == 0:
      raise newException(ValueError,
        "AME identity signing stack differs from the signature layout")
    j = j + 1

proc requireCertificateLayout(L: AmeSuiteLayout,
    c: AmeIdentityCertificate) {.role: parser.} =
  ## L/c: immutable signature slots and certified complete public-key stack.
  var
    i: int = 0
  if c.signingKeys.len != int(L.signatures.length):
    raise newException(ValueError,
      "AME certificate does not cover the signature layout")
  while i < int(L.signatures.length):
    if c.signingKeys[i].algorithm != L.signatures.algorithms[i] or
        c.signingKeys[i].publicKey.len == 0:
      raise newException(ValueError,
        "AME certificate signing stack differs from the signature layout")
    i = i + 1

proc selectedIdentitySecretKeys(L: AmeSuiteLayout, t: AmeMaskTier,
    i: AmeIdentityKey): seq[ByteSeq] {.role: parser.} =
  ## L/t/i: active tier slots selected from the complete private identity stack.
  var
    j: int = 0
  requireIdentityLayout(L, i)
  validateAmeTier(L, t)
  while j < int(L.signatures.length):
    if algorithmSlotSelected(t.masks.signature, j):
      result.add(i.secretKeys[j])
    j = j + 1

proc selectedCertificatePublicKeys(L: AmeSuiteLayout, t: AmeMaskTier,
    c: AmeIdentityCertificate): seq[ByteSeq] {.role: parser.} =
  ## L/t/c: active tier slots selected from the certified public identity stack.
  var
    i: int = 0
  requireCertificateLayout(L, c)
  validateAmeTier(L, t)
  while i < int(L.signatures.length):
    if algorithmSlotSelected(t.masks.signature, i):
      result.add(c.signingKeys[i].publicKey)
    i = i + 1

proc signIdentityStack(L: AmeSuiteLayout, t: AmeMaskTier,
    msg: openArray[uint8], i: AmeIdentityKey): seq[ByteSeq] {.
    role: orchestrator.} =
  ## L/t/msg/i: canonical message signed by every active identity slot.
  result = signAmeTier(L, t, msg, selectedIdentitySecretKeys(L, t, i))

proc verifyIdentityStack(L: AmeSuiteLayout, t: AmeMaskTier,
    msg: openArray[uint8], P: openArray[ByteSeq],
    c: AmeIdentityCertificate): bool {.role: orchestrator.} =
  ## L/t/msg/P/c: all active proofs checked against certified slot keys.
  result = verifyAmeTier(L, t, msg, selectedCertificatePublicKeys(L, t, c), P)

proc certificateSubject*(c: AmeIdentityCertificate): ByteSeq {.
    role: truthBuilder.} =
  ## c: exactly the certificate fields the authority's proofs cover.
  ## Every variable-length field carries its length in front, so no two
  ## different certificates can produce the same bytes to sign.
  appendAmeLabel(result, "AME-CERTIFICATE-v3")
  result.add(ameCertificateVersion)
  appendAmeU64(result, c.serial)
  appendHandshakeString(result, c.authority)
  appendHandshakeString(result, c.subject)
  appendIdentitySigningKeys(result, c.signingKeys)
  appendHandshakeI64(result, c.validFromUnix)
  appendHandshakeI64(result, c.validUntilUnix)

## ╭⟢ building identities

proc initAmeAuthorityKey*(name: string,
    A: AmeSignatureAlgorithms): AmeAuthorityKey {.role: orchestrator.} =
  ## name/A: authority identity and the algorithm stack it signs with.
  var
    k: AmeSigKeypair
    i: int = 0
  if name.len == 0:
    raise newException(ValueError, "AME authority name must not be empty")
  if A.length == 0'u8:
    raise newException(ValueError, "AME authority needs at least one slot")
  result.name = name
  while i < int(A.length):
    k = ameSigKeypair(A.algorithms[i])
    result.signingKeys.add(AmeIdentitySigningKey(
      algorithm: A.algorithms[i], publicKey: k.publicKey))
    result.secretKeys.add(k.secretKey)
    i = i + 1

proc initAmeAuthorityKey*(name: string): AmeAuthorityKey {.
    role: orchestrator.} =
  ## name: authority using Bifrost's default hybrid signature stack.
  result = initAmeAuthorityKey(name,
    initAmeSignatureAlgorithms(defaultAmeSigSlots()))

proc initAmeAuthorityKey*(name: string, A: AmeSignatureAlgorithms,
    seeds: openArray[ByteSeq]): AmeAuthorityKey {.role: orchestrator.} =
  ## name/A/seeds: deterministic authority for provisioned setups, one seed
  ## per slot.
  var
    k: AmeSigKeypair
    i: int = 0
  if name.len == 0 or seeds.len != int(A.length):
    raise newException(ValueError,
      "AME seeded authority must provide one seed per signature slot")
  result.name = name
  while i < int(A.length):
    if seeds[i].len == 0:
      raise newException(ValueError, "AME authority seed must not be empty")
    k = ameSigKeypair(A.algorithms[i], seeds[i])
    result.signingKeys.add(AmeIdentitySigningKey(
      algorithm: A.algorithms[i], publicKey: k.publicKey))
    result.secretKeys.add(k.secretKey)
    i = i + 1

proc initAmeIdentityKey*(subject: string,
    A: AmeSignatureAlgorithms): AmeIdentityKey {.
    role: orchestrator.} =
  ## subject/A: peer identity with one independent keypair per ordered slot.
  var
    k: AmeSigKeypair
    i: int = 0
  if subject.len == 0:
    raise newException(ValueError, "AME identity subject must not be empty")
  result.subject = subject
  while i < int(A.length):
    k = ameSigKeypair(A.algorithms[i])
    result.signingKeys.add(AmeIdentitySigningKey(
      algorithm: A.algorithms[i], publicKey: k.publicKey))
    result.secretKeys.add(k.secretKey)
    i = i + 1

proc initAmeIdentityKey*(subject: string): AmeIdentityKey {.
    role: orchestrator.} =
  ## subject: peer identity using Bifrost's default Ed25519/Falcon-512 stack.
  result = initAmeIdentityKey(subject,
    initAmeSignatureAlgorithms(defaultAmeSigSlots()))

proc initAmeIdentityKey*(subject: string, A: AmeSignatureAlgorithms,
    seeds: openArray[ByteSeq]): AmeIdentityKey {.role: orchestrator.} =
  ## subject/A/seeds: deterministic key material indexed by every layout slot.
  var
    k: AmeSigKeypair
    i: int = 0
  if subject.len == 0 or seeds.len != int(A.length):
    raise newException(ValueError,
      "AME seeded identity must provide one seed per signature slot")
  result.subject = subject
  while i < int(A.length):
    if seeds[i].len == 0:
      raise newException(ValueError, "AME identity seed must not be empty")
    k = ameSigKeypair(A.algorithms[i], seeds[i])
    result.signingKeys.add(AmeIdentitySigningKey(
      algorithm: A.algorithms[i], publicKey: k.publicKey))
    result.secretKeys.add(k.secretKey)
    i = i + 1

proc pinnedPeerIdentity*(subject: string, algorithm: AmeSignatureAlgorithm,
    publicKey: openArray[uint8]): AmePinnedPeerIdentity {.role: wrapper.} =
  ## subject/algorithm/publicKey: exact peer identity pinned out of band.
  if subject.len == 0 or publicKey.len == 0:
    raise newException(ValueError, "AME pinned peer identity is incomplete")
  result.subject = subject
  result.signingKeys.add(AmeIdentitySigningKey(algorithm: algorithm,
    publicKey: @publicKey))

proc pinnedPeerIdentity*(i: AmeIdentityKey): AmePinnedPeerIdentity {.
    role: wrapper.} =
  ## i: identity whose public portion becomes an exact peer pin.
  if i.subject.len == 0 or i.signingKeys.len == 0:
    raise newException(ValueError, "AME pinned peer identity is incomplete")
  result.subject = i.subject
  result.signingKeys = copyIdentitySigningKeys(i.signingKeys)

proc pinnedIdentityDescriptor*(i: AmeIdentityKey,
    validFromUnix, validUntilUnix: int64): AmeIdentityCertificate {.
    role: truthBuilder.} =
  ## i/validFromUnix/validUntilUnix: local identity in the handshake identity
  ## block, with a real validity window. A pinned identity that never expires
  ## is a key nobody can retire without touching every peer that pinned it.
  if i.subject.len == 0 or i.signingKeys.len == 0 or
      i.signingKeys.len != i.secretKeys.len:
    raise newException(ValueError, "AME pinned local identity is incomplete")
  if validFromUnix < 0 or validUntilUnix <= validFromUnix:
    raise newException(ValueError, "AME pinned validity range is invalid")
  result.serial = 0'u64
  result.authority = ""
  result.subject = i.subject
  result.signingKeys = copyIdentitySigningKeys(i.signingKeys)
  result.validFromUnix = validFromUnix
  result.validUntilUnix = validUntilUnix

proc initAmeAuthorityRoot*(name: string,
    K: openArray[AmeIdentitySigningKey]): AmeAuthorityRoot {.role: wrapper.} =
  ## name/K: the authority a deployment pins out of band, as a full key stack.
  ## Use this rather than filling the object by hand: a root left at its
  ## default has an empty name, which would otherwise match the empty
  ## authority field of an unsigned pinned-peer descriptor.
  var
    i: int = 0
  if name.len == 0 or K.len == 0 or K.len > ameMaxAlgorithmSlots:
    raise newException(ValueError, "AME authority root name and keys are required")
  while i < K.len:
    if K[i].publicKey.len == 0:
      raise newException(ValueError, "AME authority root key is empty")
    i = i + 1
  result.authority = name
  result.signingKeys = copyIdentitySigningKeys(K)

proc initAmeAuthorityRoot*(a: AmeAuthorityKey): AmeAuthorityRoot {.
    role: wrapper.} =
  ## a: signing authority reduced to its public pinning material.
  result = initAmeAuthorityRoot(a.name, a.signingKeys)

proc issueAmeIdentityCertificate*(a: AmeAuthorityKey, i: AmeIdentityKey,
    serial: uint64, validFromUnix, validUntilUnix: int64):
    AmeIdentityCertificate {.role: orchestrator.} =
  ## a/i/serial/timestamps: signing authority, peer key, certificate serial,
  ## and inclusive validity range. Every authority slot signs.
  var
    subject: ByteSeq = @[]
    j: int = 0
  if serial == 0'u64:
    raise newException(ValueError, "AME certificate serial must be positive")
  if validFromUnix < 0 or validUntilUnix <= validFromUnix:
    raise newException(ValueError, "AME certificate validity range is invalid")
  if a.signingKeys.len == 0 or a.signingKeys.len != a.secretKeys.len:
    raise newException(ValueError, "AME authority key stack is incomplete")
  result.serial = serial
  result.authority = a.name
  result.subject = i.subject
  result.signingKeys = copyIdentitySigningKeys(i.signingKeys)
  result.validFromUnix = validFromUnix
  result.validUntilUnix = validUntilUnix
  subject = certificateSubject(result)
  while j < a.signingKeys.len:
    result.authorityProofs.add(signAmeMessage(a.signingKeys[j].algorithm,
      subject, a.secretKeys[j]))
    j = j + 1

## ╭⟢ judging identities

proc clockIsUsable(nowUnix, validFromUnix, validUntilUnix: int64): bool {.
    role: parser.} =
  ## nowUnix/validFromUnix/validUntilUnix: refuse to judge a certificate with
  ## a clock that is absurdly far outside its window. A machine whose clock
  ## never got set would otherwise accept anything, or nothing, silently.
  if nowUnix <= 0:
    return false
  if nowUnix < validFromUnix - ameMaxCertificateSkewSeconds:
    return false
  if nowUnix > validUntilUnix + ameMaxCertificateSkewSeconds:
    return false
  result = true

proc validityError(c: AmeIdentityCertificate, nowUnix: int64): string {.
    role: parser.} =
  ## c/nowUnix: shared window check for certified and pinned identities.
  if c.validUntilUnix <= c.validFromUnix:
    return "identity validity range is invalid"
  if not clockIsUsable(nowUnix, c.validFromUnix, c.validUntilUnix):
    return "local clock is too far outside the identity validity window"
  if nowUnix < c.validFromUnix or nowUnix > c.validUntilUnix:
    return "identity is outside its validity period"

proc verifyPinnedPeerIdentity*(c: AmeIdentityCertificate,
    expected: AmePinnedPeerIdentity, nowUnix: int64): AmePeerTrustResult {.
    role: parser.} =
  ## c/expected/nowUnix: received descriptor, the locally provisioned pin, and
  ## a trusted wall clock.
  var
    err: string = ""
  if expected.subject.len == 0 or expected.signingKeys.len == 0:
    result.err = "pinned peer identity is incomplete"
    return
  if c.authority.len != 0 or c.authorityProofs.len != 0:
    result.err = "pinned peer sent a certificate instead of a direct identity"
    return
  err = validityError(c, nowUnix)
  if err.len > 0:
    result.err = err
    return
  if c.subject != expected.subject or
      not identityKeysEqual(c.signingKeys, expected.signingKeys):
    result.err = "peer identity does not match the pinned public key"
    return
  result.ok = true
  result.authority = "pinned-peer"
  result.algorithms = identityAlgorithms(c.signingKeys)
  result.subjectKeyId = c.subject
  result.serial = c.serial

proc verifyAmeIdentityCertificate*(c: AmeIdentityCertificate,
    root: AmeAuthorityRoot, nowUnix: int64,
    revokedSerials: openArray[uint64] = []): AmePeerTrustResult {.
    role: orchestrator.} =
  ## c/root/nowUnix/revokedSerials: certificate, pinned authority root,
  ## trusted wall clock, and the deployment's revocation list.
  ##
  ## Every slot the pinned root lists must produce a valid proof. A
  ## certificate that carries fewer proofs than the root has slots is refused
  ## outright, so an attacker cannot drop the post-quantum half of a hybrid
  ## authority and be judged on the classical half alone.
  var
    err: string = ""
    subject: ByteSeq = @[]
    i: int = 0
  if root.authority.len == 0 or root.signingKeys.len == 0:
    result.err = "pinned authority root is incomplete"
    return
  if c.authority.len == 0 or c.authorityProofs.len == 0:
    result.err = "certificate carries no authority proofs"
    return
  if c.authority != root.authority:
    result.err = "certificate authority does not match the pinned root"
    return
  if c.authorityProofs.len != root.signingKeys.len:
    result.err = "certificate proof count does not match the pinned root"
    return
  if c.subject.len == 0 or c.signingKeys.len == 0 or c.serial == 0'u64:
    result.err = "certificate identity is incomplete"
    return
  err = validityError(c, nowUnix)
  if err.len > 0:
    result.err = err
    return
  while i < revokedSerials.len:
    if c.serial == revokedSerials[i]:
      result.err = "certificate serial is revoked"
      return
    i = i + 1
  subject = certificateSubject(c)
  i = 0
  try:
    while i < root.signingKeys.len:
      if not verifyAmeMessage(root.signingKeys[i].algorithm, subject,
          c.authorityProofs[i], root.signingKeys[i].publicKey):
        result.err = "certificate authority proof is invalid"
        return
      i = i + 1
  except CatchableError as e:
    result.err = "certificate verification failed: " & e.msg
    return
  result.ok = true
  result.authority = c.authority
  result.algorithms = identityAlgorithms(c.signingKeys)
  result.subjectKeyId = c.subject
  result.serial = c.serial

## ╭⟢ certificate bytes
##
## One canonical encoding, used both as the thing the authority signs and as
## the thing that travels inside a sealed block. Having one form rather than
## two removes the classic trap where a value verifies in one shape and is
## read back in another.
##
##   u64 serial | u32+authority | u32+subject
##   u8 keyCount | { u8 alg, u32+publicKey } ...
##   i64 validFrom | i64 validUntil
##   u32 proofCount | { u32+proof } ...        <- 0 for a pinned identity

proc readCertU8(A: openArray[uint8], cursor: var int): uint8 {.role: parser.} =
  ## A/cursor: consume one byte.
  if cursor < 0 or cursor > A.len - 1:
    raise newException(ValueError, "AME certificate value is truncated")
  result = A[cursor]
  cursor = cursor + 1

proc readCertU32(A: openArray[uint8], cursor: var int): uint32 {.
    role: parser.} =
  ## A/cursor: consume one little-endian u32.
  if cursor < 0 or cursor > A.len - 4:
    raise newException(ValueError, "AME certificate value is truncated")
  result = uint32(A[cursor]) or (uint32(A[cursor + 1]) shl 8) or
    (uint32(A[cursor + 2]) shl 16) or (uint32(A[cursor + 3]) shl 24)
  cursor = cursor + 4

proc readCertU64(A: openArray[uint8], cursor: var int): uint64 {.
    role: parser.} =
  ## A/cursor: consume one little-endian u64.
  var
    i: int = 0
  if cursor < 0 or cursor > A.len - 8:
    raise newException(ValueError, "AME certificate value is truncated")
  while i < 8:
    result = result or (uint64(A[cursor + i]) shl (8 * i))
    i = i + 1
  cursor = cursor + 8

proc readCertField(A: openArray[uint8], cursor: var int,
    maximum: uint32): ByteSeq {.role: parser.} =
  ## A/cursor/maximum: consume one bounded length-framed field.
  var
    n: int = checkedAmeWireLen(readCertU32(A, cursor), maximum,
      "AME certificate field")
  if cursor > A.len - n:
    raise newException(ValueError, "AME certificate field is truncated")
  if n > 0:
    result = @A[cursor ..< cursor + n]
  cursor = cursor + n

proc readCertString(A: openArray[uint8], cursor: var int): string {.
    role: parser.} =
  ## A/cursor: consume one bounded identity text field.
  var
    B: ByteSeq = readCertField(A, cursor, ameHandshakeTextMax)
    i: int = 0
  result.setLen(B.len)
  while i < B.len:
    result[i] = char(B[i])
    i = i + 1

proc readBlockProofs*(A: openArray[uint8], cursor: var int): seq[ByteSeq] {.
    role: parser.} =
  ## A/cursor: consume one bounded ordered proof stack.
  var
    n: int = int(checkedAmeWireLen(readCertU32(A, cursor),
      uint32(ameMaxAlgorithmSlots), "AME proof count"))
  while result.len < n:
    result.add(readCertField(A, cursor, ameSignatureProofMax))

proc signatureAlgorithmFromByte*(v: uint8): AmeSignatureAlgorithm {.
    role: parser.} =
  ## v: stable Bifrost signature algorithm identifier.
  if int(v) < ord(low(AmeSignatureAlgorithm)) or
      int(v) > ord(high(AmeSignatureAlgorithm)):
    raise newException(ValueError, "AME certificate algorithm is invalid")
  result = AmeSignatureAlgorithm(v)

proc decodeCertificateSubject*(A: openArray[uint8],
    cursor: var int): AmeIdentityCertificate {.role: parser.} =
  ## A/cursor: consume the signed portion of one certificate. The proof stack
  ## is read separately, because the signed portion must never contain the
  ## signatures over itself.
  var
    label: ByteSeq = @[]
    count: int = 0
    key: AmeIdentitySigningKey
    i: int = 0
  label = @[]
  appendAmeLabel(label, "AME-CERTIFICATE-v3")
  if cursor < 0 or cursor > A.len - label.len - 1:
    raise newException(ValueError, "AME certificate value is truncated")
  while i < label.len:
    if A[cursor + i] != label[i]:
      raise newException(ValueError, "AME certificate identity mismatch")
    i = i + 1
  cursor = cursor + label.len
  if readCertU8(A, cursor) != ameCertificateVersion:
    raise newException(ValueError, "AME certificate version mismatch")
  result.serial = readCertU64(A, cursor)
  result.authority = readCertString(A, cursor)
  result.subject = readCertString(A, cursor)
  count = int(readCertU8(A, cursor))
  if count == 0 or count > ameMaxAlgorithmSlots:
    raise newException(ValueError, "AME certificate signing-key count is invalid")
  while result.signingKeys.len < count:
    key.algorithm = signatureAlgorithmFromByte(readCertU8(A, cursor))
    key.publicKey = readCertField(A, cursor, ameIdentityKeyMax)
    if key.publicKey.len == 0:
      raise newException(ValueError, "AME certificate signing key is empty")
    result.signingKeys.add(key)
  result.validFromUnix = cast[int64](readCertU64(A, cursor))
  result.validUntilUnix = cast[int64](readCertU64(A, cursor))

proc encodeAmeIdentityCertificate*(c: AmeIdentityCertificate): ByteSeq {.
    role: stateController, tag: {tagAppApi, tagCodecBoundary}.} =
  ## c: authority certificate or unsigned pinned identity descriptor.
  var
    certificateShape: bool = c.authority.len > 0 and
      c.authorityProofs.len > 0 and c.serial > 0'u64
    pinnedShape: bool = c.authority.len == 0 and
      c.authorityProofs.len == 0 and c.serial == 0'u64
  if c.subject.len == 0 or c.signingKeys.len == 0 or
      c.validUntilUnix <= c.validFromUnix or c.validFromUnix < 0 or
      not (certificateShape or pinnedShape):
    raise newException(ValueError, "AME certificate is incomplete")
  result = certificateSubject(c)
  appendHandshakeProofs(result, c.authorityProofs)

proc decodeAmeIdentityCertificate*(A: openArray[uint8]):
    AmeIdentityCertificate {.role: parser,
    tag: {tagAppApi, tagCodecBoundary, tagParsing}.} =
  ## A: complete bounded certificate or pinned identity descriptor bytes.
  var
    cursor: int = 0
    certificateShape: bool = false
    pinnedShape: bool = false
  result = decodeCertificateSubject(A, cursor)
  result.authorityProofs = readBlockProofs(A, cursor)
  certificateShape = result.authority.len > 0 and
    result.authorityProofs.len > 0 and result.serial > 0'u64
  pinnedShape = result.authority.len == 0 and
    result.authorityProofs.len == 0 and result.serial == 0'u64
  if cursor != A.len or result.subject.len == 0 or
      result.signingKeys.len == 0 or
      result.validUntilUnix <= result.validFromUnix or
      result.validFromUnix < 0 or
      not (certificateShape or pinnedShape):
    raise newException(ValueError, "AME certificate wire value is invalid")

## ╭⟢ the transcript
##
## Everything each side signs, and everything the temporary keys are derived
## from, is a running record of exactly what was said. Both sides build it the
## same way from the same bytes. If any field differed -- a swapped nonce, an
## edited slot layout, a downgraded tier -- the two records diverge and every
## later check fails at once.

proc clientHelloSubject*(h: AmeClientHello): ByteSeq {.role: truthBuilder.} =
  ## h: the client hello as the transcript records it.
  appendAmeLabel(result, "AME-CLIENT-HELLO-v4")
  appendAmeU64(result, h.sessionId)
  appendHandshakeBytes(result, h.nonce)
  appendHandshakeBytes(result, encodeAmeSuiteLayout(h.layout))
  appendHandshakeBytes(result, encodeAmeMaskTier(h.initialTier))
  appendHandshakeBytes(result, h.cookie)
  appendHandshakeBytes(result, encodeAmeExchangeOffer(h.offer))

proc serverHelloClearSubject*(c: AmeClientHello,
    s: AmeServerHello): ByteSeq {.role: truthBuilder.} =
  ## c/s: client hello plus the part of the server hello that travels in the
  ## clear. This is what the temporary keys are derived from, so it can only
  ## contain fields both sides hold before those keys exist.
  appendAmeLabel(result, "AME-SERVER-HELLO-CLEAR-v4")
  appendHandshakeBytes(result, clientHelloSubject(c))
  appendHandshakeBytes(result, s.nonce)
  appendHandshakeBytes(result, encodeAmeExchangeReply(s.reply))
  result.add(uint8(ord(s.params.authTagLen)))
  result.add(uint8(ord(s.params.padding)))

proc serverHelloFullSubject*(c: AmeClientHello,
    s: AmeServerHello): ByteSeq {.role: truthBuilder.} =
  ## c/s: the whole server hello, sealed block included.
  appendAmeLabel(result, "AME-SERVER-HELLO-FULL-v4")
  appendHandshakeBytes(result, serverHelloClearSubject(c, s))
  appendHandshakeBytes(result, s.authTag)
  appendHandshakeBytes(result, s.sealed)

proc handshakeTranscript*(c: AmeClientHello,
    s: AmeServerHello): ByteSeq {.role: truthBuilder.} =
  ## c/s: both complete hello messages.
  appendAmeLabel(result, "AME-HANDSHAKE-TRANSCRIPT-v4")
  appendHandshakeBytes(result, serverHelloFullSubject(c, s))

## ╭⟢ the temporary keys
##
## These protect the two sealed blocks and nothing else. They come from the
## KEM secrets and from the transcript so far, so a peer that answered a
## different hello derives different keys and its block simply will not open.

proc handshakeKeyMaterial(L: AmeSuiteLayout, t: AmeMaskTier,
    S: openArray[ByteSeq], transcript: openArray[uint8],
    label: string): ByteSeq {.role: truthBuilder,
    tag: {tagCryptoBoundary, tagKdf}.} =
  ## L/t/S/transcript/label: slot selection, every KEM secret, the transcript
  ## so far, and which direction this key block is for.
  var
    info: ByteSeq = @[]
    seed: ByteSeq = @[]
  appendAmeLabel(info, label)
  appendHandshakeBytes(info, encodeAmeSuiteLayout(L))
  appendHandshakeBytes(info, encodeAmeMaskTier(t))
  appendHandshakeBytes(info, transcript)
  appendAmeLabel(seed, "AME-HANDSHAKE-SECRETS-v1")
  result = deriveGb3HkdfInputs(seed, S, info,
    ameTierKeyMaterialLen(L, t), initGb3KdfConfig())
  secureClearAmeBytes(info)
  secureClearAmeBytes(seed)

proc secretRows(A: AmeKemAlgorithms, mask: uint8,
    S: openArray[ByteSeq]): seq[ByteSeq] {.role: truthBuilder,
    tag: {tagCryptoBoundary}.} =
  ## A/mask/S: shared secrets framed with the slot and algorithm they came
  ## from, so two different slot orders can never hash to the same input.
  var
    i: int = 0
    used: int = 0
    row: ByteSeq = @[]
  while i < int(A.length):
    if algorithmSlotSelected(mask, i):
      if used >= S.len or S[used].len == 0:
        raise newException(ValueError, "AME handshake is missing a KEM secret")
      row = @[]
      row.add(uint8(i))
      row.add(uint8(ord(A.algorithms[i])))
      appendHandshakeBytes(row, S[used])
      result.add(row)
      used = used + 1
    i = i + 1
  if used != S.len:
    raise newException(ValueError, "AME handshake KEM secret count mismatch")

proc clearSecretRows(S: var seq[ByteSeq]) {.role: stateController.} =
  ## S: framed secret rows erased once they have been consumed.
  var
    i: int = 0
  while i < S.len:
    secureClearAmeBytes(S[i])
    i = i + 1
  S.setLen(0)

## ╭⟢ the anti-flood cookie

proc initAmeCookieSecret*(): AmeCookieSecret {.role: dataFetcher.} =
  ## A fresh server-side secret. Never leaves the machine, never goes on the
  ## wire; only tags computed with it do.
  result.key = tyr_random.cryptoRand(tyr_alg.raSystem, ameCookieSecretLen)

proc cookieSubject(peerId: openArray[uint8], issuedAtUnix: int64,
    h: AmeClientHello): ByteSeq {.role: truthBuilder.} =
  ## peerId/issuedAtUnix/h: the caller's stable name for the remote address,
  ## when the cookie was minted, and the hello it belongs to.
  appendAmeLabel(result, "AME-COOKIE-v1")
  appendHandshakeBytes(result, peerId)
  appendHandshakeI64(result, issuedAtUnix)
  appendAmeU64(result, h.sessionId)
  appendHandshakeBytes(result, h.nonce)

proc issueAmeCookie*(secret: AmeCookieSecret, peerId: openArray[uint8],
    nowUnix: int64, h: AmeClientHello): ByteSeq {.role: truthBuilder,
    tag: {tagAppApi, tagCryptoBoundary}.} =
  ## secret/peerId/nowUnix/h: mint one cookie. It is a timestamp followed by a
  ## tag over that timestamp and the sender's address, so the server keeps no
  ## per-client state at all -- it recomputes the tag when the cookie returns.
  var
    subject: ByteSeq = @[]
  if secret.key.len != ameCookieSecretLen:
    raise newException(ValueError, "AME cookie secret is missing")
  subject = cookieSubject(peerId, nowUnix, h)
  appendHandshakeI64(result, nowUnix)
  appendAmeBytes(result, ameMacTag(amaBlake3, secret.key, subject, 32))
  secureClearAmeBytes(subject)

proc ameCookieValid*(secret: AmeCookieSecret, peerId: openArray[uint8],
    nowUnix: int64, h: AmeClientHello): bool {.role: parser,
    tag: {tagAppApi, tagCryptoBoundary, tagValidation}.} =
  ## secret/peerId/nowUnix/h: check the cookie the hello carries.
  var
    issuedAtUnix: int64 = 0'i64
    subject: ByteSeq = @[]
    expected: ByteSeq = @[]
    i: int = 0
  if secret.key.len != ameCookieSecretLen or h.cookie.len != 40:
    return
  while i < 8:
    issuedAtUnix = issuedAtUnix or
      cast[int64](uint64(h.cookie[i]) shl (8 * i))
    i = i + 1
  if nowUnix < issuedAtUnix or
      nowUnix - issuedAtUnix > ameCookieLifetimeSeconds:
    return
  subject = cookieSubject(peerId, issuedAtUnix, h)
  expected = ameMacTag(amaBlake3, secret.key, subject, 32)
  result = constantTimeEqualAme(expected, h.cookie[8 .. 39])
  secureClearAmeBytes(subject)
  secureClearAmeBytes(expected)

## ╭⟢ step 1: the client speaks

proc beginAmeHandshake*(sessionId: uint64, L: AmeSuiteLayout,
    initialTier: AmeMaskTier, requestId: uint32 = 1'u32,
    cookie: openArray[uint8] = []): AmeClientHandshake {.
    role: orchestrator, tag: {tagAppApi, tagExchange}.} =
  ## sessionId/L/initialTier/requestId/cookie: client inputs. The hello names
  ## no identity at all -- that waits until there is a key to hide it under.
  ##
  ## `cookie` is empty the first time. If the server asks for one, call this
  ## again with the same session id and the cookie it sent back.
  var
    request: AmeExchangeRequest
    keys: AmeExchangeKeys
  if sessionId == 0'u64:
    raise newException(ValueError, "AME client session id must be positive")
  validateAmeTier(L, initialTier)
  request = initAmeExchangeRequest(L.kems, initialTier, initialTier.masks.kem)
  keys = generateAmeExchangeKeys(L.kems, request)
  result.hello.sessionId = sessionId
  result.hello.nonce = tyr_random.cryptoRand(tyr_alg.raSystem,
    ameHandshakeNonceLen)
  result.hello.layout = L
  result.hello.initialTier = initialTier
  result.hello.cookie = @cookie
  result.hello.offer = initAmeExchangeOffer(requestId, 0'u32, request,
    keys.publicKeys)
  result.secretKeys = keys.secretKeys

proc clientHelloPolicyError*(c: AmeClientHello,
    supported: openArray[AmeTierPath]): string {.role: parser.} =
  ## c/supported: cheap shape and exact-policy checks. Everything here is
  ## arithmetic on fields the hello already carries -- no key work at all, so
  ## a flood of nonsense costs the server almost nothing.
  var
    layoutSupported: bool = false
    i: int = 0
  while i < supported.len:
    if layoutsEquivalent(c.layout, supported[i].layout) and
        ameTierPathContains(supported[i], c.initialTier):
      layoutSupported = true
    i = i + 1
  if not layoutSupported:
    return "client exact AME layout and initial tier are not supported"
  if c.sessionId == 0'u64 or c.nonce.len != ameHandshakeNonceLen or
      c.offer.baseEpochId != 0'u32:
    return "client hello shape is invalid"
  try:
    validateAmeTier(c.layout, c.initialTier)
    if not tiersEquivalent(c.offer.request.targetTier, c.initialTier) or
        c.offer.request.exchangeMask != c.initialTier.masks.kem or
        c.offer.signatures.len != 0:
      return "client hello initial tier exchange is invalid"
  except ValueError as e:
    return e.msg

## ╭⟢ step 2: the server answers

proc buildServerHello(S: var AmeServerHandshake, identity: AmeIdentityKey,
    descriptor: AmeIdentityCertificate,
    params: AmeRuntimeParams): string {.role: orchestrator,
    tag: {tagCryptoBoundary, tagExchange}.} =
  ## S/identity/descriptor/params: encapsulate, derive the temporary key, and
  ## seal the server's identity under it. Returns an error string, or "".
  var
    answer: tuple[reply: AmeExchangeReply, sharedSecrets: seq[ByteSeq]]
    clear: ByteSeq = @[]
    rows: seq[ByteSeq] = @[]
    material: ByteSeq = @[]
    block1: ByteSeq = @[]
    sealed: tuple[ciphertext: ByteSeq, authTag: ByteSeq]
    proofs: seq[ByteSeq] = @[]
    c: AmeClientHello = S.clientHello
  answer = answerAmeExchangeOffer(c.layout.kems, c.offer)
  S.sharedSecrets = answer.sharedSecrets
  S.serverHello.nonce = tyr_random.cryptoRand(tyr_alg.raSystem,
    ameHandshakeNonceLen)
  S.serverHello.reply = answer.reply
  S.serverHello.params = params
  clear = serverHelloClearSubject(c, S.serverHello)
  ## The server signs the transcript BEFORE its identity is sealed, so the
  ## proof covers what the client will independently rebuild, not the
  ## ciphertext the client has not opened yet.
  proofs = signIdentityStack(c.layout, c.initialTier, clear, identity)
  ## What the sealed block holds, in order:
  ##
  ##   certificate body   (self-delimiting, NOT length-framed -- it starts
  ##                       with its own label and every field inside it
  ##                       carries a length)
  ##   authority proofs   u32 count, then u32-framed proofs
  ##   transcript proofs  u32 count, then u32-framed proofs
  ##
  ## The certificate body goes in raw because it is the exact byte string the
  ## authority signed. Wrapping it in another length would mean the bytes
  ## verified and the bytes stored were not the same thing.
  block1 = @[]
  appendAmeBytes(block1, certificateSubject(descriptor))
  appendHandshakeProofs(block1, descriptor.authorityProofs)
  appendHandshakeProofs(block1, proofs)
  ## Padded under the same policy the epoch will use, when there is one. A
  ## certificate's length is a fingerprint of its own -- how many algorithms
  ## it names, how long the subject is -- and hiding the identity while
  ## leaving its size on the wire only does half the job.
  block1 = padAmeMessage(block1, params.padding)
  try:
    rows = secretRows(c.layout.kems, c.initialTier.masks.kem, S.sharedSecrets)
    material = handshakeKeyMaterial(c.layout, c.initialTier, rows, clear,
      "AME-HANDSHAKE-S2C-v1")
    sealed = sealAmeTier(c.layout, c.initialTier, material, block1, clear,
      params.authTagLen)
    S.serverHello.sealed = sealed.ciphertext
    S.serverHello.authTag = sealed.authTag
  except CatchableError as e:
    result = "server hello sealing failed: " & e.msg
  clearSecretRows(rows)
  secureClearAmeBytes(material)
  secureClearAmeBytes(block1)
  secureClearAmeBytes(clear)

proc answerAmeHandshake*(c: AmeClientHello,
    supported: openArray[AmeTierPath],
    descriptor: AmeIdentityCertificate, identity: AmeIdentityKey,
    params: AmeRuntimeParams = AmeRuntimeParams(authTagLen: aatl32)): tuple[
    ok: bool, state: AmeServerHandshake, err: string] {.role: orchestrator,
    tag: {tagAppApi, tagExchange}.} =
  ## c/supported/descriptor/identity/params: responder inputs. `params` are
  ## the tunables the responder imposes on the first epoch -- tag length and
  ## whether payloads are padded. The client adopts them or gives up.
  ##
  ## The client is NOT authenticated yet at this point and cannot be -- it has
  ## not said who it is. Anti-flood protection is the cookie, checked by the
  ## caller before this runs; identity checking happens at the finish.
  var
    policyError: string = clientHelloPolicyError(c, supported)
    sealError: string = ""
  if policyError.len > 0:
    result.err = policyError
    return
  if descriptor.subject != identity.subject or
      not identityKeysEqual(descriptor.signingKeys, identity.signingKeys):
    result.err = "server identity does not match its handshake descriptor"
    return
  try:
    requireIdentityLayout(c.layout, identity)
    requireCertificateLayout(c.layout, descriptor)
  except ValueError as e:
    result.err = e.msg
    return
  result.state.clientHello = c
  sealError = buildServerHello(result.state, identity, descriptor, params)
  if sealError.len > 0:
    result.err = sealError
    return
  result.state.localSignatureSecretKeys = copyByteStack(identity.secretKeys)
  result.ok = true

## ╭⟢ step 3: the client opens the answer and finishes

proc openServerIdentity(S: AmeClientHandshake, h: AmeServerHello,
    secrets: openArray[ByteSeq]): tuple[ok: bool,
    identityBlock: AmeServerIdentityBlock, err: string] {.role: orchestrator,
    tag: {tagCryptoBoundary, tagExchange}.} =
  ## S/h/secrets: unseal the server's identity with the temporary key.
  var
    clear: ByteSeq = serverHelloClearSubject(S.hello, h)
    rows: seq[ByteSeq] = @[]
    material: ByteSeq = @[]
    opened: tuple[ok: bool, payload: ByteSeq]
    cursor: int = 0
  try:
    rows = secretRows(S.hello.layout.kems, S.hello.initialTier.masks.kem,
      secrets)
    material = handshakeKeyMaterial(S.hello.layout, S.hello.initialTier, rows,
      clear, "AME-HANDSHAKE-S2C-v1")
    opened = openAmeTier(S.hello.layout, S.hello.initialTier, material,
      h.sealed, h.authTag, clear, h.params.authTagLen)
  except CatchableError as e:
    clearSecretRows(rows)
    secureClearAmeBytes(material)
    secureClearAmeBytes(clear)
    result.err = "server identity could not be opened: " & e.msg
    return
  clearSecretRows(rows)
  secureClearAmeBytes(material)
  secureClearAmeBytes(clear)
  if not opened.ok:
    result.err = "server identity block failed authentication"
    return
  result.err = "server identity block is malformed"
  try:
    opened.payload = unpadAmeMessage(opened.payload, h.params.padding)
    result.identityBlock.certificate = decodeCertificateSubject(opened.payload,
      cursor)
    result.identityBlock.certificate.authorityProofs = readBlockProofs(
      opened.payload, cursor)
    result.identityBlock.proofs = readBlockProofs(opened.payload, cursor)
    if cursor != opened.payload.len:
      return
  except ValueError:
    return
  result.err = ""
  result.ok = true

proc buildInitialAuth(L: AmeSuiteLayout, initialTier: AmeMaskTier,
    request: AmeExchangeRequest,
    sharedSecrets: openArray[ByteSeq], transcript: openArray[uint8],
    sessionId: uint64, endpointRole: AmeEndpointRole,
    params: AmeRuntimeParams): AmeAuthPackage {.role: truthBuilder.} =
  ## L/tier/request/secrets/transcript/session/role/params: the first epoch.
  ## The transcript hash becomes the salt every later key hangs off, so two
  ## handshakes that agreed different things can never share a key.
  var
    exchange: AmeExchangeState = initAmeExchangeState(L.kems)
  applyAmeExchange(exchange, request, sharedSecrets)
  result = initAmeAuthPackage(L, initialTier, exchange,
    hashAmeTier(L, initialTier, transcript, 32), 1'u32, sessionId,
    endpointRole, params)

proc serverHelloPolicyError(S: AmeClientHandshake,
    h: AmeServerHello): string {.role: parser.} =
  ## S/h: cheap responder shape checks before any key work.
  try:
    if h.nonce.len != ameHandshakeNonceLen or h.reply.signatures.len != 0 or
        h.reply.requestId == 0'u32 or
        h.authTag.len != int(ord(h.params.authTagLen)) or h.sealed.len == 0:
      return "server hello shape is invalid"
    discard encodeAmeExchangeReplySubject(S.hello.offer, h.reply)
  except ValueError as e:
    return e.msg

proc sealClientIdentity(S: AmeClientHandshake, h: AmeServerHello,
    secrets: openArray[ByteSeq], descriptor: AmeIdentityCertificate,
    identity: AmeIdentityKey, transcript: openArray[uint8]): tuple[
    ok: bool, finish: AmeClientFinish, err: string] {.role: orchestrator,
    tag: {tagCryptoBoundary, tagExchange}.} =
  ## S/h/secrets/descriptor/identity/transcript: seal the client's identity and
  ## its proof of the whole exchange under the client-to-server temporary key.
  var
    full: ByteSeq = serverHelloFullSubject(S.hello, h)
    rows: seq[ByteSeq] = @[]
    material: ByteSeq = @[]
    body: ByteSeq = @[]
    proofs: seq[ByteSeq] = @[]
    transcriptHash: ByteSeq = @[]
    sealed: tuple[ciphertext: ByteSeq, authTag: ByteSeq]
  transcriptHash = hashAmeTier(S.hello.layout, S.hello.initialTier,
    transcript, 32)
  proofs = signIdentityStack(S.hello.layout, S.hello.initialTier,
    transcriptHash, identity)
  appendAmeBytes(body, certificateSubject(descriptor))
  appendHandshakeProofs(body, descriptor.authorityProofs)
  appendHandshakeBytes(body, transcriptHash)
  appendHandshakeProofs(body, proofs)
  body = padAmeMessage(body, h.params.padding)
  try:
    rows = secretRows(S.hello.layout.kems, S.hello.initialTier.masks.kem,
      secrets)
    material = handshakeKeyMaterial(S.hello.layout, S.hello.initialTier, rows,
      full, "AME-HANDSHAKE-C2S-v1")
    sealed = sealAmeTier(S.hello.layout, S.hello.initialTier, material, body,
      full, h.params.authTagLen)
    result.finish.params = h.params
    result.finish.sealed = sealed.ciphertext
    result.finish.authTag = sealed.authTag
    result.ok = true
  except CatchableError as e:
    result.err = "client finish sealing failed: " & e.msg
  clearSecretRows(rows)
  secureClearAmeBytes(material)
  secureClearAmeBytes(body)
  secureClearAmeBytes(full)

proc finishAmeHandshakeCore(S: AmeClientHandshake, h: AmeServerHello,
    descriptor: AmeIdentityCertificate, identity: AmeIdentityKey,
    trustMode: AmeTrustMode, root: AmeAuthorityRoot,
    expectedPeer: AmePinnedPeerIdentity, nowUnix: int64,
    revokedSerials: openArray[uint64]): AmeHandshakeResult {.
    role: orchestrator.} =
  ## S/h/descriptor/identity/trustMode/root/expectedPeer/nowUnix/revoked:
  ## open the server's identity, judge it, then answer with our own.
  var
    policyError: string = serverHelloPolicyError(S, h)
    secrets: seq[ByteSeq] = @[]
    identityBlock: tuple[ok: bool, identityBlock: AmeServerIdentityBlock,
      err: string]
    transcript: ByteSeq = @[]
    clear: ByteSeq = @[]
    finish: tuple[ok: bool, finish: AmeClientFinish, err: string]
    key: AmeIdentitySigningKey
  if policyError.len > 0:
    result.err = policyError
    return
  try:
    secrets = openAmeExchangeReply(S.hello.layout.kems, S.hello.offer,
      h.reply, S.secretKeys)
  except CatchableError as e:
    result.err = "server hello exchange failed: " & e.msg
    return
  identityBlock = openServerIdentity(S, h, secrets)
  if not identityBlock.ok:
    result.err = identityBlock.err
    return
  try:
    requireCertificateLayout(S.hello.layout, identityBlock.identityBlock.certificate)
  except ValueError as e:
    result.err = e.msg
    return
  if trustMode == atmAuthorityCertificate:
    result.peerTrust = verifyAmeIdentityCertificate(
      identityBlock.identityBlock.certificate, root, nowUnix, revokedSerials)
  else:
    result.peerTrust = verifyPinnedPeerIdentity(
      identityBlock.identityBlock.certificate, expectedPeer, nowUnix)
  if not result.peerTrust.ok:
    result.err = result.peerTrust.err
    return
  clear = serverHelloClearSubject(S.hello, h)
  try:
    if not verifyIdentityStack(S.hello.layout, S.hello.initialTier, clear,
        identityBlock.identityBlock.proofs,
        identityBlock.identityBlock.certificate):
      result.err = "server hello identity proof is invalid"
      return
  except CatchableError as e:
    result.err = "server hello proof failed: " & e.msg
    return
  finally:
    secureClearAmeBytes(clear)
  transcript = handshakeTranscript(S.hello, h)
  finish = sealClientIdentity(S, h, secrets, descriptor, identity, transcript)
  if not finish.ok:
    result.err = finish.err
    return
  result.finish = finish.finish
  result.auth = buildInitialAuth(S.hello.layout, S.hello.initialTier,
    h.reply.request, secrets, transcript, S.hello.sessionId, aerInitiator,
    h.params)
  result.auth.localSignatureSecretKeys = copyByteStack(identity.secretKeys)
  for key in identityBlock.identityBlock.certificate.signingKeys:
    result.auth.peerSignaturePublicKeys.add(key.publicKey & @[])
  result.ok = true

## ╭⟢ step 4: the server opens the finish

proc acceptAmeHandshakeCore(S: AmeServerHandshake, f: AmeClientFinish,
    trustMode: AmeTrustMode, root: AmeAuthorityRoot,
    expectedPeer: AmePinnedPeerIdentity, nowUnix: int64,
    revokedSerials: openArray[uint64]): AmeHandshakeResult {.
    role: orchestrator.} =
  ## S/f/trustMode/root/expectedPeer/nowUnix/revoked: responder state and the
  ## client's sealed confirmation.
  ##
  ## Only here does the server learn who the client is. Nothing before this
  ## point produced a session, so a peer that cannot open this block, or whose
  ## identity does not check out, leaves no trace but a dropped connection.
  var
    full: ByteSeq = @[]
    rows: seq[ByteSeq] = @[]
    material: ByteSeq = @[]
    opened: tuple[ok: bool, payload: ByteSeq]
    body: AmeClientIdentityBlock
    cursor: int = 0
    transcript: ByteSeq = @[]
    expected: ByteSeq = @[]
    key: AmeIdentitySigningKey
  if f.authTag.len != int(ord(S.serverHello.params.authTagLen)) or
      f.params != S.serverHello.params or f.sealed.len == 0:
    result.err = "client finish shape is invalid"
    return
  full = serverHelloFullSubject(S.clientHello, S.serverHello)
  try:
    rows = secretRows(S.clientHello.layout.kems,
      S.clientHello.initialTier.masks.kem, S.sharedSecrets)
    material = handshakeKeyMaterial(S.clientHello.layout,
      S.clientHello.initialTier, rows, full, "AME-HANDSHAKE-C2S-v1")
    opened = openAmeTier(S.clientHello.layout, S.clientHello.initialTier,
      material, f.sealed, f.authTag, full, f.params.authTagLen)
  except CatchableError as e:
    clearSecretRows(rows)
    secureClearAmeBytes(material)
    secureClearAmeBytes(full)
    result.err = "client finish could not be opened: " & e.msg
    return
  clearSecretRows(rows)
  secureClearAmeBytes(material)
  secureClearAmeBytes(full)
  if not opened.ok:
    result.err = "client finish failed authentication"
    return
  try:
    opened.payload = unpadAmeMessage(opened.payload, f.params.padding)
    body.certificate = decodeCertificateSubject(opened.payload, cursor)
    body.certificate.authorityProofs = readBlockProofs(opened.payload, cursor)
    body.transcriptHash = readCertField(opened.payload, cursor, 1024'u32)
    body.proofs = readBlockProofs(opened.payload, cursor)
    if cursor != opened.payload.len:
      result.err = "client finish block is malformed"
      return
    requireCertificateLayout(S.clientHello.layout, body.certificate)
  except ValueError as e:
    result.err = "client finish block is malformed: " & e.msg
    return
  if trustMode == atmAuthorityCertificate:
    result.peerTrust = verifyAmeIdentityCertificate(body.certificate, root,
      nowUnix, revokedSerials)
  else:
    result.peerTrust = verifyPinnedPeerIdentity(body.certificate,
      expectedPeer, nowUnix)
  if not result.peerTrust.ok:
    result.err = result.peerTrust.err
    return
  transcript = handshakeTranscript(S.clientHello, S.serverHello)
  expected = hashAmeTier(S.clientHello.layout, S.clientHello.initialTier,
    transcript, 32)
  if not constantTimeEqualAme(body.transcriptHash, expected):
    result.err = "client finish transcript does not match"
    return
  try:
    if not verifyIdentityStack(S.clientHello.layout,
        S.clientHello.initialTier, body.transcriptHash, body.proofs,
        body.certificate):
      result.err = "client finish identity proof is invalid"
      return
  except CatchableError as e:
    result.err = "client finish verification failed: " & e.msg
    return
  result.auth = buildInitialAuth(S.clientHello.layout,
    S.clientHello.initialTier, S.serverHello.reply.request,
    S.sharedSecrets, transcript, S.clientHello.sessionId, aerResponder,
    S.serverHello.params)
  result.auth.localSignatureSecretKeys = copyByteStack(
    S.localSignatureSecretKeys)
  for key in body.certificate.signingKeys:
    result.auth.peerSignaturePublicKeys.add(key.publicKey & @[])
  result.ok = true

## ╭⟢ erasing what is finished with

proc clearAmeClientHandshake*(S: var AmeClientHandshake) {.
    role: stateController.} =
  ## S: initial KEM private keys and retained public handshake state to erase.
  var
    i: int = 0
  while i < S.secretKeys.len:
    secureClearAmeBytes(S.secretKeys[i])
    i = i + 1
  S = default(AmeClientHandshake)

proc clearAmeServerHandshake*(S: var AmeServerHandshake) {.
    role: stateController.} =
  ## S: initial shared secrets and copied local identity keys to erase.
  var
    i: int = 0
  while i < S.sharedSecrets.len:
    secureClearAmeBytes(S.sharedSecrets[i])
    i = i + 1
  i = 0
  while i < S.localSignatureSecretKeys.len:
    secureClearAmeBytes(S.localSignatureSecretKeys[i])
    i = i + 1
  S = default(AmeServerHandshake)

## ╭⟢ the four calls a caller actually makes

proc finishAmeHandshake*(S: var AmeClientHandshake, h: AmeServerHello,
    root: AmeAuthorityRoot, descriptor: AmeIdentityCertificate,
    identity: AmeIdentityKey, nowUnix: int64,
    revokedSerials: openArray[uint64] = []): AmeHandshakeResult {.
    role: orchestrator, tag: {tagAppApi}.} =
  ## S/h/root/descriptor/identity/nowUnix/revoked: certificate-mode finish.
  ## The client's KEM secrets are erased whatever the outcome.
  try:
    result = finishAmeHandshakeCore(S, h, descriptor, identity,
      atmAuthorityCertificate, root, default(AmePinnedPeerIdentity), nowUnix,
      revokedSerials)
  finally:
    clearAmeClientHandshake(S)

proc finishAmePinnedHandshake*(S: var AmeClientHandshake, h: AmeServerHello,
    expectedPeer: AmePinnedPeerIdentity,
    descriptor: AmeIdentityCertificate, identity: AmeIdentityKey,
    nowUnix: int64): AmeHandshakeResult {.role: orchestrator,
    tag: {tagAppApi}.} =
  ## S/h/expectedPeer/descriptor/identity/nowUnix: pinned-mode finish.
  try:
    result = finishAmeHandshakeCore(S, h, descriptor, identity,
      atmPinnedPeerKey, default(AmeAuthorityRoot), expectedPeer, nowUnix, [])
  finally:
    clearAmeClientHandshake(S)

proc acceptAmeHandshake*(S: var AmeServerHandshake, f: AmeClientFinish,
    root: AmeAuthorityRoot, nowUnix: int64,
    revokedSerials: openArray[uint64] = []): AmeHandshakeResult {.
    role: orchestrator, tag: {tagAppApi}.} =
  ## S/f/root/nowUnix/revoked: certificate-mode accept.
  try:
    result = acceptAmeHandshakeCore(S, f, atmAuthorityCertificate, root,
      default(AmePinnedPeerIdentity), nowUnix, revokedSerials)
  finally:
    clearAmeServerHandshake(S)

proc acceptAmePinnedHandshake*(S: var AmeServerHandshake, f: AmeClientFinish,
    expectedPeer: AmePinnedPeerIdentity,
    nowUnix: int64): AmeHandshakeResult {.role: orchestrator,
    tag: {tagAppApi}.} =
  ## S/f/expectedPeer/nowUnix: pinned-mode accept.
  try:
    result = acceptAmeHandshakeCore(S, f, atmPinnedPeerKey,
      default(AmeAuthorityRoot), expectedPeer, nowUnix, [])
  finally:
    clearAmeServerHandshake(S)
