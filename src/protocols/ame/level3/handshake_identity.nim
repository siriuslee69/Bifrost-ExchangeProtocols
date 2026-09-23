## -------------------------------------------------------------------------
## AME Handshake Identity <- who someone is, and whether you believe them
## -------------------------------------------------------------------------
##
## This file answers one question and stops: **do I believe this peer is who
## it says it is?** Nothing here knows the handshake exists. It is about
## identities, and it is equally usable before, during, or long after one.
##
## WHICH of these a connection demands -- the four modes and the one
## `AmeAuthentication` object -- lives next door in
## `handshake_authentication.nim`.
##
## ╭─ ❧ why the keys are a STACK ⟡
##
## An identity is not one signing key, it is several -- one per switched-on
## signature slot:
##
##     Ed25519  ------.
##     Dilithium ------+---> ALL of them must produce a valid proof
##     Falcon   ------'
##
## Breaking one algorithm is therefore not enough to impersonate anybody, or
## to mint a certificate. `signIdentityStack` produces one proof per slot and
## `verifyIdentityStack` demands every one of them.
##
## ╭─ ❧ what a certificate is, in bytes 🍣
##
## One canonical encoding, used BOTH as the thing the authority signs and as
## the thing that travels inside a sealed handshake block. Having one form
## rather than two removes the classic trap where a value verifies in one
## shape and is read back in another.
##
##   u64 serial | u32+authority | u32+subject
##   u8 keyCount | { u8 alg, u32+publicKey } ...
##   i64 validFrom | i64 validUntil
##   u32 proofCount | { u32+proof } ...        <- 0 for a pinned identity
##
## The serial names the CERTIFICATE, not its holder. Revoking a serial takes
## one certificate out of use and the same subject can be issued a fresh one;
## revoking by name instead would burn the name forever.

import ../level1/signatures

import ../../types
import ../types
import ../level0/bytes
import ../level1/suites
import ../level1/exchange_paths
import runePragmas

const
  ameHandshakeTextMax* = 4096'u32
  ameIdentityKeyMax* = 1_048_576'u32
  ameSignatureProofMax* = 1_048_576'u32
  ameMaxCertificateSkewSeconds* = 86_400'i64
    ## How far the caller's clock may sit outside a certificate's window
    ## before this side refuses to judge it at all. A machine whose clock is
    ## a year out would otherwise silently accept expired certificates.

type
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

## ╭⟢ length-framed bytes
##
## Two shapes, used by everything below and by the transcript next door: a
## u32 length, then that many bytes. They are exported for exactly that
## reason -- the handshake's running record is built with the same two calls,
## so the two files cannot disagree about what "length-framed" means.

proc appendHandshakeString*(A: var ByteSeq, s: string) {.
    role: dataWriter.} =
  ## A/s: destination and length-framed UTF-8 identity text.
  requireAmeU32Len(s.len, "handshake string")
  appendAmeU32(A, uint32(s.len))
  appendAmeLabel(A, s)

proc appendHandshakeBytes*(A: var ByteSeq, B: openArray[uint8]) {.
    role: dataWriter.} =
  ## A/B: destination and length-framed bytes.
  requireAmeU32Len(B.len, "handshake bytes")
  appendAmeU32(A, uint32(B.len))
  appendAmeBytes(A, B)

proc appendHandshakeProofs*(A: var ByteSeq, P: openArray[ByteSeq]) {.
    role: dataWriter.} =
  ## A/P: destination and ordered signature proof stack.
  var
    i: int = 0
  requireAmeU32Len(P.len, "handshake proof count")
  appendAmeU32(A, uint32(P.len))
  while i < P.len:
    appendHandshakeBytes(A, P[i])
    i = i + 1

proc appendHandshakeI64*(A: var ByteSeq, v: int64) {.role: dataWriter.} =
  ## A/v: destination and two's-complement little-endian timestamp.
  appendAmeU64(A, cast[uint64](v))

proc appendIdentitySigningKeys(A: var ByteSeq,
    K: openArray[AmeIdentitySigningKey]) {.role: dataWriter.} =
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

proc copyByteStack*(K: openArray[ByteSeq]): seq[ByteSeq] {.role: helper.} =
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
    key: AmeIdentitySigningKey = default(AmeIdentitySigningKey)
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

proc requireIdentityLayout*(L: AmeSuiteLayout, i: AmeIdentityKey) {.
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

proc requireCertificateLayout*(L: AmeSuiteLayout,
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

proc signIdentityStack*(L: AmeSuiteLayout, t: AmeMaskTier,
    msg: openArray[uint8], i: AmeIdentityKey): seq[ByteSeq] {.
    role: orchestrator.} =
  ## L/t/msg/i: canonical message signed by every active identity slot.
  result = signAmeTier(L, t, msg, selectedIdentitySecretKeys(L, t, i))

proc verifyIdentityStack*(L: AmeSuiteLayout, t: AmeMaskTier,
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
    k: AmeSigKeypair = default(AmeSigKeypair)
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
    k: AmeSigKeypair = default(AmeSigKeypair)
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
    k: AmeSigKeypair = default(AmeSigKeypair)
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
    k: AmeSigKeypair = default(AmeSigKeypair)
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
    publicKey: openArray[uint8]): AmePinnedPeerIdentity {.role: truthBuilder.} =
  ## subject/algorithm/publicKey: exact peer identity pinned out of band.
  if subject.len == 0 or publicKey.len == 0:
    raise newException(ValueError, "AME pinned peer identity is incomplete")
  result.subject = subject
  result.signingKeys.add(AmeIdentitySigningKey(algorithm: algorithm,
    publicKey: @publicKey))

proc pinnedPeerIdentity*(i: AmeIdentityKey): AmePinnedPeerIdentity {.
    role: truthBuilder.} =
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
    K: openArray[AmeIdentitySigningKey]): AmeAuthorityRoot {.role: configurator.} =
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
    role: configurator.} =
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

proc readCertField*(A: openArray[uint8], cursor: var int,
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

proc readCertString*(A: openArray[uint8], cursor: var int): string {.
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
    key: AmeIdentitySigningKey = default(AmeIdentitySigningKey)
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
    role: dataWriter, tag: "appApi|codecBoundary".} =
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
    tag: "appApi|codecBoundary|parsing".} =
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

