## -------------------------------------------------------------------------
## AME Handshake <- authority identity + AME KEM -> first authenticated epoch
## -------------------------------------------------------------------------

import tyr/helpers/random as tyr_random
import tyr/helpers/tiers as tyr_alg
import ../level1/signatures

import ../../types
import ../types
import ../level0/bytes
import ../level1/exchange_paths
import ../level1/suites
import ../level1/path_triggers
import ../level2/session
import ../../../analysis_pragmas

type
  AmeTrustMode* = enum
    atmAuthorityCertificate,
    atmPinnedPeerKey

  AmePinnedPeerIdentity* {.role: configurator.} = object
    subject*: string
    signingKeys*: seq[AmeIdentitySigningKey]

  AmeAuthorityKey* {.role: configurator.} = object
    name*: string
    algorithm*: AmeSignatureAlgorithm
    publicKey*: ByteSeq
    secretKey*: ByteSeq

  AmeIdentityKey* {.role: configurator.} = object
    subject*: string
    signingKeys*: seq[AmeIdentitySigningKey]
    secretKeys*: seq[ByteSeq]

  AmeIdentityCertificate* {.role: truthState.} = object
    authority*: string
    subject*: string
    signingKeys*: seq[AmeIdentitySigningKey]
    validFromUnix*: int64
    validUntilUnix*: int64
    authoritySignature*: ByteSeq

  AmeClientHello* {.role: truthState.} = object
    sessionId*: uint64
    nonce*: ByteSeq
    layout*: AmeSuiteLayout
    initialTier*: AmeMaskTier
    certificate*: AmeIdentityCertificate
    offer*: AmeExchangeOffer
    proofs*: seq[ByteSeq]

  AmeServerHello* {.role: truthState.} = object
    nonce*: ByteSeq
    certificate*: AmeIdentityCertificate
    reply*: AmeExchangeReply
    proofs*: seq[ByteSeq]

  AmeClientFinish* {.role: truthState.} = object
    requestId*: uint32
    transcriptHash*: ByteSeq
    proofs*: seq[ByteSeq]

  AmeClientHandshake* {.role: truthState.} = object
    hello*: AmeClientHello
    secretKeys*: seq[ByteSeq]

  AmeServerHandshake* {.role: truthState.} = object
    clientHello*: AmeClientHello
    serverHello*: AmeServerHello
    peerTrust*: AmePeerTrustResult
    sharedSecrets*: seq[ByteSeq]
    localSignatureSecretKeys*: seq[ByteSeq]
    peerSignaturePublicKeys*: seq[ByteSeq]

  AmeHandshakeResult* {.role: truthState.} = object
    ok*: bool
    auth*: AmeAuthPackage
    peerTrust*: AmePeerTrustResult
    finish*: AmeClientFinish
    err*: string

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

proc identityKeysEqual(A, B: openArray[AmeIdentitySigningKey]): bool {.
    role: parser.} =
  ## A/B: ordered algorithms and public keys compared without short-circuiting keys.
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

proc certificateSubject(c: AmeIdentityCertificate): ByteSeq {.
    role: truthBuilder.} =
  ## c: certificate fields covered by the authority signature.
  appendAmeLabel(result, "AME-CERTIFICATE-v2")
  result.add(ameCertificateVersion)
  appendHandshakeString(result, c.authority)
  appendHandshakeString(result, c.subject)
  appendIdentitySigningKeys(result, c.signingKeys)
  appendHandshakeI64(result, c.validFromUnix)
  appendHandshakeI64(result, c.validUntilUnix)

proc initAmeAuthorityKey*(name: string,
    algorithm: AmeSignatureAlgorithm = asaEd25519): AmeAuthorityKey {.
    role: orchestrator.} =
  ## name/algorithm: authority identity and signature algorithm.
  var
    k: AmeSigKeypair
  if name.len == 0:
    raise newException(ValueError, "AME authority name must not be empty")
  k = ameSigKeypair(algorithm)
  result.name = name
  result.algorithm = algorithm
  result.publicKey = k.publicKey
  result.secretKey = k.secretKey

proc initAmeAuthorityKey*(name: string, algorithm: AmeSignatureAlgorithm,
    seed: openArray[uint8]): AmeAuthorityKey {.role: orchestrator.} =
  ## name/algorithm/seed: deterministic authority identity for provisioned setups.
  var
    k: AmeSigKeypair
  if name.len == 0 or seed.len == 0:
    raise newException(ValueError,
      "AME seeded authority name and seed must not be empty")
  k = ameSigKeypair(algorithm, seed)
  result.name = name
  result.algorithm = algorithm
  result.publicKey = k.publicKey
  result.secretKey = k.secretKey

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
    initAmeSignatureAlgorithms([asaEd25519, asaFalcon512]))

proc initAmeIdentityKey*(subject: string,
    algorithm: AmeSignatureAlgorithm): AmeIdentityKey {.role: orchestrator.} =
  ## subject/algorithm: peer identity with one explicitly selected signing slot.
  result = initAmeIdentityKey(subject, initAmeSignatureAlgorithms([algorithm]))

proc initAmeIdentityKey*(subject: string, algorithm: AmeSignatureAlgorithm,
    seed: openArray[uint8]): AmeIdentityKey {.role: orchestrator.} =
  ## subject/algorithm/seed: deterministic identity for provisioned setups.
  var
    k: AmeSigKeypair
  if subject.len == 0 or seed.len == 0:
    raise newException(ValueError,
      "AME seeded identity subject and seed must not be empty")
  k = ameSigKeypair(algorithm, seed)
  result.subject = subject
  result.signingKeys.add(AmeIdentitySigningKey(algorithm: algorithm,
    publicKey: k.publicKey))
  result.secretKeys.add(k.secretKey)

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

proc pinnedIdentityDescriptor(i: AmeIdentityKey): AmeIdentityCertificate {.
    role: truthBuilder.} =
  ## i: local identity represented in the existing handshake identity block.
  if i.subject.len == 0 or i.signingKeys.len == 0 or
      i.signingKeys.len != i.secretKeys.len:
    raise newException(ValueError, "AME pinned local identity is incomplete")
  result.authority = ""
  result.subject = i.subject
  result.signingKeys = copyIdentitySigningKeys(i.signingKeys)
  result.validFromUnix = 0'i64
  result.validUntilUnix = high(int64)

proc verifyPinnedPeerIdentity*(c: AmeIdentityCertificate,
    expected: AmePinnedPeerIdentity): AmePeerTrustResult {.role: parser.} =
  ## c/expected: received descriptor and exact locally provisioned peer pin.
  if expected.subject.len == 0 or expected.signingKeys.len == 0:
    result.err = "pinned peer identity is incomplete"
    return
  if c.authority.len != 0 or c.authoritySignature.len != 0:
    result.err = "pinned peer sent a certificate instead of a direct identity"
    return
  if c.subject != expected.subject or
      not identityKeysEqual(c.signingKeys, expected.signingKeys):
    result.err = "peer identity does not match the pinned public key"
    return
  result.ok = true
  result.authority = "pinned-peer"
  result.algorithm = c.signingKeys[0].algorithm
  result.subjectKeyId = c.subject

proc issueAmeIdentityCertificate*(a: AmeAuthorityKey, i: AmeIdentityKey,
    validFromUnix, validUntilUnix: int64): AmeIdentityCertificate {.
    role: orchestrator.} =
  ## a/i/timestamps: signing authority, peer key, and inclusive validity range.
  if validFromUnix < 0 or validUntilUnix <= validFromUnix:
    raise newException(ValueError, "AME certificate validity range is invalid")
  result.authority = a.name
  result.subject = i.subject
  result.signingKeys = copyIdentitySigningKeys(i.signingKeys)
  result.validFromUnix = validFromUnix
  result.validUntilUnix = validUntilUnix
  result.authoritySignature = signAmeMessage(a.algorithm,
    certificateSubject(result), a.secretKey)

proc initAmeAuthorityRoot*(name: string, algorithm: AmeSignatureAlgorithm,
    publicKey: openArray[uint8]): AmeAuthorityRoot {.role: wrapper.} =
  ## name/algorithm/publicKey: the authority a deployment pins out of band.
  ## Use this rather than filling the object by hand: a root left at its
  ## default has an empty name, which would otherwise match the empty
  ## authority field of an unsigned pinned-peer descriptor.
  if name.len == 0 or publicKey.len == 0:
    raise newException(ValueError, "AME authority root name and key are required")
  result.authority = name
  result.algorithm = algorithm
  result.publicKey = @publicKey

proc initAmeAuthorityRoot*(a: AmeAuthorityKey): AmeAuthorityRoot {.
    role: wrapper.} =
  ## a: signing authority reduced to its public pinning material.
  result = initAmeAuthorityRoot(a.name, a.algorithm, a.publicKey)

proc verifyAmeIdentityCertificate*(c: AmeIdentityCertificate,
    root: AmeAuthorityRoot, nowUnix: int64,
    revokedSubjects: openArray[string] = []): AmePeerTrustResult {.
    role: orchestrator.} =
  ## c/root/nowUnix/revokedSubjects: certificate, pinned authority root, trusted
  ## wall clock, and deployment-provided revocation list.
  var
    i: int = 0
  if root.authority.len == 0 or root.publicKey.len == 0:
    result.err = "pinned authority root is incomplete"
    return
  if c.authority.len == 0 or c.authoritySignature.len == 0:
    result.err = "certificate carries no authority signature"
    return
  if c.authority != root.authority:
    result.err = "certificate authority does not match the pinned root"
    return
  if c.subject.len == 0 or c.signingKeys.len == 0:
    result.err = "certificate identity is incomplete"
    return
  if nowUnix < c.validFromUnix or nowUnix > c.validUntilUnix:
    result.err = "certificate is outside its validity period"
    return
  while i < revokedSubjects.len:
    if c.subject == revokedSubjects[i]:
      result.err = "certificate subject is revoked"
      return
    i = i + 1
  try:
    if not verifyAmeMessage(root.algorithm, certificateSubject(c),
        c.authoritySignature, root.publicKey):
      result.err = "certificate authority signature is invalid"
      return
  except CatchableError as e:
    result.err = "certificate verification failed: " & e.msg
    return
  result.ok = true
  result.authority = c.authority
  result.algorithm = c.signingKeys[0].algorithm
  result.subjectKeyId = c.subject

proc clientHelloSubject(h: AmeClientHello): ByteSeq {.role: truthBuilder.} =
  ## h: client fields covered by its identity proof.
  appendAmeLabel(result, "AME-CLIENT-HELLO-v3")
  appendAmeU64(result, h.sessionId)
  appendHandshakeBytes(result, h.nonce)
  appendHandshakeBytes(result, encodeAmeSuiteLayout(h.layout))
  appendHandshakeBytes(result, encodeAmeMaskTier(h.initialTier))
  appendHandshakeBytes(result, certificateSubject(h.certificate))
  appendHandshakeBytes(result, h.certificate.authoritySignature)
  appendHandshakeBytes(result, encodeAmeExchangeOffer(h.offer))

proc serverHelloSubject(c: AmeClientHello, s: AmeServerHello): ByteSeq {.
    role: truthBuilder.} =
  ## c/s: complete client hello and unsigned server hello transcript.
  appendAmeLabel(result, "AME-SERVER-HELLO-v3")
  appendHandshakeBytes(result, clientHelloSubject(c))
  appendHandshakeProofs(result, c.proofs)
  appendHandshakeBytes(result, s.nonce)
  appendHandshakeBytes(result, certificateSubject(s.certificate))
  appendHandshakeBytes(result, s.certificate.authoritySignature)
  appendHandshakeBytes(result, encodeAmeExchangeReply(s.reply))

proc handshakeTranscript(c: AmeClientHello, s: AmeServerHello): ByteSeq {.
    role: truthBuilder.} =
  ## c/s: both authenticated hello messages.
  appendAmeLabel(result, "AME-HANDSHAKE-TRANSCRIPT-v3")
  appendHandshakeBytes(result, clientHelloSubject(c))
  appendHandshakeProofs(result, c.proofs)
  appendHandshakeBytes(result, serverHelloSubject(c, s))
  appendHandshakeProofs(result, s.proofs)

proc beginAmeHandshake*(sessionId: uint64, L: AmeSuiteLayout,
    initialTier: AmeMaskTier,
    certificate: AmeIdentityCertificate, identity: AmeIdentityKey,
    requestId: uint32 = 1'u32): AmeClientHandshake {.
    role: orchestrator.} =
  ## sessionId/L/initialTier/identity/requestId: client inputs. The initial
  ## exchange always establishes every KEM slot the initial tier selects, so
  ## there is no separate mask to choose here.
  var
    request: AmeExchangeRequest
    keys: AmeExchangeKeys
  if sessionId == 0'u64 or certificate.subject != identity.subject or
      not identityKeysEqual(certificate.signingKeys, identity.signingKeys):
    raise newException(ValueError, "AME client identity does not match its certificate")
  validateAmeTier(L, initialTier)
  requireIdentityLayout(L, identity)
  requireCertificateLayout(L, certificate)
  request = initAmeExchangeRequest(L.kems, initialTier, initialTier.masks.kem)
  keys = generateAmeExchangeKeys(L.kems, request)
  result.hello.sessionId = sessionId
  result.hello.nonce = tyr_random.cryptoRand(tyr_alg.raSystem,
    ameHandshakeNonceLen)
  result.hello.layout = L
  result.hello.initialTier = initialTier
  result.hello.certificate = certificate
  result.hello.offer = initAmeExchangeOffer(requestId, 0'u32, request,
    keys.publicKeys)
  result.hello.proofs = signIdentityStack(L, initialTier,
    clientHelloSubject(result.hello), identity)
  result.secretKeys = keys.secretKeys

proc beginAmePinnedHandshake*(sessionId: uint64, L: AmeSuiteLayout,
    initialTier: AmeMaskTier,
    identity: AmeIdentityKey, requestId: uint32 = 1'u32): AmeClientHandshake {.
    role: orchestrator.} =
  ## sessionId/L/initialTier/identity/requestId: direct-pin inputs.
  result = beginAmeHandshake(sessionId, L, initialTier,
    pinnedIdentityDescriptor(identity), identity, requestId)

proc clientHelloPolicyError(c: AmeClientHello,
    supported: openArray[AmeTierPath]): string {.role: parser.} =
  ## c/supported: cheap shape and exact-policy checks before signature work.
  var
    layoutSupported: bool = false
    i: int = 0
    selectedSignatures: int = 0
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
    requireCertificateLayout(c.layout, c.certificate)
    selectedSignatures = activeAmeSignatures(c.layout, c.initialTier).len
    if not tiersEquivalent(c.offer.request.targetTier, c.initialTier) or
        c.offer.request.exchangeMask != c.initialTier.masks.kem or
        c.offer.signatures.len != 0 or c.proofs.len != selectedSignatures:
      return "client hello initial tier exchange is invalid"
  except ValueError as e:
    return e.msg

proc answerVerifiedAmeHandshake(c: AmeClientHello,
    supported: openArray[AmeTierPath], peerTrust: AmePeerTrustResult,
    descriptor: AmeIdentityCertificate, identity: AmeIdentityKey): tuple[
    ok: bool, state: AmeServerHandshake,
    peerTrust: AmePeerTrustResult, err: string] {.role: orchestrator.} =
  ## c/supported/peerTrust/descriptor/identity: verified responder inputs.
  var
    answer: tuple[reply: AmeExchangeReply, sharedSecrets: seq[ByteSeq]]
    policyError: string = ""
  result.peerTrust = peerTrust
  policyError = clientHelloPolicyError(c, supported)
  if policyError.len > 0:
    result.err = policyError
    return
  if not result.peerTrust.ok:
    result.err = result.peerTrust.err
    return
  try:
    if not verifyIdentityStack(c.layout, c.initialTier,
        clientHelloSubject(c), c.proofs, c.certificate):
      result.err = "client hello identity proof is invalid"
      return
  except CatchableError as e:
    result.err = "client hello proof failed: " & e.msg
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
  answer = answerAmeExchangeOffer(c.layout.kems, c.offer)
  result.state.clientHello = c
  result.state.peerTrust = result.peerTrust
  result.state.serverHello.nonce = tyr_random.cryptoRand(tyr_alg.raSystem,
    ameHandshakeNonceLen)
  result.state.serverHello.certificate = descriptor
  result.state.serverHello.reply = answer.reply
  result.state.serverHello.proofs = signIdentityStack(c.layout, c.initialTier,
    serverHelloSubject(c, result.state.serverHello), identity)
  result.state.sharedSecrets = answer.sharedSecrets
  result.state.localSignatureSecretKeys = copyByteStack(identity.secretKeys)
  for key in c.certificate.signingKeys:
    result.state.peerSignaturePublicKeys.add(key.publicKey & @[])
  result.ok = true

proc answerAmeHandshake*(c: AmeClientHello,
    supported: openArray[AmeTierPath], root: AmeAuthorityRoot,
    certificate: AmeIdentityCertificate, identity: AmeIdentityKey,
    nowUnix: int64, revokedSubjects: openArray[string] = []): tuple[
    ok: bool, state: AmeServerHandshake,
    peerTrust: AmePeerTrustResult, err: string] {.role: orchestrator.} =
  ## c/supported/root/server identity/nowUnix: responder handshake inputs.
  var
    policyError: string = clientHelloPolicyError(c, supported)
    peerTrust: AmePeerTrustResult
  if policyError.len > 0:
    result.err = policyError
    return
  peerTrust = verifyAmeIdentityCertificate(c.certificate, root, nowUnix,
    revokedSubjects)
  result = answerVerifiedAmeHandshake(c, supported, peerTrust, certificate,
    identity)

proc answerAmePinnedHandshake*(c: AmeClientHello,
    supported: openArray[AmeTierPath], expectedPeer: AmePinnedPeerIdentity,
    identity: AmeIdentityKey): tuple[ok: bool, state: AmeServerHandshake,
    peerTrust: AmePeerTrustResult, err: string] {.role: orchestrator.} =
  ## c/supported/expectedPeer/identity: direct public-key-pinned responder inputs.
  var peerTrust = verifyPinnedPeerIdentity(c.certificate, expectedPeer)
  result = answerVerifiedAmeHandshake(c, supported, peerTrust,
    pinnedIdentityDescriptor(identity), identity)

proc buildInitialAuth(L: AmeSuiteLayout, initialTier: AmeMaskTier,
    request: AmeExchangeRequest,
    sharedSecrets: openArray[ByteSeq], transcript: openArray[uint8],
    sessionId: uint64, endpointRole: AmeEndpointRole):
    AmeAuthPackage {.role: truthBuilder.} =
  ## L/tier/request/secrets/transcript/session/role: verified first epoch.
  var
    exchange: AmeExchangeState = initAmeExchangeState(L.kems)
  applyAmeExchange(exchange, request, sharedSecrets)
  result = initAmeAuthPackage(L, initialTier, exchange,
    hashAmeTier(L, initialTier, transcript, 32), 1'u32, sessionId,
    endpointRole)

proc serverHelloPolicyError(S: AmeClientHandshake,
    h: AmeServerHello): string {.role: parser.} =
  ## S/h: cheap responder shape checks before certificate verification.
  try:
    requireCertificateLayout(S.hello.layout, h.certificate)
    if h.nonce.len != ameHandshakeNonceLen or h.reply.signatures.len != 0 or
        h.proofs.len != activeAmeSignatures(S.hello.layout,
          S.hello.initialTier).len or h.reply.requestId == 0'u32:
      return "server hello shape is invalid"
    discard encodeAmeExchangeReplySubject(S.hello.offer, h.reply)
  except ValueError as e:
    return e.msg

proc finishAmeHandshakeCore(S: AmeClientHandshake, h: AmeServerHello,
    root: AmeAuthorityRoot, identity: AmeIdentityKey,
    nowUnix: int64, revokedSubjects: openArray[string] = []):
    AmeHandshakeResult {.role: orchestrator.} =
  ## S/h/root/identity/nowUnix: client state and received server hello.
  var
    transcript: ByteSeq = @[]
    secrets: seq[ByteSeq] = @[]
    policyError: string = serverHelloPolicyError(S, h)
  if policyError.len > 0:
    result.err = policyError
    return
  result.peerTrust = verifyAmeIdentityCertificate(h.certificate, root, nowUnix,
    revokedSubjects)
  if not result.peerTrust.ok:
    result.err = result.peerTrust.err
    return
  try:
    if not verifyIdentityStack(S.hello.layout, S.hello.initialTier,
        serverHelloSubject(S.hello, h), h.proofs, h.certificate):
      result.err = "server hello identity proof is invalid"
      return
    secrets = openAmeExchangeReply(S.hello.layout.kems, S.hello.offer,
      h.reply, S.secretKeys)
  except CatchableError as e:
    result.err = "server hello exchange failed: " & e.msg
    return
  transcript = handshakeTranscript(S.hello, h)
  result.auth = buildInitialAuth(S.hello.layout, S.hello.initialTier,
    h.reply.request, secrets, transcript, S.hello.sessionId, aerInitiator)
  result.auth.localSignatureSecretKeys = copyByteStack(identity.secretKeys)
  for key in h.certificate.signingKeys:
    result.auth.peerSignaturePublicKeys.add(key.publicKey & @[])
  result.finish.requestId = h.reply.requestId
  result.finish.transcriptHash = hashAmeTier(S.hello.layout,
    S.hello.initialTier, transcript, 32)
  result.finish.proofs = signIdentityStack(S.hello.layout,
    S.hello.initialTier, result.finish.transcriptHash, identity)
  result.ok = true

proc finishAmePinnedHandshakeCore(S: AmeClientHandshake, h: AmeServerHello,
    expectedPeer: AmePinnedPeerIdentity, identity: AmeIdentityKey):
    AmeHandshakeResult {.role: orchestrator.} =
  ## S/h/expectedPeer/identity: client state and directly pinned server identity.
  var
    transcript: ByteSeq = @[]
    secrets: seq[ByteSeq] = @[]
    policyError: string = serverHelloPolicyError(S, h)
  if policyError.len > 0:
    result.err = policyError
    return
  result.peerTrust = verifyPinnedPeerIdentity(h.certificate, expectedPeer)
  if not result.peerTrust.ok:
    result.err = result.peerTrust.err
    return
  try:
    if not verifyIdentityStack(S.hello.layout, S.hello.initialTier,
        serverHelloSubject(S.hello, h), h.proofs, h.certificate):
      result.err = "server hello identity proof is invalid"
      return
    secrets = openAmeExchangeReply(S.hello.layout.kems, S.hello.offer,
      h.reply, S.secretKeys)
  except CatchableError as e:
    result.err = "server hello exchange failed: " & e.msg
    return
  transcript = handshakeTranscript(S.hello, h)
  result.auth = buildInitialAuth(S.hello.layout, S.hello.initialTier,
    h.reply.request, secrets, transcript, S.hello.sessionId, aerInitiator)
  result.auth.localSignatureSecretKeys = copyByteStack(identity.secretKeys)
  for key in h.certificate.signingKeys:
    result.auth.peerSignaturePublicKeys.add(key.publicKey & @[])
  result.finish.requestId = h.reply.requestId
  result.finish.transcriptHash = hashAmeTier(S.hello.layout,
    S.hello.initialTier, transcript, 32)
  result.finish.proofs = signIdentityStack(S.hello.layout,
    S.hello.initialTier, result.finish.transcriptHash, identity)
  result.ok = true

proc acceptAmeHandshakeCore(S: AmeServerHandshake, f: AmeClientFinish):
    AmeHandshakeResult {.role: orchestrator.} =
  ## S/f: responder state and client transcript confirmation.
  ## Peer trust is carried in the state that `answerVerifiedAmeHandshake`
  ## built, never re-asserted here, so a state that never passed identity
  ## verification cannot produce a trusted session.
  var
    transcript: ByteSeq = @[]
    expected: ByteSeq = @[]
  if not S.peerTrust.ok:
    result.err = "AME responder state carries no verified peer trust"
    return
  transcript = handshakeTranscript(S.clientHello, S.serverHello)
  expected = hashAmeTier(S.clientHello.layout, S.clientHello.initialTier,
    transcript, 32)
  if f.requestId != S.serverHello.reply.requestId or
      not constantTimeEqualAme(f.transcriptHash, expected):
    result.err = "client finish transcript does not match"
    return
  try:
    if not verifyIdentityStack(S.clientHello.layout,
        S.clientHello.initialTier, f.transcriptHash, f.proofs,
        S.clientHello.certificate):
      result.err = "client finish identity proof is invalid"
      return
  except CatchableError as e:
    result.err = "client finish verification failed: " & e.msg
    return
  result.auth = buildInitialAuth(S.clientHello.layout,
    S.clientHello.initialTier, S.serverHello.reply.request,
    S.sharedSecrets, transcript, S.clientHello.sessionId, aerResponder)
  result.auth.localSignatureSecretKeys = copyByteStack(
    S.localSignatureSecretKeys)
  result.auth.peerSignaturePublicKeys = S.peerSignaturePublicKeys
  result.peerTrust = S.peerTrust
  result.ok = true

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

proc finishAmeHandshake*(S: var AmeClientHandshake,
    h: AmeServerHello, root: AmeAuthorityRoot, identity: AmeIdentityKey,
    nowUnix: int64, revokedSubjects: openArray[string] = []):
    AmeHandshakeResult {.role: orchestrator.} =
  ## S/h/root/identity/time/revocation: finish and erase client KEM secrets.
  try:
    result = finishAmeHandshakeCore(S, h, root, identity, nowUnix,
      revokedSubjects)
  finally:
    clearAmeClientHandshake(S)

proc finishAmePinnedHandshake*(S: var AmeClientHandshake,
    h: AmeServerHello, expectedPeer: AmePinnedPeerIdentity,
    identity: AmeIdentityKey): AmeHandshakeResult {.role: orchestrator.} =
  ## S/h/expectedPeer/identity: finish pinned exchange and erase KEM secrets.
  try:
    result = finishAmePinnedHandshakeCore(S, h, expectedPeer, identity)
  finally:
    clearAmeClientHandshake(S)

proc acceptAmeHandshake*(S: var AmeServerHandshake,
    f: AmeClientFinish): AmeHandshakeResult {.role: orchestrator.} =
  ## S/f: accept client confirmation and erase responder handshake secrets.
  try:
    result = acceptAmeHandshakeCore(S, f)
  finally:
    clearAmeServerHandshake(S)
