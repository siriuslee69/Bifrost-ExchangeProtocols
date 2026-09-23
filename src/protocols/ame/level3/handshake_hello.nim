## -------------------------------------------------------------------------
## AME Handshake Hello <- steps 1 and 2: the client asks, the server answers
## -------------------------------------------------------------------------
##
## The first half of the conversation, and the only half that runs before
## either side knows who the other is:
##
##   client                                                   server
##     |--- hello: nonce, layout, KEM public keys ------------->|  step 1
##     |        (sealed under the shared secret in AM1P, AM1P+S) |
##     |<-- server hello: nonce, KEM answer, sealed block -------|  step 2
##
## Everything here is about getting that far safely: the cheap checks that
## run before any key work, the sealed hello of the pre-shared modes and its
## next-secret policy, and the responder's sealed identity block.
##
## Steps 3 and 4 -- opening the answer, judging it, finishing -- are in
## `handshake.nim`, which imports this file and re-exports it.

import tyr/helpers/random as tyr_random
import tyr/helpers/tiers as tyr_alg

import ../../types
import ../types
import ../level0/bytes
import ../level1/exchange_paths
import ../level1/suites
import ../level1/tier_aead
import ../level1/padding
import ../level1/path_triggers
import ./handshake_authentication
import ./handshake_records
import ./handshake_transcript
import runePragmas

## ╭⟢ step 1: the client speaks

proc beginAmeHandshake*(sessionId: uint64, L: AmeSuiteLayout,
    initialTier: AmeMaskTier, requestId: uint32 = 1'u32,
    cookie: openArray[uint8] = [],
    a: AmeAuthentication = default(AmeAuthentication)): AmeClientHandshake {.
    role: orchestrator, tag: "appApi|exchange".} =
  ## sessionId/L/initialTier/requestId/cookie: client inputs. The hello names
  ## no identity at all -- that waits until there is a key to hide it under.
  ## a: how this side authenticates. Its `mode` goes into the hello; in the
  ##   pre-shared modes its secret also seals the offer. Left at its default
  ##   it is AM1A with nothing else set, which only needs the mode.
  ##
  ## `cookie` is empty the first time. If the server asks for one, call this
  ## again with the same session id and the cookie it sent back. The hello is
  ## then sealed afresh, under a new salt.
  var
    request: AmeExchangeRequest = default(AmeExchangeRequest)
    keys: AmeExchangeKeys = default(AmeExchangeKeys)
  if sessionId == 0'u64:
    raise newException(ValueError, "AME client session id must be positive")
  validateAmeTier(L, initialTier)
  request = initAmeExchangeRequest(L.kems, initialTier, initialTier.masks.kem)
  keys = generateAmeExchangeKeys(L.kems, request)
  result.hello.sessionId = sessionId
  result.hello.mode = a.mode
  result.hello.nonce = tyr_random.cryptoRand(tyr_alg.raSystem,
    ameHandshakeNonceLen)
  result.hello.layout = L
  result.hello.initialTier = initialTier
  result.hello.cookie = @cookie
  result.hello.offer = initAmeExchangeOffer(requestId, 0'u32, request,
    keys.publicKeys)
  result.secretKeys = keys.secretKeys
  if ameModeUsesPsk(a.mode):
    result.hello.offerSalt = tyr_random.cryptoRand(tyr_alg.raSystem,
      ameHelloSaltLen)
    sealAmeHelloOffer(result.hello, a)

proc clientHelloLayoutError(c: AmeClientHello,
    supported: openArray[AmeTierPath]): string {.role: parser,
    tag: "validation".} =
  ## c/supported: the clear fields only -- layout, tier, session id, nonce.
  ## Runs BEFORE a sealed hello is opened, so a hello this side would refuse
  ## anyway never costs it a key derivation.
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
  if c.sessionId == 0'u64 or c.nonce.len != ameHandshakeNonceLen:
    return "client hello shape is invalid"

proc clientHelloPolicyError*(c: AmeClientHello,
    supported: openArray[AmeTierPath]): string {.role: parser.} =
  ## c/supported: cheap shape and exact-policy checks. Everything here is
  ## arithmetic on fields the hello already carries -- no key work at all, so
  ## a flood of nonsense costs the server almost nothing. In the pre-shared
  ## modes it reads the offer, so it runs after the offer was opened.
  result = clientHelloLayoutError(c, supported)
  if result.len > 0:
    return
  if c.offer.baseEpochId != 0'u32:
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
##
## What goes inside the server's sealed block, by mode. The block is built by
## one of the two procs below and never by both, so there is exactly one shape
## per mode and no field that means different things on different days.
##
##   AM1A / AM1S            AM1P                AM1P+S
##   ------------------     ------------------  ------------------
##   certificate body       pskId               pskId
##   authority proofs       one proof           one proof
##   one proof per slot                         certificate body
##                                              authority proofs
##                                              one proof per slot
##
## All of them are then padded under the same policy, so the shapes are not
## distinguishable by length either.

proc serverCertificateBlock(c: AmeClientHello,
    descriptor: AmeIdentityCertificate, identity: AmeIdentityKey,
    clear: openArray[uint8]): ByteSeq {.inline, role: truthBuilder,
    tag: "cryptoBoundary".} =
  ## c/descriptor/identity/clear: the certificate shape.
  ##
  ## The certificate body goes in raw because it is the exact byte string the
  ## authority signed. Wrapping it in another length would mean the bytes
  ## verified and the bytes stored were not the same thing.
  var
    proofs: seq[ByteSeq] = signIdentityStack(c.layout, c.initialTier, clear,
      identity)
  appendAmeBytes(result, certificateSubject(descriptor))
  appendHandshakeProofs(result, descriptor.authorityProofs)
  appendHandshakeProofs(result, proofs)

proc serverPskBlock(a: AmeAuthentication,
    clear: openArray[uint8]): ByteSeq {.inline, role: truthBuilder,
    tag: "cryptoBoundary".} =
  ## a/clear: the shared-secret shape. No certificate and no signature key is
  ## touched here -- the whole claim is one tag over what both sides can
  ## rebuild from the two hellos.
  var
    proof: ByteSeq = amePskTranscriptProof(a, apdResponder, clear)
  appendHandshakeString(result, a.pskId)
  appendHandshakeProofs(result, @[proof])
  secureClearAmeBytes(proof)

proc serverIdentityBlockBytes(c: AmeClientHello, a: AmeAuthentication,
    descriptor: AmeIdentityCertificate, identity: AmeIdentityKey,
    clear: openArray[uint8]): ByteSeq {.inline, role: truthBuilder,
    tag: "cryptoBoundary".} =
  ## c/a/descriptor/identity/clear: the shape this mode uses -- the shared-
  ## secret half, the certificate half, or both one after the other.
  if ameModeUsesPsk(a.mode):
    result = serverPskBlock(a, clear)
  if ameModeUsesSignatures(a.mode):
    appendAmeBytes(result, serverCertificateBlock(c, descriptor, identity,
      clear))

proc buildServerHello(S: var AmeServerHandshake, a: AmeAuthentication,
    identity: AmeIdentityKey, descriptor: AmeIdentityCertificate,
    params: AmeRuntimeParams): string {.role: orchestrator,
    tag: "cryptoBoundary|exchange".} =
  ## S/a/identity/descriptor/params: encapsulate, derive the temporary key,
  ## and seal what this side is under it. Returns an error string, or "".
  var
    answer: tuple[reply: AmeExchangeReply, sharedSecrets: seq[ByteSeq]] = (
      reply: default(AmeExchangeReply), sharedSecrets: @[])
    clear: ByteSeq = @[]
    rows: seq[ByteSeq] = @[]
    material: ByteSeq = @[]
    block1: ByteSeq = @[]
    sealed: tuple[ciphertext: ByteSeq, authTag: ByteSeq] = (
      ciphertext: @[], authTag: @[])
    c: AmeClientHello = S.clientHello
  answer = answerAmeExchangeOffer(c.layout.kems, c.offer)
  S.sharedSecrets = answer.sharedSecrets
  S.serverHello.nonce = tyr_random.cryptoRand(tyr_alg.raSystem,
    ameHandshakeNonceLen)
  S.serverHello.mode = c.mode
  S.serverHello.reply = answer.reply
  S.serverHello.params = params
  clear = serverHelloClearSubject(c, S.serverHello)
  ## The server proves the transcript BEFORE its identity is sealed, so the
  ## proof covers what the client will independently rebuild, not the
  ## ciphertext the client has not opened yet.
  block1 = serverIdentityBlockBytes(c, a, descriptor, identity, clear)
  ## Padded under the same policy the epoch will use, when there is one. A
  ## certificate's length is a fingerprint of its own -- how many algorithms
  ## it names, how long the subject is -- and hiding the identity while
  ## leaving its size on the wire only does half the job.
  block1 = padAmeMessage(block1, params.padding)
  try:
    rows = secretRows(c.layout.kems, c.initialTier.masks.kem, S.sharedSecrets)
    appendBinderRow(rows, a)
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

proc responderIdentityError(c: AmeClientHello, a: AmeAuthentication,
    descriptor: AmeIdentityCertificate,
    identity: AmeIdentityKey): string {.inline, role: parser,
    tag: "validation".} =
  ## c/a/descriptor/identity: the identity material this mode actually needs.
  ## AM1P needs no certificate, so a responder running it is not made to
  ## carry a signature key it will never use. AM1P+S needs both.
  if ameModeUsesPsk(a.mode) and (a.psk.len < 16 or a.pskId.len == 0):
    return "AME PSK authentication is not configured"
  if not ameModeUsesSignatures(a.mode):
    return
  if descriptor.subject != identity.subject or
      not identityKeysEqual(descriptor.signingKeys, identity.signingKeys):
    return "server identity does not match its handshake descriptor"
  try:
    requireIdentityLayout(c.layout, identity)
    requireCertificateLayout(c.layout, descriptor)
  except ValueError as e:
    return e.msg

proc nextSecretPolicyError(c: AmeClientHello,
    a: var AmeAuthentication): string {.role: parser,
    tag: "cryptoBoundary|validation".} =
  ## c/a: the hello's next-secret flag against what this side holds and
  ## requires. On success `a` is left holding exactly what the hello used,
  ## so every later derivation on this side matches the client's:
  ##
  ##   hello flag   this side holds   required   outcome
  ##   ----------   ---------------   --------   -----------------------------
  ##   set          yes               any        use it
  ##   set          no                any        refuse: nothing to match
  ##   clear        any               yes        refuse: no silent fallback
  ##   clear        yes               no         drop ours, psk only
  ##   clear        no                no         psk only
  if c.usesNextSecret and a.nextSecret.len == 0:
    return "client used a next secret this side does not hold"
  if not c.usesNextSecret and a.nextSecretRequired:
    return "client hello did not carry the required next secret"
  if not c.usesNextSecret:
    secureClearAmeBytes(a.nextSecret)
    a.nextSecret = @[]

proc answerAmeHandshake*(c: AmeClientHello,
    supported: openArray[AmeTierPath], a: AmeAuthentication,
    descriptor: AmeIdentityCertificate = default(AmeIdentityCertificate),
    identity: AmeIdentityKey = default(AmeIdentityKey),
    params: AmeRuntimeParams = AmeRuntimeParams(authTagLen: aatl32)): tuple[
    ok: bool, state: AmeServerHandshake, err: string] {.role: orchestrator,
    tag: "appApi|exchange".} =
  ## c/supported/a/descriptor/identity/params: responder inputs. `a` decides
  ## whom this side will believe AND what it proves about itself; the
  ## certificate and identity key are needed only by AM1A, AM1S and AM1P+S.
  ##
  ## `params` are the tunables the responder imposes on the first epoch -- tag
  ## length and whether payloads are padded. The client adopts them or gives
  ## up.
  ##
  ## The client is NOT authenticated yet at this point and cannot be -- it has
  ## not said who it is. Anti-flood protection is the cookie, checked by the
  ## caller before this runs; identity checking happens at the finish.
  ##
  ## In the pre-shared modes the order is:
  ##
  ##   clear fields ok? ─▶ mode matches? ─▶ next-secret policy ok?
  ##        ─▶ open the sealed offer ─▶ offer fields ok? ─▶ answer
  ##
  ## so a hello this side would refuse anyway never costs a key derivation.
  var
    policyError: string = clientHelloLayoutError(c, supported)
    sealError: string = ""
    hello: AmeClientHello = c
    local: AmeAuthentication = a
  if policyError.len > 0:
    result.err = policyError
    return
  ## A hello naming a mode this responder does not run is refused here, before
  ## any key work. Mirroring it instead would let a client choose which of our
  ## checks runs.
  if c.mode != a.mode:
    result.err = "client asked for an authentication mode this side does not run"
    return
  if ameModeUsesPsk(a.mode):
    policyError = nextSecretPolicyError(hello, local)
    if policyError.len == 0:
      policyError = openAmeHelloOffer(hello, local)
    if policyError.len > 0:
      result.err = policyError
      return
  policyError = clientHelloPolicyError(hello, supported)
  if policyError.len == 0:
    policyError = responderIdentityError(hello, local, descriptor, identity)
  if policyError.len > 0:
    result.err = policyError
    return
  result.state.clientHello = hello
  result.state.authentication = local
  sealError = buildServerHello(result.state, local, identity, descriptor,
    params)
  if sealError.len > 0:
    result.err = sealError
    return
  result.state.localSignatureSecretKeys = copyByteStack(identity.secretKeys)
  result.ok = true

