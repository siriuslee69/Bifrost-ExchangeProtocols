## -------------------------------------------------------------------------
## AME Handshake <- the four messages, and what each side says in them
## -------------------------------------------------------------------------
##
## Four messages, at most. Reading left to right is the whole protocol:
##
##   client                                                   server
##     |                                                         |
##     |--- hello: nonce, slot layout, KEM public keys ---------->|
##     |                                                         |
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
## ╭─ ❧ what is NOT in this file 🌊
##
## Five neighbours, so that this one is only ever about the conversation. Each
## answers one question completely, and you can read any of them on its own:
##
##   handshake_identity.nim    who someone is, and whether you believe them.
##                             Certificates, authority keys, pinned keys, and
##                             the three ways to say whom you trust.
##   handshake_cookie.nim      proving you can receive where you claim to be,
##                             and why the server remembers nothing about it.
##   handshake_records.nim     the SHAPE of the four messages. Types only.
##   handshake_wire.nim        those same four, byte for byte.
##   handshake_transcript.nim  the running record both sides sign, and the
##                             shared-secret proofs taken over it.
##
## What IS here: the four steps, and the four calls a caller actually makes.
## Importing this file gives you all five as well, so the split costs a
## reader nothing.
##
## Below that again sit the three drivers that own a socket:
## `handshake_tcp.nim`, `handshake_dac.nim` and `handshake_transport.nim`.
##
## ╭─ ❧ why the certificates are sealed ⟡
##
## The KEM answer in the server hello is enough for both sides to work out a
## temporary key. Everything after that point is encrypted with it. So an
## observer watching the wire sees two nonces and some key material, and never
## learns WHO is talking to whom. Only the two endpoints do.
##
## ╭─ ❧ why there is a retry at all 🍣
##
## Answering a hello costs real work, and a machine sending forged return
## addresses could make a server do that work all day. The retry asks for a
## cookie first, and the cookie is only obtainable by someone who can actually
## receive at the address they claimed. See `handshake_cookie.nim` -- the
## whole argument is there, including why the server stores nothing.
import tyr/helpers/random as tyr_random
import tyr/helpers/tiers as tyr_alg
import ../level1/signatures

import ../../types
import ../types
import ../level0/bytes
import ../level1/exchange_paths
import ../level1/derivation
import ../level1/secret_stack
import ../level1/suites
import ../level1/symmetric
import ../level1/tier_aead
import ../level1/padding
import ../level1/path_triggers
import ../level2/framing
import ./handshake_identity
import ./handshake_cookie
import ./handshake_records
import ./handshake_transcript
import ../../fomke/level0/gb3hkdf
import runePragmas

## A caller reaches for one import and gets the whole handshake: the identity
## vocabulary, the cookie, the four record shapes and the transcript. The
## split is for reading, not for making anyone assemble it themselves.
export handshake_identity, handshake_cookie, handshake_records,
  handshake_transcript


## ╭⟢ step 1: the client speaks

proc beginAmeHandshake*(sessionId: uint64, L: AmeSuiteLayout,
    initialTier: AmeMaskTier, requestId: uint32 = 1'u32,
    cookie: openArray[uint8] = [], mode: AmeTrustMode = atmAuthorityCertificate): AmeClientHandshake {.
    role: orchestrator, tag: "appApi|exchange".} =
  ## sessionId/L/initialTier/requestId/cookie: client inputs. The hello names
  ## no identity at all -- that waits until there is a key to hide it under.
  ##
  ## `cookie` is empty the first time. If the server asks for one, call this
  ## again with the same session id and the cookie it sent back.
  var
    request: AmeExchangeRequest = default(AmeExchangeRequest)
    keys: AmeExchangeKeys = default(AmeExchangeKeys)
  if sessionId == 0'u64:
    raise newException(ValueError, "AME client session id must be positive")
  validateAmeTier(L, initialTier)
  request = initAmeExchangeRequest(L.kems, initialTier, initialTier.masks.kem)
  keys = generateAmeExchangeKeys(L.kems, request)
  result.hello.sessionId = sessionId
  result.hello.mode = mode
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
    if c.mode == atmPskMac and c.offer.signatures.len != 0:
      return "AM1M hello must not carry signature proofs"
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
##   AM1C / AM1S            AM1M
##   ------------------     ------------------
##   certificate body       pskId
##   authority proofs       one proof
##   one proof per slot
##
## Both are then padded under the same policy, so the two shapes are not
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
  ## c/a/descriptor/identity/clear: pick the one shape this mode uses.
  if a.mode == atmPskMac:
    return serverPskBlock(a, clear)
  result = serverCertificateBlock(c, descriptor, identity, clear)

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
  ## AM1M needs none of it, so a responder running it is not made to carry a
  ## certificate and a signature key it will never use.
  if a.mode == atmPskMac:
    if a.psk.len < 16 or a.pskId.len == 0:
      return "AME PSK authentication is not configured"
    return
  if descriptor.subject != identity.subject or
      not identityKeysEqual(descriptor.signingKeys, identity.signingKeys):
    return "server identity does not match its handshake descriptor"
  try:
    requireIdentityLayout(c.layout, identity)
    requireCertificateLayout(c.layout, descriptor)
  except ValueError as e:
    return e.msg

proc answerAmeHandshake*(c: AmeClientHello,
    supported: openArray[AmeTierPath], a: AmeAuthentication,
    descriptor: AmeIdentityCertificate = default(AmeIdentityCertificate),
    identity: AmeIdentityKey = default(AmeIdentityKey),
    params: AmeRuntimeParams = AmeRuntimeParams(authTagLen: aatl32)): tuple[
    ok: bool, state: AmeServerHandshake, err: string] {.role: orchestrator,
    tag: "appApi|exchange".} =
  ## c/supported/a/descriptor/identity/params: responder inputs. `a` decides
  ## whom this side will believe AND what it proves about itself; the
  ## certificate and identity key are needed only by AM1C and AM1S.
  ##
  ## `params` are the tunables the responder imposes on the first epoch -- tag
  ## length and whether payloads are padded. The client adopts them or gives
  ## up.
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
  ## A hello naming a mode this responder does not run is refused here, before
  ## any key work. Mirroring it instead would let a client choose which of our
  ## checks runs.
  if c.mode != a.mode:
    result.err = "client asked for an authentication mode this side does not run"
    return
  policyError = responderIdentityError(c, a, descriptor, identity)
  if policyError.len > 0:
    result.err = policyError
    return
  result.state.clientHello = c
  sealError = buildServerHello(result.state, a, identity, descriptor, params)
  if sealError.len > 0:
    result.err = sealError
    return
  result.state.localSignatureSecretKeys = copyByteStack(identity.secretKeys)
  result.ok = true

## ╭⟢ step 3: the client opens the answer and finishes

proc readServerBlockFields(A: openArray[uint8], a: AmeAuthentication,
    cursor: var int): AmeServerIdentityBlock {.inline, role: parser,
    tag: "validation".} =
  ## A/a/cursor: read the one shape this mode put in the block.
  if a.mode == atmPskMac:
    result.pskId = readCertString(A, cursor)
    result.proofs = readBlockProofs(A, cursor)
    return
  result.certificate = decodeCertificateSubject(A, cursor)
  result.certificate.authorityProofs = readBlockProofs(A, cursor)
  result.proofs = readBlockProofs(A, cursor)

proc openServerIdentity(S: AmeClientHandshake, h: AmeServerHello,
    a: AmeAuthentication, secrets: openArray[ByteSeq]): tuple[ok: bool,
    identityBlock: AmeServerIdentityBlock, err: string] {.role: orchestrator,
    tag: "cryptoBoundary|exchange".} =
  ## S/h/a/secrets: unseal what the server said it is, with the temporary key.
  var
    clear: ByteSeq = serverHelloClearSubject(S.hello, h)
    rows: seq[ByteSeq] = @[]
    material: ByteSeq = @[]
    opened: tuple[ok: bool, payload: ByteSeq] = (ok: false, payload: @[])
    cursor: int = 0
  try:
    rows = secretRows(S.hello.layout.kems, S.hello.initialTier.masks.kem,
      secrets)
    appendBinderRow(rows, a)
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
    result.identityBlock = readServerBlockFields(opened.payload, a, cursor)
    if cursor != opened.payload.len:
      return
  except ValueError:
    return
  result.err = ""
  result.ok = true

proc ameAuthenticationModeOf*(m: AmeTrustMode): AmeAuthenticationMode {.
    role: parser.} =
  ## m: the trust mode this side ran, named the way the statistics name it.
  case m
  of atmAuthorityCertificate: result = am1c
  of atmPinnedPeerKey: result = am1s
  of atmPskMac: result = am1m

proc exchangeAuthenticationKey(a: AmeAuthentication,
    transcript: openArray[uint8]): ByteSeq {.role: truthBuilder,
    tag: "cryptoBoundary|kdf".} =
  ## a/transcript: the key later epoch changes are proved with in AM1M.
  ##
  ## AM1M sessions hold no signature keys, so the offers and replies that
  ## rotate an epoch cannot be signed. They are tagged with this key instead.
  ## It is derived from the finished transcript, so it is different in every
  ## session and says nothing about the provisioned secret behind it.
  var subject: ByteSeq = @[]
  if a.mode != atmPskMac:
    return
  appendAmeLabel(subject, "AME-AM1M-EXCHANGE-AUTH-v1")
  appendHandshakeString(subject, a.pskId)
  appendHandshakeBytes(subject, transcript)
  result = ameMacTag(amaBlake3, a.psk, subject, 32)
  secureClearAmeBytes(subject)

proc exchangeBinderKey(a: AmeAuthentication,
    transcript: openArray[uint8]): ByteSeq {.role: truthBuilder,
    tag: "cryptoBoundary|kdf".} =
  ## a/transcript: what the PROVISIONED secret contributes to every key this
  ## session will ever derive.
  ##
  ## AM1M is handed a secret out of band, and until now that secret only ever
  ## proved who was speaking -- it never went anywhere near a traffic key. So a
  ## broken KEM took the whole session, and the secret the two sides had gone
  ## to the trouble of sharing beforehand did nothing to stop it.
  ##
  ## This is that secret's contribution. It is mixed into every KEM slot's
  ## accumulated stack, on the first exchange and on every rotation after it,
  ## so following the session forward needs the provisioned secret as well as
  ## every exchange.
  ##
  ## Bound to the transcript, so it is different in every session and says
  ## nothing about the secret behind it. Derived under its own label, so it is
  ## not the same bytes as `exchangeAuthenticationKey` -- one secret doing two
  ## jobs is how a proof about one of them quietly stops being a proof about
  ## the other.
  ##
  ## Empty in AM1C and AM1S. Those modes have no provisioned secret, and an
  ## empty binder changes nothing about the stack they build.
  var subject: ByteSeq = @[]
  if a.mode != atmPskMac:
    return
  appendAmeLabel(subject, "AME-PROVISIONED-BINDER-v1")
  appendHandshakeString(subject, a.pskId)
  appendHandshakeBytes(subject, transcript)
  result = ameMacTag(amaBlake3, a.psk, subject, 32)
  secureClearAmeBytes(subject)
proc buildInitialAuth(L: AmeSuiteLayout, initialTier: AmeMaskTier,
    request: AmeExchangeRequest,
    sharedSecrets: openArray[ByteSeq], transcript: openArray[uint8],
    sessionId: uint64, endpointRole: AmeEndpointRole,
    params: AmeRuntimeParams,
    a: AmeAuthentication): AmeAuthPackage {.role: truthBuilder,
    tag: "cryptoBoundary".} =
  ## L/tier/request/secrets/transcript/session/role/params/a: the first epoch.
  ## The transcript hash becomes the salt every later key hangs off, so two
  ## handshakes that agreed different things can never share a key.
  var
    exchange: AmeExchangeState = initAmeExchangeState(L.kems)
    binder: ByteSeq = exchangeBinderKey(a, transcript)
  ## The binder is built BEFORE the exchange is absorbed, because the very
  ## first stack has to contain it. A provisioned secret that only joined from
  ## the second rotation onward would leave the opening epoch resting on the
  ## KEM alone.
  applyAmeExchange(exchange, L, request, sharedSecrets, binder)
  result = initAmeAuthPackage(L, initialTier, exchange,
    hashAmeTier(L, initialTier, transcript, 32), 1'u32, sessionId,
    endpointRole, params)
  result.authenticationMode = ameAuthenticationModeOf(a.mode)
  result.exchangeAuthenticationKey = exchangeAuthenticationKey(a, transcript)
  result.exchangeBinder = binder

proc serverHelloPolicyError(S: AmeClientHandshake,
    h: AmeServerHello): string {.role: parser.} =
  ## S/h: cheap responder shape checks before any key work.
  try:
    if h.mode != S.hello.mode:
      return "server authentication mode does not match client hello"
    if h.nonce.len != ameHandshakeNonceLen or h.reply.signatures.len != 0 or
        h.reply.requestId == 0'u32 or
        h.authTag.len != int(ord(h.params.authTagLen)) or h.sealed.len == 0:
      return "server hello shape is invalid"
    discard encodeAmeExchangeReplySubject(S.hello.offer, h.reply)
  except ValueError as e:
    return e.msg

proc clientCertificateBlock(S: AmeClientHandshake,
    descriptor: AmeIdentityCertificate, identity: AmeIdentityKey,
    transcriptHash: openArray[uint8]): ByteSeq {.inline, role: truthBuilder,
    tag: "cryptoBoundary".} =
  ## S/descriptor/identity/transcriptHash: the certificate shape.
  var
    proofs: seq[ByteSeq] = signIdentityStack(S.hello.layout,
      S.hello.initialTier, transcriptHash, identity)
  appendAmeBytes(result, certificateSubject(descriptor))
  appendHandshakeProofs(result, descriptor.authorityProofs)
  appendHandshakeBytes(result, transcriptHash)
  appendHandshakeProofs(result, proofs)

proc clientPskBlock(a: AmeAuthentication,
    transcriptHash: openArray[uint8]): ByteSeq {.inline, role: truthBuilder,
    tag: "cryptoBoundary".} =
  ## a/transcriptHash: the shared-secret shape. The proof is taken over the
  ## transcript hash, which already covers the responder's sealed block, so
  ## this tag says "I saw exactly that exchange" and not merely "I hold the
  ## secret".
  var
    proof: ByteSeq = amePskTranscriptProof(a, apdInitiator, transcriptHash)
  appendHandshakeString(result, a.pskId)
  appendHandshakeBytes(result, transcriptHash)
  appendHandshakeProofs(result, @[proof])
  secureClearAmeBytes(proof)

proc clientIdentityBlockBytes(S: AmeClientHandshake, a: AmeAuthentication,
    descriptor: AmeIdentityCertificate, identity: AmeIdentityKey,
    transcriptHash: openArray[uint8]): ByteSeq {.inline, role: truthBuilder,
    tag: "cryptoBoundary".} =
  ## S/a/descriptor/identity/transcriptHash: pick the one shape this mode uses.
  if a.mode == atmPskMac:
    return clientPskBlock(a, transcriptHash)
  result = clientCertificateBlock(S, descriptor, identity, transcriptHash)

proc sealClientIdentity(S: AmeClientHandshake, h: AmeServerHello,
    a: AmeAuthentication, secrets: openArray[ByteSeq],
    descriptor: AmeIdentityCertificate,
    identity: AmeIdentityKey, transcript: openArray[uint8]): tuple[
    ok: bool, finish: AmeClientFinish, err: string] {.role: orchestrator,
    tag: "cryptoBoundary|exchange".} =
  ## S/h/a/secrets/descriptor/identity/transcript: seal what this side is, and
  ## its proof of the whole exchange, under the client-to-server key.
  var
    full: ByteSeq = serverHelloFullSubject(S.hello, h)
    rows: seq[ByteSeq] = @[]
    material: ByteSeq = @[]
    body: ByteSeq = @[]
    transcriptHash: ByteSeq = @[]
    sealed: tuple[ciphertext: ByteSeq, authTag: ByteSeq] = (
      ciphertext: @[], authTag: @[])
  transcriptHash = hashAmeTier(S.hello.layout, S.hello.initialTier,
    transcript, 32)
  body = clientIdentityBlockBytes(S, a, descriptor, identity, transcriptHash)
  body = padAmeMessage(body, h.params.padding)
  try:
    rows = secretRows(S.hello.layout.kems, S.hello.initialTier.masks.kem,
      secrets)
    appendBinderRow(rows, a)
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

proc judgeServerPskBlock(a: AmeAuthentication, B: AmeServerIdentityBlock,
    clear: openArray[uint8]): AmePeerTrustResult {.inline, role: parser,
    tag: "cryptoBoundary|validation".} =
  ## a/B/clear: the AM1M verdict. Exactly one proof, over exactly the bytes
  ## this side rebuilt for itself.
  result = pskPeerTrust(a, B.pskId)
  if not result.ok:
    return
  if B.proofs.len != 1 or
      not verifyAmePskTranscript(a, apdResponder, clear, B.proofs[0]):
    result = default(AmePeerTrustResult)
    result.err = "server shared-secret proof is invalid"

proc judgeServerCertificateBlock(S: AmeClientHandshake, a: AmeAuthentication,
    B: AmeServerIdentityBlock, clear: openArray[uint8], nowUnix: int64,
    revokedSerials: openArray[uint64]): AmePeerTrustResult {.inline,
    role: orchestrator, tag: "cryptoBoundary|validation".} =
  ## S/a/B/clear/nowUnix/revoked: the AM1C and AM1S verdict.
  try:
    requireCertificateLayout(S.hello.layout, B.certificate)
  except ValueError as e:
    result.err = e.msg
    return
  if a.mode == atmAuthorityCertificate:
    result = verifyAmeIdentityCertificate(B.certificate, a.root, nowUnix,
      revokedSerials)
    result.mode = am1c
  else:
    result = verifyPinnedPeerIdentity(B.certificate, a.expectedPeer, nowUnix)
    result.mode = am1s
  if not result.ok:
    return
  try:
    if not verifyIdentityStack(S.hello.layout, S.hello.initialTier, clear,
        B.proofs, B.certificate):
      result = default(AmePeerTrustResult)
      result.err = "server hello identity proof is invalid"
  except CatchableError as e:
    result = default(AmePeerTrustResult)
    result.err = "server hello proof failed: " & e.msg

proc judgeServerBlock(S: AmeClientHandshake, a: AmeAuthentication,
    B: AmeServerIdentityBlock, clear: openArray[uint8], nowUnix: int64,
    revokedSerials: openArray[uint64]): AmePeerTrustResult {.inline,
    role: orchestrator, tag: "cryptoBoundary|validation".} =
  ## S/a/B/clear/nowUnix/revoked: one verdict, whichever mode produced it.
  if a.mode == atmPskMac:
    return judgeServerPskBlock(a, B, clear)
  result = judgeServerCertificateBlock(S, a, B, clear, nowUnix, revokedSerials)

proc finishAmeHandshakeCore(S: AmeClientHandshake, h: AmeServerHello,
    a: AmeAuthentication, descriptor: AmeIdentityCertificate,
    identity: AmeIdentityKey, nowUnix: int64,
    revokedSerials: openArray[uint64]): AmeHandshakeResult {.
    role: orchestrator, tag: "cryptoBoundary|exchange".} =
  ## S/h/a/descriptor/identity/nowUnix/revoked: open what the server said it
  ## is, judge it, then answer with what we are.
  ##
  ## Order matters and is not negotiable: the block is opened FIRST and judged
  ## SECOND. Judging a block that has not been read yet reads default values
  ## and can only ever produce one answer.
  var
    policyError: string = serverHelloPolicyError(S, h)
    secrets: seq[ByteSeq] = @[]
    identityBlock: tuple[ok: bool, identityBlock: AmeServerIdentityBlock,
      err: string] = (ok: false,
      identityBlock: default(AmeServerIdentityBlock), err: "")
    transcript: ByteSeq = @[]
    clear: ByteSeq = @[]
    finish: tuple[ok: bool, finish: AmeClientFinish, err: string] = (
      ok: false, finish: default(AmeClientFinish), err: "")
  if policyError.len > 0:
    result.err = policyError
    return
  if h.mode != a.mode:
    result.err = "server answered in a different authentication mode"
    return
  try:
    secrets = openAmeExchangeReply(S.hello.layout.kems, S.hello.offer,
      h.reply, S.secretKeys)
  except CatchableError as e:
    result.err = "server hello exchange failed: " & e.msg
    return
  identityBlock = openServerIdentity(S, h, a, secrets)
  if not identityBlock.ok:
    result.err = identityBlock.err
    return
  clear = serverHelloClearSubject(S.hello, h)
  result.peerTrust = judgeServerBlock(S, a, identityBlock.identityBlock,
    clear, nowUnix, revokedSerials)
  secureClearAmeBytes(clear)
  if not result.peerTrust.ok:
    result.err = result.peerTrust.err
    return
  transcript = handshakeTranscript(S.hello, h)
  finish = sealClientIdentity(S, h, a, secrets, descriptor, identity,
    transcript)
  if not finish.ok:
    result.err = finish.err
    return
  result.finish = finish.finish
  result.auth = buildInitialAuth(S.hello.layout, S.hello.initialTier,
    h.reply.request, secrets, transcript, S.hello.sessionId, aerInitiator,
    h.params, a)
  result.auth.localSignatureSecretKeys = copyByteStack(identity.secretKeys)
  for key in identityBlock.identityBlock.certificate.signingKeys:
    result.auth.peerSignaturePublicKeys.add(key.publicKey & @[])
  result.ok = true

## ╭⟢ step 4: the server opens the finish

proc readClientBlockFields(A: openArray[uint8], a: AmeAuthentication,
    cursor: var int): AmeClientIdentityBlock {.inline, role: parser,
    tag: "validation".} =
  ## A/a/cursor: read the one shape this mode put in the block.
  if a.mode == atmPskMac:
    result.pskId = readCertString(A, cursor)
    result.transcriptHash = readCertField(A, cursor, 1024'u32)
    result.proofs = readBlockProofs(A, cursor)
    return
  result.certificate = decodeCertificateSubject(A, cursor)
  result.certificate.authorityProofs = readBlockProofs(A, cursor)
  result.transcriptHash = readCertField(A, cursor, 1024'u32)
  result.proofs = readBlockProofs(A, cursor)

proc judgeClientPskBlock(a: AmeAuthentication,
    B: AmeClientIdentityBlock): AmePeerTrustResult {.inline, role: parser,
    tag: "cryptoBoundary|validation".} =
  ## a/B: the AM1M verdict on the client's block. The transcript hash it
  ## carries is compared by the caller first, so proving it also proves the
  ## exchange.
  result = pskPeerTrust(a, B.pskId)
  if not result.ok:
    return
  if B.proofs.len != 1 or
      not verifyAmePskTranscript(a, apdInitiator, B.transcriptHash,
        B.proofs[0]):
    result = default(AmePeerTrustResult)
    result.err = "client shared-secret proof is invalid"

proc judgeClientCertificateBlock(S: AmeServerHandshake, a: AmeAuthentication,
    B: AmeClientIdentityBlock, nowUnix: int64,
    revokedSerials: openArray[uint64]): AmePeerTrustResult {.inline,
    role: orchestrator, tag: "cryptoBoundary|validation".} =
  ## S/a/B/nowUnix/revoked: the AM1C and AM1S verdict on the client's block.
  try:
    requireCertificateLayout(S.clientHello.layout, B.certificate)
  except ValueError as e:
    result.err = "client finish block is malformed: " & e.msg
    return
  if a.mode == atmAuthorityCertificate:
    result = verifyAmeIdentityCertificate(B.certificate, a.root, nowUnix,
      revokedSerials)
    result.mode = am1c
  else:
    result = verifyPinnedPeerIdentity(B.certificate, a.expectedPeer, nowUnix)
    result.mode = am1s
  if not result.ok:
    return
  try:
    if not verifyIdentityStack(S.clientHello.layout, S.clientHello.initialTier,
        B.transcriptHash, B.proofs, B.certificate):
      result = default(AmePeerTrustResult)
      result.err = "client finish identity proof is invalid"
  except CatchableError as e:
    result = default(AmePeerTrustResult)
    result.err = "client finish verification failed: " & e.msg

proc judgeClientBlock(S: AmeServerHandshake, a: AmeAuthentication,
    B: AmeClientIdentityBlock, nowUnix: int64,
    revokedSerials: openArray[uint64]): AmePeerTrustResult {.inline,
    role: orchestrator, tag: "cryptoBoundary|validation".} =
  ## S/a/B/nowUnix/revoked: one verdict, whichever mode produced it.
  if a.mode == atmPskMac:
    return judgeClientPskBlock(a, B)
  result = judgeClientCertificateBlock(S, a, B, nowUnix, revokedSerials)

proc acceptAmeHandshakeCore(S: AmeServerHandshake, f: AmeClientFinish,
    a: AmeAuthentication, nowUnix: int64,
    revokedSerials: openArray[uint64]): AmeHandshakeResult {.
    role: orchestrator, tag: "cryptoBoundary|exchange".} =
  ## S/f/a/nowUnix/revoked: responder state and the client's sealed
  ## confirmation.
  ##
  ## Only here does the server learn who the client is. Nothing before this
  ## point produced a session, so a peer that cannot open this block, or whose
  ## identity does not check out, leaves no trace but a dropped connection.
  var
    full: ByteSeq = @[]
    rows: seq[ByteSeq] = @[]
    material: ByteSeq = @[]
    opened: tuple[ok: bool, payload: ByteSeq] = (ok: false, payload: @[])
    body: AmeClientIdentityBlock = default(AmeClientIdentityBlock)
    cursor: int = 0
    transcript: ByteSeq = @[]
    expected: ByteSeq = @[]
  if f.authTag.len != int(ord(S.serverHello.params.authTagLen)) or
      f.params != S.serverHello.params or f.sealed.len == 0:
    result.err = "client finish shape is invalid"
    return
  full = serverHelloFullSubject(S.clientHello, S.serverHello)
  try:
    rows = secretRows(S.clientHello.layout.kems,
      S.clientHello.initialTier.masks.kem, S.sharedSecrets)
    appendBinderRow(rows, a)
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
    body = readClientBlockFields(opened.payload, a, cursor)
    if cursor != opened.payload.len:
      result.err = "client finish block is malformed"
      return
  except ValueError as e:
    result.err = "client finish block is malformed: " & e.msg
    return
  ## The transcript hash is checked BEFORE the proof over it, so a proof is
  ## only ever judged against bytes this side already agreed to.
  transcript = handshakeTranscript(S.clientHello, S.serverHello)
  expected = hashAmeTier(S.clientHello.layout, S.clientHello.initialTier,
    transcript, 32)
  if not constantTimeEqualAme(body.transcriptHash, expected):
    result.err = "client finish transcript does not match"
    return
  result.peerTrust = judgeClientBlock(S, a, body, nowUnix, revokedSerials)
  if not result.peerTrust.ok:
    result.err = result.peerTrust.err
    return
  result.auth = buildInitialAuth(S.clientHello.layout,
    S.clientHello.initialTier, S.serverHello.reply.request,
    S.sharedSecrets, transcript, S.clientHello.sessionId, aerResponder,
    S.serverHello.params, a)
  result.auth.localSignatureSecretKeys = copyByteStack(
    S.localSignatureSecretKeys)
  for key in body.certificate.signingKeys:
    result.auth.peerSignaturePublicKeys.add(key.publicKey & @[])
  result.ok = true

## ╭⟢ erasing what is finished with

proc clearAmeClientHandshake*(S: var AmeClientHandshake) {.
    role: actor.} =
  ## S: initial KEM private keys and retained public handshake state to erase.
  var
    i: int = 0
  while i < S.secretKeys.len:
    secureClearAmeBytes(S.secretKeys[i])
    i = i + 1
  S = default(AmeClientHandshake)

proc clearAmeServerHandshake*(S: var AmeServerHandshake) {.
    role: actor.} =
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
    a: AmeAuthentication,
    descriptor: AmeIdentityCertificate = default(AmeIdentityCertificate),
    identity: AmeIdentityKey = default(AmeIdentityKey),
    nowUnix: int64 = 0'i64,
    revokedSerials: openArray[uint64] = []): AmeHandshakeResult {.
    role: orchestrator, tag: "appApi".} =
  ## S/h/a/descriptor/identity/nowUnix/revoked: the initiator's third step, in
  ## whichever mode `a` names. The certificate and identity key are used by
  ## AM1C and AM1S only; AM1M leaves them at their defaults.
  ##
  ## The client's KEM secrets are erased whatever the outcome.
  try:
    result = finishAmeHandshakeCore(S, h, a, descriptor, identity, nowUnix,
      revokedSerials)
  finally:
    clearAmeClientHandshake(S)

proc acceptAmeHandshake*(S: var AmeServerHandshake, f: AmeClientFinish,
    a: AmeAuthentication, nowUnix: int64 = 0'i64,
    revokedSerials: openArray[uint64] = []): AmeHandshakeResult {.
    role: orchestrator, tag: "appApi".} =
  ## S/f/a/nowUnix/revoked: the responder's fourth step, in whichever mode `a`
  ## names. The responder's own secrets are erased whatever the outcome.
  try:
    result = acceptAmeHandshakeCore(S, f, a, nowUnix, revokedSerials)
  finally:
    clearAmeServerHandshake(S)
