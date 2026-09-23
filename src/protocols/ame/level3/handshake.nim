## -------------------------------------------------------------------------
## AME Handshake <- the four messages, and what each side says in them
## -------------------------------------------------------------------------
##
## Four messages, at most. Reading left to right is the whole protocol:
##
##   client                                                   server
##     |                                                         |
##     |--- hello: nonce, slot layout, KEM public keys ---------->|
##     |        (sealed under the shared secret in AM1P, AM1P+S) |
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
## Seven neighbours, so that this one is only ever about the conversation. Each
## answers one question completely, and you can read any of them on its own:
##
##   handshake_identity.nim    who someone is: identities, certificates and
##                             how each one is checked.
##   handshake_authentication.nim  whom this side believes: the four modes
##                             and the one AmeAuthentication object.
##   handshake_hello.nim       steps 1 and 2: the (sealed) hello and the
##                             server's answer.
##   handshake_cookie.nim      proving you can receive where you claim to be,
##                             and why the server remembers nothing about it.
##   handshake_records.nim     the SHAPE of the four messages. Types only.
##   handshake_wire.nim        those same four, byte for byte.
##   handshake_transcript.nim  the running record both sides sign, the
##                             shared-secret proofs taken over it, and the
##                             sealed hello of the pre-shared modes.
##
## What IS here: steps 3 and 4, and the calls a caller actually makes to
## finish and accept. Steps 1 and 2 are in `handshake_hello.nim`.
## Importing this file gives you all seven as well, so the split costs a
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

import ../../types
import ../types
import ../level0/bytes
import ../level1/exchange_paths
import ../level1/secret_stack
import ../level1/suites
import ../level1/symmetric
import ../level1/tier_aead
import ../level1/padding
import ../level2/framing
import ./handshake_authentication
import ./handshake_cookie
import ./handshake_records
import ./handshake_transcript
import ./handshake_hello
import runePragmas

## A caller reaches for one import and gets the whole handshake: the identity
## vocabulary, the cookie, the four record shapes and the transcript. The
## split is for reading, not for making anyone assemble it themselves.
export handshake_authentication, handshake_cookie, handshake_records,
  handshake_hello,
  handshake_transcript


## ╭⟢ step 3: the client opens the answer and finishes

proc readServerBlockFields(A: openArray[uint8], a: AmeAuthentication,
    cursor: var int): AmeServerIdentityBlock {.inline, role: parser,
    tag: "validation".} =
  ## A/a/cursor: read the halves this mode put in the block, in the order
  ## `serverIdentityBlockBytes` wrote them.
  if ameModeUsesPsk(a.mode):
    result.pskId = readCertString(A, cursor)
    result.pskProofs = readBlockProofs(A, cursor)
  if not ameModeUsesSignatures(a.mode):
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
  of atmAuthorityCertificate: result = am1a
  of atmPinnedPeerKey: result = am1s
  of atmPreSharedKey: result = am1p
  of atmPreSharedPinned: result = am1ps

proc exchangeAuthenticationKey(a: AmeAuthentication,
    transcript: openArray[uint8]): ByteSeq {.role: truthBuilder,
    tag: "cryptoBoundary|kdf".} =
  ## a/transcript: the key later epoch changes are proved with in AM1P.
  ##
  ## AM1P sessions hold no signature keys, so the offers and replies that
  ## rotate an epoch cannot be signed. They are tagged with this key instead.
  ## It is derived from the finished transcript, so it is different in every
  ## session and says nothing about the provisioned secret behind it.
  ##
  ## Empty in AM1P+S: that mode holds signature keys, so its rotations are
  ## signed exactly like AM1S ones.
  var
    subject: ByteSeq = @[]
    key: ByteSeq = @[]
  if a.mode != atmPreSharedKey:
    return
  key = amePskKeyInput(a)
  appendAmeLabel(subject, "AME-AM1P-EXCHANGE-AUTH-v2")
  appendHandshakeString(subject, a.pskId)
  appendHandshakeBytes(subject, transcript)
  result = ameMacTag(amaBlake3, key, subject, 32)
  secureClearAmeBytes(subject)
  secureClearAmeBytes(key)

proc exchangeBinderKey(a: AmeAuthentication,
    transcript: openArray[uint8]): ByteSeq {.role: truthBuilder,
    tag: "cryptoBoundary|kdf".} =
  ## a/transcript: what the PROVISIONED secret (and the carried next secret,
  ## when the hello used one) contributes to every key this session will
  ## ever derive.
  ##
  ## It is mixed into every KEM slot's accumulated stack, on the first
  ## exchange and on every rotation after it, so following the session
  ## forward needs the provisioned secret as well as every exchange. A broken
  ## KEM alone therefore does not take the session.
  ##
  ## Bound to the transcript, so it is different in every session and says
  ## nothing about the secret behind it. Derived under its own label, so it is
  ## not the same bytes as `exchangeAuthenticationKey` -- one secret doing two
  ## jobs is how a proof about one of them quietly stops being a proof about
  ## the other.
  ##
  ## Empty in AM1A and AM1S. Those modes have no provisioned secret, and an
  ## empty binder changes nothing about the stack they build.
  var
    subject: ByteSeq = @[]
    key: ByteSeq = @[]
  if not ameModeUsesPsk(a.mode):
    return
  key = amePskKeyInput(a)
  appendAmeLabel(subject, "AME-PROVISIONED-BINDER-v2")
  appendHandshakeString(subject, a.pskId)
  appendHandshakeBytes(subject, transcript)
  result = ameMacTag(amaBlake3, key, subject, 32)
  secureClearAmeBytes(subject)
  secureClearAmeBytes(key)

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

## What goes inside the client's sealed block, by mode. One fixed order, and
## each mode simply leaves out the halves it does not use:
##
##   field                    AM1A/AM1S   AM1P   AM1P+S
##   -----------------------  ---------   ----   ------
##   pskId + psk proof            -        yes     yes
##   certificate + authority     yes        -      yes
##   transcript hash             yes       yes     yes
##   one signature per slot      yes        -      yes

proc clientIdentityBlockBytes(S: AmeClientHandshake, a: AmeAuthentication,
    descriptor: AmeIdentityCertificate, identity: AmeIdentityKey,
    transcriptHash: openArray[uint8]): ByteSeq {.inline, role: truthBuilder,
    tag: "cryptoBoundary".} =
  ## S/a/descriptor/identity/transcriptHash: the halves this mode uses. Every
  ## proof is taken over the transcript hash, which already covers the
  ## responder's sealed block, so each says "I saw exactly that exchange"
  ## and not merely "I hold the key".
  var
    pskProof: ByteSeq = @[]
    proofs: seq[ByteSeq] = @[]
  if ameModeUsesPsk(a.mode):
    pskProof = amePskTranscriptProof(a, apdInitiator, transcriptHash)
    appendHandshakeString(result, a.pskId)
    appendHandshakeProofs(result, @[pskProof])
    secureClearAmeBytes(pskProof)
  if ameModeUsesSignatures(a.mode):
    appendAmeBytes(result, certificateSubject(descriptor))
    appendHandshakeProofs(result, descriptor.authorityProofs)
  appendHandshakeBytes(result, transcriptHash)
  if ameModeUsesSignatures(a.mode):
    proofs = signIdentityStack(S.hello.layout, S.hello.initialTier,
      transcriptHash, identity)
    appendHandshakeProofs(result, proofs)

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

## ╭⟢ judging a peer's block
##
## One verdict per half, and a mode that uses both halves needs both:
##
##   AM1A   certificate verdict (authority)
##   AM1S   certificate verdict (pinned key)
##   AM1P   shared-secret verdict
##   AM1P+S shared-secret verdict ─▶ only if ok ─▶ certificate verdict (pinned)
##
## The certificate and shared-secret halves are the same for both ends; only
## the bytes the proofs are taken over differ (the clear server hello for the
## responder, the transcript hash for the initiator).

proc pskHalfVerdict(a: AmeAuthentication, pskId: string,
    P: openArray[ByteSeq], d: AmePskProofDirection,
    subject: openArray[uint8]): AmePeerTrustResult {.inline, role: parser,
    tag: "cryptoBoundary|validation".} =
  ## a/pskId/P/d/subject: the shared-secret half. Exactly one proof, over
  ## exactly the bytes this side rebuilt for itself.
  result = pskPeerTrust(a, pskId)
  if not result.ok:
    return
  if P.len != 1 or not verifyAmePskTranscript(a, d, subject, P[0]):
    result = default(AmePeerTrustResult)
    result.err = "peer shared-secret proof is invalid"

proc certificateHalfVerdict(L: AmeSuiteLayout, t: AmeMaskTier,
    a: AmeAuthentication, C: AmeIdentityCertificate,
    P: openArray[ByteSeq], subject: openArray[uint8], nowUnix: int64,
    revokedSerials: openArray[uint64]): AmePeerTrustResult {.inline,
    role: orchestrator, tag: "cryptoBoundary|validation".} =
  ## L/t/a/C/P/subject/nowUnix/revoked: the certificate half. AM1A asks the
  ## authority; AM1S and AM1P+S compare against the pinned key. Then every
  ## active signature slot must have signed `subject`.
  try:
    requireCertificateLayout(L, C)
  except ValueError as e:
    result.err = "peer certificate is malformed: " & e.msg
    return
  if a.mode == atmAuthorityCertificate:
    result = verifyAmeIdentityCertificate(C, a.root, nowUnix, revokedSerials)
    result.mode = am1a
  else:
    result = verifyPinnedPeerIdentity(C, a.expectedPeer, nowUnix)
    result.mode = am1s
  if not result.ok:
    return
  try:
    if not verifyIdentityStack(L, t, subject, P, C):
      result = default(AmePeerTrustResult)
      result.err = "peer identity proof is invalid"
  except CatchableError as e:
    result = default(AmePeerTrustResult)
    result.err = "peer identity proof failed: " & e.msg

proc peerVerdict(L: AmeSuiteLayout, t: AmeMaskTier, a: AmeAuthentication,
    pskId: string, pskProofs: openArray[ByteSeq], d: AmePskProofDirection,
    C: AmeIdentityCertificate, P: openArray[ByteSeq],
    subject: openArray[uint8], nowUnix: int64,
    revokedSerials: openArray[uint64]): AmePeerTrustResult {.
    role: orchestrator, tag: "cryptoBoundary|validation".} =
  ## One verdict for whichever mode `a` runs, from the halves it uses.
  if ameModeUsesPsk(a.mode):
    result = pskHalfVerdict(a, pskId, pskProofs, d, subject)
    if not result.ok or not ameModeUsesSignatures(a.mode):
      return
  result = certificateHalfVerdict(L, t, a, C, P, subject, nowUnix,
    revokedSerials)
  if result.ok:
    result.mode = ameAuthenticationModeOf(a.mode)

proc judgeServerBlock(S: AmeClientHandshake, a: AmeAuthentication,
    B: AmeServerIdentityBlock, clear: openArray[uint8], nowUnix: int64,
    revokedSerials: openArray[uint64]): AmePeerTrustResult {.inline,
    role: orchestrator, tag: "cryptoBoundary|validation".} =
  ## S/a/B/clear/nowUnix/revoked: the responder's block, proved over the
  ## clear part of the server hello.
  result = peerVerdict(S.hello.layout, S.hello.initialTier, a, B.pskId,
    B.pskProofs, apdResponder, B.certificate, B.proofs, clear, nowUnix,
    revokedSerials)

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
  ## A/a/cursor: read the halves this mode put in the block, in the order
  ## `clientIdentityBlockBytes` wrote them.
  if ameModeUsesPsk(a.mode):
    result.pskId = readCertString(A, cursor)
    result.pskProofs = readBlockProofs(A, cursor)
  if ameModeUsesSignatures(a.mode):
    result.certificate = decodeCertificateSubject(A, cursor)
    result.certificate.authorityProofs = readBlockProofs(A, cursor)
  result.transcriptHash = readCertField(A, cursor, 1024'u32)
  if ameModeUsesSignatures(a.mode):
    result.proofs = readBlockProofs(A, cursor)

proc judgeClientBlock(S: AmeServerHandshake, a: AmeAuthentication,
    B: AmeClientIdentityBlock, nowUnix: int64,
    revokedSerials: openArray[uint64]): AmePeerTrustResult {.inline,
    role: orchestrator, tag: "cryptoBoundary|validation".} =
  ## S/a/B/nowUnix/revoked: the initiator's block, proved over the
  ## transcript hash. The caller has already compared that hash with its
  ## own, so proving it also proves the whole exchange.
  result = peerVerdict(S.clientHello.layout, S.clientHello.initialTier, a,
    B.pskId, B.pskProofs, apdInitiator, B.certificate, B.proofs,
    B.transcriptHash, nowUnix, revokedSerials)

proc acceptAmeHandshakeCore(S: AmeServerHandshake, f: AmeClientFinish,
    nowUnix: int64,
    revokedSerials: openArray[uint64]): AmeHandshakeResult {.
    role: orchestrator, tag: "cryptoBoundary|exchange".} =
  ## S/f/nowUnix/revoked: responder state and the client's sealed
  ## confirmation. The authentication used is the one the responder matched
  ## to the hello (`S.authentication`), so both ends derive from the same
  ## secrets -- including whether the next secret took part.
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
    a: AmeAuthentication = S.authentication
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
  ## S: initial shared secrets, copied local identity keys, and the copy of
  ## the authentication (shared secret, next secret) to erase.
  var
    i: int = 0
  while i < S.sharedSecrets.len:
    secureClearAmeBytes(S.sharedSecrets[i])
    i = i + 1
  i = 0
  while i < S.localSignatureSecretKeys.len:
    secureClearAmeBytes(S.localSignatureSecretKeys[i])
    i = i + 1
  clearAmeAuthentication(S.authentication)
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
  ## AM1A, AM1S and AM1P+S only; AM1P leaves them at their defaults.
  ##
  ## The client's KEM secrets are erased whatever the outcome.
  try:
    result = finishAmeHandshakeCore(S, h, a, descriptor, identity, nowUnix,
      revokedSerials)
  finally:
    clearAmeClientHandshake(S)

proc acceptAmeHandshake*(S: var AmeServerHandshake, f: AmeClientFinish,
    nowUnix: int64 = 0'i64,
    revokedSerials: openArray[uint64] = []): AmeHandshakeResult {.
    role: orchestrator, tag: "appApi".} =
  ## S/f/nowUnix/revoked: the responder's fourth step. The mode and secrets
  ## are the ones `answerAmeHandshake` settled on and stored in `S`, so no
  ## authentication is passed again here. The responder's own secrets are
  ## erased whatever the outcome.
  try:
    result = acceptAmeHandshakeCore(S, f, nowUnix, revokedSerials)
  finally:
    clearAmeServerHandshake(S)
