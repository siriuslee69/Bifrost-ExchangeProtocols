## -------------------------------------------------------------------------
## AME Handshake Transcript <- the running record of everything that was said
## -------------------------------------------------------------------------
##
## ╭─ ❧ the whole idea in one picture 🌊
##
## Both sides write down every word of the conversation, in the same order,
## byte for byte. Everything each side signs, and everything the temporary
## keys are derived from, is that record:
##
##   client nonce | slot layout | KEM public keys | cookie
##   server nonce | KEM answer  | chosen params
##            \___________  ____________/
##                        \/
##              one byte string, built the same way on both sides
##                        |
##          +-------------+--------------+
##          |                            |
##   what each side SIGNS         what the temporary
##   to prove it was there        keys are derived from
##
## If any field differed -- a swapped nonce, an edited slot layout, a
## downgraded tier, a cookie moved from another session -- the two records
## diverge, and then EVERY later check fails at once. There is no field a
## meddler can change quietly, because there is no field outside the record.
##
## ╭─ ❧ the shared-secret proofs (AM1M) ⟡
##
## In the shared-secret mode there are no certificates and no signature keys.
## What each side sends instead is a tag over that same record, computed with
## the secret:
##
##   responder proves   tag(psk, "…RESPONDER…" + transcript)
##   initiator proves   tag(psk, "…INITIATOR…" + transcript)
##
## The direction is inside the tagged bytes, which is the point: without it
## the two proofs would be tags over the same string, and a responder's proof
## could be replayed straight back as an initiator's.

import ../../types
import ../types
import ../level0/bytes
import ../level1/exchange_paths
import ../level1/suites
import ../level1/symmetric
import ../level1/padding
import ../level1/tier_aead
import ./handshake_identity
import ./handshake_records
import ../../fomke/level0/gb3hkdf
import runePragmas

proc amePskTranscriptProof*(a: AmeAuthentication, d: AmePskProofDirection,
    transcript: openArray[uint8]): ByteSeq {.role: truthBuilder,
    tag: "cryptoBoundary".} =
  ## a/d/transcript: which end is proving, and the bytes it is proving over.
  ##
  ## The direction byte is inside the tagged subject, so the two proofs of one
  ## handshake are tags over byte strings that differ before the transcript is
  ## even reached. Neither can stand in for the other.
  var subject: ByteSeq = @[]
  if a.mode != atmPskMac or a.psk.len < 16:
    raise newException(ValueError, "AME PSK authentication is not configured")
  appendAmeLabel(subject, "AME-AM1M-TRANSCRIPT-v2")
  subject.add(uint8(ord(d)))
  appendHandshakeString(subject, a.pskId)
  appendHandshakeBytes(subject, transcript)
  result = ameMacTag(amaBlake3, a.psk, subject, 32)
  secureClearAmeBytes(subject)

proc amePskExchangeBinder*(a: AmeAuthentication): ByteSeq {.
    role: truthBuilder, tag: "cryptoBoundary|kdf".} =
  ## a: provisioned shared secret turned into ONE key-schedule input.
  ##
  ## This is what makes AM1M worth having. The proof above only says who is
  ## talking; the binder goes into the same pot as the KEM secrets, so the
  ## temporary keys depend on the shared secret as well. An attacker who
  ## breaks every KEM slot still cannot open the sealed blocks without it.
  ##
  ##   AM1C / AM1S :  keys <- [ KEM slot 0 | KEM slot 1 | ... ]
  ##   AM1M        :  keys <- [ KEM slot 0 | KEM slot 1 | ... | binder ]
  ##
  ## The provisioned secret itself never enters the derivation, so a leaked
  ## key block says nothing about the secret that is reused across sessions.
  var subject: ByteSeq = @[]
  if a.mode != atmPskMac or a.psk.len < 16:
    raise newException(ValueError, "AME PSK authentication is not configured")
  appendAmeLabel(subject, "AME-AM1M-BINDER-v1")
  appendHandshakeString(subject, a.pskId)
  result = ameMacTag(amaBlake3, a.psk, subject, 32)
  secureClearAmeBytes(subject)

proc ameHandshakeBinder(a: AmeAuthentication): ByteSeq {.role: helper,
    tag: "cryptoBoundary|kdf".} =
  ## a: the extra secret row this mode contributes, empty for AM1C and AM1S.
  if a.mode != atmPskMac:
    return
  result = amePskExchangeBinder(a)

proc verifyAmePskTranscript*(a: AmeAuthentication, d: AmePskProofDirection,
    transcript, proof: openArray[uint8]): bool {.role: parser,
    tag: "cryptoBoundary|validation".} =
  ## a/d/transcript/proof: constant-time check of one directional proof.
  var expected: ByteSeq = amePskTranscriptProof(a, d, transcript)
  result = constantTimeEqualAme(expected, proof)
  secureClearAmeBytes(expected)

proc pskPeerTrust*(a: AmeAuthentication, peerId: string): AmePeerTrustResult {.
    role: truthBuilder.} =
  ## a/peerId: the trust verdict an opened AM1M block earns. The name the peer
  ## sealed must be the name this side provisioned, so one machine holding
  ## several shared secrets cannot be talked into judging by the wrong one.
  if peerId.len == 0 or peerId != a.pskId:
    result.err = "peer named a different shared secret"
    return
  result.ok = true
  result.mode = am1m
  result.authority = "shared-secret"
  result.subjectKeyId = a.pskId

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
  result.add(uint8(ord(h.mode)))
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
  result.add(uint8(ord(s.mode)))
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

proc handshakeKeyMaterial*(L: AmeSuiteLayout, t: AmeMaskTier,
    S: openArray[ByteSeq], transcript: openArray[uint8],
    label: string): ByteSeq {.role: truthBuilder,
    tag: "cryptoBoundary|kdf".} =
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

proc secretRows*(A: AmeKemAlgorithms, mask: uint8,
    S: openArray[ByteSeq]): seq[ByteSeq] {.role: truthBuilder,
    tag: "cryptoBoundary".} =
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

proc clearSecretRows*(S: var seq[ByteSeq]) {.role: actor.} =
  ## S: framed secret rows erased once they have been consumed.
  var
    i: int = 0
  while i < S.len:
    secureClearAmeBytes(S[i])
    i = i + 1
  S.setLen(0)

proc appendBinderRow*(R: var seq[ByteSeq], a: AmeAuthentication) {.
    role: dataWriter, tag: "cryptoBoundary|kdf".} =
  ## R/a: add this mode's extra secret row, if it has one.
  ##
  ## AM1C and AM1S add nothing, so their key schedule is byte for byte what
  ## it always was. AM1M adds one framed row after the last KEM slot. Callers
  ## already erase every row through `clearSecretRows`, so this row is erased
  ## on exactly the same path.
  var
    row: ByteSeq = @[]
    binder: ByteSeq = ameHandshakeBinder(a)
  if binder.len == 0:
    return
  appendAmeLabel(row, "AME-HANDSHAKE-BINDER-v1")
  appendHandshakeBytes(row, binder)
  R.add(row)
  secureClearAmeBytes(binder)
