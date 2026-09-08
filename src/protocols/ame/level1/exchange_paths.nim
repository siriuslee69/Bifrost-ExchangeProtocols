## -------------------------------------------------------------------------
## AME Exchange Paths <- immutable KEM slots and target-tier transactions
## -------------------------------------------------------------------------

import ../../types
import ../types
import ../level0/bytes
import ./padding
import ./algorithms
import ../../../analysis_pragmas

const
  ameMaxExchangeComponentLen* = 16_777_216'u32
  ameExchangeRequestLen* = 13

proc slotMask*(i: int): uint8 {.role: helper.} =
  ## i: zero-based path slot. Slot 0 is the most-significant bit.
  if i < 0 or i >= ameMaxAlgorithmSlots:
    raise newException(ValueError, "AME algorithm slot must be in 0..7")
  result = 1'u8 shl (ameMaxAlgorithmSlots - 1 - i)

proc algorithmSlotSelected*(m: uint8, i: int): bool {.role: parser.} =
  ## m/i: MSB-first mask and zero-based path slot.
  result = (m and slotMask(i)) != 0'u8

proc validAmeKemMask*(A: AmeKemAlgorithms): uint8 {.role: helper.} =
  ## A: layout whose occupied slots become one MSB-first mask.
  var i: int = 0
  while i < int(A.length):
    result = result or slotMask(i)
    i = i + 1

proc initAmeKemAlgorithms*(A: openArray[AmeKemAlgorithm]): AmeKemAlgorithms {.
    role: configurator.} =
  ## A: immutable ordered KEM slots. Repeated entries remain independent.
  ## A slot whose family this build left out is refused here, so a session is
  ## never configured with a KEM the binary cannot execute.
  var i: int = 0
  if A.len == 0 or A.len > ameMaxAlgorithmSlots:
    raise newException(ValueError, "AME KEM layout must contain 1..8 slots")
  result.length = uint8(A.len)
  while i < A.len:
    requireAmeKemBuilt(A[i])
    result.algorithms[i] = A[i]
    i = i + 1

converter toAmeKemAlgorithms*[N: static[int]](
    A: array[N, AmeKemAlgorithm]): AmeKemAlgorithms {.role: helper.} =
  ## A: compile-time-friendly immutable KEM layout.
  result = initAmeKemAlgorithms(A)

proc `[]`*(A: AmeKemAlgorithms, i: int): AmeKemAlgorithm {.role: parser.} =
  ## A/i: immutable KEM layout and occupied slot index.
  if i < 0 or i >= int(A.length):
    raise newException(IndexDefect, "AME KEM layout slot is out of bounds")
  result = A.algorithms[i]

proc kemLayoutsEquivalent*(A, B: AmeKemAlgorithms): bool {.role: parser.} =
  ## A/B: exact KEM layouts compared including order and repetitions.
  var i: int = 0
  if A.length != B.length:
    return false
  result = true
  while i < int(A.length):
    if A.algorithms[i] != B.algorithms[i]:
      return false
    i = i + 1

proc requireExchangeTierShape(t: AmeMaskTier) {.role: parser.} =
  ## t: target tier shape checked without the non-KEM suite layout.
  if t.tierId == 0'u32 or t.masks.kem == 0'u8 or
      t.masks.cipher == 0'u8 or t.masks.mac == 0'u8 or
      t.masks.hash == 0'u8 or t.masks.signature == 0'u8 or
      t.masks.kdf == 0'u8:
    raise newException(ValueError, "AME exchange target tier is incomplete")

proc ameAuthTagLenFromId*(id: uint8): AmeAuthTagLen {.role: parser.} =
  ## id: the one byte a peer used to name a tag length. Only the three
  ## defined sizes decode; anything else is refused rather than rounded.
  case id
  of 16'u8: result = aatl16
  of 24'u8: result = aatl24
  of 32'u8: result = aatl32
  else:
    raise newException(ValueError, "AME auth tag length is not 16, 24 or 32")

proc initAmeExchangeRequest*(A: AmeKemAlgorithms, targetTier: AmeMaskTier,
    exchangeMask: uint8,
    params: AmeRuntimeParams = AmeRuntimeParams(authTagLen: aatl32)):
    AmeExchangeRequest {.role: configurator.} =
  ## A/targetTier: immutable KEM layout and complete next-epoch selection.
  ## exchangeMask: target KEM slots receiving fresh secrets; zero is permitted.
  ## params: tunables the next epoch should adopt on both sides.
  var occupied: uint8 = validAmeKemMask(A)
  requireExchangeTierShape(targetTier)
  if (targetTier.masks.kem and not occupied) != 0'u8:
    raise newException(ValueError, "AME target KEM mask selects an empty slot")
  if (exchangeMask and not targetTier.masks.kem) != 0'u8:
    raise newException(ValueError,
      "AME exchange mask must be contained in the target KEM mask")
  result.targetTier = targetTier
  result.exchangeMask = exchangeMask
  result.params = params

proc initAmeExchangeRequest*(A: AmeKemAlgorithms, targetTier: AmeMaskTier,
    I: openArray[int]): AmeExchangeRequest {.role: configurator.} =
  ## A/targetTier/I: layout, next tier, and fresh/rekeyed slot indices.
  var
    i: int = 0
    m: uint8 = 0'u8
  while i < I.len:
    if I[i] < 0 or I[i] >= int(A.length):
      raise newException(ValueError, "AME exchange slot is outside the layout")
    m = m or slotMask(I[i])
    i = i + 1
  result = initAmeExchangeRequest(A, targetTier, m)

proc selectedAlgorithmCount*(r: AmeExchangeRequest): int {.role: parser.} =
  ## r: exchange request whose selected KEM slots are counted.
  var i: int = 0
  while i < ameMaxAlgorithmSlots:
    if algorithmSlotSelected(r.exchangeMask, i):
      result = result + 1
    i = i + 1

proc algorithmIdValid*(id: uint8): bool {.role: parser.} =
  ## id: stable one-byte KEM registry value.
  result = id >= uint8(ord(low(AmeKemAlgorithm))) and
    id <= uint8(ord(high(AmeKemAlgorithm)))

proc algorithmFromId*(id: uint8): AmeKemAlgorithm {.role: parser.} =
  ## id: stable one-byte KEM registry value.
  if not algorithmIdValid(id):
    raise newException(ValueError, "AME KEM algorithm id is unknown")
  result = AmeKemAlgorithm(id)

proc encodeAmeKemAlgorithms*(A: AmeKemAlgorithms): ByteSeq {.
    role: dataWriter.} =
  ## A: immutable KEM layout encoded as length and stable one-byte ids.
  var i: int = 0
  if A.length == 0 or A.length > ameMaxAlgorithmSlots:
    raise newException(ValueError, "AME KEM layout length is invalid")
  result.add(A.length)
  while i < int(A.length):
    result.add(uint8(ord(A.algorithms[i])))
    i = i + 1

proc decodeAmeKemAlgorithms*(A: openArray[uint8]): AmeKemAlgorithms {.
    role: parser.} =
  ## A: immutable KEM layout bytes containing length and stable ids.
  ## A peer naming a family this build left out is refused here, before any
  ## key material is generated or read.
  var
    n: int = 0
    i: int = 0
  if A.len == 0:
    raise newException(ValueError, "AME KEM layout is empty")
  n = int(A[0])
  if n == 0 or n > ameMaxAlgorithmSlots or A.len != n + 1:
    raise newException(ValueError, "AME KEM layout length mismatch")
  result.length = uint8(n)
  while i < n:
    result.algorithms[i] = algorithmFromId(A[i + 1])
    requireAmeKemBuilt(result.algorithms[i])
    i = i + 1

proc appendExchangeTier(A: var ByteSeq, t: AmeMaskTier) {.
    role: dataWriter.} =
  ## A/t: destination and compact stable target-tier fields.
  requireExchangeTierShape(t)
  appendAmeU32(A, t.tierId)
  A.add(t.masks.kem)
  A.add(t.masks.cipher)
  A.add(t.masks.mac)
  A.add(t.masks.hash)
  A.add(t.masks.signature)
  A.add(t.masks.kdf)

proc encodeAmeExchangeRequest*(r: AmeExchangeRequest): ByteSeq {.
    role: dataWriter.} =
  ## r: target tier and independent fresh-KEM mask.
  if (r.exchangeMask and not r.targetTier.masks.kem) != 0'u8:
    raise newException(ValueError, "AME exchange request mask is invalid")
  appendExchangeTier(result, r.targetTier)
  result.add(r.exchangeMask)
  result.add(uint8(ord(r.params.authTagLen)))
  result.add(uint8(ord(r.params.padding)))

proc decodeAmeExchangeRequest*(A: AmeKemAlgorithms,
    B: openArray[uint8]): AmeExchangeRequest {.role: parser.} =
  ## A/B: immutable KEM layout and complete target-tier request bytes.
  var t: AmeMaskTier
  if B.len != ameExchangeRequestLen:
    raise newException(ValueError, "AME exchange request length mismatch")
  t.tierId = uint32(B[0]) or (uint32(B[1]) shl 8) or
    (uint32(B[2]) shl 16) or (uint32(B[3]) shl 24)
  t.masks.kem = B[4]
  t.masks.cipher = B[5]
  t.masks.mac = B[6]
  t.masks.hash = B[7]
  t.masks.signature = B[8]
  t.masks.kdf = B[9]
  result = initAmeExchangeRequest(A, t, B[10],
    AmeRuntimeParams(authTagLen: ameAuthTagLenFromId(B[11]),
    padding: amePaddingPolicyFromId(B[12])))

proc generateAmeExchangeKeys*(A: AmeKemAlgorithms,
    r: AmeExchangeRequest): AmeExchangeKeys {.role: orchestrator.} =
  ## A/r: immutable slots and exact fresh exchanges receiving keypairs.
  var
    i: int = 0
    keypair: AmeKemKeypair
  discard initAmeExchangeRequest(A, r.targetTier, r.exchangeMask)
  result.request = r
  while i < int(A.length):
    if algorithmSlotSelected(r.exchangeMask, i):
      keypair = ameKemKeypair(A[i])
      result.publicKeys.add(keypair.publicKey)
      result.secretKeys.add(keypair.secretKey)
    i = i + 1

proc sealAmeExchange*(A: AmeKemAlgorithms, r: AmeExchangeRequest,
    publicKeys: openArray[ByteSeq]): AmeExchangeResult {.role: orchestrator.} =
  ## A/r/publicKeys: immutable slots, fresh selectors, and receiver keys.
  var
    i: int = 0
    j: int = 0
    env: AmeKemCipher
    wire: AmeKemEnvelope
  discard initAmeExchangeRequest(A, r.targetTier, r.exchangeMask)
  if publicKeys.len != selectedAlgorithmCount(r):
    raise newException(ValueError, "AME exchange public-key count mismatch")
  result.request = r
  while i < int(A.length):
    if algorithmSlotSelected(r.exchangeMask, i):
      env = sealAmeKem(A[i], publicKeys[j])
      wire.ciphertext = env.envelope.ciphertext
      wire.senderPublicKey = env.envelope.senderPublicKey
      result.envelopes.add(wire)
      result.sharedSecrets.add(env.sharedSecret)
      j = j + 1
    i = i + 1

proc openAmeExchange*(A: AmeKemAlgorithms, r: AmeExchangeRequest,
    E: openArray[AmeKemEnvelope],
    secretKeys: openArray[ByteSeq]): seq[ByteSeq] {.role: orchestrator.} =
  ## A/r/E/secretKeys: immutable slots and selected rows to decapsulate.
  var
    i: int = 0
    j: int = 0
    env: AmeKemCipher
    n: int = selectedAlgorithmCount(r)
  discard initAmeExchangeRequest(A, r.targetTier, r.exchangeMask)
  if E.len != n or secretKeys.len != n:
    raise newException(ValueError, "AME exchange secret-key count mismatch")
  while i < int(A.length):
    if algorithmSlotSelected(r.exchangeMask, i):
      env.envelope.ciphertext = E[j].ciphertext
      env.envelope.senderPublicKey = E[j].senderPublicKey
      result.add(openAmeKem(A[i], env, secretKeys[j]))
      j = j + 1
    i = i + 1

proc initAmeExchangeState*(A: AmeKemAlgorithms): AmeExchangeState {.
    role: configurator.} =
  ## A: immutable exact KEM layout for this state.
  if A.length == 0 or A.length > ameMaxAlgorithmSlots:
    raise newException(ValueError, "AME exchange state layout is invalid")
  result.algorithms = A

proc applyAmeExchange*(S: var AmeExchangeState, r: AmeExchangeRequest,
    sharedSecrets: openArray[ByteSeq]) {.role: actor.} =
  ## S/r/sharedSecrets: selected slots added or rekeyed; other secrets remain.
  var
    i: int = 0
    j: int = 0
  discard initAmeExchangeRequest(S.algorithms, r.targetTier, r.exchangeMask)
  if sharedSecrets.len != selectedAlgorithmCount(r):
    raise newException(ValueError, "AME exchange shared-secret count mismatch")
  while i < int(S.algorithms.length):
    if algorithmSlotSelected(r.exchangeMask, i):
      if sharedSecrets[j].len == 0:
        raise newException(ValueError, "AME exchange shared secret is empty")
      if S.generation[i] == high(uint32):
        raise newException(ValueError, "AME exchange generation is exhausted")
      secureClearAmeBytes(S.sharedSecrets[i])
      S.sharedSecrets[i] = @sharedSecrets[j]
      S.generation[i] = S.generation[i] + 1'u32
      S.activeMask = S.activeMask or slotMask(i)
      j = j + 1
    i = i + 1

proc buildAmeExchangeSeed*(S: AmeExchangeState,
    selectedMask: uint8): ByteSeq {.role: truthBuilder.} =
  ## S/selectedMask: chosen established KEM slots bound by position/generation.
  var i: int = 0
  if selectedMask == 0'u8 or (selectedMask and not S.activeMask) != 0'u8:
    raise newException(ValueError, "AME selected KEM secret is unavailable")
  appendAmeLabel(result, "AME-EXCHANGE-SELECTION-v2")
  result.add(S.algorithms.length)
  result.add(selectedMask)
  while i < int(S.algorithms.length):
    if algorithmSlotSelected(selectedMask, i):
      if S.generation[i] == 0'u32 or S.sharedSecrets[i].len == 0:
        raise newException(ValueError, "AME selected KEM secret is unavailable")
      result.add(uint8(i))
      result.add(uint8(ord(S.algorithms[i])))
      appendAmeU32(result, S.generation[i])
      appendAmeU32(result, uint32(S.sharedSecrets[i].len))
      appendAmeBytes(result, S.sharedSecrets[i])
    i = i + 1

proc readPathU32(A: openArray[uint8], cursor: var int,
    what: string): uint32 {.role: parser.} =
  ## A/cursor/what: source, cursor, and field label for a little-endian u32.
  if cursor < 0 or cursor > A.len - 4:
    raise newException(ValueError, "AME " & what & " is truncated")
  result = uint32(A[cursor]) or (uint32(A[cursor + 1]) shl 8) or
    (uint32(A[cursor + 2]) shl 16) or (uint32(A[cursor + 3]) shl 24)
  cursor = cursor + 4

proc appendPathBytes(A: var ByteSeq, B: openArray[uint8]) {.
    role: dataWriter.} =
  ## A/B: destination and length-framed bytes.
  appendAmeU32(A, uint32(B.len))
  appendAmeBytes(A, B)

proc readPathBytes(A: openArray[uint8], cursor: var int,
    what: string): ByteSeq {.role: parser.} =
  ## A/cursor/what: source, cursor, and bounded length-framed bytes.
  var n: int = checkedAmeWireLen(readPathU32(A, cursor, what & " length"),
    ameMaxExchangeComponentLen, what)
  if n < 0 or cursor > A.len - n:
    raise newException(ValueError, "AME " & what & " is truncated")
  result = @A[cursor ..< cursor + n]
  cursor = cursor + n

proc initAmeExchangeOffer*(requestId, baseEpochId: uint32,
    r: AmeExchangeRequest, publicKeys: openArray[ByteSeq]): AmeExchangeOffer {.
    role: configurator.} =
  ## requestId/baseEpochId/r/publicKeys: replay-bound receiver exchange offer.
  if requestId == 0'u32 or publicKeys.len != selectedAlgorithmCount(r):
    raise newException(ValueError, "AME exchange offer is invalid")
  result.requestId = requestId
  result.baseEpochId = baseEpochId
  result.request = r
  result.publicKeys = @publicKeys

proc encodeAmeExchangeOfferCore(o: AmeExchangeOffer): ByteSeq {.
    role: truthBuilder.} =
  ## o: canonical wire transaction and KEM public keys without proof fields.
  appendAmeU32(result, o.requestId)
  appendAmeU32(result, o.baseEpochId)
  appendPathBytes(result, encodeAmeExchangeRequest(o.request))
  if o.publicKeys.len != selectedAlgorithmCount(o.request):
    raise newException(ValueError, "AME exchange offer public-key count mismatch")
  appendAmeU32(result, uint32(o.publicKeys.len))
  for key in o.publicKeys:
    appendPathBytes(result, key)

proc encodeAmeExchangeOfferSubject*(o: AmeExchangeOffer): ByteSeq {.
    role: truthBuilder.} =
  ## o: domain-separated KEM public-key offer excluding its signatures.
  appendAmeLabel(result, "AME-KEM-OFFER-v1")
  appendAmeBytes(result, encodeAmeExchangeOfferCore(o))

proc answerAmeExchangeOffer*(A: AmeKemAlgorithms, o: AmeExchangeOffer): tuple[
    reply: AmeExchangeReply, sharedSecrets: seq[ByteSeq]] {.
    role: orchestrator.} =
  ## A/o: immutable layout and validated offer to encapsulate.
  var sealed: AmeExchangeResult = sealAmeExchange(A, o.request, o.publicKeys)
  result.reply.requestId = o.requestId
  result.reply.baseEpochId = o.baseEpochId
  result.reply.request = o.request
  result.reply.envelopes = sealed.envelopes
  result.sharedSecrets = sealed.sharedSecrets

proc encodeAmeExchangeReplySubject*(o: AmeExchangeOffer,
    r: AmeExchangeReply): ByteSeq {.role: truthBuilder.} =
  ## o/r: complete KEM offer and matching encapsulation reply without signatures.
  if r.requestId != o.requestId or r.baseEpochId != o.baseEpochId or
      r.request.exchangeMask != o.request.exchangeMask or
      r.request.targetTier != o.request.targetTier:
    raise newException(ValueError, "AME exchange reply transaction mismatch")
  appendAmeLabel(result, "AME-KEM-REPLY-v1")
  appendPathBytes(result, encodeAmeExchangeOfferSubject(o))
  appendAmeU32(result, r.requestId)
  appendAmeU32(result, r.baseEpochId)
  appendPathBytes(result, encodeAmeExchangeRequest(r.request))
  if r.envelopes.len != selectedAlgorithmCount(r.request):
    raise newException(ValueError, "AME exchange reply envelope count mismatch")
  appendAmeU32(result, uint32(r.envelopes.len))
  for envelope in r.envelopes:
    appendPathBytes(result, envelope.ciphertext)
    appendPathBytes(result, envelope.senderPublicKey)

proc openAmeExchangeReply*(A: AmeKemAlgorithms, o: AmeExchangeOffer,
    r: AmeExchangeReply,
    secretKeys: openArray[ByteSeq]): seq[ByteSeq] {.role: orchestrator.} =
  ## A/o/r/secretKeys: layout, original offer, exact reply, and private keys.
  if r.requestId != o.requestId or r.baseEpochId != o.baseEpochId or
      r.request.exchangeMask != o.request.exchangeMask or
      r.request.targetTier != o.request.targetTier:
    raise newException(ValueError, "AME exchange reply transaction mismatch")
  result = openAmeExchange(A, r.request, r.envelopes, secretKeys)

proc encodeAmeExchangeOffer*(o: AmeExchangeOffer): ByteSeq {.
    role: dataWriter.} =
  ## o: canonical offer bytes authenticated by handshake or current epoch.
  result = encodeAmeExchangeOfferCore(o)
  appendAmeU32(result, uint32(o.signatures.len))
  for signature in o.signatures:
    appendPathBytes(result, signature)

proc decodeAmeExchangeOffer*(A: AmeKemAlgorithms,
    B: openArray[uint8]): AmeExchangeOffer {.role: parser.} =
  ## A/B: immutable layout and canonical exchange offer bytes.
  var
    cursor: int = 0
    count: int = 0
    requestBytes: ByteSeq = @[]
    signatures: seq[ByteSeq] = @[]
  result.requestId = readPathU32(B, cursor, "exchange request id")
  result.baseEpochId = readPathU32(B, cursor, "exchange base epoch")
  requestBytes = readPathBytes(B, cursor, "exchange request")
  result.request = decodeAmeExchangeRequest(A, requestBytes)
  count = checkedAmeWireLen(readPathU32(B, cursor,
    "exchange public-key count"), uint32(ameMaxAlgorithmSlots),
    "exchange public-key count")
  if count != selectedAlgorithmCount(result.request):
    raise newException(ValueError, "AME exchange offer public-key count mismatch")
  while result.publicKeys.len < count:
    result.publicKeys.add(readPathBytes(B, cursor, "exchange public key"))
  count = checkedAmeWireLen(readPathU32(B, cursor,
    "exchange signature count"), uint32(ameMaxAlgorithmSlots),
    "exchange signature count")
  while result.signatures.len < count:
    result.signatures.add(readPathBytes(B, cursor, "exchange signature"))
  if cursor != B.len:
    raise newException(ValueError, "AME exchange offer has trailing bytes")
  signatures = result.signatures
  result = initAmeExchangeOffer(result.requestId, result.baseEpochId,
    result.request, result.publicKeys)
  result.signatures = signatures

proc encodeAmeExchangeReply*(r: AmeExchangeReply): ByteSeq {.
    role: dataWriter.} =
  ## r: canonical exchange reply bytes carrying the exact target tier again.
  appendAmeU32(result, r.requestId)
  appendAmeU32(result, r.baseEpochId)
  appendPathBytes(result, encodeAmeExchangeRequest(r.request))
  if r.requestId == 0'u32 or
      r.envelopes.len != selectedAlgorithmCount(r.request):
    raise newException(ValueError, "AME exchange reply is invalid")
  appendAmeU32(result, uint32(r.envelopes.len))
  for envelope in r.envelopes:
    appendPathBytes(result, envelope.ciphertext)
    appendPathBytes(result, envelope.senderPublicKey)
  appendAmeU32(result, uint32(r.signatures.len))
  for signature in r.signatures:
    appendPathBytes(result, signature)

proc decodeAmeExchangeReply*(A: AmeKemAlgorithms,
    B: openArray[uint8]): AmeExchangeReply {.role: parser.} =
  ## A/B: immutable layout and canonical exchange reply bytes.
  var
    cursor: int = 0
    count: int = 0
    requestBytes: ByteSeq = @[]
    envelope: AmeKemEnvelope
  result.requestId = readPathU32(B, cursor, "exchange reply id")
  result.baseEpochId = readPathU32(B, cursor, "exchange reply base epoch")
  requestBytes = readPathBytes(B, cursor, "exchange reply request")
  result.request = decodeAmeExchangeRequest(A, requestBytes)
  count = checkedAmeWireLen(readPathU32(B, cursor,
    "exchange envelope count"), uint32(ameMaxAlgorithmSlots),
    "exchange envelope count")
  if count != selectedAlgorithmCount(result.request):
    raise newException(ValueError, "AME exchange reply envelope count mismatch")
  while result.envelopes.len < count:
    envelope.ciphertext = readPathBytes(B, cursor, "KEM ciphertext")
    envelope.senderPublicKey = readPathBytes(B, cursor, "KEM sender key")
    result.envelopes.add(envelope)
  count = checkedAmeWireLen(readPathU32(B, cursor,
    "exchange reply signature count"), uint32(ameMaxAlgorithmSlots),
    "exchange reply signature count")
  while result.signatures.len < count:
    result.signatures.add(readPathBytes(B, cursor,
      "exchange reply signature"))
  if cursor != B.len or result.requestId == 0'u32:
    raise newException(ValueError, "AME exchange reply is invalid")
