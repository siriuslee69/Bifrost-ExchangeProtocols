## -------------------------------------------------------------------------
## AME Suite Layouts <- immutable slots and independently selected mask tiers
## -------------------------------------------------------------------------


import ./signatures
import ./symmetric




import ../../types
import ../types
import ../level0/bytes
import ./exchange_paths
import ./algorithms
import runePragmas

template requirePathLength(n: int, what: string) {.role: parser.} =
  if n <= 0 or n > ameMaxAlgorithmSlots:
    raise newException(ValueError, "AME " & what & " layout must contain 1..8 slots")

proc initAmeCipherAlgorithms*(A: openArray[AmeCipherAlgorithm]):
    AmeCipherAlgorithms {.role: configurator.} =
  ## A: immutable ordered symmetric-cipher slots. A slot whose primitive
  ## this build left out is refused here, before any session uses it.
  var
    i: int = 0
    S: seq[AmeCipherAlgorithm] = sortedByWireId(A)
  requirePathLength(A.len, "cipher")
  result.length = uint8(A.len)
  while i < A.len:
    requireAmeCipherBuilt(A[i])
    result.algorithms[i] = S[i]
    i = i + 1

proc initAmeMacAlgorithms*(A: openArray[AmeMacAlgorithm]):
    AmeMacAlgorithms {.role: configurator.} =
  ## A: ordered keyed-authentication slots, refused if not compiled.
  var
    i: int = 0
    S: seq[AmeMacAlgorithm] = sortedByWireId(A)
  requirePathLength(A.len, "MAC")
  result.length = uint8(A.len)
  while i < A.len:
    requireAmeMacBuilt(A[i])
    result.algorithms[i] = S[i]
    i = i + 1

proc initAmeHashAlgorithms*(A: openArray[AmeHashAlgorithm]):
    AmeHashAlgorithms {.role: configurator.} =
  ## A: ordered transcript-hash slots, refused if not compiled.
  var
    i: int = 0
    S: seq[AmeHashAlgorithm] = sortedByWireId(A)
  requirePathLength(A.len, "hash")
  result.length = uint8(A.len)
  while i < A.len:
    requireAmeHashBuilt(A[i])
    result.algorithms[i] = S[i]
    i = i + 1

proc initAmeSignatureAlgorithms*(A: openArray[AmeSignatureAlgorithm]):
    AmeSignatureAlgorithms {.role: configurator.} =
  ## A: ordered signature slots, refused if not compiled.
  var
    i: int = 0
    S: seq[AmeSignatureAlgorithm] = sortedByWireId(A)
  requirePathLength(A.len, "signature")
  result.length = uint8(A.len)
  while i < A.len:
    requireAmeSigBuilt(A[i])
    result.algorithms[i] = S[i]
    i = i + 1

proc initAmeKdfAlgorithms*(A: openArray[AmeKdfAlgorithm]):
    AmeKdfAlgorithms {.role: configurator.} =
  ## A: ordered KDF slots, refused if not compiled.
  var
    i: int = 0
    S: seq[AmeKdfAlgorithm] = sortedByWireId(A)
  requirePathLength(A.len, "KDF")
  result.length = uint8(A.len)
  while i < A.len:
    requireAmeKdfBuilt(A[i])
    result.algorithms[i] = S[i]
    i = i + 1

converter toAmeCipherAlgorithms*[N: static[int]](
    A: array[N, AmeCipherAlgorithm]): AmeCipherAlgorithms {.role: helper.} =
  result = initAmeCipherAlgorithms(A)

converter toAmeMacAlgorithms*[N: static[int]](
    A: array[N, AmeMacAlgorithm]): AmeMacAlgorithms {.role: helper.} =
  result = initAmeMacAlgorithms(A)

converter toAmeHashAlgorithms*[N: static[int]](
    A: array[N, AmeHashAlgorithm]): AmeHashAlgorithms {.role: helper.} =
  result = initAmeHashAlgorithms(A)

converter toAmeSignatureAlgorithms*[N: static[int]](
    A: array[N, AmeSignatureAlgorithm]): AmeSignatureAlgorithms {.
    role: helper.} =
  result = initAmeSignatureAlgorithms(A)

converter toAmeKdfAlgorithms*[N: static[int]](
    A: array[N, AmeKdfAlgorithm]): AmeKdfAlgorithms {.role: helper.} =
  result = initAmeKdfAlgorithms(A)

proc occupiedAmeMask*(n: uint8): uint8 {.role: helper.} =
  ## n: occupied slot count converted into an MSB-first mask.
  var i: int = 0
  requirePathLength(int(n), "algorithm")
  while i < int(n):
    result = result or slotMask(i)
    i = i + 1

proc requireSelection(n, m: uint8, what: string) {.role: parser.} =
  ## n/m/what: occupied slots, selected slots, and field label.
  requirePathLength(int(n), what)
  if m == 0'u8:
    raise newException(ValueError, "AME " & what & " mask must select a slot")
  if (m and not occupiedAmeMask(n)) != 0'u8:
    raise newException(ValueError, "AME " & what & " mask selects an empty slot")

proc requireUniqueActiveHashes(P: AmeHashAlgorithms, m: uint8) {.
    role: parser.} =
  ## P/m: reject duplicate active hashes before XOR overlay cancellation.
  var
    seen: set[AmeHashAlgorithm] = {}
    i: int = 0
  while i < int(P.length):
    if algorithmSlotSelected(m, i):
      if P.algorithms[i] in seen:
        raise newException(ValueError,
          "AME hash layout contains a duplicate active algorithm")
      seen.incl(P.algorithms[i])
    i = i + 1

proc requireUniqueActiveKdfs(P: AmeKdfAlgorithms, m: uint8) {.
    role: parser.} =
  ## P/m: reject duplicate active KDFs before XOR overlay cancellation.
  var
    seen: set[AmeKdfAlgorithm] = {}
    i: int = 0
  while i < int(P.length):
    if algorithmSlotSelected(m, i):
      if P.algorithms[i] in seen:
        raise newException(ValueError,
          "AME KDF layout contains a duplicate active algorithm")
      seen.incl(P.algorithms[i])
    i = i + 1

proc initAmeSuiteLayout*(kems: AmeKemAlgorithms,
    ciphers: AmeCipherAlgorithms, macs: AmeMacAlgorithms,
    hashes: AmeHashAlgorithms, signatures: AmeSignatureAlgorithms,
    kdfs: AmeKdfAlgorithms): AmeSuiteLayout {.role: configurator.} =
  ## All parameters form one immutable ordered in-session algorithm layout.
  requirePathLength(int(kems.length), "KEM")
  requirePathLength(int(ciphers.length), "cipher")
  requirePathLength(int(macs.length), "MAC")
  requirePathLength(int(hashes.length), "hash")
  requirePathLength(int(signatures.length), "signature")
  requirePathLength(int(kdfs.length), "KDF")
  result.kems = kems
  result.ciphers = ciphers
  result.macs = macs
  result.hashes = hashes
  result.signatures = signatures
  result.kdfs = kdfs

proc defaultAmeLayout*(kems: AmeKemAlgorithms): AmeSuiteLayout {.
    role: configurator.} =
  ## kems: caller-selected KEM slots combined with conservative fixed slots.
  ## Every non-KEM slot comes from what this build carries, so the default
  ## layout is always runnable; a full build gives the same slots it always
  ## did (XChaCha20, BLAKE3, BLAKE3, Ed25519 + Falcon512, BLAKE3 + GimliXof).
  result = initAmeSuiteLayout(kems,
    initAmeCipherAlgorithms([defaultAmeCipherSlot()]),
    initAmeMacAlgorithms([defaultAmeMacSlot()]),
    initAmeHashAlgorithms([defaultAmeHashSlot()]),
    initAmeSignatureAlgorithms(defaultAmeSigSlots()),
    initAmeKdfAlgorithms(defaultAmeKdfSlots()))

proc initAmeTierMasks*(kem, cipher, mac, hash, signature,
    kdf: uint8): AmeTierMasks {.role: configurator.} =
  ## Parameters are independent MSB-first selections over one suite layout.
  result.kem = kem
  result.cipher = cipher
  result.mac = mac
  result.hash = hash
  result.signature = signature
  result.kdf = kdf

proc validateAmeTier*(L: AmeSuiteLayout, t: AmeMaskTier) {.role: parser.} =
  ## L/t: immutable layout and complete mask tier selected over it.
  discard initAmeSuiteLayout(L.kems, L.ciphers, L.macs, L.hashes,
    L.signatures, L.kdfs)
  if t.tierId == 0'u32:
    raise newException(ValueError, "AME tier id must be positive")
  requireSelection(L.kems.length, t.masks.kem, "KEM")
  requireSelection(L.ciphers.length, t.masks.cipher, "cipher")
  requireSelection(L.macs.length, t.masks.mac, "MAC")
  requireSelection(L.hashes.length, t.masks.hash, "hash")
  requireSelection(L.signatures.length, t.masks.signature, "signature")
  requireSelection(L.kdfs.length, t.masks.kdf, "KDF")
  requireUniqueActiveHashes(L.hashes, t.masks.hash)
  requireUniqueActiveKdfs(L.kdfs, t.masks.kdf)

proc initAmeMaskTier*(L: AmeSuiteLayout, tierId: uint32,
    masks: AmeTierMasks): AmeMaskTier {.role: configurator.} =
  ## L/tierId/masks: stable tier identity and complete selections to validate.
  result.tierId = tierId
  result.masks = masks
  validateAmeTier(L, result)

proc validateAmeTierTransition*(L: AmeSuiteLayout, current,
    target: AmeMaskTier, exchangeMask, availableKemMask: uint8) {.
    role: parser.} =
  ## L/current/target: immutable layout and atomic epoch tier transition.
  ## exchangeMask/availableKemMask: fresh slots and already established secrets.
  var newlyActive: uint8 = 0'u8
  validateAmeTier(L, current)
  validateAmeTier(L, target)
  newlyActive = target.masks.kem and not current.masks.kem
  if (exchangeMask and not target.masks.kem) != 0'u8:
    raise newException(ValueError,
      "AME exchange mask is outside the target KEM selection")
  if (newlyActive and not exchangeMask) != 0'u8:
    raise newException(ValueError,
      "AME exchange mask omits a newly activated KEM slot")
  if (target.masks.kem and not (availableKemMask or exchangeMask)) != 0'u8:
    raise newException(ValueError,
      "AME target tier selects an unavailable KEM slot")

proc familyIds[T](P: T): seq[int] {.role: helper.} =
  ## P: one algorithm list -> its wire ids, in order. Walks the array with
  ## `items` on purpose: indexing it inside a generic lets Nim pick the
  ## array-to-layout converter and read the unused (zero) entries.
  for a in items(P.algorithms):
    if result.len < int(P.length):
      result.add(ord(a))

proc countId(A: openArray[int], x: int): int {.role: helper.} =
  ## A/x: wire ids and one id -> how often it appears.
  for a in A:
    if a == x:
      result = result + 1

proc idsFitInside(small, big: openArray[int]): bool {.role: parser.} =
  ## small/big: wire ids of one family -> true when every id of small is in
  ## big at least as often (repeats count).
  result = true
  for x in small:
    if countId(small, x) > countId(big, x):
      return false

proc familyFitsInside[T](small, big: T): bool {.role: parser.} =
  ## small/big: two lists of one family -> see `idsFitInside`.
  result = idsFitInside(familyIds(small), familyIds(big))

proc ameLayoutFitsInside*(small, big: AmeSuiteLayout): bool {.role: parser.} =
  ## small/big: a client's layout and one a server offers -> true when
  ## every algorithm the client lists is also in the server's, family by
  ## family, as often as the client lists it. Order plays no part: both
  ## are kept in wire-id order anyway.
  ##
  ##   server offers   [LightSaber, Kyber768, X25519]  ciphers [XChaCha20, Gimli]
  ##   client lists    [LightSaber, X25519]            ciphers [XChaCha20]   fits
  ##   client lists    [FireSaber, X25519]             ...                   does not
  result = familyFitsInside(small.kems, big.kems) and
    familyFitsInside(small.ciphers, big.ciphers) and
    familyFitsInside(small.macs, big.macs) and
    familyFitsInside(small.hashes, big.hashes) and
    familyFitsInside(small.signatures, big.signatures) and
    familyFitsInside(small.kdfs, big.kdfs)

proc ameTierPqKemCount*(L: AmeSuiteLayout, t: AmeMaskTier): int {.
    role: parser.} =
  ## L/t: layout and selection -> how many switched-on KEM slots are
  ## post-quantum (every family but X25519).
  var
    i: int = 0
  while i < int(L.kems.length):
    if algorithmSlotSelected(t.masks.kem, i) and
        ameKemFamily(L.kems.algorithms[i]) != akfX25519:
      result = result + 1
    i = i + 1

proc ameTierPolicyError*(L: AmeSuiteLayout, t: AmeMaskTier,
    minPqKems: int): string {.role: parser.} =
  ## L/t/minPqKems: a selection -> "" when it may be used, else why not.
  ## The one minimum AME enforces on a selection, whoever proposes it and
  ## whenever: at least `minPqKems` post-quantum KEMs switched on
  ## (`ameMinPqKems` in the runtime config).
  if ameTierPqKemCount(L, t) < minPqKems:
    result = "AME selection keeps " & $ameTierPqKemCount(L, t) &
      " post-quantum KEM(s) switched on; this side requires " & $minPqKems

proc fullAmeMaskTier*(L: AmeSuiteLayout,
    tierId: uint32 = 1'u32): AmeMaskTier {.role: truthBuilder.} =
  ## L/tierId: tier selecting every occupied slot in each algorithm family.
  result = initAmeMaskTier(L, tierId, initAmeTierMasks(
    occupiedAmeMask(L.kems.length), occupiedAmeMask(L.ciphers.length),
    occupiedAmeMask(L.macs.length), occupiedAmeMask(L.hashes.length),
    occupiedAmeMask(L.signatures.length), occupiedAmeMask(L.kdfs.length)))

template encodeNibbleLayout(result: var ByteSeq, P: untyped) {.
    role: dataWriter.} =
  result.add(P.length)
  block:
    var
      i: int = 0
      packed: uint8 = 0'u8
    while i < int(P.length):
      packed = uint8(ord(P.algorithms[i])) shl 4
      if i + 1 < int(P.length):
        packed = packed or uint8(ord(P.algorithms[i + 1]))
      result.add(packed)
      i = i + 2

proc encodeAmeSuiteLayout*(L: AmeSuiteLayout): ByteSeq {.
    role: dataWriter.} =
  ## L: canonical immutable layout bytes; no tier masks are embedded.
  discard initAmeSuiteLayout(L.kems, L.ciphers, L.macs, L.hashes,
    L.signatures, L.kdfs)
  result.add(2'u8)
  result.add(encodeAmeKemAlgorithms(L.kems))
  encodeNibbleLayout(result, L.ciphers)
  encodeNibbleLayout(result, L.macs)
  encodeNibbleLayout(result, L.hashes)
  encodeNibbleLayout(result, L.signatures)
  encodeNibbleLayout(result, L.kdfs)

proc requireSuiteBytes(A: openArray[uint8], cursor, n: int) {.role: parser.} =
  ## A/cursor/n: bounds check for exact layout parsing.
  if cursor < 0 or n < 0 or cursor > A.len - n:
    raise newException(ValueError, "AME suite layout is truncated")

template decodeNibbleLayout(A: untyped, cursor: var int, P: untyped,
    EnumType: typedesc, what: string) {.role: parser.} =
  requireSuiteBytes(A, cursor, 1)
  block:
    var
      n: int = int(A[cursor])
      packedLen: int = (n + 1) div 2
      packed: uint8 = 0'u8
      id: uint8 = 0'u8
      i: int = 0
    requirePathLength(n, what)
    cursor = cursor + 1
    requireSuiteBytes(A, cursor, packedLen)
    P.length = uint8(n)
    while i < n:
      packed = A[cursor + (i div 2)]
      id = if (i and 1) == 0: packed shr 4 else: packed and 0x0f'u8
      if id < uint8(ord(low(EnumType))) or id > uint8(ord(high(EnumType))):
        raise newException(ValueError, "AME " & what & " algorithm id is unknown")
      if i > 0:
        requireWireOrder(uint8(ord(P.algorithms[i - 1])), id, what)
      P.algorithms[i] = EnumType(id)
      i = i + 1
    if (n and 1) != 0 and (A[cursor + packedLen - 1] and 0x0f'u8) != 0'u8:
      raise newException(ValueError, "AME " & what & " layout padding is non-zero")
    cursor = cursor + packedLen

proc decodeAmeSuiteLayout*(A: openArray[uint8]): AmeSuiteLayout {.
    role: parser.} =
  ## A: canonical immutable layout bytes.
  var
    cursor: int = 0
    n: int = 0
    kemBytes: ByteSeq = @[]
  requireSuiteBytes(A, cursor, 2)
  if A[cursor] != 2'u8:
    raise newException(ValueError, "AME suite layout version mismatch")
  cursor = cursor + 1
  n = int(A[cursor])
  requirePathLength(n, "KEM")
  requireSuiteBytes(A, cursor, n + 1)
  kemBytes = newSeq[uint8](n + 1)
  for i in 0 .. n:
    kemBytes[i] = A[cursor + i]
  result.kems = decodeAmeKemAlgorithms(kemBytes)
  cursor = cursor + n + 1
  decodeNibbleLayout(A, cursor, result.ciphers, AmeCipherAlgorithm, "cipher")
  decodeNibbleLayout(A, cursor, result.macs, AmeMacAlgorithm, "MAC")
  decodeNibbleLayout(A, cursor, result.hashes, AmeHashAlgorithm, "hash")
  decodeNibbleLayout(A, cursor, result.signatures, AmeSignatureAlgorithm,
    "signature")
  decodeNibbleLayout(A, cursor, result.kdfs, AmeKdfAlgorithm, "KDF")
  if cursor != A.len:
    raise newException(ValueError, "AME suite layout has trailing bytes")
  result = initAmeSuiteLayout(result.kems, result.ciphers, result.macs,
    result.hashes, result.signatures, result.kdfs)

proc encodeAmeMaskTier*(t: AmeMaskTier): ByteSeq {.role: dataWriter.} =
  ## t: stable tier id followed by six MSB-first family masks.
  if t.tierId == 0'u32:
    raise newException(ValueError, "AME tier id must be positive")
  result.add(1'u8)
  appendAmeU32(result, t.tierId)
  result.add(t.masks.kem)
  result.add(t.masks.cipher)
  result.add(t.masks.mac)
  result.add(t.masks.hash)
  result.add(t.masks.signature)
  result.add(t.masks.kdf)

proc decodeAmeMaskTier*(L: AmeSuiteLayout,
    A: openArray[uint8]): AmeMaskTier {.role: parser.} =
  ## L/A: layout and canonical eleven-byte tier value.
  if A.len != 11 or A[0] != 1'u8:
    raise newException(ValueError, "AME mask tier encoding is invalid")
  result.tierId = uint32(A[1]) or (uint32(A[2]) shl 8) or
    (uint32(A[3]) shl 16) or (uint32(A[4]) shl 24)
  result.masks = initAmeTierMasks(A[5], A[6], A[7], A[8], A[9], A[10])
  validateAmeTier(L, result)

proc layoutsEquivalent*(A, B: AmeSuiteLayout): bool {.role: parser.} =
  ## A/B: canonical immutable layouts compared byte-for-byte.
  result = encodeAmeSuiteLayout(A) == encodeAmeSuiteLayout(B)

proc tiersEquivalent*(A, B: AmeMaskTier): bool {.role: parser.} =
  ## A/B: stable tier ids and all family masks compared byte-for-byte.
  result = encodeAmeMaskTier(A) == encodeAmeMaskTier(B)



proc activeAmeSignatures*(L: AmeSuiteLayout,
    t: AmeMaskTier): seq[AmeSignatureAlgorithm] {.role: parser.} =
  ## L/t: selected signature slots returned in immutable layout order.
  var i: int = 0
  validateAmeTier(L, t)
  while i < int(L.signatures.length):
    if algorithmSlotSelected(t.masks.signature, i):
      result.add(L.signatures.algorithms[i])
    i = i + 1

proc activeAmeSignatureKeys*(L: AmeSuiteLayout, t: AmeMaskTier,
    K: openArray[ByteSeq]): seq[ByteSeq] {.role: parser.} =
  ## L/t/K: complete layout-ordered key stack filtered by the active mask.
  var
    i: int = 0
  validateAmeTier(L, t)
  if K.len != int(L.signatures.length):
    raise newException(ValueError, "AME signature key stack length mismatch")
  while i < int(L.signatures.length):
    if K[i].len == 0:
      raise newException(ValueError, "AME signature key stack contains an empty key")
    if algorithmSlotSelected(t.masks.signature, i):
      result.add(K[i])
    i = i + 1

proc transitionAmeSignatureTier*(L: AmeSuiteLayout, current,
    target: AmeMaskTier): AmeMaskTier {.role: truthBuilder.} =
  ## L/current/target: target state authorized by current plus target signatures.
  validateAmeTier(L, current)
  validateAmeTier(L, target)
  result = target
  result.masks.signature = current.masks.signature or target.masks.signature
  validateAmeTier(L, result)

proc hashAmeLayer(a: AmeHashAlgorithm, A: openArray[byte],
    outLen: int): ByteSeq {.role: helper.} =
  ## a/A/outLen: exact hash primitive, input, and output length.
  result = ameHashBytes(a, A, outLen)

proc hashAmeTier*(L: AmeSuiteLayout, t: AmeMaskTier,
    A: openArray[byte], outLen: int = 32): ByteSeq {.role: orchestrator.} =
  ## L/t/A/outLen: selected hash overlay and immutable layout binding.
  var
    seed: ByteSeq = @[]
    layer: ByteSeq = @[]
    i: int = 0
  validateAmeTier(L, t)
  if outLen <= 0:
    raise newException(ValueError, "AME hash length must be positive")
  appendAmeLabel(seed, "AME-HASH-TIER-v2")
  appendAmeBytes(seed, encodeAmeSuiteLayout(L))
  appendAmeBytes(seed, encodeAmeMaskTier(t))
  appendAmeU32(seed, uint32(A.len))
  appendAmeBytes(seed, A)
  result = newSeq[byte](outLen)
  while i < int(L.hashes.length):
    if algorithmSlotSelected(t.masks.hash, i):
      layer = hashAmeLayer(L.hashes.algorithms[i], seed, outLen)
      xorAmeInto(result, layer)
    i = i + 1

proc generateAmeSigningKeys*(L: AmeSuiteLayout, t: AmeMaskTier): tuple[
    publicKeys: seq[ByteSeq], secretKeys: seq[ByteSeq]] {.
    role: orchestrator.} =
  ## L/t: selected signature slots receiving independent keypairs.
  var
    A: seq[AmeSignatureAlgorithm] = @[]
    keypair: AmeSigKeypair = default(AmeSigKeypair)
    i: int = 0
  A = activeAmeSignatures(L, t)
  while i < A.len:
    keypair = ameSigKeypair(A[i])
    result.publicKeys.add(keypair.publicKey)
    result.secretKeys.add(keypair.secretKey)
    i = i + 1

proc signatureSubject(L: AmeSuiteLayout, t: AmeMaskTier,
    msg: openArray[byte]): ByteSeq {.role: truthBuilder.} =
  ## L/t/msg: canonical tier-bound signature subject.
  appendAmeLabel(result, "AME-SIGNATURE-TIER-v2")
  appendAmeBytes(result, encodeAmeSuiteLayout(L))
  appendAmeBytes(result, encodeAmeMaskTier(t))
  appendAmeU32(result, uint32(msg.len))
  appendAmeBytes(result, msg)

proc signAmeTier*(L: AmeSuiteLayout, t: AmeMaskTier,
    msg: openArray[byte], secretKeys: openArray[ByteSeq]): seq[ByteSeq] {.
    role: orchestrator.} =
  ## L/t/msg/secretKeys: selected signature stack and ordered private keys.
  var
    A: seq[AmeSignatureAlgorithm] = activeAmeSignatures(L, t)
    subject: ByteSeq = @[]
    i: int = 0
  if secretKeys.len != A.len:
    raise newException(ValueError, "AME signature secret-key count mismatch")
  subject = signatureSubject(L, t, msg)
  while i < A.len:
    result.add(signAmeMessage(A[i], subject, secretKeys[i]))
    i = i + 1

proc verifyAmeTier*(L: AmeSuiteLayout, t: AmeMaskTier,
    msg: openArray[byte], publicKeys,
    signatures: openArray[ByteSeq]): bool {.role: orchestrator.} =
  ## L/t/msg/publicKeys/signatures: all selected signatures must verify.
  var
    A: seq[AmeSignatureAlgorithm] = activeAmeSignatures(L, t)
    subject: ByteSeq = @[]
    i: int = 0
  if publicKeys.len != A.len or signatures.len != A.len:
    return false
  subject = signatureSubject(L, t, msg)
  result = true
  while i < A.len:
    if not verifyAmeMessage(A[i], subject, signatures[i], publicKeys[i]):
      return false
    i = i + 1

proc nextFreeSlot(layoutIds: openArray[int], x: int, taken: uint8): uint8 {.
    role: parser.} =
  ## layoutIds/x/taken: the first slot holding id x whose bit is not taken.
  for i in 0 ..< layoutIds.len:
    if layoutIds[i] == x and (taken and slotMask(i)) == 0'u8:
      return slotMask(i)
  raise newException(ValueError, "AME layout has no free slot for algorithm id " &
    $x)

proc idsToSlotMask(layoutIds, want: openArray[int]): uint8 {.role: parser.} =
  ## layoutIds/want: one family's ids in layout order and the ids asked for
  ## -> the bits that select them. Each mention takes the next instance not
  ## yet taken; an id the layout does not hold (often enough) is refused.
  var
    taken: uint8 = 0'u8
  for x in want:
    taken = taken or nextFreeSlot(layoutIds, x, taken)
  result = taken

proc ameSelectionMask*[P, E](layoutFamily: P, want: openArray[E]): uint8 {.
    role: parser.} =
  ## layoutFamily/want: one family of a layout and the algorithms to switch
  ## on -> the bit mask over that family. Name an algorithm twice to select
  ## two instances of it:
  ##
  ##   layout KEMs  [FireSaber, X25519, X25519]
  ##   want         [X25519]            -> 0b01000000  (first X25519)
  ##   want         [X25519, X25519]    -> 0b01100000  (both)
  ##   want         [Kyber768]          -> refused: not in the layout
  var
    ids: seq[int] = @[]
  for a in want:
    ids.add(ord(a))
  result = idsToSlotMask(familyIds(layoutFamily), ids)
