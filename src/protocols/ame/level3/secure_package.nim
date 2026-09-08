## -------------------------------------------------------------------------
## AME Secure Package <- seal once, then cut up and add repair data
## -------------------------------------------------------------------------

import ../../types
import ../types
import ../level2/session
import ../level1/compression
import ../level0/bytes
import ../level1/exchange_paths
import ../level2/protection
import ../../dac/types
import ../../dac/level2/package_transfer
import ../../dac/level3/link_table
import ./dac_relay
import ../../../analysis_pragmas

const
  ameSecurePackageMagic* = [uint8('A'), uint8('S'), uint8('P')]
  ameSecurePackageVersion* = 1'u8
  ameSecurePackageHeaderLen* = 15

type
  AmeSecurePackagePlan* {.role: truthState.} = object
    package*: DacPackagePlan
    compression*: AmeCompressionPolicy

  AmeSecurePackageResult* {.role: truthState.} = object
    ok*: bool
    payload*: ByteSeq
    packageId*: uint64
    digest*: array[32, uint8]
    dataCount*: uint16
    repairCount*: uint16
    status*: DacCommitStatus
    err*: string

proc securePackageAad(packageId: uint64, epochId: uint32,
    compression: AmeCompressionPolicy): ByteSeq {.role: truthBuilder.} =
  ## packageId/epochId/compression: package identity bound to AME authentication.
  appendAmeLabel(result, "AME-SECURE-PACKAGE-v2")
  appendAmeU64(result, packageId)
  appendAmeU32(result, epochId)
  result.add(uint8(ord(compression.algorithm)))
  result.add(uint8(ord(effectiveAmePadding(compression))))

proc encodeSecurePackage(epochId: uint32, nonce: openArray[uint8],
    tagLen: AmeAuthTagLen, m: AmeProtectedMessage): ByteSeq {.
    role: dataWriter.} =
  ## epochId/nonce/tagLen/m: detached AME protection fields made packageable.
  ##
  ##   "ASP" | ver | epoch u32 | nonceLen u16 | tagLen u8 | ctLen u32
  ##         | nonce | tag | ciphertext
  ##
  ## The nonce IS stored here, unlike a live frame. A frame derives its nonce
  ## from the ratchet position both sides share; a package sitting in a file
  ## has no such position, so the nonce has to travel with it.
  requireAmeU16Len(nonce.len, "secure-package nonce")
  requireAmeU32Len(m.payload.len, "secure-package ciphertext")
  if m.authTag.len != int(ord(tagLen)):
    raise newException(ValueError, "secure-package tag length mismatch")
  appendAmeBytes(result, ameSecurePackageMagic)
  result.add(ameSecurePackageVersion)
  appendAmeU32(result, epochId)
  appendAmeU16(result, uint16(nonce.len))
  result.add(uint8(ord(tagLen)))
  appendAmeU32(result, uint32(m.payload.len))
  appendAmeBytes(result, nonce)
  appendAmeBytes(result, m.authTag)
  appendAmeBytes(result, m.payload)

proc readSecurePackageU16(A: openArray[uint8], o: int): uint16 {.
    role: parser.} =
  ## A/o: source and little-endian u16 offset.
  result = uint16(A[o]) or (uint16(A[o + 1]) shl 8)

proc readSecurePackageU32(A: openArray[uint8], o: int): uint32 {.
    role: parser.} =
  ## A/o: source and little-endian u32 offset.
  result = uint32(A[o]) or (uint32(A[o + 1]) shl 8) or
    (uint32(A[o + 2]) shl 16) or (uint32(A[o + 3]) shl 24)

proc decodeSecurePackage(A: openArray[uint8]): tuple[epochId: uint32,
    nonce: ByteSeq, tagLen: AmeAuthTagLen,
    message: AmeProtectedMessage] {.role: parser.} =
  ## A: complete authenticated-package envelope.
  var
    nonceLen: int = 0
    tagLen: int = 0
    payloadLen: int = 0
    offset: int = ameSecurePackageHeaderLen
  if A.len < ameSecurePackageHeaderLen or A[0 .. 2] != ameSecurePackageMagic:
    raise newException(ValueError, "AME secure-package identity mismatch")
  if A[3] != ameSecurePackageVersion:
    raise newException(ValueError, "AME secure-package version mismatch")
  result.epochId = readSecurePackageU32(A, 4)
  nonceLen = int(readSecurePackageU16(A, 8))
  result.tagLen = ameAuthTagLenFromId(A[10])
  tagLen = int(ord(result.tagLen))
  payloadLen = checkedAmeWireLen(readSecurePackageU32(A, 11),
    uint32(defaultAmeMaxFrameBytes), "secure-package ciphertext")
  if nonceLen <= 0 or A.len != offset + nonceLen + tagLen + payloadLen:
    raise newException(ValueError, "AME secure-package length mismatch")
  result.nonce = @A[offset ..< offset + nonceLen]
  offset = offset + nonceLen
  result.message.authTag = @A[offset ..< offset + tagLen]
  offset = offset + tagLen
  result.message.payload = @A[offset ..< A.len]

proc planAmeSecurePackage*(a: AmeAuthPackage, packageId: uint64,
    plaintext: openArray[uint8], d: DacScenarioDefaults,
    compression: AmeCompressionPolicy = defaultAmeCompressionPolicy(),
    limits: DacPackageLimits = defaultDacPackageLimits()):
    AmeSecurePackagePlan {.role: orchestrator.} =
  ## a/packageId/plaintext/d/compression/limits: established epoch, package
  ## identity, application bytes, DAC policy, compression, and resource limits.
  var
    compressed: ByteSeq = encodeAmeCompressed(plaintext, compression)
    sealed: tuple[message: AmeProtectedMessage, nonce: ByteSeq]
    wire: ByteSeq = @[]
    keyContext: ByteSeq = @[]
  requireAmeAuth(a)
  keyContext = ameEpochKeyContext(a.current, a.sessionId,
    outboundAmeDirection(a.endpointRole))
  sealed = protectAmeMessage(a.current.layout, a.current.tier,
    a.current.exchange, compressed,
    securePackageAad(packageId, a.current.epochId, compression),
    keyContext, a.current.params.authTagLen)
  wire = encodeSecurePackage(a.current.epochId, sealed.nonce,
    a.current.params.authTagLen, sealed.message)
  ## Chunking and parity happen on the SEALED bytes, never on the plaintext.
  ## That is the ordering to keep: encrypt, then authenticate, then add the
  ## repair data on top. A repair layer can then rebuild lost pieces with no
  ## key at all, and the one tag over the whole package is checked once, at
  ## the end, on bytes that have already been put back together.
  result.package = planDacPackage(packageId, wire, d, dtcUserData, limits)
  result.compression = compression

proc openSecurePackageWithEpoch(E: AmeEpochKeySet, packageId: uint64,
    wire: openArray[uint8], compression: AmeCompressionPolicy,
    sessionId: uint64, direction: AmeTrafficDirection):
    tuple[ok: bool, payload: ByteSeq] {.role: orchestrator.} =
  ## E/packageId/wire/compression: epoch and restored secure-package bytes.
  var
    decoded = decodeSecurePackage(wire)
    opened: tuple[ok: bool, payload: ByteSeq]
    keyContext: ByteSeq = @[]
  if decoded.epochId != E.epochId or
      decoded.nonce.len != ameProtectionNonceLen(E.layout, E.tier):
    return
  if decoded.tagLen != E.params.authTagLen:
    return
  keyContext = ameEpochKeyContext(E, sessionId, direction)
  opened = openAmeMessage(E.layout, E.tier, E.exchange, decoded.nonce,
    decoded.message, securePackageAad(packageId, E.epochId,
    compression), keyContext, E.params.authTagLen)
  if not opened.ok:
    return
  result.payload = decodeAmeCompressed(opened.payload, compression)
  result.ok = true

proc restoreAmeSecurePackage*(a: AmeAuthPackage, packageId: uint64,
    wire: openArray[uint8],
    compression: AmeCompressionPolicy = defaultAmeCompressionPolicy()):
    AmeSecurePackageResult {.role: orchestrator.} =
  ## a/packageId/wire/compression: established epochs, package identity, the
  ## reassembled sealed bytes, and the negotiated codec.
  ## This is the byte-level entry point. It does not care how the bytes were
  ## carried, which is the whole point of sealing the package rather than the
  ## transport: the same call restores a package that came off the relay, out
  ## of a file, or from a courier nobody trusts.
  var
    opened: tuple[ok: bool, payload: ByteSeq]
  result.packageId = packageId
  try:
    opened = openSecurePackageWithEpoch(a.current, packageId, wire,
      compression, a.sessionId, inboundAmeDirection(a.endpointRole))
    if not opened.ok and a.retiring.epochId != 0'u32:
      opened = openSecurePackageWithEpoch(a.retiring, packageId, wire,
        compression, a.sessionId, inboundAmeDirection(a.endpointRole))
  except CatchableError as e:
    result.err = e.msg
    return
  if not opened.ok:
    result.err = "AME secure-package authentication failed"
    return
  result.payload = opened.payload
  result.ok = true

proc finishAmeSecurePackage*(a: AmeAuthPackage, S: DacPackageReceiver,
    compression: AmeCompressionPolicy = defaultAmeCompressionPolicy()):
    AmeSecurePackageResult {.role: orchestrator.} =
  ## a/S/compression: established epochs, repaired receiver, negotiated codec.
  ## The hand-driven path: the caller owned the receiver and did its own
  ## repair. A live session should use the relay instead.
  var
    assembled: DacPackageResult = finishDacPackage(S)
  if not assembled.ok:
    result.err = assembled.err
    return
  result = restoreAmeSecurePackage(a, S.manifest.packageId,
    assembled.payload, compression)
  result.digest = S.manifest.digest
  result.dataCount = S.manifest.dataCount
  result.repairCount = S.repairCount
  result.status = if S.repairCount == 0'u16: dcsCommitted else:
    dcsCommittedWithRepair

proc sendAmeSecurePackage*(R: var AmeDacRelay, key: DacLinkKey,
    packageId: uint64, plaintext: openArray[uint8], nowMs: uint32,
    compression: AmeCompressionPolicy = defaultAmeCompressionPolicy()):
    AmeDacRelayStep {.role: orchestrator.} =
  ## R/key: relay and the peer the package goes to.
  ## packageId/plaintext/nowMs: package identity, application bytes, clock.
  ## compression: codec both ends agreed on.
  ##
  ## This path COMPRESSES ONLY, and takes no key material. Sealing here would
  ## encrypt bytes that are about to be encrypted again one datagram at a
  ## time -- exactly the double wrapping the rest of AME was rid of.
  ##
  ## Where the repair data sits, and why it differs from the file path
  ## -----------------------------------------------------------------
  ## There are two honest orderings, and which one applies is forced by where
  ## the sealing happens.
  ##
  ##   file path (planAmeSecurePackage)
  ##     seal the whole package once, THEN cut it up and add parity
  ##     -> parity is computed over ciphertext, sits outside the tag
  ##     -> a relay repairs it without holding any key
  ##
  ##   live path (here)
  ##     cut the package up, compute parity, THEN seal each piece separately
  ##     -> parity is computed over plaintext, sits inside the tags
  ##     -> only an endpoint can repair, because only it can decrypt
  ##
  ## The live path cannot use the first ordering. Each datagram is sealed
  ## with its own ratchet key, so two sealed datagrams XORed together are not
  ## a sealed datagram -- parity across them would be meaningless. Sealing
  ## per datagram and erasure-coding across datagrams cannot both be the
  ## outer layer.
  ##
  ## That is safe here because the loss being repaired is a WHOLE MISSING
  ## datagram, not a flipped bit. A datagram that arrives damaged fails its
  ## own tag and is dropped, which looks exactly like one that never came. A
  ## piece rebuilt from parity is then checked twice over: the manifest
  ## carrying the package's BLAKE3 digest is itself a sealed message, and
  ## `finishDacPackage` compares the reassembled bytes against that digest
  ## before committing. So nothing an attacker supplies is ever handed up.
  ##
  ## If bit-level correction is ever wanted instead of whole-piece recovery,
  ## it MUST go on the file path's side of the tag. Correcting bits underneath
  ## an authenticator is dead code: the tag rejects the message before the
  ## correction ever runs.
  result = sendAmeDacPackage(R, key, packageId,
    encodeAmeCompressed(plaintext, compression), nowMs)

proc openAmeSecurePackageStep*(packageId: uint64, step: AmeDacRelayStep,
    compression: AmeCompressionPolicy = defaultAmeCompressionPolicy()):
    AmeSecurePackageResult {.role: orchestrator.} =
  ## packageId/compression: expected package identity and the agreed codec.
  ## step: a relay step whose kind is adrPackageComplete.
  ## Turns the relay's finished payload back into plaintext, so a caller never
  ## has to own a DacPackageReceiver to receive a package. The bytes arrived
  ## authenticated, so all that is left is bounded decompression.
  result.packageId = packageId
  if step.kind != adrPackageComplete:
    result.err = "AME secure package needs a completed relay step"
    return
  try:
    result.payload = decodeAmeCompressed(step.payload, compression)
  except CatchableError as e:
    result.err = e.msg
    return
  result.ok = true

proc planAmeSecurePackage*(S: AmeSession, packageId: uint64,
    plaintext: openArray[uint8],
    compression: AmeCompressionPolicy = defaultAmeCompressionPolicy(),
    limits: DacPackageLimits = defaultDacPackageLimits()):
    AmeSecurePackagePlan {.role: orchestrator,
    metaTags: {tagAppApi, tagAme, tagProtocol}.} =
  ## S/packageId/plaintext/compression/limits: same as the overload above,
  ## except the DAC parameters come from the session's own path profile
  ## instead of the caller.
  ##
  ## Prefer this one. The other takes a `DacScenarioDefaults` the caller has
  ## to keep in step with the session by hand, and nothing checks that they
  ## agree; here the chunk size and repair strength are the ones the path this
  ## session is actually running over calls for.
  result = planAmeSecurePackage(S.auth, packageId, plaintext,
    ameSessionPathDefaults(S), compression, limits)
