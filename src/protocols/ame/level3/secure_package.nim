## -------------------------------------------------------------------------
## AME Secure Package <- compress -> authenticate -> DAC repair -> restore
## -------------------------------------------------------------------------

import ../../types
import ../types
import ../level2/session
import ../level1/compression
import ../level0/bytes
import ../level2/protection
import ../../dac/types
import ../../dac/level2/package_transfer
import ../../../analysis_pragmas

const
  ameSecurePackageMagic* = [uint8('A'), uint8('S'), uint8('P'), uint8('1')]
  ameSecurePackageHeaderLen* = 16

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
    compression: AmeCompressionAlgorithm): ByteSeq {.role: truthBuilder.} =
  ## packageId/epochId/compression: package identity bound to AME authentication.
  appendAmeLabel(result, "AME-SECURE-PACKAGE-v1")
  appendAmeU64(result, packageId)
  appendAmeU32(result, epochId)
  result.add(uint8(ord(compression)))

proc encodeSecurePackage(epochId: uint32, nonce: openArray[uint8],
    m: AmeProtectedMessage): ByteSeq {.role: stateController.} =
  ## epochId/nonce/m: detached AME protection fields made packageable.
  requireAmeU16Len(nonce.len, "secure-package nonce")
  requireAmeU16Len(m.authTag.len, "secure-package tag")
  requireAmeU32Len(m.payload.len, "secure-package ciphertext")
  appendAmeBytes(result, ameSecurePackageMagic)
  appendAmeU32(result, epochId)
  appendAmeU16(result, uint16(nonce.len))
  appendAmeU16(result, uint16(m.authTag.len))
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
    nonce: ByteSeq, message: AmeProtectedMessage] {.role: parser.} =
  ## A: complete authenticated-package envelope.
  var
    nonceLen: int = 0
    tagLen: int = 0
    payloadLen: int = 0
    offset: int = ameSecurePackageHeaderLen
  if A.len < ameSecurePackageHeaderLen or A[0 .. 3] != ameSecurePackageMagic:
    raise newException(ValueError, "AME secure-package identity mismatch")
  result.epochId = readSecurePackageU32(A, 4)
  nonceLen = int(readSecurePackageU16(A, 8))
  tagLen = int(readSecurePackageU16(A, 10))
  payloadLen = checkedAmeWireLen(readSecurePackageU32(A, 12),
    uint32(defaultAmeMaxFrameBytes), "secure-package ciphertext")
  if nonceLen <= 0 or tagLen != ameProtectionAuthTagLen or
      A.len != offset + nonceLen + tagLen + payloadLen:
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
    securePackageAad(packageId, a.current.epochId, compression.algorithm),
    keyContext)
  wire = encodeSecurePackage(a.current.epochId, sealed.nonce, sealed.message)
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
  keyContext = ameEpochKeyContext(E, sessionId, direction)
  opened = openAmeMessage(E.layout, E.tier, E.exchange, decoded.nonce,
    decoded.message, securePackageAad(packageId, E.epochId,
    compression.algorithm), keyContext)
  if not opened.ok:
    return
  result.payload = decodeAmeCompressed(opened.payload, compression)
  result.ok = true

proc finishAmeSecurePackage*(a: AmeAuthPackage, S: DacPackageReceiver,
    compression: AmeCompressionPolicy = defaultAmeCompressionPolicy()):
    AmeSecurePackageResult {.role: orchestrator.} =
  ## a/S/compression: established epochs, repaired receiver, negotiated codec.
  var
    assembled: DacPackageResult = finishDacPackage(S)
    opened: tuple[ok: bool, payload: ByteSeq]
  if not assembled.ok:
    result.err = assembled.err
    return
  result.packageId = S.manifest.packageId
  result.digest = S.manifest.digest
  result.dataCount = S.manifest.dataCount
  result.repairCount = S.repairCount
  result.status = if S.repairCount == 0'u16: dcsCommitted else:
    dcsCommittedWithRepair
  try:
    opened = openSecurePackageWithEpoch(a.current, S.manifest.packageId,
      assembled.payload, compression, a.sessionId,
      inboundAmeDirection(a.endpointRole))
    if not opened.ok and a.retiring.epochId != 0'u32:
      opened = openSecurePackageWithEpoch(a.retiring, S.manifest.packageId,
        assembled.payload, compression, a.sessionId,
        inboundAmeDirection(a.endpointRole))
  except CatchableError as e:
    result.err = e.msg
    return
  if not opened.ok:
    result.err = "AME secure-package authentication failed"
    return
  result.payload = opened.payload
  result.ok = true
