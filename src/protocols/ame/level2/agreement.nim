## -------------------------------------------------------------------------
## AME Agreement <- immutable layout plus initial tier accept-or-reject
## -------------------------------------------------------------------------

import ../../types
import ../types
import ../level0/bytes
import ../level1/suites
import ../level1/path_triggers
import ../../../analysis_pragmas

proc readAgreementU32(A: openArray[uint8], o: int): uint32 {.role: parser.} =
  ## A/o: source bytes and little-endian offset.
  if o < 0 or o > A.len - 4:
    raise newException(ValueError, "AME agreement is truncated")
  result = uint32(A[o]) or (uint32(A[o + 1]) shl 8) or
    (uint32(A[o + 2]) shl 16) or (uint32(A[o + 3]) shl 24)

proc initAmeAgreementProposal*(proposalId: uint32,
    L: AmeSuiteLayout, initialTier: AmeMaskTier): AmeAgreementProposal {.
    role: wrapper.} =
  ## proposalId/L/initialTier: unique id and exact initial selection.
  if proposalId == 0'u32:
    raise newException(ValueError, "AME agreement proposal id must be positive")
  validateAmeTier(L, initialTier)
  result.proposalId = proposalId
  result.layout = L
  result.initialTier = initialTier

proc decideAmeAgreement*(p: AmeAgreementProposal,
    supported: openArray[AmeTierPath]): AmeAgreementDecision {.
    role: truthBuilder.} =
  ## p/supported: exact proposal and locally allowed layout/tier paths.
  var
    i: int = 0
    encoded: ByteSeq = encodeAmeSuiteLayout(p.layout)
  result.proposalId = p.proposalId
  result.selectionHash = hashAmeTier(p.layout, p.initialTier, encoded, 32)
  while i < supported.len:
    if layoutsEquivalent(p.layout, supported[i].layout) and
        ameTierPathContains(supported[i], p.initialTier):
      result.accepted = true
      return
    i = i + 1
  result.reason = "exact AME layout and initial tier are not supported"

proc verifyAmeAgreementDecision*(p: AmeAgreementProposal,
    d: AmeAgreementDecision): bool {.role: parser.} =
  ## p/d: original proposal and received peer decision.
  var encoded: ByteSeq = @[]
  if d.proposalId != p.proposalId or d.selectionHash.len != 32:
    return false
  encoded = encodeAmeSuiteLayout(p.layout)
  result = d.selectionHash == hashAmeTier(p.layout, p.initialTier, encoded, 32)

proc encodeAmeAgreementProposal*(p: AmeAgreementProposal): ByteSeq {.
    role: stateController.} =
  ## p: canonical proposal bytes.
  var
    layout: ByteSeq = encodeAmeSuiteLayout(p.layout)
    tier: ByteSeq = encodeAmeMaskTier(p.initialTier)
  appendAmeU32(result, p.proposalId)
  appendAmeU32(result, uint32(layout.len))
  appendAmeBytes(result, layout)
  appendAmeBytes(result, tier)

proc decodeAmeAgreementProposal*(A: openArray[uint8]): AmeAgreementProposal {.
    role: parser.} =
  ## A: canonical proposal bytes.
  var
    proposalId: uint32 = 0'u32
    n: int = 0
  if A.len < 20:
    raise newException(ValueError, "AME agreement proposal is too short")
  proposalId = readAgreementU32(A, 0)
  n = checkedAmeWireLen(readAgreementU32(A, 4),
    uint32(defaultAmeMaxFrameBytes), "AME agreement layout")
  if n <= 0 or A.len != 8 + n + 11:
    raise newException(ValueError, "AME agreement proposal length mismatch")
  result.layout = decodeAmeSuiteLayout(A.toOpenArray(8, 8 + n - 1))
  result = initAmeAgreementProposal(proposalId, result.layout,
    decodeAmeMaskTier(result.layout, A.toOpenArray(8 + n, A.high)))

proc encodeAmeAgreementDecision*(d: AmeAgreementDecision): ByteSeq {.
    role: stateController.} =
  ## d: canonical layout-and-initial-tier decision bytes.
  if d.proposalId == 0'u32 or d.selectionHash.len != 32:
    raise newException(ValueError, "AME agreement decision is invalid")
  if d.accepted and d.reason.len != 0:
    raise newException(ValueError, "AME accepted decision must not include a reason")
  if not d.accepted and d.reason.len == 0:
    raise newException(ValueError, "AME rejected decision requires a reason")
  requireAmeU32Len(d.reason.len, "agreement reason")
  appendAmeU32(result, d.proposalId)
  result.add(if d.accepted: 1'u8 else: 0'u8)
  appendAmeBytes(result, d.selectionHash)
  appendAmeU32(result, uint32(d.reason.len))
  for c in d.reason:
    result.add(uint8(ord(c)))

proc decodeAmeAgreementDecision*(A: openArray[uint8]): AmeAgreementDecision {.
    role: parser.} =
  ## A: canonical layout-and-initial-tier decision bytes.
  var
    n: int = 0
    i: int = 0
  if A.len < 41 or A[4] > 1'u8:
    raise newException(ValueError, "AME agreement decision is invalid")
  result.proposalId = readAgreementU32(A, 0)
  result.accepted = A[4] == 1'u8
  result.selectionHash = @A[5 .. 36]
  if result.proposalId == 0'u32:
    raise newException(ValueError, "AME agreement decision id must be positive")
  n = checkedAmeWireLen(readAgreementU32(A, 37), 4096'u32,
    "agreement reason")
  if A.len != 41 + n:
    raise newException(ValueError, "AME agreement decision length mismatch")
  result.reason = newString(n)
  while i < n:
    result.reason[i] = char(A[41 + i])
    i = i + 1
  if result.accepted and result.reason.len != 0:
    raise newException(ValueError, "AME accepted decision must not include a reason")
  if not result.accepted and result.reason.len == 0:
    raise newException(ValueError, "AME rejected decision requires a reason")
