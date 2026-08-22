## -------------------------------------------------------------------------
## AME Trust <- validated handoff from an external identity verifier
## -------------------------------------------------------------------------

import ../types
import ../../../analysis_pragmas

proc initVerifiedAmePeerTrust*(authority, subjectKeyId: string,
    algorithms: openArray[AmeSignatureAlgorithm]): AmePeerTrustResult {.
    role: wrapper.} =
  ## authority/subjectKeyId/algorithms: evidence already verified by the
  ## caller's certificate, key-directory, or provisioning policy. The
  ## algorithm list is the whole stack that was checked, not just the first
  ## one, so a caller cannot record a hybrid identity as if one signature had
  ## carried it.
  if authority.len == 0 or subjectKeyId.len == 0 or algorithms.len == 0:
    raise newException(ValueError, "AME verified peer trust requires identity evidence")
  result.ok = true
  result.authority = authority
  result.algorithms = @algorithms
  result.subjectKeyId = subjectKeyId

proc initRejectedAmePeerTrust*(err: string): AmePeerTrustResult {.
    role: wrapper.} =
  ## err: external verifier failure retained for the AME trust gate.
  if err.len == 0:
    raise newException(ValueError, "AME rejected peer trust requires an error")
  result.err = err
