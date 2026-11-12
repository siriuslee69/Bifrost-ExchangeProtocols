## -------------------------------------------------------------------------
## Enrollment roster <- who is a member: two lists and the enroller's pin
## -------------------------------------------------------------------------
##
##   a key is a member of group G when
##     it is in the predefined list, OR
##     the operator added it, OR
##     it holds a valid enroller-signed enrollment naming (G, that key)
##
## The roster touches no disk. encodeGroupRoster / decodeGroupRoster turn it
## into bytes so a caller (the operator CLI, or Nebel) can keep it. The
## predefined list is configuration; the CLI only edits the added list.

import ../../types
import ../../ame/types
import ../../ame/level0/bytes
import ../../ame/level3/handshake_identity
import ../../byte_codec
import ../types
import ../level0/token
import runePragmas

## ╭⟢ building and editing

proc initGroupRoster*(enroller: AmeAuthorityRoot,
    predefined: openArray[string] = []): GroupRoster {.role: configurator.} =
  ## enroller/predefined: the pinned enroller public key, and the key ids
  ## admitted without a token.
  var
    i: int = 0
  result.enroller = enroller
  while i < predefined.len:
    result.predefined.add(predefined[i])
    i = i + 1

proc rosterHasKey*(R: GroupRoster, keyId: string): bool {.role: parser.} =
  ## R/keyId: true when either list names this key.
  result = keyId in R.predefined or keyId in R.added

proc addRosterKey*(R: var GroupRoster, keyId: string): tuple[ok: bool,
    err: string] {.role: actor, tag: "enrollment|appApi".} =
  ## R/keyId: the operator admits this key by hand. ok when added, else err
  ## says why nothing changed.
  if keyId.len != enrollmentKeyIdChars:
    return (ok: false, err: "a key id is " & $enrollmentKeyIdChars &
      " hex characters")
  if rosterHasKey(R, keyId):
    return (ok: false, err: "key is already in the roster")
  if R.added.len >= enrollmentMaxKeys:
    return (ok: false, err: "the roster holds at most " & $enrollmentMaxKeys &
      " added keys")
  R.added.add(keyId)
  result = (ok: true, err: "")

proc removeRosterKey*(R: var GroupRoster, keyId: string): tuple[ok: bool,
    err: string] {.role: actor, tag: "enrollment|appApi".} =
  ## R/keyId: the operator takes this key out of the added list. The
  ## predefined list is configuration and is not edited here.
  var
    i: int = 0
  while i < R.added.len:
    if R.added[i] == keyId:
      R.added.delete(i)
      return (ok: true, err: "")
    i = i + 1
  result = (ok: false, err: "key is not in the added list")

## ╭⟢ the membership question

proc groupMemberAllowed*(R: GroupRoster, group: string,
    memberKeys: openArray[AmeIdentitySigningKey], E: GroupEnrollment,
    nowUnix: int64): tuple[ok: bool, err: string] {.role: orchestrator,
    tag: "enrollment|appApi".} =
  ## R/group/memberKeys/E/nowUnix: is this key a member of this group? The
  ## lists admit it directly; otherwise a valid enrollment must name this
  ## group and this very key. E may be empty (no token presented).
  var
    keyId: string = ameIdentityKeyId(memberKeys)
  if rosterHasKey(R, keyId):
    return (ok: true, err: "")
  if E.proofs.len == 0:
    return (ok: false, err: "key is not in the roster and no enrollment was presented")
  if E.group != group:
    return (ok: false, err: "enrollment names a different group")
  if E.memberKeyId != keyId:
    return (ok: false, err: "enrollment names a different key")
  result = verifyGroupEnrollment(E, R.enroller, nowUnix)

## ╭⟢ the saved form
##
##   u8 version | u32+enrollerName
##   u8 keyCount | { u8 alg, u32+publicKey } ...
##   u32 predefinedCount | { u32+keyId } ...
##   u32 addedCount | { u32+keyId } ...

proc appendRosterKeyList(A: var ByteSeq, K: openArray[string]) {.
    role: dataWriter.} =
  ## A/K: destination and one u32-counted list of key ids.
  var
    i: int = 0
  appendU32Le(A, uint32(K.len))
  while i < K.len:
    appendHandshakeString(A, K[i])
    i = i + 1

proc appendRosterSigningKeys(A: var ByteSeq,
    K: openArray[AmeIdentitySigningKey]) {.role: dataWriter.} =
  ## A/K: destination and the enroller's ordered public-key stack.
  var
    i: int = 0
  if K.len == 0 or K.len > enrollmentMaxProofs:
    raise newException(ValueError, "enroller signing-key count is invalid")
  A.add(uint8(K.len))
  while i < K.len:
    A.add(uint8(ord(K[i].algorithm)))
    appendHandshakeBytes(A, K[i].publicKey)
    i = i + 1

proc encodeGroupRoster*(R: GroupRoster): ByteSeq {.role: dataWriter.} =
  ## R: the roster as bytes, so a caller can keep it.
  result.add(enrollmentVersion)
  appendHandshakeString(result, R.enroller.authority)
  appendRosterSigningKeys(result, R.enroller.signingKeys)
  appendRosterKeyList(result, R.predefined)
  appendRosterKeyList(result, R.added)

proc takeRosterKeyList(A: openArray[uint8], o: var int,
    K: var seq[string]) {.role: parser.} =
  ## A/o/K: source, cursor, and the list being filled; refuses an over-sized
  ## count before reading it.
  var
    n: uint32 = takeEnrollU32(A, o)
    i: int = 0
  if n > uint32(enrollmentMaxKeys):
    raise newException(ValueError, "roster keeps too many keys in one list")
  while i < int(n):
    K.add(takeEnrollString(A, o))
    i = i + 1

proc decodeGroupRoster*(A: openArray[uint8]): tuple[ok: bool,
    roster: GroupRoster, err: string] {.role: parser.} =
  ## A: roster bytes. Refuses a truncated or over-sized roster; never raises.
  var
    o: int = 0
    R: GroupRoster = default(GroupRoster)
    keyCount: uint8 = 0
    i: int = 0
    alg: uint8 = 0
    pub: ByteSeq = @[]
  try:
    if takeEnrollU8(A, o) != enrollmentVersion:
      return (ok: false, roster: R, err: "roster version is not supported")
    R.enroller.authority = takeEnrollString(A, o)
    keyCount = takeEnrollU8(A, o)
    if keyCount == 0 or int(keyCount) > enrollmentMaxProofs:
      return (ok: false, roster: R, err: "enroller signing-key count is invalid")
    while i < int(keyCount):
      alg = takeEnrollU8(A, o)
      if alg < uint8(ord(low(AmeSignatureAlgorithm))) or
          alg > uint8(ord(high(AmeSignatureAlgorithm))):
        return (ok: false, roster: R, err: "enroller key algorithm is unknown")
      pub = takeEnrollBytes(A, o)
      R.enroller.signingKeys.add(AmeIdentitySigningKey(
        algorithm: AmeSignatureAlgorithm(alg), publicKey: pub))
      i = i + 1
    takeRosterKeyList(A, o, R.predefined)
    takeRosterKeyList(A, o, R.added)
  except ValueError as e:
    return (ok: false, roster: R, err: e.msg)
  result = (ok: true, roster: R, err: "")