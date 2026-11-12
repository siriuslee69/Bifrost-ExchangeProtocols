## -------------------------------------------------------------------------
## Enrollment token <- the enroller's signed admission, as bytes
## -------------------------------------------------------------------------
##
## One canonical encoding, used BOTH as the thing the enroller signs and as
## the thing that travels over the wire:
##
##   u8 version | u32+group | u32+memberKeyId | u64 serial
##   i64 validFrom | i64 validUntil | u32 proofCount | { u32+proof } ...
##
## The signed text is the domain label plus every field except the proofs:
##
##   "GROUP-ENROLL-v1" | version | group | memberKeyId | serial | window
##
## Every enroller slot signs and every slot must verify, so breaking one
## algorithm is not enough to forge an admission. This is the same key-stack
## rule the AME identity certificates use, reusing signAmeMessage and
## verifyAmeMessage rather than a second signature path.

import ../../types
import ../../ame/types
import ../../ame/level0/bytes
import ../../ame/level1/signatures
import ../../ame/level3/handshake_identity
import ../../byte_codec
import ../types
import runePragmas

## ╭⟢ the signed bytes

proc enrollmentBody(E: GroupEnrollment): ByteSeq {.role: truthBuilder.} =
  ## E: every field the enroller signs, in wire order, without the label.
  result.add(enrollmentVersion)
  appendHandshakeString(result, E.group)
  appendHandshakeString(result, E.memberKeyId)
  appendU64Le(result, E.serial)
  appendHandshakeI64(result, E.validFromUnix)
  appendHandshakeI64(result, E.validUntilUnix)

proc enrollmentSignedText(E: GroupEnrollment): ByteSeq {.role: truthBuilder.} =
  ## E: exactly the bytes the enroller's proofs cover.
  appendAmeLabel(result, enrollmentLabel)
  appendAmeBytes(result, enrollmentBody(E))

## ╭⟢ issuing and judging

proc issueGroupEnrollment*(enroller: AmeAuthorityKey, group: string,
    member: AmeIdentityKey, serial: uint64,
    validFromUnix, validUntilUnix: int64): GroupEnrollment {.
    role: orchestrator, tag: "enrollment|appApi|cryptoBoundary".} =
  ## enroller/group/member/serial/timestamps: the signing enroller, the group
  ## name, the member's keys, a positive serial, and the inclusive validity
  ## window. Every enroller slot signs. This is the operator's own call, so a
  ## bad request raises rather than travelling to a stranger.
  var
    text: ByteSeq = @[]
    j: int = 0
  if group.len == 0 or group.len > enrollmentMaxGroupBytes:
    raise newException(ValueError, "enrollment group name is invalid")
  if serial == 0'u64:
    raise newException(ValueError, "enrollment serial must be positive")
  if validFromUnix < 0 or validUntilUnix <= validFromUnix:
    raise newException(ValueError, "enrollment validity range is invalid")
  if enroller.signingKeys.len == 0 or
      enroller.signingKeys.len != enroller.secretKeys.len:
    raise newException(ValueError, "enroller key stack is incomplete")
  if member.signingKeys.len == 0:
    raise newException(ValueError, "member has no public keys")
  result.group = group
  result.memberKeyId = ameIdentityKeyId(member.signingKeys)
  result.serial = serial
  result.validFromUnix = validFromUnix
  result.validUntilUnix = validUntilUnix
  text = enrollmentSignedText(result)
  while j < enroller.signingKeys.len:
    result.proofs.add(signAmeMessage(enroller.signingKeys[j].algorithm, text,
      enroller.secretKeys[j]))
    j = j + 1

proc verifyGroupEnrollment*(E: GroupEnrollment, root: AmeAuthorityRoot,
    nowUnix: int64): tuple[ok: bool, err: string] {.role: orchestrator,
    tag: "enrollment|cryptoBoundary".} =
  ## E/root/nowUnix: the admission, the pinned enroller public key, and a
  ## trusted clock. ok when every enroller slot verifies and the window holds.
  ## Nothing here raises: a stranger's bytes only ever earn an err.
  var
    text: ByteSeq = @[]
    i: int = 0
  if root.authority.len == 0 or root.signingKeys.len == 0:
    return (ok: false, err: "enroller root is incomplete")
  if E.group.len == 0 or E.memberKeyId.len != enrollmentKeyIdChars:
    return (ok: false, err: "enrollment identity is incomplete")
  if E.serial == 0'u64:
    return (ok: false, err: "enrollment serial must be positive")
  if E.proofs.len != root.signingKeys.len:
    return (ok: false, err: "enrollment proof count does not match the enroller")
  if E.validUntilUnix <= E.validFromUnix:
    return (ok: false, err: "enrollment validity range is invalid")
  if nowUnix < E.validFromUnix or nowUnix > E.validUntilUnix:
    return (ok: false, err: "enrollment is outside its validity period")
  text = enrollmentSignedText(E)
  try:
    while i < root.signingKeys.len:
      if not verifyAmeMessage(root.signingKeys[i].algorithm, text, E.proofs[i],
          root.signingKeys[i].publicKey):
        return (ok: false, err: "enrollment proof is invalid")
      i = i + 1
  except CatchableError as e:
    return (ok: false, err: "enrollment verification failed: " & e.msg)
  result = (ok: true, err: "")

## ╭⟢ length-framed readers (shared with the roster codec next door)
##
## Each one refuses a value that reaches past the end, so a truncated token
## can never be read beyond what it holds.

proc takeEnrollU8*(A: openArray[uint8], o: var int): uint8 {.role: parser.} =
  ## A/o: source bytes and cursor; consume one byte.
  if o < 0 or o > A.len - 1:
    raise newException(ValueError, "enrollment is truncated")
  result = A[o]
  o = o + 1

proc takeEnrollU32*(A: openArray[uint8], o: var int): uint32 {.role: parser.} =
  ## A/o: source bytes and cursor; consume one little-endian u32.
  if o < 0 or o > A.len - 4:
    raise newException(ValueError, "enrollment is truncated")
  result = readU32Le(A, o)
  o = o + 4

proc takeEnrollU64*(A: openArray[uint8], o: var int): uint64 {.role: parser.} =
  ## A/o: source bytes and cursor; consume one little-endian u64.
  if o < 0 or o > A.len - 8:
    raise newException(ValueError, "enrollment is truncated")
  result = readU64Le(A, o)
  o = o + 8

proc takeEnrollBytes*(A: openArray[uint8], o: var int): ByteSeq {.role: parser.} =
  ## A/o: source bytes and cursor; consume a u32-length-framed byte field.
  var
    n: uint32 = takeEnrollU32(A, o)
  if uint64(n) > uint64(A.len - o):
    raise newException(ValueError, "enrollment field reaches past the end")
  result = @(A.toOpenArray(o, o + int(n) - 1))
  o = o + int(n)

proc takeEnrollString*(A: openArray[uint8], o: var int): string {.role: parser.} =
  ## A/o: source bytes and cursor; consume a u32-length-framed text field.
  var
    bs: ByteSeq = takeEnrollBytes(A, o)
  result = bytesToString(bs)

## ╭⟢ the wire form

proc encodeGroupEnrollment*(E: GroupEnrollment): ByteSeq {.role: dataWriter.} =
  ## E: the admission as wire bytes (version + fields + proofs).
  result = enrollmentBody(E)
  appendHandshakeProofs(result, E.proofs)

proc decodeGroupEnrollment*(A: openArray[uint8]): tuple[ok: bool,
    enrollment: GroupEnrollment, err: string] {.role: parser.} =
  ## A: wire bytes. Refuses a truncated or over-sized token; never raises.
  var
    o: int = 0
    E: GroupEnrollment = default(GroupEnrollment)
    count: uint32 = 0
    i: int = 0
  try:
    if takeEnrollU8(A, o) != enrollmentVersion:
      return (ok: false, enrollment: E, err: "enrollment version is not supported")
    E.group = takeEnrollString(A, o)
    E.memberKeyId = takeEnrollString(A, o)
    E.serial = takeEnrollU64(A, o)
    E.validFromUnix = cast[int64](takeEnrollU64(A, o))
    E.validUntilUnix = cast[int64](takeEnrollU64(A, o))
    count = takeEnrollU32(A, o)
    if count > uint32(enrollmentMaxProofs):
      return (ok: false, enrollment: E, err: "enrollment carries too many proofs")
    while i < int(count):
      E.proofs.add(takeEnrollBytes(A, o))
      i = i + 1
  except ValueError as e:
    return (ok: false, enrollment: E, err: e.msg)
  if E.group.len > enrollmentMaxGroupBytes:
    return (ok: false, enrollment: E, err: "enrollment group name is too long")
  result = (ok: true, enrollment: E, err: "")

## ╭⟢ the enroller key, for the operator's own keeping
##
##   u8 version | u32+name | u8 keyCount
##   { u8 alg, u32+publicKey, u32+secretKey } ...
##
## The secret half is written only by the operator CLI into a file the operator
## protects; it never travels to a peer.

proc encodeGroupEnroller*(e: AmeAuthorityKey): ByteSeq {.role: dataWriter,
    tag: "enrollment|cryptoBoundary".} =
  ## e: the enroller's name and full key stack, as bytes for local keeping.
  var
    i: int = 0
  if e.signingKeys.len == 0 or e.signingKeys.len != e.secretKeys.len:
    raise newException(ValueError, "enroller key stack is incomplete")
  result.add(enrollmentVersion)
  appendHandshakeString(result, e.name)
  result.add(uint8(e.signingKeys.len))
  while i < e.signingKeys.len:
    result.add(uint8(ord(e.signingKeys[i].algorithm)))
    appendHandshakeBytes(result, e.signingKeys[i].publicKey)
    appendHandshakeBytes(result, e.secretKeys[i])
    i = i + 1

proc decodeGroupEnroller*(A: openArray[uint8]): tuple[ok: bool,
    enroller: AmeAuthorityKey, err: string] {.role: parser,
    tag: "enrollment|cryptoBoundary".} =
  ## A: enroller bytes. Refuses a truncated or over-sized key; never raises.
  var
    o: int = 0
    e: AmeAuthorityKey = default(AmeAuthorityKey)
    keyCount: uint8 = 0
    i: int = 0
    alg: uint8 = 0
    pub: ByteSeq = @[]
    sec: ByteSeq = @[]
  try:
    if takeEnrollU8(A, o) != enrollmentVersion:
      return (ok: false, enroller: e, err: "enroller version is not supported")
    e.name = takeEnrollString(A, o)
    keyCount = takeEnrollU8(A, o)
    if keyCount == 0 or int(keyCount) > enrollmentMaxProofs:
      return (ok: false, enroller: e, err: "enroller signing-key count is invalid")
    while i < int(keyCount):
      alg = takeEnrollU8(A, o)
      if alg < uint8(ord(low(AmeSignatureAlgorithm))) or
          alg > uint8(ord(high(AmeSignatureAlgorithm))):
        return (ok: false, enroller: e, err: "enroller key algorithm is unknown")
      pub = takeEnrollBytes(A, o)
      sec = takeEnrollBytes(A, o)
      e.signingKeys.add(AmeIdentitySigningKey(
        algorithm: AmeSignatureAlgorithm(alg), publicKey: pub))
      e.secretKeys.add(sec)
      i = i + 1
  except ValueError as exc:
    return (ok: false, enroller: e, err: exc.msg)
  result = (ok: true, enroller: e, err: "")