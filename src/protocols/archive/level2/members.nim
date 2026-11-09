## -------------------------------------------------------------------------
## Archive Members <- who wrote it, when everybody holds the same key
## -------------------------------------------------------------------------
##
## All members of a space hold one secret, so any of them can seal a record on
## any lane. With two people that is enough: "not me" means "the other one".
## With three, it is not. So in a group every record carries a signature.
##
## ╭─ ❧ Def. 1: a signed record 🌊
##
##   +-------+---------------------+-----------------------+
##   | count | count x u16 + proof | the sealed bytes      |
##   | u8    |                     |                       |
##   +-------+---------------------+-----------------------+
##
##   One proof per signature slot of the writer's key. EVERY slot must verify,
##   so breaking one algorithm is not enough to write as somebody else.
##
##   signed text = "ARCHIVE-MEMBER-v1" | u16 + label | u16 + place | sealed bytes
##
## `label` says what kind of thing this is and `place` where it belongs (a space
## id), so a signature cannot be moved to something else.

import ../../types
import ../../ame/types
import ../../ame/level0/bytes
import ../../ame/level1/signatures
import ../../ame/level3/handshake_identity
import ../types
import ../level1/keys
import ./account
import runePragmas

const
  archiveMemberLogLabel* = "log"
    ## the label of a log record in a space

proc memberText(label: string, place, sealed: openArray[uint8]): ByteSeq {.
    role: truthBuilder.} =
  ## label/place/sealed: Def. 1, the signed text.
  appendAmeLabel(result, "ARCHIVE-MEMBER-v1")
  appendSizedArchive(result, toBytesArchive(label))
  appendSizedArchive(result, place)
  appendAmeBytes(result, sealed)

proc signArchiveMember*(i: AmeIdentityKey, label: string,
    place, sealed: openArray[uint8]): ByteSeq {.role: encryptor,
    tag: "archive|appApi|cryptoBoundary".} =
  ## i: the writer's keys. label/place/sealed: Def. 1. Returns the signed record.
  var
    text: ByteSeq = memberText(label, place, sealed)
    k: int = 0
  if i.signingKeys.len == 0 or i.signingKeys.len > 255 or
      i.signingKeys.len != i.secretKeys.len:
    raise newException(ValueError, "archive member needs matching signing keys")
  result.add(uint8(i.signingKeys.len))
  while k < i.signingKeys.len:
    appendSizedArchive(result, signAmeMessage(i.signingKeys[k].algorithm, text,
      i.secretKeys[k]))
    k = k + 1
  appendAmeBytes(result, sealed)

proc slotHolds(k: AmeIdentitySigningKey, text: openArray[uint8],
    proof: ByteSeq): bool {.role: parser, inline.} =
  ## k/text/proof: true when this one proof verifies. Nothing here raises.
  try:
    result = verifyAmeMessage(k.algorithm, text, proof, k.publicKey)
  except CatchableError:
    result = false

proc verifySlots(K: openArray[AmeIdentitySigningKey], text: openArray[uint8],
    P: openArray[ByteSeq]): bool {.role: parser.} =
  ## K/text/P: true when every key has a proof and every proof verifies.
  var
    i: int = 0
  if K.len == 0 or K.len != P.len:
    return false
  while i < K.len and slotHolds(K[i], text, P[i]):
    i = i + 1
  result = i == K.len

proc openArchiveMember*(K: openArray[AmeIdentitySigningKey], label: string,
    place, A: openArray[uint8]): tuple[ok: bool, sealed: ByteSeq] {.role: parser,
    tag: "archive|appApi|cryptoBoundary".} =
  ## K: the public keys of the one who should have written it. label/place:
  ## as signed. A: the signed record. Nothing here raises.
  var
    o: int = 1
    i: int = 0
    P: seq[ByteSeq] = @[]
  if A.len < 1:
    return
  try:
    while i < int(A[0]):
      P.add(takeSizedArchive(A, o))
      i = i + 1
  except ValueError:
    return
  if not verifySlots(K, memberText(label, place, A.toOpenArray(o, A.len - 1)), P):
    return
  result = (true, @(A.toOpenArray(o, A.len - 1)))
