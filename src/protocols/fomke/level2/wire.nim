## -------------------------------------------------------------------------
## FOMKE Wire <- bounded message and KEM-upgrade commit codecs
## -------------------------------------------------------------------------
##
## The message envelope, byte by byte:
##
##   +---+---+---+---+---+---+---+---+---+---+---+---+----+
##   |   epoch   |            index              |lane|
##   +---+---+---+---+---+---+---+---+---+---+---+---+----+
##     0..3        4..11                          12
##
##   then: tag (the length THIS session agreed), then ciphertext
##
## Thirteen bytes, and every one of them is something the receiver cannot
## work out for itself. Four things a reader might expect are deliberately
## absent, and each was removed because it repeated something already known:
##
##   no magic, no version   This envelope only ever travels as the body of
##                          an AME frame, and that frame's packet kind
##                          already says the body is one of these. A second
##                          name for the same thing is four wasted bytes on
##                          every message.
##   no nonce               Derived from the ratchet position, which both
##                          sides hold.
##   no ciphertext length   It is whatever is left after the tag. The frame
##                          that carries this envelope already delimits it.
##   no tag length          The receiver uses what its own epoch agreed and
##                          would refuse any other value anyway, so writing
##                          it down only offered an attacker a field to
##                          edit. `decodeFomkeMessage` is told the length by
##                          its caller instead -- which is also what makes a
##                          retiring epoch with a different tag length
##                          decode correctly rather than by luck.

import ../../types
import ../../ame/types
import ../../ame/level0/bytes
import ../types
import runePragmas

const
  fomkeUpgradeMagic = [uint8('F'), uint8('K'), uint8('U')]
  fomkeUpgradeVersion = 1'u8
  fomkeUpgradeFixedLen = 108

proc validateFomkeUpgradeShape(c: FomkeUpgradeCommit) {.role: parser,
    tag: "exchange|fomke|validation".} =
  ## c: public commit shape before wire encoding or after decoding.
  var
    i: int = 0
    selected: bool = false
  if c.requestId == 0'u32 or c.baseEpoch == 0'u32 or
      c.targetEpoch != c.baseEpoch + 1'u32 or c.targetTier.tierId == 0'u32 or
      c.targetTier.masks.kem == 0'u8 or c.targetTier.masks.cipher == 0'u8 or
      c.targetTier.masks.mac == 0'u8 or c.targetTier.masks.hash == 0'u8 or
      c.targetTier.masks.signature == 0'u8 or c.targetTier.masks.kdf == 0'u8 or
      c.confirmationTag.len != gb3BlockBytes:
    raise newException(ValueError, "FOMKE upgrade commit is invalid")
  while i < ameMaxAlgorithmSlots:
    selected = (c.exchangeMask and (1'u8 shl
      (ameMaxAlgorithmSlots - 1 - i))) != 0'u8
    if selected and c.generations[i] == 0'u32:
      raise newException(ValueError,
        "FOMKE selected upgrade generation is missing")
    if not selected and c.generations[i] != 0'u32:
      raise newException(ValueError,
        "FOMKE unselected upgrade generation is present")
    i = i + 1

proc readFomkeU32(A: openArray[uint8], offset: int): uint32 {.role: parser,
    tag: "fomke|parsing".} =
  ## A/offset: source and little-endian u32 position.
  if offset < 0 or offset > A.len - 4:
    raise newException(ValueError, "FOMKE u32 is truncated")
  result = uint32(A[offset]) or (uint32(A[offset + 1]) shl 8) or
    (uint32(A[offset + 2]) shl 16) or (uint32(A[offset + 3]) shl 24)

proc readFomkeU64(A: openArray[uint8], offset: int): uint64 {.role: parser,
    tag: "fomke|parsing".} =
  ## A/offset: source and little-endian u64 position.
  var
    i: int = 0
  if offset < 0 or offset > A.len - 8:
    raise newException(ValueError, "FOMKE u64 is truncated")
  while i < 8:
    result = result or (uint64(A[offset + i]) shl (8 * i))
    i = i + 1

proc fomkeLaneFromByte(v: uint8): FomkeLane {.role: parser,
    tag: "fomke|parsing".} =
  ## v: stable lane identifier.
  if v == uint8(ord(flLane1)):
    return flLane1
  if v == uint8(ord(flLane2)):
    return flLane2
  raise newException(ValueError, "FOMKE sender lane is invalid")

proc fomkeWireLen*(plaintextLen: int, tagLen: AmeAuthTagLen): int {.
    role: helper, tag: "appApi|fomke|packet".} =
  ## plaintextLen/tagLen: envelope size for a payload of this length. The
  ## ciphers are all keystream XOR, so the ciphertext is exactly as long as
  ## the plaintext -- the only growth is the header and the tag.
  if plaintextLen < 0 or uint64(plaintextLen) > uint64(fomkeMaxCiphertextBytes):
    raise newException(ValueError, "FOMKE ciphertext length exceeds its limit")
  result = fomkeHeaderLen + int(ord(tagLen)) + plaintextLen

proc encodeFomkeMessage*(m: FomkeMessage): ByteSeq {.role: dataWriter,
    tag: "appApi|codecBoundary|fomke|packet".} =
  ## m: complete forward-only message envelope.
  if m.epoch == 0'u32 or m.authTag.len != int(ord(m.tagLen)) or
      uint64(m.ciphertext.len) > uint64(fomkeMaxCiphertextBytes):
    raise newException(ValueError, "FOMKE message is invalid")
  appendAmeU32(result, m.epoch)
  appendAmeU64(result, m.index)
  result.add(uint8(ord(m.senderLane)))
  appendAmeBytes(result, m.authTag)
  appendAmeBytes(result, m.ciphertext)

proc decodeFomkeMessage*(A: openArray[uint8],
    tagLen: AmeAuthTagLen): FomkeMessage {.role: parser,
    tag: "appApi|codecBoundary|fomke|packet|parsing".} =
  ## A/tagLen: the envelope, and the tag length the caller's own epoch
  ## agreed. The length is a parameter rather than a field because it is the
  ## one thing here that must never come from the sender: a message that
  ## could name its own tag length could name a short one.
  var
    n: int = int(ord(tagLen))
    offset: int = fomkeHeaderLen
  if A.len < fomkeHeaderLen + n:
    raise newException(ValueError, "FOMKE message length mismatch")
  if uint64(A.len - fomkeHeaderLen - n) > uint64(fomkeMaxCiphertextBytes):
    raise newException(ValueError, "FOMKE ciphertext length exceeds its limit")
  result.epoch = readFomkeU32(A, 0)
  result.index = readFomkeU64(A, 4)
  result.senderLane = fomkeLaneFromByte(A[12])
  result.tagLen = tagLen
  if result.epoch == 0'u32:
    raise newException(ValueError, "FOMKE message epoch must be positive")
  result.authTag = @A[offset ..< offset + n]
  offset = offset + n
  result.ciphertext = @A[offset ..< A.len]

proc encodeFomkeUpgradeCommit*(c: FomkeUpgradeCommit): ByteSeq {.
    role: dataWriter,
    tag: "appApi|codecBoundary|exchange|fomke".} =
  ## c: exact AME/FOMKE epoch transition confirmation.
  var
    i: int = 0
  validateFomkeUpgradeShape(c)
  while i < fomkeUpgradeMagic.len:
    result.add(fomkeUpgradeMagic[i])
    i = i + 1
  result.add(fomkeUpgradeVersion)
  appendAmeU32(result, c.requestId)
  appendAmeU32(result, c.baseEpoch)
  appendAmeU32(result, c.targetEpoch)
  appendAmeU32(result, c.targetTier.tierId)
  result.add(c.targetTier.masks.kem)
  result.add(c.targetTier.masks.cipher)
  result.add(c.targetTier.masks.mac)
  result.add(c.targetTier.masks.hash)
  result.add(c.targetTier.masks.signature)
  result.add(c.targetTier.masks.kdf)
  result.add(c.exchangeMask)
  appendAmeU64(result, c.lane1Index)
  appendAmeU64(result, c.lane2Index)
  i = 0
  while i < ameMaxAlgorithmSlots:
    appendAmeU32(result, c.generations[i])
    i = i + 1
  result.add(uint8(c.confirmationTag.len))
  appendAmeBytes(result, c.confirmationTag)

proc decodeFomkeUpgradeCommit*(A: openArray[uint8]): FomkeUpgradeCommit {.
    role: parser,
    tag: "appApi|codecBoundary|exchange|fomke|parsing".} =
  ## A: complete bounded FKU1 commit bytes.
  var
    i: int = 0
    offset: int = 43
    tagLen: int = 0
  if A.len < fomkeUpgradeFixedLen or A[0 .. 2] != fomkeUpgradeMagic:
    raise newException(ValueError, "FOMKE upgrade identity mismatch")
  if A[3] != fomkeUpgradeVersion:
    raise newException(ValueError, "FOMKE upgrade version mismatch")
  result.requestId = readFomkeU32(A, 4)
  result.baseEpoch = readFomkeU32(A, 8)
  result.targetEpoch = readFomkeU32(A, 12)
  result.targetTier.tierId = readFomkeU32(A, 16)
  result.targetTier.masks.kem = A[20]
  result.targetTier.masks.cipher = A[21]
  result.targetTier.masks.mac = A[22]
  result.targetTier.masks.hash = A[23]
  result.targetTier.masks.signature = A[24]
  result.targetTier.masks.kdf = A[25]
  result.exchangeMask = A[26]
  result.lane1Index = readFomkeU64(A, 27)
  result.lane2Index = readFomkeU64(A, 35)
  while i < ameMaxAlgorithmSlots:
    result.generations[i] = readFomkeU32(A, offset)
    offset = offset + 4
    i = i + 1
  tagLen = int(A[offset])
  offset = offset + 1
  if result.requestId == 0'u32 or result.baseEpoch == 0'u32 or
      result.targetEpoch != result.baseEpoch + 1'u32 or
      tagLen != gb3BlockBytes or
      A.len != offset + tagLen:
    raise newException(ValueError, "FOMKE upgrade commit is invalid")
  result.confirmationTag = @A[offset ..< offset + tagLen]
  validateFomkeUpgradeShape(result)
