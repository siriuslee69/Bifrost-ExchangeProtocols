## -------------------------------------------------------------------------
## FOMKE Wire <- bounded message and KEM-upgrade commit codecs
## -------------------------------------------------------------------------
##
## The message envelope, byte by byte:
##
##   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+
##   | F | O | M | 1 |   epoch   |        index              |
##   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+
##     0   1   2   3   4..7        8..15
##
##   +----+----+---+---+---+---+
##   |lane|tlen|  cipherLen    |  then: tag (tlen bytes), then ciphertext
##   +----+----+---+---+---+---+
##     16   17   18..21           22..
##
## Nothing here repeats what the receiver can work out for itself. The nonce
## is derived from the ratchet on both sides, so it is absent. The tag length
## is one byte and must match what the session agreed -- it is written down
## so a decoder can walk the frame without holding session state, never so a
## sender can choose it.

import ../../types
import ../../ame/types
import ../../ame/level0/bytes
import ../../ame/level1/exchange_paths
import ../types
import ../../../analysis_pragmas

const
  fomkeUpgradeMagic = [uint8('F'), uint8('K'), uint8('U')]
  fomkeUpgradeVersion = 1'u8
  fomkeUpgradeFixedLen = 108

proc validateFomkeUpgradeShape(c: FomkeUpgradeCommit) {.role: parser,
    tag: {tagExchange, tagFomke, tagValidation}.} =
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

proc readFomkeU16(A: openArray[uint8], offset: int): uint16 {.role: parser,
    tag: {tagFomke, tagParsing}.} =
  ## A/offset: source and little-endian u16 position.
  if offset < 0 or offset > A.len - 2:
    raise newException(ValueError, "FOMKE u16 is truncated")
  result = uint16(A[offset]) or (uint16(A[offset + 1]) shl 8)

proc readFomkeU32(A: openArray[uint8], offset: int): uint32 {.role: parser,
    tag: {tagFomke, tagParsing}.} =
  ## A/offset: source and little-endian u32 position.
  if offset < 0 or offset > A.len - 4:
    raise newException(ValueError, "FOMKE u32 is truncated")
  result = uint32(A[offset]) or (uint32(A[offset + 1]) shl 8) or
    (uint32(A[offset + 2]) shl 16) or (uint32(A[offset + 3]) shl 24)

proc readFomkeU64(A: openArray[uint8], offset: int): uint64 {.role: parser,
    tag: {tagFomke, tagParsing}.} =
  ## A/offset: source and little-endian u64 position.
  var
    i: int = 0
  if offset < 0 or offset > A.len - 8:
    raise newException(ValueError, "FOMKE u64 is truncated")
  while i < 8:
    result = result or (uint64(A[offset + i]) shl (8 * i))
    i = i + 1

proc fomkeLaneFromByte(v: uint8): FomkeLane {.role: parser,
    tag: {tagFomke, tagParsing}.} =
  ## v: stable lane identifier.
  if v == uint8(ord(flLane1)):
    return flLane1
  if v == uint8(ord(flLane2)):
    return flLane2
  raise newException(ValueError, "FOMKE sender lane is invalid")

proc fomkeWireLen*(plaintextLen: int, tagLen: AmeAuthTagLen): int {.
    role: helper, tag: {tagAppApi, tagFomke, tagPacket}.} =
  ## plaintextLen/tagLen: envelope size for a payload of this length. The
  ## ciphers are all keystream XOR, so the ciphertext is exactly as long as
  ## the plaintext -- the only growth is the header and the tag.
  if plaintextLen < 0 or uint64(plaintextLen) > uint64(fomkeMaxCiphertextBytes):
    raise newException(ValueError, "FOMKE ciphertext length exceeds its limit")
  result = fomkeHeaderLen + int(ord(tagLen)) + plaintextLen

proc encodeFomkeMessage*(m: FomkeMessage): ByteSeq {.role: stateController,
    tag: {tagAppApi, tagCodecBoundary, tagFomke, tagPacket}.} =
  ## m: complete forward-only message envelope.
  var
    i: int = 0
  if m.epoch == 0'u32 or m.authTag.len != int(ord(m.tagLen)) or
      uint64(m.ciphertext.len) > uint64(fomkeMaxCiphertextBytes):
    raise newException(ValueError, "FOMKE message is invalid")
  while i < fomkeMagic.len:
    result.add(fomkeMagic[i])
    i = i + 1
  result.add(fomkeFormatVersion)
  appendAmeU32(result, m.epoch)
  appendAmeU64(result, m.index)
  result.add(uint8(ord(m.senderLane)))
  result.add(uint8(ord(m.tagLen)))
  appendAmeU32(result, uint32(m.ciphertext.len))
  appendAmeBytes(result, m.authTag)
  appendAmeBytes(result, m.ciphertext)

proc decodeFomkeMessage*(A: openArray[uint8]): FomkeMessage {.role: parser,
    tag: {tagAppApi, tagCodecBoundary, tagFomke, tagPacket, tagParsing}.} =
  ## A: complete bounded FOM1 wire bytes.
  var
    tagLen: int = 0
    cipherLen: int = 0
    offset: int = fomkeHeaderLen
  if A.len < fomkeHeaderLen or A[0 .. 2] != fomkeMagic:
    raise newException(ValueError, "FOMKE message identity mismatch")
  if A[3] != fomkeFormatVersion:
    raise newException(ValueError, "FOMKE message version mismatch")
  result.epoch = readFomkeU32(A, 4)
  result.index = readFomkeU64(A, 8)
  result.senderLane = fomkeLaneFromByte(A[16])
  result.tagLen = ameAuthTagLenFromId(A[17])
  tagLen = int(ord(result.tagLen))
  cipherLen = checkedAmeWireLen(readFomkeU32(A, 18),
    fomkeMaxCiphertextBytes, "FOMKE ciphertext")
  if result.epoch == 0'u32 or A.len != offset + tagLen + cipherLen:
    raise newException(ValueError, "FOMKE message length mismatch")
  result.authTag = @A[offset ..< offset + tagLen]
  offset = offset + tagLen
  result.ciphertext = @A[offset ..< offset + cipherLen]

proc encodeFomkeUpgradeCommit*(c: FomkeUpgradeCommit): ByteSeq {.
    role: stateController,
    tag: {tagAppApi, tagCodecBoundary, tagExchange, tagFomke}.} =
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
    tag: {tagAppApi, tagCodecBoundary, tagExchange, tagFomke, tagParsing}.} =
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
