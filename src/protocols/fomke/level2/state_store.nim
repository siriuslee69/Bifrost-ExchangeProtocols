## -------------------------------------------------------------------------
## FOMKE State Store <- encrypted two-slot atomic ratchet checkpoints
## -------------------------------------------------------------------------

import std/os
when defined(posix):
  import std/posix

import ../../types
import ../../ame/level0/bytes
import ../types
import ../../ame/types as ame_types
import ../../ame/level1/tier_aead
import ../../ame/level2/protection
import ../level1/chain
import ./state_codec
import bifrostPragmas

const
  fomkeCheckpointMagic = [uint8('F'), uint8('S'), uint8('T'), uint8('1')]
  fomkeCheckpointVersion = 1'u16
  fomkeCheckpointHeaderLen = 18
  fomkeCheckpointMaxOverheadBytes = 512
    ## Room for the header, the longest nonce a slot selection can want, and
    ## the longest tag. Only an upper bound: the exact sizes come from the
    ## suite the caller names, and are checked against the file.
  fomkeCheckpointEnvelopeMaxBytes = int(fomkeMaxStateBytes) +
    fomkeCheckpointHeaderLen + fomkeCheckpointMaxOverheadBytes

proc checkpointSlotPath(basePath: string, slot: int): string {.role: helper,
    metaTags: {tagFomke, tagWrite}.} =
  ## basePath/slot: stable alternating checkpoint file name.
  result = basePath & "." & $slot

proc requireCheckpointInputs(basePath: string, storageKey,
    context: openArray[uint8]) {.role: parser,
    metaTags: {tagCryptoBoundary, tagFomke, tagValidation}.} =
  ## basePath/storageKey/context: persistence boundary inputs.
  if basePath.len == 0:
    raise newException(ValueError, "FOMKE checkpoint path is empty")
  if storageKey.len < fomkeCheckpointKeyMinBytes:
    raise newException(ValueError,
      "FOMKE checkpoint storage key must contain at least 32 bytes")
  if context.len == 0:
    raise newException(ValueError, "FOMKE checkpoint context is empty")

proc appendCheckpointField(A: var ByteSeq, B: openArray[uint8]) {.
    role: dataWriter, metaTags: {tagFomke, tagWrite}.} =
  ## A/B: append one bounded checkpoint field.
  if uint64(B.len) > uint64(fomkeMaxStateBytes):
    raise newException(ValueError, "FOMKE checkpoint field exceeds its limit")
  appendAmeU32(A, uint32(B.len))
  appendAmeBytes(A, B)

proc buildCheckpointKeyInfo(context: openArray[uint8]): ByteSeq {.
    role: truthBuilder, metaTags: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## context: caller-owned session identity bound to the storage key.
  appendAmeLabel(result, "FOMKE-CHECKPOINT-KEY-v1")
  appendCheckpointField(result, context)

proc buildCheckpointAad(counter: uint64,
    context: openArray[uint8]): ByteSeq {.role: truthBuilder,
    metaTags: {tagCryptoBoundary, tagFomke}.} =
  ## counter/context: authenticated monotonic version and session identity.
  appendAmeLabel(result, "FOMKE-CHECKPOINT-AAD-v1")
  appendAmeU64(result, counter)
  appendCheckpointField(result, context)

proc checkpointStringToBytes(s: string): ByteSeq {.role: helper,
    metaTags: {tagFomke, tagParsing}.} =
  ## s: exact binary file contents converted without text encoding.
  var
    i: int = 0
  result.setLen(s.len)
  while i < s.len:
    result[i] = uint8(ord(s[i]))
    i = i + 1

proc flushCheckpointFile(path: string, A: openArray[uint8]) {.
    role: dataWriter, metaTags: {tagCryptoBoundary, tagFomke, tagWrite}.} =
  ## path/A: write, flush, and close one temporary checkpoint file.
  var
    f: File
    written: int = 0
  if not open(f, path, fmWrite):
    raise newException(IOError, "cannot open FOMKE checkpoint temporary file")
  try:
    if A.len > 0:
      written = writeBuffer(f, unsafeAddr A[0], A.len)
      if written != A.len:
        raise newException(IOError, "short FOMKE checkpoint write")
    flushFile(f)
    when defined(posix):
      if posix.fsync(cint(getFileHandle(f))) != 0:
        raise newException(IOError, "failed to sync FOMKE checkpoint")
  finally:
    close(f)

proc replaceCheckpointSlot(path: string, A: openArray[uint8]) {.
    role: dataWriter, metaTags: {tagCryptoBoundary, tagFomke, tagWrite}.} =
  ## path/A: replace the older slot while the other valid slot remains intact.
  var
    parent: string = parentDir(path)
    temporary: string = path & ".next"
  if parent.len > 0 and parent != "." and not dirExists(parent):
    createDir(parent)
  if fileExists(temporary):
    removeFile(temporary)
  flushCheckpointFile(temporary, A)
  if fileExists(path):
    removeFile(path)
  moveFile(temporary, path)

proc readCheckpointU16(A: openArray[uint8], offset: int): uint16 {.
    role: parser, metaTags: {tagFomke, tagParsing}.} =
  ## A/offset: little-endian u16 inside the fixed envelope header.
  if offset < 0 or offset > A.len - 2:
    raise newException(ValueError, "FOMKE checkpoint u16 is truncated")
  result = uint16(A[offset]) or (uint16(A[offset + 1]) shl 8)

proc readCheckpointU32(A: openArray[uint8], offset: int): uint32 {.
    role: parser, metaTags: {tagFomke, tagParsing}.} =
  ## A/offset: little-endian u32 inside the fixed envelope header.
  if offset < 0 or offset > A.len - 4:
    raise newException(ValueError, "FOMKE checkpoint u32 is truncated")
  result = uint32(A[offset]) or (uint32(A[offset + 1]) shl 8) or
    (uint32(A[offset + 2]) shl 16) or (uint32(A[offset + 3]) shl 24)

proc readCheckpointU64(A: openArray[uint8], offset: int): uint64 {.
    role: parser, metaTags: {tagFomke, tagParsing}.} =
  ## A/offset: little-endian u64 inside the fixed envelope header.
  var
    i: int = 0
  if offset < 0 or offset > A.len - 8:
    raise newException(ValueError, "FOMKE checkpoint u64 is truncated")
  while i < 8:
    result = result or (uint64(A[offset + i]) shl (8 * i))
    i = i + 1

proc encodeCheckpointEnvelope(counter: uint64, nonce: openArray[uint8],
    sealed: AmeProtectedMessage): ByteSeq {.role: dataWriter,
    metaTags: {tagCodecBoundary, tagCryptoBoundary, tagFomke, tagWrite}.} =
  ## counter/nonce/sealed: complete encrypted checkpoint envelope.
  ##
  ##   "FST1" | ver u16 | counter u64 | ctLen u32 | nonce | tag | ciphertext
  ##
  ## Neither the nonce nor the tag carries its own length. Both are fixed by
  ## the slot selection the caller names when opening the file, so a length
  ## in the file would be a second opinion about something already settled --
  ## and one an attacker could edit.
  if counter == 0'u64 or nonce.len == 0 or sealed.authTag.len == 0 or
      uint64(sealed.payload.len) > uint64(fomkeMaxStateBytes):
    raise newException(ValueError, "FOMKE checkpoint envelope is invalid")
  appendAmeBytes(result, fomkeCheckpointMagic)
  appendAmeU16(result, fomkeCheckpointVersion)
  appendAmeU64(result, counter)
  appendAmeU32(result, uint32(sealed.payload.len))
  appendAmeBytes(result, nonce)
  appendAmeBytes(result, sealed.authTag)
  appendAmeBytes(result, sealed.payload)

proc decodeCheckpointEnvelope(A: openArray[uint8], nonceLen,
    tagLen: int): tuple[counter: uint64, nonce: ByteSeq,
    sealed: AmeProtectedMessage] {.role: parser,
    metaTags: {tagCodecBoundary, tagCryptoBoundary, tagFomke, tagParsing}.} =
  ## A/nonceLen/tagLen: the file, and the sizes the caller's suite demands.
  var
    cipherLen: int = 0
    offset: int = fomkeCheckpointHeaderLen
  if nonceLen <= 0 or tagLen <= 0:
    raise newException(ValueError, "FOMKE checkpoint suite is invalid")
  if A.len < fomkeCheckpointHeaderLen + nonceLen + tagLen or
      A.len > fomkeCheckpointEnvelopeMaxBytes or A[0 .. 3] !=
      fomkeCheckpointMagic:
    raise newException(ValueError, "FOMKE checkpoint identity is invalid")
  if readCheckpointU16(A, 4) != fomkeCheckpointVersion:
    raise newException(ValueError, "FOMKE checkpoint version mismatch")
  result.counter = readCheckpointU64(A, 6)
  cipherLen = checkedAmeWireLen(readCheckpointU32(A, 14),
    fomkeMaxStateBytes, "FOMKE checkpoint ciphertext")
  if result.counter == 0'u64 or A.len != offset + nonceLen +
      tagLen + cipherLen:
    raise newException(ValueError, "FOMKE checkpoint length mismatch")
  result.nonce = @A[offset ..< offset + nonceLen]
  offset = offset + nonceLen
  result.sealed.authTag = @A[offset ..< offset + tagLen]
  offset = offset + tagLen
  result.sealed.payload = @A[offset ..< offset + cipherLen]

proc saveFomkeCheckpoint*(basePath: string, S: FomkeState,
    storageKey: openArray[uint8], counter: uint64,
    context: openArray[uint8]): tuple[ok: bool, err: string] {.
    role: orchestrator, metaTags: {tagAppApi, tagCryptoBoundary, tagFomke,
    tagWrite}.} =
  ## basePath/S/storageKey/counter/context: atomically seal one newer slot.
  ##
  ## The file is sealed with the SAME slot selection the ratchet inside it
  ## runs on -- `S` carries its own layout, tier and tag length, so there is
  ## no second suite to configure and no way for the two to drift apart.
  ## Whoever loads this file has to name that selection back.
  var
    stateBytes: ByteSeq = @[]
    keyInfo: ByteSeq = @[]
    aad: ByteSeq = @[]
    nonce: ByteSeq = @[]
    envelope: ByteSeq = @[]
    sealed: AmeProtectedMessage
    slot: int = 0
  try:
    requireCheckpointInputs(basePath, storageKey, context)
    if counter == 0'u64:
      raise newException(ValueError, "FOMKE checkpoint counter must be positive")
    stateBytes = encodeFomkeState(S)
    keyInfo = buildCheckpointKeyInfo(context)
    aad = buildCheckpointAad(counter, context)
    nonce = randomAmeNonce(S.layout, S.tier)
    sealed = sealAmeStored(S.layout, S.tier, storageKey, keyInfo, nonce,
      stateBytes, aad, S.tagLen)
    envelope = encodeCheckpointEnvelope(counter, nonce, sealed)
    slot = int(counter and 1'u64)
    replaceCheckpointSlot(checkpointSlotPath(basePath, slot), envelope)
    result.ok = true
  except CatchableError as exc:
    result.err = exc.msg
  secureClearAmeBytes(stateBytes)
  secureClearAmeBytes(keyInfo)
  secureClearAmeBytes(aad)
  secureClearAmeBytes(nonce)
  secureClearAmeBytes(envelope)
  secureClearAmeBytes(sealed.authTag)
  secureClearAmeBytes(sealed.payload)

proc openCheckpointSlot(path: string, storageKey, context: openArray[uint8],
    L: AmeSuiteLayout, t: AmeMaskTier,
    tagLen: AmeAuthTagLen): FomkeCheckpoint {.role: orchestrator,
    metaTags: {tagCryptoBoundary, tagFomke, tagParsing}.} =
  ## path/storageKey/context: authenticate and decode one candidate slot.
  ## L/t/tagLen: the slot selection the file was sealed with.
  var
    fileBytes: ByteSeq = @[]
    decoded: tuple[counter: uint64, nonce: ByteSeq,
      sealed: AmeProtectedMessage]
    keyInfo: ByteSeq = @[]
    aad: ByteSeq = @[]
    opened: tuple[ok: bool, payload: ByteSeq]
  if not fileExists(path):
    result.err = "checkpoint slot is missing"
    return
  try:
    fileBytes = checkpointStringToBytes(readFile(path))
    decoded = decodeCheckpointEnvelope(fileBytes, ameTierNonceLen(L, t),
      int(ord(tagLen)))
    keyInfo = buildCheckpointKeyInfo(context)
    aad = buildCheckpointAad(decoded.counter, context)
    opened = openAmeStored(L, t, storageKey, keyInfo, decoded.nonce,
      decoded.sealed, aad, tagLen)
    if not opened.ok:
      raise newException(ValueError, "FOMKE checkpoint authentication failed")
    result.state = decodeFomkeState(opened.payload)
    result.counter = decoded.counter
    result.ok = true
  except CatchableError as exc:
    clearFomkeState(result.state)
    result.err = exc.msg
  secureClearAmeBytes(fileBytes)
  secureClearAmeBytes(decoded.nonce)
  secureClearAmeBytes(decoded.sealed.authTag)
  secureClearAmeBytes(decoded.sealed.payload)
  secureClearAmeBytes(keyInfo)
  secureClearAmeBytes(aad)
  secureClearAmeBytes(opened.payload)

proc loadFomkeCheckpoint*(basePath: string, storageKey: openArray[uint8],
    minimumCounter: uint64, context: openArray[uint8], L: AmeSuiteLayout,
    t: AmeMaskTier, tagLen: AmeAuthTagLen = aatl32): FomkeCheckpoint {.
    role: orchestrator, metaTags: {tagAppApi, tagCryptoBoundary, tagFomke,
    tagParsing}.} =
  ## minimumCounter: trusted external floor; lower valid files are rollbacks.
  ## L/t/tagLen: the slot selection the checkpoint was sealed with, which is
  ## the one the saved ratchet itself runs on. The caller knows it because it
  ## configured the session; naming it wrong reads as a failed
  ## authentication, not as a different-but-valid file.
  var
    first: FomkeCheckpoint
    second: FomkeCheckpoint
  try:
    requireCheckpointInputs(basePath, storageKey, context)
    first = openCheckpointSlot(checkpointSlotPath(basePath, 0), storageKey,
      context, L, t, tagLen)
    second = openCheckpointSlot(checkpointSlotPath(basePath, 1), storageKey,
      context, L, t, tagLen)
    if first.ok and (not second.ok or first.counter > second.counter):
      result = first
      clearFomkeState(second.state)
    elif second.ok:
      result = second
      clearFomkeState(first.state)
    else:
      result.err = "no authenticated FOMKE checkpoint is available"
      return
    if result.counter < minimumCounter:
      clearFomkeState(result.state)
      result.ok = false
      result.err = "FOMKE checkpoint rollback detected"
  except CatchableError as exc:
    clearFomkeState(first.state)
    clearFomkeState(second.state)
    clearFomkeState(result.state)
    result.err = exc.msg

proc sealFomkeMessageDurable*(S: var FomkeState, basePath: string,
    storageKey: openArray[uint8], checkpointCounter: var uint64,
    plaintext, context: openArray[uint8],
    aad: openArray[uint8] = []): FomkeDurableMessage {.role: orchestrator,
    metaTags: {tagAppApi, tagCryptoBoundary, tagFomke, tagWrite}.} =
  ## S/checkpointCounter: advance only after the new state reaches disk.
  var
    pending: FomkeState
    saved: tuple[ok: bool, err: string]
    nextCounter: uint64 = 0'u64
  if checkpointCounter == high(uint64):
    result.err = "FOMKE checkpoint counter is exhausted"
    return
  try:
    pending = cloneFomkeState(S)
    result.message = sealFomkeMessage(pending, plaintext, aad)
    nextCounter = checkpointCounter + 1'u64
    saved = saveFomkeCheckpoint(basePath, pending, storageKey, nextCounter,
      context)
    if not saved.ok:
      clearFomkeState(pending)
      result.err = saved.err
      return
    clearFomkeState(S)
    S = pending
    checkpointCounter = nextCounter
    result.checkpointCounter = nextCounter
    result.ok = true
  except CatchableError as exc:
    clearFomkeState(pending)
    result.err = exc.msg

proc openFomkeMessageDurable*(S: var FomkeState, basePath: string,
    storageKey: openArray[uint8], checkpointCounter: var uint64,
    message: FomkeMessage, context: openArray[uint8],
    aad: openArray[uint8] = []): FomkeDurableOpen {.role: orchestrator,
    metaTags: {tagAppApi, tagCryptoBoundary, tagFomke, tagWrite}.} =
  ## S/checkpointCounter: accept only after the authenticated state reaches disk.
  var
    pending: FomkeState
    opened: FomkeOpenResult
    saved: tuple[ok: bool, err: string]
    nextCounter: uint64 = 0'u64
  if checkpointCounter == high(uint64):
    result.err = "FOMKE checkpoint counter is exhausted"
    return
  try:
    pending = cloneFomkeState(S)
    opened = openFomkeMessage(pending, message, aad)
    if not opened.ok:
      clearFomkeState(pending)
      result.err = opened.err
      return
    nextCounter = checkpointCounter + 1'u64
    saved = saveFomkeCheckpoint(basePath, pending, storageKey, nextCounter,
      context)
    if not saved.ok:
      clearFomkeState(pending)
      secureClearAmeBytes(opened.payload)
      result.err = saved.err
      return
    clearFomkeState(S)
    S = pending
    checkpointCounter = nextCounter
    result.payload = opened.payload
    result.checkpointCounter = nextCounter
    result.ok = true
  except CatchableError as exc:
    clearFomkeState(pending)
    secureClearAmeBytes(opened.payload)
    result.err = exc.msg
