## -------------------------------------------------------------------------
## FOMKE State Store <- encrypted two-slot atomic ratchet checkpoints
## -------------------------------------------------------------------------

import std/os
when defined(posix):
  import std/posix

import tyr/helpers/random as tyr_random
import tyr/helpers/tiers as tyr_alg

import ../../types
import ../../ame/level0/bytes
import ../types
import ../../tmeaead
import ../level1/chain
import ./state_codec
import ../../../analysis_pragmas

const
  fomkeCheckpointMagic = [uint8('F'), uint8('S'), uint8('T'), uint8('1')]
  fomkeCheckpointVersion = 1'u16
  fomkeCheckpointHeaderLen = 18
  fomkeCheckpointEnvelopeMaxBytes = int(fomkeMaxStateBytes) +
    fomkeCheckpointHeaderLen + tmeAeadNonceBytes + tmeAeadTagBytes

proc checkpointSlotPath(basePath: string, slot: int): string {.role: helper,
    tag: {tagFomke, tagWrite}.} =
  ## basePath/slot: stable alternating checkpoint file name.
  result = basePath & "." & $slot

proc requireCheckpointInputs(basePath: string, storageKey,
    context: openArray[uint8]) {.role: parser,
    tag: {tagCryptoBoundary, tagFomke, tagValidation}.} =
  ## basePath/storageKey/context: persistence boundary inputs.
  if basePath.len == 0:
    raise newException(ValueError, "FOMKE checkpoint path is empty")
  if storageKey.len < fomkeCheckpointKeyMinBytes:
    raise newException(ValueError,
      "FOMKE checkpoint storage key must contain at least 32 bytes")
  if context.len == 0:
    raise newException(ValueError, "FOMKE checkpoint context is empty")

proc appendCheckpointField(A: var ByteSeq, B: openArray[uint8]) {.
    role: stateController, tag: {tagFomke, tagWrite}.} =
  ## A/B: append one bounded checkpoint field.
  if uint64(B.len) > uint64(fomkeMaxStateBytes):
    raise newException(ValueError, "FOMKE checkpoint field exceeds its limit")
  appendAmeU32(A, uint32(B.len))
  appendAmeBytes(A, B)

proc buildCheckpointKeyInfo(context: openArray[uint8]): ByteSeq {.
    role: truthBuilder, tag: {tagCryptoBoundary, tagFomke, tagKdf}.} =
  ## context: caller-owned session identity bound to the storage key.
  appendAmeLabel(result, "FOMKE-CHECKPOINT-KEY-v1")
  appendCheckpointField(result, context)

proc buildCheckpointAad(counter: uint64,
    context: openArray[uint8]): ByteSeq {.role: truthBuilder,
    tag: {tagCryptoBoundary, tagFomke}.} =
  ## counter/context: authenticated monotonic version and session identity.
  appendAmeLabel(result, "FOMKE-CHECKPOINT-AAD-v1")
  appendAmeU64(result, counter)
  appendCheckpointField(result, context)

proc checkpointStringToBytes(s: string): ByteSeq {.role: helper,
    tag: {tagFomke, tagParsing}.} =
  ## s: exact binary file contents converted without text encoding.
  var
    i: int = 0
  result.setLen(s.len)
  while i < s.len:
    result[i] = uint8(ord(s[i]))
    i = i + 1

proc flushCheckpointFile(path: string, A: openArray[uint8]) {.
    role: dataWriter, tag: {tagCryptoBoundary, tagFomke, tagWrite}.} =
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
    role: dataWriter, tag: {tagCryptoBoundary, tagFomke, tagWrite}.} =
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
    role: parser, tag: {tagFomke, tagParsing}.} =
  ## A/offset: little-endian u16 inside the fixed envelope header.
  if offset < 0 or offset > A.len - 2:
    raise newException(ValueError, "FOMKE checkpoint u16 is truncated")
  result = uint16(A[offset]) or (uint16(A[offset + 1]) shl 8)

proc readCheckpointU32(A: openArray[uint8], offset: int): uint32 {.
    role: parser, tag: {tagFomke, tagParsing}.} =
  ## A/offset: little-endian u32 inside the fixed envelope header.
  if offset < 0 or offset > A.len - 4:
    raise newException(ValueError, "FOMKE checkpoint u32 is truncated")
  result = uint32(A[offset]) or (uint32(A[offset + 1]) shl 8) or
    (uint32(A[offset + 2]) shl 16) or (uint32(A[offset + 3]) shl 24)

proc readCheckpointU64(A: openArray[uint8], offset: int): uint64 {.
    role: parser, tag: {tagFomke, tagParsing}.} =
  ## A/offset: little-endian u64 inside the fixed envelope header.
  var
    i: int = 0
  if offset < 0 or offset > A.len - 8:
    raise newException(ValueError, "FOMKE checkpoint u64 is truncated")
  while i < 8:
    result = result or (uint64(A[offset + i]) shl (8 * i))
    i = i + 1

proc encodeCheckpointEnvelope(counter: uint64, nonce: openArray[uint8],
    sealed: TmeAeadCiphertext): ByteSeq {.role: stateController,
    tag: {tagCodecBoundary, tagCryptoBoundary, tagFomke, tagWrite}.} =
  ## counter/nonce/sealed: complete encrypted checkpoint envelope.
  if counter == 0'u64 or nonce.len != tmeAeadNonceBytes or
      sealed.authTag.len != tmeAeadTagBytes or
      uint64(sealed.ciphertext.len) > uint64(fomkeMaxStateBytes):
    raise newException(ValueError, "FOMKE checkpoint envelope is invalid")
  appendAmeBytes(result, fomkeCheckpointMagic)
  appendAmeU16(result, fomkeCheckpointVersion)
  appendAmeU64(result, counter)
  appendAmeU32(result, uint32(sealed.ciphertext.len))
  appendAmeBytes(result, nonce)
  appendAmeBytes(result, sealed.authTag)
  appendAmeBytes(result, sealed.ciphertext)

proc decodeCheckpointEnvelope(A: openArray[uint8]): tuple[counter: uint64,
    nonce: ByteSeq, sealed: TmeAeadCiphertext] {.role: parser,
    tag: {tagCodecBoundary, tagCryptoBoundary, tagFomke, tagParsing}.} =
  ## A: strict encrypted checkpoint envelope.
  var
    cipherLen: int = 0
    offset: int = fomkeCheckpointHeaderLen
  if A.len < fomkeCheckpointHeaderLen + tmeAeadNonceBytes + tmeAeadTagBytes or
      A.len > fomkeCheckpointEnvelopeMaxBytes or A[0 .. 3] !=
      fomkeCheckpointMagic:
    raise newException(ValueError, "FOMKE checkpoint identity is invalid")
  if readCheckpointU16(A, 4) != fomkeCheckpointVersion:
    raise newException(ValueError, "FOMKE checkpoint version mismatch")
  result.counter = readCheckpointU64(A, 6)
  cipherLen = checkedAmeWireLen(readCheckpointU32(A, 14),
    fomkeMaxStateBytes, "FOMKE checkpoint ciphertext")
  if result.counter == 0'u64 or A.len != offset + tmeAeadNonceBytes +
      tmeAeadTagBytes + cipherLen:
    raise newException(ValueError, "FOMKE checkpoint length mismatch")
  result.nonce = @A[offset ..< offset + tmeAeadNonceBytes]
  offset = offset + tmeAeadNonceBytes
  result.sealed.authTag = @A[offset ..< offset + tmeAeadTagBytes]
  offset = offset + tmeAeadTagBytes
  result.sealed.ciphertext = @A[offset ..< offset + cipherLen]

proc saveFomkeCheckpoint*(basePath: string, S: FomkeState,
    storageKey: openArray[uint8], counter: uint64,
    context: openArray[uint8]): tuple[ok: bool, err: string] {.
    role: orchestrator, tag: {tagAppApi, tagCryptoBoundary, tagFomke,
    tagWrite}.} =
  ## basePath/S/storageKey/counter/context: atomically seal one newer slot.
  var
    stateBytes: ByteSeq = @[]
    keyInfo: ByteSeq = @[]
    aad: ByteSeq = @[]
    keyMaterial: ByteSeq = @[]
    nonce: ByteSeq = @[]
    envelope: ByteSeq = @[]
    sealed: TmeAeadCiphertext
    slot: int = 0
  try:
    requireCheckpointInputs(basePath, storageKey, context)
    if counter == 0'u64:
      raise newException(ValueError, "FOMKE checkpoint counter must be positive")
    stateBytes = encodeFomkeState(S)
    keyInfo = buildCheckpointKeyInfo(context)
    aad = buildCheckpointAad(counter, context)
    keyMaterial = deriveTmeAeadKeyMaterial(storageKey, keyInfo)
    nonce = tyr_random.cryptoRand(tyr_alg.raSystem, tmeAeadNonceBytes)
    sealed = sealTmeAead(keyMaterial, nonce, stateBytes, aad)
    envelope = encodeCheckpointEnvelope(counter, nonce, sealed)
    slot = int(counter and 1'u64)
    replaceCheckpointSlot(checkpointSlotPath(basePath, slot), envelope)
    result.ok = true
  except CatchableError as exc:
    result.err = exc.msg
  secureClearAmeBytes(stateBytes)
  secureClearAmeBytes(keyInfo)
  secureClearAmeBytes(aad)
  secureClearAmeBytes(keyMaterial)
  secureClearAmeBytes(nonce)
  secureClearAmeBytes(envelope)
  secureClearAmeBytes(sealed.authTag)
  secureClearAmeBytes(sealed.ciphertext)

proc openCheckpointSlot(path: string, storageKey,
    context: openArray[uint8]): FomkeCheckpoint {.role: orchestrator,
    tag: {tagCryptoBoundary, tagFomke, tagParsing}.} =
  ## path/storageKey/context: authenticate and decode one candidate slot.
  var
    fileBytes: ByteSeq = @[]
    decoded: tuple[counter: uint64, nonce: ByteSeq,
      sealed: TmeAeadCiphertext]
    keyInfo: ByteSeq = @[]
    aad: ByteSeq = @[]
    keyMaterial: ByteSeq = @[]
    opened: tuple[ok: bool, payload: ByteSeq]
  if not fileExists(path):
    result.err = "checkpoint slot is missing"
    return
  try:
    fileBytes = checkpointStringToBytes(readFile(path))
    decoded = decodeCheckpointEnvelope(fileBytes)
    keyInfo = buildCheckpointKeyInfo(context)
    aad = buildCheckpointAad(decoded.counter, context)
    keyMaterial = deriveTmeAeadKeyMaterial(storageKey, keyInfo)
    opened = openTmeAead(keyMaterial, decoded.nonce, decoded.sealed, aad)
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
  secureClearAmeBytes(decoded.sealed.ciphertext)
  secureClearAmeBytes(keyInfo)
  secureClearAmeBytes(aad)
  secureClearAmeBytes(keyMaterial)
  secureClearAmeBytes(opened.payload)

proc loadFomkeCheckpoint*(basePath: string, storageKey: openArray[uint8],
    minimumCounter: uint64, context: openArray[uint8]): FomkeCheckpoint {.
    role: orchestrator, tag: {tagAppApi, tagCryptoBoundary, tagFomke,
    tagParsing}.} =
  ## minimumCounter: trusted external floor; lower valid files are rollbacks.
  var
    first: FomkeCheckpoint
    second: FomkeCheckpoint
  try:
    requireCheckpointInputs(basePath, storageKey, context)
    first = openCheckpointSlot(checkpointSlotPath(basePath, 0), storageKey,
      context)
    second = openCheckpointSlot(checkpointSlotPath(basePath, 1), storageKey,
      context)
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
    tag: {tagAppApi, tagCryptoBoundary, tagFomke, tagWrite}.} =
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
    tag: {tagAppApi, tagCryptoBoundary, tagFomke, tagWrite}.} =
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
