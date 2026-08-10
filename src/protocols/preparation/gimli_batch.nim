## -------------------------------------------------------------------------
## Gimli Batch <- independent streams through scalar, SSE, NEON, or AVX2
## -------------------------------------------------------------------------

import protocols/custom_crypto/gimli as tyr_gimli
import protocols/custom_crypto/gimli_sponge as tyr_gimli_sponge
import protocols/custom_crypto/symmetric/secure_memory as tyr_memory

import ../types
import ../../analysis_pragmas

const
  gimliBatchRateBytes {.used.} = 16
  gimliBatchMaterialBytes = 96
  gimliBatchKeyBytes = 32
  gimliBatchNonceBytes = 24
  gimliStreamDomain: array[16, uint8] = [
    uint8('T'), uint8('Y'), uint8('R'), uint8('-'),
    uint8('G'), uint8('I'), uint8('M'), uint8('L'),
    uint8('I'), uint8('-'), uint8('S'), uint8('T'),
    uint8('R'), uint8('M'), uint8('-'), uint8('2')
  ]

type
  GimliBatchMaterial = array[gimliBatchMaterialBytes, uint8]

proc appendBatchU64(M: var GimliBatchMaterial, offset: var int,
    v: uint64) {.inline, role: stateController,
    tag: {tagCryptoBoundary}.} =
  ## M/offset/v: fixed stream framing and one little-endian length.
  var
    i: int = 0
  while i < 8:
    M[offset] = uint8((v shr (i * 8)) and 0xff'u64)
    offset = offset + 1
    i = i + 1

proc appendBatchBytes(M: var GimliBatchMaterial, offset: var int,
    A: openArray[uint8]) {.inline, role: stateController,
    tag: {tagCryptoBoundary}.} =
  ## M/offset/A: fixed stream framing and bytes copied into it.
  var
    i: int = 0
  while i < A.len:
    M[offset] = A[i]
    offset = offset + 1
    i = i + 1

proc buildGimliStreamMaterial(K, N: openArray[uint8]): GimliBatchMaterial {.
    used, role: truthBuilder, tag: {tagCryptoBoundary}.} =
  ## K/N: one standard 32-byte Gimli key and 24-byte nonce.
  var
    offset: int = 0
  if K.len != gimliBatchKeyBytes or N.len != gimliBatchNonceBytes:
    raise newException(ValueError,
      "Gimli batch stream requires 32-byte keys and 24-byte nonces")
  appendBatchBytes(result, offset, gimliStreamDomain)
  appendBatchU64(result, offset, uint64(K.len))
  appendBatchBytes(result, offset, K)
  appendBatchU64(result, offset, uint64(N.len))
  appendBatchBytes(result, offset, N)
  appendBatchU64(result, offset, 0'u64)

proc loadBatchU32(M: GimliBatchMaterial, offset: int): uint32 {.inline,
    role: parser, tag: {tagCryptoBoundary}.} =
  ## M/offset: one little-endian rate word.
  result = uint32(M[offset]) or (uint32(M[offset + 1]) shl 8) or
    (uint32(M[offset + 2]) shl 16) or
    (uint32(M[offset + 3]) shl 24)

proc absorbBatchBlock(S: var tyr_gimli.Gimli_Block,
    M: GimliBatchMaterial, offset: int) {.used, inline, role: stateController,
    tag: {tagCryptoBoundary}.} =
  ## S/M/offset: one framed rate block absorbed before a permutation.
  var
    i: int = 0
  while i < 4:
    S[i] = S[i] xor loadBatchU32(M, offset + i * 4)
    i = i + 1

proc padBatchState(S: var tyr_gimli.Gimli_Block) {.used, inline,
    role: stateController, tag: {tagCryptoBoundary}.} =
  ## S: block-aligned Gimli stream input finalized with multi-rate padding.
  S[0] = S[0] xor 0x1f'u32
  S[3] = S[3] xor 0x80000000'u32

proc copyBatchRate(S: tyr_gimli.Gimli_Block, A: var ByteSeq,
    offset, count: int) {.used, inline, role: stateController,
    tag: {tagCryptoBoundary}.} =
  ## S/A/offset/count: current rate words copied as little-endian bytes.
  var
    i: int = 0
    word: uint32 = 0'u32
    shift: int = 0
  while i < count:
    word = S[i div 4]
    shift = (i and 3) * 8
    A[offset + i] = uint8((word shr shift) and 0xff'u32)
    i = i + 1

when defined(avx2):
  proc absorbBatch8(S: var array[8, tyr_gimli.Gimli_Block],
      M: array[8, GimliBatchMaterial], offset: int) {.inline,
      role: stateController, tag: {tagCryptoBoundary}.} =
    ## S/M/offset: eight independent rate blocks absorbed in lane order.
    var
      i: int = 0
    while i < S.len:
      absorbBatchBlock(S[i], M[i], offset)
      i = i + 1

  proc padBatch8(S: var array[8, tyr_gimli.Gimli_Block]) {.inline,
      role: stateController, tag: {tagCryptoBoundary}.} =
    ## S: eight block-aligned stream states finalized in lane order.
    var
      i: int = 0
    while i < S.len:
      padBatchState(S[i])
      i = i + 1

  proc copyBatchRate8(S: array[8, tyr_gimli.Gimli_Block],
      A: var array[8, ByteSeq], offset, count: int) {.inline,
      role: stateController, tag: {tagCryptoBoundary}.} =
    ## S/A/offset/count: eight current rate blocks copied to output lanes.
    var
      i: int = 0
    while i < S.len:
      copyBatchRate(S[i], A[i], offset, count)
      i = i + 1

  proc prepareGimliBatch8(K, N: array[8, ByteSeq],
      outputBytes: int): array[8, ByteSeq] {.role: truthBuilder,
      tag: {tagCryptoBoundary}.} =
    ## K/N/outputBytes: eight independent streams generated with AVX2 lanes.
    var
      S: array[8, tyr_gimli.Gimli_Block]
      M: array[8, GimliBatchMaterial]
      i: int = 0
      materialOffset: int = 0
      outputOffset: int = 0
      count: int = 0
    defer:
      tyr_memory.secureClearPod(S)
      tyr_memory.secureClearPod(M)
    while i < S.len:
      M[i] = buildGimliStreamMaterial(K[i], N[i])
      result[i].setLen(outputBytes)
      i = i + 1
    while materialOffset < gimliBatchMaterialBytes:
      absorbBatch8(S, M, materialOffset)
      tyr_gimli.gimliPermuteAvx8x(S)
      materialOffset = materialOffset + gimliBatchRateBytes
    padBatch8(S)
    tyr_gimli.gimliPermuteAvx8x(S)
    while outputOffset < outputBytes:
      count = min(gimliBatchRateBytes, outputBytes - outputOffset)
      copyBatchRate8(S, result, outputOffset, count)
      outputOffset = outputOffset + count
      if outputOffset < outputBytes:
        tyr_gimli.gimliPermuteAvx8x(S)

when defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
  proc absorbBatch4(S: var array[4, tyr_gimli.Gimli_Block],
      M: array[4, GimliBatchMaterial], offset: int) {.inline,
      role: stateController, tag: {tagCryptoBoundary}.} =
    ## S/M/offset: four independent rate blocks absorbed in lane order.
    var
      i: int = 0
    while i < S.len:
      absorbBatchBlock(S[i], M[i], offset)
      i = i + 1

  proc padBatch4(S: var array[4, tyr_gimli.Gimli_Block]) {.inline,
      role: stateController, tag: {tagCryptoBoundary}.} =
    ## S: four block-aligned stream states finalized in lane order.
    var
      i: int = 0
    while i < S.len:
      padBatchState(S[i])
      i = i + 1

  proc copyBatchRate4(S: array[4, tyr_gimli.Gimli_Block],
      A: var array[4, ByteSeq], offset, count: int) {.inline,
      role: stateController, tag: {tagCryptoBoundary}.} =
    ## S/A/offset/count: four current rate blocks copied to output lanes.
    var
      i: int = 0
    while i < S.len:
      copyBatchRate(S[i], A[i], offset, count)
      i = i + 1

  proc permuteBatch4(S: var array[4, tyr_gimli.Gimli_Block]) {.inline,
      role: actor, tag: {tagCryptoBoundary}.} =
    ## S: four states permuted by the native 128-bit implementation.
    when defined(neon) or defined(arm64) or defined(aarch64):
      tyr_gimli.gimliPermuteNeon4x(S)
    else:
      tyr_gimli.gimliPermuteSse4x(S)

  proc prepareGimliBatch4(K, N: array[4, ByteSeq],
      outputBytes: int): array[4, ByteSeq] {.role: truthBuilder,
      tag: {tagCryptoBoundary}.} =
    ## K/N/outputBytes: four independent streams generated with SIMD lanes.
    var
      S: array[4, tyr_gimli.Gimli_Block]
      M: array[4, GimliBatchMaterial]
      i: int = 0
      materialOffset: int = 0
      outputOffset: int = 0
      count: int = 0
    defer:
      tyr_memory.secureClearPod(S)
      tyr_memory.secureClearPod(M)
    while i < S.len:
      M[i] = buildGimliStreamMaterial(K[i], N[i])
      result[i].setLen(outputBytes)
      i = i + 1
    while materialOffset < gimliBatchMaterialBytes:
      absorbBatch4(S, M, materialOffset)
      permuteBatch4(S)
      materialOffset = materialOffset + gimliBatchRateBytes
    padBatch4(S)
    permuteBatch4(S)
    while outputOffset < outputBytes:
      count = min(gimliBatchRateBytes, outputBytes - outputOffset)
      copyBatchRate4(S, result, outputOffset, count)
      outputOffset = outputOffset + count
      if outputOffset < outputBytes:
        permuteBatch4(S)

proc gimliPreparedBatchWidth*(): int {.role: configurator,
    tag: {tagAppApi, tagCryptoBoundary}.} =
  ## Return the compiled future-message lane width; scalar tails remain exact.
  when defined(avx2):
    result = 8
  elif defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
    result = 4
  else:
    result = 1

proc prepareGimliStreams*(K, N: openArray[ByteSeq],
    outputBytes: int): seq[ByteSeq] {.role: truthBuilder,
    tag: {tagAppApi, tagCryptoBoundary}.} =
  ## K/N/outputBytes: equal key/nonce lists and bounded bytes per future message.
  var
    i: int = 0
    zeros: ByteSeq = @[]
    scalar: ByteSeq = @[]
  when defined(avx2):
    var
      j8: int = 0
      keys8: array[8, ByteSeq]
      nonces8: array[8, ByteSeq]
      streams8: array[8, ByteSeq]
  when defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
    var
      j4: int = 0
      keys4: array[4, ByteSeq]
      nonces4: array[4, ByteSeq]
      streams4: array[4, ByteSeq]
  if K.len != N.len:
    raise newException(ValueError, "Gimli batch key and nonce counts differ")
  if outputBytes < 0:
    raise newException(ValueError, "Gimli batch output length must not be negative")
  result.setLen(K.len)
  when defined(avx2):
    while i <= K.len - keys8.len:
      j8 = 0
      while j8 < keys8.len:
        keys8[j8] = K[i + j8]
        nonces8[j8] = N[i + j8]
        j8 = j8 + 1
      streams8 = prepareGimliBatch8(keys8, nonces8, outputBytes)
      j8 = 0
      while j8 < streams8.len:
        result[i + j8] = move(streams8[j8])
        j8 = j8 + 1
      i = i + keys8.len
  when defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
    while i <= K.len - keys4.len:
      j4 = 0
      while j4 < keys4.len:
        keys4[j4] = K[i + j4]
        nonces4[j4] = N[i + j4]
        j4 = j4 + 1
      streams4 = prepareGimliBatch4(keys4, nonces4, outputBytes)
      j4 = 0
      while j4 < streams4.len:
        result[i + j4] = move(streams4[j4])
        j4 = j4 + 1
      i = i + keys4.len
  zeros.setLen(outputBytes)
  while i < K.len:
    scalar = tyr_gimli_sponge.gimliStreamXor(K[i], N[i], zeros)
    result[i] = move(scalar)
    i = i + 1
  tyr_memory.secureClearBytes(zeros)
