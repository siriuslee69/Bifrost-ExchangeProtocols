## ============================================================
## | CHUNKYAEAD File Ops <- threaded chunk file processing    |
## ============================================================

import std/os
when compileOption("threads"):
  import std/locks

import ../level0/types
import ../level0/memory_ops
import ../level1/nonce_ops
import ../level1/chunk_crypto_ops
import tyr/hashes/blake3
import tyr/ciphers/gimli_sponge
import bifrostPragmas

const
  chunkHeaderLen = 52
  chunkHashLen = 32
  maxTagLen = 1024'u16

when compileOption("threads"):
  type
    EncryptCtx = object
      ts: ptr seq[ChunkEncryptTask]
      l: ptr Lock
      n: ptr int

    DecryptCtx = object
      ts: ptr seq[ChunkDecryptTask]
      l: ptr Lock
      n: ptr int

proc constantTimeEqual(a, b: openArray[uint8]): bool {.role: helper,
    metaTags: {tagChunkyAead, tagCryptoBoundary, tagValidation}.} =
  if a.len != b.len:
    return false
  var diff: uint8 = 0
  for i in 0 ..< a.len:
    diff = diff or (a[i] xor b[i])
  diff == 0

proc storeU16Le(v: uint16, bs: var openArray[uint8], o: int) {.role: helper,
    metaTags: {tagChunkyAead, tagCodecBoundary}.} =
  bs[o] = uint8(v and 0xff)
  bs[o + 1] = uint8((v shr 8) and 0xff)

proc storeU64Le(v: uint64, bs: var openArray[uint8], o: int) {.role: helper,
    metaTags: {tagChunkyAead, tagCodecBoundary}.} =
  bs[o] = uint8(v and 0xff)
  bs[o + 1] = uint8((v shr 8) and 0xff)
  bs[o + 2] = uint8((v shr 16) and 0xff)
  bs[o + 3] = uint8((v shr 24) and 0xff)
  bs[o + 4] = uint8((v shr 32) and 0xff)
  bs[o + 5] = uint8((v shr 40) and 0xff)
  bs[o + 6] = uint8((v shr 48) and 0xff)
  bs[o + 7] = uint8((v shr 56) and 0xff)

proc loadU16Le(bs: openArray[uint8], o: int): uint16 {.role: parser,
    metaTags: {tagChunkyAead, tagCodecBoundary, tagParsing}.} =
  result = uint16(bs[o]) or (uint16(bs[o + 1]) shl 8)

proc loadU64Le(bs: openArray[uint8], o: int): uint64 {.role: parser,
    metaTags: {tagChunkyAead, tagCodecBoundary, tagParsing}.} =
  result =
    (uint64(bs[o]) or
    (uint64(bs[o + 1]) shl 8) or
    (uint64(bs[o + 2]) shl 16) or
    (uint64(bs[o + 3]) shl 24) or
    (uint64(bs[o + 4]) shl 32) or
    (uint64(bs[o + 5]) shl 40) or
    (uint64(bs[o + 6]) shl 48) or
    (uint64(bs[o + 7]) shl 56))

proc encodeHeader(h: ChunkHeader): array[chunkHeaderLen, uint8] {.
    role: dataWriter, metaTags: {tagChunkyAead, tagCodecBoundary}.} =
  var
    bs: array[chunkHeaderLen, uint8]
    o: int = 0
    i: int = 0
  i = 0
  while i < h.magic.len:
    bs[o] = h.magic[i]
    i = i + 1
    o = o + 1
  bs[o] = h.version
  o = o + 1
  bs[o] = uint8(ord(h.algo))
  o = o + 1
  storeU16Le(h.tagLen, bs, o)
  o = o + 2
  storeU64Le(h.chunkIndex, bs, o)
  o = o + 8
  storeU64Le(h.plainLen, bs, o)
  o = o + 8
  i = 0
  while i < h.nonce.len:
    bs[o] = h.nonce[i]
    i = i + 1
    o = o + 1
  result = bs

proc decodeHeader(bs: array[chunkHeaderLen, uint8]): ChunkHeader {.
    role: parser, metaTags: {tagChunkyAead, tagCodecBoundary, tagParsing}.} =
  var
    h: ChunkHeader
    o: int = 0
    i: int = 0
  i = 0
  while i < h.magic.len:
    h.magic[i] = bs[o]
    i = i + 1
    o = o + 1
  h.version = bs[o]
  o = o + 1
  h.algo = ChunkyAlgo(bs[o])
  o = o + 1
  h.tagLen = loadU16Le(bs, o)
  o = o + 2
  h.chunkIndex = loadU64Le(bs, o)
  o = o + 8
  h.plainLen = loadU64Le(bs, o)
  o = o + 8
  i = 0
  while i < h.nonce.len:
    h.nonce[i] = bs[o]
    i = i + 1
    o = o + 1
  result = h

proc writeChunkHeader(f: var File, h: ChunkHeader) {.role: dataWriter,
    metaTags: {tagChunkyAead, tagCodecBoundary, tagWrite}.} =
  var
    bs: array[chunkHeaderLen, uint8]
    wrote: int = 0
  bs = encodeHeader(h)
  wrote = f.writeBuffer(addr bs[0], bs.len)
  if wrote != bs.len:
    raise newException(IOError, "failed to write chunk header")

proc readChunkHeader(f: var File): ChunkHeader {.role: dataFetcher,
    metaTags: {tagChunkyAead, tagCodecBoundary, tagRead}.} =
  var
    bs: array[chunkHeaderLen, uint8]
    readBytes: int = 0
  readBytes = f.readBuffer(addr bs[0], bs.len)
  if readBytes != bs.len:
    raise newException(IOError, "failed to read chunk header")
  result = decodeHeader(bs)

proc ensureDir(p: string) {.role: helper, metaTags: {tagChunkyAead, tagWrite}.} =
  if p.len == 0:
    return
  if not dirExists(p):
    createDir(p)

proc calcChunkCount(sz, cs: int64): int {.role: parser,
    metaTags: {tagChunkyAead}.} =
  if sz <= 0:
    return 1
  result = int((sz + cs - 1) div cs)

proc buildChunkName(bs: string, i: int): string {.role: helper,
    metaTags: {tagChunkyAead}.} =
  result = bs & ".chunk" & $i & ".bin"

proc resolveOutputDir(i, o: string, opt: ChunkyOptions): string {.
    role: configurator, metaTags: {tagChunkyAead}.} =
  if o.len > 0:
    return o
  if opt.outputDir.len > 0:
    return opt.outputDir
  let parts = splitFile(i)
  result = joinPath(parts.dir, parts.name & ".chunks")

proc resolveTagLen(opt: ChunkyOptions, s: ChunkyCipherState): uint16 {.
    role: configurator, metaTags: {tagChunkyAead}.} =
  if opt.tagLen != 0'u16:
    return opt.tagLen
  if s.tagLen != 0'u16:
    return s.tagLen
  result = defaultTagLen

proc requireKey32(s: ChunkyCipherState, idx: int,
    name: string): array[32, uint8] {.role: parser,
    metaTags: {tagChunkyAead, tagCryptoBoundary, tagValidation}.} =
  if s.keys.len <= idx:
    raise newException(ValueError, "missing symmetric key for " & name)
  result = s.keys[idx]

proc zeroKey32(): array[32, uint8] {.role: helper,
    metaTags: {tagChunkyAead, tagCryptoBoundary}.} =
  result = default(array[32, uint8])

proc requireNonce24(s: ChunkyCipherState): array[24, uint8] {.role: parser,
    metaTags: {tagChunkyAead, tagCryptoBoundary, tagValidation}.} =
  result = s.nonce

proc buildHeader(i: uint64, l: int64, ns: array[24, uint8],
    a: ChunkyAlgo, t: uint16): ChunkHeader {.role: truthBuilder,
    metaTags: {tagChunkyAead, tagCodecBoundary}.} =
  var h: ChunkHeader
  h.magic = chunkyMagic
  h.version = chunkyVersion
  h.algo = a
  h.tagLen = t
  h.chunkIndex = i
  h.plainLen = uint64(l)
  h.nonce = ns
  result = h

when compileOption("threads"):
  proc fetchTaskIndex(l: var Lock, n: var int): int {.role: actor,
      metaTags: {tagChunkyAead}.} =
    var idx: int = 0
    acquire(l)
    idx = n
    n = n + 1
    release(l)
    result = idx

proc encryptChunkTask(t: var ChunkEncryptTask) {.role: orchestrator,
    metaTags: {tagChunkyAead, tagCryptoBoundary, tagWrite}.} =
  var
    fIn: File
    fOut: File
    okIn: bool = false
    okOut: bool = false
    ns: array[24, uint8]
    h: ChunkHeader
    st: ChunkCryptoState
    buf: seq[uint8] = @[]
    remaining: int64 = 0
    take: int = 0
    got: int = 0
    tag: seq[uint8] = @[]
  t.ok = false
  t.err = ""
  if t.chunkLen < 0:
    t.err = "invalid chunk length"
    return
  okIn = open(fIn, t.inputPath, fmRead)
  if not okIn:
    t.err = "failed to open input chunk source"
    return
  okOut = open(fOut, t.outputPath, fmWrite)
  if not okOut:
    close(fIn)
    t.err = "failed to open output chunk file"
    return
  try:
    setFilePos(fIn, t.chunkOffset)
    ns = deriveChunkNonce(t.baseNonce, t.chunkIndex)
    h = buildHeader(t.chunkIndex, t.chunkLen, ns, t.algo, t.tagLen)
    writeChunkHeader(fOut, h)
    initChunkCryptoState(st, t.algo, t.keyXs, t.keyAs, t.keyGs, ns, t.bufferBytes)
    buf.setLen(t.bufferBytes)
    remaining = t.chunkLen
    while remaining > 0:
      take = t.bufferBytes
      if remaining < int64(take):
        take = int(remaining)
      got = fIn.readBuffer(addr buf[0], take)
      if got != take:
        raise newException(IOError, "failed to read input chunk bytes")
      encryptChunkBuffer(st, buf.toOpenArray(0, take - 1))
      if fOut.writeBuffer(addr buf[0], take) != take:
        raise newException(IOError, "failed to write chunk ciphertext")
      remaining = remaining - int64(take)
    tag.setLen(int(t.tagLen))
    if tag.len > 0:
      finalizeChunkTag(st, tag)
      if fOut.writeBuffer(addr tag[0], tag.len) != tag.len:
        raise newException(IOError, "failed to write chunk tag")
    t.ok = true
  except CatchableError as e:
    t.err = e.msg
  finally:
    close(fIn)
    close(fOut)

proc decryptChunkTask(t: var ChunkDecryptTask) {.role: orchestrator,
    metaTags: {tagChunkyAead, tagCryptoBoundary, tagRead, tagWrite}.} =
  var
    fIn: File
    fOut: File
    okIn: bool = false
    okOut: bool = false
    h: ChunkHeader
    st: ChunkCryptoState
    buf: seq[uint8] = @[]
    remaining: int64 = 0
    take: int = 0
    got: int = 0
    expected: seq[uint8] = @[]
    actual: seq[uint8] = @[]
  t.ok = false
  t.err = ""
  okIn = open(fIn, t.inputPath, fmRead)
  if not okIn:
    t.err = "failed to open input chunk file"
    return
  okOut = open(fOut, t.outputPath, fmWrite)
  if not okOut:
    close(fIn)
    t.err = "failed to open output chunk temp file"
    return
  try:
    h = readChunkHeader(fIn)
    if h.magic != chunkyMagic:
      raise newException(ValueError, "invalid chunk magic")
    if h.version != chunkyVersion:
      raise newException(ValueError, "unsupported chunk version")
    if h.algo notin {caXChaCha20Gimli, caAesGimli, caXChaCha20AesGimli}:
      raise newException(ValueError, "unsupported chunk algorithm")
    if h.tagLen == 0'u16 or h.tagLen > maxTagLen:
      raise newException(ValueError, "invalid chunk tag length")
    if h.chunkIndex != t.chunkIndex:
      raise newException(ValueError, "chunk index mismatch")
    if h.nonce != deriveChunkNonce(t.baseNonce, t.chunkIndex):
      raise newException(ValueError, "chunk nonce mismatch")
    initChunkCryptoState(st, h.algo, t.keyXs, t.keyAs, t.keyGs, h.nonce, t.bufferBytes)
    buf.setLen(t.bufferBytes)
    remaining = int64(h.plainLen)
    while remaining > 0:
      take = t.bufferBytes
      if remaining < int64(take):
        take = int(remaining)
      got = fIn.readBuffer(addr buf[0], take)
      if got != take:
        raise newException(IOError, "failed to read chunk ciphertext")
      decryptChunkBuffer(st, buf.toOpenArray(0, take - 1))
      if fOut.writeBuffer(addr buf[0], take) != take:
        raise newException(IOError, "failed to write chunk plaintext")
      remaining = remaining - int64(take)
    expected.setLen(int(h.tagLen))
    if expected.len > 0:
      got = fIn.readBuffer(addr expected[0], expected.len)
      if got != expected.len:
        raise newException(IOError, "failed to read chunk tag")
      actual.setLen(expected.len)
      finalizeChunkTag(st, actual)
      if not constantTimeEqual(expected, actual):
        raise newException(ValueError, "chunk authentication tag mismatch")
    t.ok = true
  except CatchableError as e:
    t.err = e.msg
  finally:
    close(fIn)
    close(fOut)
    if not t.ok and fileExists(t.outputPath):
      removeFile(t.outputPath)

proc hashChunkTask(t: var ChunkHashTask) {.role: orchestrator,
    metaTags: {tagChunkyAead, tagCryptoBoundary, tagRead}.} =
  var
    fIn: File
    okIn: bool = false
    buf: seq[uint8] = @[]
    remaining: int64 = 0
    take: int = 0
    got: int = 0
    chunkBytes: seq[uint8] = @[]
    hasher: Blake3Hasher
  t.ok = false
  t.err = ""
  okIn = open(fIn, t.inputPath, fmRead)
  if not okIn:
    t.err = "failed to open hash input"
    return
  try:
    setFilePos(fIn, t.chunkOffset)
    buf.setLen(t.bufferBytes)
    remaining = t.chunkLen
    if t.algo == haBlake3Tree:
      hasher = initBlake3Hasher()
    else:
      chunkBytes.setLen(0)
    while remaining > 0:
      take = t.bufferBytes
      if remaining < int64(take):
        take = int(remaining)
      got = fIn.readBuffer(addr buf[0], take)
      if got != take:
        raise newException(IOError, "failed to read hash bytes")
      case t.algo
      of haBlake3Tree:
        updateBlake3(hasher, buf.toOpenArray(0, take - 1))
      of haGimliTree:
        chunkBytes.add(buf.toOpenArray(0, take - 1))
      remaining = remaining - int64(take)
    case t.algo
    of haBlake3Tree:
      t.hashs = finalBlake3(hasher, chunkHashLen)
    of haGimliTree:
      t.hashs = gimliXof(@[], @[], chunkBytes, chunkHashLen)
    t.ok = true
  except CatchableError as e:
    t.err = e.msg
  finally:
    close(fIn)

when compileOption("threads"):
  proc encryptWorker(ctx: ptr EncryptCtx) {.thread, role: orchestrator,
      metaTags: {tagChunkyAead, tagCryptoBoundary}.} =
    var
      idx: int = 0
    while true:
      idx = fetchTaskIndex(ctx.l[], ctx.n[])
      if idx >= ctx.ts[].len:
        break
      encryptChunkTask(ctx.ts[][idx])

  proc decryptWorker(ctx: ptr DecryptCtx) {.thread, role: orchestrator,
      metaTags: {tagChunkyAead, tagCryptoBoundary}.} =
    var
      idx: int = 0
    while true:
      idx = fetchTaskIndex(ctx.l[], ctx.n[])
      if idx >= ctx.ts[].len:
        break
      decryptChunkTask(ctx.ts[][idx])

proc runEncryptTasks(ts: var seq[ChunkEncryptTask], tc: int) {.
    role: orchestrator, metaTags: {tagChunkyAead, tagCryptoBoundary}.} =
  var
    i: int = 0
  if ts.len == 0:
    return
  when compileOption("threads"):
    when defined(gcOrc) or defined(gcArc):
      var
        l: Lock
        n: int = 0
        ctx: EncryptCtx
        ths: seq[Thread[ptr EncryptCtx]] = @[]
      initLock(l)
      ctx.ts = addr ts
      ctx.l = addr l
      ctx.n = addr n
      ths.setLen(tc)
      i = 0
      while i < ths.len:
        createThread(ths[i], encryptWorker, addr ctx)
        i = i + 1
      i = 0
      while i < ths.len:
        joinThread(ths[i])
        i = i + 1
      deinitLock(l)
    else:
      i = 0
      while i < ts.len:
        encryptChunkTask(ts[i])
        i = i + 1
  else:
    i = 0
    while i < ts.len:
      encryptChunkTask(ts[i])
      i = i + 1

proc runDecryptTasks(ts: var seq[ChunkDecryptTask], tc: int) {.
    role: orchestrator, metaTags: {tagChunkyAead, tagCryptoBoundary}.} =
  var
    i: int = 0
  if ts.len == 0:
    return
  when compileOption("threads"):
    when defined(gcOrc) or defined(gcArc):
      var
        l: Lock
        n: int = 0
        ctx: DecryptCtx
        ths: seq[Thread[ptr DecryptCtx]] = @[]
      initLock(l)
      ctx.ts = addr ts
      ctx.l = addr l
      ctx.n = addr n
      ths.setLen(tc)
      i = 0
      while i < ths.len:
        createThread(ths[i], decryptWorker, addr ctx)
        i = i + 1
      i = 0
      while i < ths.len:
        joinThread(ths[i])
        i = i + 1
      deinitLock(l)
    else:
      i = 0
      while i < ts.len:
        decryptChunkTask(ts[i])
        i = i + 1
  else:
    i = 0
    while i < ts.len:
      decryptChunkTask(ts[i])
      i = i + 1

proc runHashTasks(ts: var seq[ChunkHashTask], tc: int) {.role: orchestrator,
    metaTags: {tagChunkyAead}.} =
  var
    i: int = 0
  if ts.len == 0:
    return
  discard tc
  # Keep hash tasks serial for now: ORC/ARC thread handoff of seq payloads
  # was causing intermittent corruption in the regression suite.
  i = 0
  while i < ts.len:
    hashChunkTask(ts[i])
    i = i + 1

proc ensureTasksOk(ts: seq[ChunkEncryptTask]) {.role: parser,
    metaTags: {tagChunkyAead, tagValidation}.} =
  for t in ts:
    if not t.ok:
      raise newException(IOError, t.err)

proc ensureTasksOk(ts: seq[ChunkDecryptTask]) {.role: parser,
    metaTags: {tagChunkyAead, tagValidation}.} =
  for t in ts:
    if not t.ok:
      raise newException(IOError, t.err)

proc ensureTasksOk(ts: seq[ChunkHashTask]) {.role: parser,
    metaTags: {tagChunkyAead, tagValidation}.} =
  for t in ts:
    if not t.ok:
      raise newException(IOError, t.err)

proc mergeChunks(paths: seq[string], outPath: string, b: int) {.
    role: dataWriter, metaTags: {tagChunkyAead, tagWrite}.} =
  var
    fOut: File
    okOut: bool = false
    buf: seq[uint8] = @[]
    i: int = 0
    fIn: File
    okIn: bool = false
    got: int = 0
  okOut = open(fOut, outPath, fmWrite)
  if not okOut:
    raise newException(IOError, "failed to open merge output")
  try:
    buf.setLen(b)
    i = 0
    while i < paths.len:
      okIn = open(fIn, paths[i], fmRead)
      if not okIn:
        raise newException(IOError, "failed to open chunk for merge")
      try:
        while true:
          got = fIn.readBuffer(addr buf[0], buf.len)
          if got <= 0:
            break
          if fOut.writeBuffer(addr buf[0], got) != got:
            raise newException(IOError, "failed to write merged output")
      finally:
        close(fIn)
      i = i + 1
  finally:
    close(fOut)

proc buildTreeHash(hs: seq[seq[uint8]], a: HashAlgo): seq[uint8] {.
    role: truthBuilder, metaTags: {tagChunkyAead, tagCryptoBoundary}.} =
  var
    current: seq[seq[uint8]] = @[]
    nextLevel: seq[seq[uint8]] = @[]
    i: int = 0
    buf: seq[uint8] = @[]
  if hs.len == 0:
    return @[]
  if hs.len == 1:
    return hs[0]
  current = newSeq[seq[uint8]](hs.len)
  for j in 0 ..< hs.len:
    current[j] = hs[j]
  while current.len > 1:
    nextLevel = newSeqOfCap[seq[uint8]]((current.len + 1) div 2)
    i = 0
    while i + 1 < current.len:
      buf.setLen(current[i].len + current[i + 1].len)
      if current[i].len > 0:
        copyMem(addr buf[0], unsafeAddr current[i][0], current[i].len)
      if current[i + 1].len > 0:
        copyMem(addr buf[current[i].len], unsafeAddr current[i + 1][0],
          current[i + 1].len)
      case a
      of haBlake3Tree:
        nextLevel.add(blake3Hash(buf, chunkHashLen))
      of haGimliTree:
        nextLevel.add(gimliXof(@[], @[], buf, chunkHashLen))
      i = i + 2
    if i < current.len:
      nextLevel.add(current[i])
    current = nextLevel
  result = current[0]

proc encryptFileChunks*(i: string, o: string, s: ChunkyCipherState,
    opt: ChunkyOptions): ChunkyManifest {.role: orchestrator,
    metaTags: {tagAppApi, tagChunkyAead, tagCryptoBoundary, tagWrite}.} =
  ## i: input file path.
  ## o: output directory.
  ## s: encryption state (keys + base nonce).
  ## opt: chunky options.
  var
    outDir: string
    chunkBytes: int64
    bufferBytes: int
    sizeBytes: int64
    chunkCount: int
    tagLen: uint16
    keyXs: array[32, uint8]
    keyAs: array[32, uint8]
    keyGs: array[32, uint8]
    baseNonce: array[24, uint8]
    tasks: seq[ChunkEncryptTask] = @[]
    idx: int = 0
    off: int64 = 0
    take: int64 = 0
    tc: int = 0
    perThreadBytes: int64 = 0
    manifest: ChunkyManifest
    parts: tuple[dir, name, ext: string]
    baseName: string
  if not fileExists(i):
    raise newException(IOError, "input file not found")
  outDir = resolveOutputDir(i, o, opt)
  ensureDir(outDir)
  chunkBytes = resolveChunkBytes(opt)
  bufferBytes = resolveBufferBytes(opt)
  sizeBytes = getFileSize(i)
  chunkCount = calcChunkCount(sizeBytes, chunkBytes)
  tagLen = resolveTagLen(opt, s)
  if tagLen == 0'u16 or tagLen > maxTagLen:
    raise newException(ValueError, "invalid tag length")
  if opt.algo notin {caXChaCha20Gimli, caAesGimli, caXChaCha20AesGimli}:
    raise newException(ValueError, "unsupported chunk algorithm")
  if opt.algo != s.algo:
    raise newException(ValueError, "encryption state mismatch")
  case opt.algo
  of caXChaCha20Gimli:
    keyXs = requireKey32(s, 0, "xchacha20")
    keyAs = zeroKey32()
    keyGs = requireKey32(s, 1, "gimli")
  of caAesGimli:
    keyXs = zeroKey32()
    keyAs = requireKey32(s, 0, "aes-ctr")
    keyGs = requireKey32(s, 1, "gimli")
  of caXChaCha20AesGimli:
    keyXs = requireKey32(s, 0, "xchacha20")
    keyAs = requireKey32(s, 1, "aes-ctr")
    keyGs = requireKey32(s, 2, "gimli")
  baseNonce = requireNonce24(s)
  parts = splitFile(i)
  baseName = parts.name
  tasks.setLen(chunkCount)
  idx = 0
  while idx < chunkCount:
    off = int64(idx) * chunkBytes
    take = chunkBytes
    if off + take > sizeBytes:
      take = sizeBytes - off
      if take < 0:
        take = 0
    tasks[idx].inputPath = i
    tasks[idx].outputPath = joinPath(outDir, buildChunkName(baseName, idx))
    tasks[idx].chunkIndex = uint64(idx)
    tasks[idx].chunkOffset = off
    tasks[idx].chunkLen = take
    tasks[idx].baseNonce = baseNonce
    tasks[idx].keyXs = keyXs
    tasks[idx].keyAs = keyAs
    tasks[idx].keyGs = keyGs
    tasks[idx].tagLen = tagLen
    tasks[idx].bufferBytes = bufferBytes
    tasks[idx].algo = opt.algo
    idx = idx + 1
  perThreadBytes = chunkBytes
  tc = resolveThreadCount(opt, perThreadBytes, chunkCount)
  runEncryptTasks(tasks, tc)
  ensureTasksOk(tasks)
  manifest.version = chunkyVersion
  manifest.algo = opt.algo
  manifest.chunkBytes = chunkBytes
  manifest.tagLen = tagLen
  manifest.chunkCount = chunkCount
  manifest.originalSize = sizeBytes
  manifest.baseNonce = baseNonce
  manifest.fileName = parts.name & parts.ext
  manifest.chunkFiles.setLen(chunkCount)
  idx = 0
  while idx < chunkCount:
    manifest.chunkFiles[idx] = extractFilename(tasks[idx].outputPath)
    idx = idx + 1
  result = manifest

proc decryptFileChunks*(m: ChunkyManifest, iDir: string, oFile: string,
    s: ChunkyCipherState, opt: ChunkyOptions) {.role: orchestrator,
    metaTags: {tagAppApi, tagChunkyAead, tagCryptoBoundary, tagRead,
    tagWrite}.} =
  ## m: chunk manifest.
  ## iDir: directory containing chunk files.
  ## oFile: output file path.
  ## s: encryption state.
  ## opt: chunky options.
  var
    bufferBytes: int
    keyXs: array[32, uint8]
    keyAs: array[32, uint8]
    keyGs: array[32, uint8]
    baseNonce: array[24, uint8]
    tasks: seq[ChunkDecryptTask] = @[]
    idx: int = 0
    tc: int = 0
    perThreadBytes: int64 = 0
    tempDir: string
    tempFiles: seq[string] = @[]
  if m.chunkCount <= 0:
    raise newException(ValueError, "manifest has no chunks")
  if m.chunkFiles.len != m.chunkCount:
    raise newException(ValueError, "manifest chunk list mismatch")
  if opt.algo != m.algo:
    raise newException(ValueError, "chunk algorithm mismatch")
  if opt.algo != s.algo:
    raise newException(ValueError, "encryption state mismatch")
  bufferBytes = resolveBufferBytes(opt)
  case opt.algo
  of caXChaCha20Gimli:
    keyXs = requireKey32(s, 0, "xchacha20")
    keyAs = zeroKey32()
    keyGs = requireKey32(s, 1, "gimli")
  of caAesGimli:
    keyXs = zeroKey32()
    keyAs = requireKey32(s, 0, "aes-ctr")
    keyGs = requireKey32(s, 1, "gimli")
  of caXChaCha20AesGimli:
    keyXs = requireKey32(s, 0, "xchacha20")
    keyAs = requireKey32(s, 1, "aes-ctr")
    keyGs = requireKey32(s, 2, "gimli")
  baseNonce = m.baseNonce
  tempDir = oFile & ".parts"
  ensureDir(tempDir)
  tasks.setLen(m.chunkCount)
  tempFiles.setLen(m.chunkCount)
  idx = 0
  while idx < m.chunkCount:
    tasks[idx].inputPath = joinPath(iDir, m.chunkFiles[idx])
    tasks[idx].outputPath = joinPath(tempDir, "chunk_" & $idx & ".bin")
    tasks[idx].chunkIndex = uint64(idx)
    tasks[idx].baseNonce = baseNonce
    tasks[idx].keyXs = keyXs
    tasks[idx].keyAs = keyAs
    tasks[idx].keyGs = keyGs
    tasks[idx].bufferBytes = bufferBytes
    tempFiles[idx] = tasks[idx].outputPath
    idx = idx + 1
  perThreadBytes = int64(bufferBytes)
  tc = resolveThreadCount(opt, perThreadBytes, m.chunkCount)
  runDecryptTasks(tasks, tc)
  ensureTasksOk(tasks)
  ensureDir(parentDir(oFile))
  mergeChunks(tempFiles, oFile, bufferBytes)
  idx = 0
  while idx < tempFiles.len:
    if fileExists(tempFiles[idx]):
      removeFile(tempFiles[idx])
    idx = idx + 1
  if dirExists(tempDir):
    removeDir(tempDir)

proc hashFileChunks*(i: string, opt: ChunkyOptions,
    a: HashAlgo): seq[uint8] {.role: orchestrator,
    metaTags: {tagAppApi, tagChunkyAead, tagCryptoBoundary, tagRead}.} =
  ## i: input file path.
  ## opt: chunky options.
  ## a: hash algorithm.
  var
    chunkBytes: int64
    bufferBytes: int
    sizeBytes: int64
    chunkCount: int
    tasks: seq[ChunkHashTask] = @[]
    idx: int = 0
    off: int64 = 0
    take: int64 = 0
    tc: int = 0
    perThreadBytes: int64 = 0
    hashes: seq[seq[uint8]] = @[]
  if not fileExists(i):
    raise newException(IOError, "input file not found")
  chunkBytes = resolveChunkBytes(opt)
  bufferBytes = resolveBufferBytes(opt)
  sizeBytes = getFileSize(i)
  chunkCount = calcChunkCount(sizeBytes, chunkBytes)
  tasks.setLen(chunkCount)
  idx = 0
  while idx < chunkCount:
    off = int64(idx) * chunkBytes
    take = chunkBytes
    if off + take > sizeBytes:
      take = sizeBytes - off
      if take < 0:
        take = 0
    tasks[idx].inputPath = i
    tasks[idx].chunkOffset = off
    tasks[idx].chunkLen = take
    tasks[idx].bufferBytes = bufferBytes
    tasks[idx].algo = a
    idx = idx + 1
  perThreadBytes = int64(bufferBytes)
  tc = resolveThreadCount(opt, perThreadBytes, chunkCount)
  runHashTasks(tasks, tc)
  ensureTasksOk(tasks)
  hashes.setLen(chunkCount)
  idx = 0
  while idx < chunkCount:
    hashes[idx] = tasks[idx].hashs
    idx = idx + 1
  result = buildTreeHash(hashes, a)
