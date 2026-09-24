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
import runePragmas

const
  chunkHeaderLen = 52
  chunkHashLen = 32
  maxTagLen = 1024'u16

when compileOption("threads") and (defined(gcOrc) or defined(gcArc)):
  const chunkyThreaded = true
    ## Chunk tasks run on worker threads only under ORC/ARC, where a task's
    ## strings and seqs can cross threads safely.
  type
    TaskCtx[T] = object
      ## Shared by every worker of one run: the tasks, the next index to
      ## take, the lock guarding it, and the routine that does one task.
      ts: ptr seq[T]
      l: ptr Lock
      n: ptr int
      work: proc (t: var T) {.nimcall, gcsafe.}
else:
  const chunkyThreaded = false


proc storeU16Le(v: uint16, bs: var openArray[uint8], o: int) {.role: helper,
    tag: "chunkyAead|codecBoundary".} =
  bs[o] = uint8(v and 0xff)
  bs[o + 1] = uint8((v shr 8) and 0xff)

proc storeU64Le(v: uint64, bs: var openArray[uint8], o: int) {.role: helper,
    tag: "chunkyAead|codecBoundary".} =
  bs[o] = uint8(v and 0xff)
  bs[o + 1] = uint8((v shr 8) and 0xff)
  bs[o + 2] = uint8((v shr 16) and 0xff)
  bs[o + 3] = uint8((v shr 24) and 0xff)
  bs[o + 4] = uint8((v shr 32) and 0xff)
  bs[o + 5] = uint8((v shr 40) and 0xff)
  bs[o + 6] = uint8((v shr 48) and 0xff)
  bs[o + 7] = uint8((v shr 56) and 0xff)

proc loadU16Le(bs: openArray[uint8], o: int): uint16 {.role: parser,
    tag: "chunkyAead|codecBoundary|parsing".} =
  result = uint16(bs[o]) or (uint16(bs[o + 1]) shl 8)

proc loadU64Le(bs: openArray[uint8], o: int): uint64 {.role: parser,
    tag: "chunkyAead|codecBoundary|parsing".} =
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
    role: dataWriter, tag: "chunkyAead|codecBoundary".} =
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
    role: parser, tag: "chunkyAead|codecBoundary|parsing".} =
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

proc requireKey32(s: ChunkyCipherState, idx: int,
    name: string): array[32, uint8] {.role: parser,
    tag: "chunkyAead|cryptoBoundary|validation".} =
  if s.keys.len <= idx:
    raise newException(ValueError, "missing symmetric key for " & name)
  result = s.keys[idx]

proc zeroKey32(): array[32, uint8] {.role: helper,
    tag: "chunkyAead|cryptoBoundary".} =
  result = default(array[32, uint8])

when chunkyThreaded:
  proc fetchTaskIndex(l: var Lock, n: var int): int {.role: actor,
      tag: "chunkyAead".} =
    acquire(l)
    result = n
    n = n + 1
    release(l)

## ╭⟢ moving bytes: every read and write is all-or-error

## ╭⟢ one chunk: encrypt, decrypt, hash

proc writeChunkHeader(f: var File, h: ChunkHeader) {.role: dataWriter,
    tag: "chunkyAead|codecBoundary|write".} =
  var
    bs: array[chunkHeaderLen, uint8]
    wrote: int = 0
  bs = encodeHeader(h)
  wrote = f.writeBuffer(addr bs[0], bs.len)
  if wrote != bs.len:
    raise newException(IOError, "failed to write chunk header")

proc buildHeader(i: uint64, l: int64, ns: array[24, uint8],
    a: ChunkyAlgo, t: uint16): ChunkHeader {.role: truthBuilder,
    tag: "chunkyAead|codecBoundary".} =
  var h: ChunkHeader
  h.magic = chunkyMagic
  h.version = chunkyVersion
  h.algo = a
  h.tagLen = t
  h.chunkIndex = i
  h.plainLen = uint64(l)
  h.nonce = ns
  result = h

proc takeLen(remaining: int64, bufferBytes: int): int {.inline, role: math,
    tag: "chunkyAead".} =
  ## remaining/bufferBytes: bytes still to move, and the buffer size ->
  ## how many to move this round.
  result = bufferBytes
  if remaining < int64(result):
    result = int(remaining)

proc readExactly(f: var File, buf: var seq[uint8], n: int, what: string) {.
    role: dataFetcher, tag: "chunkyAead|read".} =
  ## f/buf/n/what: read exactly `n` bytes into `buf`, or raise naming `what`.
  if n > 0 and f.readBuffer(addr buf[0], n) != n:
    raise newException(IOError, "failed to read " & what)

proc writeExactly(f: var File, buf: var seq[uint8], n: int, what: string) {.
    role: dataWriter, tag: "chunkyAead|write".} =
  ## f/buf/n/what: write the first `n` bytes of `buf`, or raise naming `what`.
  if n > 0 and f.writeBuffer(addr buf[0], n) != n:
    raise newException(IOError, "failed to write " & what)

proc encryptChunkBody(t: ChunkEncryptTask, st: var ChunkCryptoState,
    fIn, fOut: var File) {.role: encryptor, tag: "chunkyAead|cryptoBoundary".} =
  ## t/st/fIn/fOut: stream the chunk's plaintext through the ciphers, then
  ## write its tag.
  var
    buf: seq[uint8] = newSeq[uint8](t.bufferBytes)
    tag: seq[uint8] = newSeq[uint8](int(t.tagLen))
    remaining: int64 = t.chunkLen
    take: int = 0
  while remaining > 0:
    take = takeLen(remaining, t.bufferBytes)
    readExactly(fIn, buf, take, "input chunk bytes")
    encryptChunkBuffer(st, buf.toOpenArray(0, take - 1))
    writeExactly(fOut, buf, take, "chunk ciphertext")
    remaining = remaining - int64(take)
  if tag.len > 0:
    finalizeChunkTag(st, tag)
  writeExactly(fOut, tag, tag.len, "chunk tag")

proc encryptChunkTask(t: var ChunkEncryptTask) {.role: orchestrator,
    tag: "chunkyAead|cryptoBoundary|write".} =
  ## t: one chunk to encrypt; `ok`/`err` say how it went.
  var
    fIn: File = nil
    fOut: File = nil
    ns: array[24, uint8] = default(array[24, uint8])
    st: ChunkCryptoState = default(ChunkCryptoState)
  t.ok = false
  t.err = ""
  if t.chunkLen < 0:
    t.err = "invalid chunk length"
    return
  if not open(fIn, t.inputPath, fmRead):
    t.err = "failed to open input chunk source"
    return
  if not open(fOut, t.outputPath, fmWrite):
    close(fIn)
    t.err = "failed to open output chunk file"
    return
  try:
    setFilePos(fIn, t.chunkOffset)
    ns = deriveChunkNonce(t.baseNonce, t.chunkIndex)
    writeChunkHeader(fOut, buildHeader(t.chunkIndex, t.chunkLen, ns, t.algo,
      t.tagLen))
    initChunkCryptoState(st, t.algo, t.keyXs, t.keyAs, t.keyGs, ns,
      t.bufferBytes)
    encryptChunkBody(t, st, fIn, fOut)
    t.ok = true
  except CatchableError as e:
    t.err = e.msg
  finally:
    close(fIn)
    close(fOut)

proc readChunkHeader(f: var File): ChunkHeader {.role: dataFetcher,
    tag: "chunkyAead|codecBoundary|read".} =
  var
    bs: array[chunkHeaderLen, uint8]
    readBytes: int = 0
  readBytes = f.readBuffer(addr bs[0], bs.len)
  if readBytes != bs.len:
    raise newException(IOError, "failed to read chunk header")
  result = decodeHeader(bs)

proc requireChunkHeader(h: ChunkHeader, t: ChunkDecryptTask) {.role: parser,
    tag: "chunkyAead|validation".} =
  ## h/t: refuses a header that is not the one this task expects.
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

proc constantTimeEqual(a, b: openArray[uint8]): bool {.role: helper,
    tag: "chunkyAead|cryptoBoundary|validation".} =
  if a.len != b.len:
    return false
  var diff: uint8 = 0
  for i in 0 ..< a.len:
    diff = diff or (a[i] xor b[i])
  diff == 0

proc decryptChunkBody(t: ChunkDecryptTask, h: ChunkHeader,
    st: var ChunkCryptoState, fIn, fOut: var File) {.role: decryptor,
    tag: "chunkyAead|cryptoBoundary".} =
  ## t/h/st/fIn/fOut: stream the ciphertext back to plaintext, then check
  ## the tag. A mismatch raises; the caller removes the half-written output.
  var
    buf: seq[uint8] = newSeq[uint8](t.bufferBytes)
    expected: seq[uint8] = newSeq[uint8](int(h.tagLen))
    actual: seq[uint8] = newSeq[uint8](int(h.tagLen))
    remaining: int64 = int64(h.plainLen)
    take: int = 0
  while remaining > 0:
    take = takeLen(remaining, t.bufferBytes)
    readExactly(fIn, buf, take, "chunk ciphertext")
    decryptChunkBuffer(st, buf.toOpenArray(0, take - 1))
    writeExactly(fOut, buf, take, "chunk plaintext")
    remaining = remaining - int64(take)
  readExactly(fIn, expected, expected.len, "chunk tag")
  finalizeChunkTag(st, actual)
  if not constantTimeEqual(expected, actual):
    raise newException(ValueError, "chunk authentication tag mismatch")

proc decryptChunkTask(t: var ChunkDecryptTask) {.role: orchestrator,
    tag: "chunkyAead|cryptoBoundary|read|write".} =
  ## t: one chunk to decrypt; `ok`/`err` say how it went. A failed chunk
  ## leaves no output file behind.
  var
    fIn: File = nil
    fOut: File = nil
    h: ChunkHeader = default(ChunkHeader)
    st: ChunkCryptoState = default(ChunkCryptoState)
  t.ok = false
  t.err = ""
  if not open(fIn, t.inputPath, fmRead):
    t.err = "failed to open input chunk file"
    return
  if not open(fOut, t.outputPath, fmWrite):
    close(fIn)
    t.err = "failed to open output chunk temp file"
    return
  try:
    h = readChunkHeader(fIn)
    requireChunkHeader(h, t)
    initChunkCryptoState(st, h.algo, t.keyXs, t.keyAs, t.keyGs, h.nonce,
      t.bufferBytes)
    decryptChunkBody(t, h, st, fIn, fOut)
    t.ok = true
  except CatchableError as e:
    t.err = e.msg
  finally:
    close(fIn)
    close(fOut)
  if not t.ok and fileExists(t.outputPath):
    removeFile(t.outputPath)

proc hashChunkBody(t: ChunkHashTask, fIn: var File): seq[uint8] {.
    role: truthBuilder, tag: "chunkyAead|cryptoBoundary|read".} =
  ## t/fIn: the chunk's bytes, hashed with the task's algorithm.
  var
    buf: seq[uint8] = newSeq[uint8](t.bufferBytes)
    remaining: int64 = t.chunkLen
    take: int = 0
    chunkBytes: seq[uint8] = @[]
    hasher: Blake3Hasher = initBlake3Hasher()
  while remaining > 0:
    take = takeLen(remaining, t.bufferBytes)
    readExactly(fIn, buf, take, "hash bytes")
    if t.algo == haBlake3Tree:
      updateBlake3(hasher, buf.toOpenArray(0, take - 1))
    else:
      chunkBytes.add(buf.toOpenArray(0, take - 1))
    remaining = remaining - int64(take)
  if t.algo == haBlake3Tree:
    return finalBlake3(hasher, chunkHashLen)
  result = gimliXof(@[], @[], chunkBytes, chunkHashLen)

proc hashChunkTask(t: var ChunkHashTask) {.role: orchestrator,
    tag: "chunkyAead|cryptoBoundary|read".} =
  ## t: one chunk to hash; `hashs` holds the answer when `ok`.
  var
    fIn: File = nil
  t.ok = false
  t.err = ""
  if not open(fIn, t.inputPath, fmRead):
    t.err = "failed to open hash input"
    return
  try:
    setFilePos(fIn, t.chunkOffset)
    t.hashs = hashChunkBody(t, fIn)
    t.ok = true
  except CatchableError as e:
    t.err = e.msg
  finally:
    close(fIn)

## ╭⟢ running many chunks
##
##   threads (ORC/ARC)   tc workers each take the next index under a lock
##                       and run that one task, until none are left
##   otherwise           one after the other, on this thread

when chunkyThreaded:
  proc taskWorker[T](ctx: ptr TaskCtx[T]) {.thread, role: orchestrator,
      tag: "chunkyAead".} =
    ## ctx: take the next task until there is none left.
    var
      idx: int = fetchTaskIndex(ctx.l[], ctx.n[])
    while idx < ctx.ts[].len:
      ctx.work(ctx.ts[][idx])
      idx = fetchTaskIndex(ctx.l[], ctx.n[])

  proc runTasksThreaded[T](ts: var seq[T], tc: int,
      work: proc (t: var T) {.nimcall, gcsafe.}) {.role: orchestrator,
      tag: "chunkyAead".} =
    ## ts/tc/work: run every task on `tc` worker threads.
    var
      l: Lock = default(Lock)
      n: int = 0
      ctx: TaskCtx[T] = TaskCtx[T](ts: addr ts, n: addr n, work: work)
      ths: seq[Thread[ptr TaskCtx[T]]] = newSeq[Thread[ptr TaskCtx[T]]](tc)
    initLock(l)
    ctx.l = addr l
    for th in ths.mitems:
      createThread(th, taskWorker[T], addr ctx)
    for th in ths.mitems:
      joinThread(th)
    deinitLock(l)

## ╭⟢ merging and the hash tree

proc appendChunkFile(fOut: var File, path: string,
    buf: var seq[uint8]) {.inline, role: dataWriter,
    tag: "chunkyAead|write".} =
  ## fOut/path/buf: copy one chunk file onto the end of the merged output.
  ## The buffer is the caller's, so a merge of many chunks allocates once
  ## rather than once per chunk.
  var
    fIn: File = nil
    got: int = 1
  if not open(fIn, path, fmRead):
    raise newException(IOError, "failed to open chunk for merge")
  try:
    got = fIn.readBuffer(addr buf[0], buf.len)
    while got > 0:
      writeExactly(fOut, buf, got, "merged output")
      got = fIn.readBuffer(addr buf[0], buf.len)
  finally:
    close(fIn)

proc hashPair(a, b: seq[uint8], algo: HashAlgo): seq[uint8] {.
    role: truthBuilder, tag: "chunkyAead|cryptoBoundary".} =
  ## a/b/algo: the parent of two tree nodes: hash(a | b).
  if algo == haBlake3Tree:
    return blake3Hash(a & b, chunkHashLen)
  result = gimliXof(@[], @[], a & b, chunkHashLen)

proc nextTreeLevel(current: seq[seq[uint8]], a: HashAlgo): seq[seq[uint8]] {.
    role: truthBuilder, tag: "chunkyAead|cryptoBoundary".} =
  ## current/a: one level up the tree. Pairs are hashed together; an odd
  ## node out is carried up unchanged.
  ##
  ##   h0 h1 h2 h3 h4   ->   H(h0|h1) H(h2|h3) h4
  var
    i: int = 0
  result = newSeqOfCap[seq[uint8]]((current.len + 1) div 2)
  while i + 1 < current.len:
    result.add(hashPair(current[i], current[i + 1], a))
    i = i + 2
  if i < current.len:
    result.add(current[i])

## ╭⟢ whole files

proc requireNonce24(s: ChunkyCipherState): array[24, uint8] {.role: parser,
    tag: "chunkyAead|cryptoBoundary|validation".} =
  result = s.nonce

proc ensureDir(p: string) {.role: helper, tag: "chunkyAead|write".} =
  if p.len == 0:
    return
  if not dirExists(p):
    createDir(p)

proc chunkKeys(s: ChunkyCipherState, a: ChunkyAlgo): tuple[x, aes,
    g: array[32, uint8]] {.role: parser, tag: "chunkyAead|cryptoBoundary".} =
  ## s/a: the keys each stage of algorithm `a` uses, in the order the state
  ## holds them; a stage `a` does not run gets zeros.
  ##
  ##   algorithm            keys[0]    keys[1]   keys[2]
  ##   XChaCha20+Gimli      xchacha20  gimli
  ##   AES+Gimli            aes-ctr    gimli
  ##   XChaCha20+AES+Gimli  xchacha20  aes-ctr   gimli
  case a
  of caXChaCha20Gimli:
    result = (requireKey32(s, 0, "xchacha20"), zeroKey32(),
      requireKey32(s, 1, "gimli"))
  of caAesGimli:
    result = (zeroKey32(), requireKey32(s, 0, "aes-ctr"),
      requireKey32(s, 1, "gimli"))
  of caXChaCha20AesGimli:
    result = (requireKey32(s, 0, "xchacha20"), requireKey32(s, 1, "aes-ctr"),
      requireKey32(s, 2, "gimli"))

proc runTasksSerial[T](ts: var seq[T], work: proc (t: var T) {.nimcall,
    gcsafe.}) {.role: orchestrator, tag: "chunkyAead".} =
  ## ts/work: run every task, in order, on this thread.
  for t in ts.mitems:
    work(t)

proc runTasks[T](ts: var seq[T], tc: int, work: proc (t: var T) {.nimcall,
    gcsafe.}) {.role: orchestrator, tag: "chunkyAead".} =
  ## ts/tc/work: every task, on threads when this build has them.
  when chunkyThreaded:
    runTasksThreaded(ts, tc, work)
  else:
    runTasksSerial(ts, work)

proc buildChunkName(bs: string, i: int): string {.role: helper,
    tag: "chunkyAead".} =
  result = bs & ".chunk" & $i & ".bin"

proc resolveOutputDir(i, o: string, opt: ChunkyOptions): string {.
    role: configurator, tag: "chunkyAead".} =
  if o.len > 0:
    return o
  if opt.outputDir.len > 0:
    return opt.outputDir
  let parts = splitFile(i)
  result = joinPath(parts.dir, parts.name & ".chunks")

proc resolveTagLen(opt: ChunkyOptions, s: ChunkyCipherState): uint16 {.
    role: configurator, tag: "chunkyAead".} =
  if opt.tagLen != 0'u16:
    return opt.tagLen
  if s.tagLen != 0'u16:
    return s.tagLen
  result = defaultTagLen

proc chunkLenAt(idx: int, chunkBytes, sizeBytes: int64): int64 {.role: math,
    tag: "chunkyAead".} =
  ## idx/chunkBytes/sizeBytes: how many bytes chunk `idx` of the file holds;
  ## the last chunk may be short, and a chunk past the end holds none.
  result = min(chunkBytes, sizeBytes - int64(idx) * chunkBytes)
  if result < 0:
    result = 0

proc ensureTasksOk[T](ts: seq[T]) {.role: parser,
    tag: "chunkyAead|validation".} =
  ## ts: finished tasks of one kind (encrypt, decrypt, hash); the first
  ## failure is raised with its own message.
  for t in ts:
    if not t.ok:
      raise newException(IOError, t.err)

proc calcChunkCount(sz, cs: int64): int {.role: parser,
    tag: "chunkyAead".} =
  if sz <= 0:
    return 1
  result = int((sz + cs - 1) div cs)

proc encryptFileChunks*(i: string, o: string, s: ChunkyCipherState,
    opt: ChunkyOptions): ChunkyManifest {.role: orchestrator,
    tag: "appApi|chunkyAead|cryptoBoundary|write".} =
  ## i: input file path.
  ## o: output directory.
  ## s: encryption state (keys + base nonce).
  ## opt: chunky options.
  var
    outDir: string = ""
    chunkBytes: int64 = 0
    bufferBytes: int = 0
    sizeBytes: int64 = 0
    chunkCount: int = 0
    tagLen: uint16 = 0'u16
    keys: tuple[x, aes, g: array[32, uint8]] = default(tuple[x, aes,
      g: array[32, uint8]])
    baseNonce: array[24, uint8] = default(array[24, uint8])
    tasks: seq[ChunkEncryptTask] = @[]
    idx: int = 0
    parts: tuple[dir, name, ext: string] = ("", "", "")
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
  keys = chunkKeys(s, opt.algo)
  baseNonce = requireNonce24(s)
  parts = splitFile(i)
  tasks.setLen(chunkCount)
  while idx < chunkCount:
    tasks[idx] = ChunkEncryptTask(inputPath: i,
      outputPath: joinPath(outDir, buildChunkName(parts.name, idx)),
      chunkIndex: uint64(idx), chunkOffset: int64(idx) * chunkBytes,
      chunkLen: chunkLenAt(idx, chunkBytes, sizeBytes), baseNonce: baseNonce,
      keyXs: keys.x, keyAs: keys.aes, keyGs: keys.g, tagLen: tagLen,
      bufferBytes: bufferBytes, algo: opt.algo)
    idx = idx + 1
  runTasks(tasks, resolveThreadCount(opt, chunkBytes, chunkCount),
    encryptChunkTask)
  ensureTasksOk(tasks)
  result.version = chunkyVersion
  result.algo = opt.algo
  result.chunkBytes = chunkBytes
  result.tagLen = tagLen
  result.chunkCount = chunkCount
  result.originalSize = sizeBytes
  result.baseNonce = baseNonce
  result.fileName = parts.name & parts.ext
  for t in tasks:
    result.chunkFiles.add(extractFilename(t.outputPath))

proc removeIfPresent(p: string) {.role: actor, tag: "chunkyAead|write".} =
  ## p: a temporary file, gone afterwards.
  if fileExists(p):
    removeFile(p)

proc mergeChunks(paths: seq[string], outPath: string, b: int) {.
    role: dataWriter, tag: "chunkyAead|write".} =
  ## paths/outPath/b: the chunk files, in order, as one file.
  var
    fOut: File = nil
    buf: seq[uint8] = newSeq[uint8](b)
  if not open(fOut, outPath, fmWrite):
    raise newException(IOError, "failed to open merge output")
  try:
    for p in paths:
      appendChunkFile(fOut, p, buf)
  finally:
    close(fOut)

proc decryptFileChunks*(m: ChunkyManifest, iDir: string, oFile: string,
    s: ChunkyCipherState, opt: ChunkyOptions) {.role: orchestrator,
    tag: "appApi|chunkyAead|cryptoBoundary|read|write".} =
  ## m: chunk manifest.
  ## iDir: directory containing chunk files.
  ## oFile: output file path.
  ## s: encryption state.
  ## opt: chunky options.
  var
    bufferBytes: int = 0
    keys: tuple[x, aes, g: array[32, uint8]] = default(tuple[x, aes,
      g: array[32, uint8]])
    tasks: seq[ChunkDecryptTask] = @[]
    idx: int = 0
    tempDir: string = oFile & ".parts"
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
  keys = chunkKeys(s, opt.algo)
  ensureDir(tempDir)
  tasks.setLen(m.chunkCount)
  while idx < m.chunkCount:
    tasks[idx] = ChunkDecryptTask(inputPath: joinPath(iDir, m.chunkFiles[idx]),
      outputPath: joinPath(tempDir, "chunk_" & $idx & ".bin"),
      chunkIndex: uint64(idx), baseNonce: m.baseNonce, keyXs: keys.x,
      keyAs: keys.aes, keyGs: keys.g, bufferBytes: bufferBytes)
    tempFiles.add(tasks[idx].outputPath)
    idx = idx + 1
  runTasks(tasks, resolveThreadCount(opt, int64(bufferBytes), m.chunkCount),
    decryptChunkTask)
  ensureTasksOk(tasks)
  ensureDir(parentDir(oFile))
  mergeChunks(tempFiles, oFile, bufferBytes)
  for p in tempFiles:
    removeIfPresent(p)
  if dirExists(tempDir):
    removeDir(tempDir)

proc buildTreeHash(hs: seq[seq[uint8]], a: HashAlgo): seq[uint8] {.
    role: truthBuilder, tag: "chunkyAead|cryptoBoundary".} =
  ## hs/a: the chunk hashes folded level by level into one root.
  var
    current: seq[seq[uint8]] = hs
  if hs.len == 0:
    return @[]
  while current.len > 1:
    current = nextTreeLevel(current, a)
  result = current[0]

proc hashFileChunks*(i: string, opt: ChunkyOptions,
    a: HashAlgo): seq[uint8] {.role: orchestrator,
    tag: "appApi|chunkyAead|cryptoBoundary|read".} =
  ## i: input file path.
  ## opt: chunky options.
  ## a: hash algorithm.
  ##
  ## Hash tasks stay on one thread: ORC/ARC thread handoff of their seq
  ## payloads caused intermittent corruption in the regression suite.
  var
    chunkBytes: int64 = 0
    bufferBytes: int = 0
    sizeBytes: int64 = 0
    chunkCount: int = 0
    tasks: seq[ChunkHashTask] = @[]
    idx: int = 0
    hashes: seq[seq[uint8]] = @[]
  if not fileExists(i):
    raise newException(IOError, "input file not found")
  chunkBytes = resolveChunkBytes(opt)
  bufferBytes = resolveBufferBytes(opt)
  sizeBytes = getFileSize(i)
  chunkCount = calcChunkCount(sizeBytes, chunkBytes)
  tasks.setLen(chunkCount)
  while idx < chunkCount:
    tasks[idx] = ChunkHashTask(inputPath: i,
      chunkOffset: int64(idx) * chunkBytes,
      chunkLen: chunkLenAt(idx, chunkBytes, sizeBytes),
      bufferBytes: bufferBytes, algo: a)
    idx = idx + 1
  runTasksSerial(tasks, hashChunkTask)
  ensureTasksOk(tasks)
  for t in tasks:
    hashes.add(t.hashs)
  result = buildTreeHash(hashes, a)
