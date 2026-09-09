## -----------------------------------------------------------------
## Bifrost Benchmarks <- committed protocol microbenchmark harness
## -----------------------------------------------------------------

import std/[json, monotimes, os, strutils, times]

import bifrost_exchange_protocols
import runePragmas

type
  BenchConfig = object
    iterations: int
    warmup: int
    payloadBytes: int
    jsonOut: string
    only: seq[string]

  BenchResult = object
    name: string
    iterations: int
    payloadBytes: int
    wireBytes: int
    totalNs: int64
    sampleWireHex: string
    sink: uint64

var
  benchSink: uint64 = 0'u64

proc printHelp() =
  echo "Bifrost protocol benchmark harness"
  echo ""
  echo "Flags:"
  echo "  --iterations=N       Timed iterations per benchmark (default 2000)"
  echo "  --warmup=N           Warmup iterations per benchmark (default 128)"
  echo "  --payload-bytes=N    Payload bytes per benchmark operation (default 1024)"
  echo "  --only=a,b,c         Run only the named benchmarks"
  echo "  --json-out=PATH      Write machine-readable JSON results"
  echo "  --help               Show this help"
  echo ""
  echo "Benchmarks:"
  echo "  ame_protect, ame_open, dac_encode, dac_decode,"
  echo "  bfx2_encode, bfx2_decode, ame_dac_seal, ame_dac_open,"
  echo "  fomke_seal_1slot, fomke_cached_seal_1slot,"
  echo "  fomke_seal_2slot, fomke_cached_seal_2slot,"
  echo "  fomke_prepare8_1slot, fomke_prepare8_2slot,"
  echo "  gimli_stream_prepare8, xchacha_stream_prepare8"

proc parsePositiveInt(flag, raw: string): int =
  try:
    result = parseInt(raw)
  except ValueError:
    raise newException(ValueError, flag & " expects an integer")
  if result < 1:
    raise newException(ValueError, flag & " must be >= 1")

proc parseNonNegativeInt(flag, raw: string): int =
  try:
    result = parseInt(raw)
  except ValueError:
    raise newException(ValueError, flag & " expects an integer")
  if result < 0:
    raise newException(ValueError, flag & " must be >= 0")

proc normalizeBenchName(name: string): string =
  result = name.strip().toLowerAscii()

proc parseOnlyList(raw: string): seq[string] =
  for part in raw.split(','):
    let name = normalizeBenchName(part)
    if name.len > 0:
      result.add(name)

proc parseArgs(): BenchConfig =
  result.iterations = 2000
  result.warmup = 128
  result.payloadBytes = 1024
  for arg in commandLineParams():
    if arg == "--":
      continue
    elif arg == "--help" or arg == "-h":
      printHelp()
      quit(0)
    elif arg.startsWith("--iterations="):
      result.iterations = parsePositiveInt("--iterations",
        arg["--iterations=".len .. ^1])
    elif arg.startsWith("--warmup="):
      result.warmup = parseNonNegativeInt("--warmup",
        arg["--warmup=".len .. ^1])
    elif arg.startsWith("--payload-bytes="):
      result.payloadBytes = parsePositiveInt("--payload-bytes",
        arg["--payload-bytes=".len .. ^1])
    elif arg.startsWith("--json-out="):
      result.jsonOut = arg["--json-out=".len .. ^1].strip()
    elif arg.startsWith("--only="):
      result.only = parseOnlyList(arg["--only=".len .. ^1])
    else:
      raise newException(ValueError, "unsupported benchmark flag: " & arg)

proc shouldRun(cfg: BenchConfig, name: string): bool =
  let normalized = normalizeBenchName(name)
  if cfg.only.len == 0:
    return true
  for candidate in cfg.only:
    if candidate == normalized:
      return true
  result = false

proc buildPayload(n: int): ByteSeq =
  result = newSeq[uint8](n)
  for i in 0 ..< n:
    result[i] = uint8((i * 37 + 11) and 0xff)

proc mixSinkBytes(A: openArray[uint8]) =
  benchSink = benchSink xor uint64(A.len)
  if A.len > 0:
    benchSink = (benchSink shl 7) xor uint64(A[0])
    benchSink = benchSink xor (uint64(A[^1]) shl 17)

proc mixSinkUint(v: SomeInteger) =
  benchSink = (benchSink shl 9) xor uint64(v)

proc clearBenchBytes(A: var ByteSeq) =
  var
    i: int = 0
  while i < A.len:
    A[i] = 0'u8
    i = i + 1
  A.setLen(0)

proc clearBenchRows(S: var seq[ByteSeq]) =
  var
    i: int = 0
  while i < S.len:
    clearBenchBytes(S[i])
    i = i + 1
  S.setLen(0)

proc hexByte(b: uint8): string =
  const digits = "0123456789abcdef"
  result = newString(2)
  result[0] = digits[int((b shr 4) and 0x0f'u8)]
  result[1] = digits[int(b and 0x0f'u8)]

proc sampleWireHex(A: openArray[uint8], maxBytes: int = 8): string =
  let limit = min(A.len, maxBytes)
  for i in 0 ..< limit:
    if i > 0:
      result.add(' ')
    result.add(hexByte(A[i]))
  if A.len > limit:
    result.add(" ...")

proc initResult(name: string, cfg: BenchConfig, wireBytes: int,
    sampleBytes: openArray[uint8],
    startedAt, endedAt: MonoTime): BenchResult {.role: configurator.} =
  var
    elapsed: int64 = 0'i64
  elapsed = (endedAt - startedAt).inNanoseconds
  if elapsed < 1'i64:
    elapsed = 1'i64
  result.name = name
  result.iterations = cfg.iterations
  result.payloadBytes = cfg.payloadBytes
  result.wireBytes = wireBytes
  result.totalNs = elapsed
  result.sampleWireHex = sampleWireHex(sampleBytes)
  result.sink = benchSink

proc nsPerOp(r: BenchResult): float =
  result = float(r.totalNs) / float(r.iterations)

proc opsPerSec(r: BenchResult): float =
  result = (float(r.iterations) * 1_000_000_000.0) / float(r.totalNs)

proc mibPerSec(r: BenchResult): float =
  let totalPayloadBytes = float(r.payloadBytes) * float(r.iterations)
  result = totalPayloadBytes / (1024.0 * 1024.0) / (float(r.totalNs) / 1_000_000_000.0)

proc buildAmeBenchAad(): ByteSeq =
  var h: AmeFrameHeader
  h = initAmeFrameHeader(ampkLaneData, amcUserdata, 0'u8,
    7'u64, 1'u32, 5'u32, 3'u32)
  result = encodeAmeFrameHeader(h)

proc exactBenchAuth(seed: openArray[uint8],
    role: AmeEndpointRole = aerInitiator): AmeAuthPackage =
  const K: AmeKemAlgorithms = [akaFireSaber, akaX25519]
  var
    layout: AmeSuiteLayout = defaultAmeLayout(K)
    tier: AmeMaskTier = fullAmeMaskTier(layout)
    state: AmeExchangeState = initAmeExchangeState(K)
    secret: ByteSeq = @seed
  tier.masks.kem = 0b10000000'u8
  applyAmeExchange(state, initAmeExchangeRequest(K, tier,
    0b10000000'u8), [secret])
  result = initAmeAuthPackage(layout, tier, state, endpointRole = role)

proc buildDacBenchHeader(payloadLen: int): DacFrameHeader =
  var flags: DacFrameFlags
  if payloadLen > int(high(uint16)):
    result = initDacSuperCleanFrameHeader(dmkPackageChunk, 9'u64,
      5'u32, 0'u16, 1'u32, uint32(payloadLen), flags)
  else:
    result = initDacFrameHeader(dmkPackageChunk, 9'u64,
      5'u32, 0'u16, 1'u32, uint32(payloadLen), flags)

proc benchAmeProtect(cfg: BenchConfig): BenchResult =
  var
    auth: AmeAuthPackage = exactBenchAuth(@[byte 1, 2, 3, 4, 5, 6, 7, 8])
    payload: ByteSeq = buildPayload(cfg.payloadBytes)
    aad: ByteSeq = buildAmeBenchAad()
    sealed: tuple[message: AmeProtectedMessage, nonce: ByteSeq]
    env: AmeProtectedMessage
    startedAt: MonoTime
    endedAt: MonoTime
  for _ in 0 ..< cfg.warmup:
    sealed = protectAmeMessage(auth.current.layout, auth.current.tier,
      auth.current.exchange,
      payload, aad)
    env = sealed.message
    mixSinkBytes(env.payload)
    mixSinkBytes(env.authTag)
  startedAt = getMonoTime()
  for _ in 0 ..< cfg.iterations:
    sealed = protectAmeMessage(auth.current.layout, auth.current.tier,
      auth.current.exchange,
      payload, aad)
    env = sealed.message
    mixSinkBytes(env.payload)
    mixSinkBytes(env.authTag)
  endedAt = getMonoTime()
  result = initResult("ame_protect", cfg, env.payload.len + env.authTag.len,
    env.payload, startedAt, endedAt)

proc benchAmeOpen(cfg: BenchConfig): BenchResult =
  var
    auth: AmeAuthPackage = exactBenchAuth(
      @[byte 11, 12, 13, 14, 15, 16, 17, 18])
    payload: ByteSeq = buildPayload(cfg.payloadBytes)
    aad: ByteSeq = buildAmeBenchAad()
    sealed: tuple[message: AmeProtectedMessage, nonce: ByteSeq]
    opened: tuple[ok: bool, payload: ByteSeq]
    startedAt: MonoTime
    endedAt: MonoTime
  sealed = protectAmeMessage(auth.current.layout, auth.current.tier,
    auth.current.exchange,
    payload, aad)
  for _ in 0 ..< cfg.warmup:
    opened = openAmeMessage(auth.current.layout, auth.current.tier,
      auth.current.exchange,
      sealed.nonce, sealed.message, aad)
    if not opened.ok:
      raise newException(ValueError, "AME open benchmark warmup failed")
    mixSinkBytes(opened.payload)
  startedAt = getMonoTime()
  for _ in 0 ..< cfg.iterations:
    opened = openAmeMessage(auth.current.layout, auth.current.tier,
      auth.current.exchange,
      sealed.nonce, sealed.message, aad)
    if not opened.ok:
      raise newException(ValueError, "AME open benchmark failed")
    mixSinkBytes(opened.payload)
  endedAt = getMonoTime()
  result = initResult("ame_open", cfg,
    sealed.message.payload.len + sealed.message.authTag.len,
    sealed.message.payload, startedAt, endedAt)

proc benchDacEncode(cfg: BenchConfig): BenchResult =
  let
    payload = buildPayload(cfg.payloadBytes)
    h = buildDacBenchHeader(payload.len)
  var
    frame: ByteSeq
    startedAt: MonoTime
    endedAt: MonoTime
  for _ in 0 ..< cfg.warmup:
    frame = encodeDacFrame(h, payload)
    mixSinkBytes(frame)
  startedAt = getMonoTime()
  for _ in 0 ..< cfg.iterations:
    frame = encodeDacFrame(h, payload)
    mixSinkBytes(frame)
  endedAt = getMonoTime()
  result = initResult("dac_encode", cfg, frame.len, frame, startedAt, endedAt)

proc benchDacDecode(cfg: BenchConfig): BenchResult =
  let
    payload = buildPayload(cfg.payloadBytes)
    h = buildDacBenchHeader(payload.len)
    frame = encodeDacFrame(h, payload)
  var
    decoded: DacDecodedFrame
    startedAt: MonoTime
    endedAt: MonoTime
  for _ in 0 ..< cfg.warmup:
    decoded = decodeDacFrame(frame)
    mixSinkBytes(decoded.payload)
    mixSinkUint(decoded.header.sequence)
  startedAt = getMonoTime()
  for _ in 0 ..< cfg.iterations:
    decoded = decodeDacFrame(frame)
    mixSinkBytes(decoded.payload)
    mixSinkUint(decoded.header.sequence)
  endedAt = getMonoTime()
  result = initResult("dac_decode", cfg, frame.len, frame, startedAt, endedAt)

proc benchBfx2Encode(cfg: BenchConfig): BenchResult =
  let payload = buildPayload(cfg.payloadBytes)
  var
    envelope: ByteSeq
    startedAt: MonoTime
    endedAt: MonoTime
  for _ in 0 ..< cfg.warmup:
    envelope = encodeBfxEnvelope(0x1201'u16, 1'u16, payload)
    mixSinkBytes(envelope)
  startedAt = getMonoTime()
  for _ in 0 ..< cfg.iterations:
    envelope = encodeBfxEnvelope(0x1201'u16, 1'u16, payload)
    mixSinkBytes(envelope)
  endedAt = getMonoTime()
  result = initResult("bfx2_encode", cfg, envelope.len, envelope, startedAt, endedAt)

proc benchBfx2Decode(cfg: BenchConfig): BenchResult =
  let
    payload = buildPayload(cfg.payloadBytes)
    envelope = encodeBfxEnvelope(0x1201'u16, 1'u16, payload)
  var
    decoded: tuple[ok: bool, header: BfxHeader, payload: ByteSeq, err: string]
    startedAt: MonoTime
    endedAt: MonoTime
  for _ in 0 ..< cfg.warmup:
    decoded = decodeBfxEnvelope(envelope)
    if not decoded.ok:
      raise newException(ValueError, "BFX2 decode benchmark warmup failed: " &
        decoded.err)
    mixSinkBytes(decoded.payload)
    mixSinkUint(decoded.payload.len)
  startedAt = getMonoTime()
  for _ in 0 ..< cfg.iterations:
    decoded = decodeBfxEnvelope(envelope)
    if not decoded.ok:
      raise newException(ValueError, "BFX2 decode benchmark failed: " &
        decoded.err)
    mixSinkBytes(decoded.payload)
    mixSinkUint(decoded.payload.len)
  endedAt = getMonoTime()
  result = initResult("bfx2_decode", cfg, envelope.len, envelope, startedAt, endedAt)

proc initBenchAmeSession(auth: AmeAuthPackage, inboxCapacity: int): AmeSession =
  result = initAmeSession(auth, sessionId = 41'u64, rootLaneId = 1'u32,
    laneId = 5'u32, messageClass = amcUserdata, inboxCapacity = inboxCapacity,
    peerTrustRequired = false)

proc benchAmeDacSeal(cfg: BenchConfig): BenchResult =
  var
    auth: AmeAuthPackage = exactBenchAuth(
      @[byte 21, 22, 23, 24, 25, 26, 27, 28])
    payload: ByteSeq = buildPayload(cfg.payloadBytes)
    sender: AmeSession
    frame: ByteSeq
    startedAt: MonoTime
    endedAt: MonoTime
  sender = initBenchAmeSession(auth, 8)
  for _ in 0 ..< cfg.warmup:
    frame = sealAmeDacFrame(sender, payload)
    mixSinkBytes(frame)
  sender = initBenchAmeSession(auth, 8)
  startedAt = getMonoTime()
  for _ in 0 ..< cfg.iterations:
    frame = sealAmeDacFrame(sender, payload)
    mixSinkBytes(frame)
  endedAt = getMonoTime()
  result = initResult("ame_dac_seal", cfg, frame.len, frame, startedAt, endedAt)

proc benchAmeDacOpen(cfg: BenchConfig): BenchResult =
  var
    auth: AmeAuthPackage = exactBenchAuth(
      @[byte 31, 32, 33, 34, 35, 36, 37, 38], aerInitiator)
    peerAuth: AmeAuthPackage = exactBenchAuth(
      @[byte 31, 32, 33, 34, 35, 36, 37, 38], aerResponder)
    payload: ByteSeq = buildPayload(cfg.payloadBytes)
    warmupSender: AmeSession
    warmupReceiver: AmeSession
    sender: AmeSession
    receiver: AmeSession
    frames: seq[ByteSeq]
    opened: AmeOpenResult
    startedAt: MonoTime
    endedAt: MonoTime
  warmupSender = initBenchAmeSession(auth, max(cfg.warmup, 8))
  warmupReceiver = initBenchAmeSession(peerAuth, max(cfg.warmup, 8))
  for _ in 0 ..< cfg.warmup:
    opened = openAmeDacFrame(warmupReceiver, sealAmeDacFrame(warmupSender, payload))
    if not opened.ok:
      raise newException(ValueError, "AME DAC open benchmark warmup failed: " &
        opened.err)
    mixSinkBytes(opened.packet.payload)
  frames = newSeq[ByteSeq](cfg.iterations)
  sender = initBenchAmeSession(auth, 8)
  for i in 0 ..< cfg.iterations:
    frames[i] = sealAmeDacFrame(sender, payload)
  receiver = initBenchAmeSession(peerAuth, max(cfg.iterations, 8))
  startedAt = getMonoTime()
  for i in 0 ..< cfg.iterations:
    opened = openAmeDacFrame(receiver, frames[i])
    if not opened.ok:
      raise newException(ValueError, "AME DAC open benchmark failed: " &
        opened.err)
    mixSinkBytes(opened.packet.payload)
    mixSinkUint(opened.packet.dacSequence)
  endedAt = getMonoTime()
  result = initResult("ame_dac_open", cfg,
    if frames.len > 0: frames[0].len else: 0,
    if frames.len > 0: frames[0] else: @[],
    startedAt, endedAt)

proc layeredBenchAuth(seed: openArray[uint8],
    role: AmeEndpointRole = aerInitiator): AmeAuthPackage =
  ## seed: one stable secret for a layout that switches TWO cipher and TWO
  ## authenticator slots on. Comparing this against the single-slot layout is
  ## what the numbers below are for: it prices the cost of stacking.
  const K: AmeKemAlgorithms = [akaFireSaber, akaX25519]
  var
    layout: AmeSuiteLayout = initAmeSuiteLayout(K,
      initAmeCipherAlgorithms([acaXChaCha20, acaGimli]),
      initAmeMacAlgorithms([amaBlake3, amaPoly1305]),
      initAmeHashAlgorithms([defaultAmeHashSlot()]),
      initAmeSignatureAlgorithms(defaultAmeSigSlots()),
      initAmeKdfAlgorithms(defaultAmeKdfSlots()))
    tier: AmeMaskTier = fullAmeMaskTier(layout)
    state: AmeExchangeState = initAmeExchangeState(K)
    secret: ByteSeq = @seed
  tier.masks.kem = 0b10000000'u8
  applyAmeExchange(state, initAmeExchangeRequest(K, tier,
    0b10000000'u8), [secret])
  result = initAmeAuthPackage(layout, tier, state, endpointRole = role)

proc initBenchFomke(a: AmeAuthPackage): FomkeState =
  ## a: stable AME exchange turned into one ratchet.
  result = initFomkeFromAme(a.current.exchange, a.current.layout,
    a.current.tier, frInitiator)

proc benchFomkeSeal(cfg: BenchConfig, layered: bool,
    prepared: bool, name: string): BenchResult {.role: other.} =
  ## cfg/layered/prepared/name: one short-message send-path latency benchmark.
  var
    auth: AmeAuthPackage =
      if layered: layeredBenchAuth(@[byte 41, 42, 43, 44, 45, 46, 47, 48])
      else: exactBenchAuth(@[byte 41, 42, 43, 44, 45, 46, 47, 48])
    state: FomkeState = initBenchFomke(auth)
    cache: FomkeSendCache
    payload: ByteSeq = buildPayload(cfg.payloadBytes)
    message: FomkeMessage
    startedAt: MonoTime
    endedAt: MonoTime
  if prepared and cfg.warmup > 0:
    cache = prepareFomkeSendCache(state, cfg.warmup)
    for _ in 0 ..< cfg.warmup:
      message = sealFomkeMessagePrepared(state, cache, payload)
      mixSinkBytes(message.ciphertext)
      mixSinkBytes(message.authTag)
  else:
    for _ in 0 ..< cfg.warmup:
      message = sealFomkeMessage(state, payload)
      mixSinkBytes(message.ciphertext)
      mixSinkBytes(message.authTag)
  clearFomkeSendCache(cache)
  clearFomkeState(state)
  state = initBenchFomke(auth)
  if prepared:
    cache = prepareFomkeSendCache(state, cfg.iterations)
    startedAt = getMonoTime()
    for _ in 0 ..< cfg.iterations:
      message = sealFomkeMessagePrepared(state, cache, payload)
      mixSinkBytes(message.ciphertext)
      mixSinkBytes(message.authTag)
    endedAt = getMonoTime()
  else:
    startedAt = getMonoTime()
    for _ in 0 ..< cfg.iterations:
      message = sealFomkeMessage(state, payload)
      mixSinkBytes(message.ciphertext)
      mixSinkBytes(message.authTag)
    endedAt = getMonoTime()
  result = initResult(name, cfg,
    fomkeWireLen(payload.len, state.tagLen),
    message.ciphertext, startedAt, endedAt)
  clearFomkeSendCache(cache)
  clearFomkeState(state)

proc benchFomkePrepare8(cfg: BenchConfig, layered: bool,
    name: string): BenchResult {.role: other.} =
  ## cfg/layered/name: one eight-message cache-build throughput benchmark.
  var
    auth: AmeAuthPackage =
      if layered: layeredBenchAuth(@[byte 51, 52, 53, 54, 55, 56, 57, 58])
      else: exactBenchAuth(@[byte 51, 52, 53, 54, 55, 56, 57, 58])
    state: FomkeState = initBenchFomke(auth)
    cache: FomkeSendCache
    startedAt: MonoTime
    endedAt: MonoTime
    cacheBytes: int = 0
    sample: ByteSeq = @[]
  for _ in 0 ..< cfg.warmup:
    cache = prepareFomkeSendCache(state, 8)
    mixSinkBytes(cache.entries[0].material)
    clearFomkeSendCache(cache)
  startedAt = getMonoTime()
  for _ in 0 ..< cfg.iterations:
    cache = prepareFomkeSendCache(state, 8)
    mixSinkBytes(cache.entries[0].material)
    clearFomkeSendCache(cache)
  endedAt = getMonoTime()
  cache = prepareFomkeSendCache(state, 8)
  cacheBytes = fomkePreparedSecretBytes(cache)
  sample = cache.entries[0].material
  result = initResult(name, cfg, cacheBytes, sample, startedAt, endedAt)
  clearFomkeSendCache(cache)
  clearFomkeState(state)

proc benchStreamKeys(seed, outLen: uint8): seq[ByteSeq] =
  ## seed/outLen: eight independent key or nonce rows of `outLen` bytes.
  var
    i: int = 0
  while i < 8:
    result.add(deriveGb3Hkdf(@[byte seed + uint8(i)], @[], @[seed],
      int(outLen)))
    i = i + 1

proc printResults(results: openArray[BenchResult]) =
  const
    nameWidth = 26
  echo "Bifrost protocol benchmarks"
  echo ""
  echo "name".alignLeft(nameWidth) &
    "iters".alignLeft(10) &
    "payload".alignLeft(10) &
    "wire".alignLeft(10) &
    "total_ms".alignLeft(12) &
    "ns_op".alignLeft(14) &
    "MiB_s".alignLeft(10) &
    "sample"
  echo repeat('-', 118)
  for r in results:
    echo r.name.alignLeft(nameWidth) &
      alignLeft($r.iterations, 10) &
      alignLeft($r.payloadBytes, 10) &
      alignLeft($r.wireBytes, 10) &
      formatFloat(float(r.totalNs) / 1_000_000.0, ffDecimal, 3).alignLeft(12) &
      formatFloat(nsPerOp(r), ffDecimal, 2).alignLeft(14) &
      formatFloat(mibPerSec(r), ffDecimal, 2).alignLeft(10) &
      r.sampleWireHex
  echo ""
  echo "sink=" & $benchSink

proc ensureDir(path: string) =
  if path.len == 0 or dirExists(path):
    return
  let parent = parentDir(path)
  if parent.len > 0 and parent != path and not dirExists(parent):
    ensureDir(parent)
  createDir(path)

proc writeJsonResults(path: string, cfg: BenchConfig,
    results: openArray[BenchResult]) {.role: dataWriter.} =
  var
    root: JsonNode
    rows: JsonNode = newJArray()
  for r in results:
    rows.add(%*{
      "name": r.name,
      "iterations": r.iterations,
      "payload_bytes": r.payloadBytes,
      "wire_bytes": r.wireBytes,
      "total_ns": r.totalNs,
      "ns_per_op": nsPerOp(r),
      "ops_per_sec": opsPerSec(r),
      "mib_per_sec": mibPerSec(r),
      "sample_wire_hex": r.sampleWireHex,
      "sink": $r.sink,
    })
  root = %*{
    "harness": "bench_protocols",
    "iterations": cfg.iterations,
    "warmup": cfg.warmup,
    "payload_bytes": cfg.payloadBytes,
    "results": rows,
  }
  let dir = splitFile(path).dir
  if dir.len > 0:
    ensureDir(dir)
  writeFile(path, pretty(root))

proc main() =
  let cfg = parseArgs()
  var results: seq[BenchResult] = @[]
  if shouldRun(cfg, "ame_protect"):
    results.add(benchAmeProtect(cfg))
  if shouldRun(cfg, "ame_open"):
    results.add(benchAmeOpen(cfg))
  if shouldRun(cfg, "dac_encode"):
    results.add(benchDacEncode(cfg))
  if shouldRun(cfg, "dac_decode"):
    results.add(benchDacDecode(cfg))
  if shouldRun(cfg, "bfx2_encode"):
    results.add(benchBfx2Encode(cfg))
  if shouldRun(cfg, "bfx2_decode"):
    results.add(benchBfx2Decode(cfg))
  if shouldRun(cfg, "ame_dac_seal"):
    results.add(benchAmeDacSeal(cfg))
  if shouldRun(cfg, "ame_dac_open"):
    results.add(benchAmeDacOpen(cfg))
  ## One slot versus two: what stacking a second cipher and a second
  ## authenticator actually costs per message.
  if shouldRun(cfg, "fomke_seal_1slot"):
    results.add(benchFomkeSeal(cfg, false, false, "fomke_seal_1slot"))
  if shouldRun(cfg, "fomke_cached_seal_1slot"):
    results.add(benchFomkeSeal(cfg, false, true,
      "fomke_cached_seal_1slot"))
  if shouldRun(cfg, "fomke_seal_2slot"):
    results.add(benchFomkeSeal(cfg, true, false, "fomke_seal_2slot"))
  if shouldRun(cfg, "fomke_cached_seal_2slot"):
    results.add(benchFomkeSeal(cfg, true, true,
      "fomke_cached_seal_2slot"))
  if shouldRun(cfg, "fomke_prepare8_1slot"):
    results.add(benchFomkePrepare8(cfg, false, "fomke_prepare8_1slot"))
  if shouldRun(cfg, "fomke_prepare8_2slot"):
    results.add(benchFomkePrepare8(cfg, true, "fomke_prepare8_2slot"))
  if results.len == 0:
    raise newException(ValueError, "no benchmarks matched --only filter")
  printResults(results)
  if cfg.jsonOut.len > 0:
    writeJsonResults(cfg.jsonOut, cfg, results)
    echo "json_out=" & cfg.jsonOut

when isMainModule:
  main()
