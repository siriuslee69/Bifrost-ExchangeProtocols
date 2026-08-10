import std/unittest
import std/os

import ../src/protocols/chunkyaead
import ../src/protocols/chunkyaead/level1/nonce_ops

proc toBytes(s: string): seq[uint8] =
  var
    i: int = 0
  result.setLen(s.len)
  while i < s.len:
    result[i] = uint8(ord(s[i]))
    i = i + 1

proc hexNibble(c: char): uint8 =
  if c >= '0' and c <= '9':
    return uint8(ord(c) - ord('0'))
  if c >= 'a' and c <= 'f':
    return uint8(ord(c) - ord('a') + 10)
  if c >= 'A' and c <= 'F':
    return uint8(ord(c) - ord('A') + 10)
  raise newException(ValueError, "invalid hexadecimal character")

proc hexToBytes(s: string): seq[uint8] =
  var
    i: int = 0
  if (s.len and 1) != 0:
    raise newException(ValueError, "hexadecimal text must have even length")
  result.setLen(s.len div 2)
  while i < result.len:
    result[i] = (hexNibble(s[i * 2]) shl 4) or hexNibble(s[i * 2 + 1])
    i = i + 1

proc writeBytes(p: string, bs: seq[uint8]) =
  var
    f: File
  if not open(f, p, fmWrite):
    raise newException(IOError, "failed to open output file")
  try:
    if bs.len > 0 and f.writeBuffer(unsafeAddr bs[0], bs.len) != bs.len:
      raise newException(IOError, "failed to write output bytes")
  finally:
    close(f)

proc readBytes(p: string): seq[uint8] =
  let s = readFile(p)
  result = newSeq[uint8](s.len)
  for i, ch in s:
    result[i] = uint8(ord(ch))

proc removeTree(p: string) =
  if not dirExists(p):
    return
  for entry in walkDir(p, relative = false):
    if entry.kind == pcFile:
      removeFile(entry.path)
    elif entry.kind == pcDir:
      removeTree(entry.path)
  if dirExists(p):
    removeDir(p)

proc buildState(keyX, keyA, keyG,
    nonce: seq[uint8]): ChunkyCipherState =
  result = initChunkyCipherState(caXChaCha20AesGimli,
    @[keyX, keyA, keyG], nonce, 64'u16)

proc buildAesGimliState(keyA, keyG,
    nonce: seq[uint8]): ChunkyCipherState =
  result = initChunkyCipherState(caAesGimli, @[keyA, keyG], nonce, 64'u16)

suite "CHUNKYAEAD":
  test "encrypt/decrypt roundtrip":
    let tmpDir = joinPath(getTempDir(), "bifrost_chunkyaead_" & $getCurrentProcessId())
    if dirExists(tmpDir):
      removeTree(tmpDir)
    createDir(tmpDir)
    defer:
      removeTree(tmpDir)
    let inputPath = joinPath(tmpDir, "input.bin")
    let chunkDir = joinPath(tmpDir, "chunks")
    let outputPath = joinPath(tmpDir, "output.bin")
    var data = newSeq[uint8](256 * 1024)
    for i in 0 ..< data.len:
      data[i] = uint8((i * 17) mod 251)
    writeBytes(inputPath, data)

    let keyX = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let keyA = hexToBytes("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
    let keyG = hexToBytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    let nonce = hexToBytes("000102030405060708090a0b0c0d0e0f1011121314151617")
    let state = buildState(keyX, keyA, keyG, nonce)
    var opt = initChunkyOptions()
    opt.chunkBytes = 64 * 1024
    opt.bufferBytes = 4096
    opt.outputDir = chunkDir
    opt.maxThreads = 2
    let manifest = encryptFileChunks(inputPath, chunkDir, state, opt)
    decryptFileChunks(manifest, chunkDir, outputPath, state, opt)
    let outBytes = readBytes(outputPath)
    check outBytes == data

  test "tag mismatch rejects":
    let tmpDir = joinPath(getTempDir(), "bifrost_chunkyaead_tag_" & $getCurrentProcessId())
    if dirExists(tmpDir):
      removeTree(tmpDir)
    createDir(tmpDir)
    defer:
      removeTree(tmpDir)
    let inputPath = joinPath(tmpDir, "input.bin")
    let chunkDir = joinPath(tmpDir, "chunks")
    let outputPath = joinPath(tmpDir, "output.bin")
    let data = toBytes("chunky crypto tamper test")
    writeBytes(inputPath, data)

    let keyX = hexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000000000000000000000000000")
    let keyA = hexToBytes("00000000000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    let keyG = hexToBytes("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccc")
    let nonce = hexToBytes("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    let state = buildState(keyX, keyA, keyG, nonce)
    var opt = initChunkyOptions()
    opt.chunkBytes = 1024
    opt.bufferBytes = 256
    opt.outputDir = chunkDir
    let manifest = encryptFileChunks(inputPath, chunkDir, state, opt)
    let chunkPath = joinPath(chunkDir, manifest.chunkFiles[0])
    var f: File
    if open(f, chunkPath, fmReadWrite):
      let sz = getFileSize(chunkPath)
      if sz > 0:
        setFilePos(f, sz - 1)
        var b: array[1, uint8]
        b[0] = 0'u8
        discard f.writeBuffer(addr b[0], 1)
      close(f)
    expect IOError:
      decryptFileChunks(manifest, chunkDir, outputPath, state, opt)

  test "aes gimli chunk mode roundtrip":
    let tmpDir = joinPath(getTempDir(), "bifrost_chunkyaead_aes_gimli_" & $getCurrentProcessId())
    if dirExists(tmpDir):
      removeTree(tmpDir)
    createDir(tmpDir)
    defer:
      removeTree(tmpDir)
    let inputPath = joinPath(tmpDir, "input.bin")
    let chunkDir = joinPath(tmpDir, "chunks")
    let outputPath = joinPath(tmpDir, "output.bin")
    var data = newSeq[uint8](64 * 1024)
    for i in 0 ..< data.len:
      data[i] = uint8((i * 19) mod 251)
    writeBytes(inputPath, data)

    let keyA = hexToBytes("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
    let keyG = hexToBytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    let nonce = hexToBytes("000102030405060708090a0b0c0d0e0f1011121314151617")
    let state = buildAesGimliState(keyA, keyG, nonce)
    var opt = initChunkyOptions()
    opt.chunkBytes = 16 * 1024
    opt.bufferBytes = 2048
    opt.outputDir = chunkDir
    opt.algo = caAesGimli
    let manifest = encryptFileChunks(inputPath, chunkDir, state, opt)
    decryptFileChunks(manifest, chunkDir, outputPath, state, opt)
    let outBytes = readBytes(outputPath)
    check outBytes == data

  test "nonce derivation differs":
    let base = hexToBytes("000102030405060708090a0b0c0d0e0f1011121314151617")
    var bArr: array[24, uint8]
    for i in 0 ..< bArr.len:
      bArr[i] = base[i]
    let n0 = deriveChunkNonce(bArr, 0'u64)
    let n1 = deriveChunkNonce(bArr, 1'u64)
    check n0 != n1

  test "chunk hash deterministic":
    let tmpDir = joinPath(getTempDir(), "bifrost_chunkyaead_hash_" & $getCurrentProcessId())
    if dirExists(tmpDir):
      removeTree(tmpDir)
    createDir(tmpDir)
    defer:
      removeTree(tmpDir)
    let inputPath = joinPath(tmpDir, "input.bin")
    var data = newSeq[uint8](8192)
    for i in 0 ..< data.len:
      data[i] = uint8(i mod 251)
    writeBytes(inputPath, data)
    var opt = initChunkyOptions()
    opt.chunkBytes = 2048
    opt.bufferBytes = 512
    let h0 = hashFileChunks(inputPath, opt, haBlake3Tree)
    let h1 = hashFileChunks(inputPath, opt, haBlake3Tree)
    check h0.len == 32
    check h0 == h1
