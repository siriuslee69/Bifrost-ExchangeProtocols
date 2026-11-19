## -------------------------------------------------------------------------
## CHUNKYAEAD threads <- eight workers give exactly what one worker gives
## -------------------------------------------------------------------------
##
## The chunk workers take the next chunk number from a shared counter under a lock and
## write each chunk to a file of its own. A race here would show as a chunk that differs
## between runs, or a file that opens on one run and not on the next. The test seals and
## opens the same file many times, with 1 worker and with 8, and requires byte-identical
## chunk files and an identical result every time.

import std/[unittest, os, algorithm]

import ../../src/protocols/chunkyaead
import runePragmas

proc keyOf(b: uint8): seq[uint8] {.role: helper.} =
  result = newSeq[uint8](32)
  for i in 0 ..< result.len:
    result[i] = b xor uint8(i)

proc stateOf(): ChunkyCipherState {.role: configurator.} =
  var
    n: seq[uint8] = newSeq[uint8](24)
  for i in 0 ..< n.len:
    n[i] = uint8(0x30 + i)
  result = initChunkyCipherState(caXChaCha20AesGimli,
    @[keyOf(1'u8), keyOf(2'u8), keyOf(3'u8)], n, 64'u16)

proc optionsOf(dir: string, threads: int): ChunkyOptions {.role: configurator.} =
  result = initChunkyOptions()
  result.chunkBytes = 64 * 1024
  result.bufferBytes = 4096
  result.outputDir = dir
  result.maxThreads = threads
  result.forceChunkBytes = true

proc chunkFiles(dir: string): seq[string] {.role: dataFetcher.} =
  ## every chunk file of a folder, its bytes, in name order
  var
    names: seq[string] = @[]
  for p in walkFiles(dir / "*.bin"):
    names.add(p)
  names.sort()
  for p in names:
    result.add(readFile(p))

suite "chunk workers are repeatable":
  # {.testKind: tkProperty, covers: "encryptFileChunks|decryptFileChunks",
  #   pins: "intermittent corruption when chunk tasks crossed threads".}
  test "40 rounds: 8 workers seal and open exactly what 1 worker does":
    var
      root: string = getTempDir() / ("bfx_threads_" & $getCurrentProcessId())
      data: string = newString(3 * 1024 * 1024 + 123)
      m1: ChunkyManifest = ChunkyManifest()
      m8: ChunkyManifest = ChunkyManifest()
      want: seq[string] = @[]
      differ: int = 0
      failedOpen: int = 0
    createDir(root)
    defer: removeDir(root)
    for i in 0 ..< data.len:
      data[i] = char((i * 31 + 7) mod 251)
    writeFile(root / "in.bin", data)
    m1 = encryptFileChunks(root / "in.bin", root / "c1", stateOf(), optionsOf(root / "c1", 1))
    want = chunkFiles(root / "c1")
    check want.len == 49
    for round in 0 ..< 40:
      removeDir(root / "c8")
      m8 = encryptFileChunks(root / "in.bin", root / "c8", stateOf(), optionsOf(root / "c8", 8))
      if chunkFiles(root / "c8") != want:
        differ = differ + 1
      try:
        decryptFileChunks(m8, root / "c8", root / "out.bin", stateOf(), optionsOf(root / "c8", 8))
        if readFile(root / "out.bin") != data:
          failedOpen = failedOpen + 1
      except CatchableError:
        failedOpen = failedOpen + 1
    check m1.chunkCount == m8.chunkCount
    check differ == 0
    check failedOpen == 0
