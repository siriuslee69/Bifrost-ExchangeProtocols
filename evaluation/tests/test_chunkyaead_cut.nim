## ------------------------------------------------------------------
## CHUNKYAEAD cut files <- a file cut short, or a chunk header edited,
## never opens. Version 2 binds "this is the last chunk" and the whole
## chunk header into each chunk's tag.
## ------------------------------------------------------------------
##
##   chunk file:  [ header 53 bytes ][ ciphertext ][ tag ]
##                  ^ covered by the tag, byte for byte
##   header:      magic 0-7 | version 8 | algo 9 | tagLen 10-11 | index 12-19
##                plainLen 20-27 | nonce 28-51 | flags 52 (bit 0 = LAST chunk)

import std/unittest
import std/os
import std/strutils

import ../../src/protocols/chunkyaead
import runePragmas

const
  offVersion = 8
  offAlgo = 9
  offTagLen = 10
  offFlags = 52
  headerLen = 53

type
  OpenResult = tuple[ok: bool, err: string]

proc keyOf(b: uint8): seq[uint8] {.role: helper.} =
  result = newSeq[uint8](32)
  for i in 0 ..< result.len:
    result[i] = b xor uint8(i)

proc makeState(): ChunkyCipherState {.role: configurator.} =
  var
    n: seq[uint8] = newSeq[uint8](24)
  for i in 0 ..< n.len:
    n[i] = uint8(0xA0 + i)
  result = initChunkyCipherState(caXChaCha20AesGimli,
    @[keyOf(1'u8), keyOf(2'u8), keyOf(3'u8)], n, 64'u16)

proc makeOptions(dir: string): ChunkyOptions {.role: configurator.} =
  result = initChunkyOptions()
  result.chunkBytes = 1024
  result.bufferBytes = 256
  result.outputDir = dir
  result.maxThreads = 1

proc scratch(name: string): string {.role: helper.} =
  var
    d: string = joinPath(getTempDir(), "bfx_cut_" & name & "_" & $getCurrentProcessId())
  if dirExists(d):
    removeDir(d)
  createDir(d)
  result = d

proc sealed(dir: string, size: int, m: var ChunkyManifest) {.role: helper.} =
  ## dir/size/m: write a file of `size` bytes, seal it in 1 KiB chunks.
  var
    data: string = newString(size)
    inP: string = joinPath(dir, "input.bin")
  for i in 0 ..< size:
    data[i] = char((i * 7 + 3) mod 251)
  writeFile(inP, data)
  m = encryptFileChunks(inP, joinPath(dir, "chunks"), makeState(),
    makeOptions(joinPath(dir, "chunks")))

proc tryOpen(dir: string, m: ChunkyManifest): OpenResult {.role: actor.} =
  ## dir/m: open the chunks of `m`; says whether it worked and the reason.
  var
    outP: string = joinPath(dir, "out.bin")
  result = (ok: true, err: "")
  if fileExists(outP):
    removeFile(outP)
  try:
    decryptFileChunks(m, joinPath(dir, "chunks"), outP, makeState(),
      makeOptions(joinPath(dir, "chunks")))
  except CatchableError as e:
    result = (ok: false, err: e.msg)
  if not result.ok and fileExists(outP):
    result = (ok: false, err: "REFUSED BUT LEFT AN OUTPUT FILE: " & result.err)

proc patchByte(path: string, off: int, v: uint8) {.role: helper.} =
  var
    s: string = readFile(path)
  s[off] = char(v)
  writeFile(path, s)

proc chunkPath(dir: string, m: ChunkyManifest, i: int): string {.role: helper.} =
  result = joinPath(joinPath(dir, "chunks"), m.chunkFiles[i])

suite "CHUNKYAEAD: a cut file never opens":
  # {.testKind: tkRegression, covers: "decryptFileChunks",
  #   pins: "a manifest cut to fewer chunks opened a shorter file with no error".}
  test "a manifest cut to one or two chunks is refused":
    var
      d: string = scratch("cut")
      m: ChunkyManifest = ChunkyManifest()
      c: ChunkyManifest = ChunkyManifest()
      r: OpenResult = (ok: true, err: "")
    defer: removeDir(d)
    sealed(d, 3 * 1024 + 100, m)
    check m.chunkCount == 4
    check tryOpen(d, m).ok
    ## only the count and the list are cut: the size no longer fits
    for keep in 1 .. 3:
      c = m
      c.chunkCount = keep
      c.chunkFiles.setLen(keep)
      r = tryOpen(d, c)
      check not r.ok
      check "does not fit" in r.err
    ## the attacker edits the size too: only the last-chunk flag is left
    for keep in 1 .. 3:
      c = m
      c.chunkCount = keep
      c.chunkFiles.setLen(keep)
      c.originalSize = int64(keep) * 1024
      r = tryOpen(d, c)
      check not r.ok
      check "last one" in r.err

  # {.testKind: tkEdgeCase, covers: "decryptFileChunks".}
  test "a manifest that asks for one chunk more is refused":
    var
      d: string = scratch("more")
      m: ChunkyManifest = ChunkyManifest()
      c: ChunkyManifest = ChunkyManifest()
      r: OpenResult = (ok: true, err: "")
    defer: removeDir(d)
    sealed(d, 2 * 1024, m)
    c = m
    c.chunkCount = 3
    c.originalSize = 3 * 1024
    c.chunkFiles.add(m.chunkFiles[0])
    r = tryOpen(d, c)
    check not r.ok

  # {.testKind: tkEdgeCase, covers: "decryptFileChunks".}
  test "the exact sizes all open: empty, one byte, one chunk, two chunks, a bit more":
    var
      d: string = ""
      m: ChunkyManifest = ChunkyManifest()
      sizes: array[5, int] = [0, 1, 1024, 2048, 2049]
    for sz in sizes:
      d = scratch("sz" & $sz)
      sealed(d, sz, m)
      check tryOpen(d, m).ok
      check readFile(joinPath(d, "out.bin")) == readFile(joinPath(d, "input.bin"))
      removeDir(d)

suite "CHUNKYAEAD: the chunk header is a claim, not an instruction":
  # {.testKind: tkRegression, covers: "requireChunkHeader",
  #   pins: "the tag length came from the chunk file, so a one-byte tag could be forced".}
  test "a header that says the tag is 1 byte long is refused":
    var
      d: string = scratch("tag1")
      m: ChunkyManifest = ChunkyManifest()
      p: string = ""
      s: string = ""
      r: OpenResult = (ok: true, err: "")
    defer: removeDir(d)
    sealed(d, 1024, m)
    p = chunkPath(d, m, 0)
    s = readFile(p)
    ## header says tagLen = 1; the file is cut to header + body + 1 tag byte
    s[offTagLen] = char(1)
    s[offTagLen + 1] = char(0)
    s.setLen(s.len - 63)
    writeFile(p, s)
    r = tryOpen(d, m)
    check not r.ok
    check "tag length" in r.err

  # {.testKind: tkEdgeCase, covers: "requireChunkHeader".}
  test "clearing the last-chunk flag, or setting it early, is refused":
    var
      d: string = scratch("flag")
      m: ChunkyManifest = ChunkyManifest()
      r: OpenResult = (ok: true, err: "")
    defer: removeDir(d)
    sealed(d, 2 * 1024, m)
    patchByte(chunkPath(d, m, 1), offFlags, 0'u8)
    r = tryOpen(d, m)
    check not r.ok
    check "last one" in r.err
    sealed(d, 2 * 1024, m)
    patchByte(chunkPath(d, m, 0), offFlags, 1'u8)
    r = tryOpen(d, m)
    check not r.ok
    patchByte(chunkPath(d, m, 0), offFlags, 0x80'u8)
    r = tryOpen(d, m)
    check not r.ok

  # {.testKind: tkEdgeCase, covers: "requireChunkHeader".}
  test "a version 1 file is refused with words that say what to do":
    var
      d: string = scratch("v1")
      m: ChunkyManifest = ChunkyManifest()
      r: OpenResult = (ok: true, err: "")
    defer: removeDir(d)
    sealed(d, 100, m)
    patchByte(chunkPath(d, m, 0), offVersion, 1'u8)
    r = tryOpen(d, m)
    check not r.ok
    check "version 1" in r.err
    check "encrypted again" in r.err

  # {.testKind: tkFuzz, covers: "decodeHeader".}
  test "every byte of the header, set to every one of 256 values, never opens and never crashes":
    var
      d: string = scratch("hdr")
      m: ChunkyManifest = ChunkyManifest()
      p: string = ""
      orig: string = ""
      s: string = ""
      r: OpenResult = (ok: true, err: "")
      opened: int = 0
    defer: removeDir(d)
    sealed(d, 700, m)
    p = chunkPath(d, m, 0)
    orig = readFile(p)
    for off in 0 ..< headerLen:
      for v in 0 .. 255:
        if char(v) == orig[off]:
          continue
        s = orig
        s[off] = char(v)
        writeFile(p, s)
        r = tryOpen(d, m)
        if r.ok:
          opened = opened + 1
    writeFile(p, orig)
    check opened == 0
    check tryOpen(d, m).ok

  # {.testKind: tkEdgeCase, covers: "decodeHeader".}
  test "an algorithm byte that is no algorithm is an error, not a crash":
    var
      d: string = scratch("algo")
      m: ChunkyManifest = ChunkyManifest()
      r: OpenResult = (ok: true, err: "")
    defer: removeDir(d)
    sealed(d, 100, m)
    patchByte(chunkPath(d, m, 0), offAlgo, 0xFF'u8)
    r = tryOpen(d, m)
    check not r.ok
    check "algorithm" in r.err

suite "CHUNKYAEAD: a manifest is hostile input":
  # {.testKind: tkEdgeCase, covers: "requireManifestShape".}
  test "chunk names that point outside the chunk folder are refused":
    var
      d: string = scratch("names")
      m: ChunkyManifest = ChunkyManifest()
      c: ChunkyManifest = ChunkyManifest()
      bad: seq[string] = @["../input.bin", "/etc/hostname", "a/b", "..", ".", "",
        "x\0y", "a\\b"]
      r: OpenResult = (ok: true, err: "")
    defer: removeDir(d)
    sealed(d, 100, m)
    for name in bad:
      c = m
      c.chunkFiles[0] = name
      r = tryOpen(d, c)
      check not r.ok
      check "not a file name" in r.err

  # {.testKind: tkEdgeCase, covers: "requireManifestShape".}
  test "numbers that would overflow the size sums are refused, not computed":
    var
      d: string = scratch("nums")
      m: ChunkyManifest = ChunkyManifest()
      c: ChunkyManifest = ChunkyManifest()
      r: OpenResult = (ok: true, err: "")
    defer: removeDir(d)
    sealed(d, 100, m)
    c = m
    c.chunkBytes = int64.high
    r = tryOpen(d, c)
    check not r.ok
    c = m
    c.originalSize = int64.high
    r = tryOpen(d, c)
    check not r.ok
    c = m
    c.originalSize = -5
    r = tryOpen(d, c)
    check not r.ok
    c = m
    c.chunkBytes = 0
    r = tryOpen(d, c)
    check not r.ok
    c = m
    c.tagLen = 0
    r = tryOpen(d, c)
    check not r.ok
    c = m
    c.chunkCount = 1_000_000_000
    r = tryOpen(d, c)
    check not r.ok
