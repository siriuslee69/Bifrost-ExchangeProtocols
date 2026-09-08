## -------------------------------------------------------------
## CHUNKYAEAD Memory Ops <- RAM-aware chunk and buffer selection
## -------------------------------------------------------------

import ./types
import bifrostPragmas

when defined(windows):
  import std/winlean

type MemInfo = object
  availBytes: int64

when defined(windows):
  type MemoryStatusEx {.pure.} = object
    dwLength, dwMemoryLoad: DWORD
    ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile: uint64
    ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual: uint64
  proc GlobalMemoryStatusEx(s: ptr MemoryStatusEx): WINBOOL {.importc: "GlobalMemoryStatusEx", stdcall, dynlib: "Kernel32.dll".}

proc readMemInfo(): MemInfo {.role: dataFetcher.} =
  when defined(windows):
    var s: MemoryStatusEx
    s.dwLength = DWORD(sizeof(MemoryStatusEx))
    if GlobalMemoryStatusEx(addr s) != 0:
      result.availBytes = int64(s.ullAvailPhys)
    else:
      result.availBytes = -1
  else:
    result.availBytes = -1

proc availableRamBytes*(): int64 {.role: dataFetcher.} =
  result = readMemInfo().availBytes

proc resolveChunkBytes*(o: ChunkyOptions): int64 {.role: configurator.} =
  result = o.chunkBytes
  if result <= 0: result = defaultChunkBytes
  if not o.forceChunkBytes and availableRamBytes() > 0 and
      availableRamBytes() < lowRamThresholdBytes:
    result = fallbackChunkBytes

proc resolveBufferBytes*(o: ChunkyOptions): int {.role: configurator.} =
  result = o.bufferBytes
  if result <= 0: result = defaultBufferBytes
  if result mod 64 != 0:
    result = result - (result mod 64)
    if result <= 0: result = 64

proc resolveThreadCount*(o: ChunkyOptions, perThreadBytes: int64,
    chunkCount: int): int {.role: configurator,
    metaTags: {tagAppApi, tagChunkyAead}.} =
  var byMem, byOpt: int
  if chunkCount <= 0: return
  if availableRamBytes() > 0 and perThreadBytes > 0:
    byMem = int((availableRamBytes() * 8 div 10) div perThreadBytes)
  byOpt = o.maxThreads
  if byMem <= 0 and byOpt <= 0: result = chunkCount
  elif byMem <= 0: result = byOpt
  elif byOpt <= 0: result = byMem
  else: result = min(byMem, byOpt)
  result = max(1, min(result, chunkCount))
