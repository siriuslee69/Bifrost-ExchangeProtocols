## -------------------------------------------------
## BFX2 Checksum <- CRC32 implementation for headers
## -------------------------------------------------

import ../types
import runePragmas

const
  crc32Poly = 0xEDB88320'u32

proc crc32Byte(c: uint32, b: uint8): uint32 {.inline, gcsafe, role: math.} =
  ## c/b: the running CRC after one more byte (reflected, 0xEDB88320).
  var
    j: int = 0
  result = c xor uint32(b)
  while j < 8:
    result = (result shr 1) xor (crc32Poly and (0'u32 - (result and 1'u32)))
    j = j + 1

proc crc32*(bs: ByteSeq): uint32 {.gcsafe, role: truthBuilder.} =
  ## crc32: build crc 32.
  var
    c: uint32 = 0xFFFFFFFF'u32
  for b in bs:
    c = crc32Byte(c, b)
  result = not c


