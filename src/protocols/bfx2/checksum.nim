## -------------------------------------------------
## BFX2 Checksum <- CRC32 implementation for headers
## -------------------------------------------------

import ../types
import ../../analysis_pragmas

const
  crc32Poly = 0xEDB88320'u32

proc crc32*(bs: ByteSeq): uint32 {.gcsafe, role: truthBuilder.} =
  ## crc32: build crc 32.
  var
    c: uint32 = 0xFFFFFFFF'u32
    i: int = 0
    j: int = 0
  i = 0
  while i < bs.len:
    c = c xor uint32(bs[i])
    j = 0
    while j < 8:
      if (c and 1'u32) != 0'u32:
        c = (c shr 1) xor crc32Poly
      else:
        c = c shr 1
      j.inc
    i.inc
  result = not c


