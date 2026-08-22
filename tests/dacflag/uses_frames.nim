## Uses only the DAC wire: envelope plus fixed profiles. Must build either way.
import ../../src/protocols/dac/types
import ../../src/protocols/dac/build
import ../../src/protocols/dac/level0/framing
import ../../src/protocols/dac/level0/defaults
var
  d = cleanLanDacDefaults()
  flags: DacFrameFlags
  h = initDacFrameHeader(dmkPackageChunk, 1'u64, 2'u32, 3'u16, 4'u32, 4'u32, flags)
  frame = encodeDacFrame(h, @[byte 1, 2, 3, 4])
doAssert decodeDacFrame(frame).payload.len == 4
doAssert d.chunkBytes == 1200'u16
echo "adaptive layer present: ", dacAdaptiveBuilt
