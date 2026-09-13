## Uses only the DAC wire: message bodies plus fixed profiles. Must build
## either way.
##
## The "wire" used to mean a DAC frame envelope. There is no envelope any
## more -- DAC frames nothing itself, and every message it sends travels as
## the authenticated body of an AME frame. So what this probe pins is what is
## left and still has to survive `-d:bifrostDac=off`: the body codecs and the
## fixed scenario profiles.
import ../../../src/protocols/types
import ../../../src/protocols/dac/types
import ../../../src/protocols/dac/build
import ../../../src/protocols/dac/level1/package_chunk
import ../../../src/protocols/dac/level0/defaults
var
  d = dacDefaultsFor(dscCleanLan)
  chunk = initDacPackageChunk(1'u64, 2'u32, 3'u16, 0'u32, @[byte 1, 2, 3, 4])
  body: ByteSeq = encodeDacPackageChunk(chunk)
doAssert decodeDacPackageChunk(body).payload.len == 4
doAssert d.chunkBytes == 1200'u16
echo "adaptive layer present: ", dacAdaptiveBuilt
