## Uses the adaptive layer. Must NOT build under -d:bifrostDac=off.
import ../../src/protocols/dac/level0/defaults
import ../../src/protocols/dac/level3/link
var
  S = initDacLink(1'u64, 1'u32, cleanLanDacDefaults(), 7'u64)
doAssert beginDacPackage(S, 1'u64, newSeq[uint8](4096), 0'u32).len > 0
