## AME over the DAC carrier. Builds either way; the adaptive layer is extra.
import ../../src/protocols/ame
import ../../src/protocols/dac/build
import ../../src/protocols/dac/level0/defaults
var
  layout = defaultAmeLayout(initAmeKemAlgorithms(defaultAmeKemSlots()))
  d = cleanLanDacDefaults()
echo "kems: ", layout.kems.length, " chunk: ", d.chunkBytes,
     " adaptive: ", dacAdaptiveBuilt
