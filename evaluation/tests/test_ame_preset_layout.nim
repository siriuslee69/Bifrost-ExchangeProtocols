## -------------------------------------------------------------------------
## AME Preset Layout Tests <- a pinned bitmask always has its algorithms
## -------------------------------------------------------------------------
##
## Compiled once per preset by `nimble testPresetLayout`, including three
## fixtures (evaluation/tests/fixtures/presets/) whose flags deliberately
## leave out what their layout pins:
##
##   fixture                 layout pins          flags compile   expected
##   ----------------------  -------------------  --------------  ----------
##   adds_kyber              Kyber768, X25519     saber, x25519   kyber added
##   adds_falcon_gimli       Falcon512, GimliXof  ed25519, blake3 both added
##   firesaber_rank2         FireSaber            saberMaxRank=2  build stops
##
## Every build that compiles must satisfy the same rules, checked below.

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/config
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/algorithms
import ../../src/protocols/ame/level1/signatures
import ../../src/protocols/ame/level1/symmetric
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/preset_layout
import runePragmas

suite "AME preset layout":
  # {.testKind: tkIntegration, covers: "presetKemSlotSet".}
  test "every slot the pinned layout names is compiled":
    check presetKemSlotSet <= ameKemSlotsBuilt
    check presetSigSlotSet <= ameSigSlotsBuilt
    check presetSymPrimitives <= ameSymBuilt

  # {.testKind: tkUnit, covers: "presetKemSlots".}
  test "the build-time decoder agrees with the real one":
    ## preset_layout.nim reads the layout bytes on its own (it sits below
    ## the real decoder). Both must see the same KEM slots.
    var
      L: AmeSuiteLayout = defaultBifrostConfig().ameLayout
      i: int = 0
    if presetLayoutSource.len > 0:
      check int(L.kems.length) == presetKemSlots.len
      while i < presetKemSlots.len:
        check L.kems.algorithms[i] == presetKemSlots[i]
        i = i + 1

  # {.testKind: tkIntegration, covers: "defaultBifrostConfig".}
  test "the pinned layout is the default and every KEM slot runs":
    var
      L: AmeSuiteLayout = defaultBifrostConfig().ameLayout
      i: int = 0
      kp: AmeKemKeypair = default(AmeKemKeypair)
    while i < int(L.kems.length):
      checkpoint(ameKemName(L.kems.algorithms[i]))
      check ameKemBuilt(L.kems.algorithms[i])
      kp = ameKemKeypair(L.kems.algorithms[i])
      check kp.publicKey.len > 0
      i = i + 1
