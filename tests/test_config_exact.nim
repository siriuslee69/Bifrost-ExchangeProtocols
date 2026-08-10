## -------------------------------------------------------------------------
## Exact Config Tests <- canonical AME layout and initial-tier roundtrip
## -------------------------------------------------------------------------

import std/unittest

import ../src/protocols/config
import ../src/protocols/ame/level1/suites
import ../src/protocols/fomke/types

suite "exact Bifrost config":
  test "committed layout and tier equal the programmatic default":
    var
      expected: BifrostConfig = defaultBifrostConfig()
      loaded: BifrostConfig = loadBifrostConfigFile("config.toml")
    check layoutsEquivalent(expected.ameLayout, loaded.ameLayout)
    check tiersEquivalent(expected.ameInitialTier, loaded.ameInitialTier)
    check encodeConfigHex(encodeAmeSuiteLayout(expected.ameLayout)) ==
      encodeConfigHex(encodeAmeSuiteLayout(loaded.ameLayout))
    check encodeConfigHex(encodeAmeMaskTier(expected.ameInitialTier)) ==
      encodeConfigHex(encodeAmeMaskTier(loaded.ameInitialTier))
    check not loaded.tmeAeadPregeneration
    check loaded.ggAeadPregeneration
    check loaded.fomkePregenerationMessages == 8
    check loaded.fomkePregenerationPayloadBytes == 256
    check not fomkePregenerationEnabledFor(loaded, fmcTmeAead)
    check fomkePregenerationEnabledFor(loaded, fmcGgAead)

  test "invalid layout and tier hex are rejected":
    expect ValueError:
      discard parseBifrostConfigText("ameLayoutHex = \"01ff\"")
    expect ValueError:
      discard parseBifrostConfigText("ameInitialTierHex = \"01ff\"")

  test "validated configuration becomes the active process default":
    var
      configured: BifrostConfig = defaultBifrostConfig()
      active: BifrostConfig
    configured.defaultTimeoutMs = 1234
    applyBifrostConfig(configured)
    active = currentBifrostConfig()
    check active.defaultTimeoutMs == 1234

  test "cipher policies and cache dimensions parse independently":
    var
      parsed: BifrostConfig = parseBifrostConfigText("""
        tmeAeadPregeneration = true
        ggAeadPregeneration = false
        fomkePregenerationMessages = 16
        fomkePregenerationPayloadBytes = 96
      """)
    check parsed.tmeAeadPregeneration
    check not parsed.ggAeadPregeneration
    check parsed.fomkePregenerationMessages == 16
    check parsed.fomkePregenerationPayloadBytes == 96
    expect ValueError:
      discard parseBifrostConfigText("fomkePregenerationMessages = 0")
