## -------------------------------------------------------------------------
## Exact Config Tests <- canonical AME layout and initial-tier roundtrip
## -------------------------------------------------------------------------

import std/unittest

import ../../src/protocols/config
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/fomke/types

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
    check not loaded.fomkePregeneration
    check loaded.fomkePregenerationMessages == 8
    check not fomkePregenerationEnabled(loaded)

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

  test "send-cache policy and size parse independently":
    var
      parsed: BifrostConfig = parseBifrostConfigText("""
        fomkePregeneration = true
        fomkePregenerationMessages = 16
      """)
    check parsed.fomkePregeneration
    check fomkePregenerationEnabled(parsed)
    check parsed.fomkePregenerationMessages == 16
    expect ValueError:
      discard parseBifrostConfigText("fomkePregenerationMessages = 0")
