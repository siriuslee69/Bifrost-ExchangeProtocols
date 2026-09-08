## -------------------------------------------------------------------------
## Exact Config Tests <- canonical AME layout and initial-tier roundtrip
## -------------------------------------------------------------------------

import std/unittest
import std/strutils

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

suite "NixOS module output is loadable":
  ## The module generates TOML; the parser refuses unknown keys. Nothing tied
  ## the two together, so the module's own documented example named
  ## `defaultAecInboxCapacity` -- a key that would have thrown on load.
  # {.testKind: tkRegression.}
  test "every key the module documents is a key the parser accepts":
    var
      exampleKeys: seq[string] = @[]
      moduleText: string = readFile("nix/module.nix")
      checkText: string = readFile("nix/module-check.nix")
      parsed: BifrostConfig
    ## Exactly the settings block `nix/module.nix` shows as its example.
    parsed = parseBifrostConfigText("""
maxTcpFrameBytes = 16777216
maxDacFrameBytes = 16777216
defaultAmeInboxCapacity = 64
defaultTimeoutMs = 4000
peerTrustRequired = true
""")
    check parsed.defaultAmeInboxCapacity == 64
    check parsed.defaultTimeoutMs == 4000
    check parsed.peerTrustRequired
    ## And the settings the module check itself generates.
    parsed = parseBifrostConfigText("""
maxTcpFrameBytes = 16777216
defaultTimeoutMs = 4000
defaultAmeInboxCapacity = 64
peerTrustRequired = true

[fomke]
fomkePregeneration = false
""")
    check not parsed.fomkePregeneration
    ## Neither file may name the retired layer's key again.
    exampleKeys = @["defaultAecInboxCapacity", "aec.inboxCapacity"]
    for i in 0 ..< exampleKeys.len:
      check moduleText.find(exampleKeys[i]) < 0
      check checkText.find(exampleKeys[i]) < 0

  # {.testKind: tkEdgeCase.}
  test "a key the parser does not know is refused, not ignored":
    expect ValueError:
      discard parseBifrostConfigText("defaultAecInboxCapacity = 64")
    expect ValueError:
      discard parseBifrostConfigText("timeoutMs = 4000")
