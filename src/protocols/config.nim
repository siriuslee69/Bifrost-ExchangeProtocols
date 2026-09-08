## -------------------------------------------------------------------------
## Bifrost Config <- transport defaults, immutable AME layout, and initial tier
## -------------------------------------------------------------------------

import std/[os, strutils]

import ./ame/types
import ./ame/level1/algorithms
import ./ame/level1/exchange_paths
import ./ame/level1/suites
import ./fomke/types
import bifrostPragmas

type
  BifrostConfig* {.role: configurator.} = object
    maxTcpFrameBytes*: uint32
    maxDacFrameBytes*: int
    defaultAmeInboxCapacity*: int
    defaultTimeoutMs*: int
    peerTrustRequired*: bool
    fomkePregeneration*: bool
    fomkePregenerationMessages*: int
    ameLayout*: AmeSuiteLayout
    ameInitialTier*: AmeMaskTier

var
  bifrostRuntimeConfig*: BifrostConfig

proc defaultBifrostConfig*(): BifrostConfig {.role: configurator.} =
  ## Build safe runtime defaults with an explicit hybrid KEM path. The slots
  ## come from the families this build carries, so the defaults are always
  ## runnable; see `defaultAmeKemSlots`.
  result.maxTcpFrameBytes = uint32(defaultAmeMaxFrameBytes)
  result.maxDacFrameBytes = defaultAmeMaxFrameBytes
  result.defaultAmeInboxCapacity = defaultAmeInboxCapacity
  result.defaultTimeoutMs = 4000
  result.peerTrustRequired = true
  result.fomkePregeneration = false
  result.fomkePregenerationMessages = fomkeDefaultPreparedMessages
  result.ameLayout = defaultAmeLayout(initAmeKemAlgorithms(
    defaultAmeKemSlots()))
  result.ameInitialTier = fullAmeMaskTier(result.ameLayout)

proc fomkePregenerationEnabled*(c: BifrostConfig): bool {.role: parser.} =
  ## c: runtime policy for preparing future message keys ahead of time.
  ## Off by default: a filled cache holds the keys for messages not yet sent,
  ## so a machine seized while it is full gives those up.
  ## Turning it off costs latency and buys forward secrecy for messages that
  ## have not been sent yet -- see `prepareFomkeSendCache`.
  result = c.fomkePregeneration

proc hexNibble(c: char): uint8 {.role: parser.} =
  ## c: one hexadecimal character.
  if c >= '0' and c <= '9':
    return uint8(ord(c) - ord('0'))
  if c >= 'a' and c <= 'f':
    return uint8(ord(c) - ord('a') + 10)
  if c >= 'A' and c <= 'F':
    return uint8(ord(c) - ord('A') + 10)
  raise newException(ValueError, "Bifrost config contains invalid hexadecimal data")

proc decodeConfigHex(s: string): seq[uint8] {.role: parser.} =
  ## s: even-length canonical suite hexadecimal text.
  var
    clean: string = s.strip(chars = {' ', '\t', '"', '\''})
    i: int = 0
  if clean.len == 0 or (clean.len and 1) != 0:
    raise newException(ValueError, "Bifrost AME hex value length is invalid")
  result = newSeq[uint8](clean.len div 2)
  while i < result.len:
    result[i] = (hexNibble(clean[i * 2]) shl 4) or hexNibble(clean[i * 2 + 1])
    i = i + 1

proc encodeConfigHex*(A: openArray[uint8]): string {.role: helper.} =
  ## A: bytes rendered as lowercase hexadecimal text.
  const digits = "0123456789abcdef"
  var i: int = 0
  result = newString(A.len * 2)
  while i < A.len:
    result[i * 2] = digits[int(A[i] shr 4)]
    result[i * 2 + 1] = digits[int(A[i] and 0x0f'u8)]
    i = i + 1

proc sanitizeBifrostConfig*(c: BifrostConfig): BifrostConfig {.role: parser.} =
  ## c: parsed configuration validated before use.
  result = c
  if c.maxTcpFrameBytes == 0'u32 or
      c.maxTcpFrameBytes > uint32(defaultAmeMaxFrameBytes):
    raise newException(ValueError, "Bifrost maxTcpFrameBytes is invalid")
  if c.maxDacFrameBytes <= 0 or c.maxDacFrameBytes > defaultAmeMaxFrameBytes:
    raise newException(ValueError, "Bifrost maxDacFrameBytes is invalid")
  if c.defaultAmeInboxCapacity <= 0 or c.defaultTimeoutMs <= 0:
    raise newException(ValueError, "Bifrost AME runtime defaults are invalid")
  if c.fomkePregenerationMessages <= 0 or
      c.fomkePregenerationMessages > fomkeMaxPreparedMessages:
    raise newException(ValueError,
      "Bifrost FOMKE pregeneration message count is invalid")
  discard encodeAmeSuiteLayout(c.ameLayout)
  validateAmeTier(c.ameLayout, c.ameInitialTier)

proc applyBifrostConfig*(c: BifrostConfig) {.role: actor.} =
  ## c: caller-selected defaults validated before becoming process state.
  bifrostRuntimeConfig = sanitizeBifrostConfig(c)

proc currentBifrostConfig*(): BifrostConfig {.role: configurator.} =
  ## Return the active process defaults, initializing them on first use.
  if bifrostRuntimeConfig.maxTcpFrameBytes == 0'u32:
    bifrostRuntimeConfig = defaultBifrostConfig()
  result = bifrostRuntimeConfig

proc parseBool(v: string): bool {.role: parser.} =
  ## v: simple TOML boolean text.
  var clean: string = v.strip().toLowerAscii()
  if clean == "true":
    return true
  if clean == "false":
    return false
  raise newException(ValueError, "Bifrost config bool is invalid")

proc parseBifrostConfigText*(text: string,
    base: BifrostConfig = defaultBifrostConfig()): BifrostConfig {.role: parser.} =
  ## text/base: simple key-value config text and starting defaults.
  var
    line: string = ""
    parts: seq[string] = @[]
    key: string = ""
    value: string = ""
  result = base
  for raw in text.splitLines:
    line = raw.split('#', maxsplit = 1)[0].strip()
    if line.len == 0 or line[0] == '[':
      continue
    parts = line.split('=', maxsplit = 1)
    if parts.len != 2:
      raise newException(ValueError, "Bifrost config line must be key = value")
    key = parts[0].strip().toLowerAscii()
    value = parts[1].strip()
    case key
    of "maxtcpframebytes": result.maxTcpFrameBytes = uint32(parseUInt(value))
    of "maxdacframebytes": result.maxDacFrameBytes = parseInt(value)
    of "defaultameinboxcapacity": result.defaultAmeInboxCapacity = parseInt(value)
    of "defaulttimeoutms": result.defaultTimeoutMs = parseInt(value)
    of "peertrustrequired": result.peerTrustRequired = parseBool(value)
    of "fomkepregeneration": result.fomkePregeneration = parseBool(value)
    of "fomkepregenerationmessages":
      result.fomkePregenerationMessages = parseInt(value)
    of "amelayouthex":
      result.ameLayout = decodeAmeSuiteLayout(decodeConfigHex(value))
    of "ameinitialtierhex":
      result.ameInitialTier = decodeAmeMaskTier(result.ameLayout,
        decodeConfigHex(value))
    else: raise newException(ValueError, "unknown Bifrost config key: " & key)
  result = sanitizeBifrostConfig(result)

proc loadBifrostConfigFile*(path: string = "config.toml"): BifrostConfig {.
    role: orchestrator.} =
  ## path: configuration file to read and validate.
  if not fileExists(path):
    raise newException(IOError, "Bifrost config file is missing: " & path)
  result = parseBifrostConfigText(readFile(path))
