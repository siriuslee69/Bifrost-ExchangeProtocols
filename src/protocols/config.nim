## -------------------------------------------------------------------------
## Bifrost Config <- transport defaults, immutable AME layout, and initial tier
## -------------------------------------------------------------------------

import std/[os, strutils]

import ./ame/types
import ./ame/level1/algorithms
import ./ame/level1/exchange_paths
import ./ame/level1/suites
import ./ame/level1/preset_layout
import ./fomke/types
import runePragmas

type
  BifrostConfig* {.role: configurator.} = object
    maxTcpFrameBytes*: uint32
    maxDacFrameBytes*: int
    defaultAmeInboxCapacity*: int
    defaultTimeoutMs*: int
    peerTrustRequired*: bool
    fomkePregeneration*: bool
    fomkePregenerationMessages*: int
    fomkeReorderCeiling*: uint32
      ## How many message keys a lane may hold for messages that arrive out
      ## of order (see `fomkeMaxReorderWindow`). Each held key is 32 bytes.
      ## It is also the furthest a message may sit behind and still open.
    ameLayout*: AmeSuiteLayout
    ameInitialTier*: AmeMaskTier
    ameMinPqKems*: int
      ## The fewest post-quantum KEMs (anything but X25519) a selection must
      ## keep switched on -- in a client's hello and in every later change
      ## request, whichever side sends it. 0 (the default) asks for none.
      ## A request below it is answered with a deny, not a switch.
    ameSignedExchanges*: bool
      ## false (default): in-session exchanges are proved with a tag under
      ## the session's own secret (the AM1P way). true: this side signs
      ## every request it sends and denies unsigned ones -- only for
      ## sessions that hold signature keys (AM1A, AM1S, AM1P+S).

var
  bifrostRuntimeConfig*: BifrostConfig

proc defaultBifrostConfig*(): BifrostConfig {.role: configurator, gcsafe.}
  ## Declared here, defined at the bottom: it needs the preset reader.

proc codeBifrostConfig(): BifrostConfig {.role: configurator.} =
  ## The values written in code, before any preset. The slots come from the
  ## families this build carries, so they are always runnable; see
  ## `defaultAmeKemSlots`. `defaultBifrostConfig` lays the preset over this.
  result.maxTcpFrameBytes = uint32(defaultAmeMaxFrameBytes)
  result.maxDacFrameBytes = defaultAmeMaxFrameBytes
  result.defaultAmeInboxCapacity = defaultAmeInboxCapacity
  result.defaultTimeoutMs = 4000
  result.peerTrustRequired = true
  result.fomkePregeneration = false
  result.fomkePregenerationMessages = fomkeDefaultPreparedMessages
  result.fomkeReorderCeiling = fomkeDefaultReorderCeiling
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
  if c.fomkeReorderCeiling < fomkeMinReorderWindow or
      c.fomkeReorderCeiling > fomkeMaxReorderWindow:
    raise newException(ValueError, "Bifrost FOMKE reorder ceiling is invalid")
  if c.ameMinPqKems < 0 or c.ameMinPqKems > ameMaxAlgorithmSlots:
    raise newException(ValueError, "Bifrost ameMinPqKems must be in 0..8")
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

const
  bifrostRuntimeSections: array[6, string] = ["", "runtime", "runtime.fomke",
    "runtime.ame", "fomke", "ame"]
    ## Sections whose keys are runtime settings. A preset file also holds
    ## [nim], [define], [passC] ... for the build; those are skipped here.

proc configSectionOf(line, current: string): string {.role: parser.} =
  ## line/current: a `[section]` line -> its name; any other line keeps
  ## the current section.
  result = current
  if line.len > 1 and line[0] == '[' and line[^1] == ']':
    result = line[1 .. ^2].strip()

proc applyConfigKey(c: var BifrostConfig, key, value: string) {.
    role: truthBuilder.} =
  ## c/key/value: one runtime setting written into c. An empty layout or
  ## tier keeps what c already has ("derive it from the build"); a new
  ## layout starts with every slot switched on until a tier says otherwise.
  var
    clean: string = value.strip(chars = {' ', '\t', '"', '\''})
  if key in ["amelayouthex", "ameinitialtierhex"] and clean.len == 0:
    return
  case key
  of "maxtcpframebytes": c.maxTcpFrameBytes = uint32(parseUInt(value))
  of "maxdacframebytes": c.maxDacFrameBytes = parseInt(value)
  of "defaultameinboxcapacity": c.defaultAmeInboxCapacity = parseInt(value)
  of "defaulttimeoutms": c.defaultTimeoutMs = parseInt(value)
  of "peertrustrequired": c.peerTrustRequired = parseBool(value)
  of "fomkepregeneration": c.fomkePregeneration = parseBool(value)
  of "fomkepregenerationmessages":
    c.fomkePregenerationMessages = parseInt(value)
  of "fomkereorderceiling":
    c.fomkeReorderCeiling = uint32(parseUInt(value))
  of "amelayouthex":
    c.ameLayout = decodeAmeSuiteLayout(decodeConfigHex(value))
    c.ameInitialTier = fullAmeMaskTier(c.ameLayout)
  of "ameinitialtierhex":
    c.ameInitialTier = decodeAmeMaskTier(c.ameLayout,
      decodeConfigHex(value))
  of "ameminpqkems": c.ameMinPqKems = parseInt(value)
  of "amesignedexchanges": c.ameSignedExchanges = parseBool(value)
  else: raise newException(ValueError, "unknown Bifrost config key: " & key)

proc parseBifrostConfigText*(text: string,
    base: BifrostConfig = defaultBifrostConfig()): BifrostConfig {.role: parser.} =
  ## text/base: config text and the values it starts from. Reads a plain
  ## runtime file (top-level keys, [fomke], [ame]) and a preset file
  ## ([runtime], [runtime.fomke], [runtime.ame]) alike; every other section
  ## of a preset ([nim], [define], ...) belongs to the build and is skipped.
  var
    line: string = ""
    section: string = ""
    parts: seq[string] = @[]
  result = base
  for raw in text.splitLines:
    line = raw.split('#', maxsplit = 1)[0].strip()
    section = configSectionOf(line, section)
    if line.len == 0 or line[0] == '[' or section notin bifrostRuntimeSections:
      continue
    parts = line.split('=', maxsplit = 1)
    if parts.len != 2:
      raise newException(ValueError, "Bifrost config line must be key = value")
    applyConfigKey(result, parts[0].strip().toLowerAscii(), parts[1].strip())
  result = sanitizeBifrostConfig(result)

proc readPresetTexts(): seq[string] {.compileTime, role: dataFetcher.} =
  ## The preset files this build used (base first), read while compiling.
  for path in presetFiles.split(';'):
    if path.len > 0:
      result.add(readFile(path))

const
  presetBifrostConfig: BifrostConfig = block:
    ## The runtime values of the build's presets, laid over the code
    ## defaults while compiling. The program carries the result, not the
    ## TOML text and not the parser.
    var
      c: BifrostConfig = codeBifrostConfig()
    for t in readPresetTexts():
      c = parseBifrostConfigText(t, c)
    c

proc defaultBifrostConfig*(): BifrostConfig {.role: configurator, gcsafe.} =
  ## The process defaults: code values, then configs/default.toml, then the
  ## preset named by -d:preset (see configs/ and preset_layout.nim).
  result = presetBifrostConfig

proc loadBifrostConfigFile*(path: string = "config.toml"): BifrostConfig {.
    role: orchestrator.} =
  ## path: configuration file to read and validate.
  if not fileExists(path):
    raise newException(IOError, "Bifrost config file is missing: " & path)
  result = parseBifrostConfigText(readFile(path))
