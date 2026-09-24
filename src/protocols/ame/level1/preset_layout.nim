## -------------------------------------------------------------------------
## Preset Layout <- which algorithms the build's preset pins, read while
##                  compiling, so the build can never lack one of them
## -------------------------------------------------------------------------
##
## A preset (configs/*.toml) may pin the AME layout -- the ordered list of
## algorithms a session offers -- in its `[runtime.ame]` table:
##
##   [runtime.ame]
##   ameLayoutHex = "0202..."      "" = derive it from what is compiled
##
## A pinned layout naming an algorithm the build left out could never run.
## So the families named here are ADDED to what `-d:bifrostKems`,
## `-d:bifrostSigs` and `-d:bifrostSymmetric` compile, and the compiler says
## so with a warning (an error under -d:bifrostStrictConfig):
##
##   preset layout            flags                      compiled
##   -----------------------  -------------------------  -----------------
##   LightSaber, X25519       bifrostKems=saber,x25519   saber, x25519
##   Kyber768, X25519         bifrostKems=saber,x25519   saber, x25519,
##                                                       kyber  <- WARNING
##
## Added families use the build's own -d:tyrSimd setting like everything
## else: SIMD is chosen once, for the whole program.
##
## Which files: the ones Nimble-Tasks/src/preset.nims applied, handed over
## as -d:presetFiles=a.toml;b.toml. The LAST file that sets a non-empty
## ameLayoutHex wins, the same rule the preset reader uses.
##
## This module decodes the layout bytes itself instead of calling
## `decodeAmeSuiteLayout`: that decoder lives above the "what is built"
## sets this module feeds, so using it here would go in a circle. The byte
## format is the same, and test_ame_preset_layout checks both agree.
##
##   byte 0      version (2)
##   byte 1      n KEMs, then n KEM ids, one byte each
##   then five times (cipher, MAC, hash, signature, KDF):
##               n, then n ids packed two per byte, high nibble first

import std/strutils

import ../types
import ./kems/types as kem_types
import ./sigs/types as sig_types
import ./symmetric/types as sym_types
import runePragmas

const
  presetFiles* {.strdefine.}: string = ""
    ## Set by Nimble-Tasks/src/preset.nims: the preset files this build used.

proc presetSectionValue(text, section, key: string): string {.role: parser.} =
  ## text/section/key: one `key = "value"` inside `[section]` of a TOML
  ## file -> value without quotes, or "" when absent.
  var
    current: string = ""
    line: string = ""
    parts: seq[string] = @[]
  for raw in text.splitLines():
    line = raw.split('#', maxsplit = 1)[0].strip()
    if line.startsWith("[") and line.endsWith("]"):
      current = line[1 .. ^2].strip()
    parts = line.split('=', maxsplit = 1)
    if current == section and parts.len == 2 and parts[0].strip() == key:
      result = parts[1].strip().strip(chars = {'"'})

proc presetLayoutPick(): tuple[hex, source: string] {.role: dataFetcher.} =
  ## The last non-empty pinned layout among the preset files, and its file.
  var
    value: string = ""
  for path in presetFiles.split(';'):
    if path.len == 0:
      continue
    value = presetSectionValue(readFile(path), "runtime.ame",
      "ameLayoutHex")
    if value.len > 0:
      result = (value, path)

proc presetHexBytes(s: string): seq[uint8] {.role: parser.} =
  ## s: lowercase or uppercase hex text -> bytes.
  var
    i: int = 0
  if (s.len and 1) != 0:
    raise newException(ValueError, "preset ameLayoutHex has an odd length")
  while i < s.len:
    result.add(uint8(parseHexInt(s[i .. i + 1])))
    i = i + 2

proc presetNibbleIds(A: seq[uint8], cursor: var int): seq[uint8] {.
    role: parser.} =
  ## A/cursor: one packed group (n, then ids two per byte) -> its ids.
  var
    n: int = int(A[cursor])
    i: int = 0
    packed: uint8 = 0'u8
  cursor = cursor + 1
  while i < n:
    packed = A[cursor + (i div 2)]
    result.add(if (i and 1) == 0: packed shr 4 else: packed and 0x0f'u8)
    i = i + 1
  cursor = cursor + (n + 1) div 2

type
  PresetLayoutIds = object
    ## The raw ids of one pinned layout, per algorithm group.
    kems, ciphers, macs, hashes, sigs, kdfs: seq[uint8]

proc presetLayoutIds(hex: string): PresetLayoutIds {.role: parser.} =
  ## hex: a pinned layout -> its ids. Empty hex -> nothing pinned.
  var
    A: seq[uint8] = @[]
    cursor: int = 2
  if hex.len == 0:
    return
  A = presetHexBytes(hex)
  if A.len < 2 or A[0] != 2'u8:
    raise newException(ValueError, "preset ameLayoutHex is not a version 2 layout")
  result.kems = A[2 ..< 2 + int(A[1])]
  cursor = 2 + int(A[1])
  result.ciphers = presetNibbleIds(A, cursor)
  result.macs = presetNibbleIds(A, cursor)
  result.hashes = presetNibbleIds(A, cursor)
  result.sigs = presetNibbleIds(A, cursor)
  result.kdfs = presetNibbleIds(A, cursor)

template presetEnum(T: typedesc, id: uint8): untyped {.role: parser.} =
  ## T/id: one id -> its enum value; an unknown id stops the build.
  if id < uint8(ord(low(T))) or id > uint8(ord(high(T))):
    raise newException(ValueError, "preset ameLayoutHex names unknown " &
      $T & " id " & $id)
  T(id)

proc presetKemSlotsOf(I: PresetLayoutIds): seq[AmeKemAlgorithm] {.role: parser.} =
  ## I: layout ids -> its KEM slots.
  for id in I.kems:
    result.add(presetEnum(AmeKemAlgorithm, id))

proc presetSigSlotsOf(I: PresetLayoutIds): set[AmeSignatureAlgorithm] {.
    role: parser.} =
  ## I: layout ids -> the signature slots the pinned layout names.
  for id in I.sigs:
    result.incl(presetEnum(AmeSignatureAlgorithm, id))

proc presetSymOf(I: PresetLayoutIds): set[AmeSymPrimitive] {.role: parser.} =
  ## I: layout ids -> every symmetric primitive its cipher, MAC, hash and
  ## KDF slots need.
  for id in I.ciphers:
    result.incl(ameCipherPrimitive(presetEnum(AmeCipherAlgorithm, id)))
  for id in I.macs:
    result.incl(ameMacPrimitive(presetEnum(AmeMacAlgorithm, id)))
  for id in I.hashes:
    result.incl(ameHashPrimitive(presetEnum(AmeHashAlgorithm, id)))
  for id in I.kdfs:
    result.incl(ameKdfPrimitive(presetEnum(AmeKdfAlgorithm, id)))

proc presetKemSetOf(A: seq[AmeKemAlgorithm]): set[AmeKemAlgorithm] {.
    role: parser.} =
  ## A: KEM slots in layout order -> the same slots as a set.
  for a in A:
    result.incl(a)

proc presetKemFamiliesOf(A: seq[AmeKemAlgorithm]): set[AmeKemFamily] {.
    role: parser.} =
  ## A: KEM slots -> their families.
  for a in A:
    result.incl(ameKemFamily(a))

const
  presetLayout: tuple[hex, source: string] = presetLayoutPick()
  presetIds: PresetLayoutIds = presetLayoutIds(presetLayout.hex)
  presetLayoutSource* = presetLayout.source
    ## The preset file whose layout is pinned ("" when none is).
  presetKemSlots* = presetKemSlotsOf(presetIds)
    ## The KEM slots the pinned layout names, in order.
  presetKemSlotSet* = presetKemSetOf(presetKemSlots)
    ## The same slots as a set, for the build-set union.
  presetKemFamilies* = presetKemFamiliesOf(presetKemSlots)
  presetSigSlotSet* = presetSigSlotsOf(presetIds)
  presetSymPrimitives* = presetSymOf(presetIds)

proc presetAddedMessage*(flag, added: string): string {.compileTime,
    role: helper.} =
  ## flag/added: the -d: flag that left families out, and their names ->
  ## the one warning (or, under -d:bifrostStrictConfig, error) about them.
  result = "the layout pinned in " & presetLayoutSource & " uses " & added &
    ", which -d:" & flag & " left out. "
  when defined(bifrostStrictConfig):
    result.add("-d:bifrostStrictConfig forbids adding it: add it to " & flag &
      " in the preset, or remove it from ameLayoutHex.")
  else:
    result.add("Compiling it anyway (with the same -d:tyrSimd as the rest), " &
      "so the layout can run. To silence this, add it to " & flag &
      " in the preset, or remove it from ameLayoutHex. " &
      "-d:bifrostStrictConfig turns this into an error.")
