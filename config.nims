import std/[os, strutils]

var
  repoRoot: string = thisDir()
  tyrRoot: string = ""
# Let direct `nim` calls use Nim's default per-target cache behavior.
# Repo tasks set their own isolated local caches in the nimble file.

proc addPathIfExists(pathArg: string) =
  if dirExists(pathArg):
    switch("path", pathArg.replace('\\', '/'))

addPathIfExists(joinPath(repoRoot, "src"))
if dirExists(joinPath(repoRoot, "..", "Otter-RepoEvaluation", "src")):
  addPathIfExists(joinPath(repoRoot, "..", "Otter-RepoEvaluation", "src"))
else:
  addPathIfExists(joinPath(repoRoot, "submodules", "Otter-RepoEvaluation", "src"))
## Prefer a sibling Tyr checkout during cross-repository development. This
## keeps Bifrost on the same implementation revision as Tyr (including the
## pure Ed25519 path used by the lower AME tiers); the pinned submodule remains
## the fallback for standalone clones.
when not defined(bifrostPinnedTyr):
  if dirExists(joinPath(repoRoot, "..", "Tyr-Crypto", "src")):
    tyrRoot = joinPath(repoRoot, "..", "Tyr-Crypto")
if tyrRoot.len == 0 and
    dirExists(joinPath(repoRoot, "submodules", "Tyr-Crypto", "src")):
  tyrRoot = joinPath(repoRoot, "submodules", "Tyr-Crypto")
if tyrRoot.len > 0:
  addPathIfExists(tyrRoot)
  addPathIfExists(joinPath(tyrRoot, "src"))

## Sibling checkouts win over the pinned submodules for the same reason Tyr
## does above: Bifrost, Eir, and SIMD-Nexus move together, and the DAC repair
## path calls Eir's Reed-Solomon, which calls SIMD-Nexus' GF(256) tables. A
## stale pin would compile against a codec that no longer matches.
if dirExists(joinPath(repoRoot, "..", "SIMD-Nexus", "src")):
  addPathIfExists(joinPath(repoRoot, "..", "SIMD-Nexus", "src"))
elif dirExists(joinPath(repoRoot, "submodules", "SIMD-Nexus", "src")):
  addPathIfExists(joinPath(repoRoot, "submodules", "SIMD-Nexus", "src"))
elif dirExists(joinPath(repoRoot, "submodules", "Tyr-Crypto", "submodules", "simd_nexus", "src")):
  addPathIfExists(joinPath(repoRoot, "submodules", "Tyr-Crypto", "submodules", "simd_nexus", "src"))
elif dirExists(joinPath(repoRoot, "submodules", "Tyr-Crypto", "simd_nexus", "src")):
  addPathIfExists(joinPath(repoRoot, "submodules", "Tyr-Crypto", "simd_nexus", "src"))

if dirExists(joinPath(repoRoot, "..", "Eir-CompressionAndECC", "src")):
  addPathIfExists(joinPath(repoRoot, "..", "Eir-CompressionAndECC"))
  addPathIfExists(joinPath(repoRoot, "..", "Eir-CompressionAndECC", "src"))
elif dirExists(joinPath(repoRoot, "submodules", "Eir-CompressionAndECC", "src")):
  addPathIfExists(joinPath(repoRoot, "submodules", "Eir-CompressionAndECC"))
  addPathIfExists(joinPath(repoRoot, "submodules", "Eir-CompressionAndECC", "src"))

if dirExists(joinPath(repoRoot, "submodules", "Fylgia-Utils", "src")):
  addPathIfExists(joinPath(repoRoot, "submodules", "Fylgia-Utils"))
  addPathIfExists(joinPath(repoRoot, "submodules", "Fylgia-Utils", "src"))
elif dirExists(joinPath(repoRoot, "..", "Fylgia-Utils", "src")):
  addPathIfExists(joinPath(repoRoot, "..", "Fylgia-Utils"))
  addPathIfExists(joinPath(repoRoot, "..", "Fylgia-Utils", "src"))

var nimblePkgs2: string = getHomeDir() / ".nimble" / "pkgs2"
if dirExists(nimblePkgs2):
  for kind, path in walkDir(nimblePkgs2):
    if kind == pcDir and path.extractFilename().startsWith("nimsimd-"):
      switch("path", path)
      break
# begin Nimble config (version 2)
when withDir(thisDir(), system.fileExists("nimble.paths")):
  include "nimble.paths"
# end Nimble config

## Shared pragma module: one file for the whole workspace, so there is no
## per-repository copy to drift or to collide on the Nim path. A sibling
## checkout wins over the pinned submodule for the same reason Tyr does
## above -- during cross-repository work the two move together. Exactly one
## of the two is put on the path, because Nim takes the LAST matching
## `--path` entry and adding both would silently reverse that preference.
if dirExists(thisDir() & "/../Rune-Pragmas/meta"):
  switch("path", thisDir() & "/../Rune-Pragmas/meta")
elif dirExists(thisDir() & "/submodules/Rune-Pragmas/meta"):
  switch("path", thisDir() & "/submodules/Rune-Pragmas/meta")
else:
  echo "config.nims: cannot find runePragmas. Run `git submodule update " &
    "--init` (one level, NOT --recursive), or clone Rune-Pragmas next to " &
    "this repository."

## Build presets: configs/default.toml always, plus configs/<name>.toml when
## the build says -d:preset=<name>. One file per kind of device holds every
## switch below (families, modes, SIMD, compiler options). The reader is
## shared by every repo: Nimble-Tasks/src/preset.nims.
when fileExists(thisDir() & "/../Nimble-Tasks/src/preset.nims"):
  include "../Nimble-Tasks/src/preset.nims"
elif fileExists(thisDir() & "/submodules/Nimble-Tasks/src/preset.nims"):
  include "submodules/Nimble-Tasks/src/preset.nims"
else:
  proc presetValue(section, key, fallback: string): string = fallback
  proc applyPreset() = echo "config.nims: Nimble-Tasks/src/preset.nims " &
    "not found; configs/*.toml are ignored. Update the submodule."
applyPreset()

## Tyr's Saber arrays are sized for the largest Saber slot the build may
## run (-d:saberMaxRank). That follows from the chosen slots, so it is
## worked out here rather than set by hand:
##
##   -d:bifrostKems=...          pinned layout      -> saberMaxRank
##   lightsaber,x25519           (none)                2   (2 KB matrices)
##   saber3                      LightSaber            3
##   saber  (the whole family)   anything              4   (8 KB matrices)
##   ""     (every slot)         anything              4
##
## An explicit -d:saberMaxRank on the command line or in a preset wins.
proc bifrostWordsRank(words: string): int =
  ## words: the -d:bifrostKems value -> largest Saber rank it selects.
  if words.strip().len == 0:
    return 4
  for w in words.split(','):
    case w.strip().toLowerAscii()
    of "saber", "firesaber": result = max(result, 4)
    of "saber3": result = max(result, 3)
    of "lightsaber": result = max(result, 2)
    else: discard

proc bifrostLayoutRank(hex: string): int =
  ## hex: a pinned ameLayoutHex -> largest Saber rank among its KEM ids
  ## (byte 1 = how many, then one id each: 0x01 FireSaber, 0x06 Saber,
  ## 0x0B LightSaber).
  var
    i: int = 0
  if hex.len < 4:
    return 0
  while i < parseHexInt(hex[2 .. 3]) and hex.len >= 6 + 2 * i:
    case parseHexInt(hex[4 + 2 * i .. 5 + 2 * i])
    of 0x01: result = max(result, 4)
    of 0x06: result = max(result, 3)
    of 0x0B: result = max(result, 2)
    else: discard
    i = i + 1

proc bifrostKemsWords(): string =
  ## The -d:bifrostKems value in force: the command line, else the preset.
  var
    i: int = 1
  result = presetValue("define", "bifrostKems", "")
  while i <= paramCount():
    if paramStr(i).startsWith("-d:bifrostKems=") or
        paramStr(i).startsWith("--define:bifrostKems="):
      result = paramStr(i).split('=', maxsplit = 1)[1]
    i = i + 1

proc applySaberRank() =
  ## Sets -d:saberMaxRank to what the chosen slots need, unless given.
  var
    rank: int = max(bifrostWordsRank(bifrostKemsWords()),
      bifrostLayoutRank(presetValue("runtime.ame", "ameLayoutHex", "")))
  if rank in 2 .. 3 and presetValue("define", "saberMaxRank", "").len == 0:
    switch("define", "saberMaxRank=" & $rank)

applySaberRank()

## CPU vector code (SIMD) for Tyr and SIMD-Nexus: one flag, read by Tyr's own
## `tyr_simd.nims`, so it means the same here as inside Tyr:
##
##   nim c -d:tyrSimd=avx2 app.nim      AVX2 code + its C flags
##   nim c app.nim                      scalar (Bifrost's default: smallest,
##                                      runs on every CPU)
##
## The table of accepted values sits at the top of that file. The same
## sibling-first order as the Tyr path above applies.
when not defined(bifrostPinnedTyr) and
    fileExists(thisDir() & "/../Tyr-Crypto/tyr_simd.nims"):
  include "../Tyr-Crypto/tyr_simd.nims"
  applyTyrSimd(presetValue("define", "tyrSimd", "scalar"))
elif fileExists(thisDir() & "/submodules/Tyr-Crypto/tyr_simd.nims"):
  include "submodules/Tyr-Crypto/tyr_simd.nims"
  applyTyrSimd(presetValue("define", "tyrSimd", "scalar"))
else:
  echo "config.nims: Tyr's tyr_simd.nims was not found; -d:tyrSimd is " &
    "ignored. Update the Tyr-Crypto submodule."
