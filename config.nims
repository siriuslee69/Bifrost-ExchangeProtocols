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
## `meta` is deliberately NOT on the path: Tyr ships a module of the same
## name, and whichever landed first would win. `src/analysis_pragmas.nim`
## reaches ours by relative path instead.
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
  ## Tyr keeps its Otter-readable pragma definitions in `meta/`. Leaving this
  ## path out is what made a plain `nim c` fail with
  ## "cannot open file: metaPragmas".
  addPathIfExists(joinPath(tyrRoot, "meta"))
  addPathIfExists(joinPath(tyrRoot, "tools", "meta"))

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
proc useLocalNimblePaths(): bool =
  const path: string = "nimble.paths"
  if not withDir(thisDir(), system.fileExists(path)):
    return false
  result = true
when useLocalNimblePaths():
  include "nimble.paths"
# end Nimble config
