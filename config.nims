import std/[os, strutils]

let repoRoot = thisDir()
var tyrRoot = ""
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
  addPathIfExists(joinPath(tyrRoot, ".iron", "meta"))
  if fileExists(joinPath(tyrRoot, "src", "protocols", "custom_crypto",
      "xchacha20_batch.nim")):
    switch("define", "bifrostTyrXChaChaBatch")

if dirExists(joinPath(repoRoot, "submodules", "SIMD-Nexus", "src")):
  addPathIfExists(joinPath(repoRoot, "submodules", "SIMD-Nexus", "src"))
elif dirExists(joinPath(repoRoot, "submodules", "Tyr-Crypto", "submodules", "simd_nexus", "src")):
  addPathIfExists(joinPath(repoRoot, "submodules", "Tyr-Crypto", "submodules", "simd_nexus", "src"))
elif dirExists(joinPath(repoRoot, "submodules", "Tyr-Crypto", "simd_nexus", "src")):
  addPathIfExists(joinPath(repoRoot, "submodules", "Tyr-Crypto", "simd_nexus", "src"))
elif dirExists(joinPath(repoRoot, "..", "SIMD-Nexus", "src")):
  addPathIfExists(joinPath(repoRoot, "..", "SIMD-Nexus", "src"))

if dirExists(joinPath(repoRoot, "submodules", "Eir-CompressionAndECC", "src")):
  addPathIfExists(joinPath(repoRoot, "submodules", "Eir-CompressionAndECC"))
  addPathIfExists(joinPath(repoRoot, "submodules", "Eir-CompressionAndECC", "src"))
elif dirExists(joinPath(repoRoot, "..", "Eir-CompressionAndECC", "src")):
  addPathIfExists(joinPath(repoRoot, "..", "Eir-CompressionAndECC"))
  addPathIfExists(joinPath(repoRoot, "..", "Eir-CompressionAndECC", "src"))

if dirExists(joinPath(repoRoot, "submodules", "Fylgia-Utils", "src")):
  addPathIfExists(joinPath(repoRoot, "submodules", "Fylgia-Utils"))
  addPathIfExists(joinPath(repoRoot, "submodules", "Fylgia-Utils", "src"))
elif dirExists(joinPath(repoRoot, "..", "Fylgia-Utils", "src")):
  addPathIfExists(joinPath(repoRoot, "..", "Fylgia-Utils"))
  addPathIfExists(joinPath(repoRoot, "..", "Fylgia-Utils", "src"))

let nimblePkgs2 = getHomeDir() / ".nimble" / "pkgs2"
if dirExists(nimblePkgs2):
  for kind, path in walkDir(nimblePkgs2):
    if kind == pcDir and path.extractFilename().startsWith("nimsimd-"):
      switch("path", path)
      break
# begin Nimble config (version 2)
proc useLocalNimblePaths(): bool =
  let path = "nimble.paths"
  if not withDir(thisDir(), system.fileExists(path)):
    return false
  result = true
when useLocalNimblePaths():
  include "nimble.paths"
# end Nimble config
