## ------------------------------------------------------------
## Bifrost Task Contract <- build-task output and repo hygiene
## ------------------------------------------------------------

import std/[os, strutils, unittest]

import ../../tools/repo_hygiene
import runePragmas

const
  nimblePath = "bifrost_exchange_protocols.nimble"
  nixPackagePath = "nix/package.nix"
  nixTlsCheckPath = "nix/tls-check.nix"
  legacyProjectTerms = [
    "aegis_" & "firewall",
    "Aeg" & "is " & "Firewall",
    "Aeg" & "is-" & "Firewall",
    "Aeg" & "is",
    "Geist-" & "Server",
    "Geist-" & "Client",
    "Geist-" & "Protocols",
    "Geist-" & "Database-S",
    "upload-" & "key-hex",
    "UPLOAD_" & "KEY_HEX",
    "Ame" & "Socket"
  ]
  repoScanDirs = [
    "src",
    "evaluation",
    "docs",
    "examples"
  ]
  repoScanFiles = [
    "README.md",
    "CONTRIBUTING.md",
    "bifrost_exchange_protocols.nimble",
    "config.nims",
    "config.toml",
    "userconfig.toml.template"
  ]
  repoScanExts = [
    ".nim",
    ".nims",
    ".nimble",
    ".md",
    ".json",
    ".toml",
    ".nix",
    ".yml",
    ".yaml",
    ".kt",
    ".java",
    ".cpp",
    ".h",
    ".ps1",
    ".sh"
  ]
  skippedRepoScanDirs = [
    "/.git/",
    "/build/",
    "/dist/",
    "/.nimble/",
    "/.nimble_cache/",
    "/nimcache/",
    "/submodules/"
  ]

proc shouldScanRepoFile(p: string): bool =
  let lower = p.toLowerAscii()
  for ext in repoScanExts:
    if lower.endsWith(ext):
      return true
  result = false

proc shouldSkipRepoPath(p: string): bool =
  let normalized = "/" & p.replace('\\', '/')
  for skipped in skippedRepoScanDirs:
    if normalized.contains(skipped):
      return true
  result = false

proc countLegacyProjectTermsInRepo(): int {.role: parser.} =
  proc scanFile(path: string; hits: var int) =
    var text: string = ""
    if shouldSkipRepoPath(path) or not shouldScanRepoFile(path):
      return
    try:
      text = readFile(path)
    except OSError:
      return
    for term in legacyProjectTerms:
      if text.contains(term):
        hits.inc

  for base in repoScanDirs:
    if dirExists(base):
      for path in walkDirRec(base):
        scanFile(path, result)
  for path in repoScanFiles:
    if fileExists(path):
      scanFile(path, result)

proc taskContractFixtureDir(name: string): string =
  var
    root: string = getCurrentDir() / "builds" / "task_contract" / name
  if dirExists(root):
    removeDir(root)
  if not dirExists(getCurrentDir() / "builds"):
    createDir(getCurrentDir() / "builds")
  if not dirExists(getCurrentDir() / "builds" / "task_contract"):
    createDir(getCurrentDir() / "builds" / "task_contract")
  createDir(root)
  result = root

suite "Bifrost task contract":
  # {.testKind: tkUnit.}
  test "buildLib writes the shared library under build lib":
    var
      content: string = ""
    content = readFile(nimblePath)
    check content.find("""task buildLib, "Build the bifrost_exchange_protocols module as a library":
  runNim("c", "src/bifrost_exchange_protocols.nim",
    @["--app:lib", "--outdir:build/lib"])""") >= 0
    check content.find("""runNim("c", "src/bifrost_exchange_protocols.nim", @["--app:lib"])""") < 0
    check content.find("""runCommand("git", @["commit", "-m", msg])""") >= 0
    check content.find("""proc shellPath(p: string): string =""") >= 0
    check content.find("""paths.add("--path:" & normalizePath(src))""") >= 0
    check content.find("""proc runCommand(command: string; args: openArray[string]) =""") >= 0
    check content.find("""exec shellCommand(command, args)""") >= 0
    check content.find("""var useHermeticTlsCheck = false""") >= 0
    check content.find("""proc runHermeticTlsCheck() =""") >= 0
    check content.find("""runCommand("nix-build", @["nix/tls-check.nix", "--no-out-link"])""") >= 0
    check content.find("""proc ensureOpenSslBuildEnv(taskName: string) =""") >= 0
    check content.find("""ensureOpenSslBuildEnv("nimble testTls")""") >= 0
    check content.find("""if useHermeticTlsCheck:
    runHermeticTlsCheck()""") >= 0
    check content.find("startProcess") < 0
    check content.find("""normalizePath(cacheDirFor(root, mode, filePath, extraKey))""") >= 0
    check content.find("""args.add(normalizePath(filePath))""") >= 0

  # {.testKind: tkUnit.}
  test "runnable helper tasks keep binaries under build output roots":
    var
      content: string = ""
      examplesDoc: string = ""
    content = readFile(nimblePath)
    examplesDoc = readFile("examples/README.md")
    check content.find("""proc runnableOutputPath(filePath: string): string =""") >= 0
    check content.find("""result = joinPath("build", "tests", binName)""") >= 0
    check content.find("""result = joinPath("build", "examples", binName)""") >= 0
    check content.find("""result = joinPath("build", "tools", binName)""") >= 0
    check content.find("""args.add(defaultOutputArgs(filePath, extraArgs))""") >= 0
    check examplesDoc.find("nimble exampleAmeExactPath") >= 0
    check examplesDoc.find("nim c -r examples/ame_exact_path.nim") < 0
    check examplesDoc.find("Avoid raw `nim c -r examples/...` here.") >= 0

  # {.testKind: tkUnit.}
  test "release hygiene tasks and ignore rules stay wired":
    var
      content: string = ""
      readmeText: string = ""
      ignoreText: string = ""
      toolText: string = ""
    content = readFile(nimblePath)
    readmeText = readFile("README.md")
    ignoreText = readFile(".gitignore")
    toolText = readFile("tools/repo_hygiene.nim")
    check content.find("""task releaseHygiene, "Audit generated and local repo artifacts that should not ship":""") >= 0
    check content.find("""proc runRepoHygiene(extraArgs: openArray[string] = []) =""") >= 0
    check content.find("bifrost_repo_hygiene_tool") >= 0
    check content.find("bifrost_repo_hygiene_nimcache") >= 0
    check content.find("""runRepoHygiene(@["--root=."])""") >= 0
    check content.find("""task cleanGenerated, "Remove generated and local repo artifacts such as build/, nimcache/, and helper binaries":""") >= 0
    check content.find("""runRepoHygiene(@["--root=.", "--clean"])""") >= 0
    check toolText.find("""const
  GeneratedRoots = [""") >= 0
    check toolText.find("""RootGeneratedPrefixes = [""") >= 0
    check toolText.find("""name.startsWith(prefix)""") >= 0
    check toolText.find("""relPath.startsWith("result-")""") >= 0
    check toolText.find("""if isSourceArtifact(p):""") >= 0
    check readmeText.find("`nimble releaseHygiene`") >= 0
    check readmeText.find("`nimble cleanGenerated`") >= 0
    check ignoreText.find("result") >= 0
    check ignoreText.find("result-*") >= 0
    check ignoreText.find("tmp_bifrost") >= 0

  # {.testKind: tkUnit.}
  test "repo hygiene finds root helpers and nested source build trees":
    var
      root: string = ""
      findings: seq[HygieneFinding] = @[]
      sawRootBinary: bool = false
      sawSharedLib: bool = false
      sawTestExe: bool = false
      sawAndroidBuild: bool = false
      i: int = 0
    root = taskContractFixtureDir("repo_hygiene")
    createDir(root / "src")
    createDir(root / "evaluation")
    createDir(root / "evaluation" / "tests")
    createDir(root / "src" / "clients")
    createDir(root / "src" / "clients" / "android")
    createDir(root / "src" / "clients" / "android" / "app")
    createDir(root / "src" / "clients" / "android" / "app" / "build")
    writeFile(root / "bifrost_exchange_protocols_root", "bin")
    writeFile(root / "src" / "libbifrost_exchange_protocols.so", "bin")
    writeFile(root / "evaluation" / "tests" / "test_crypto_suites.exe", "bin")
    writeFile(root / "src" / "clients" / "android" / "app" / "build" / "artifact.bin", "bin")
    findings = repoHygieneFindings(root)
    while i < findings.len:
      case findings[i].relPath
      of "bifrost_exchange_protocols_root":
        sawRootBinary = true
      of "src/libbifrost_exchange_protocols.so":
        sawSharedLib = true
      of "evaluation/tests/test_crypto_suites.exe":
        sawTestExe = true
      of "src/clients/android/app/build":
        sawAndroidBuild = true
      else:
        discard
      i = i + 1
    check sawRootBinary
    check sawSharedLib
    check sawTestExe
    check sawAndroidBuild

  # {.testKind: tkUnit.}
  test "nix package installs the shared library from build lib":
    var
      content: string = ""
    content = readFile(nixPackagePath)
    check content.find("--outdir:build/lib") >= 0
    check content.find("""cp build/lib/libbifrost_exchange_protocols.* "$out/lib/"""") >= 0
    check content.find("""cp src/libbifrost_exchange_protocols.* "$out/lib/"""") < 0

  # {.testKind: tkUnit.}
  test "flake check wires TLS verification through Nix":
    var
      flakeText: string = ""
      tlsCheckText: string = ""
    flakeText = readFile("flake.nix")
    tlsCheckText = readFile(nixTlsCheckPath)
    check flakeText.find("""tls = pkgs.callPackage ./nix/tls-check.nix { };""") >= 0
    check tlsCheckText.find("""pkgs.openssl""") >= 0
    check tlsCheckText.find("""pkgs.pkg-config""") >= 0
    check tlsCheckText.find("""--nimcache:nimcache_tls_transport""") >= 0
    check tlsCheckText.find("""-d:ssl""") >= 0
    check tlsCheckText.find("""evaluation/tests/test_transport_ops.nim""") >= 0

  # {.testKind: tkUnit.}
  test "benchmark harness stays committed and wired":
    var
      content: string = ""
      benchDoc: string = ""
      readmeText: string = ""
      contributingText: string = ""
      testsDoc: string = ""
    content = readFile(nimblePath)
    benchDoc = readFile("docs/benchmarks.md")
    readmeText = readFile("README.md")
    contributingText = readFile("CONTRIBUTING.md")
    testsDoc = readFile("docs/tests.md")
    check content.find("""task benchmarks, "Run the committed protocol benchmark harness":""") >= 0
    check content.find("""runNim("c", "evaluation/benchmarks/bench_protocols.nim", @["-d:release", "-r"])""") >= 0
    check benchDoc.find("does not yet ship a committed Otter benchmark harness") < 0
    check benchDoc.find("evaluation/benchmarks/bench_protocols.nim") >= 0
    check benchDoc.find("nim c -d:release -r evaluation/benchmarks/bench_protocols.nim") < 0
    check benchDoc.find("--out:build/benchmarks/bench_protocols") >= 0
    check readmeText.find("`nimble benchmarks`") >= 0
    check readmeText.find("`--out:build/benchmarks/...`") >= 0
    check contributingText.find("| nimble benchmarks         | release-mode protocol microbench harness    |") >= 0
    check testsDoc.find("| nimble benchmarks         | release-mode protocol microbenchmark harness |") >= 0
    check contributingText.find("| nix-build nix/module-check.nix --no-out-link | NixOS module merge/replace/conflict checks |") >= 0
    check testsDoc.find("`nix-build nix/module-check.nix --no-out-link`") >= 0
    check testsDoc.find("package build plus flake-wired TLS transport/AME TCP check and module contract check") >= 0

# {.testKind: tkUnit.}
test "repo scan has no stale project-name or alias references":
  check countLegacyProjectTermsInRepo() == 0

  # {.testKind: tkUnit.}
  test "release docs describe closed readiness gaps as closed":
    var
      readinessDoc: string = ""
      readmeText: string = ""
      contributingText: string = ""
      testsDoc: string = ""
    readinessDoc = readFile("docs/production_readiness.md")
    readmeText = readFile("README.md")
    contributingText = readFile("CONTRIBUTING.md")
    testsDoc = readFile("docs/tests.md")
    check readinessDoc.find("## What Was Missing") < 0
    check readinessDoc.find("Before this pass, the main production gaps were:") < 0
    check readinessDoc.find("nimble build --verbose") < 0
    check readinessDoc.find("nimble build + buildLib both pass") < 0
    check readinessDoc.find("`nimble testTls` uses host OpenSSL build libraries") >= 0
    check readinessDoc.find("`nix-build nix/module-check.nix --no-out-link`") >= 0
    check readinessDoc.find("checks Nix module rules") >= 0
    check readmeText.find("- `nimble build`\n") < 0
    check readmeText.find("default `nimble build` command is not a supported") >= 0
    check readmeText.find("`nix flake check path:$PWD` validates the package build") >= 0
    check contributingText.find("| nimble build              |") < 0
    check contributingText.find("`nimble build` command is not a supported artifact path here") >= 0
    check contributingText.find("| nimble testTls            | TLS transport/AME TCP checks; uses host OpenSSL or Nix fallback |") >= 0
    check contributingText.find("| nix flake check path:$PWD | package + TLS + module checks in Nix        |") >= 0
    check testsDoc.find("nimble testTls") >= 0
    check testsDoc.find("falls back to") >= 0
    check testsDoc.find("`nix-build nix/tls-check.nix --no-out-link`") >= 0

suite "the pragma module is the shared one":
  ## Pragmas used to be copied into every repository with a per-repository
  ## MetaTag enum inside. The copies drifted -- this one had silently lost
  ## the testKind and stage pragmas entirely, which is why 475 of 487 tests
  ## could not declare a kind -- and they collided, because they were all
  ## called metaPragmas and Nim takes the LAST matching --path entry.
  ## Tags are strings now, so there is one file and everybody shares it.
  # {.testKind: tkRegression.}
  test "no local pragma copy exists to drift or collide":
    check not fileExists("meta/metaPragmas.nim")
    check not fileExists("meta/bifrostPragmas.nim")
    check not fileExists("src/analysis_pragmas.nim")

  # {.testKind: tkRegression.}
  test "every annotated file imports the shared module":
    var
      offenders: seq[string] = @[]
      text: string = ""
      config: string = readFile("config.nims")
    for path in walkDirRec("src"):
      if not path.endsWith(".nim"):
        continue
      text = readFile(path)
      if text.find("role: ") < 0:
        continue
      if text.find("import runePragmas") < 0:
        offenders.add(path)
    check offenders.len == 0
    check config.find("Rune-Pragmas") >= 0

  # {.testKind: tkRegression.}
  test "tags are strings, with no enum-set form left":
    var
      text: string = ""
      enumForm: int = 0
    for path in walkDirRec("src"):
      if not path.endsWith(".nim"):
        continue
      text = readFile(path)
      if text.find("metaTags: {") >= 0 or text.find("tag: {") >= 0:
        enumForm = enumForm + 1
    check enumForm == 0
