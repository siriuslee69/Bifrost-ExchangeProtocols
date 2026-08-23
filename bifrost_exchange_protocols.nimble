import std/[os, strutils, sequtils, tables, hashes]

const
  LibsodiumTaskShellEnv = "BIFROST_NIMBLE_IN_NIX_SHELL"
  LibsodiumLibNames = [
    "libsodium.so",
    "libsodium.so.23",
    "libsodium.so.24",
    "libsodium.dylib",
    "libsodium.dll"
  ]

version       = "0.1.0"
author        = "siriuslee69"
description   = "Bifrost transport, encryption, and wire protocols."
license       = "UNLICENSED"
srcDir        = "src"
bin           = @[]
requires "nim >= 1.6.0"
requires "webui >= 2.5.0"

proc normalizePath(p: string): string =
  ## Normalize slashes for Nim compiler path arguments.
  result = p.replace('\\', '/')

proc shellPath(p: string): string =
  ## Quote normalized paths so Nimble tasks survive spaces in repo roots.
  result = quoteShell(normalizePath(p))

proc shellCommand(command: string; args: openArray[string]): string =
  ## Build one shell-safe command line for NimScript `exec`/`gorgeEx`.
  var parts: seq[string] = @[shellPath(command)]
  for arg in args:
    parts.add(shellPath(arg))
  result = parts.join(" ")

proc runCommand(command: string; args: openArray[string])

proc otterRootDir(): string =
  var
    candidates: array[2, string] = [
      joinPath(parentDir(getCurrentDir()), "Otter-RepoEvaluation"),
      joinPath(getCurrentDir(), "submodules", "Otter-RepoEvaluation")
    ]
  for path in candidates:
    if fileExists(joinPath(path, "src", "clients", "test_ui", "app.nim")):
      return path
  raise newException(IOError, "Missing Otter-RepoEvaluation")

proc otterTestUiPath(): string =
  var
    name: string = "otter-test-ui"
  when defined(windows):
    name.add(".exe")
  result = joinPath(getCurrentDir(), "build", name)

proc buildOtterTestUi() =
  var
    root: string = otterRootDir()
  if not dirExists(joinPath(getCurrentDir(), "build")):
    mkDir(joinPath(getCurrentDir(), "build"))
  runCommand("nim", @["c", "--path:" & joinPath(root, "src"),
    "--out:" & otterTestUiPath(),
    joinPath(root, "src", "clients", "test_ui", "app.nim")])

proc runCommand(command: string; args: openArray[string]) =
  ## Run one quoted command through NimScript's shell-backed executor.
  exec shellCommand(command, args)

proc probeCommand(command: string; args: openArray[string]):
    tuple[output: string, exitCode: int] =
  ## Run one quoted command and return its combined output plus exit code.
  result = gorgeEx(shellCommand(command, args))

proc captureCommand(command: string; args: openArray[string]): string =
  ## Capture stdout/stderr from one quoted command.
  let probe = probeCommand(command, args)
  result = probe.output
  if probe.exitCode != 0:
    if result.len > 0:
      echo result
    quit(probe.exitCode)

proc dirHasLibsodium(dirPath: string): bool =
  ## Detect one visible libsodium runtime file inside a directory.
  var
    dir: string = ""
    libPath: string = ""
  dir = dirPath.strip()
  if dir.len == 0 or not dirExists(dir):
    return false
  for name in LibsodiumLibNames:
    libPath = joinPath(dir, name)
    if fileExists(libPath):
      return true
  result = false

proc libsodiumAvailable(): bool =
  ## Detect whether libsodium should already be reachable for runtime tests.
  var
    envLibDirs: string = ""
    dir: string = ""
    probe: tuple[output: string, exitCode: int]
  envLibDirs = getEnv("LIBSODIUM_LIB_DIRS").strip()
  if envLibDirs.len > 0:
    for raw in envLibDirs.split({';', ':'}):
      dir = raw.strip()
      if dirHasLibsodium(dir):
        return true
  if findExe("pkg-config").len > 0:
    probe = probeCommand("pkg-config", @["--exists", "libsodium"])
    if probe.exitCode == 0:
      return true
  result = false

proc libsodiumShellReady(): bool =
  ## Detect whether the repo-local Nix shell can provide libsodium.
  result = findExe("nix-shell").len > 0 and fileExists("shell.nix")

proc handoffTestTaskToLibsodiumShell(taskName: string): bool =
  ## Re-run one nimble task inside the repo shell when libsodium is missing.
  var
    cmd: string = ""
  if getEnv(LibsodiumTaskShellEnv) == "1":
    return false
  if libsodiumAvailable():
    return false
  if not libsodiumShellReady():
    quit("libsodium runtime was not detected for nimble " & taskName &
      ". Install libsodium or run inside nix-shell ./shell.nix.", 1)
  cmd = "export " & LibsodiumTaskShellEnv & "=1; nimble " & taskName
  echo "FALLBACK | libsodium missing | nix-shell ./shell.nix | nimble ", taskName
  runCommand("nix-shell", @["./shell.nix", "--run", cmd])
  result = true

var useHermeticTlsCheck = false

proc ensureDir(path: string)

proc findCCompiler(): string =
  ## Resolve a standalone host C compiler for small link probes.
  let envCc = getEnv("CC")
  if envCc.len > 0 and findExe(envCc).len > 0:
    result = normalizePath(envCc)
    return
  let cc = findExe("cc")
  if cc.len > 0:
    result = normalizePath(cc)
    return
  let gcc = findExe("gcc")
  if gcc.len > 0:
    result = normalizePath(gcc)
    return
  let clang = findExe("clang")
  if clang.len > 0:
    result = normalizePath(clang)
    return

proc canRunHermeticTlsCheck(): bool =
  ## Detect whether the repo-local hermetic TLS check is available.
  let tlsCheck = joinPath(getCurrentDir(), "nix", "tls-check.nix")
  result = findExe("nix-build").len > 0 and fileExists(tlsCheck)

proc runHermeticTlsCheck() =
  ## Execute the repo-local hermetic TLS transport/AME session verification path.
  if findExe("nix-build").len == 0:
    echo "nix-build was not found for the hermetic TLS check."
    quit(1)
  runCommand("nix-build", @["nix/tls-check.nix", "--no-out-link"])

proc ensureOpenSslBuildEnv(taskName: string) =
  ## Fail fast with an explicit prerequisite message before `-d:ssl` tasks
  ## reach the linker and emit a raw missing-library error.
  var
    probeName = "openssl_link_probe"
  useHermeticTlsCheck = false
  let pkgConfig = findExe("pkg-config")
  if pkgConfig.len > 0:
    let pkgProbe = probeCommand(pkgConfig, @["--exists", "openssl"])
    if pkgProbe.exitCode == 0:
      return

  let compiler = findCCompiler()
  if compiler.len == 0:
    if canRunHermeticTlsCheck():
      echo "OpenSSL build libraries were not detected for " & taskName &
        "; falling back to nix-build nix/tls-check.nix --no-out-link."
      useHermeticTlsCheck = true
      return
    echo "OpenSSL build libraries are required for " & taskName &
      ", and no standalone C compiler was found for a link probe."
    echo "Install OpenSSL development libraries or run the task inside an environment that provides libssl and libcrypto."
    quit(1)

  when defined(windows):
    probeName = "openssl_link_probe.exe"

  let
    root = getCurrentDir()
    probeDir = normalizePath(joinPath(root, "build", "tls_probe"))
    probeSrc = normalizePath(joinPath(probeDir, "openssl_link_probe.c"))
    probeOut = normalizePath(joinPath(probeDir, probeName))
  ensureDir(probeDir)
  writeFile(probeSrc, "int main(void) { return 0; }\n")
  let linkProbe = probeCommand(compiler,
    @[probeSrc, "-lcrypto", "-lssl", "-o", probeOut])
  if linkProbe.exitCode == 0:
    return

  if canRunHermeticTlsCheck():
    echo "OpenSSL build libraries were not detected for " & taskName &
      "; falling back to nix-build nix/tls-check.nix --no-out-link."
    useHermeticTlsCheck = true
    return

  echo "OpenSSL build libraries are required for " & taskName & "."
  echo "Install OpenSSL development libraries or run the task inside an environment that provides libssl and libcrypto."
  if linkProbe.output.len > 0:
    echo linkProbe.output
  quit(1)

proc ensureDir(path: string) =
  ## Recursively create a directory path with NimScript-safe `mkDir`.
  let dir = normalizePath(path)
  if dir.len == 0 or dirExists(dir):
    return
  let parent = normalizePath(parentDir(dir))
  if parent.len > 0 and parent != dir and not dirExists(parent):
    ensureDir(parent)
  if not dirExists(dir):
    mkDir(dir)

proc unquoteValue(v: string): string =
  ## Remove one layer of matching quote characters around a parsed value.
  result = v.strip()
  if result.len >= 2 and result[0] == '"' and result[^1] == '"':
    result = result[1 .. ^2]
  if result.len >= 2 and result[0] == '\'' and result[^1] == '\'':
    result = result[1 .. ^2]

proc findIronOverrideFile(repoRoot: string): string =
  ## Pick the current `.iron` override file first, then the legacy fallback.
  var
    candidates: seq[string] = @[
      joinPath(repoRoot, ".iron", ".local.gitmodules.toml"),
      joinPath(repoRoot, "iron", ".gitmodules.local")
    ]
  for path in candidates:
    if fileExists(path):
      return path
  result = ""

proc parseironOverrides(path: string): Table[string, string] =
  ## Parse a local `.iron` submodule-override file and map repo tail -> local path.
  result = initTable[string, string]()
  if not fileExists(path):
    return
  var
    repoTail: string = ""
    key: string = ""
    value: string = ""
  for raw in readFile(path).splitLines:
    let line = raw.strip()
    if line.len == 0 or line.startsWith("#"):
      continue
    if line.startsWith("[") and line.endsWith("]"):
      repoTail = ""
      continue
    key = ""
    value = ""
    if line.contains("="):
      let parts = line.split("=", maxsplit = 1)
      if parts.len == 2:
        key = parts[0].strip()
        value = unquoteValue(parts[1])
    if key.len == 0:
      continue
    if key == "name":
      repoTail = splitPath(value).tail
    elif key == "path":
      repoTail = splitPath(value).tail
    elif key == "url" and repoTail.len > 0:
      result[repoTail] = value
      repoTail = ""

proc resolveDepSrc(repoRoot: string; dep: string; overrides: Table[string, string]): string =
  ## Resolve a dependency src directory and fail with explicit message.
  var roots: seq[string] = @[]
  if overrides.hasKey(dep):
    roots.add(overrides[dep])
  if dep == "Tyr-Crypto":
    ## AME lower tiers require the companion pure Ed25519 implementation. When
    ## Tyr is checked out beside Bifrost, keep both projects on that same
    ## revision; standalone clones continue with their pinned submodule.
    roots.add(joinPath(parentDir(repoRoot), dep))
  roots.add(joinPath(repoRoot, "submodules", dep))
  roots.add(joinPath(repoRoot, dep))
  if dep != "Tyr-Crypto":
    roots.add(joinPath(parentDir(repoRoot), dep))

  for root in roots:
    let src = joinPath(root, "src")
    if dirExists(src):
      return normalizePath(src)

  raise newException(IOError,
    "Missing dependency src/ for " & dep &
    ". Checked: " & roots.join(", "))

proc findDirWithPrefix(base, prefix: string): string =
  ## Find the first child directory with a given prefix.
  if not dirExists(base):
    return ""
  for kind, path in walkDir(base):
    if kind == pcDir and splitPath(path).tail.startsWith(prefix):
      return normalizePath(path)
  result = ""

proc resolveNimSimdPath(): string =
  ## Resolve nimsimd from env or nimble package cache.
  let override = getEnv("NIMSIMD_PATH")
  if override.len > 0 and dirExists(override):
    return normalizePath(override)
  let home = getHomeDir()
  let p2 = findDirWithPrefix(joinPath(home, ".nimble", "pkgs2"), "nimsimd-")
  if p2.len > 0:
    return p2
  let p1 = findDirWithPrefix(joinPath(home, ".nimble", "pkgs"), "nimsimd-")
  if p1.len > 0:
    return p1
  result = ""

proc depPaths(repoRoot: string): seq[string] =
  ## Build `--path` compiler arguments for local sibling dependency layout.
  let overrides = parseironOverrides(findIronOverrideFile(repoRoot))
  let deps = @[
    "Fylgia-Utils",
    "Tyr-Crypto",
    "SIMD-Nexus",
    "Eir-CompressionAndECC"
  ]
  var paths: seq[string] = @[]
  for dep in deps:
    let src = resolveDepSrc(repoRoot, dep, overrides)
    paths.add("--path:" & normalizePath(src))
    if dep == "Tyr-Crypto":
      let root = normalizePath(parentDir(src))
      paths.add("--path:" & root)
      let tyrMeta = normalizePath(joinPath(root, "tools", "meta"))
      if dirExists(tyrMeta):
        paths.add("--path:" & tyrMeta)
      let nestedSimd = normalizePath(joinPath(root, "submodules", "simd_nexus", "src"))
      if dirExists(joinPath(root, "submodules", "simd_nexus", "src")):
        paths.add("--path:" & nestedSimd)
      let flatSimd = normalizePath(joinPath(root, "simd_nexus", "src"))
      if dirExists(joinPath(root, "simd_nexus", "src")):
        paths.add("--path:" & flatSimd)
  let nimsimdPath = resolveNimSimdPath()
  if nimsimdPath.len > 0:
    paths.add("--path:" & normalizePath(nimsimdPath))
  else:
    echo "Warning: nimsimd path was not detected; SIMD-backed tests may fail."
  result = paths

proc cacheDirFor(root: string; mode: string; filePath: string;
    extra: string): string =
  ## Isolate Nim object caches per target/flag-set to avoid stale cross-talk.
  let key = mode & "|" & normalizePath(filePath) & "|" & extra
  let leaf = splitFile(filePath).name & "_" &
    toHex(cast[uint64](hash(key)), 16)
  result = normalizePath(joinPath(root, "nimcache", leaf))

proc runnableOutputPath(filePath: string): string =
  ## Keep runnable helper binaries out of source-controlled trees.
  var
    parts: tuple[dir, name, ext: string]
    binName: string
  parts = splitFile(filePath)
  binName = parts.name
  when defined(windows):
    binName = binName & ".exe"
  if filePath.startsWith("tests/"):
    result = joinPath("build", "tests", binName)
  elif filePath.startsWith("examples/"):
    result = joinPath("build", "examples", binName)
  elif filePath.startsWith("tools/"):
    result = joinPath("build", "tools", binName)

proc hasExplicitOutputArg(args: openArray[string]): bool =
  ## Detect explicit binary output args so callers can override defaults.
  var
    i: int = 0
  while i < args.len:
    if args[i].startsWith("-o:") or args[i].startsWith("--out:"):
      return true
    i.inc

proc defaultOutputArgs(filePath: string; extraArgs: openArray[string]): seq[string] =
  ## Auto-place runnable helper binaries under ignored build directories.
  var
    t: string = ""
    outPath: string = ""
  if not hasExplicitOutputArg(extraArgs):
    t = runnableOutputPath(filePath)
    if t.len > 0:
      ensureDir(splitFile(t).dir)
      outPath = t.replace('\\', '/')
      result = @["-o:" & outPath]

proc runNim(mode: string; filePath: string;
    extraArgs: openArray[string] = []) =
  ## Execute a Nim command with resolved dependency paths.
  let root = getCurrentDir()
  let extraKey = @extraArgs.join("\x1f")
  var args: seq[string] = @[mode, "--nimcache:" &
    normalizePath(cacheDirFor(root, mode, filePath, extraKey))]
  args.add(depPaths(root))
  args.add(defaultOutputArgs(filePath, extraArgs))
  args.add(extraArgs)
  args.add(normalizePath(filePath))
  runCommand("nim", args)

proc runRepoHygiene(extraArgs: openArray[string] = []) =
  ## Compile and run the repo hygiene tool outside build/ so clean can remove
  ## generated roots without deleting the currently running executable.
  var
    tempTool: string = normalizePath(joinPath(getTempDir(),
      "bifrost_repo_hygiene_tool"))
    tempCache: string = normalizePath(joinPath(getTempDir(),
      "bifrost_repo_hygiene_nimcache"))
    args: seq[string] = @[
      "c",
      "-r",
      "--nimcache:" & tempCache,
      "--out:" & tempTool,
      normalizePath(joinPath("tools", "repo_hygiene.nim"))
    ]
  args.add(extraArgs)
  runCommand("nim", args)

proc ensureAndroidJava() =
  ## Prefer Android Studio's bundled JBR when JAVA_HOME is not configured.
  when defined(windows):
    let studioJbr = r"C:\Program Files\Android\Android Studio\jbr"
    if getEnv("JAVA_HOME").len == 0 and dirExists(studioJbr):
      putEnv("JAVA_HOME", studioJbr)
  let sharedGradleHome = joinPath(parentDir(getCurrentDir()), ".gradle-codex")
  if getEnv("GRADLE_USER_HOME").len == 0 and dirExists(sharedGradleHome):
    putEnv("GRADLE_USER_HOME", sharedGradleHome)

proc runGradle(args: openArray[string]) =
  ## Execute the repo-local Gradle wrapper for Android client tasks.
  ensureAndroidJava()
  let androidRoot = joinPath(getCurrentDir(), "src", "clients", "android")
  when defined(windows):
    runCommand("cmd", @["/c", joinPath(androidRoot, "gradlew.bat"),
      "--project-dir", androidRoot] & @args)
  else:
    runCommand(joinPath(androidRoot, "gradlew"),
      @["--project-dir", androidRoot] & @args)

proc isGeneratedOrLocalArtifact(path: string): bool =
  ## Reject local/generated outputs before autopush can commit them.
  let p = normalizePath(path)
  result = splitPath(p).tail.startsWith(".fuse_hidden") or
    p.startsWith("nimcache") or
    p.startsWith("build/") or p.startsWith("builds/") or
    p.startsWith(".gradle/") or p.startsWith(".kotlin/") or
    p.endsWith(".exe") or p.endsWith(".dll") or p.endsWith(".so") or
    p.endsWith(".dylib") or p.endsWith(".o") or p.endsWith(".obj") or
    p.endsWith(".a") or p.endsWith(".lib") or p.endsWith(".pdb") or
    p == "local.properties" or p == "userconfig.toml" or
    p == "nimble.paths" or p == "nimble.develop" or
    p.startsWith(".iron/.local")

task buildLib, "Build the bifrost_exchange_protocols module as a library":
  runNim("c", "src/bifrost_exchange_protocols.nim",
    @["--app:lib", "--outdir:build/lib"])

task vectors, "Regenerate committed BFX2 test vectors":
  runNim("c", "tools/generate_bfx2_vectors.nim", @["-r"])

task benchmarks, "Run the committed protocol benchmark harness":
  runNim("c", "tools/bench_protocols.nim", @["-d:release", "-r"])

task benchmarksServerSimd, "Run protocol benchmarks with server AVX2 batching":
  runNim("c", "tools/bench_protocols.nim", @[
    "-d:release", "-d:sse2", "-d:avx2",
    "--passC:-msse4.1 -mavx2", "--passL:-mavx2", "-r"
  ])

task buildTestUi, "Build the pragma-driven Otter test UI":
  buildOtterTestUi()

task testUi, "Discover Bifrost Otter tests and open the isolated test UI":
  buildOtterTestUi()
  runCommand(otterTestUiPath(), @["--repo-root:" & getCurrentDir()])

task test, "Run bifrost_exchange_protocols tests":
  if not handoffTestTaskToLibsodiumShell("test"):
    runNim("c", "tests/test_task_contract.nim", @["-r"])
    runNim("c", "tests/test_http_protocol.nim", @["-r"])
    runNim("c", "tests/test_config_exact.nim", @["-r"])
    runNim("c", "tests/test_ame_exchange_paths.nim", @["-r"])
    runNim("c", "tests/test_ame_build_flags.nim", @["-r"])
    runNim("c", "tests/test_chunkyaead.nim", @["--threads:on", "-r"])
    runNim("c", "tests/test_fomke.nim", @["-r"])
    runNim("c", "tests/test_fomke_forward_secrecy.nim", @["-r"])
    runNim("c", "tests/test_ame_session.nim", @["-r"])
    runNim("c", "tests/test_ame_handshake_package.nim", @["-r"])
    runNim("c", "tests/test_ame_dac_relay.nim", @["-r"])
    runNim("c", "tests/test_mitm_and_loss.nim", @["-r"])
    runNim("c", "tests/test_ame_tcp_handshake.nim", @["--threads:on", "-r"])
    runNim("c", "tests/test_ame_dac_handshake.nim", @["--threads:on", "-r"])
    runNim("c", "tests/test_ame_session_api.nim", @["-r"])

    runNim("c", "tests/test_ame_dac_endpoint.nim", @["--threads:on", "-r"])
    runNim("c", "tests/test_dac_defaults.nim", @["-r"])
    runNim("c", "tests/test_dac_wire.nim", @["-r"])
    runNim("c", "tests/test_dac_ack_policy.nim", @["-r"])
    runNim("c", "tests/test_dac_package_repair.nim", @["-r"])
    runNim("c", "tests/test_dac_scramble.nim", @["-r"])
    runNim("c", "tests/test_dac_link.nim", @["-r"])
    runNim("c", "tests/test_dac_link_table.nim", @["-r"])
    runNim("c", "tests/test_wire_fuzz.nim", @["-r"])
    runNim("c", "tests/test_wire_fuzz_protocols.nim", @["-r"])
    runNim("c", "tests/test_dac_drift_payload.nim", @["-r"])
    runNim("c", "tests/test_transport_ops.nim", @["--threads:on", "-r"])
    runNim("c", "tests/test_async_stream_ops.nim", @["-r"])
    runNim("c", "tests/test_bfx2_wire.nim", @["-r"])
    runNim("c", "tests/test_bfx2_geojson.nim", @["-r"])
    runNim("c", "tests/test_bfx2_external_bridge.nim", @["-r"])
    runNim("c", "tests/test_lan_message.nim", @["-r"])
    runNim("c", "tests/test_tls13_foundation.nim", @["-r"])
    runNim("c", "tests/test_tls13_webpki.nim", @["-r"])

task testTls, "Run TLS-enabled transport tests (host OpenSSL or Nix fallback)":
  ensureOpenSslBuildEnv("nimble testTls")
  if useHermeticTlsCheck:
    runHermeticTlsCheck()
  else:
    runNim("c", "tests/test_transport_ops.nim", @["--threads:on", "-d:ssl", "-r"])

task testNativeTls, "Run the pure-Nim TLS 1.3 foundation suite":
  runNim("c", "tests/test_tls13_foundation.nim", @["-r"])

task testNativeTlsWebpki, "Run TLS 1.3 handshakes with RSA and ECDSA certificates":
  runNim("c", "tests/test_tls13_webpki.nim", @["-r"])

task testNativeTlsInterop, "Run native TLS 1.3 client/server interoperability against OpenSSL":
  runNim("c", "tools/run_tls13_openssl_interop.nim", @["-r"])
  runNim("c", "tools/run_tls13_openssl_client_interop.nim", @["-r"])

task exampleAmeExactPath, "Run the exact AME algorithm-path example":
  runNim("c", "examples/ame_exact_path.nim", @["-r"])

task exampleSecurePackage, "Run authority handshake and repaired package example":
  runNim("c", "examples/secure_authority_package.nim", @["-r"])

task exampleFomke, "Run AME-backed forward-only message ratchet example":
  runNim("c", "examples/fomke_ame_chain.nim", @["-r"])

task testMinimalAme, "Run the AME flag tests under each slim build profile":
  ## Same tests, four builds: full, DAC-only, TCP-only, and the smallest
  ## profile that still completes a session. A flag combination that breaks
  ## a slim build fails here rather than on a device.
  runNim("c", "tests/test_ame_build_flags.nim", @["-r"])
  runNim("c", "tests/test_ame_build_flags.nim", @[
    "-d:bifrostKems=kyber,x25519", "-d:bifrostCarriers=dac", "-r"
  ])
  runNim("c", "tests/test_ame_build_flags.nim", @[
    "-d:bifrostKems=kyber,x25519", "-d:bifrostCarriers=tcp", "-r"
  ])
  runNim("c", "tests/test_ame_build_flags.nim", @[
    "-d:bifrostKems=kyber,x25519", "-d:bifrostCarriers=dac",
    "-d:bifrostSigs=ed25519", "-d:bifrostSymmetric=blake3,chacha20", "-r"
  ])


task testDacFlag, "Check that -d:bifrostDac=off removes the adaptive layer":
  ## The wire and the fixed profiles must still build with the flag off, the
  ## adaptive layer must refuse to build, and the umbrella must build both ways.
  runNim("c", "tests/dacflag/uses_frames.nim", @["-r"])
  runNim("c", "tests/dacflag/uses_frames.nim", @["-d:bifrostDac=off", "-r"])
  runNim("c", "tests/dacflag/uses_link.nim", @["-r"])
  runNim("c", "tests/dacflag/uses_link_table.nim", @["-r"])
  runNim("c", "tests/dacflag/uses_relay.nim", @["-r"])
  runNim("c", "src/bifrost_exchange_protocols.nim", @["-d:bifrostDac=off", "-o:build/dacflag_umbrella"])
  if gorgeEx(shellCommand("nim", @["c", "-d:bifrostDac=off",
      "-o:build/dacflag_probe", "tests/dacflag/uses_link.nim"])).exitCode == 0:
    quit("-d:bifrostDac=off still compiled the adaptive layer", 1)
  if gorgeEx(shellCommand("nim", @["c", "-d:bifrostDac=off",
      "-o:build/dacflag_probe_table", "tests/dacflag/uses_link_table.nim"])).exitCode == 0:
    quit("-d:bifrostDac=off still compiled the DAC link table", 1)
  if gorgeEx(shellCommand("nim", @["c", "-d:bifrostDac=off",
      "-o:build/dacflag_probe_relay", "tests/dacflag/uses_relay.nim"])).exitCode == 0:
    quit("-d:bifrostDac=off still compiled the AME DAC relay", 1)
  echo "OK | -d:bifrostDac=off keeps the wire and refuses the adaptive layer"

task testDac, "Run DAC transport schema/default tests":
  runNim("c", "tests/test_dac_defaults.nim", @["-r"])
  runNim("c", "tests/test_dac_wire.nim", @["-r"])
  runNim("c", "tests/test_dac_ack_policy.nim", @["-r"])
  runNim("c", "tests/test_dac_package_repair.nim", @["-r"])
  runNim("c", "tests/test_dac_scramble.nim", @["-r"])
  runNim("c", "tests/test_dac_link.nim", @["-r"])

  runNim("c", "tests/test_dac_link_table.nim", @["-r"])


  runNim("c", "tests/test_ame_dac_relay.nim", @["-r"])



  runNim("c", "tests/test_ame_dac_endpoint.nim", @["--threads:on", "-r"])
  runNim("c", "tests/test_wire_fuzz.nim", @["-r"])

  runNim("c", "tests/test_wire_fuzz_protocols.nim", @["-r"])
  runNim("c", "tests/test_dac_drift_payload.nim", @["-r"])

task testFuzz, "Run every wire decoder against mutated frames":
  ## The parser surface an attacker reaches first: DAC datagrams and the link
  ## table that routes them, AME frames and protected bodies, BFX2 envelopes,
  ## and the TLS 1.3 record and handshake decoders.
  runNim("c", "tests/test_wire_fuzz.nim", @["-r"])
  runNim("c", "tests/test_wire_fuzz_protocols.nim", @["-r"])

task testFomke, "Run GB3HKDF, AEAD preset, and FOMKE ratchet tests":
  if not handoffTestTaskToLibsodiumShell("testFomke"):
    runNim("c", "tests/test_fomke.nim", @["-r"])
    runNim("c", "tests/test_fomke_forward_secrecy.nim", @["-r"])

task testMitm, "Run on-path attacker, loss, and repair tests":
  if not handoffTestTaskToLibsodiumShell("testMitm"):
    runNim("c", "tests/test_mitm_and_loss.nim", @["-r"])

task testChunkyAead, "Run CHUNKYAEAD chunk encryption and hash tests":
  runNim("c", "tests/test_chunkyaead.nim", @["--threads:on", "-r"])

task testFomkeServerSimd, "Run FOMKE tests with server AVX2 batching":
  if not handoffTestTaskToLibsodiumShell("testFomkeServerSimd"):
    runNim("c", "tests/test_fomke.nim", @[
      "-d:release", "-d:sse2", "-d:avx2",
      "--passC:-msse4.1 -mavx2", "--passL:-mavx2", "-r"
    ])

task examples, "Run all Bifrost examples":
  runNim("c", "examples/ame_exact_path.nim", @["-r"])
  runNim("c", "examples/secure_authority_package.nim", @["-r"])
  runNim("c", "examples/fomke_ame_chain.nim", @["-r"])

task releaseHygiene, "Audit generated and local repo artifacts that should not ship":
  runRepoHygiene(@["--root=."])

task cleanGenerated, "Remove generated and local repo artifacts such as build/, nimcache/, and helper binaries":
  runRepoHygiene(@["--root=.", "--clean"])

task androidDebug, "Build the Android LAN client debug APK":
  runGradle(@[":androidApp:assembleDebug"])

task desktop, "Build and run the themed direct-LAN desktop client":
  runNim("c", "src/clients/desktop/app.nim", @["--threads:on", "-r"])

task desktopBuild, "Build the themed direct-LAN desktop client for release":
  runNim("c", "src/clients/desktop/app.nim", @[
    "--threads:on", "-d:release", "--out:build/clients/bifrost-lan-desktop"
  ])

task androidTest, "Run Android client JVM tests and assemble the instrumented test APK":
  runGradle(@[":androidApp:testDebugUnitTest", ":androidApp:assembleDebugAndroidTest"])

task androidConnectedTest, "Run Android client instrumented tests on a connected device":
  runGradle(@[":androidApp:connectedDebugAndroidTest"])

task androidLanTest, "Run direct host-to-Android BMSG exchange over LAN IP":
  runGradle(@[":androidApp:assembleDebug", ":androidApp:assembleDebugAndroidTest"])
  runNim("c", "tools/test_android_lan_ip.nim", @["--threads:on", "-r"])

task androidInstall, "Install the Android LAN client debug APK on a connected device":
  runGradle(@[":androidApp:installDebug"])

task autopush, "Add, commit, and push after rejecting generated/local artifacts":
  let path = ".iron/PROGRESS.md"
  var msg = ""
  if fileExists(path):
    let content = readFile(path)
    for line in content.splitLines:
      if line.startsWith("Commit Message:"):
        msg = line["Commit Message:".len .. ^1].strip()
        break
  if msg.len == 0:
    msg = "No specific commit message given."
  runCommand("git", @["add", "-A", "."])
  let staged = captureCommand("git", @["diff", "--cached", "--name-only"]).strip()
  if staged.len == 0:
    echo "No staged changes. Skipping commit."
  else:
    for stagedPath in staged.splitLines:
      if isGeneratedOrLocalArtifact(stagedPath):
        echo "Refusing autopush: generated/local artifact staged: " & stagedPath
        echo "Remove it from the index or extend .gitignore before committing."
        quit(1)
    runCommand("git", @["commit", "-m", msg])
  runCommand("git", @["push"])

task switch, "Toggle the working branch between nightly and main":
  var
    branch: string = captureCommand("git", @["branch", "--show-current"]).strip()
    target: string = ""
  if branch == "nightly":
    target = "main"
  else:
    target = "nightly"
  echo "Switching from '" & (if branch.len > 0: branch else: "(detached HEAD)") &
    "' to '" & target & "'."
  runCommand("git", @["checkout", target])

task applynightly, "Promote nightly onto main by fast-forward and push":
  var
    branch: string = captureCommand("git", @["branch", "--show-current"]).strip()
  if branch == "main":
    quit "On 'main'. Run `nimble switch` to move to nightly before applying."
  runCommand("git", @["fetch", ".", "nightly:main"])
  runCommand("git", @["push", "origin", "nightly:main"])
  echo "main is now at the nightly state; nightly branch left intact."

task find, "Use local clones for submodules in parent folder":
  let modulesPath = ".gitmodules"
  if not fileExists(modulesPath):
    echo "No .gitmodules found."
  else:
    let root = parentDir(getCurrentDir())
    var current = ""
    for line in readFile(modulesPath).splitLines:
      let s = line.strip()
      if s.startsWith("[submodule"):
        let start = s.find('"')
        let stop = s.rfind('"')
        if start >= 0 and stop > start:
          current = s[start + 1 .. stop - 1]
      elif current.len > 0 and s.startsWith("path"):
        let parts = s.split("=", maxsplit = 1)
        if parts.len == 2:
          let subPath = parts[1].strip()
          let tail = splitPath(subPath).tail
          let localDir = joinPath(root, tail)
          if dirExists(localDir):
            let localUrl = normalizePath(localDir)
            runCommand("git", @["config", "-f", ".gitmodules",
              "submodule." & current & ".url", localUrl])
            runCommand("git", @["config",
              "submodule." & current & ".url", localUrl])
    runCommand("git", @["submodule", "sync", "--recursive"])
