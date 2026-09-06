## -------------------------------------------------------------------
## Otter Test Catalog <- isolated Bifrost repository test entry points
## -------------------------------------------------------------------

import std/[os, osproc]

import otter_repo_evaluation

proc repoRoot(): string =
  result = parentDir(parentDir(currentSourcePath()))

proc runTask(name: string) =
  var
    process: Process = startProcess("nimble", workingDir = repoRoot(),
      args = @[name, "-y"], options = {poParentStreams, poUsePath})
    exitCode: int = 0
  exitCode = process.waitForExit()
  process.close()
  if exitCode != 0:
    raise newException(OSError, "Bifrost test task failed: " & name)

proc otterBifrostSuite*() {.otterUiTest: ("Protocol suite", "Bifrost", "functional, protocol", "").} =
  runTask("test")

proc otterDacSuite*() {.otterUiTest: ("DAC", "Bifrost", "functional, transport, dac", "").} =
  runTask("testDac")

proc otterChunkyAeadSuite*() {.otterUiTest: ("CHUNKYAEAD", "Bifrost", "functional, encryption, file", "").} =
  runTask("testChunkyAead")

proc otterNativeTls*() {.otterUiTest: ("TLS 1.3", "Bifrost", "functional, transport, tls", "Pure Nim").} =
  runTask("testNativeTls")

proc otterOpenSslTls*() {.otterUiTest: ("TLS 1.3", "Bifrost", "interop, transport, tls", "OpenSSL").} =
  runTask("testNativeTlsInterop")
