## -------------------------------------------------------------------------
## Low-Memory Size Benchmark <- builds each tiny profile, measures, writes it
## -------------------------------------------------------------------------
##
## What it does, once per profile:
##
##   profile flags --nim c--> lowmem_probe --run--> "LOWMEM heap=.. stack=.."
##                                 |
##                                 +--size--> program bytes, static RAM bytes
##
## then once, for the reference tiny profile:
##
##   nm --> every routine's size --> summed per module --> module table
##
## Both tables are printed and written into README.md between the two lines
##
##   <!-- lowmem:begin -->
##   <!-- lowmem:end -->
##
## so the README always shows the numbers of the last run. Run it with
##
##   nimble benchLowMem          (or as part of `nimble runBenchmarks`)
##
## Needs `nm` and `size` (binutils) and a Linux target: the heap meter wraps
## glibc's malloc. On another system it prints why and stops without failing.

import std/[os, osproc, strutils, algorithm]
import runePragmas

type
  LowmemProfile = object
    ## One row of the table: a name and the flags that make that build.
    name: string
    flags: seq[string]

  LowmemRow = object
    ## What one profile measured. Sizes in bytes.
    name: string
    ok: bool
    program: int   ## code + constants: what goes into flash
    staticRam: int ## globals: RAM taken before the first line runs
    heap: int      ## most heap bytes alive at once
    stack: int     ## deepest stack reach
    note: string

const
  repoRoot: string = currentSourcePath().parentDir().parentDir().parentDir().parentDir()
  probeSource: string = "evaluation/benchmarks/lowmem/lowmem_probe.nim"
  buildDir: string = "build/lowmem"
  beginMark: string = "<!-- lowmem:begin -->"
  endMark: string = "<!-- lowmem:end -->"
  ## Every row starts from a preset in configs/ -- the same file a real
  ## device build uses -- plus only the switches that row changes. So the
  ## table measures exactly what `nim c -d:preset=iot` ships.
  iot: string = "-d:preset=iot"
  iotMin: string = "-d:preset=iot-min"
  allFamilies: seq[string] = @["-d:bifrostKems=", "-d:bifrostSigs=",
    "-d:bifrostSymmetric=", "-d:bifrostCarriers=", "-d:bifrostHandshakes=",
    "-d:bifrostDac=on"]
    ## Undoes iot's family choices while keeping its compiler settings.
  referenceProfile: int = 6
    ## Index of the profile whose modules are broken down (AM1P+S, LightSaber).

proc profiles(): seq[LowmemProfile] {.role: configurator.} =
  ## Every row, top to bottom: from the whole library down to the smallest.
  result = @[
    LowmemProfile(name: "AM1P, whole library, -d:release",
      flags: @["-d:release", "-d:useMalloc", "-d:lowmemMode=psk"]),
    LowmemProfile(name: "AM1P, whole library, iot compiler",
      flags: @[iot] & allFamilies & @["-d:lowmemMode=psk"]),
    LowmemProfile(name: "AM1P, X25519            [iot-min]",
      flags: @[iotMin, "-d:lowmemMode=psk"]),
    LowmemProfile(name: "AM1P, ML-KEM-768 + X25519",
      flags: @[iotMin, "-d:bifrostKems=mlkem,x25519", "-d:lowmemMode=psk"]),
    LowmemProfile(name: "AM1P, LightSaber + X25519",
      flags: @[iot, "-d:bifrostHandshakes=am1p", "-d:lowmemMode=psk"]),
    LowmemProfile(name: "AM1P or AM1P+S, LightSaber   [iot]",
      flags: @[iot, "-d:lowmemMode=pskSig"]),
    LowmemProfile(name: "AM1P+S, LightSaber + X25519, Ed25519",
      flags: @[iot, "-d:bifrostHandshakes=am1ps", "-d:lowmemMode=pskSig"]),
    LowmemProfile(name: "AM1S, LightSaber + X25519, Ed25519",
      flags: @[iot, "-d:bifrostHandshakes=am1s", "-d:lowmemMode=sig"]),
    LowmemProfile(name: "AM1P+S, LightSaber, whole Saber family",
      flags: @[iot, "-d:bifrostHandshakes=am1ps", "-d:bifrostKems=saber,x25519",
        "-d:lowmemMode=pskSig"]),
    LowmemProfile(name: "AM1P+S, LightSaber, AVX2",
      flags: @[iot, "-d:bifrostHandshakes=am1ps", "-d:tyrSimd=avx2",
        "-d:lowmemMode=pskSig"])]

proc outName(i: int): string {.role: helper.} =
  ## i: profile index -> its own program path, so builds never collide.
  result = repoRoot / buildDir / ("probe_" & $i)

proc hasAvx2(): bool {.role: dataFetcher.} =
  ## True when this machine can run AVX2 code.
  var
    info: string = ""
  if fileExists("/proc/cpuinfo"):
    info = readFile("/proc/cpuinfo")
  result = info.contains(" avx2")

proc buildProbe(p: LowmemProfile, i: int,
    extra: seq[string] = @[]): tuple[ok: bool, err: string] {.role: dataWriter.} =
  ## p/i/extra: compile one profile's probe into build/lowmem/probe_<i>.
  var
    args: seq[string] = @["c", "--hints:off", "--warnings:off"]
    run: tuple[output: string, exitCode: int] = ("", 0)
  args.add(p.flags & extra)
  args.add(@["--nimcache:" & (buildDir / ("cache_" & $i)), "-o:" & outName(i),
    probeSource])
  run = execCmdEx(quoteShellCommand(@["nim"] & args), workingDir = repoRoot)
  result.ok = run.exitCode == 0
  if not result.ok:
    result.err = run.output.strip().splitLines()[^1]

proc sectionSizes(path: string): tuple[program, staticRam: int] {.
    role: parser.} =
  ## path: program -> (text, data + bss) from `size`'s one-line answer:
  ##   "   text  data  bss  dec  hex filename"
  ##   " 208834  3968  408  ..."
  var
    run: tuple[output: string, exitCode: int] = ("", 0)
    cols: seq[string] = @[]
  run = execCmdEx(quoteShellCommand(@["size", path]))
  cols = run.output.strip().splitLines()[^1].splitWhitespace()
  result.program = parseInt(cols[0]) + parseInt(cols[1])
  result.staticRam = parseInt(cols[1]) + parseInt(cols[2])

proc fieldOf(line, key: string): int {.role: parser.} =
  ## line/key: "LOWMEM ok=1 heap=35048 ..." and "heap" -> 35048.
  var
    parts: seq[string] = line.splitWhitespace()
    i: int = 0
  while i < parts.len:
    if parts[i].startsWith(key & "="):
      return parseInt(parts[i][key.len + 1 .. ^1])
    i = i + 1

proc runProbe(path: string): string {.role: dataFetcher.} =
  ## path: probe program -> its LOWMEM line, or "" if it failed.
  var
    run: tuple[output: string, exitCode: int] = ("", 0)
  run = execCmdEx(quoteShellCommand(@[path]))
  for line in run.output.splitLines():
    if line.startsWith("LOWMEM ok=1"):
      result = line

proc measure(p: LowmemProfile, i: int): LowmemRow {.role: orchestrator.} =
  ## p/i: build twice -- plain for the true program size, with the meter for
  ## heap and stack -- because the meter itself adds a little code.
  var
    built: tuple[ok: bool, err: string] = (false, "")
    sizes: tuple[program, staticRam: int] = (0, 0)
    line: string = ""
  result.name = p.name
  built = buildProbe(p, i)
  if not built.ok:
    result.note = "build failed: " & built.err
    return
  discard execCmdEx(quoteShellCommand(@["strip", outName(i)]))
  sizes = sectionSizes(outName(i))
  built = buildProbe(p, i, @["-d:lowmemMeter"])
  line = runProbe(outName(i))
  if not built.ok or line.len == 0:
    result.note = "probe failed"
    return
  result.ok = true
  result.program = sizes.program
  result.staticRam = sizes.staticRam
  result.heap = fieldOf(line, "heap")
  result.stack = fieldOf(line, "stack")

proc kb(n: int): string {.role: helper.} =
  ## n: bytes -> "12.3 KB", right-aligned to 9 characters.
  result = formatFloat(n.float / 1024.0, ffDecimal, 1).align(6) & " KB"

proc rowLine(r: LowmemRow): string {.role: helper.} =
  ## r: one measured profile as one table line.
  if not r.ok:
    return "| " & r.name.alignLeft(38) & " | " & r.note
  result = "| " & r.name.alignLeft(38) & " | " & kb(r.program) & " | " &
    kb(r.staticRam + r.heap + r.stack) & " | " & kb(r.heap) & " | " &
    kb(r.stack) & " | " & kb(r.staticRam) & " |"

proc profileTable(R: seq[LowmemRow]): string {.role: actor.} =
  ## R: every measured row -> the whole profile table.
  var
    rule: string = "+" & "-".repeat(40) & ("+" & "-".repeat(11)).repeat(5) & "+"
    lines: seq[string] = @[]
  lines.add(rule)
  lines.add("| " & "profile".alignLeft(38) &
    " | program   | RAM total | heap peak | stack     | globals   |")
  lines.add(rule)
  for r in R:
    lines.add(rowLine(r))
  lines.add(rule)
  result = lines.join("\n")

proc rot13(s: string): string {.role: helper.} =
  ## s: Nim writes module paths into C names letter-shifted by 13; this
  ## shifts them back ("fepZcebgbpbyf" -> "srcMprotocols").
  var
    i: int = 0
  result = s
  while i < s.len:
    if s[i] in {'a'..'z'}:
      result[i] = char((ord(s[i]) - ord('a') + 13) mod 26 + ord('a'))
    elif s[i] in {'A'..'Z'}:
      result[i] = char((ord(s[i]) - ord('A') + 13) mod 26 + ord('A'))
    i = i + 1

const
  moduleGroups: array[17, tuple[mark, label: string]] = [
    ("protocolsMameMlevel3", "Bifrost AME handshake     (ame/level3)"),
    ("protocolsMameMlevel2", "Bifrost AME session/frame (ame/level2)"),
    ("protocolsMameMlevel1", "Bifrost AME suites/keys   (ame/level1)"),
    ("protocolsMameMlevel0", "Bifrost AME bytes         (ame/level0)"),
    ("protocolsMameMtypes", "Bifrost AME types"),
    ("protocolsMfomke", "Bifrost FOMKE ratchet     (fomke)"),
    ("protocolsMdac", "Bifrost DAC wire          (dac)"),
    ("protocols", "Bifrost other"),
    ("tyrMkemsMsaber", "Tyr Saber"),
    ("tyrMkemsMmlkem", "Tyr ML-KEM"),
    ("tyrMkemsMx25519", "Tyr X25519"),
    ("tyrMsignaturesMed25519", "Tyr Ed25519"),
    ("tyrMhashes", "Tyr hashes (BLAKE3, SHA-3)"),
    ("tyrMciphers", "Tyr ciphers (ChaCha20)"),
    ("tyrM", "Tyr other (MACs, random, helpers)"),
    ("lowmem95probe", "the probe itself"),
    ("flfgrz", "Nim runtime (system)")]
    ## First match wins, so the specific marks sit above the general ones.
    ## "flfgrz" is "system" still shifted: that module is not path-named.

proc groupOf(symbol: string): string {.role: parser.} =
  ## symbol: one C symbol name -> the label of the module it came from.
  var
    plain: string = rot13(symbol)
    i: int = 0
  result = "C library / start-up"
  if not symbol.contains("__"):
    return
  while i < moduleGroups.len:
    if plain.contains(moduleGroups[i].mark) or
        symbol.contains(moduleGroups[i].mark):
      return moduleGroups[i].label
    i = i + 1
  result = "Nim runtime (std)"

proc addSymbol(G: var seq[tuple[label: string, bytes: int]], label: string,
    n: int) {.role: helper.} =
  ## G/label/n: adds n bytes to the group named label, making it if new.
  var
    i: int = 0
  while i < G.len:
    if G[i].label == label:
      G[i].bytes = G[i].bytes + n
      return
    i = i + 1
  G.add((label: label, bytes: n))

proc moduleSizes(path: string): seq[tuple[label: string, bytes: int]] {.
    role: truthBuilder.} =
  ## path: unstripped program -> code bytes per module group, largest first.
  var
    run: tuple[output: string, exitCode: int] = ("", 0)
    cols: seq[string] = @[]
  run = execCmdEx(quoteShellCommand(@["nm", "-S", "--size-sort", path]))
  for line in run.output.splitLines():
    cols = line.splitWhitespace()
    if cols.len == 4 and cols[2] in ["t", "T"]:
      addSymbol(result, groupOf(cols[3]), parseHexInt(cols[1]))
  result.sort(proc (a, b: tuple[label: string, bytes: int]): int =
    cmp(b.bytes, a.bytes))

proc moduleTable(G: seq[tuple[label: string, bytes: int]]): string {.
    role: actor.} =
  ## G: code bytes per group -> the module table.
  var
    rule: string = "+" & "-".repeat(42) & "+" & "-".repeat(11) & "+"
    lines: seq[string] = @[]
    total: int = 0
  for g in G:
    total = total + g.bytes
  lines.add(rule)
  lines.add("| " & "module".alignLeft(40) & " | code      |")
  lines.add(rule)
  for g in G:
    lines.add("| " & g.label.alignLeft(40) & " | " & kb(g.bytes) & " |")
  lines.add(rule)
  lines.add("| " & "total named code".alignLeft(40) & " | " & kb(total) & " |")
  lines.add(rule)
  result = lines.join("\n")

proc writeReadme(body: string) {.role: dataWriter.} =
  ## body: text that replaces whatever sits between the two README marks.
  var
    path: string = repoRoot / "README.md"
    text: string = readFile(path)
    a: int = text.find(beginMark)
    b: int = text.find(endMark)
  if a < 0 or b < a:
    echo "README.md has no ", beginMark, " / ", endMark, " pair; not written"
    return
  text = text[0 ..< a + beginMark.len] & "\n" & body & "\n" & text[b .. ^1]
  writeFile(path, text)
  echo "README.md updated"

proc toolsMissing(): string {.role: parser.} =
  ## Names the first missing requirement, or "" when everything is there.
  if not defined(linux):
    return "the heap meter wraps glibc's malloc; run this on Linux"
  for t in ["nm", "size", "strip", "nim"]:
    if findExe(t).len == 0:
      return "`" & t & "` is not on PATH (binutils)"

proc main() {.role: metaOrchestrator.} =
  ## Build and measure every profile, break down one, write the README.
  var
    P: seq[LowmemProfile] = profiles()
    R: seq[LowmemRow] = @[]
    missing: string = toolsMissing()
    groups: seq[tuple[label: string, bytes: int]] = @[]
    body: string = ""
    i: int = 0
  if missing.len > 0:
    echo "bench_lowmem_sizes skipped: ", missing
    return
  createDir(repoRoot / buildDir)
  while i < P.len:
    if P[i].flags.contains("-d:tyrSimd=avx2") and not hasAvx2():
      R.add(LowmemRow(name: P[i].name, note: "skipped: no AVX2 on this CPU"))
    else:
      R.add(measure(P[i], i))
    echo rowLine(R[^1])
    i = i + 1
  discard buildProbe(P[referenceProfile], 99)
  groups = moduleSizes(outName(99))
  body = "```text\n" & profileTable(R) & "\n```\n\nCode per module, " &
    "profile \"" & P[referenceProfile].name & "\":\n\n```text\n" &
    moduleTable(groups) & "\n```"
  echo body
  writeReadme(body)

when isMainModule:
  main()
