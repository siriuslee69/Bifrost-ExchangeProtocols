## Bifrost Repo Hygiene Tool <- generated artifact check + cleanup

import std/[os, parseopt, strutils]
import runePragmas

type
  HygieneFindingKind* = enum
    hfkGenerated
    hfkLocal

  HygieneFinding* = object
    relPath*: string
    isDir*: bool
    kind*: HygieneFindingKind
    cleanable*: bool

const
  GeneratedRoots = [
    "build",
    "builds",
    "nimcache",
    ".nimcache",
    ".nimble_cache",
    "nimbledeps",
    ".gradle",
    ".kotlin",
    "evaluation/tests/output",
    "evaluation/tests/outputs",
    "evaluation/tests/results",
    "test-results",
    "tmp",
    "temp"
  ]
  LocalFiles = [
    "local.properties",
    "userconfig.toml"
  ]
  SourceArtifactRoots = [
    "src",
    "evaluation",
    "examples",
    "tools"
  ]
  NestedGeneratedDirNames = [
    "build",
    "builds",
    "nimcache",
    ".nimcache",
    ".nimble_cache",
    ".gradle",
    ".kotlin",
    ".cxx",
    "test-results",
    "tmp",
    "temp"
  ]
  GeneratedExts = [
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".o",
    ".obj",
    ".a",
    ".lib",
    ".pdb",
    ".ilk",
    ".idb",
    ".exp"
  ]
  RootGeneratedPrefixes = [
    "tmp_bifrost"
  ]

proc normalizedRoot*(root: string): string {.role: sanitizer.} =
  var
    t: string = absolutePath(root)
  t = t.replace('\\', '/')
  result = t

proc relPathFrom*(root, path: string): string {.role: helper.} =
  var
    absRoot: string = normalizedRoot(root)
    absPath: string = absolutePath(path)
  absPath = absPath.replace('\\', '/')
  result = relativePath(absPath, absRoot).replace('\\', '/')

proc hasGeneratedExt(path: string): bool {.role: parser.} =
  var
    lower: string = path.toLowerAscii()
    i: int = 0
  while i < GeneratedExts.len:
    if lower.endsWith(GeneratedExts[i]):
      return true
    i.inc

proc isSourceArtifact(path: string): bool {.role: parser.} =
  var parts: tuple[dir, name, ext: string] = splitFile(path)
  if hasGeneratedExt(path):
    return true
  if parts.ext.len == 0:
    return fileExists(path & ".nim")

proc isNestedGeneratedDirName(name: string): bool {.role: parser.} =
  var
    lower: string = name.toLowerAscii()
    i: int = 0
  while i < NestedGeneratedDirNames.len:
    if lower == NestedGeneratedDirNames[i]:
      return true
    i = i + 1

proc addFinding(S: var seq[HygieneFinding]; relPath: string; isDir: bool;
    kind: HygieneFindingKind; cleanable: bool) {.role: helper.} =
  ## S/relPath/isDir/kind/cleanable: one more finding.
  S.add(HygieneFinding(relPath: relPath, isDir: isDir, kind: kind,
    cleanable: cleanable))

proc addSourceRootFindings(root, dir: string,
    S: var seq[HygieneFinding]) {.role: truthBuilder.} =
  ## root/dir/S: build output left inside a source folder, walked down.
  var
    relPath: string = ""
    generatedDir: bool = false
  for kind, p in walkDir(dir):
    relPath = relPathFrom(root, p)
    generatedDir = kind == pcDir and
      isNestedGeneratedDirName(splitPath(relPath).tail)
    if generatedDir:
      S.addFinding(relPath, true, hfkGenerated, true)
    elif kind == pcDir:
      addSourceRootFindings(root, p, S)
    elif isSourceArtifact(p):
      S.addFinding(relPath, false, hfkGenerated, true)

proc isRootBinary(relPath: string): bool {.role: parser.} =
  ## relPath: a file at the repo root. True for a built program:
  ## `bifrost_exchange_protocols` or `bifrost_exchange_protocols_*`, with no
  ## extension or a build extension.
  var
    parts: tuple[dir, name, ext: string] = splitFile(relPath)
  result = (parts.name == "bifrost_exchange_protocols" or
    parts.name.startsWith("bifrost_exchange_protocols_")) and
    (parts.ext.len == 0 or hasGeneratedExt(relPath))

proc addRootEntryFindings(S: var seq[HygieneFinding], relPath: string,
    kind: PathComponent) {.role: truthBuilder.} =
  ## S/relPath/kind: one entry at the repo root that build output left.
  var
    name: string = splitPath(relPath).tail
  for prefix in RootGeneratedPrefixes:
    if name.startsWith(prefix):
      S.addFinding(relPath, kind == pcDir, hfkGenerated, true)
  if kind == pcFile and isRootBinary(relPath):
    S.addFinding(relPath, false, hfkGenerated, true)
  if relPath == "result" or relPath.startsWith("result-"):
    S.addFinding(relPath, kind == pcDir, hfkGenerated, true)

proc repoHygieneFindings*(root: string): seq[HygieneFinding] {.
    role: truthBuilder.} =
  ## root: everything in the checkout that is build output or local-only.
  var
    absPath: string = ""
  for relRoot in GeneratedRoots:
    absPath = joinPath(root, relRoot)
    if dirExists(absPath) or fileExists(absPath):
      result.addFinding(relRoot, dirExists(absPath), hfkGenerated, true)
  for relFile in LocalFiles:
    if fileExists(joinPath(root, relFile)):
      result.addFinding(relFile, false, hfkLocal, true)
  for relRoot in SourceArtifactRoots:
    if dirExists(joinPath(root, relRoot)):
      addSourceRootFindings(root, joinPath(root, relRoot), result)
  for kind, p in walkDir(root):
    addRootEntryFindings(result, relPathFrom(root, p), kind)

proc removeFinding*(root: string; finding: HygieneFinding) {.role: actor.} =
  ## root/finding: deleted from disk, if it is still there.
  var
    absPath: string = joinPath(root, finding.relPath)
  if finding.isDir and dirExists(absPath):
    removeDir(absPath)
  if not finding.isDir and fileExists(absPath):
    removeFile(absPath)

proc renderFindings*(root: string;
    findings: openArray[HygieneFinding]): string {.role: dataWriter.} =
  ## root/findings: the report, one line per finding.
  result.add("repo root: " & normalizedRoot(root) & "\n")
  if findings.len == 0:
    result.add("status: clean\n")
    return
  result.add("status: generated or local artifacts present\n")
  for finding in findings:
    case finding.kind
    of hfkGenerated:
      result.add((if finding.isDir: "dir: " else: "file: ") & finding.relPath & "\n")
    of hfkLocal:
      result.add("local: " & finding.relPath & "\n")

proc readOption(key, val: string, root: var string, clean: var bool) {.
    role: parser.} =
  ## key/val: one `--root=DIR` or `--clean`; anything else stops the tool.
  case key.toLowerAscii().strip()
  of "root":
    root = val
  of "clean":
    clean = true
  else:
    stderr.writeLine("unknown option: " & key)
    quit(1)

proc cleanFindings(root: string, findings: seq[HygieneFinding]) {.
    role: actor.} =
  ## root/findings: every cleanable finding removed.
  for finding in findings:
    if finding.cleanable:
      removeFinding(root, finding)

proc main() {.role: metaOrchestrator.} =
  var
    parser = initOptParser(commandLineParams())
    root: string = getCurrentDir()
    clean: bool = false
    findings: seq[HygieneFinding] = @[]
  parser.next()
  while parser.kind != cmdEnd:
    if parser.kind == cmdArgument:
      stderr.writeLine("unexpected argument: " & parser.key)
      quit(1)
    readOption(parser.key, parser.val, root, clean)
    parser.next()
  root = normalizedRoot(root)
  findings = repoHygieneFindings(root)
  if clean:
    cleanFindings(root, findings)
    findings = repoHygieneFindings(root)
  stdout.write(renderFindings(root, findings))
  if findings.len > 0:
    quit(2)

when isMainModule:
  main()
