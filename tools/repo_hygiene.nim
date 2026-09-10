## Bifrost Repo Hygiene Tool <- generated artifact check + cleanup

import std/[os, parseopt, strutils]

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

proc normalizedRoot*(root: string): string =
  var
    t: string = absolutePath(root)
  t = t.replace('\\', '/')
  result = t

proc relPathFrom*(root, path: string): string =
  var
    absRoot: string = normalizedRoot(root)
    absPath: string = absolutePath(path)
  absPath = absPath.replace('\\', '/')
  result = relativePath(absPath, absRoot).replace('\\', '/')

proc hasGeneratedExt(path: string): bool =
  var
    lower: string = path.toLowerAscii()
    i: int = 0
  while i < GeneratedExts.len:
    if lower.endsWith(GeneratedExts[i]):
      return true
    i.inc

proc siblingNimPath(path: string): string =
  var parts: tuple[dir, name, ext: string] = splitFile(path)
  result = joinPath(parts.dir, parts.name & ".nim")

proc isSourceArtifact(path: string): bool =
  var parts: tuple[dir, name, ext: string] = splitFile(path)
  if hasGeneratedExt(path):
    return true
  if parts.ext.len == 0:
    return fileExists(path & ".nim")

proc isNestedGeneratedDirName(name: string): bool =
  var
    lower: string = name.toLowerAscii()
    i: int = 0
  while i < NestedGeneratedDirNames.len:
    if lower == NestedGeneratedDirNames[i]:
      return true
    i = i + 1

proc addFinding(S: var seq[HygieneFinding]; relPath: string; isDir: bool;
    kind: HygieneFindingKind; cleanable: bool)

proc addSourceRootFindings(root, dir: string, S: var seq[HygieneFinding]) =
  var
    relPath: string = ""
    name: string = ""
  for kind, p in walkDir(dir):
    relPath = relPathFrom(root, p)
    name = splitPath(relPath).tail
    if kind == pcDir:
      if isNestedGeneratedDirName(name):
        S.addFinding(relPath, true, hfkGenerated, true)
      else:
        addSourceRootFindings(root, p, S)
    elif isSourceArtifact(p):
      S.addFinding(relPath, false, hfkGenerated, true)

proc addFinding(S: var seq[HygieneFinding]; relPath: string; isDir: bool;
    kind: HygieneFindingKind; cleanable: bool) =
  S.add(HygieneFinding(
    relPath: relPath,
    isDir: isDir,
    kind: kind,
    cleanable: cleanable
  ))

proc repoHygieneFindings*(root: string): seq[HygieneFinding] =
  var
    absPath: string = ""
    relPath: string = ""
    scanRoot: string = ""
    name: string = ""
  for relRoot in GeneratedRoots:
    absPath = joinPath(root, relRoot)
    if dirExists(absPath):
      result.addFinding(relRoot, true, hfkGenerated, true)
    elif fileExists(absPath):
      result.addFinding(relRoot, false, hfkGenerated, true)

  for relFile in LocalFiles:
    absPath = joinPath(root, relFile)
    if fileExists(absPath):
      result.addFinding(relFile, false, hfkLocal, true)

  if dirExists(joinPath(root, ".iron")):
    for p in walkDirRec(joinPath(root, ".iron")):
      relPath = relPathFrom(root, p)
      if relPath.contains("/.local") and not relPath.endsWith(".template"):
        result.addFinding(relPath, false, hfkLocal, true)

  for relRoot in SourceArtifactRoots:
    scanRoot = joinPath(root, relRoot)
    if not dirExists(scanRoot):
      continue
    addSourceRootFindings(root, scanRoot, result)

  for kind, p in walkDir(root):
    relPath = relPathFrom(root, p)
    name = splitPath(relPath).tail
    for prefix in RootGeneratedPrefixes:
      if name.startsWith(prefix):
        result.addFinding(relPath, kind == pcDir, hfkGenerated, true)
    if kind == pcFile:
      var parts: tuple[dir, name, ext: string] = splitFile(relPath)
      if parts.name == "bifrost_exchange_protocols" and
          (parts.ext.len == 0 or hasGeneratedExt(relPath)):
        result.addFinding(relPath, false, hfkGenerated, true)
      elif parts.name.startsWith("bifrost_exchange_protocols_") and
          (parts.ext.len == 0 or hasGeneratedExt(relPath)):
        result.addFinding(relPath, false, hfkGenerated, true)
    if relPath == "result" or relPath.startsWith("result-"):
      result.addFinding(relPath, kind == pcDir, hfkGenerated, true)

proc removeFinding*(root: string; finding: HygieneFinding) =
  var absPath: string = joinPath(root, finding.relPath)
  if finding.isDir:
    if dirExists(absPath):
      removeDir(absPath)
  elif fileExists(absPath):
    removeFile(absPath)

proc renderFindings*(root: string; findings: openArray[HygieneFinding]): string =
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

proc main() =
  var
    parser = initOptParser(commandLineParams())
    root: string = getCurrentDir()
    clean: bool = false
    findings: seq[HygieneFinding] = @[]
  while true:
    parser.next()
    case parser.kind
    of cmdEnd:
      break
    of cmdLongOption, cmdShortOption:
      case parser.key.toLowerAscii().strip()
      of "root":
        root = parser.val
      of "clean":
        clean = true
      else:
        stderr.writeLine("unknown option: " & parser.key)
        quit(1)
    of cmdArgument:
      stderr.writeLine("unexpected argument: " & parser.key)
      quit(1)
  root = normalizedRoot(root)
  findings = repoHygieneFindings(root)
  if clean:
    for finding in findings:
      if finding.cleanable:
        removeFinding(root, finding)
    findings = repoHygieneFindings(root)
  stdout.write(renderFindings(root, findings))
  if findings.len > 0:
    quit(2)

when isMainModule:
  main()
