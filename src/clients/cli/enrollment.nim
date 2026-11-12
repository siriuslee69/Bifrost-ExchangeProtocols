## -------------------------------------------------------------------------
## Enrollment CLI <- the operator admits public keys into a group roster
## -------------------------------------------------------------------------
##
## Run from the repo root:
##   nim c -r src/clients/cli/enrollment.nim <command> ...
##
##   init <file> [name]        make a roster + a fresh enroller; the enroller's
##                             secret half goes to <file>.key (protect it)
##   add <file> <key-id>       admit a public key by hand (32 hex characters)
##   list <file>               show the enroller and both key lists
##   remove <file> <key-id>    take a hand-added key back out
##
## This is an operator tool, not one of the multi-device test clients. It is
## the only part of enrollment that touches a disk: the protocol module itself
## stays bytes-in, bytes-out. The roster file is the binary roster codec.

import std/[os, strutils]

import ../../protocols/types
import ../../protocols/byte_codec
import ../../protocols/ame/types
import ../../protocols/ame/level3/handshake_identity
import ../../protocols/enrollment
import runePragmas

proc printUsage() {.role: actor, tag: "enrollment|cli".} =
  ## The help text, one line at a time.
  echo "enrollment - the operator admits public keys into a group roster"
  echo "  init FILE [NAME]   make a roster and a fresh enroller; the secret"
  echo "                     half goes to FILE.key (protect it)"
  echo "  add FILE KEYID     admit a public key by hand (32 hex characters)"
  echo "  list FILE          show the enroller and both key lists"
  echo "  remove FILE KEYID  take a hand-added key back out"

proc fileBytes(path: string): tuple[ok: bool, bytes: ByteSeq, err: string] {.
    role: dataFetcher, tag: "enrollment|cli".} =
  ## path: the file to read, as bytes. ok=false when it cannot be read.
  var
    s: string = ""
  if not fileExists(path):
    return (ok: false, bytes: @[], err: "no such file: " & path)
  try:
    s = readFile(path)
  except CatchableError as e:
    return (ok: false, bytes: @[], err: "cannot read " & path & ": " & e.msg)
  result = (ok: true, bytes: stringToBytes(s), err: "")

proc writeFileBytes(path: string, B: ByteSeq): tuple[ok: bool, err: string] {.
    role: dataWriter, tag: "enrollment|cli".} =
  ## path/B: where to write, and the bytes. ok=false when it cannot be written.
  try:
    writeFile(path, bytesToString(B))
  except CatchableError as e:
    return (ok: false, err: "cannot write " & path & ": " & e.msg)
  result = (ok: true, err: "")

proc loadRoster(path: string): tuple[ok: bool, roster: GroupRoster,
    err: string] {.role: orchestrator, tag: "enrollment|cli".} =
  ## path: read and decode the roster file.
  var
    got: tuple[ok: bool, bytes: ByteSeq, err: string] = (false, @[], "")
  got = fileBytes(path)
  if not got.ok:
    return (ok: false, roster: GroupRoster(), err: got.err)
  result = decodeGroupRoster(got.bytes)

proc cmdInit(file, name: string): tuple[ok: bool, err: string] {.
    role: orchestrator, tag: "enrollment|cli".} =
  ## file/name: make a roster with a fresh enroller; keep the secret apart.
  var
    enroller: AmeAuthorityKey = initAmeAuthorityKey(name)
    R: GroupRoster = initGroupRoster(initAmeAuthorityRoot(enroller))
    wrote: tuple[ok: bool, err: string] = (false, "")
  if fileExists(file):
    return (ok: false, err: "refusing to overwrite " & file)
  if fileExists(file & ".key"):
    return (ok: false, err: "refusing to overwrite " & file & ".key")
  wrote = writeFileBytes(file, encodeGroupRoster(R))
  if not wrote.ok:
    return wrote
  wrote = writeFileBytes(file & ".key", encodeGroupEnroller(enroller))
  if not wrote.ok:
    return wrote
  echo "created roster ", file, " and enroller secret ", file, ".key"
  echo "enroller key id: ", ameIdentityKeyId(enroller.signingKeys)
  echo "protect ", file, ".key: whoever holds it can enroll keys"
  result = (ok: true, err: "")

proc cmdAdd(file, keyId: string): tuple[ok: bool, err: string] {.
    role: orchestrator, tag: "enrollment|cli".} =
  ## file/keyId: admit this public key by hand, then save the roster.
  var
    got: tuple[ok: bool, roster: GroupRoster, err: string] = (false,
      GroupRoster(), "")
    added: tuple[ok: bool, err: string] = (false, "")
    wrote: tuple[ok: bool, err: string] = (false, "")
  got = loadRoster(file)
  if not got.ok:
    return (ok: false, err: got.err)
  added = addRosterKey(got.roster, keyId)
  if not added.ok:
    return added
  wrote = writeFileBytes(file, encodeGroupRoster(got.roster))
  if not wrote.ok:
    return wrote
  echo "added ", keyId
  result = (ok: true, err: "")

proc cmdList(file: string): tuple[ok: bool, err: string] {.
    role: orchestrator, tag: "enrollment|cli".} =
  ## file: show the enroller and both key lists.
  var
    got: tuple[ok: bool, roster: GroupRoster, err: string] = (false,
      GroupRoster(), "")
    i: int = 0
  got = loadRoster(file)
  if not got.ok:
    return (ok: false, err: got.err)
  echo "enroller:   ", got.roster.enroller.authority
  echo "predefined: ", got.roster.predefined.len
  while i < got.roster.predefined.len:
    echo "  ", got.roster.predefined[i]
    i = i + 1
  echo "added:      ", got.roster.added.len
  i = 0
  while i < got.roster.added.len:
    echo "  ", got.roster.added[i]
    i = i + 1
  result = (ok: true, err: "")

proc cmdRemove(file, keyId: string): tuple[ok: bool, err: string] {.
    role: orchestrator, tag: "enrollment|cli".} =
  ## file/keyId: take this hand-added key back out, then save the roster.
  var
    got: tuple[ok: bool, roster: GroupRoster, err: string] = (false,
      GroupRoster(), "")
    removed: tuple[ok: bool, err: string] = (false, "")
    wrote: tuple[ok: bool, err: string] = (false, "")
  got = loadRoster(file)
  if not got.ok:
    return (ok: false, err: got.err)
  removed = removeRosterKey(got.roster, keyId)
  if not removed.ok:
    return removed
  wrote = writeFileBytes(file, encodeGroupRoster(got.roster))
  if not wrote.ok:
    return wrote
  echo "removed ", keyId
  result = (ok: true, err: "")

proc run(args: openArray[string]): tuple[ok: bool, err: string] {.
    role: orchestrator, tag: "enrollment|cli".} =
  ## args: the command line after the program name.
  if args.len == 0:
    printUsage()
    return (ok: false, err: "no command given")
  case args[0]
  of "init":
    if args.len == 2:
      return cmdInit(args[1], "enroller")
    if args.len == 3:
      return cmdInit(args[1], args[2])
    return (ok: false, err: "usage: init FILE [NAME]")
  of "add":
    if args.len != 3:
      return (ok: false, err: "usage: add FILE KEYID")
    return cmdAdd(args[1], args[2])
  of "list":
    if args.len != 2:
      return (ok: false, err: "usage: list FILE")
    return cmdList(args[1])
  of "remove":
    if args.len != 3:
      return (ok: false, err: "usage: remove FILE KEYID")
    return cmdRemove(args[1], args[2])
  else:
    printUsage()
    return (ok: false, err: "unknown command: " & args[0])

proc main(): int {.role: orchestrator, tag: "enrollment|cli".} =
  var
    args: seq[string] = @[]
    i: int = 1
    got: tuple[ok: bool, err: string] = (false, "")
  while i <= paramCount():
    args.add(paramStr(i))
    i = i + 1
  got = run(args)
  if not got.ok:
    echo "error: ", got.err
    return 1
  result = 0

when isMainModule:
  quit(main())