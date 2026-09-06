## ------------------------------------------------------
## Generate BFX2 Vectors <- deterministic committed fixtures
## ------------------------------------------------------

import std/[json, os, strutils]

import bifrost_exchange_protocols

proc bytesToHex(bs: ByteSeq): string =
  var i = 0
  while i < bs.len:
    result.add(toHex(int(bs[i]), 2))
    i.inc

proc writeVector(path: string; content: string) =
  createDir(parentDir(path))
  writeFile(path, content)

proc main() =
  let repoRoot = getCurrentDir()
  let vectorsRoot = joinPath(repoRoot, "evaluation", "tests", "vectors")

  let helloPayload = %*{
    "kind": "hello",
    "fromNode": "node-a",
    "toNode": "node-b",
    "sentAt": 55,
    "payloadHash": [1, 2, 3],
    "payload": [10, 20, 30]
  }
  let helloSchemaId = 900'u16
  let helloSchemaVersion = 1'u16
  let helloFlags = bfxFlagChecksum
  let helloPacket = encodeBfxEnvelope(
    helloSchemaId,
    helloSchemaVersion,
    encodeJsonNodePacket(helloPayload),
    helloFlags
  )
  let helloMeta = %*{
    "schemaId": helloSchemaId,
    "schemaVersion": helloSchemaVersion,
    "flags": helloFlags,
    "payload": helloPayload,
    "notes": "Generic BFX2 envelope vector for Nim and TS parity."
  }
  writeVector(
    joinPath(vectorsRoot, "bfx2", "hello_payload_v2.hex"),
    bytesToHex(helloPacket) & "\n"
  )
  writeVector(
    joinPath(vectorsRoot, "bfx2", "hello_payload_v2.json"),
    helloMeta.pretty() & "\n"
  )
  writeVector(
    joinPath(vectorsRoot, "bfx2", "README.md"),
    "# BFX2 Cross-Language Vectors\n\n" &
    "This folder stores deterministic vectors for Nim <-> TS BFX2 parity.\n\n" &
    "- `hello_payload_v2.hex`: current BFX2 envelope with a payload-bound checksum.\n" &
    "- `hello_payload_v2.json`: source schema metadata and payload used to generate the vector.\n"
  )

  let externalPayload: ByteSeq = @[1'u8, 2'u8, 3'u8]
  let externalSchemaId = 410'u16
  let externalSchemaVersion = 1'u16
  let externalFlags = bfxFlagChecksum
  let externalEncoded = encodeExternalEnvelope(
    externalSchemaId,
    externalSchemaVersion,
    externalPayload,
    externalFlags
  )
  if not externalEncoded.ok:
    raise newException(ValueError, externalEncoded.err)
  let externalMeta = %*{
    "schemaId": externalSchemaId,
    "schemaVersion": externalSchemaVersion,
    "flags": externalFlags,
    "payloadHex": bytesToHex(externalPayload),
    "notes": "BFX2 external bridge vector for the Ermine reserved schema block."
  }
  writeVector(
    joinPath(vectorsRoot, "bfx2_external", "ermine_schema_410_v2.hex"),
    bytesToHex(externalEncoded.packet) & "\n"
  )
  writeVector(
    joinPath(vectorsRoot, "bfx2_external", "ermine_schema_410_v2.json"),
    externalMeta.pretty() & "\n"
  )

main()
