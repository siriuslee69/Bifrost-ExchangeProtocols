## -----------------------------------------------------------
## BFX2 External Bridge <- official extension envelope contract
## -----------------------------------------------------------

import ../types
import ./types
import ./schema_ids
import ./writer
import ./reader
import ../../analysis_pragmas

proc validateExternalEnvelope*(schemaId: uint16): tuple[ok: bool, err: string] {.role: parser.} =
  ## Validate that schema id is in reserved external range.
  if not isExternalSchemaId(schemaId):
    return (false, "bfx2: schema id is outside external reserved range")
  result = (true, "")

proc encodeExternalEnvelope*(
    schemaId: uint16;
    schemaVersion: uint16;
    payload: ByteSeq;
    flags: uint16 = bfxFlagChecksum
): tuple[ok: bool, packet: ByteSeq, err: string] {.role: wrapper.} =
  ## Encode external envelope into BFX2 wire packet.
  var
    v: tuple[ok: bool, err: string] = validateExternalEnvelope(schemaId)
  if not v.ok:
    return (false, @[], v.err)
  result = (true, encodeBfxEnvelope(schemaId, schemaVersion, payload, flags), "")

proc decodeExternalEnvelope*(bs: ByteSeq): ExternalDecodeResult {.role: parser.} =
  ## Decode BFX2 wire packet and validate external schema range.
  var
    d: tuple[ok: bool, header: BfxHeader, payload: ByteSeq, err: string]
    v: tuple[ok: bool, err: string]
  d = decodeBfxEnvelope(bs)
  if not d.ok:
    return (false, (0'u16, 0'u16, 0'u16, @[]), d.err)
  v = validateExternalEnvelope(d.header.schemaId)
  if not v.ok:
    return (false, (0'u16, 0'u16, 0'u16, @[]), v.err)
  result.ok = true
  result.envelope.schemaId = d.header.schemaId
  result.envelope.schemaVersion = d.header.schemaVersion
  result.envelope.flags = d.header.flags
  result.envelope.payload = d.payload
  result.err = ""

