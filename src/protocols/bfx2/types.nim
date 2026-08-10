## ---------------------------------------------------------
## BFX2 Types <- wire constants and shared binary structures
## ---------------------------------------------------------

import ../types
import ../../analysis_pragmas

const
  bfxMagic* = [uint8('B'), uint8('F'), uint8('X'), uint8('2')]
  ## BFX2 v1 checks only the fixed header and is deliberately rejected. v2
  ## checks the complete envelope prefix and payload when bfxFlagChecksum is
  ## set, so current decoders never silently accept a weak checksum scope.
  bfxFormatVersion* = 2'u16

  bfxFlagChecksum* = 0x0001'u16
  bfxFlagCompressed* = 0x0002'u16
  bfxFlagEncrypted* = 0x0004'u16

  bfxHeaderLen* = 20
  bfxMaxEnvelopePayloadBytes* = 16_777_216
  bfxMaxValuePacketBytes* = 16_777_216
  bfxMaxCollectionEntries* = 1_000_000
  bfxMaxNestingDepth* = 64

type
  BfxWireType* = enum
    bfxWtUnknown = 0x00'u8,
    bfxWtU8 = 0x01'u8,
    bfxWtU16 = 0x02'u8,
    bfxWtU32 = 0x03'u8,
    bfxWtU64 = 0x04'u8,
    bfxWtI8 = 0x05'u8,
    bfxWtI16 = 0x06'u8,
    bfxWtI32 = 0x07'u8,
    bfxWtI64 = 0x08'u8,
    bfxWtF32 = 0x09'u8,
    bfxWtF64 = 0x0A'u8,
    bfxWtBool = 0x0B'u8,
    bfxWtBytes = 0x0C'u8,
    bfxWtString = 0x0D'u8,
    bfxWtEnum = 0x0E'u8,
    bfxWtObject = 0x0F'u8,
    bfxWtSeq = 0x10'u8,
    bfxWtOption = 0x11'u8

  BfxHeader* {.role: truthState.} = object
    magic*: array[4, uint8]
    formatVersion*: uint16
    schemaId*: uint16
    schemaVersion*: uint16
    flags*: uint16
    payloadLen*: uint32
    headerChecksum*: uint32

  BfxField* {.role: truthState.} = object
    fieldId*: uint16
    fieldName*: string
    wireType*: BfxWireType
    value*: ByteSeq

  ## ExternalEnvelope: generic external protocol envelope over BFX2.
  ExternalEnvelope* {.role: truthState.} = tuple[
    schemaId: uint16,
    schemaVersion: uint16,
    flags: uint16,
    payload: ByteSeq
  ]

  ## ExternalDecodeResult: decode result for extension bridge.
  ExternalDecodeResult* {.role: truthState.} = tuple[
    ok: bool,
    envelope: ExternalEnvelope,
    err: string
  ]
