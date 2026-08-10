## ---------------------------------------------------
## BFX2 Errors <- stable error constants for decoders
## ---------------------------------------------------

const
  bfxErrEmptyInput* = "bfx2: empty input"
  bfxErrHeaderTooShort* = "bfx2: input shorter than header"
  bfxErrBadMagic* = "bfx2: invalid magic"
  bfxErrUnsupportedFormatVersion* = "bfx2: unsupported format version"
  bfxErrHeaderChecksumMismatch* = "bfx2: header checksum mismatch"
  bfxErrChecksumMismatch* = "bfx2: envelope checksum mismatch"
  bfxErrPayloadLengthMismatch* = "bfx2: payload length mismatch"
  bfxErrResourceLimit* = "bfx2: decoder resource limit exceeded"
  bfxErrTruncated* = "bfx2: truncated payload"
  bfxErrInvalidBoolField* = "bfx2: invalid bool field"
  bfxErrInvalidWireType* = "bfx2: invalid wire type"
  bfxErrIntegerOutOfRange* = "bfx2: integer out of range"
  bfxErrInvalidObjectField* = "bfx2: invalid object field"
  bfxErrInvalidSequenceField* = "bfx2: invalid sequence field"
  bfxErrInvalidOptionField* = "bfx2: invalid option field"
