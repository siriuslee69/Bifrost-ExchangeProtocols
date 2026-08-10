## -----------------------------------------------------
## BFX2 Schema Ids <- shared reserved schema identifiers
## -----------------------------------------------------

import ../../analysis_pragmas
const
  schemaExternalReservedStart* = 400'u16
  schemaExternalReservedEnd* = 899'u16

  ## Reserved external block for Ermine IoT payload schemas.
  schemaErmineReservedStart* = 400'u16
  schemaErmineReservedEnd* = 499'u16

proc isExternalSchemaId*(sid: uint16): bool {.inline, role: wrapper.} =
  ## True when schema id is in reserved external range.
  result = sid >= schemaExternalReservedStart and sid <= schemaExternalReservedEnd

proc isErmineSchemaId*(sid: uint16): bool {.inline, role: wrapper.} =
  ## True when schema id is in Ermine-reserved external range.
  result = sid >= schemaErmineReservedStart and sid <= schemaErmineReservedEnd
