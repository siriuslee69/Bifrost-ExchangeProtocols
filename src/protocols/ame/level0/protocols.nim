## -------------------------------------------------------------------------
## AME Protocol <- descriptor for immutable layouts and mask tiers
## -------------------------------------------------------------------------

import ../../types
import ../types
import ../../../analysis_pragmas

const
  ameProtocolId* = "bifrost.ame"

proc initAmeDescriptor*(): ProtocolDescriptor {.role: wrapper.} =
  ## Initialize the AME2 immutable-layout mask-tier protocol descriptor.
  result.protocolId = ameProtocolId
  result.name = "AME"
  result.kind = pkControl
  result.version = ameFormatVersion
  result.minVersion = ameFormatVersion
  result.capabilities.supportsEncryption = true
  result.capabilities.supportsReliability = false
  result.capabilities.supportsAck = true

proc initAmeSessionDescriptor*(): ProtocolDescriptor {.role: wrapper.} =
  ## Session-facing AME descriptor (encrypted live link).
  result.protocolId = ameSessionProtocolId
  result.name = "AME-Session"
  result.kind = pkTransport
  result.version = ameFormatVersion
  result.minVersion = ameFormatVersion
  result.capabilities.supportsCompression = true
  result.capabilities.supportsEncryption = true
  result.capabilities.supportsReliability = true
  result.capabilities.supportsAck = true
