## -------------------------------------------------------------------------
## FOMKE Protocol <- forward-only message key extension descriptor
## -------------------------------------------------------------------------

import ../../types
import ../types
import ../../../analysis_pragmas

const
  fomkeProtocolId* = "bifrost.fomke"
  fomkeProtocolLongName* = "Forward-Only Message Key Extension"

proc initFomkeDescriptor*(): ProtocolDescriptor {.role: configurator,
    metaTags: {tagAppApi, tagFomke, tagProtocol}.} =
  ## Return the FOM1 protocol descriptor.
  result.protocolId = fomkeProtocolId
  result.name = "FOMKE"
  result.kind = pkControl
  result.version = fomkeProtocolVersion
  result.minVersion = fomkeProtocolVersion
  result.capabilities.supportsEncryption = true
  result.capabilities.supportsReliability = false
  result.capabilities.supportsAck = true
