## ---------------------------------------------------------------------
## DAC Protocols <- descriptor for Data Adaptive Connection
## ---------------------------------------------------------------------

import ../../types
import runePragmas

const
  dacProtocolId* = "transport.dac"
  dacProtocolName* = "DAC"
  dacProtocolLongName* = "Data Adaptive Connection"

proc initDacDescriptor*(): ProtocolDescriptor {.role: configurator.} =
  ## initDacDescriptor: initialize DAC descriptor.
  var
    d: ProtocolDescriptor
  d.protocolId = dacProtocolId
  d.name = dacProtocolName
  d.kind = pkTransport
  d.version = 1'u16
  d.minVersion = 1'u16
  d.capabilities.supportsCompression = false
  d.capabilities.supportsEncryption = false
  d.capabilities.supportsReliability = true
  d.capabilities.supportsAck = true
  result = d
