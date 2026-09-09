## ----------------------------------------------------------
## Transport Protocols <- built-in descriptor helpers
## ----------------------------------------------------------

import ../types
import runePragmas

const
  tcpTransportProtocolId* = "transport.tcp"
  tcpTransportProtocolName* = "TCP"
  udpTransportProtocolId* = "transport.udp"
  udpTransportProtocolName* = "UDP"
  tlsTransportProtocolId* = "transport.tls"
  tlsTransportProtocolName* = "TLS"

proc initTransportDescriptor(p: ProtocolId, n: string, e, r, a: bool):
    ProtocolDescriptor {.role: helper.} =
  ## initTransportDescriptor: initialize transport descriptor.
  var
    d: ProtocolDescriptor
  d.protocolId = p
  d.name = n
  d.kind = pkTransport
  d.version = 1'u16
  d.minVersion = 1'u16
  d.capabilities.supportsCompression = false
  d.capabilities.supportsEncryption = e
  d.capabilities.supportsReliability = r
  d.capabilities.supportsAck = a
  result = d

proc initTcpTransportDescriptor*(): ProtocolDescriptor {.role: configurator.} =
  ## initTcpTransportDescriptor: initialize TCP transport descriptor.
  result = initTransportDescriptor(tcpTransportProtocolId,
    tcpTransportProtocolName, false, true, false)

proc initUdpTransportDescriptor*(): ProtocolDescriptor {.role: configurator.} =
  ## initUdpTransportDescriptor: initialize UDP transport descriptor.
  result = initTransportDescriptor(udpTransportProtocolId,
    udpTransportProtocolName, false, false, false)

proc initTlsTransportDescriptor*(): ProtocolDescriptor {.role: configurator.} =
  ## initTlsTransportDescriptor: initialize TLS transport descriptor.
  result = initTransportDescriptor(tlsTransportProtocolId,
    tlsTransportProtocolName, true, true, false)

proc listBasicTransportDescriptors*(): seq[ProtocolDescriptor] {.role: truthBuilder.} =
  ## listBasicTransportDescriptors: build list basic transport descriptors.
  result = @[
    initTcpTransportDescriptor(),
    initUdpTransportDescriptor(),
    initTlsTransportDescriptor()
  ]
