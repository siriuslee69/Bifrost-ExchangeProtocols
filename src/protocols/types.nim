# ==================================================
# | Bifrost Types <- shared protocol metadata types |
# ==================================================

import bifrostPragmas
type
  ## ByteSeq: generic byte sequence payload.
  ByteSeq* = seq[uint8]

  ## ProtocolId: unique protocol identifier.
  ProtocolId* = string

  ## ProtocolVersion: protocol version number.
  ProtocolVersion* = uint16

  ## ProtocolKind: high-level protocol kind.
  ProtocolKind* = enum
    pkUnknown,
    pkTransport,
    pkSnapshot,
    pkDelta,
    pkStateSync,
    pkControl

  ## ProtocolCapabilities: feature flags for a protocol.
  ## supportsCompression: compression support.
  ## supportsEncryption: encryption support.
  ## supportsReliability: reliable delivery support.
  ## supportsAck: explicit ack support.
  ProtocolCapabilities* {.role: configurator.} = object
    supportsCompression*: bool
    supportsEncryption*: bool
    supportsReliability*: bool
    supportsAck*: bool

  ## ProtocolDescriptor: protocol metadata.
  ## protocolId: stable protocol identifier.
  ## name: display name.
  ## kind: protocol kind.
  ## version: current protocol version.
  ## minVersion: minimum supported protocol version.
  ## capabilities: supported protocol features.
  ProtocolDescriptor* {.role: configurator.} = object
    protocolId*: ProtocolId
    name*: string
    kind*: ProtocolKind
    version*: ProtocolVersion
    minVersion*: ProtocolVersion
    capabilities*: ProtocolCapabilities
