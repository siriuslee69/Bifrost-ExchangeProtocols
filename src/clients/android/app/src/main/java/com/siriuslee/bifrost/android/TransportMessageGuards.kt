package com.siriuslee.bifrost.android

internal fun requireTransportMessageProtocol(
  message: BifrostMessage,
  expected: ProtocolKind,
  context: String,
) {
  require(message.protocol == expected) {
    "$context expected ${expected.label} protocol message"
  }
}

internal fun requireTransportAckMessage(
  message: BifrostMessage,
  expected: ProtocolKind,
  context: String,
) {
  requireTransportMessageProtocol(message, expected, context)
  require(message.isAck) {
    "$context expected ack message"
  }
}
