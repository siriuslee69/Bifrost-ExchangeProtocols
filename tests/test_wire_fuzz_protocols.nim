## ---------------------------------------------------------------------
## Protocol Fuzz <- the AME, BFX2 and TLS 1.3 decoders under mutated bytes
## ---------------------------------------------------------------------
##
## The DAC harness covers the datagram layer. These are the other three
## parsers an attacker reaches: the AME frame and protected body that wrap
## every session, the BFX2 envelope that carries structured data, and the
## TLS 1.3 record and handshake decoders.
##
## TLS matters most here. It is a hand-written implementation of a protocol
## whose length fields nest four deep -- record, handshake, message, then
## extension lists inside that -- and every one of those is attacker-chosen.
## The contract is the same everywhere: a value or a CatchableError, never a
## Defect, never a hang.

import unittest

import ../src/protocols/types
import ../src/protocols/ame/types
import ../src/protocols/ame/level2/wire
import ../src/protocols/ame/level2/session
import ../src/protocols/bfx2/types
import ../src/protocols/bfx2/writer
import ../src/protocols/bfx2/reader
import ../src/protocols/tls13/types
import ../src/protocols/tls13/codec
import ../src/protocols/tls13/hello
import ../src/protocols/tls13/handshake_messages
import ./fuzz_support

proc sampleAmeFrame(): ByteSeq =
  ## A well-formed AME frame carrying lane data.
  result = encodeAmeFrame(ampkLaneData, amcUserdata, 0x1122334455667788'u64,
    1'u32, 2'u32, 3'u32, 4'u32, rampBytes(96))

proc sampleAmeProtectedBody(): ByteSeq =
  ## A well-formed protected body with a 32-byte tag.
  var
    e: AmeProtectedBody
  e.epochId = 3'u32
  e.nonce = rampBytes(24)
  e.authTag = rampBytes(32)
  e.payload = rampBytes(128)
  result = encodeAmeProtectedBody(e)

proc sampleAmeSealedFrame(): ByteSeq =
  ## An AME frame whose payload is a protected body, which is the shape that
  ## actually arrives on the wire: two nested length fields, not one.
  var
    body: ByteSeq = sampleAmeProtectedBody()
  result = encodeAmeFrame(ampkLaneData, amcUserdata, 7'u64, 1'u32, 1'u32,
    1'u32, 9'u32, body)

suite "AME frame fuzz":
  test "the frame header decoder never raises a Defect":
    fuzzBody("decodeAmeFrameHeader", 101'u64, sampleAmeFrame()):
      discard decodeAmeFrameHeader(data)

  test "the frame decoder never raises a Defect":
    fuzzBody("decodeAmeFrame", 102'u64, sampleAmeFrame()):
      discard decodeAmeFrame(data)

  test "the protected body decoder never raises a Defect":
    fuzzBody("decodeAmeProtectedBody", 103'u64, sampleAmeProtectedBody()):
      discard decodeAmeProtectedBody(data)

  test "a nested frame plus body survives mutation at either depth":
    fuzzBody("decodeAmeFrame + body", 104'u64, sampleAmeSealedFrame()):
      discard decodeAmeProtectedBody(decodeAmeFrame(data).payload)

  test "a declared payload length far past the buffer is refused":
    var
      f: ByteSeq = sampleAmeFrame()
      i: int = 0
    f[32] = 0xFF'u8
    f[33] = 0xFF'u8
    f[34] = 0xFF'u8
    f[35] = 0x7F'u8
    expect CatchableError:
      discard decodeAmeFrame(f)
    while i < 4:
      f = sampleAmeProtectedBody()
      f[8 + i] = 0xFF'u8
      expect CatchableError:
        discard decodeAmeProtectedBody(f)
      i = i + 1

suite "BFX2 fuzz":
  test "the envelope decoder never raises a Defect":
    fuzzBody("decodeBfxEnvelope", 201'u64,
        encodeBfxEnvelope(7'u16, 2'u16, rampBytes(200))):
      discard decodeBfxEnvelope(data)

  test "a checksummed envelope never raises a Defect":
    fuzzBody("decodeBfxEnvelope checksummed", 202'u64,
        encodeBfxEnvelope(7'u16, 2'u16, rampBytes(200), bfxFlagChecksum)):
      discard decodeBfxEnvelope(data)

  test "the value packet decoder never raises a Defect":
    fuzzBody("decodeJsonNodePacket", 203'u64,
        encodeValuePacket(bfxWtBytes, rampBytes(64))):
      discard decodeJsonNodePacket(data)

suite "TLS 1.3 record fuzz":
  test "the record decoder never raises a Defect":
    fuzzBody("decodeTls13Record", 301'u64,
        encodeTls13Record(Tls13Record(contentType: tctHandshake,
        legacyVersion: 0x0303'u16, fragment: rampBytes(300)))):
      discard decodeTls13Record(data)

  test "an application-data record never raises a Defect":
    fuzzBody("decodeTls13Record appdata", 302'u64,
        encodeTls13Record(Tls13Record(contentType: tctApplicationData,
        legacyVersion: 0x0303'u16, fragment: rampBytes(1200)))):
      discard decodeTls13Record(data)

  test "the handshake decoder never raises a Defect":
    fuzzBody("decodeTls13Handshake", 303'u64,
        encodeTls13Handshake(Tls13Handshake(messageType: thtClientHello,
        body: rampBytes(400)))):
      discard decodeTls13Handshake(data)

  test "a record wrapping a handshake survives mutation at either depth":
    fuzzBody("record + handshake", 304'u64,
        encodeTls13Record(Tls13Record(contentType: tctHandshake,
        legacyVersion: 0x0303'u16,
        fragment: encodeTls13Handshake(Tls13Handshake(
          messageType: thtServerHello, body: rampBytes(90)))))):
      discard decodeTls13Handshake(decodeTls13Record(data).record.fragment)

suite "TLS 1.3 handshake message fuzz":
  test "the ClientHello decoder never raises a Defect":
    var
      H: Tls13ClientHello
      i: int = 0
    while i < 32:
      H.random[i] = byte(i)
      i = i + 1
    H.legacySessionId = rampBytes(32)
    H.serverName = "fuzz.example.invalid"
    H.alpn = @["h2", "http/1.1"]
    H.x25519PublicKey = rampBytes(32)
    H.signatureSchemes = @[0x0804'u16, 0x0403'u16, 0x0805'u16]
    fuzzBody("decodeTls13ClientHello", 401'u64, encodeTls13ClientHello(H)):
      discard decodeTls13ClientHello(data)

  test "the ServerHello decoder never raises a Defect":
    var
      H: Tls13ServerHello
      i: int = 0
    while i < 32:
      H.random[i] = byte(255 - i)
      i = i + 1
    H.legacySessionId = rampBytes(32)
    H.x25519PublicKey = rampBytes(32)
    fuzzBody("decodeTls13ServerHello", 402'u64, encodeTls13ServerHello(H)):
      discard decodeTls13ServerHello(data)

  test "the EncryptedExtensions decoder never raises a Defect":
    fuzzBody("decodeTls13EncryptedExtensions", 403'u64,
        decodeTls13Handshake(encodeTls13EncryptedExtensions("h2")).message.body):
      discard decodeTls13EncryptedExtensions(data)

  test "the Certificate decoder never raises a Defect":
    var
      C: Tls13CertificateMessage
    C.entries = @[
      Tls13CertificateEntry(certificateDer: rampBytes(600)),
      Tls13CertificateEntry(certificateDer: rampBytes(400))]
    fuzzBody("decodeTls13Certificate", 404'u64,
        decodeTls13Handshake(encodeTls13Certificate(C)).message.body):
      discard decodeTls13Certificate(data)

  test "the CertificateVerify decoder never raises a Defect":
    fuzzBody("decodeTls13CertificateVerify", 405'u64,
        decodeTls13Handshake(encodeTls13CertificateVerify(rampBytes(256),
        0x0804'u16)).message.body):
      discard decodeTls13CertificateVerify(data)

  test "a certificate chain past the caller's bound is refused, not truncated":
    var
      C: Tls13CertificateMessage
      encoded: ByteSeq
    C.entries = @[Tls13CertificateEntry(certificateDer: rampBytes(4000))]
    encoded = decodeTls13Handshake(encodeTls13Certificate(C)).message.body
    check decodeTls13Certificate(encoded, maxChainBytes = 64_000).ok
    check not decodeTls13Certificate(encoded, maxChainBytes = 100).ok
