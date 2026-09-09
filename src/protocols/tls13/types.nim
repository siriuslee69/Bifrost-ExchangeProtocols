## -------------------------------------------------------------------
## TLS 1.3 Types <- bounded record, handshake, and traffic-key state
## -------------------------------------------------------------------

import ../types
import runePragmas

const
  tls13LegacyRecordVersion* = 0x0303'u16
  tls13PlaintextLimit* = 16_384
  tls13CiphertextLimit* = tls13PlaintextLimit + 256
  tls13DefaultHandshakeLimit* = 1_048_576
  tls13AeadKeyLen* = 32
  tls13AeadIvLen* = 12
  tls13AeadTagLen* = 16

type
  Tls13ContentType* = enum
    tctChangeCipherSpec = 20,
    tctAlert = 21,
    tctHandshake = 22,
    tctApplicationData = 23

  Tls13HandshakeType* = enum
    thtClientHello = 1,
    thtServerHello = 2,
    thtNewSessionTicket = 4,
    thtEncryptedExtensions = 8,
    thtCertificate = 11,
    thtCertificateRequest = 13,
    thtCertificateVerify = 15,
    thtFinished = 20,
    thtKeyUpdate = 24,
    thtMessageHash = 254

  Tls13Record* {.role: truthState, tag: "tls|packet".} = object
    contentType*: Tls13ContentType
    legacyVersion*: uint16
    fragment*: ByteSeq

  Tls13RecordResult* {.role: truthState, tag: "tls|parsing".} = object
    ok*: bool
    needMore*: bool
    consumed*: int
    record*: Tls13Record
    err*: string

  Tls13Handshake* {.role: truthState, tag: "tls|packet".} = object
    messageType*: Tls13HandshakeType
    body*: ByteSeq
    encoded*: ByteSeq

  Tls13HandshakeResult* {.role: truthState, tag: "tls|parsing".} = object
    ok*: bool
    needMore*: bool
    consumed*: int
    message*: Tls13Handshake
    err*: string

  Tls13TrafficKeys* {.role: memory, tag: "tls|cryptoBoundary".} = object
    key*: array[tls13AeadKeyLen, byte]
    iv*: array[tls13AeadIvLen, byte]
    sequence*: uint64

  Tls13OpenResult* {.role: truthState, tag: "tls|cryptoBoundary".} = object
    ok*: bool
    contentType*: Tls13ContentType
    content*: ByteSeq
    err*: string
