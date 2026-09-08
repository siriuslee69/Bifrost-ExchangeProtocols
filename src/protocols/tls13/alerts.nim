## ------------------------------------------------------------
## TLS 1.3 Alerts <- typed alert descriptions and wire helpers
## ------------------------------------------------------------

import std/strutils

import ../types
import ./[types, codec]
import bifrostPragmas

type
  Tls13AlertLevel* = enum
    talWarning = 1,
    talFatal = 2

  Tls13AlertDescription* = enum
    tadCloseNotify = 0,
    tadUnexpectedMessage = 10,
    tadBadRecordMac = 20,
    tadRecordOverflow = 22,
    tadHandshakeFailure = 40,
    tadBadCertificate = 42,
    tadUnsupportedCertificate = 43,
    tadCertificateRevoked = 44,
    tadCertificateExpired = 45,
    tadCertificateUnknown = 46,
    tadIllegalParameter = 47,
    tadUnknownCa = 48,
    tadAccessDenied = 49,
    tadDecodeError = 50,
    tadDecryptError = 51,
    tadProtocolVersion = 70,
    tadInternalError = 80,
    tadMissingExtension = 109,
    tadUnsupportedExtension = 110,
    tadUnrecognizedName = 112,
    tadCertificateRequired = 116,
    tadNoApplicationProtocol = 120

proc encodeTls13PlainAlert*(level: Tls13AlertLevel,
    description: Tls13AlertDescription): ByteSeq {.role: dataWriter,
    metaTags: {tagTls, tagWrite}.} =
  ## level/description: pre-key alert values for one plaintext alert record.
  var R: Tls13Record
  R.contentType = tctAlert
  R.legacyVersion = tls13LegacyRecordVersion
  R.fragment = @[byte(ord(level)), byte(ord(description))]
  result = encodeTls13Record(R)

proc tls13AlertForError*(e: string): Tls13AlertDescription {.role: parser,
    metaTags: {tagTls, tagValidation}.} =
  ## e: internal validation failure reduced to a non-sensitive wire alert.
  if e.find("version") >= 0:
    return tadProtocolVersion
  if e.find("extension") >= 0 or e.find("missing") >= 0:
    return tadMissingExtension
  if e.find("certificate") >= 0 or e.find("X.509") >= 0:
    return tadBadCertificate
  if e.find("authentication") >= 0 or e.find("Finished") >= 0 or
      e.find("signature") >= 0:
    return tadDecryptError
  if e.find("record") >= 0 and e.find("maximum") >= 0:
    return tadRecordOverflow
  if e.find("invalid") >= 0 or e.find("incomplete") >= 0 or
      e.find("length") >= 0:
    return tadDecodeError
  result = tadHandshakeFailure
