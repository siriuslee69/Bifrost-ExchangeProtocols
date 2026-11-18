## -------------------------------------------------------------------------
## SMTP with STARTTLS <- what a mail daemon does with one connection
## -------------------------------------------------------------------------
##
##   certificate + key (PEM text) ──▶ tls13ServerConfigFromPem ──▶ config
##   config ──▶ initSmtpTlsServer ──▶ one conversation object per connection
##
##   bytes from the socket ──▶ feedSmtpTlsServer ──▶ step.send   (put on the wire as it is)
##                                               └─▶ step.reply  (SMTP text: settle it,
##                                                                then sealSmtpTlsReply)
##
## No socket here: the "wire" is a string. A real daemon (Fjord's `fjord-maild`)
## reads a socket, calls these three routines and writes what they return.
##
## The burst below is what a man in the middle would send: a MAIL line slipped in
## right behind STARTTLS, in the clear. The server answers EHLO and STARTTLS and
## then behaves as if the MAIL line was never said.

import std/strutils

import bifrost_exchange_protocols
import protocols/smtp/level2/server_tls

const
  certificatePem = """-----BEGIN CERTIFICATE-----
MIIBPDCB76ADAgECAhQkqENccCvOQyI4iKFuuOKwl860bTAFBgMrZXAwFDESMBAG
A1UEAwwJbG9jYWxob3N0MB4XDTIxMDcyNjE0MjcwN1oXDTIxMDgyNTE0MjcwN1ow
FDESMBAGA1UEAwwJbG9jYWxob3N0MCowBQYDK2VwAyEA1KMGmAZealfgakBuCx/E
n69fo072qm90eM40ulGex0ajUzBRMB0GA1UdDgQWBBTHKWv5l/SxnkkYJhh5r3Pv
ESAh1DAfBgNVHSMEGDAWgBTHKWv5l/SxnkkYJhh5r3PvESAh1DAPBgNVHRMBAf8E
BTADAQH/MAUGAytlcANBAF/vSBfOHAdRl29sWDTkuqy1dCuSf7j7jKE/Be8Fk7xs
WteXJmIa0HlRAZjxNfWbsSGLnTYbsGTbxKx3QU9H9g0=
-----END CERTIFICATE-----"""
  keyPem = """-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAjtEwCECqbot5RZxSmiNDWcPp+Xc9Y9WJcUhti3JgSP
-----END PRIVATE KEY-----"""

proc isOurs(a: string): bool {.gcsafe.} =
  ## Mail for mine.example is ours.
  result = a.endsWith("@mine.example")

proc main() =
  var
    config = tls13ServerConfigFromPem(certificatePem, keyPem)
    conn: SmtpTlsServer = SmtpTlsServer()
    step: SmtpTlsStep = SmtpTlsStep()
  doAssert config.ok, config.err
  conn = initSmtpTlsServer("mx.mine.example", config.cfg)
  echo "to the sender:  ", greetSmtpTls(conn).strip()
  step = feedSmtpTlsServer(conn, "EHLO a.example\r\nSTARTTLS\r\n" &
    "MAIL FROM:<evil@x.example>\r\n", isOurs)
  echo "on the wire:    ", step.send.replace("\r\n", " | ")
  doAssert "250-STARTTLS" in step.send
  doAssert "220 go ahead" in step.send
  doAssert "250 ok" notin step.send   # the slipped-in MAIL line got no answer
  doAssert conn.mode == swHandshake   # the next bytes are the TLS handshake
  echo "the MAIL line behind STARTTLS was dropped; the TLS handshake is next"

main()
