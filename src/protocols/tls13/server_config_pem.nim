## -------------------------------------------------------------------------
## Server config from PEM <- certificate chain and key as the CA hands them out
## -------------------------------------------------------------------------
##
## A certificate authority (Let's Encrypt, your own) gives two text files:
##
##   fullchain.pem   the server certificate, then the ones above it
##   privkey.pem     the secret key that belongs to the first certificate
##
## `tls13ServerConfigFromPem` turns their TEXT into a `Tls13ServerConfig`.
## No file is read here (this repo does no disk work): the caller reads the
## two files and hands the text in.
##
##   key text begins with            what it is                    goes into
##   ------------------------------  ----------------------------  ------------------
##   BEGIN PRIVATE KEY               PKCS#8: Ed25519, RSA or P-256  the matching field
##   BEGIN RSA PRIVATE KEY           PKCS#1 RSA                     rsaPrivateKeyDer
##   BEGIN EC PRIVATE KEY            SEC1 P-256                     ecdsaPrivateScalar
##   BEGIN ENCRYPTED PRIVATE KEY     protected by a password        refused, with a hint
##
## The result is tried once by starting a session, so a key that does not belong
## to the certificate fails HERE, at start-up, and not at the first visitor.

import std/strutils

import tyr/certs/[der, pem]
import tyr/certs/keys
import tyr/certs/rsa
import tyr/signatures/ed25519

import ../types
import ./server_session
import runePragmas

const
  tlsMaxChainCertificates* = 8
    ## a chain longer than this is not a chain; it is refused

type
  PemSplit {.role: preparedData, tag: "tls|config".} = object
    ok: bool
    blocks: seq[string]
    err: string

proc splitPemBlocks(s, label: string, maxBlocks: int): PemSplit {.
    role: parser, tag: "tls|config".} =
  ## s/label/maxBlocks: every armoured block with that label, in order.
  var
    startMark: string = "-----BEGIN " & label & "-----"
    endMark: string = "-----END " & label & "-----"
    at: int = 0
    a: int = 0
    b: int = 0
  a = s.find(startMark, at)
  while a >= 0:
    b = s.find(endMark, a)
    if b < 0:
      result.err = "a " & label & " block has no end line"
      return
    result.blocks.add(s[a ..< b + endMark.len])
    if result.blocks.len > maxBlocks:
      result.err = "more than " & $maxBlocks & " " & label & " blocks"
      return
    at = b + endMark.len
    a = s.find(startMark, at)
  result.ok = true

proc ecScalarOfSec1(A: openArray[byte]): tuple[ok: bool, scalar: seq[byte],
    err: string] {.role: parser, tag: "tls|config"} =
  ## A: DER of a SEC1 ECPrivateKey: SEQUENCE { 1, OCTET STRING scalar, ... }.
  var
    R: DerReadResult = readDerElement(A, 0)
    C: tuple[ok: bool, children: seq[DerElement], err: string] = (false, @[], "")
  if not R.ok or R.element.endOffset != A.len:
    result.err = "the EC private key is not one DER block"
    return
  result.err = requireDerShape(R.element, dcUniversal, derTagSequence, true)
  if result.err.len > 0:
    return
  C = readDerChildren(A, R.element)
  if not C.ok or C.children.len < 2:
    result.err = "the EC private key has too few fields"
    return
  result.err = requireDerShape(C.children[1], dcUniversal, derTagOctetString, false)
  if result.err.len > 0:
    return
  result.scalar = derContent(A, C.children[1])
  result.ok = true

proc ecScalarOfPkcs8(A: openArray[byte]): tuple[ok: bool, scalar: seq[byte],
    err: string] {.role: parser, tag: "tls|config"} =
  ## A: DER of a PKCS#8 PrivateKeyInfo that wraps an SEC1 EC key:
  ## SEQUENCE { 0, SEQUENCE { algorithm }, OCTET STRING { SEC1 } }.
  var
    R: DerReadResult = readDerElement(A, 0)
    C: tuple[ok: bool, children: seq[DerElement], err: string] = (false, @[], "")
    inner: seq[byte] = @[]
  if not R.ok or R.element.endOffset != A.len:
    result.err = "the private key is not one DER block"
    return
  result.err = requireDerShape(R.element, dcUniversal, derTagSequence, true)
  if result.err.len > 0:
    return
  C = readDerChildren(A, R.element)
  if not C.ok or C.children.len != 3:
    result.err = "the private key is not Ed25519, RSA or P-256"
    return
  result.err = requireDerShape(C.children[2], dcUniversal, derTagOctetString, false)
  if result.err.len > 0:
    return
  inner = derContent(A, C.children[2])
  result = ecScalarOfSec1(inner)

proc ecIntoConfig(ec: tuple[ok: bool, scalar: seq[byte], err: string],
    cfg: var Tls13ServerConfig): string {.role: actor,
    tag: "tls|config|cryptoBoundary".} =
  ## ec/cfg: a P-256 scalar read from a key block. Answers "" or why not.
  if not ec.ok:
    return ec.err
  cfg.ecdsaPrivateScalar = ec.scalar
  result = ""

proc pkcs8IntoConfig(der: seq[byte], cfg: var Tls13ServerConfig): string {.
    role: actor, tag: "tls|config|cryptoBoundary".} =
  ## der/cfg: a PKCS#8 key: Ed25519, RSA or P-256, tried in that order.
  var
    ed: Ed25519Pkcs8Result = parseEd25519Pkcs8(der)
  if ed.ok:
    cfg.ed25519SecretKey = ed25519TyrKeypairFromSeed(ed.seed).secretKey
    return ""
  if parseRsaPkcs8PrivateKey(der).ok:
    cfg.rsaPrivateKeyDer = der
    return ""
  result = ecIntoConfig(ecScalarOfPkcs8(der), cfg)

proc keyIntoConfig(label: string, der: seq[byte], cfg: var Tls13ServerConfig): string {.
    role: actor, tag: "tls|config|cryptoBoundary".} =
  ## label/der/cfg: the key block. Puts it where the leaf's kind will look.
  ## Answers "" when it fitted, otherwise why not.
  case label
  of "RSA PRIVATE KEY":
    cfg.rsaPrivateKeyDer = der
  of "EC PRIVATE KEY":
    result = ecIntoConfig(ecScalarOfSec1(der), cfg)
  of "ENCRYPTED PRIVATE KEY":
    result = "the key is protected by a password: remove it first " &
      "(openssl pkey -in key.pem -out plain.pem)"
  of "PRIVATE KEY":
    result = pkcs8IntoConfig(der, cfg)
  else:
    result = "the key block is a '" & label & "', not a private key"

proc tls13ServerConfigFromPem*(certChainPem, keyPem: string,
    alpn: seq[string] = @[]): tuple[ok: bool, cfg: Tls13ServerConfig,
    err: string] {.role: truthBuilder, tag: "tls|config|cryptoBoundary".} =
  ## certChainPem: the server certificate first, then the ones above it.
  ## keyPem: the private key of the FIRST certificate (no password).
  ## alpn: the protocol names the server speaks, if any.
  ## Answers the config, tried once; or why it cannot be used.
  var
    chain: PemSplit = splitPemBlocks(certChainPem, "CERTIFICATE",
      tlsMaxChainCertificates)
    key: PemReadResult = readPemBlock(keyPem)
    one: PemReadResult = PemReadResult()
    why: string = ""
    probe: Tls13ServerSession = default(Tls13ServerSession)
    i: int = 0
  if not chain.ok:
    result.err = chain.err
    return
  if chain.blocks.len == 0:
    result.err = "no certificate found in the chain text"
    return
  while i < chain.blocks.len:
    one = readPemBlock(chain.blocks[i], "CERTIFICATE")
    if not one.ok:
      result.err = "certificate " & $(i + 1) & ": " & one.err
      return
    result.cfg.certificateChainDer.add(one.pemBlock.der)
    i = i + 1
  if not key.ok:
    result.err = "private key: " & key.err
    return
  why = keyIntoConfig(key.pemBlock.label, key.pemBlock.der, result.cfg)
  if why.len > 0:
    result.err = why
    return
  result.cfg.alpn = alpn
  try:
    probe = initTls13ServerSession(result.cfg)
  except CatchableError as e:
    result.err = e.msg
    return
  result.ok = true
