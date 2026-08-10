## ---------------------------------------------------------------------
## DKIM Crypto <- RFC 6376 signing primitives over Tyr's native crypto
## ---------------------------------------------------------------------
##
## Bifrost owns the crypto boundary for mail protocols so that Fjord (and
## anything else that signs mail) never links OpenSSL or reaches into Tyr
## directly. Everything here is `rsa-sha256`, the algorithm RFC 6376 makes
## mandatory to implement and the only one real verifiers expect.
##
## Keys arrive in the two shapes DKIM actually uses:
##   * verification: the bare base64 SPKI carried in the DNS `p=` tag
##   * signing:      a PEM file on disk, PKCS#1 or PKCS#8

import std/[base64, strutils]

import protocols/custom_crypto/rsa
import protocols/custom_crypto/sha256

import ../../analysis_pragmas

type
  DkimSignResult* {.role: truthState, tag: {tagCryptoBoundary}.} = object
    ok*: bool
    signature*: string ## raw signature octets, not base64
    err*: string

  DkimKeyResult* {.role: truthState, tag: {tagCryptoBoundary}.} = object
    ok*: bool
    key*: RsaPublicKey
    err*: string

proc toBytes(s: string): seq[byte] {.role: helper, tag: {tagCryptoBoundary}.} =
  ## s: text or octet string to view as bytes.
  result = newSeq[byte](s.len)
  for i, c in s:
    result[i] = byte(c)

proc toStr(b: openArray[byte]): string {.role: helper,
    tag: {tagCryptoBoundary}.} =
  ## b: octets to view as a string.
  result = newString(b.len)
  for i, v in b:
    result[i] = char(v)

proc dkimSha256*(s: string): string {.role: math, tag: {tagCryptoBoundary}.} =
  ## s: data to hash.
  ## Returns the raw 32-byte SHA-256 digest, used for the DKIM `bh=` tag.
  result = toStr(sha256Hash(toBytes(s)))

proc dkimLoadPublicKey*(p: string): DkimKeyResult {.role: truthBuilder,
    tag: {tagCryptoBoundary, tagValidation}.} =
  ## p: base64 SubjectPublicKeyInfo from the DNS `p=` tag, whitespace allowed.
  var
    clean: string = ""
    raw: string = ""
    parsed: RsaPublicKeyResult
  for c in p:
    if c notin {' ', '\t', '\r', '\n'}:
      clean.add(c)
  if clean.len == 0:
    result.err = "DKIM public key is empty"
    return
  try:
    raw = decode(clean)
  except CatchableError:
    result.err = "DKIM public key is not valid base64"
    return
  parsed = parseRsaSpki(toBytes(raw))
  if not parsed.ok:
    result.err = "DKIM public key is unusable: " & parsed.err
    return
  result.key = parsed.key
  result.ok = true

proc dkimVerifyRsaSha256*(data, signatureB64, publicKeyB64: string): bool {.
    role: actor, tag: {tagCryptoBoundary, tagValidation}.} =
  ## data: canonicalized header set that was signed.
  ## signatureB64: the DKIM `b=` tag value.
  ## publicKeyB64: the DNS `p=` tag value.
  var
    sig: string = ""
    key: DkimKeyResult
  if signatureB64.len == 0 or publicKeyB64.len == 0:
    return false
  key = dkimLoadPublicKey(publicKeyB64)
  if not key.ok:
    return false
  try:
    sig = decode(signatureB64.strip())
  except CatchableError:
    return false
  if sig.len == 0:
    return false
  result = rsaVerifyPkcs1v15Sha256(key.key, toBytes(data), toBytes(sig))

proc dkimSignRsaSha256*(data, privateKeyPem: string): DkimSignResult {.
    role: actor, tag: {tagCryptoBoundary}.} =
  ## data: canonicalized header set to sign.
  ## privateKeyPem: PEM text of the signing key, PKCS#1 or PKCS#8.
  var
    parsed: RsaPrivateKeyResult = parseRsaPrivateKeyPem(privateKeyPem)
    signed: RsaSignResult
  if not parsed.ok:
    result.err = "DKIM signing key is unusable: " & parsed.err
    return
  signed = rsaSignPkcs1v15Sha256(parsed.key, toBytes(data))
  if not signed.ok:
    result.err = signed.err
    return
  result.signature = toStr(signed.signature)
  result.ok = true
