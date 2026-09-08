## ----------------------------------------------------------------------
## TLS 1.3 Key Schedule <- RFC 8446 SHA-256 secrets and traffic material
## ----------------------------------------------------------------------

import tyr/hashes/sha256
import tyr/helpers/secure_memory

import ./types
import ../../analysis_pragmas

const
  tls13SecretLen* = sha256DigestBytes

type
  Tls13Secret* = array[tls13SecretLen, byte]

  Tls13HandshakeSecrets* {.role: truthState,
      metaTags: {tagTls, tagCryptoBoundary}.} = object
    earlySecret*: Tls13Secret
    handshakeSecret*: Tls13Secret
    clientHandshakeTraffic*: Tls13Secret
    serverHandshakeTraffic*: Tls13Secret

  Tls13ApplicationSecrets* {.role: truthState,
      metaTags: {tagTls, tagCryptoBoundary}.} = object
    masterSecret*: Tls13Secret
    clientApplicationTraffic*: Tls13Secret
    serverApplicationTraffic*: Tls13Secret
    exporterMaster*: Tls13Secret

proc toTls13Secret(A: openArray[byte]): Tls13Secret {.role: helper,
    metaTags: {tagTls, tagCryptoBoundary}.} =
  ## A: exact SHA-256-length secret bytes.
  var i: int = 0
  if A.len != tls13SecretLen:
    raise newException(ValueError, "TLS 1.3 secret must be 32 bytes")
  while i < result.len:
    result[i] = A[i]
    i = i + 1

proc emptyTranscriptHash*(): Sha256Digest {.role: truthBuilder,
    metaTags: {tagTls, tagCryptoBoundary}.} =
  ## Return Transcript-Hash of an empty handshake transcript.
  result = sha256Hash([])

proc deriveTls13Secret*(secret: openArray[byte], label: string,
    transcriptHash: openArray[byte]): Tls13Secret {.role: truthBuilder,
    metaTags: {tagTls, tagCryptoBoundary}.} =
  ## secret/label/transcriptHash: RFC 8446 Derive-Secret inputs.
  if secret.len != tls13SecretLen:
    raise newException(ValueError, "TLS 1.3 base secret must be 32 bytes")
  if transcriptHash.len != sha256DigestBytes:
    raise newException(ValueError, "TLS 1.3 transcript hash must be 32 bytes")
  result = toTls13Secret(hkdfExpandLabelSha256(secret, label,
    transcriptHash, tls13SecretLen))

proc initTls13EarlySecret*(psk: openArray[byte] = []): Tls13Secret {.
    role: truthBuilder, metaTags: {tagTls, tagCryptoBoundary}.} =
  ## psk: optional external or resumption PSK; empty selects the no-PSK zeros.
  var
    Z: array[tls13SecretLen, byte]
    extracted: Sha256Digest
  defer:
    secureClearBytes(Z)
    secureClearBytes(extracted)
  if psk.len == 0:
    extracted = hkdfSha256Extract(Z, Z)
  else:
    extracted = hkdfSha256Extract(Z, psk)
  result = toTls13Secret(extracted)

proc buildTls13HandshakeSecrets*(psk, sharedSecret,
    helloTranscriptHash: openArray[byte]): Tls13HandshakeSecrets {.
    role: truthBuilder, metaTags: {tagTls, tagCryptoBoundary}.} =
  ## psk/sharedSecret/helloTranscriptHash: secrets through ServerHello.
  var
    derived: Tls13Secret
    extracted: Sha256Digest
    emptyHash: Sha256Digest
  defer:
    secureClearBytes(derived)
    secureClearBytes(extracted)
    secureClearBytes(emptyHash)
  if sharedSecret.len == 0:
    raise newException(ValueError, "TLS 1.3 shared secret must not be empty")
  result.earlySecret = initTls13EarlySecret(psk)
  emptyHash = emptyTranscriptHash()
  derived = deriveTls13Secret(result.earlySecret, "derived", emptyHash)
  extracted = hkdfSha256Extract(derived, sharedSecret)
  result.handshakeSecret = toTls13Secret(extracted)
  result.clientHandshakeTraffic = deriveTls13Secret(result.handshakeSecret,
    "c hs traffic", helloTranscriptHash)
  result.serverHandshakeTraffic = deriveTls13Secret(result.handshakeSecret,
    "s hs traffic", helloTranscriptHash)

proc buildTls13ApplicationSecrets*(handshakeSecret,
    serverFinishedTranscriptHash: openArray[byte]): Tls13ApplicationSecrets {.
    role: truthBuilder, metaTags: {tagTls, tagCryptoBoundary}.} =
  ## handshakeSecret/serverFinishedTranscriptHash: application secret inputs.
  var
    derived: Tls13Secret
    extracted: Sha256Digest
    emptyHash: Sha256Digest
    Z: array[tls13SecretLen, byte]
  defer:
    secureClearBytes(derived)
    secureClearBytes(extracted)
    secureClearBytes(emptyHash)
    secureClearBytes(Z)
  if handshakeSecret.len != tls13SecretLen:
    raise newException(ValueError, "TLS 1.3 handshake secret must be 32 bytes")
  emptyHash = emptyTranscriptHash()
  derived = deriveTls13Secret(handshakeSecret, "derived", emptyHash)
  extracted = hkdfSha256Extract(derived, Z)
  result.masterSecret = toTls13Secret(extracted)
  result.clientApplicationTraffic = deriveTls13Secret(result.masterSecret,
    "c ap traffic", serverFinishedTranscriptHash)
  result.serverApplicationTraffic = deriveTls13Secret(result.masterSecret,
    "s ap traffic", serverFinishedTranscriptHash)
  result.exporterMaster = deriveTls13Secret(result.masterSecret,
    "exp master", serverFinishedTranscriptHash)

proc deriveTls13FinishedKey*(trafficSecret: openArray[byte]): Tls13Secret {.
    role: truthBuilder, metaTags: {tagTls, tagCryptoBoundary}.} =
  ## trafficSecret: handshake traffic secret for one endpoint.
  result = toTls13Secret(hkdfExpandLabelSha256(trafficSecret, "finished", [],
    tls13SecretLen))

proc deriveTls13TrafficKeys*(trafficSecret: openArray[byte]):
    Tls13TrafficKeys {.role: truthBuilder,
    metaTags: {tagTls, tagCryptoBoundary}.} =
  ## trafficSecret: client or server traffic secret for one encryption level.
  var
    keyBytes: seq[byte] = @[]
    ivBytes: seq[byte] = @[]
    i: int = 0
  defer:
    secureClearBytes(keyBytes)
    secureClearBytes(ivBytes)
  if trafficSecret.len != tls13SecretLen:
    raise newException(ValueError, "TLS 1.3 traffic secret must be 32 bytes")
  keyBytes = hkdfExpandLabelSha256(trafficSecret, "key", [], tls13AeadKeyLen)
  ivBytes = hkdfExpandLabelSha256(trafficSecret, "iv", [], tls13AeadIvLen)
  while i < result.key.len:
    result.key[i] = keyBytes[i]
    i = i + 1
  i = 0
  while i < result.iv.len:
    result.iv[i] = ivBytes[i]
    i = i + 1

proc nextTls13TrafficSecret*(trafficSecret: openArray[byte]): Tls13Secret {.
    role: truthBuilder, metaTags: {tagTls, tagCryptoBoundary}.} =
  ## trafficSecret: current application traffic secret for KeyUpdate.
  result = toTls13Secret(hkdfExpandLabelSha256(trafficSecret, "traffic upd", [],
    tls13SecretLen))

proc clearTls13Secret*(S: var Tls13Secret) {.role: actor,
    metaTags: {tagTls, tagCryptoBoundary}.} =
  ## S: secret material to clear after an encryption-level transition.
  secureClearBytes(S)

proc clearTls13HandshakeSecrets*(S: var Tls13HandshakeSecrets) {.
    role: actor, metaTags: {tagTls, tagCryptoBoundary}.} =
  ## S: handshake schedule material that is no longer needed.
  clearTls13Secret(S.earlySecret)
  clearTls13Secret(S.handshakeSecret)
  clearTls13Secret(S.clientHandshakeTraffic)
  clearTls13Secret(S.serverHandshakeTraffic)

proc clearTls13ApplicationSecrets*(S: var Tls13ApplicationSecrets) {.
    role: actor, metaTags: {tagTls, tagCryptoBoundary}.} =
  ## S: copied application schedule material after traffic-key installation.
  clearTls13Secret(S.masterSecret)
  clearTls13Secret(S.clientApplicationTraffic)
  clearTls13Secret(S.serverApplicationTraffic)
  clearTls13Secret(S.exporterMaster)
