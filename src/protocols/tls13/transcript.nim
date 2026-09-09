## ----------------------------------------------------------------------
## TLS 1.3 Transcript <- handshake hashing, Finished, and signature context
## ----------------------------------------------------------------------

import tyr/hashes/sha256
import tyr/signatures/ed25519
import tyr/certs/rsa
import tyr/helpers/bigint
import tyr/signatures/ecdsa_p256

import ../types
import ./key_schedule
import runePragmas

type
  Tls13Transcript* {.role: memory, tag: "tls|cryptoBoundary".} = object
    hashState: Sha256Context

proc initTls13Transcript*(): Tls13Transcript {.role: truthBuilder,
    tag: "tls|cryptoBoundary".} =
  ## Initialize an empty handshake transcript.
  result.hashState = initSha256()

proc appendTls13Transcript*(T: var Tls13Transcript,
    encodedHandshake: openArray[byte]) {.role: dataWriter,
    tag: "tls|cryptoBoundary".} =
  ## T/encodedHandshake: transcript and exact type+length+body bytes.
  T.hashState.updateSha256(encodedHandshake)

proc tls13TranscriptHash*(T: Tls13Transcript): Sha256Digest {.
    role: truthBuilder, tag: "tls|cryptoBoundary".} =
  ## T: clonable transcript whose current digest is returned.
  result = T.hashState.finishSha256()

proc tls13FinishedVerifyData*(trafficSecret: openArray[byte],
    transcriptHash: openArray[byte]): Tls13Secret {.role: truthBuilder,
    tag: "tls|cryptoBoundary".} =
  ## trafficSecret/transcriptHash: endpoint handshake secret and current hash.
  var key: Tls13Secret = deriveTls13FinishedKey(trafficSecret)
  result = hmacSha256(key, transcriptHash)

proc constantTimeFinishedEqual*(A, B: openArray[byte]): bool {.role: helper,
    tag: "tls|cryptoBoundary".} =
  ## A/B: received and expected Finished verify_data.
  var
    diff: uint = if A.len == B.len: 0'u else: 1'u
    i: int = 0
    b: byte = 0
  while i < A.len:
    b = if i < B.len: B[i] else: 0'u8
    diff = diff or uint(A[i] xor b)
    i = i + 1
  result = diff == 0'u

proc tls13CertificateVerifyInput*(server: bool,
    transcriptHash: openArray[byte]): ByteSeq {.role: truthBuilder,
    tag: "tls|cryptoBoundary".} =
  ## server/transcriptHash: signer role and transcript hash before CertificateVerify.
  const
    serverContext = "TLS 1.3, server CertificateVerify"
    clientContext = "TLS 1.3, client CertificateVerify"
  var
    context: string = if server: serverContext else: clientContext
    i: int = 0
  if transcriptHash.len != sha256DigestBytes:
    raise newException(ValueError, "TLS CertificateVerify transcript hash must be 32 bytes")
  result = newSeq[byte](64 + context.len + 1 + transcriptHash.len)
  while i < 64:
    result[i] = 0x20'u8
    i = i + 1
  i = 0
  while i < context.len:
    result[64 + i] = byte(ord(context[i]))
    i = i + 1
  result[64 + context.len] = 0'u8
  i = 0
  while i < transcriptHash.len:
    result[65 + context.len + i] = transcriptHash[i]
    i = i + 1

proc signTls13CertificateVerify*(secretKey: openArray[byte], server: bool,
    transcriptHash: openArray[byte]): ByteSeq {.role: actor,
    tag: "tls|cryptoBoundary".} =
  ## secretKey/server/transcriptHash: Ed25519 key and TLS signature context.
  result = ed25519TyrSign(tls13CertificateVerifyInput(server, transcriptHash),
    secretKey)

proc verifyTls13CertificateVerify*(publicKey, signature: openArray[byte],
    server: bool, transcriptHash: openArray[byte]): bool {.role: actor,
    tag: "tls|cryptoBoundary".} =
  ## publicKey/signature/server/transcriptHash: Ed25519 TLS verification inputs.
  result = ed25519TyrVerify(tls13CertificateVerifyInput(server,
    transcriptHash), signature, publicKey)

proc signTls13CertificateVerifyRsaPss*(key: RsaPrivateKey, server: bool,
    transcriptHash: openArray[byte]): ByteSeq {.role: actor,
    tag: "tls|cryptoBoundary".} =
  ## key/server/transcriptHash: RSA private key and TLS signature context.
  ## Produces the `rsa_pss_rsae_sha256` CertificateVerify signature.
  var signed = rsaSignPssSha256(key, tls13CertificateVerifyInput(server,
    transcriptHash))
  if not signed.ok:
    raise newException(ValueError,
      "TLS RSA-PSS CertificateVerify failed: " & signed.err)
  result = signed.signature

proc verifyTls13CertificateVerifyRsaPss*(key: RsaPublicKey,
    signature: openArray[byte], server: bool,
    transcriptHash: openArray[byte]): bool {.role: actor,
    tag: "tls|cryptoBoundary".} =
  ## key/signature/server/transcriptHash: RSA verification inputs.
  result = rsaVerifyPssSha256(key, tls13CertificateVerifyInput(server,
    transcriptHash), signature)

proc signTls13CertificateVerifyEcdsaP256*(scalar: BigInt, server: bool,
    transcriptHash: openArray[byte]): ByteSeq {.role: actor,
    tag: "tls|cryptoBoundary".} =
  ## scalar/server/transcriptHash: P-256 private scalar and signature context.
  ## Produces the DER-encoded `ecdsa_secp256r1_sha256` signature.
  var signed = ecdsaSignP256(scalar, tls13CertificateVerifyInput(server,
    transcriptHash))
  if not signed.ok:
    raise newException(ValueError,
      "TLS ECDSA CertificateVerify failed: " & signed.err)
  result = encodeEcdsaSignatureDer(signed.signature)

proc verifyTls13CertificateVerifyEcdsaP256*(point: P256AffinePoint,
    signature: openArray[byte], server: bool,
    transcriptHash: openArray[byte]): bool {.role: actor,
    tag: "tls|cryptoBoundary".} =
  ## point/signature/server/transcriptHash: P-256 verification inputs.
  var parsed = parseEcdsaSignatureDer(signature)
  if not parsed.ok:
    return false
  result = ecdsaVerifyP256(point, tls13CertificateVerifyInput(server,
    transcriptHash), parsed.sig)
