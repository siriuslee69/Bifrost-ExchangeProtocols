## -------------------------------------------------------------------------
## AME Compression <- bounded Eir compression before AME protection
## -------------------------------------------------------------------------

from eir_compression_and_ecc import encodeRle, decodeRle

import ../../types
import ../types
import ../level0/bytes
import ../../../analysis_pragmas

const
  ameCompressionMagic* = [uint8('E'), uint8('I'), uint8('R'), uint8('1')]
  ameCompressionHeaderLen* = 13

proc defaultAmeCompressionPolicy*(): AmeCompressionPolicy {.role: wrapper.} =
  ## Conservative package-compression limits, with compression OFF.
  ##
  ## Compressing before encrypting leaks. The ciphertext is as long as the
  ## compressed input, so its LENGTH tells an observer how well the plaintext
  ## compressed -- and if an attacker can get some of their own text placed
  ## next to a secret, a shorter result means the two matched. That is how
  ## secrets have been read out of compressed-then-encrypted channels before.
  ##
  ## So a caller who wants compression has to ask for it by name, and should
  ## only do so when no part of the payload is attacker-influenced. Sending
  ## the same fixed content repeatedly is fine; compressing a message that
  ## mixes a secret with anything a stranger supplied is not.
  result.algorithm = aczNone
  result.maxPlaintextBytes = 16_777_216'u32
  result.maxEncodedBytes = 16_777_216'u32
  result.maxExpansionRatio = 4096'u16

proc compressedAmeCompressionPolicy*(): AmeCompressionPolicy {.role: wrapper.} =
  ## The same limits with Eir run-length compression switched on. Read the
  ## warning on `defaultAmeCompressionPolicy` before reaching for this.
  result = defaultAmeCompressionPolicy()
  result.algorithm = aczEirRle

proc readCompressionU32(A: openArray[uint8], o: int): uint32 {.role: parser.} =
  ## A/o: source and little-endian offset.
  result = uint32(A[o]) or (uint32(A[o + 1]) shl 8) or
    (uint32(A[o + 2]) shl 16) or (uint32(A[o + 3]) shl 24)

proc validateCompressionPolicy*(p: AmeCompressionPolicy) {.role: parser.} =
  ## p: compression policy checked before encoding or decoding.
  if p.maxPlaintextBytes == 0'u32 or p.maxEncodedBytes == 0'u32 or
      p.maxExpansionRatio == 0'u16:
    raise newException(ValueError, "AME compression limits must be positive")

proc encodeAmeCompressed*(A: openArray[uint8],
    p: AmeCompressionPolicy = defaultAmeCompressionPolicy()): ByteSeq {.
    role: orchestrator.} =
  ## A/p: plaintext and negotiated bounded Eir compression policy.
  var
    source: ByteSeq = @A
    encoded: ByteSeq = @[]
    algorithm: AmeCompressionAlgorithm = p.algorithm
  validateCompressionPolicy(p)
  if uint64(A.len) > uint64(p.maxPlaintextBytes):
    raise newException(ValueError, "AME plaintext exceeds compression limit")
  if algorithm == aczEirRle:
    encoded = encodeRle(source)
    if encoded.len >= source.len:
      algorithm = aczNone
      encoded = source
  else:
    encoded = source
  if uint64(encoded.len) > uint64(p.maxEncodedBytes):
    raise newException(ValueError, "AME encoded payload exceeds compression limit")
  appendAmeBytes(result, ameCompressionMagic)
  result.add(uint8(ord(algorithm)))
  appendAmeU32(result, uint32(source.len))
  appendAmeU32(result, uint32(encoded.len))
  appendAmeBytes(result, encoded)

proc decodeAmeCompressed*(A: openArray[uint8],
    p: AmeCompressionPolicy = defaultAmeCompressionPolicy()): ByteSeq {.
    role: orchestrator.} =
  ## A/p: authenticated compression envelope and negotiated limits.
  var
    algorithm: AmeCompressionAlgorithm
    plainLen: uint32 = 0'u32
    encodedLen: uint32 = 0'u32
    encoded: ByteSeq = @[]
    decoded: tuple[ok: bool, payload: ByteSeq, err: string]
  validateCompressionPolicy(p)
  if A.len < ameCompressionHeaderLen or A[0 .. 3] != ameCompressionMagic:
    raise newException(ValueError, "AME compression envelope identity mismatch")
  if A[4] > uint8(ord(high(AmeCompressionAlgorithm))):
    raise newException(ValueError, "AME compression algorithm is unknown")
  algorithm = AmeCompressionAlgorithm(A[4])
  if algorithm != p.algorithm and algorithm != aczNone:
    raise newException(ValueError, "AME compression algorithm was not negotiated")
  plainLen = readCompressionU32(A, 5)
  encodedLen = readCompressionU32(A, 9)
  if plainLen > p.maxPlaintextBytes or encodedLen > p.maxEncodedBytes or
      uint64(encodedLen) > uint64(high(int)) or
      A.len != ameCompressionHeaderLen + int(encodedLen):
    raise newException(ValueError, "AME compression envelope length is invalid")
  if encodedLen > 0'u32 and
      uint64(plainLen) > uint64(encodedLen) * uint64(p.maxExpansionRatio):
    raise newException(ValueError, "AME decompression expansion ratio is too large")
  encoded = @A[ameCompressionHeaderLen ..< A.len]
  if algorithm == aczNone:
    result = encoded
  else:
    decoded = decodeRle(encoded)
    if not decoded.ok:
      raise newException(ValueError, "AME Eir decompression failed: " & decoded.err)
    result = decoded.payload
  if result.len != int(plainLen):
    raise newException(ValueError, "AME decompressed length mismatch")
