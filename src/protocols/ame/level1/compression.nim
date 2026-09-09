## -------------------------------------------------------------------------
## AME Compression <- bounded Eir compression before AME protection
## -------------------------------------------------------------------------

from eir_compression_and_ecc import encodeRle, decodeRle

import ../../types
import ../types
import ../level0/bytes
import ./padding
import runePragmas

const
  ameCompressionMagic* = [uint8('E'), uint8('I'), uint8('R'), uint8('1')]
  ameCompressionHeaderLen* = 14
    ## "EIR1" | algorithm u8 | padding u8 | plainLen u32 | encodedLen u32
    ##
    ## The padding byte states the block size the envelope was rounded up to,
    ## and zero means it was not. It sits INSIDE the encryption along with
    ## everything else here, so it tells the receiver how to undo the padding
    ## without telling an observer anything.

proc defaultAmeCompressionPolicy*(): AmeCompressionPolicy {.role: configurator.} =
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
  result.padding = apadNone
  result.maxPlaintextBytes = 16_777_216'u32
  result.maxEncodedBytes = 16_777_216'u32
  result.maxExpansionRatio = 4096'u16

proc paddedAmeCompressionPolicy*(): AmeCompressionPolicy {.role: configurator.} =
  ## No compression, but every payload rounded up to whole 64-byte blocks.
  ## Worth it on its own when the SIZE of a stored package would say what it
  ## is, even though nothing about it compresses.
  result = defaultAmeCompressionPolicy()
  result.padding = apadBlock64

proc compressedAmeCompressionPolicy*(): AmeCompressionPolicy {.role: configurator.} =
  ## The same limits with Eir run-length compression switched on, and padding
  ## with it. Read the warning on `defaultAmeCompressionPolicy` first: padding
  ## blunts the length leak, it does not delete it. A payload that compresses
  ## from 4 KiB to 100 bytes still lands in a different block count than one
  ## that does not compress at all.
  result = defaultAmeCompressionPolicy()
  result.algorithm = aczEirRle
  result.padding = apadBlock64

proc readCompressionU32(A: openArray[uint8], o: int): uint32 {.role: parser.} =
  ## A/o: source and little-endian offset.
  result = uint32(A[o]) or (uint32(A[o + 1]) shl 8) or
    (uint32(A[o + 2]) shl 16) or (uint32(A[o + 3]) shl 24)

proc effectiveAmePadding*(p: AmeCompressionPolicy): AmePaddingPolicy {.
    role: parser.} =
  ## p: policy whose padding is decided, compression having a veto.
  ##
  ## Note what this does NOT look at: whether compression actually shrank
  ## anything. The decision is taken from the policy alone, because deciding
  ## it from the outcome would make the presence of padding a signal about
  ## the plaintext -- which is the very leak being closed here.
  if p.algorithm != aczNone:
    return apadBlock64
  result = p.padding

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
    padding: AmePaddingPolicy = effectiveAmePadding(p)
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
  result.add(uint8(ord(padding)))
  appendAmeU32(result, uint32(source.len))
  appendAmeU32(result, uint32(encoded.len))
  appendAmeBytes(result, encoded)
  ## Padding goes on the OUTSIDE of the whole envelope, header included, so
  ## the caller who encrypts this sees one length that is a whole number of
  ## blocks and nothing that varies with the payload.
  result = padAmeMessage(result, padding)

proc decodeAmeCompressed*(A: openArray[uint8],
    p: AmeCompressionPolicy = defaultAmeCompressionPolicy()): ByteSeq {.
    role: orchestrator.} =
  ## A/p: authenticated compression envelope and negotiated limits.
  var
    algorithm: AmeCompressionAlgorithm
    padding: AmePaddingPolicy = apadNone
    body: ByteSeq = @[]
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
  ## The padding byte is at a fixed offset near the front, so it can be read
  ## before the filler at the back is removed.
  padding = amePaddingPolicyFromId(A[5])
  if padding != effectiveAmePadding(p):
    raise newException(ValueError, "AME padding policy was not negotiated")
  body = unpadAmeMessage(A, padding)
  if body.len < ameCompressionHeaderLen:
    raise newException(ValueError, "AME compression envelope length is invalid")
  plainLen = readCompressionU32(body, 6)
  encodedLen = readCompressionU32(body, 10)
  if plainLen > p.maxPlaintextBytes or encodedLen > p.maxEncodedBytes or
      uint64(encodedLen) > uint64(high(int)) or
      body.len != ameCompressionHeaderLen + int(encodedLen):
    raise newException(ValueError, "AME compression envelope length is invalid")
  if encodedLen > 0'u32 and
      uint64(plainLen) > uint64(encodedLen) * uint64(p.maxExpansionRatio):
    raise newException(ValueError, "AME decompression expansion ratio is too large")
  encoded = body[ameCompressionHeaderLen ..< body.len]
  if algorithm == aczNone:
    result = encoded
  else:
    decoded = decodeRle(encoded)
    if not decoded.ok:
      raise newException(ValueError, "AME Eir decompression failed: " & decoded.err)
    result = decoded.payload
  if result.len != int(plainLen):
    raise newException(ValueError, "AME decompressed length mismatch")
