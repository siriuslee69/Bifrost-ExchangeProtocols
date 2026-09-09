## -------------------------------------------------------------------------
## AME Padding <- hiding the exact length of what was encrypted
## -------------------------------------------------------------------------
##
## A stream cipher makes ciphertext exactly as long as its plaintext. That is
## convenient and it leaks: anyone watching the wire learns the size of every
## message even though they cannot read one.
##
## The leak turns from a nuisance into a break as soon as the plaintext was
## COMPRESSED first. Compression makes output shorter when the input repeats
## itself, so if an attacker can get some text of their own placed next to a
## secret, a shorter message means their guess matched part of that secret.
## Guess by guess, the length alone hands over the secret. That is why this
## file exists, and why compression in AME is not allowed to run without it.
##
## What padding does about it
## --------------------------
## Before the plaintext is encrypted, filler is added until the total is a
## whole number of 64-byte blocks. The LAST byte of the filler says how many
## filler bytes there are:
##
##   plaintext (5 bytes)              padded to one 64-byte block
##   +---+---+---+---+---+            +---+---+---+---+---+-----------+----+
##   | h | e | l | l | o |    -->     | h | e | l | l | o | 0 0 ... 0 | 59 |
##   +---+---+---+---+---+            +---+---+---+---+---+-----------+----+
##                                      \_____ 5 _____/ \____ 59 filler ___/
##                                      \____________ 64 total ____________/
##
## Every message from 0 to 63 bytes now looks the same size on the wire, every
## message from 64 to 127 looks like the next size up, and so on.
##
## Why there is ALWAYS filler
## --------------------------
## The filler is never empty, not even when the plaintext already fills whole
## blocks. If it could be empty there would be no last filler byte to read,
## and a plaintext whose own final byte happened to read as a length would be
## mistaken for a padded one. So a 64-byte plaintext becomes 128 bytes: 64 of
## payload and 64 of filler. Filler length is therefore always 1 to 64, and
## the byte that states it can never be ambiguous.
##
## The filler bytes are zero. They sit inside the encryption, so nothing is
## gained by making them random -- and reading them back gives a cheap check
## that the padding is exactly what this code writes, with no room for a peer
## to smuggle extra bytes past a receiver in space that gets discarded.

import ../../types
import ../types
import runePragmas

const
  ameBlockPaddingBytes* = 64
    ## The block every padded message is rounded up to. Also the largest
    ## number of filler bytes a message can carry, which is why one byte is
    ## always enough to state the count.

proc amePaddingBlock*(p: AmePaddingPolicy): int {.role: parser.} =
  ## p: policy whose block size in bytes is returned. `apadNone` has none,
  ## and its wire value is zero, so the two agree on purpose.
  result = int(ord(p))

proc amePaddingPolicyFromId*(id: uint8): AmePaddingPolicy {.role: parser.} =
  ## id: the one byte a peer used to name a padding policy. Only the defined
  ## values decode; anything else is refused rather than treated as "off".
  case id
  of 0'u8: result = apadNone
  of 64'u8: result = apadBlock64
  else:
    raise newException(ValueError, "AME padding policy is not 0 or 64")

proc amePaddedLen*(n: int, p: AmePaddingPolicy): int {.role: parser.} =
  ## n/p: plaintext length and policy, giving the length after padding.
  ## Callers size a frame header with this BEFORE sealing anything.
  var
    block1: int = amePaddingBlock(p)
  if n < 0:
    raise newException(ValueError, "AME padded length is negative")
  if block1 == 0:
    return n
  if n > high(int) - block1:
    raise newException(ValueError, "AME padded length overflows")
  result = n + block1 - (n mod block1)

proc padAmeMessage*(A: openArray[uint8], p: AmePaddingPolicy): ByteSeq {.
    role: encryptor, tag: "cryptoBoundary".} =
  ## A/p: plaintext and policy. Returns the bytes that get encrypted.
  var
    total: int = amePaddedLen(A.len, p)
    i: int = 0
  if p == apadNone:
    return @A
  result = newSeq[uint8](total)
  while i < A.len:
    result[i] = A[i]
    i = i + 1
  result[total - 1] = uint8(total - A.len)

proc unpadAmeMessage*(A: openArray[uint8], p: AmePaddingPolicy): ByteSeq {.
    role: parser, tag: "cryptoBoundary|parsing|validation".} =
  ## A/p: bytes that came out of a successful decryption, and the policy this
  ## side agreed. Anything that is not exactly what `padAmeMessage` writes is
  ## refused -- length, filler and all.
  var
    block1: int = amePaddingBlock(p)
    filler: int = 0
    i: int = 0
  if p == apadNone:
    return @A
  if A.len == 0 or (A.len mod block1) != 0:
    raise newException(ValueError, "AME padded length is not a whole block")
  filler = int(A[A.len - 1])
  if filler < 1 or filler > block1 or filler > A.len:
    raise newException(ValueError, "AME padding length byte is out of range")
  i = A.len - filler
  while i < A.len - 1:
    if A[i] != 0'u8:
      raise newException(ValueError, "AME padding filler is not zero")
    i = i + 1
  result = @A[0 ..< A.len - filler]
