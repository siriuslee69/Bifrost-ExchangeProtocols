## -------------------------------------------------------------------------
## AME Header Protection <- hiding the frame counter from anyone watching
## -------------------------------------------------------------------------
##
## The AME header cannot be encrypted. A receiver has to read it before it
## knows which keys to reach for, so session id, lane and sequence all travel
## in the clear and are authenticated rather than hidden.
##
## Authenticated is not the same as private. The sequence number counts up by
## one per frame, forever, and that is the single most useful field an
## observer can have:
##
##   watching one link          watching two links
##   -----------------          --------------------------------------
##   how much you sent          "these two flows count up together, so
##   when you were idle          they are the same conversation"
##   when you restarted
##
## The second column is the one that matters for a relay. The whole point of
## forwarding through one is that the traffic arriving at the relay and the
## traffic leaving it should not obviously be the same traffic. A counter in
## the clear on both sides undoes that on its own.
##
## So the counter is masked. Four bytes, XORed with a mask nobody without the
## keys can produce:
##
##   +------------------------- the frame on the wire -------------------+
##   | 0          22      26        39                55                 |
##   | "AME"...   SEQ     payload   sample(16 bytes)  ...ciphertext      |
##   +------|------------------------|--------------------------------- +
##          |                        |
##          |                        v
##          |            BLAKE3-MAC(headerKey, sample) -> 4 bytes
##          |                        |
##          +<------- XOR -----------+
##
## Reading it back is the same operation: XOR is its own inverse, and the
## sample sits in the part of the frame that is NOT masked, so a receiver can
## take it before it has unmasked anything.
##
## ┊ Why a sample of the payload and not the sequence itself ┊
##
## The mask has to change every frame, or the same counter value would always
## produce the same bytes and the counter would be back in the clear one step
## removed. The sample is 16 bytes of the authentication tag, which is a
## different unpredictable value on every single frame, so the mask is too.
##
## ┊ What this does NOT do ┊
##
## It is not a second layer of encryption and it is not authentication. An
## attacker who flips a bit in the masked sequence changes the sequence this
## side recovers, that recovered value goes into the tag calculation, and the
## frame fails to open -- exactly as it did before, because the real sequence
## was always covered by the tag. Header protection buys privacy from someone
## WATCHING. It buys nothing against someone EDITING, because the tag already
## covered that and still does.
##
## ┊ Why BLAKE3 and not Gimli ┊
##
## Because header protection cannot be optional. Both ends must produce the
## same mask or every frame fails, so it cannot depend on a primitive that
## `-d:bifrostSymmetric=` might have left out of one of the two builds.
## BLAKE3 is the one primitive always compiled -- the protocol does not work
## without it -- so it is the only honest choice for a step with no way to
## negotiate. Keyed BLAKE3 with a 4-byte output is a cheap call: one
## compression over 16 bytes, no key schedule, nothing to set up per frame.

import ./symmetric

import ../../types
import ../types
import ../level0/bytes
import ./derivation
import runePragmas

const
  ameHeaderMaskOffset* = 22
    ## Where the sequence sits in the header. See level2/wire.nim.
  ameHeaderMaskLen* = 4
    ## How many bytes of it are masked: the whole sequence.
  ameHeaderMaskDrawLen = 16
    ## How many mask bytes are produced before being cut down to the four
    ## that are used. The MAC will not go below sixteen.
  ameHeaderSampleOffset* = 39
    ## Where the mask input is taken from, counted from the start of the
    ## frame: 26 bytes of AME header plus the 13-byte FOMKE envelope, which
    ## lands on the first byte of the authentication tag.
  ameHeaderSampleLen* = 16
    ## How much of it is used.
  ameHeaderMinFrameLen* = ameHeaderSampleOffset + ameHeaderSampleLen
    ## The shortest frame this can run on, 55 bytes. A real frame is never
    ## shorter: 26 header + 13 envelope + a tag of at least 16 is exactly 55
    ## with an empty payload, and anything carrying data is longer.
  ameHeaderProtectLabel* = "AME-HEADER-PROTECT-v1"
    ## Separates this key from every other key the same epoch derives.

proc deriveAmeHeaderKey*(S: AmeExchangeState, L: AmeSuiteLayout,
    t: AmeMaskTier, context: openArray[byte]): ByteSeq {.role: truthBuilder,
    tag: "ame|cryptoBoundary|kdf".} =
  ## S/L/t: the epoch's exchange state, slot layout and active slots.
  ## context: the epoch's traffic context, which already names the session id,
  ##   the epoch number, the direction and the transcript salt. Passing it in
  ##   rather than building it here keeps this module below the session layer
  ##   that knows those things.
  ##
  ## Derived ONCE per epoch per direction and kept, because deriving it runs
  ## every switched-on KDF slot -- work worth doing once and never per frame.
  result = deriveAmeLayerKey(S, L, t, ameHeaderProtectLabel,
    ameProtectionKeyLen, context)

proc requireAmeHeaderKey(key: openArray[uint8]) {.role: parser,
    tag: "ame|validation", inline.} =
  ## key: refused unless it is a full-length header key.
  ##
  ## An empty key is NOT treated as "protection off". Both ends must mask or
  ## neither can, so a missing key is a bug in the session that built it, and
  ## quietly sending the counter in the clear is the worst way to report one.
  if key.len != ameProtectionKeyLen:
    raise newException(ValueError, "AME header key is missing or wrong length")

proc requireAmeMaskableFrame(n: int) {.role: parser,
    tag: "ame|validation", inline.} =
  ## n: frame length refused unless the mask input fits inside it.
  if n < ameHeaderMinFrameLen:
    raise newException(ValueError,
      "AME frame is too short to carry header protection")

proc ameHeaderMask(key, sample: openArray[uint8]): ByteSeq {.role: math,
    tag: "ame|cryptoBoundary", inline.} =
  ## key/sample: the epoch's header key and this frame's 16 tag bytes.
  ##
  ## Sixteen bytes are asked for and four are used. `blake3AmeMac` refuses to
  ## produce fewer than sixteen, and it is right to: a short MAC is a weak
  ## MAC, and it cannot tell that this caller wants a mask rather than a tag.
  ## Truncating a keyed hash is the ordinary way to size one down, and the
  ## discarded bytes never leave this routine.
  result = blake3AmeMac(key, sample, ameHeaderMaskDrawLen)
  result.setLen(ameHeaderMaskLen)

proc maskAmeFrameHeader*(F: var ByteSeq, key: openArray[uint8]) {.role: actor,
    tag: "ame|cryptoBoundary|wire".} =
  ## F: one whole encoded frame, masked or unmasked in place.
  ## key: the header key for this epoch and direction.
  ##
  ## One routine does both jobs. XOR is its own inverse and the sample is
  ## taken from a part of the frame this never touches, so masking a frame and
  ## then masking it again returns the frame that went in. There is no pair of
  ## routines here to get the wrong way round.
  var
    mask: ByteSeq = @[]
    i: int = 0
  requireAmeHeaderKey(key)
  requireAmeMaskableFrame(F.len)
  mask = ameHeaderMask(key, F.toOpenArray(ameHeaderSampleOffset,
    ameHeaderSampleOffset + ameHeaderSampleLen - 1))
  while i < ameHeaderMaskLen:
    F[ameHeaderMaskOffset + i] = F[ameHeaderMaskOffset + i] xor mask[i]
    i = i + 1
  secureClearAmeBytes(mask)

proc unmaskedAmeFrameSequence*(F: openArray[uint8],
    key: openArray[uint8]): uint32 {.role: parser,
    tag: "ame|cryptoBoundary|wire".} =
  ## F/key: an arriving frame and the header key for its direction.
  ##
  ## Recovers the true sequence without copying the frame. The caller writes
  ## it back into the decoded header before the header is fed to the tag, so
  ## everything downstream -- binding checks, the replay window, the tag
  ## itself -- sees the number the sender actually used.
  var
    mask: ByteSeq = @[]
    i: int = 0
  requireAmeHeaderKey(key)
  requireAmeMaskableFrame(F.len)
  mask = ameHeaderMask(key, F.toOpenArray(ameHeaderSampleOffset,
    ameHeaderSampleOffset + ameHeaderSampleLen - 1))
  while i < ameHeaderMaskLen:
    result = result or (uint32(F[ameHeaderMaskOffset + i] xor mask[i]) shl
      (8 * i))
    i = i + 1
  secureClearAmeBytes(mask)
