## -------------------------------------------------------------------------
## AME Route Block <- who a routed message is for, sealed in one Gimli block
## -------------------------------------------------------------------------
##
## A routed message names two ids: where it goes (target) and who sent it
## (origin). Those 16 bytes are sealed on their own, with their own key,
## before the whole message is sealed again by the session ratchet:
##
##   +------------------ plaintext inside the AME frame ------------------+
##   | kind | route block (24)                 | hops | payload ...       |
##   |      | sealed ids (16)   | tag (8)      |      |                   |
##   +--------------------------------------------------------------------+
##     \______________________________________________________________/
##                  all of this is sealed AGAIN by FOMKE
##
## ╭─ ❧ Def. 1: the block 🌊
##
##   byte   0 ........ 7   8 ........ 15  16 ............. 23
##          target id      origin id      tag (first 8 bytes)
##          u64 LE         u64 LE         of the Gimli state
##          \___________ sealed ________/
##
## Example 1. A phone (id 0x30) sends to a NAS (id 0x20):
##
##   plain   20 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
##           \___ target 0x20 ____/   \_ origin 0: router fills it _/
##   sealed  9c 41 ... (16 bytes that look random) | 8 tag bytes
##
## ╭─ ❧ Def. 2: how one block is sealed 🐦‍🔥
##
## Gimli is a 48-byte state, shuffled by one fixed routine (the
## "permutation"). The first 16 bytes are the part data touches (the
## "rate"); the other 32 are never seen from outside.
##
##   state   [ nonce 16 bytes ][ key 32 bytes                     ]
##              |
##              v  shuffle (1)
##   state   [ R 16 bytes     ][ ...                              ]
##   sealed  =  R xor plain           <- this is the 16 sealed bytes
##   state   [ sealed         ][ ... last byte xor 0x01           ]
##              |
##              v  shuffle (2)
##   tag     =  first 8 bytes of the state
##
## Opening runs the same two shuffles. The receiver puts the SEALED bytes
## back into the state before shuffle (2), so it ends in the same state as
## the sender and the tag matches. One changed bit anywhere -- key, nonce,
## either id, the tag -- and the 8 bytes differ.
##
## The `xor 0x01` into the hidden part marks "this was the last block". The
## block is always exactly 16 bytes, so no padding rule is needed.
##
## ╭─ ❧ Def. 3: the nonce 🍣
##
##   byte  0  1  2  3   4      5  6  7   8 ......... 11   12 ...... 15
##         A  M  R  B   kind   00 00 00  frame counter   00 00 00 00
##                                       u32 LE
##
## The frame counter is the AME sequence of the frame the block rides in,
## which the ratchet's tag also covers. The key is per session, per epoch
## and per direction. So no two blocks ever share key AND nonce, and a block
## copied from frame 41 into frame 42 -- or from a forward into a refusal --
## fails its tag.
##
## ╭─ ❧ Why 8 bytes of tag is enough here ⟡
##
## A forger has to guess 64 bits, online, one frame per guess, and every
## wrong guess is thrown away without an answer. On top of that, the block
## only ever arrives inside a frame the ratchet already authenticated, so
## the guess has to be made by someone holding the session keys anyway.
## The tag is there so a router never acts on a target id that was not
## sealed for THIS frame, with THIS direction's key.
##
## ╭─ ❧ Why Gimli and not a negotiated cipher ⟡
##
## Route blocks are not negotiated, so both ends must always have the same
## primitive. Only the bare permutation is used (no sponge mode), it is a
## few hundred bytes of code, and it is compiled whatever
## `-d:bifrostSymmetric=` says.

import tyr/ciphers/gimli as tyr_gimli

import ../../types
import ../types
import ../level0/bytes
import ./derivation
import runePragmas

const
  ameRouteIdsLen* = 16
    ## target u64 + origin u64: exactly one Gimli rate block.
  ameRouteTagLen* = 8
  ameRouteBlockLen* = ameRouteIdsLen + ameRouteTagLen
  ameRouteKeyLen* = 32
  ameRouteBlockLabel* = "AME-ROUTE-BLOCK-v1"
    ## Separates this key from every other key the same epoch derives.

type
  ## AmeRouteIds: the two ids a route block carries, after it opened.
  AmeRouteIds* {.role: preparedData, expectedCount: [0, 512],
      lifeCycle: lcScratch.} = object
    ok*: bool
    target*: uint64
    origin*: uint64

proc deriveAmeRouteKey*(S: AmeExchangeState, L: AmeSuiteLayout,
    t: AmeMaskTier, context: openArray[byte]): ByteSeq {.role: truthBuilder,
    tag: "ame|cryptoBoundary|kdf".} =
  ## S/L/t: the epoch's exchange state, slot layout and active slots.
  ## context: the epoch's traffic context (session, epoch, direction, salt).
  ## Derived once per epoch per direction, beside the header key.
  result = deriveAmeLayerKey(S, L, t, ameRouteBlockLabel, ameRouteKeyLen,
    context)

proc stateByte(G: Gimli_Block, i: int): uint8 {.role: parser, inline.} =
  ## G/i: byte i of the state, counted the way the reference code counts it
  ## (each 32-bit word little-endian, words in order).
  result = uint8((G[i div 4] shr (8 * (i mod 4))) and 0xff'u32)

proc setStateByte(G: var Gimli_Block, i: int, v: uint8) {.role: actor,
    inline.} =
  ## G/i/v: byte i of the state replaced by v.
  var
    shift: int = 8 * (i mod 4)
  G[i div 4] = (G[i div 4] and not (0xff'u32 shl shift)) or
    (uint32(v) shl shift)

proc routeNonce(kind: AmeRouteKind, sequence: uint32): array[16, uint8] {.
    role: truthBuilder.} =
  ## kind/sequence: the message kind and the AME frame counter (Def. 3).
  result[0] = uint8('A')
  result[1] = uint8('M')
  result[2] = uint8('R')
  result[3] = uint8('B')
  result[4] = uint8(ord(kind))
  result[8] = uint8(sequence and 0xff'u32)
  result[9] = uint8((sequence shr 8) and 0xff'u32)
  result[10] = uint8((sequence shr 16) and 0xff'u32)
  result[11] = uint8((sequence shr 24) and 0xff'u32)

proc startRouteState(key: openArray[uint8], kind: AmeRouteKind,
    sequence: uint32): Gimli_Block {.role: truthBuilder,
    tag: "ame|cryptoBoundary".} =
  ## key/kind/sequence: state loaded with nonce then key, shuffled once.
  var
    nonce: array[16, uint8] = routeNonce(kind, sequence)
    i: int = 0
  if key.len != ameRouteKeyLen:
    raise newException(ValueError, "AME route key is missing or wrong length")
  while i < 16:
    setStateByte(result, i, nonce[i])
    i = i + 1
  while i < 48:
    setStateByte(result, i, key[i - 16])
    i = i + 1
  gimliPermute(result)

proc finishRouteState(G: var Gimli_Block) {.role: math, inline.} =
  ## G: state after the sealed bytes are in; marks the last block and
  ## shuffles a second time, so the first 8 bytes become the tag.
  G[11] = G[11] xor (1'u32 shl 24)
  gimliPermute(G)

proc sealAmeRouteBlock*(key: openArray[uint8], kind: AmeRouteKind,
    sequence: uint32, target, origin: uint64): ByteSeq {.role: encryptor,
    tag: "ame|cryptoBoundary".} =
  ## key: this direction's route key (32 bytes).
  ## kind/sequence: message kind and frame counter, bound as the nonce.
  ## target/origin: the two ids.
  ## Returns 24 bytes: 16 sealed + 8 tag (Def. 1).
  var
    G: Gimli_Block = startRouteState(key, kind, sequence)
    plain: ByteSeq = @[]
    c: uint8 = 0
    i: int = 0
  appendAmeU64(plain, target)
  appendAmeU64(plain, origin)
  result = newSeq[uint8](ameRouteBlockLen)
  while i < ameRouteIdsLen:
    c = stateByte(G, i) xor plain[i]
    setStateByte(G, i, c)
    result[i] = c
    i = i + 1
  finishRouteState(G)
  i = 0
  while i < ameRouteTagLen:
    result[ameRouteIdsLen + i] = stateByte(G, i)
    i = i + 1
  secureClearAmeBytes(plain)
  G = default(Gimli_Block)

proc openAmeRouteBlock*(key: openArray[uint8], kind: AmeRouteKind,
    sequence: uint32, A: openArray[uint8]): AmeRouteIds {.role: decryptor,
    tag: "ame|cryptoBoundary".} =
  ## key: the sender's direction's route key, as this side holds it.
  ## kind/sequence: message kind and frame counter, bound as the nonce.
  ## A: exactly 24 bytes. `ok` is false on any mismatch, and then neither
  ## id is filled in.
  var
    G: Gimli_Block = default(Gimli_Block)
    plain: ByteSeq = newSeq[uint8](ameRouteIdsLen)
    tag: ByteSeq = newSeq[uint8](ameRouteTagLen)
    i: int = 0
  if A.len != ameRouteBlockLen:
    return
  G = startRouteState(key, kind, sequence)
  while i < ameRouteIdsLen:
    plain[i] = stateByte(G, i) xor A[i]
    setStateByte(G, i, A[i])
    i = i + 1
  finishRouteState(G)
  i = 0
  while i < ameRouteTagLen:
    tag[i] = stateByte(G, i)
    i = i + 1
  G = default(Gimli_Block)
  if constantTimeEqualAme(tag, A.toOpenArray(ameRouteIdsLen,
      ameRouteBlockLen - 1)):
    result.ok = true
    result.target = readAmeU64(plain, 0)
    result.origin = readAmeU64(plain, 8)
  secureClearAmeBytes(plain)
