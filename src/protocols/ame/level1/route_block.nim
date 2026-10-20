## -------------------------------------------------------------------------
## AME Route Block <- who a routed frame is for, sealed in one Gimli block
## -------------------------------------------------------------------------
##
## A routed frame names two ids: where it goes (target) and who sent it
## (origin). Those 16 bytes are the ONLY part of a route frame that is
## encrypted per hop. The payload behind them is not touched; it is the
## sender's own end-to-end AME frame, which no router holds a key for.
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
## ╭─ ❧ Def. 3: the nonce is the frame's header 🍣
##
## The caller (level2/route_wire.nim) builds the 16 nonce bytes from the
## route frame's own clear header: magic, kind, hops or reason, the link's
## route counter and the payload length. So the tag covers the header too,
## at no extra cost: a changed counter, hop count, reason or length makes
## the tag fail, exactly like a changed id.
##
## The key is per session, per epoch and per direction, and the counter
## never repeats on one link. So no two blocks ever share key AND nonce.
##
## ╭─ ❧ Why 8 bytes of tag is enough here ⟡
##
## A forger has to guess 64 bits, online, one frame per guess, and every
## wrong guess is dropped without an answer. Meeting the right tag by luck
## takes, on average, 2^63 frames sent at one router.
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
  ameRouteNonceLen* = 16
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

proc startRouteState(key, nonce: openArray[uint8]): Gimli_Block {.
    role: truthBuilder, tag: "ame|cryptoBoundary".} =
  ## key/nonce: state loaded with nonce then key, shuffled once.
  var
    i: int = 0
  if key.len != ameRouteKeyLen:
    raise newException(ValueError, "AME route key is missing or wrong length")
  if nonce.len != ameRouteNonceLen:
    raise newException(ValueError, "AME route nonce must be 16 bytes")
  while i < ameRouteNonceLen:
    setStateByte(result, i, nonce[i])
    i = i + 1
  while i < 48:
    setStateByte(result, i, key[i - ameRouteNonceLen])
    i = i + 1
  gimliPermute(result)

proc finishRouteState(G: var Gimli_Block) {.role: math, inline.} =
  ## G: state after the sealed bytes are in; marks the last block and
  ## shuffles a second time, so the first 8 bytes become the tag.
  G[11] = G[11] xor (1'u32 shl 24)
  gimliPermute(G)

proc sealAmeRouteBlock*(key, nonce: openArray[uint8],
    target, origin: uint64): ByteSeq {.role: encryptor,
    tag: "ame|cryptoBoundary".} =
  ## key: this direction's route key (32 bytes).
  ## nonce: 16 bytes built from the frame header (Def. 3).
  ## target/origin: the two ids.
  ## Returns 24 bytes: 16 sealed + 8 tag (Def. 1).
  var
    G: Gimli_Block = startRouteState(key, nonce)
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

proc openAmeRouteBlock*(key, nonce: openArray[uint8],
    A: openArray[uint8]): AmeRouteIds {.role: decryptor,
    tag: "ame|cryptoBoundary".} =
  ## key: the sender's direction's route key, as this side holds it.
  ## nonce: 16 bytes built from the frame header as it arrived (Def. 3).
  ## A: exactly 24 bytes. `ok` is false on any mismatch, and then neither
  ## id is filled in.
  var
    G: Gimli_Block = default(Gimli_Block)
    plain: ByteSeq = newSeq[uint8](ameRouteIdsLen)
    tag: ByteSeq = newSeq[uint8](ameRouteTagLen)
    i: int = 0
  if A.len != ameRouteBlockLen:
    return
  G = startRouteState(key, nonce)
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
