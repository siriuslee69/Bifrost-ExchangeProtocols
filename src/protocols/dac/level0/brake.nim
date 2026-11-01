## -------------------------------------------------------------------------
## DAC Brake <- a relay tells a neighbour to slow down, in two bits
## -------------------------------------------------------------------------
##
## A relay in the middle can be crowded while its neighbours (clients, servers)
## cannot see that. The relay says so with ONE byte and its neighbour slows its
## own sending. Only a relay may say it.
##
##   level   bits   meaning                    wait added   chunk size
##   -----   ----   -------------------------  ----------   ----------
##     0     00     no congestion, go ham          0 ms        100 %
##     1     01     a little crowded               4 ms         75 %
##     2     10     crowded                       16 ms         50 %
##     3     11     full brakes                   64 ms         25 %
##
## "wait added" is put on top of whatever wait the link already draws (the
## scramble delay). "chunk size" is how much of the usual chunk a package is cut
## into; it never goes below `dacBrakeMinChunkBytes`.
##
## ┊ The three messages ┊
##
##   dmkBrake        relay -> neighbour   [ level u8 ]   level 0..3, nothing else
##   dmkBrakeStance  neighbour -> relay   [ follows u8 ] 1 = I follow, 0 = I do not
##
## An order is a LEASE, not a switch. It lapses `dacBrakeHoldMs` after it
## arrived, so a lost "back to 00" can never leave a link slow for good. The
## relay repeats a non-zero order every `dacBrakeRefreshMs` to keep it alive.
##
## ┊ One byte of state per side ┊
##
## A neighbour keeps the bits of `DacBrakeBits` (one u8) per connection:
##
##   bit:   7 6 5   4        3        2         1 0
##          - - -   stance   refuse   fromRelay level obeyed
##                  pending  orders   (peer is  (0..3)
##                                     a relay)
##
## A byte of 0 is the normal case: level 0, orders from relays are followed.

import ../../types
import runePragmas
import var_invariants

const
  dacBrakeMaxLevel* = 3'u8
  dacBrakeGapMs*: array[4, uint16] = [0'u16, 4'u16, 16'u16, 64'u16]
    ## Milliseconds added to the wait before each datagram, per level.
  dacBrakeChunkPercent*: array[4, uint16] = [100'u16, 75'u16, 50'u16, 25'u16]
    ## Share of the usual chunk size a package is cut into, per level.
  dacBrakeMinChunkBytes*: uint16 = 128'u16
    ## A chunk is never cut smaller than this; below it the headers outweigh
    ## the payload and the brake would only add load.
  dacBrakeHoldMs*: uint32 = 30_000'u32
    ## How long an order lasts without being repeated.
  dacBrakeRefreshMs*: uint32 = 10_000'u32
    ## How often a relay repeats a non-zero order. Three tries per lease.

  dacBrakeLevelMask*: uint8 = 0b0000_0011'u8
  dacBrakeFromRelay*: uint8 = 0b0000_0100'u8
  dacBrakeRefuse*: uint8 = 0b0000_1000'u8
  dacBrakeStancePending*: uint8 = 0b0001_0000'u8
  dacBrakeDeaf*: uint8 = 0b0010_0000'u8
    ## Set by whoever ORDERS: the peer said it will not follow orders. Same
    ## bit on a relay's neighbour and on a server's client link.

type
  ## DacBrakeBits: the one byte a neighbour keeps per connection (see top).
  DacBrakeBits* = uint8

proc encodeDacBrake*(level: uint8): ByteSeq {.role: dataWriter,
    needs: level <= 3'u8.} =
  ## level: 0 (no brake) .. 3 (full brakes). The body is that single byte.
  result = @[level]

proc decodeDacBrake*(A: openArray[uint8]): uint8 {.role: parser,
    gives: result <= 3'u8.} =
  ## A: a dmkBrake body. One byte, 0..3. Anything else is refused, so the six
  ## spare bits stay free for a later version instead of meaning something by
  ## accident.
  if A.len != 1 or A[0] > dacBrakeMaxLevel:
    raise newException(ValueError, "DAC brake body must be one byte, 0..3")
  result = A[0]

proc encodeDacBrakeStance*(follows: bool): ByteSeq {.role: dataWriter.} =
  ## follows: whether this side obeys a relay's dmkBrake.
  result = @[if follows: 1'u8 else: 0'u8]

proc decodeDacBrakeStance*(A: openArray[uint8]): bool {.role: parser.} =
  ## A: a dmkBrakeStance body. One byte, 0 or 1.
  if A.len != 1 or A[0] > 1'u8:
    raise newException(ValueError, "DAC brake stance must be one byte, 0 or 1")
  result = A[0] == 1'u8

proc dacBrakeChunkBytes*(chunkBytes: uint16, level: uint8): uint16 {.
    role: math, needs: level <= 3'u8, gives: result <= chunkBytes or
    chunkBytes < dacBrakeMinChunkBytes.} =
  ## chunkBytes: the usual chunk size. level: the brake level.
  ## A chunk already smaller than the floor is left alone.
  var
    t: uint32 = 0'u32
  if chunkBytes <= dacBrakeMinChunkBytes:
    return chunkBytes
  t = uint32(chunkBytes) * uint32(dacBrakeChunkPercent[int(level)]) div 100'u32
  result = uint16(max(t, uint32(dacBrakeMinChunkBytes)))

proc dacBrakeForLoad*(used, capacity: int): uint8 {.role: math.} =
  ## used/capacity: how full the relay's queue or table is.
  ## A suggestion a relay may use instead of choosing a level itself:
  ##
  ##   below 50 % full  -> 0     50..74 % -> 1     75..89 % -> 2     90 %+ -> 3
  if capacity <= 0 or used <= 0:
    return 0'u8
  if used * 10 >= capacity * 9:
    return 3'u8
  if used * 4 >= capacity * 3:
    return 2'u8
  if used * 2 >= capacity:
    return 1'u8
  result = 0'u8
