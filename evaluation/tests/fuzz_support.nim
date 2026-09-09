## ---------------------------------------------------------------------
## Fuzz Support <- the mutator every parser harness shares
## ---------------------------------------------------------------------
##
## Structured mutation of REAL encodings, not pure noise. A random buffer
## almost never survives a magic check or a length field, so it would leave
## exactly the code paths worth testing untouched. Damaging a valid frame
## instead keeps the parser deep in its own logic while the bytes lie.
##
## Everything here is deterministic: a failure prints the seed and round that
## produced it, and replaying that seed reproduces it exactly.

import unittest

import ../../src/protocols/types
import runePragmas

type
  ## Rng: splitmix64. Small, seedable, and identical on every platform, which
  ## is what makes a reported failure reproducible.
  Rng* = object
    seed*: uint64

proc next*(R: var Rng): uint64 =
  ## R: state advanced one splitmix64 step.
  var
    t: uint64 = 0'u64
  R.seed = R.seed + 0x9E3779B97F4A7C15'u64
  t = R.seed
  t = (t xor (t shr 30)) * 0xBF58476D1CE4E5B9'u64
  t = (t xor (t shr 27)) * 0x94D049BB133111EB'u64
  result = t xor (t shr 31)

proc below*(R: var Rng, n: int): int =
  ## R/n: state and exclusive bound.
  if n <= 0:
    return 0
  result = int(next(R) mod uint64(n))

proc mutate*(R: var Rng, A: ByteSeq): ByteSeq =
  ## R: state driving the choice of mutation.
  ## A: a well-formed encoding to damage in one of five ways: overwrite a byte,
  ## truncate, extend, flip a single bit, or smear a neighbouring byte over its
  ## predecessor. The bit flip matters most -- it produces frames that are
  ## structurally almost right, which is where length maths goes wrong.
  var
    i: int = 0
  result = A
  case below(R, 5)
  of 0:
    if result.len > 0:
      i = below(R, result.len)
      result[i] = uint8(below(R, 256))
  of 1:
    if result.len > 1:
      result.setLen(below(R, result.len))
  of 2:
    result.add(uint8(below(R, 256)))
  of 3:
    if result.len > 0:
      i = below(R, result.len)
      result[i] = result[i] xor uint8(1 shl below(R, 8))
  else:
    if result.len > 2:
      i = below(R, result.len - 1)
      result[i] = result[i + 1]

proc rampBytes*(n: int): ByteSeq =
  ## n: payload length filled with a deterministic ramp.
  var
    i: int = 0
  result = newSeq[uint8](n)
  while i < n:
    result[i] = uint8((i * 11 + 3) mod 251)
    i = i + 1

const
  fuzzRounds* = 3000
    ## Mutations per decoder. High enough that every length field gets walked
    ## past its bounds, low enough that the whole suite stays a few seconds.

template fuzzBody*(name: string, startSeed: uint64, sample: ByteSeq,
    decodeCall: untyped) {.role: orchestrator.} =
  ## name/startSeed/sample: label, reproducible seed, and a valid encoding.
  ## decodeCall: the parser under test, reading the injected `data`.
  ## A value or a CatchableError is a pass. A Defect is a bug and fails the
  ## test with the seed and round needed to reproduce it.
  var
    R: Rng = Rng(seed: startSeed)
    data {.inject.}: ByteSeq = @[]
    round: int = 0
    broke: bool = false
  while round < fuzzRounds and not broke:
    data = mutate(R, sample)
    try:
      decodeCall
    except CatchableError:
      discard
    except Defect as e:
      checkpoint(name & " raised a Defect at seed " & $startSeed &
        " round " & $round & ": " & e.msg)
      broke = true
    round = round + 1
  check not broke
