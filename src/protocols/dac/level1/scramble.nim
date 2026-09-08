## ----------------------------------------------------------------------
## DAC Scramble <- blur send timing and chunk order so probes learn nothing
## ----------------------------------------------------------------------

import ../build

when not dacAdaptiveBuilt:
  {.error: "This module is part of the DAC adaptive layer, which -d:bifrostDac=off removed from this build.".}

import bifrostPragmas

const
  dacScrambleAscii* = """
An attacker who can send packages and watch what comes back learns from two
free channels: HOW LONG a reply took, and IN WHICH ORDER chunks appeared.
Both are closed by the sender alone, with no memory of who is asking.

  plain                          scrambled
  -----                          ---------
  C0 C1 C2 C3 C4                 C3 C0 C4 C1 C2
  |  |  |  |  |                  |    |   |  |   |
  +--+--+--+--+  even gaps       +----+---+--+---+  uneven gaps
  always in order                order carries nothing

Chunks are self-describing -- each one names its own id and offset -- so a
receiver reassembles a shuffled package exactly as it does an ordered one.
No agreement, no negotiation, nothing on the wire changes.

There is deliberately NO per-client tracking here. Remembering who probed
what is a table an attacker can grow, and a thousand connections would cost
more memory than the defence is worth.
"""

  dacScrambleMixA = 0x9E3779B97F4A7C15'u64
  dacScrambleMixB = 0xBF58476D1CE4E5B9'u64
  dacScrambleMixC = 0x94D049BB133111EB'u64

type
  ## DacScramblePolicy: how far a sender is willing to blur its own output.
  ## minDelayMs/maxDelayMs: inclusive range a per-package delay is drawn from.
  ## shuffleChunks: emit a package's chunks in a random order.
  DacScramblePolicy* {.role: configurator.} = object
    minDelayMs*: uint16
    maxDelayMs*: uint16
    shuffleChunks*: bool

  ## DacScrambleState: eight bytes of sender-local randomness, nothing else.
  ## seed: advanced once per draw; never sent and never derived from a peer.
  DacScrambleState* {.role: truthState.} = object
    seed*: uint64

proc initDacScramblePolicy*(minDelayMs: uint16 = 3'u16,
    maxDelayMs: uint16 = 11'u16,
    shuffleChunks: bool = true): DacScramblePolicy {.role: configurator.} =
  ## minDelayMs/maxDelayMs: inclusive delay range; equal values give a fixed
  ## delay, and both zero turns delaying off.
  ## shuffleChunks: whether a package's chunks leave in a random order.
  if maxDelayMs < minDelayMs:
    raise newException(ValueError,
      "DAC scramble delay range must not be inverted")
  result.minDelayMs = minDelayMs
  result.maxDelayMs = maxDelayMs
  result.shuffleChunks = shuffleChunks

proc quietDacScramblePolicy*(): DacScramblePolicy {.role: configurator.} =
  ## Return the policy that changes nothing, for paths where the extra
  ## latency costs more than the leak is worth.
  result = initDacScramblePolicy(0'u16, 0'u16, false)

proc dacScrambleActive*(p: DacScramblePolicy): bool {.role: parser.} =
  ## p: policy asked whether it does anything at all.
  result = p.shuffleChunks or p.maxDelayMs > 0'u16

proc initDacScrambleState*(seed: uint64): DacScrambleState {.role: configurator.} =
  ## seed: sender-local starting value. Feed it something the peer cannot
  ## guess; a session key byte or a system random word both work.
  result.seed = seed

proc nextDacScramble(S: var DacScrambleState): uint64 {.role: math.} =
  ## S: state advanced by one splitmix64 step.
  var
    t: uint64 = 0'u64
  S.seed = S.seed + dacScrambleMixA
  t = S.seed
  t = (t xor (t shr 30)) * dacScrambleMixB
  t = (t xor (t shr 27)) * dacScrambleMixC
  result = t xor (t shr 31)

proc dacScrambleBelow(S: var DacScrambleState, n: uint64): uint64 {.role: math.} =
  ## S: state advanced by one draw.
  ## n: exclusive upper bound; zero returns zero.
  if n == 0'u64:
    return 0'u64
  result = nextDacScramble(S) mod n

proc dacScrambleDelayMs*(S: var DacScrambleState,
    p: DacScramblePolicy): uint16 {.role: math.} =
  ## S: state advanced by one draw.
  ## p: policy holding the delay range.
  ## Returns milliseconds to wait before sending. This never sleeps; the
  ## caller schedules it, so a single-threaded or async sender is not blocked.
  if p.maxDelayMs == 0'u16:
    return 0'u16
  result = p.minDelayMs + uint16(dacScrambleBelow(S,
    uint64(p.maxDelayMs - p.minDelayMs) + 1'u64))

proc dacChunkSendOrder*(S: var DacScrambleState, p: DacScramblePolicy,
    n: int): seq[uint16] {.role: actor.} =
  ## S: state advanced once per swap when shuffling.
  ## p: policy deciding whether the order is shuffled at all.
  ## n: number of chunks in the package.
  ## Returns the chunk ids in the order they should be sent. Walk it and emit
  ## `plan.chunks[id]`; the receiver already accepts chunks in any order.
  var
    i: int = 0
    j: int = 0
    t: uint16 = 0'u16
  if n < 0 or n > int(high(uint16)):
    raise newException(ValueError, "DAC package chunk count is out of range")
  result = newSeq[uint16](n)
  while i < n:
    result[i] = uint16(i)
    i = i + 1
  if not p.shuffleChunks:
    return
  i = n - 1
  while i > 0:
    j = int(dacScrambleBelow(S, uint64(i) + 1'u64))
    t = result[i]
    result[i] = result[j]
    result[j] = t
    i = i - 1
