## ---------------------------------------------------------------------
## DAC Scramble Tests <- send delay and chunk-order blurring
## ---------------------------------------------------------------------

import unittest

import ../src/protocols/dac/level1/scramble

proc sortedOrder(A: seq[uint16]): seq[uint16] =
  ## A: chunk order whose sorted copy proves it is a permutation.
  var
    i: int = 0
    j: int = 0
    t: uint16 = 0'u16
  result = A
  while i < result.len:
    j = i + 1
    while j < result.len:
      if result[j] < result[i]:
        t = result[i]
        result[i] = result[j]
        result[j] = t
      j = j + 1
    i = i + 1

proc identityOrder(n: int): seq[uint16] =
  ## n: chunk count whose in-order id list is returned.
  var
    i: int = 0
  result = newSeq[uint16](n)
  while i < n:
    result[i] = uint16(i)
    i = i + 1

suite "DAC scramble policy":
  test "an inverted delay range is refused":
    expect ValueError:
      discard initDacScramblePolicy(20'u16, 5'u16)

  test "the quiet policy does nothing and says so":
    var
      p: DacScramblePolicy = quietDacScramblePolicy()
      S: DacScrambleState = initDacScrambleState(1'u64)
    check not dacScrambleActive(p)
    check dacScrambleDelayMs(S, p) == 0'u16
    check dacChunkSendOrder(S, p, 16) == identityOrder(16)

  test "shuffling alone counts as active":
    check dacScrambleActive(initDacScramblePolicy(0'u16, 0'u16, true))
    check dacScrambleActive(initDacScramblePolicy(1'u16, 4'u16, false))

suite "DAC scramble delay":
  test "every draw lands inside the configured range":
    var
      p: DacScramblePolicy = initDacScramblePolicy(3'u16, 11'u16)
      S: DacScrambleState = initDacScrambleState(0xDEADBEEF'u64)
      d: uint16 = 0'u16
      i: int = 0
    while i < 5000:
      d = dacScrambleDelayMs(S, p)
      check d >= 3'u16
      check d <= 11'u16
      i = i + 1

  test "the draws actually vary and cover both ends":
    var
      p: DacScramblePolicy = initDacScramblePolicy(3'u16, 11'u16)
      S: DacScrambleState = initDacScrambleState(7'u64)
      seen: set[uint8] = {}
      i: int = 0
    while i < 5000:
      seen.incl(uint8(dacScrambleDelayMs(S, p)))
      i = i + 1
    check 3'u8 in seen
    check 11'u8 in seen
    check card(seen) == 9

  test "an equal range gives a fixed delay":
    var
      p: DacScramblePolicy = initDacScramblePolicy(7'u16, 7'u16)
      S: DacScrambleState = initDacScrambleState(3'u64)
      i: int = 0
    while i < 100:
      check dacScrambleDelayMs(S, p) == 7'u16
      i = i + 1

  test "different seeds diverge, the same seed repeats":
    var
      p: DacScramblePolicy = initDacScramblePolicy(0'u16, 1000'u16)
      a: DacScrambleState = initDacScrambleState(11'u64)
      b: DacScrambleState = initDacScrambleState(11'u64)
      c: DacScrambleState = initDacScrambleState(12'u64)
      same: bool = true
      differs: bool = false
      i: int = 0
    while i < 50:
      if dacScrambleDelayMs(a, p) != dacScrambleDelayMs(b, p):
        same = false
      i = i + 1
    a = initDacScrambleState(11'u64)
    i = 0
    while i < 50:
      if dacScrambleDelayMs(a, p) != dacScrambleDelayMs(c, p):
        differs = true
      i = i + 1
    check same
    check differs

suite "DAC chunk order":
  test "a shuffled order is still every chunk exactly once":
    var
      p: DacScramblePolicy = initDacScramblePolicy()
      S: DacScrambleState = initDacScrambleState(99'u64)
      n: int = 0
      order: seq[uint16] = @[]
    while n <= 64:
      order = dacChunkSendOrder(S, p, n)
      check order.len == n
      check sortedOrder(order) == identityOrder(n)
      n = n + 1

  test "a large package does get reordered":
    var
      p: DacScramblePolicy = initDacScramblePolicy()
      S: DacScrambleState = initDacScrambleState(4242'u64)
      order: seq[uint16] = dacChunkSendOrder(S, p, 256)
    check order != identityOrder(256)
    check sortedOrder(order) == identityOrder(256)

  test "shuffling off leaves the order alone":
    var
      p: DacScramblePolicy = initDacScramblePolicy(3'u16, 11'u16, false)
      S: DacScrambleState = initDacScrambleState(5'u64)
    check dacChunkSendOrder(S, p, 200) == identityOrder(200)

  test "empty and single-chunk packages are handled":
    var
      p: DacScramblePolicy = initDacScramblePolicy()
      S: DacScrambleState = initDacScrambleState(1'u64)
    check dacChunkSendOrder(S, p, 0).len == 0
    check dacChunkSendOrder(S, p, 1) == @[0'u16]

  test "a chunk count past the id width is refused":
    var
      p: DacScramblePolicy = initDacScramblePolicy()
      S: DacScrambleState = initDacScrambleState(1'u64)
    expect ValueError:
      discard dacChunkSendOrder(S, p, int(high(uint16)) + 1)
