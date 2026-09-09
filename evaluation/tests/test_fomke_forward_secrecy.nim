## -------------------------------------------------------------------------
## FOMKE Forward Secrecy <- what a seized machine can and cannot read
## -------------------------------------------------------------------------
##
## "Forward secrecy" means one thing here, and these tests are what it means:
##
##   Taking every byte of a machine's memory RIGHT NOW must not open the
##   messages it already sent or received.
##
## The mechanism is that using a key destroys it, and the step that produced
## it runs only forwards:
##
##   chainKey(0) --step--> chainKey(1) --step--> chainKey(2)
##       |                     |                     |
##   messageKey 0          messageKey 1          messageKey 2
##       |                     |                     |
##   used, then wiped      used, then wiped      still to come
##
## Each test below tries one way of getting an old message back out of a
## state that has moved past it.

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/tier_aead
import ../../src/protocols/fomke/types
import ../../src/protocols/fomke/level0/gb3hkdf
import ../../src/protocols/fomke/level1/chain
import ../../src/protocols/fomke/level2/wire
import runePragmas

const
  fsKems: AmeKemAlgorithms = [akaX25519, akaKyber768]

proc fsLayout(): AmeSuiteLayout =
  result = defaultAmeLayout(fsKems)

proc fsTier(kemMask: uint8 = 0b11000000'u8): AmeMaskTier =
  var L: AmeSuiteLayout = fsLayout()
  result = initAmeMaskTier(L, 1'u32, initAmeTierMasks(kemMask,
    occupiedAmeMask(L.ciphers.length), occupiedAmeMask(L.macs.length),
    occupiedAmeMask(L.hashes.length), occupiedAmeMask(L.signatures.length),
    occupiedAmeMask(L.kdfs.length)))

proc fsExchange(mask: uint8 = 0b11000000'u8,
    secrets: openArray[ByteSeq] = [@[byte 1, 2, 3, 4], @[byte 5, 6, 7, 8]]):
    AmeExchangeState {.role: configurator.} =
  result = initAmeExchangeState(fsKems)
  applyAmeExchange(result, initAmeExchangeRequest(fsKems, fsTier(mask), mask),
    secrets)

proc fsPair(): tuple[a: FomkeState, b: FomkeState] {.role: configurator.} =
  var
    state: AmeExchangeState = fsExchange()
  result.a = initFomkeFromAme(state, fsLayout(), fsTier(), frInitiator)
  result.b = initFomkeFromAme(state, fsLayout(), fsTier(), frResponder)

suite "FOMKE forward secrecy":
  # {.testKind: tkEdgeCase.}
  test "the state that sent a message cannot open it again afterwards":
    var
      p = fsPair()
      first: FomkeMessage
      second: FomkeMessage
      replay: FomkeState
      opened: FomkeOpenResult
    first = sealFomkeMessage(p.a, @[byte 1, 1, 1])
    check openFomkeMessage(p.b, first).ok
    second = sealFomkeMessage(p.a, @[byte 2, 2, 2])
    check openFomkeMessage(p.b, second).ok
    ## Seize the receiver's state at this exact moment and try the first
    ## message again. The key that opened it was destroyed on use.
    replay = cloneFomkeState(p.b)
    opened = openFomkeMessage(replay, first)
    check not opened.ok
    check opened.err == "FOMKE message key is unavailable or replayed"
    clearFomkeState(replay)

  # {.testKind: tkUnit.}
  test "a captured chain key opens nothing that came before it":
    var
      p = fsPair()
      early: FomkeMessage
      late: FomkeMessage
      seized: FomkeState
      opened: FomkeOpenResult
    early = sealFomkeMessage(p.a, @[byte 9, 9])
    check openFomkeMessage(p.b, early).ok
    late = sealFomkeMessage(p.a, @[byte 8, 8])
    ## `seized` is everything the receiver holds after the early message was
    ## read and destroyed: chain keys, counters, skipped cache, the lot.
    seized = cloneFomkeState(p.b)
    ## It still works going forwards -- so this really is the live state and
    ## not a broken copy.
    opened = openFomkeMessage(seized, late)
    check opened.ok
    check opened.payload == @[byte 8, 8]
    ## And it cannot go backwards.
    opened = openFomkeMessage(seized, early)
    check not opened.ok
    clearFomkeState(seized)

  # {.testKind: tkUnit.}
  test "the chain key is replaced, not extended, on every step":
    var
      p = fsPair()
      before: ByteSeq = @[]
      after: ByteSeq = @[]
    before = p.a.lane1.chainKey & @[]
    discard sealFomkeMessage(p.a, @[byte 1])
    after = p.a.lane1.chainKey & @[]
    check before.len == after.len
    check before != after
    check p.a.lane1.nextIndex == 1'u64

  # {.testKind: tkUnit.}
  test "an epoch change destroys every key from the epoch before it":
    var
      p = fsPair()
      old: FomkeMessage
      upgraded: AmeExchangeState = fsExchange(0b11000000'u8,
        [@[byte 40, 41, 42, 43], @[byte 50, 51, 52, 53]])
      request: AmeExchangeRequest = initAmeExchangeRequest(fsKems, fsTier(),
        0b11000000'u8)
      commitA: FomkeUpgradeCommit
      commitB: FomkeUpgradeCommit
      opened: FomkeOpenResult
    old = sealFomkeMessage(p.a, @[byte 7])
    check openFomkeMessage(p.b, old).ok
    ## A rotation starts from a quiet chain: both sides are at the same lane
    ## positions, which is what makes them derive the same new root.
    commitA = prepareFomkeUpgrade(p.a, 1'u32, 2'u32, request, upgraded)
    commitB = prepareFomkeUpgrade(p.b, 1'u32, 2'u32, request, upgraded)
    check fomkeUpgradeCommitsEqual(commitA, commitB)
    confirmFomkeUpgrade(p.a, commitB)
    confirmFomkeUpgrade(p.b, commitA)
    check p.a.epoch == 2'u32
    check p.b.skipped.len == 0
    ## The old message belongs to an epoch this state no longer has keys for.
    opened = openFomkeMessage(p.b, old)
    check not opened.ok
    check opened.err == "FOMKE epoch or sender lane mismatch"

  # {.testKind: tkUnit.}
  test "a failed open leaves the ratchet exactly where it was":
    var
      p = fsPair()
      good: FomkeMessage
      forged: FomkeMessage
      opened: FomkeOpenResult
      indexBefore: uint64 = 0'u64
      keyBefore: ByteSeq = @[]
    good = sealFomkeMessage(p.a, @[byte 3, 3, 3])
    forged = good
    forged.ciphertext[0] = forged.ciphertext[0] xor 0xFF'u8
    indexBefore = p.b.lane1.nextIndex
    keyBefore = p.b.lane1.chainKey & @[]
    opened = openFomkeMessage(p.b, forged)
    check not opened.ok
    ## Nothing moved. A stranger cannot make this side burn ratchet positions
    ## or fill its skipped-key cache by sending rubbish.
    check p.b.lane1.nextIndex == indexBefore
    check p.b.lane1.chainKey == keyBefore
    check p.b.skipped.len == 0
    ## The genuine message still opens afterwards.
    opened = openFomkeMessage(p.b, good)
    check opened.ok
    check opened.payload == @[byte 3, 3, 3]

  # {.testKind: tkEdgeCase.}
  test "a gap larger than the skip budget is refused, not absorbed":
    var
      p = fsPair()
      far: FomkeMessage
      i: int = 0
      opened: FomkeOpenResult
    p.b.maxSkip = 4'u32
    while i < 10:
      far = sealFomkeMessage(p.a, @[byte uint8(i)])
      i = i + 1
    ## Message 9 is nine steps ahead of where the receiver sits. Deriving that
    ## far on demand is work an attacker could ask for without limit.
    opened = openFomkeMessage(p.b, far)
    check not opened.ok
    check opened.err == "FOMKE message gap exceeds skipped-key limit"
    check p.b.lane1.nextIndex == 0'u64
    check p.b.skipped.len == 0

  # {.testKind: tkUnit.}
  test "every switched-on KEM slot feeds the root, not just the first":
    var
      bothSlots: AmeExchangeState = fsExchange(0b11000000'u8,
        [@[byte 1, 2, 3, 4], @[byte 5, 6, 7, 8]])
      secondChanged: AmeExchangeState = fsExchange(0b11000000'u8,
        [@[byte 1, 2, 3, 4], @[byte 99, 99, 99, 99]])
      a: FomkeState = initFomkeFromAme(bothSlots, fsLayout(), fsTier(),
        frInitiator)
      b: FomkeState = initFomkeFromAme(secondChanged, fsLayout(), fsTier(),
        frInitiator)
    ## Only the SECOND slot's secret differs. If the root were derived from
    ## the first slot alone -- a hybrid in name only -- these chains would be
    ## identical and a break of one algorithm would be enough.
    check a.lane1.chainKey != b.lane1.chainKey
    check a.lane2.chainKey != b.lane2.chainKey

  # {.testKind: tkEdgeCase.}
  test "a tier that names a KEM slot with no secret is refused":
    var
      partial: AmeExchangeState = fsExchange(0b10000000'u8,
        [@[byte 1, 2, 3, 4]])
    expect ValueError:
      discard initFomkeFromAme(partial, fsLayout(), fsTier(0b11000000'u8),
        frInitiator)

  # {.testKind: tkEdgeCase.}
  test "preparing ahead is bounded and its cost is visible":
    var
      p = fsPair()
      cache: FomkeSendCache = prepareFomkeSendCache(p.a, 4)
      materialLen: int = ameTierKeyMaterialLen(fsLayout(), fsTier())
    ## A filled cache holds real key material for messages not yet sent. That
    ## is the trade: latency now, at the cost of those messages' secrecy if
    ## the machine is taken before they go out. The size is countable, so a
    ## caller can decide knowingly.
    check fomkePreparedMessages(cache) == 4
    check fomkePreparedSecretBytes(cache) ==
      fomkeChainKeyBytes + 4 * (materialLen + fomkeChainKeyBytes)
    clearFomkeSendCache(cache)
    check fomkePreparedSecretBytes(cache) == 0
    expect ValueError:
      discard prepareFomkeSendCache(p.a, fomkeMaxPreparedMessages + 1)

  # {.testKind: tkEdgeCase.}
  test "the nonce never repeats and never travels":
    var
      p = fsPair()
      first: FomkeMessage = sealFomkeMessage(p.a, @[byte 1])
      second: FomkeMessage = sealFomkeMessage(p.a, @[byte 1])
      wire: ByteSeq = encodeFomkeMessage(first)
    ## Same plaintext, different ciphertext: the per-message key and its
    ## derived nonce moved on.
    check first.ciphertext != second.ciphertext
    check first.index != second.index
    ## And the envelope carries no nonce at all -- header, tag, ciphertext.
    check wire.len == fomkeHeaderLen + int(ord(first.tagLen)) +
      first.ciphertext.len
