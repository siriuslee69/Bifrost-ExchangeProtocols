## ---------------------------------------------------------------------
## DAC ACK Modes <- the five answer strategies, each doing its own thing
## ---------------------------------------------------------------------
##
## A profile declares HOW its receiver answers. For a long time the five
## words existed and the loop ignored all of them: every profile batched by
## count and deadline, so the table promised a metered uplink would send only
## NACKs and a recovery lane would verify, and neither was true.
##
##   damSilent    never answers
##   damNackOnly  answers only when something is really missing
##   damBatch     answers on the count or the deadline
##   damExplicit  answers every chunk
##   damVerified  answers on the count or deadline, and says how many
##                packages it has committed while it is there
##
## These tests exist so that stops being a promise and starts being a fact.
## Each one shows the mode doing something the OTHER modes measurably do not.

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/defaults
import ../../src/protocols/dac/level0/ack_range
import ../../src/protocols/dac/level1/ack_policy
import ../../src/protocols/dac/level3/link

proc rampBytes(n: int): ByteSeq =
  ## n: payload length filled with a deterministic ramp.
  var
    i: int = 0
  result = newSeq[uint8](n)
  while i < n:
    result[i] = uint8((i * 13 + 7) mod 251)
    i = i + 1

proc defaultsWith(mode: DacAckMode): DacScenarioDefaults =
  ## mode: the answer strategy under test.
  ## Everything else is the clean-LAN row, so the mode is the only thing that
  ## differs between one test and the next.
  result = initDacDefaults(dplCleanPath, dtcUserData, drmXor, mode,
    1200'u16, 32'u16, 1'u16, 64'u16, 100'u16, 75'u16, 2'u8)

proc deliver(mode: DacAckMode, payload: ByteSeq,
    dropCount: int = 0): tuple[receipts: int, complete: bool,
    committed: uint8, senderIdle: bool] =
  ## mode: the receiver's answer strategy.
  ## payload: bytes the sender ships, once.
  ## dropCount: how many of the first chunks to lose. One is repaired by the
  ##   profile's single XOR shard and the receiver never notices; two in the
  ##   same group are past that budget, and only then is there a real hole.
  ## Returns how many receipts came back, whether the package completed, how
  ## many packages the receiver has committed, and whether the sender has let
  ## its package go.
  var
    d: DacScenarioDefaults = defaultsWith(mode)
    sender: DacLink = initDacLink(d, 11'u64)
    receiver: DacLink = initDacLink(d, 22'u64)
    clock: uint32 = 0'u32
    chunkSeen: int = 0
    st: DacLinkStep = default(DacLinkStep)
    back: seq[DacTaggedMessage] = @[]
  for m in beginDacPackage(sender, 1'u64, payload, clock):
    clock = clock + 5'u32
    if m.kind == dmkPackageChunk:
      chunkSeen = chunkSeen + 1
      if chunkSeen <= dropCount:
        continue
    st = feedDacMessage(receiver, m.kind, m.body, clock)
    if st.kind == dlkPackageComplete:
      result.complete = true
    for reply in st.messages:
      back.add(reply)
  ## One stall, long after the stream stopped, so a receiver that only speaks
  ## when something is wrong gets its chance to.
  clock = clock + 5_000'u32
  st = tickDacLink(receiver, clock)
  if st.kind == dlkPackageComplete:
    result.complete = true
  for reply in st.messages:
    back.add(reply)
  for m in back:
    if m.kind == dmkAckRange:
      result.receipts = result.receipts + 1
    clock = clock + 1'u32
    discard feedDacMessage(sender, m.kind, m.body, clock)
  result.committed = receiver.committed
  result.senderIdle = not sender.outgoing.active

suite "each mode answers differently on the SAME flawless delivery":
  ## One payload, one perfect wire, five receivers. If the mode did nothing,
  ## every row of this table would read the same.

  # {.testKind: tkIntegration, covers: "dacAckDue", pins: "a declared ackMode that nothing acted on".}
  test "silent says nothing, explicit says everything, batch sits between":
    var
      payload: ByteSeq = rampBytes(40_000)
      silent = deliver(damSilent, payload)
      nack = deliver(damNackOnly, payload)
      batch = deliver(damBatch, payload)
      explicit = deliver(damExplicit, payload)
      verified = deliver(damVerified, payload)
    ## Every one of them gets the bytes. The mode changes what it SAYS about
    ## them, never whether they arrive.
    check silent.complete
    check nack.complete
    check batch.complete
    check explicit.complete
    check verified.complete
    ## A silent receiver is silent. Not "quiet" -- silent.
    check silent.receipts == 0
    ## Nothing went missing, so a NACK-only receiver has nothing to report.
    check nack.receipts == 0
    ## Batch closes on the count or the deadline: a handful, not one per chunk.
    check batch.receipts >= 1
    check batch.receipts <= 4
    ## Explicit answers every chunk, so it must be far chattier than batch.
    check explicit.receipts > batch.receipts * 4
    ## Verified paces like batch.
    check verified.receipts >= 1
    check verified.receipts <= 4

suite "a NACK-only receiver speaks when there IS something to say":
  # {.testKind: tkIntegration, covers: "dacAckDue".}
  test "silence on a clean run, a receipt once a chunk is really missing":
    ## The distinction the mode exists for. A metered uplink should not pay
    ## for receipts that carry no news -- but it must still report a hole.
    var
      payload: ByteSeq = rampBytes(40_000)
      clean = deliver(damNackOnly, payload)
      lossy = deliver(damNackOnly, payload, dropCount = 2)
    check clean.receipts == 0
    check lossy.receipts > 0

suite "a verified receiver reports what it has committed":
  # {.testKind: tkUnit, covers: "dacAckCommitCount".}
  test "only damVerified puts the count on the wire":
    var
      v: DacAckPolicy = initDacAckPolicy(defaultsWith(damVerified))
      b: DacAckPolicy = initDacAckPolicy(defaultsWith(damBatch))
    check dacAckCommitCount(v, 7'u8) == 7'u8
    ## Every other mode sends a fixed zero, which a sender reads as "this peer
    ## does not report commits" rather than as "this peer has committed none".
    check dacAckCommitCount(b, 7'u8) == 0'u8

  # {.testKind: tkIntegration, covers: "feedDacAck".}
  test "the sender lets its package go even when the commit is lost":
    ## This is what verification buys on a barely-working path: the commit
    ## message is one datagram and it can die like any other. The receipt says
    ## the same thing, cheaply, over and over.
    var
      d: DacScenarioDefaults = defaultsWith(damVerified)
      sender: DacLink = initDacLink(d, 11'u64)
      receiver: DacLink = initDacLink(d, 22'u64)
      payload: ByteSeq = rampBytes(8_000)
      clock: uint32 = 0'u32
      st: DacLinkStep = default(DacLinkStep)
      back: seq[DacTaggedMessage] = @[]
      acksOnly: seq[DacTaggedMessage] = @[]
    for m in beginDacPackage(sender, 1'u64, payload, clock):
      clock = clock + 5'u32
      st = feedDacMessage(receiver, m.kind, m.body, clock)
      for reply in st.messages:
        back.add(reply)
    clock = clock + 5_000'u32
    for reply in tickDacLink(receiver, clock).messages:
      back.add(reply)
    check receiver.committed == 1'u8
    ## Throw the commit away, exactly as a lossy path would. Only receipts
    ## reach the sender.
    for m in back:
      if m.kind == dmkAckRange:
        acksOnly.add(m)
    check acksOnly.len > 0
    check sender.outgoing.active
    for m in acksOnly:
      clock = clock + 1'u32
      st = feedDacMessage(sender, m.kind, m.body, clock)
    check not sender.outgoing.active
    check st.kind == dlkCommitReceived or sender.peerCommits == 1'u8

  # {.testKind: tkEdgeCase, covers: "feedDacAck", pins: "a non-verifying peer's zero read as a fresh commit".}
  test "a batching peer's zero never looks like a commit":
    ## The guard that keeps the above from firing for everyone else. A peer
    ## that reports a fixed zero must never be mistaken for one that just
    ## committed something -- otherwise the very first receipt would end every
    ## package on every link.
    var
      d: DacScenarioDefaults = defaultsWith(damBatch)
      sender: DacLink = initDacLink(d, 11'u64)
      receiver: DacLink = initDacLink(d, 22'u64)
      payload: ByteSeq = rampBytes(8_000)
      clock: uint32 = 0'u32
      st: DacLinkStep = default(DacLinkStep)
      back: seq[DacTaggedMessage] = @[]
      acks: int = 0
    ## Thirty milliseconds a chunk, so the batch deadline really expires while
    ## the package is still arriving. A receipt has to be EARNED here: a batch
    ## left over after the package finished is not one, and does not go out.
    for m in beginDacPackage(sender, 1'u64, payload, clock):
      clock = clock + 30'u32
      st = feedDacMessage(receiver, m.kind, m.body, clock)
      for reply in st.messages:
        back.add(reply)
      for reply in tickDacLink(receiver, clock).messages:
        back.add(reply)
    clock = clock + 5_000'u32
    for reply in tickDacLink(receiver, clock).messages:
      back.add(reply)
    check receiver.committed == 1'u8
    ## Only the receipts reach the sender, exactly as in the verified test.
    ## The difference is what they carry.
    for m in back:
      if m.kind != dmkAckRange:
        continue
      acks = acks + 1
      clock = clock + 1'u32
      discard feedDacMessage(sender, m.kind, m.body, clock)
    check acks > 0
    ## Receipts arrived, the receiver HAS committed, and the package is still
    ## in flight: a peer that does not verify says nothing about commits, so
    ## only the commit message itself can end this.
    check sender.outgoing.active
