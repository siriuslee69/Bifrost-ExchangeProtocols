## ---------------------------------------------------------------------
## AME DAC Relay <- the loop, the peer table and the crypto, assembled
## ---------------------------------------------------------------------

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level2/session
import ../../src/protocols/ame/level3/dac_relay
import ../../src/protocols/ame/level3/secure_package
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/defaults
import ../../src/protocols/dac/level0/path_stats
import ../../src/protocols/dac/level2/package_transfer
import ../../src/protocols/ame/level1/compression
import ../../src/protocols/dac/level3/link
import ../../src/protocols/dac/level3/link_table
import ../../src/analysis_pragmas

const
  exactKems: AmeKemAlgorithms = [akaFireSaber, akaX25519, akaFireSaber]

proc exactAuth(role: AmeEndpointRole = aerInitiator): AmeAuthPackage =
  ## One established epoch both endpoints share.
  var
    layout: AmeSuiteLayout = defaultAmeLayout(exactKems)
    tier: AmeMaskTier = initAmeMaskTier(layout, 1'u32,
      initAmeTierMasks(0b10000000'u8,
        occupiedAmeMask(layout.ciphers.length),
        occupiedAmeMask(layout.macs.length),
        occupiedAmeMask(layout.hashes.length),
        occupiedAmeMask(layout.signatures.length),
        occupiedAmeMask(layout.kdfs.length)))
    state: AmeExchangeState = initAmeExchangeState(exactKems)
  applyAmeExchange(state, initAmeExchangeRequest(exactKems, tier,
    0b10000000'u8), [@[byte 9, 8, 7, 6, 5, 4, 3, 2]])
  result = initAmeAuthPackage(layout, tier, state, endpointRole = role)

proc peerSessions(): tuple[a: AmeSession, b: AmeSession] =
  ## Two sessions on one epoch, facing each other.
  ## Roles are fixed before construction: a session starts its ratchet at
  ## once, and the role decides which lane it sends on.
  result.a = initAmeSession(exactAuth(aerInitiator), peerTrustRequired = false)
  result.b = initAmeSession(exactAuth(aerResponder), peerTrustRequired = false)

proc rampBytes(n: int): ByteSeq =
  ## n: payload length filled with a deterministic ramp.
  var
    i: int = 0
  result = newSeq[uint8](n)
  while i < n:
    result[i] = uint8((i * 13 + 7) mod 251)
    i = i + 1

proc keyA(): DacLinkKey =
  result = initDacLinkKey("10.0.0.1", 7000'u16, dlcDatagram)

proc keyB(): DacLinkKey =
  result = initDacLinkKey("10.0.0.2", 7001'u16, dlcDatagram)

proc feedLossReport(R: var AmeDacRelay, slot: int) =
  ## R/slot: relay and the peer whose link is handed a heavy-loss report,
  ## fed straight into the loop so the test does not depend on a live peer
  ## having measured it.
  var
    stats: DacPathStats
  stats.lossPpm = 90_000'u32
  stats.rttMs = 400'u16
  stats.jitterMs = 200'u16
  stats.mtuHint = 1200'u16
  discard feedDacMessage(R.table.slots[slot].link, dmkPathStats,
    encodeDacPathStats(stats), 0'u32)

suite "AME DAC relay admission":
  test "a peer with a session gets a slot; one without gets nothing":
    var
      P = peerSessions()
      R: AmeDacRelay = initAmeDacRelay(badSignalDacDefaults(), 5'u64,
        capacity = 4)
      admitted = admitAmeDacPeer(R, keyA(), P.a, 0'u32)
      step: AmeDacRelayStep
    check admitted.ok
    check admitted.slot >= 0
    check ameDacRelayLive(R) == 1
    step = feedAmeDacDatagram(R, keyB(), rampBytes(80), 0'u32)
    check step.kind == adrDropped
    check step.err == "DAC datagram from a peer with no session"
    check R.dropped == 1'u32

  test "releasing a peer erases its session with its slot":
    var
      P = peerSessions()
      R: AmeDacRelay = initAmeDacRelay(badSignalDacDefaults(), 5'u64,
        capacity = 4)
      slot: int = 0
    discard admitAmeDacPeer(R, keyA(), P.a, 0'u32)
    slot = ameDacPeerSlot(R, keyA())
    check slot >= 0
    check R.sessions[slot].sessionId == P.a.sessionId
    check releaseAmeDacPeer(R, keyA())
    check ameDacRelayLive(R) == 0
    check R.sessions[slot].sessionId == 0'u64
    check not releaseAmeDacPeer(R, keyA())

  test "a full relay refuses a new peer rather than evicting a live one":
    var
      R: AmeDacRelay = initAmeDacRelay(badSignalDacDefaults(), 5'u64,
        capacity = 2)
      P = peerSessions()
      first = admitAmeDacPeer(R, keyA(), P.a, 0'u32)
      second = admitAmeDacPeer(R, keyB(), P.b, 0'u32)
      third = admitAmeDacPeer(R,
        initDacLinkKey("10.0.0.3", 7003'u16, dlcDatagram), P.a, 0'u32)
    check first.ok
    check second.ok
    check not third.ok
    check third.slot == -1
    check ameDacRelayLive(R) == 2

suite "AME DAC relay transfer":
  test "a whole package crosses the relay, sealed the entire way":
    var
      P = peerSessions()
      sender: AmeDacRelay = initAmeDacRelay(badSignalDacDefaults(), 1'u64)
      receiver: AmeDacRelay = initAmeDacRelay(badSignalDacDefaults(), 2'u64)
      payload: ByteSeq = rampBytes(12_000)
      out1: AmeDacRelayStep
      step: AmeDacRelayStep
      done: bool = false
      i: int = 0
    discard admitAmeDacPeer(sender, keyB(), P.a, 0'u32)
    discard admitAmeDacPeer(receiver, keyA(), P.b, 0'u32)
    out1 = sendAmeDacPackage(sender, keyB(), 42'u64, payload, 0'u32)
    check out1.kind == adrProgress
    check out1.send.len > 0
    while i < out1.send.len:
      step = feedAmeDacDatagram(receiver, keyA(), out1.send[i], uint32(i))
      if step.kind == adrPackageComplete:
        check step.payload == payload
        done = true
      i = i + 1
    check done

  test "every datagram on the wire is an authenticated AME frame":
    var
      P = peerSessions()
      sender: AmeDacRelay = initAmeDacRelay(badSignalDacDefaults(), 1'u64)
      receiver: AmeDacRelay = initAmeDacRelay(badSignalDacDefaults(), 2'u64)
      out1: AmeDacRelayStep
      tampered: ByteSeq
      step: AmeDacRelayStep
      i: int = 0
      refused: int = 0
    discard admitAmeDacPeer(sender, keyB(), P.a, 0'u32)
    discard admitAmeDacPeer(receiver, keyA(), P.b, 0'u32)
    out1 = sendAmeDacPackage(sender, keyB(), 7'u64, rampBytes(3_000), 0'u32)
    while i < out1.send.len:
      tampered = out1.send[i]
      tampered[tampered.len div 2] = tampered[tampered.len div 2] xor 0x01'u8
      step = feedAmeDacDatagram(receiver, keyA(), tampered, uint32(i))
      if step.kind == adrDropped:
        refused = refused + 1
      i = i + 1
    check refused == out1.send.len
    check receiver.dropped == uint32(out1.send.len)

  test "rubbish from an admitted peer is dropped, never raised":
    var
      P = peerSessions()
      R: AmeDacRelay = initAmeDacRelay(badSignalDacDefaults(), 3'u64)
      step: AmeDacRelayStep
      i: int = 0
      broke: bool = false
    discard admitAmeDacPeer(R, keyA(), P.b, 0'u32)
    while i < 400 and not broke:
      try:
        step = feedAmeDacDatagram(R, keyA(), rampBytes(i mod 200), uint32(i))
        if step.kind != adrDropped:
          checkpoint("rubbish was not dropped at round " & $i)
          broke = true
      except CatchableError as e:
        checkpoint("relay escaped an error at round " & $i & ": " & e.msg)
        broke = true
      except Defect as e:
        checkpoint("relay raised a Defect at round " & $i & ": " & e.msg)
        broke = true
      i = i + 1
    check not broke
    check ameDacRelayLive(R) == 1

  test "a package survives loss, repairing over the sealed lane":
    var
      P = peerSessions()
      sender: AmeDacRelay = initAmeDacRelay(badSignalDacDefaults(), 1'u64)
      receiver: AmeDacRelay = initAmeDacRelay(badSignalDacDefaults(), 2'u64)
      payload: ByteSeq = rampBytes(14_000)
      toReceiver: seq[ByteSeq] = @[]
      toSender: seq[ByteSeq] = @[]
      steps: seq[AmeDacRelayStep] = @[]
      step: AmeDacRelayStep
      nowMs: uint32 = 0'u32
      done: bool = false
      tick: int = 0
      i: int = 0
    discard admitAmeDacPeer(sender, keyB(), P.a, 0'u32)
    discard admitAmeDacPeer(receiver, keyA(), P.b, 0'u32)
    toReceiver = sendAmeDacPackage(sender, keyB(), 9'u64, payload, 0'u32).send
    i = 0
    while i < toReceiver.len:
      if i mod 4 == 3:
        toReceiver[i] = @[]
      i = i + 1
    while tick < 40 and not done:
      nowMs = nowMs + 60'u32
      i = 0
      while i < toReceiver.len:
        if toReceiver[i].len > 0:
          step = feedAmeDacDatagram(receiver, keyA(), toReceiver[i], nowMs)
          toSender.add(step.send)
          if step.kind == adrPackageComplete:
            check step.payload == payload
            done = true
        i = i + 1
      toReceiver = @[]
      i = 0
      while i < toSender.len:
        step = feedAmeDacDatagram(sender, keyB(), toSender[i], nowMs)
        toReceiver.add(step.send)
        i = i + 1
      toSender = @[]
      steps = tickAmeDacRelay(receiver, nowMs)
      i = 0
      while i < steps.len:
        toSender.add(steps[i].send)
        i = i + 1
      steps = tickAmeDacRelay(sender, nowMs)
      i = 0
      while i < steps.len:
        toReceiver.add(steps[i].send)
        i = i + 1
      tick = tick + 1
    check done

suite "AME DAC relay bounds":
  test "a swept peer releases its session as well as its slot":
    var
      P = peerSessions()
      R: AmeDacRelay = initAmeDacRelay(badSignalDacDefaults(), 5'u64,
        capacity = 4, idleMs = 50'u32)
      slot: int = 0
    discard admitAmeDacPeer(R, keyA(), P.a, 0'u32)
    slot = ameDacPeerSlot(R, keyA())
    check sweepAmeDacRelay(R, 10'u32) == 0
    check sweepAmeDacRelay(R, 100'u32) == 1
    check ameDacRelayLive(R) == 0
    check R.sessions[slot].sessionId == 0'u64

  test "sending to a peer with no session is refused, not attempted":
    var
      R: AmeDacRelay = initAmeDacRelay(badSignalDacDefaults(), 5'u64)
      step: AmeDacRelayStep = sendAmeDacPackage(R, keyA(), 1'u64,
        rampBytes(100), 0'u32)
    check step.kind == adrDropped
    check step.err == "DAC relay has no session for that peer"

suite "DAC admission and dispatch agree":
  test "every kind that opens a link is a kind the loop acts on":
    var
      k: DacMessageKind
    for k in DacMessageKind:
      if dacFrameOpensLink(k):
        check dacLinkHandlesKind(k)

  test "a path probe no longer takes a slot the loop cannot use":
    check not dacFrameOpensLink(dmkPathProbe)
    check not dacLinkHandlesKind(dmkPathProbe)

suite "secure package over the relay":
  test "a secure package crosses the relay and restores its plaintext":
    var
      P = peerSessions()
      sender: AmeDacRelay = initAmeDacRelay(cleanLanDacDefaults(), 1'u64)
      receiver: AmeDacRelay = initAmeDacRelay(cleanLanDacDefaults(), 2'u64)
      plaintext: ByteSeq = rampBytes(9_000)
      out1: AmeDacRelayStep
      step: AmeDacRelayStep
      restored: AmeSecurePackageResult
      done: bool = false
      i: int = 0
    discard admitAmeDacPeer(sender, keyB(), P.a, 0'u32)
    discard admitAmeDacPeer(receiver, keyA(), P.b, 0'u32)
    out1 = sendAmeSecurePackage(sender, keyB(), 3'u64, plaintext, 0'u32)
    check out1.kind == adrProgress
    while i < out1.send.len:
      step = feedAmeDacDatagram(receiver, keyA(), out1.send[i], uint32(i))
      if step.kind == adrPackageComplete:
        restored = openAmeSecurePackageStep(3'u64, step)
        check restored.ok
        check restored.payload == plaintext
        done = true
      i = i + 1
    check done

  test "the relay path carries no package seal, because it needs none":
    var
      P = peerSessions()
      sender: AmeDacRelay = initAmeDacRelay(cleanLanDacDefaults(), 1'u64)
      plaintext: ByteSeq = rampBytes(4_000)
      relayed: AmeDacRelayStep
      stored: AmeSecurePackagePlan
      relayedBytes: int = 0
      i: int = 0
    discard admitAmeDacPeer(sender, keyB(), P.a, 0'u32)
    relayed = sendAmeSecurePackage(sender, keyB(), 5'u64, plaintext, 0'u32)
    stored = planAmeSecurePackage(P.a.auth, 5'u64, plaintext,
      cleanLanDacDefaults())
    while i < relayed.send.len:
      relayedBytes = relayedBytes + relayed.send[i].len
      i = i + 1
    check relayedBytes > 0
    ## The store-and-forward plan carries an ASP1 envelope; the relay does not,
    ## because every datagram is sealed and the manifest digest is authentic.
    check stored.package.manifest.totalLen >
      uint64(len(encodeAmeCompressed(plaintext,
        defaultAmeCompressionPolicy())))

  test "a package that leaves through a file still carries its own seal":
    var
      P = peerSessions()
      plaintext: ByteSeq = rampBytes(4_000)
      stored: AmeSecurePackagePlan = planAmeSecurePackage(P.a.auth, 5'u64,
        plaintext, cleanLanDacDefaults())
      incoming: DacPackageReceiver = initDacPackageReceiver(
        stored.package.manifest)
      restored: AmeSecurePackageResult
      wrong: AmeSecurePackageResult
      i: int = 0
    while i < stored.package.chunks.len:
      acceptDacPackageChunk(incoming, stored.package.chunks[i])
      i = i + 1
    restored = finishAmeSecurePackage(P.b.auth, incoming, stored.compression)
    check restored.ok
    check restored.payload == plaintext
    ## Bound to its package id: the same bytes under another id do not open.
    wrong = restoreAmeSecurePackage(P.b.auth, 6'u64,
      finishDacPackage(incoming).payload, stored.compression)
    check not wrong.ok
    check wrong.err == "AME secure-package authentication failed"

  test "an incomplete relay step cannot be opened as a package":
    var
      P = peerSessions()
      step: AmeDacRelayStep
      got: AmeSecurePackageResult
    step.kind = adrProgress
    got = openAmeSecurePackageStep(1'u64, step)
    check not got.ok
    check got.err == "AME secure package needs a completed relay step"

suite "DAC path reports move a lane without being asked to":
  test "a completed package reports what this side measured":
    var
      P = peerSessions()
      sender: AmeDacRelay = initAmeDacRelay(cleanLanDacDefaults(), 1'u64)
      receiver: AmeDacRelay = initAmeDacRelay(cleanLanDacDefaults(), 2'u64)
      payload: ByteSeq = rampBytes(9_000)
      out1: AmeDacRelayStep
      step: AmeDacRelayStep
      replied: int = 0
      i: int = 0
    discard admitAmeDacPeer(sender, keyB(), P.a, 0'u32)
    discard admitAmeDacPeer(receiver, keyA(), P.b, 0'u32)
    out1 = sendAmeDacPackage(sender, keyB(), 31'u64, payload, 0'u32)
    while i < out1.send.len:
      step = feedAmeDacDatagram(receiver, keyA(), out1.send[i], uint32(i))
      if step.kind == adrPackageComplete:
        ## The commit AND the path report both come back, sealed like
        ## everything else on the lane.
        replied = step.send.len
      i = i + 1
    check replied == 2

  test "a peer's report moves this side's lane, one step at a time":
    var
      P = peerSessions()
      R: AmeDacRelay = initAmeDacRelay(superCleanDacDefaults(), 7'u64)
      slot: int = 0
      before: DacPathLane
    discard admitAmeDacPeer(R, keyA(), P.a, 0'u32)
    slot = ameDacPeerSlot(R, keyA())
    before = R.table.slots[slot].link.defaults.pathLane
    check before == dplSuperCleanPath
    ## A report of heavy loss should walk the lane down, not teleport it.
    feedLossReport(R, slot)
    check R.table.slots[slot].link.pathMoves == 1'u16
    check R.table.slots[slot].link.defaults.pathLane != before
    check R.table.slots[slot].link.defaults.pathLane == dplCleanPath

  test "a report cannot move a lane out from under a package in flight":
    var
      P = peerSessions()
      R: AmeDacRelay = initAmeDacRelay(superCleanDacDefaults(), 7'u64)
      slot: int = 0
    discard admitAmeDacPeer(R, keyA(), P.a, 0'u32)
    slot = ameDacPeerSlot(R, keyA())
    discard sendAmeDacPackage(R, keyA(), 4'u64, rampBytes(6_000), 0'u32)
    feedLossReport(R, slot)
    check R.table.slots[slot].link.pathMoves == 0'u16
    check R.table.slots[slot].link.defaults.pathLane == dplSuperCleanPath
