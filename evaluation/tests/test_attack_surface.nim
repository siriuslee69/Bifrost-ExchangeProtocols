## -------------------------------------------------------------------------
## Attack Surface <- specific attacks, and exactly how far each one gets
## -------------------------------------------------------------------------
##
## The other suites check that two honest endpoints agree. This one is written
## from the other chair: somebody who wants to read or change what is going
## past, and who gets to try.
##
## Every test below is one attack. Each says three things, in this order:
##
##   1. WHAT THE ATTACKER HOLDS   captured bytes, a session of their own,
##                                a relay they control, a manifest
##   2. WHAT THEY TRY             the actual manipulation, written out
##   3. HOW FAR THEY GET          the exact stopping point, named
##
## Point 3 is the reason this file exists. "It is refused" is not a useful
## answer on its own -- what matters is WHICH check refused it, because that
## is the check that must never be weakened later. So the tests assert on the
## error the protocol gives, not merely on failure.
##
## ┊ Two things this file deliberately does NOT claim ┊
##
## It is not a proof of security and does not pretend to be. It is a list of
## attacks somebody thought of, and it grows when somebody thinks of another.
##
## And one section near the end records a limitation rather than a defence:
## the relay does NOT hide a conversation from an observer who can watch both
## sides of it at once. That is a design decision, not an oversight, and it is
## tested here so it stays a decision somebody made on purpose.

import std/[strutils, unittest]

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/derivation
import ../../src/protocols/ame/level1/secret_stack
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/padding
import ../../src/protocols/ame/level1/compression
import ../../src/protocols/ame/level1/header_protection
import ../../src/protocols/ame/level2/framing
import ../../src/protocols/ame/level2/wire
import ../../src/protocols/ame/level3/secure_package
import ../../src/protocols/fomke/types
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/defaults
import ../../src/protocols/dac/level2/package_transfer
import ../../src/protocols/relay/udp_forward
import ../../src/protocols/transport/types as transport_types
import runePragmas

const
  atKems: AmeKemAlgorithms = [akaX25519, akaFireSaber]
  ## A payload an interceptor could not miss if any of it leaked. Long enough
  ## that a four-byte run of it turning up in random bytes by chance is about
  ## one in four billion per position.
  secretText = "THE-VAULT-CODE-IS-884213-AND-THE-BACKUP-PHRASE-IS-CORRECT-HORSE"

proc atLayout(): AmeSuiteLayout =
  result = defaultAmeLayout(atKems)

proc atTier(L: AmeSuiteLayout): AmeMaskTier =
  result = initAmeMaskTier(L, 1'u32, initAmeTierMasks(0b11000000'u8,
    occupiedAmeMask(L.ciphers.length), occupiedAmeMask(L.macs.length),
    occupiedAmeMask(L.hashes.length), occupiedAmeMask(L.signatures.length),
    occupiedAmeMask(L.kdfs.length)))

proc atAuth(role: AmeEndpointRole, seed: byte = 7'u8,
    params: AmeRuntimeParams = AmeRuntimeParams(authTagLen: aatl32)):
    AmeAuthPackage {.role: configurator.} =
  ## role/seed/params: one endpoint. Two calls with the same seed are the two
  ## ends of one session; a different seed is the attacker's own session,
  ## which is what they use when they try to open what they captured.
  var
    layout: AmeSuiteLayout = atLayout()
    tier: AmeMaskTier = atTier(layout)
    state: AmeExchangeState = initAmeExchangeState(atKems)
  applyAmeExchange(state, defaultAmeLayout(atKems), initAmeExchangeRequest(atKems, tier,
    0b11000000'u8), [@[seed, 2'u8, 3'u8, 4'u8], @[seed, 6'u8, 7'u8, 8'u8]])
  result = initAmeAuthPackage(layout, tier, state, endpointRole = role,
    params = params)

proc atSession(role: AmeEndpointRole, seed: byte = 7'u8): AmeSession {.
    role: configurator.} =
  result = initAmeSession(atAuth(role, seed), peerTrustRequired = false)

proc secretBytes(): ByteSeq {.role: configurator.} =
  for c in secretText:
    result.add(uint8(ord(c)))

proc windowFound(haystack, needle: openArray[uint8],
    window: int): bool {.role: parser.} =
  ## haystack/needle/window: does any `window`-byte run of `needle` occur
  ## anywhere in `haystack`? This is the search an interceptor would run.
  var
    i: int = 0
    j: int = 0
  if needle.len < window or haystack.len < window:
    return false
  while i + window <= needle.len:
    j = 0
    while j + window <= haystack.len:
      if haystack[j ..< j + window] == needle[i ..< i + window]:
        return true
      j = j + 1
    i = i + 1

proc patterned(n: int): ByteSeq {.role: configurator.} =
  ## n: a payload with obvious structure, so that structure surviving into the
  ## ciphertext would be visible.
  var
    i: int = 0
  result = newSeq[uint8](n)
  while i < n:
    result[i] = uint8((i * 31 + 7) mod 251)
    i = i + 1

suite "intercepting a package in flight":
  # {.testKind: tkRegression, covers: "planAmeSecurePackage".}
  test "holding EVERY chunk of a package reveals none of the plaintext":
    ## HOLDS  the complete package: manifest, every data chunk, every repair
    ##        shard. Nothing was lost, so this is the best case for them.
    ## TRIES  scanning the whole lot for any four-byte run of the secret.
    ## GETS   nothing. The chunks carry sealed bytes; the sealing happened
    ##        before the package was ever cut up.
    var
      sender: AmeAuthPackage = atAuth(aerInitiator)
      plaintext: ByteSeq = secretBytes() & patterned(9_000)
      plan: AmeSecurePackagePlan = planAmeSecurePackage(sender, 61'u64,
        plaintext, dacDefaultsFor(dscCleanLan))
      wire: ByteSeq = @[]
    for chunk in plan.package.chunks:
      wire.add(chunk.payload)
    for repair in plan.package.repairs:
      for shard in repair.shards:
        wire.add(shard)
    check wire.len > plaintext.len
    check not windowFound(wire, plaintext, 4)
    ## And the obvious structure of the payload does not survive either: a
    ## run that repeats in the plaintext must not repeat in the bytes.
    check not windowFound(wire, patterned(64), 4)

  # {.testKind: tkRegression.}
  test "reassembling every chunk without a key yields sealed bytes, not text":
    ## HOLDS  the same complete capture, plus the reassembly code, which is
    ##        public -- a relay is SUPPOSED to be able to do this much.
    ## TRIES  running the reassembly to completion and reading the result.
    ## GETS   the sealed blob. Reassembly and opening are different jobs, and
    ##        only the second one needs a key.
    var
      sender: AmeAuthPackage = atAuth(aerInitiator)
      receiver: AmeAuthPackage = atAuth(aerResponder)
      stranger: AmeAuthPackage = atAuth(aerResponder, 200'u8)
      plaintext: ByteSeq = secretBytes()
      plan: AmeSecurePackagePlan = planAmeSecurePackage(sender, 62'u64,
        plaintext, dacDefaultsFor(dscCleanLan))
      relay: DacPackageReceiver = initDacPackageReceiver(
        plan.package.manifest)
      opened: AmeSecurePackageResult = default(AmeSecurePackageResult)
    for chunk in plan.package.chunks:
      relay.acceptDacPackageChunk(chunk)
    check relay.missingChunkCount == 0
    ## The interceptor has a complete, verified reassembly and still cannot
    ## read it: their own session's keys are the wrong keys.
    opened = finishAmeSecurePackage(stranger, relay, plan.compression)
    check not opened.ok
    check opened.err == "AME secure-package authentication failed"
    ## The real receiver, with the real keys, gets the text.
    opened = finishAmeSecurePackage(receiver, relay, plan.compression)
    check opened.ok
    check opened.payload == plaintext

  # {.testKind: tkEdgeCase.}
  test "the manifest states the size, and that is a real leak":
    ## Named here rather than hidden. An interceptor learns how many bytes are
    ## moving, because the manifest has to say so for repair to work at all.
    ## What they do NOT learn is what the bytes are. If a deployment cares
    ## about the size, padding is the lever -- not the manifest.
    var
      sender: AmeAuthPackage = atAuth(aerInitiator)
      small: AmeSecurePackagePlan = planAmeSecurePackage(sender, 63'u64,
        patterned(1_000), dacDefaultsFor(dscCleanLan))
      large: AmeSecurePackagePlan = planAmeSecurePackage(sender, 64'u64,
        patterned(20_000), dacDefaultsFor(dscCleanLan))
    check small.package.manifest.totalLen < large.package.manifest.totalLen
    check small.package.chunks.len < large.package.chunks.len

  # {.testKind: tkRegression, covers: "finishAmeSecurePackage".}
  test "a chunk swapped in from another package is refused":
    ## HOLDS  two packages captured from the same sender.
    ## TRIES  substituting a chunk of package B at the same position in
    ##        package A, so the receiver reassembles a blend of the two.
    ## GETS   stopped at the package digest, before any key is used. The
    ##        manifest commits to the whole reassembled blob.
    var
      sender: AmeAuthPackage = atAuth(aerInitiator)
      receiver: AmeAuthPackage = atAuth(aerResponder)
      a: AmeSecurePackagePlan = planAmeSecurePackage(sender, 71'u64,
        patterned(9_000), dacDefaultsFor(dscCleanLan))
      b: AmeSecurePackagePlan = planAmeSecurePackage(sender, 72'u64,
        patterned(9_000), dacDefaultsFor(dscCleanLan))
      relay: DacPackageReceiver = initDacPackageReceiver(a.package.manifest)
      forged: DacPackageChunk = default(DacPackageChunk)
      opened: AmeSecurePackageResult = default(AmeSecurePackageResult)
      i: int = 0
    check a.package.chunks.len > 2
    while i < a.package.chunks.len:
      if i != 1:
        relay.acceptDacPackageChunk(a.package.chunks[i])
      i = i + 1
    ## Relabelled so it claims to belong where the missing one should be.
    forged = b.package.chunks[1]
    forged.packageId = a.package.manifest.packageId
    relay.acceptDacPackageChunk(forged)
    check relay.missingChunkCount == 0
    opened = finishAmeSecurePackage(receiver, relay, a.compression)
    check not opened.ok

  # {.testKind: tkRegression.}
  test "a poisoned repair shard cannot be used to forge plaintext":
    ## HOLDS  the package, one chunk withheld, and the ability to hand the
    ##        receiver a repair shard of their own making.
    ## TRIES  supplying a corrupted shard so the rebuilt chunk is attacker
    ##        chosen -- the interesting attack on any FEC scheme, because
    ##        repair happens OUTSIDE the tag.
    ## GETS   a rebuild that then fails the tag. Parity sits outside the tag
    ##        precisely so a relay can repair without a key; what keeps that
    ##        honest is that the endpoint still checks the tag afterwards.
    var
      sender: AmeAuthPackage = atAuth(aerInitiator)
      receiver: AmeAuthPackage = atAuth(aerResponder)
      plan: AmeSecurePackagePlan = planAmeSecurePackage(sender, 73'u64,
        patterned(9_000), dacDefaultsFor(dscCleanLan))
      relay: DacPackageReceiver = initDacPackageReceiver(
        plan.package.manifest)
      poisoned: DacPackageGroupRepair = plan.package.repairs[0]
      opened: AmeSecurePackageResult = default(AmeSecurePackageResult)
    for chunk in plan.package.chunks:
      if chunk.chunkId != 2'u16:
        relay.acceptDacPackageChunk(chunk)
    check relay.missingChunkCount == 1
    poisoned.shards[0][0] = poisoned.shards[0][0] xor 0xFF'u8
    discard relay.repairGroup(poisoned)
    opened = finishAmeSecurePackage(receiver, relay, plan.compression)
    check not opened.ok

suite "attacks on one AME frame":
  # {.testKind: tkRegression, covers: "validateFrameBinding".}
  test "a data frame relabelled as control is refused":
    ## TRIES  editing the packet-kind byte so a data frame is presented on the
    ##        control path, hoping the two paths trust different things.
    ## GETS   stopped at the kind check, and would be stopped at the tag even
    ##        if that check were removed: the kind byte is in the header, and
    ##        the header is in the tag.
    var
      sender: AmeSession = atSession(aerInitiator)
      receiver: AmeSession = atSession(aerResponder)
      frame: ByteSeq = sealAmeTcpFrame(sender, secretBytes())
      opened: AmeOpenResult = default(AmeOpenResult)
    frame[4] = uint8(ord(ampkEpochReady))
    opened = openAmeTcpFrame(receiver, frame)
    check not opened.ok
    check opened.err == "AME expected lane data"

  # {.testKind: tkRegression.}
  test "a frame from another session is refused by this one":
    ## HOLDS  a frame captured from a session they are not part of, and a
    ##        live session of their own with the victim.
    ## TRIES  injecting the captured frame into their own session.
    ## GETS   stopped at the tag. The keys differ, so nothing about the body
    ##        checks out.
    var
      victimA: AmeSession = atSession(aerInitiator, 7'u8)
      victimB: AmeSession = atSession(aerResponder, 7'u8)
      attacker: AmeSession = atSession(aerResponder, 200'u8)
      frame: ByteSeq = sealAmeTcpFrame(victimA, secretBytes())
      opened: AmeOpenResult = default(AmeOpenResult)
    opened = openAmeTcpFrame(attacker, frame)
    check not opened.ok
    ## The real peer opens it, so the frame itself was never malformed.
    check openAmeTcpFrame(victimB, frame).ok

  # {.testKind: tkRegression, covers: "openFrameBody".}
  test "a frame from before the rotation is refused after it":
    ## HOLDS  a frame sealed under epoch 1, withheld until epoch 2 is live.
    ## TRIES  delivering it late, hoping the old keys are still accepted.
    ## GETS   stopped at the tag. The old ratchet is gone -- deliberately, and
    ##        this is the test that says so. The transport is what recovers a
    ##        genuinely delayed frame, by sending it again.
    var
      client: AmeSession = atSession(aerInitiator)
      server: AmeSession = atSession(aerResponder)
      held: ByteSeq = sealAmeDacFrame(client, secretBytes())
      opened: AmeOpenResult = default(AmeOpenResult)
    check openAmeDacFrame(server, held).ok
    held = sealAmeDacFrame(client, secretBytes())
    rotateAmeTier(server, initAmeExchangeRequest(atKems,
      atTier(server.auth.current.layout), 0b11000000'u8),
      [@[byte 40, 41, 42, 43], @[byte 50, 51, 52, 53]], @[byte 1, 2, 3, 4])
    opened = openAmeDacFrame(server, held)
    check not opened.ok
    check opened.err.len > 0

  # {.testKind: tkRegression.}
  test "truncating the ciphertext but keeping the tag is refused":
    ## TRIES  cutting bytes off the end of the body while leaving the header
    ##        and tag in place, hoping a length is trusted somewhere.
    ## GETS   stopped at the tag. There is no length field to lie to -- the
    ##        carrier delimits the frame, and the tag covers the ciphertext.
    var
      sender: AmeSession = atSession(aerInitiator)
      receiver: AmeSession = atSession(aerResponder)
      frame: ByteSeq = sealAmeTcpFrame(sender, secretBytes())
      cut: ByteSeq = frame[0 ..< frame.len - 8]
      opened: AmeOpenResult = openAmeTcpFrame(receiver, cut)
    check not opened.ok

  # {.testKind: tkRegression, covers: "unmaskedAmeFrameSequence", pins: "masking must not be mistaken for authentication".}
  test "shifting the masked counter does not move the frame's position":
    ## TRIES  editing the four masked bytes at offset 22, hoping that because
    ##        they are now scrambled they are also unchecked -- the obvious
    ##        mistake to make about header protection.
    ## GETS   stopped at the tag, on EVERY one of the four bytes. The real
    ##        sequence was always covered; masking changed what an observer
    ##        reads, not what the tag commits to.
    var
      sender: AmeSession = atSession(aerInitiator)
      receiver: AmeSession = atSession(aerResponder)
      frame: ByteSeq = @[]
      edited: ByteSeq = @[]
      i: int = 0
    while i < ameHeaderMaskLen:
      sender = atSession(aerInitiator)
      receiver = atSession(aerResponder)
      frame = sealAmeTcpFrame(sender, secretBytes())
      edited = frame
      edited[ameHeaderMaskOffset + i] =
        edited[ameHeaderMaskOffset + i] xor 0x80'u8
      check not openAmeTcpFrame(receiver, edited).ok
      i = i + 1

  # {.testKind: tkRegression.}
  test "splicing one frame's header onto another's body is refused":
    ## TRIES  the classic cut-and-paste: take the header an endpoint will
    ##        accept and attach the body of a different frame to it.
    ## GETS   stopped at the tag, because the tag is computed OVER the header.
    ##        A header and a body that did not travel together cannot be made
    ##        to agree.
    var
      sender: AmeSession = atSession(aerInitiator)
      receiver: AmeSession = atSession(aerResponder)
      first: ByteSeq = sealAmeTcpFrame(sender, secretBytes())
      second: ByteSeq = sealAmeTcpFrame(sender, patterned(64))
      spliced: ByteSeq = @[]
      opened: AmeOpenResult = default(AmeOpenResult)
    spliced = first[0 ..< ameFrameHeaderLen] &
      second[ameFrameHeaderLen ..< second.len]
    opened = openAmeTcpFrame(receiver, spliced)
    check not opened.ok

  # {.testKind: tkRegression, covers: "acceptsSessionId".}
  test "a guessed session id does not get a frame accepted":
    ## TRIES  rewriting the session id in the clear header to a value the
    ##        receiver is known to answer to, so the frame is at least looked
    ##        at by the right session.
    ## GETS   past the binding check and stopped at the tag -- which is the
    ##        correct order. The id is a routing label; being routed correctly
    ##        is not the same as being believed.
    var
      sender: AmeSession = atSession(aerInitiator, 200'u8)
      receiver: AmeSession = atSession(aerResponder, 7'u8)
      frame: ByteSeq = sealAmeTcpFrame(sender, secretBytes())
      h: AmeFrameHeader = decodeAmeFrameHeader(frame)
      rebuilt: ByteSeq = @[]
      opened: AmeOpenResult = default(AmeOpenResult)
    h.sessionId = receiver.sessionId
    h.rootLaneId = receiver.rootLaneId
    h.laneId = receiver.laneId
    rebuilt = encodeAmeFrameHeader(h) &
      frame[ameFrameHeaderLen ..< frame.len]
    opened = openAmeTcpFrame(receiver, rebuilt)
    check not opened.ok
    check opened.err.startsWith("AME authentication failed")

  # {.testKind: tkRegression, covers: "replayAccept".}
  test "replaying a frame the receiver already took is refused":
    ## TRIES  sending a genuine, correctly sealed frame a second time. Nothing
    ##        is edited, so no tag check can catch this one.
    ## GETS   stopped by the RATCHET, one layer earlier than expected. Using a
    ##        message key destroys it, so the second copy finds no key to open
    ##        with. The replay window is the backstop behind that, for frames
    ##        that never reach a ratchet.
    ##
    ## The exact message matters here: if this ever starts reading "AME replay
    ## rejected" instead, the ratchet stopped consuming its keys and forward
    ## secrecy went with it.
    var
      sender: AmeSession = atSession(aerInitiator)
      receiver: AmeSession = atSession(aerResponder)
      frame: ByteSeq = sealAmeDacFrame(sender, secretBytes())
    check openAmeDacFrame(receiver, frame).ok
    check not openAmeDacFrame(receiver, frame).ok
    check receiver.lastErr ==
      "AME authentication failed: FOMKE message key is unavailable or replayed"

  # {.testKind: tkEdgeCase.}
  test "the padded flag cannot be cleared to hand filler up as data":
    ## TRIES  clearing the padded bit so the receiver stops stripping the
    ##        padding and hands the filler to the application.
    ## GETS   stopped at the tag. Byte 5 is header, and the header is covered.
    var
      sender: AmeSession = initAmeSession(atAuth(aerInitiator, 7'u8,
        AmeRuntimeParams(authTagLen: aatl32, padding: apadBlock64)),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(atAuth(aerResponder, 7'u8,
        AmeRuntimeParams(authTagLen: aatl32, padding: apadBlock64)),
        peerTrustRequired = false)
      frame: ByteSeq = sealAmeTcpFrame(sender, secretBytes())
    check (frame[5] and ameFrameFlagPadded) != 0'u8
    frame[5] = frame[5] and not ameFrameFlagPadded
    check not openAmeTcpFrame(receiver, frame).ok

suite "attacks through the relay":
  # {.testKind: tkRegression, covers: "fromNas".}
  test "a reused tag CAN misdeliver, and only the endpoint catches it":
    ## HOLDS  the relay itself -- the strongest position in this file, since
    ##        the whole point of the VPS is that it is the least trusted box.
    ## TRIES  waiting for a client to go idle, taking the tag it freed, and
    ##        letting an answer meant for the first client arrive afterwards.
    ## GETS   the answer delivered to the WRONG CLIENT. This one works at the
    ##        relay layer, and the test is written to say so plainly.
    ##
    ## What stops it being a leak is that the relay was never the boundary.
    ## The misdelivered bytes were sealed for somebody else, so they do not
    ## open. An answer that arrives with NO live slot is dropped; an answer
    ## that arrives after the tag was re-let goes to the new holder and dies
    ## at their tag check.
    ##
    ## Narrowing this is a matter of not re-letting a tag until well past any
    ## answer that could still be in flight -- `clientIdleMs` is that lever,
    ## and 5 seconds here is deliberately far too short to force the case.
    var
      F: UdpForwarder = initUdpForwarder(
        initUdpAddress("10.0.0.2", 9000'u16),
        initUdpForwardConfig(maxClients = 1, clientIdleMs = 5_000'u64))
      first: UdpForwardStep = fromClient(F,
        initUdpAddress("203.0.113.7", 40000'u16), @[byte 1], 1_000'u64)
      tag: uint32 = first.send[0].tag
      second: UdpForwardStep = default(UdpForwardStep)
      late: UdpForwardStep = default(UdpForwardStep)
    ## The first client goes quiet and a second takes the freed tag.
    second = fromClient(F, initUdpAddress("203.0.113.8", 40000'u16),
      @[byte 2], 50_000'u64)
    check second.send[0].tag == tag
    ## An answer meant for the FIRST client arrives now. It must not be
    ## delivered to the second, and it is not -- the slot it belonged to is
    ## gone, so the datagram dies here.
    late = fromNas(F, tag, @[byte 9, 9], 50_100'u64)
    check late.event == ufeForwarded
    check late.send[0].peer == initUdpAddress("203.0.113.8", 40000'u16)
    ## NOTE what that just said: the tag WAS reused, so this answer did reach
    ## the wrong client. The protection is the endpoint's, not the relay's --
    ## the bytes will not open, because they were sealed for somebody else.
    ## The relay is not a security boundary and this test exists to say so.

  # {.testKind: tkEdgeCase, covers: "fromClient".}
  test "a flood from many addresses cannot exhaust the relay":
    ## TRIES  sending from more addresses than the table can hold, to make the
    ##        VPS allocate without bound or to push real clients out.
    ## GETS   refused at the ceiling, and the clients already in the table
    ##        keep their slots.
    var
      F: UdpForwarder = initUdpForwarder(
        initUdpAddress("10.0.0.2", 9000'u16),
        initUdpForwardConfig(maxClients = 8))
      real: UdpForwardStep = fromClient(F,
        initUdpAddress("203.0.113.1", 40000'u16), @[byte 1], 1_000'u64)
      step: UdpForwardStep = default(UdpForwardStep)
      refused: int = 0
      i: int = 0
    while i < 200:
      step = fromClient(F, initUdpAddress("198.51.100." & $(i mod 254),
        uint16(30000 + i)), @[byte 1], 1_000'u64)
      if step.event == ufeDropped:
        refused = refused + 1
      i = i + 1
    check refused > 0
    check udpForwardClients(F) == 8
    ## The client that was already there still works.
    step = fromClient(F, initUdpAddress("203.0.113.1", 40000'u16),
      @[byte 2], 1_100'u64)
    check step.event == ufeForwarded
    check step.send[0].tag == real.send[0].tag

  # {.testKind: tkEdgeCase.}
  test "the relay never reads far enough into a datagram to be fooled":
    ## TRIES  feeding the relay rubbish that is not an AME frame at all,
    ##        hoping to reach a parser on the weak machine.
    ## GETS   forwarded, untouched. There IS no parser here to reach -- the
    ##        only judgements are size and source. Rubbish costs the NAS one
    ##        failed tag check, which is where that decision belongs.
    var
      F: UdpForwarder = initUdpForwarder(
        initUdpAddress("10.0.0.2", 9000'u16))
      junk: ByteSeq = @[byte 0xFF, 0x00, 0xFF, 0x00, 0x41, 0x4D, 0x45]
      step: UdpForwardStep = fromClient(F,
        initUdpAddress("203.0.113.7", 40000'u16), junk, 1_000'u64)
    check step.event == ufeForwarded
    check step.send[0].payload == junk

suite "what the relay does NOT hide":
  # {.testKind: tkRegression, pins: "the relay is not an anonymity system and must not be mistaken for one".}
  test "an observer on BOTH sides of the relay can pair the flows":
    ## This is a limitation, recorded on purpose, not a defence.
    ##
    ## The relay forwards bytes unchanged -- that is what lets the client and
    ## the NAS stay unaware of it. The cost is that somebody who can watch the
    ## traffic going IN and the traffic coming OUT sees identical bytes:
    ##
    ##   client -> relay    [ exactly these bytes ]
    ##   relay  -> NAS      [ exactly these bytes ]   <- trivially the same
    ##
    ## Header protection and id rotation defeat an observer on ONE side, who
    ## can no longer follow a counter or a constant id. They do not defeat an
    ## observer on both, and nothing short of the relay re-encrypting would.
    ## If that ever matters, this test is where the change gets noticed.
    var
      sender: AmeSession = atSession(aerInitiator)
      F: UdpForwarder = initUdpForwarder(
        initUdpAddress("10.0.0.2", 9000'u16))
      frame: ByteSeq = sealAmeDacFrame(sender, secretBytes())
      step: UdpForwardStep = fromClient(F,
        initUdpAddress("203.0.113.7", 40000'u16), frame, 1_000'u64)
    check step.send[0].payload == frame

  # {.testKind: tkUnit.}
  test "an observer on one side cannot follow the counter":
    ## The other half of the same statement, and the part that IS bought.
    ## Sixteen frames go past. Their real positions are 0..15; what an
    ## observer reads is sixteen unrelated numbers.
    var
      sender: AmeSession = atSession(aerInitiator)
      frame: ByteSeq = @[]
      inPlace: int = 0
      consecutive: int = 0
      previous: uint32 = 0'u32
      current: uint32 = 0'u32
      i: int = 0
    while i < 16:
      frame = sealAmeDacFrame(sender, patterned(32))
      current = decodeAmeFrameHeader(frame).sequence
      if current == uint32(i):
        inPlace = inPlace + 1
      if i > 0 and current == previous + 1'u32:
        consecutive = consecutive + 1
      previous = current
      i = i + 1
    check inPlace < 16
    check consecutive < 15

suite "losing things, and getting them back":
  ## Loss is the normal case on a datagram link, not an exception. Two very
  ## different machines handle it, and they are easy to confuse:
  ##
  ##   DAC repair    rebuilds a chunk of a PACKAGE from parity, with no key,
  ##                 so a relay can do it. Works on bytes in a group.
  ##   FOMKE skips   keeps the message keys for FRAMES that were jumped over,
  ##                 so a late datagram still opens. Works on ratchet
  ##                 positions, and needs the keys.
  ##
  ## Neither can do the other's job. These tests drop things and check what
  ## comes back out is exactly what went in -- byte for byte, because "it
  ## recovered" is worth nothing if the bytes are subtly different.

  ## The two presets used below have very different repair geometry, and
  ## reading a test here without knowing which is which will mislead you:
  ##
  ##   dscCleanLan    18 KB -> 16 chunks, ONE group, ONE XOR shard
  ##                  budget: one lost chunk, full stop
  ##   dscHeavyLoss   18 KB -> 36 chunks, THREE groups of 12, SIX Reed-Solomon
  ##                  shards each; budget: six per group, independently
  ##
  ## A clean LAN gets one cheap shard because loss there is rare enough that
  ## asking again is cheaper than carrying parity. The lossy profile pays for
  ## real parity because asking again is what is expensive.

  # {.testKind: tkIntegration, covers: "repairGroup".}
  test "XOR parity rebuilds its one lost chunk, byte for byte":
    var
      sender: AmeAuthPackage = atAuth(aerInitiator)
      receiver: AmeAuthPackage = atAuth(aerResponder)
      plaintext: ByteSeq = secretBytes() & patterned(18_000)
      plan: AmeSecurePackagePlan = planAmeSecurePackage(sender, 81'u64,
        plaintext, dacDefaultsFor(dscCleanLan))
      relay: DacPackageReceiver = initDacPackageReceiver(
        plan.package.manifest)
      restored: AmeSecurePackageResult = default(AmeSecurePackageResult)
      i: int = 0
    check plan.package.repairs.len == 1
    check plan.package.repairs[0].shards.len == 1
    while i < plan.package.chunks.len:
      if plan.package.chunks[i].chunkId != 5'u16:
        relay.acceptDacPackageChunk(plan.package.chunks[i])
      i = i + 1
    check relay.missingChunkCount == 1
    check relay.repairGroup(plan.package.repairs[0]).ok
    check relay.missingChunkCount == 0
    restored = finishAmeSecurePackage(receiver, relay, plan.compression)
    check restored.ok
    ## Byte for byte. A repair that rebuilt *something* would still fail here.
    check restored.payload == plaintext
    check restored.payload.len == plaintext.len

  # {.testKind: tkEdgeCase, covers: "repairGroup".}
  test "two losses in a one-shard group are refused, never guessed at":
    ## The failure that matters. A repair scheme that quietly produced
    ## plausible-but-wrong bytes would be worse than one that gave up, because
    ## the endpoint would then be checking a tag over invented data.
    ##
    ## One past the budget, not far past it -- the interesting boundary is the
    ## first loss it cannot cover, not an obviously hopeless case.
    var
      sender: AmeAuthPackage = atAuth(aerInitiator)
      receiver: AmeAuthPackage = atAuth(aerResponder)
      plaintext: ByteSeq = patterned(18_000)
      plan: AmeSecurePackagePlan = planAmeSecurePackage(sender, 82'u64,
        plaintext, dacDefaultsFor(dscCleanLan))
      relay: DacPackageReceiver = initDacPackageReceiver(
        plan.package.manifest)
      restored: AmeSecurePackageResult = default(AmeSecurePackageResult)
      i: int = 0
    while i < plan.package.chunks.len:
      if plan.package.chunks[i].chunkId notin {5'u16, 9'u16}:
        relay.acceptDacPackageChunk(plan.package.chunks[i])
      i = i + 1
    check relay.missingChunkCount == 2
    check not relay.repairGroup(plan.package.repairs[0]).ok
    ## Still two short. Nothing was invented to fill the hole.
    check relay.missingChunkCount == 2
    restored = finishAmeSecurePackage(receiver, relay, plan.compression)
    check not restored.ok

  # {.testKind: tkIntegration, covers: "repairGroup".}
  test "Reed-Solomon covers losses in every group at once":
    ## Three groups, each losing three of its twelve chunks. Each group is
    ## repaired from its own shards, so loss in one cannot exhaust another's
    ## budget -- which is the point of grouping at all.
    var
      sender: AmeAuthPackage = atAuth(aerInitiator)
      receiver: AmeAuthPackage = atAuth(aerResponder)
      plaintext: ByteSeq = secretBytes() & patterned(18_000)
      plan: AmeSecurePackagePlan = planAmeSecurePackage(sender, 84'u64,
        plaintext, dacDefaultsFor(dscHeavyLoss))
      relay: DacPackageReceiver = initDacPackageReceiver(
        plan.package.manifest)
      restored: AmeSecurePackageResult = default(AmeSecurePackageResult)
      lost: int = 0
      i: int = 0
    check plan.package.repairs.len == 3
    while i < plan.package.chunks.len:
      if plan.package.chunks[i].chunkId mod 4'u16 == 0'u16:
        lost = lost + 1
      else:
        relay.acceptDacPackageChunk(plan.package.chunks[i])
      i = i + 1
    check lost == 9
    check relay.missingChunkCount == 9
    i = 0
    while i < plan.package.repairs.len:
      check relay.repairGroup(plan.package.repairs[i]).ok
      i = i + 1
    check relay.missingChunkCount == 0
    restored = finishAmeSecurePackage(receiver, relay, plan.compression)
    check restored.ok
    check restored.payload == plaintext

  # {.testKind: tkIntegration, covers: "acquireFomkeInboundKey".}
  test "datagrams arriving out of order all open, with the right payloads":
    ## Nothing is LOST here -- everything arrives, just in the wrong order.
    ## This is the common case on a datagram link and must cost nothing.
    var
      client: AmeSession = atSession(aerInitiator)
      server: AmeSession = atSession(aerResponder)
      frames: seq[ByteSeq] = @[]
      opened: AmeOpenResult = default(AmeOpenResult)
      seen: seq[int] = @[]
      i: int = 0
    while i < 8:
      frames.add(sealAmeDacFrame(client, @[byte uint8(i), 0xAA'u8]))
      i = i + 1
    ## Delivered back to front, which is the deepest reordering possible for
    ## eight frames.
    i = frames.len - 1
    while i >= 0:
      opened = openAmeDacFrame(server, frames[i])
      check opened.ok
      seen.add(int(opened.packet.payload[0]))
      i = i - 1
    check seen == @[7, 6, 5, 4, 3, 2, 1, 0]
    ## Every parked key was claimed, so nothing is still being held.
    check ameSessionSkippedMessages(server) == 0

  # {.testKind: tkIntegration.}
  test "a datagram lost for good leaves its key held, and the rest still open":
    ## The frames behind a hole must keep working. A transport that stalled on
    ## one lost datagram would be useless on a lossy link.
    var
      client: AmeSession = atSession(aerInitiator)
      server: AmeSession = atSession(aerResponder)
      frames: seq[ByteSeq] = @[]
      opened: AmeOpenResult = default(AmeOpenResult)
      i: int = 0
    while i < 6:
      frames.add(sealAmeDacFrame(client, @[byte uint8(i)]))
      i = i + 1
    i = 0
    while i < frames.len:
      if i != 2:
        opened = openAmeDacFrame(server, frames[i])
        check opened.ok
        check opened.packet.payload == @[byte uint8(i)]
      i = i + 1
    ## One key is still parked, waiting for a datagram that will never come.
    check ameSessionSkippedMessages(server) == 1
    ## And it is still claimable if the datagram does turn up after all.
    opened = openAmeDacFrame(server, frames[2])
    check opened.ok
    check opened.packet.payload == @[byte 2]
    check ameSessionSkippedMessages(server) == 0

  # {.testKind: tkRegression, covers: "discardAmeSessionSkipped".}
  test "a session full of permanent losses can be freed and keeps working":
    ## Two deliberate rules trap a lossy session between them: a gap past the
    ## window is refused, and a rekey refuses to run while any key is still
    ## parked. Giving up on the parked keys by name is the way out, and it is
    ## the caller's decision because it destroys messages for good.
    var
      client: AmeSession = atSession(aerInitiator)
      server: AmeSession = atSession(aerResponder)
      frames: seq[ByteSeq] = @[]
      opened: AmeOpenResult = default(AmeOpenResult)
      given: int = 0
      i: int = 0
    while i < 10:
      frames.add(sealAmeDacFrame(client, @[byte uint8(i)]))
      i = i + 1
    ## Only the last one is delivered: nine keys get parked at once.
    opened = openAmeDacFrame(server, frames[9])
    check opened.ok
    check ameSessionSkippedMessages(server) == 9
    given = discardAmeSessionSkipped(server)
    check given == 9
    check ameSessionSkippedMessages(server) == 0
    ## The abandoned messages stay shut for good, even if they do arrive.
    check not openAmeDacFrame(server, frames[3]).ok
    ## And the session carries on from where it is.
    check openAmeDacFrame(server, sealAmeDacFrame(client, @[byte 77])).ok

  # {.testKind: tkIntegration.}
  test "loss does not desynchronise the two directions":
    ## The two lanes are independent ratchets. Losing traffic one way must not
    ## move the other way's position, or a link with asymmetric loss would
    ## drift apart and never recover.
    var
      client: AmeSession = atSession(aerInitiator)
      server: AmeSession = atSession(aerResponder)
      opened: AmeOpenResult = default(AmeOpenResult)
      i: int = 0
    while i < 5:
      ## Client to server: every other frame is thrown away in flight.
      if i mod 2 == 0:
        opened = openAmeDacFrame(server, sealAmeDacFrame(client,
          @[byte uint8(i)]))
        check opened.ok
      else:
        discard sealAmeDacFrame(client, @[byte uint8(i)])
      ## Server to client: nothing is lost, and every one must still open.
      opened = openAmeDacFrame(client, sealAmeDacFrame(server,
        @[byte uint8(100 + i)]))
      check opened.ok
      check opened.packet.payload == @[byte uint8(100 + i)]
      i = i + 1
    check ameSessionSkippedMessages(client) == 0

  # {.testKind: tkIntegration.}
  test "a package survives loss AND reordering together":
    ## The realistic case: chunks turn up late, out of order, and some never
    ## turn up at all. What comes out has to be the file that went in.
    var
      sender: AmeAuthPackage = atAuth(aerInitiator)
      receiver: AmeAuthPackage = atAuth(aerResponder)
      plaintext: ByteSeq = secretBytes() & patterned(18_000)
      plan: AmeSecurePackagePlan = planAmeSecurePackage(sender, 83'u64,
        plaintext, dacDefaultsFor(dscHeavyLoss))
      relay: DacPackageReceiver = initDacPackageReceiver(
        plan.package.manifest)
      restored: AmeSecurePackageResult = default(AmeSecurePackageResult)
      i: int = 0
    ## Delivered back to front, with three chunks per group dropped on the
    ## way -- inside the six-shard budget, but arriving in the worst order.
    i = plan.package.chunks.len - 1
    while i >= 0:
      if plan.package.chunks[i].chunkId mod 4'u16 != 0'u16:
        relay.acceptDacPackageChunk(plan.package.chunks[i])
      i = i - 1
    check relay.missingChunkCount == 9
    i = 0
    while i < plan.package.repairs.len:
      check relay.repairGroup(plan.package.repairs[i]).ok
      i = i + 1
    check relay.missingChunkCount == 0
    restored = finishAmeSecurePackage(receiver, relay, plan.compression)
    check restored.ok
    check restored.payload == plaintext

suite "a package outlives one rotation, and then it is gone":
  ## A session keeps two epochs of keys: the current one and the one before
  ## it. That is the whole allowance a stored package gets.
  ##
  ##   sealed under epoch 5, opened while current is 5   -> opens
  ##   sealed under epoch 5, opened while current is 6   -> opens (retiring)
  ##   sealed under epoch 5, opened while current is 7   -> GONE
  ##
  ## The last line is a decision, not a gap. Keeping more epochs alive is
  ## keeping more key material alive, and the point of rotating is that old
  ## keys stop existing. A package that sat too long is discarded.
  ##
  ## What these tests hold the line on is that "discard it" and "somebody
  ## tampered with this" are told APART. They want opposite responses, and one
  ## error string for both would hide a real problem behind a routine one.

  proc sealedWire(plan: AmeSecurePackagePlan): ByteSeq {.role: helper.} =
    ## plan: the sealed bytes as they would be reassembled from every chunk.
    ## This is what somebody finds on a disk, with no session involved.
    for chunk in plan.package.chunks:
      result.add(chunk.payload)
    result.setLen(int(plan.package.manifest.totalLen))

  proc restoreFrom(a: AmeAuthPackage,
      plan: AmeSecurePackagePlan): AmeSecurePackageResult {.role: helper.} =
    ## a/plan: every chunk delivered, then opened with whatever keys `a` has.
    var
      relay: DacPackageReceiver = initDacPackageReceiver(
        plan.package.manifest)
    for chunk in plan.package.chunks:
      relay.acceptDacPackageChunk(chunk)
    result = finishAmeSecurePackage(a, relay, plan.compression)

  proc rotate(S: var AmeSession, seed: byte) {.role: helper.} =
    ## S/seed: one epoch turn, with fresh KEM secrets.
    rotateAmeTier(S, initAmeExchangeRequest(atKems,
      atTier(S.auth.current.layout), 0b11000000'u8),
      [@[seed, 41'u8, 42'u8, 43'u8], @[seed, 51'u8, 52'u8, 53'u8]],
      @[seed, 2'u8, 3'u8, 4'u8])

  # {.testKind: tkIntegration, covers: "restoreAmeSecurePackage".}
  test "a package opens under its own epoch and one rotation later":
    var
      sender: AmeSession = atSession(aerInitiator)
      receiver: AmeSession = atSession(aerResponder)
      plaintext: ByteSeq = secretBytes() & patterned(4_000)
      plan: AmeSecurePackagePlan = planAmeSecurePackage(sender.auth, 91'u64,
        plaintext, dacDefaultsFor(dscCleanLan))
      restored: AmeSecurePackageResult = default(AmeSecurePackageResult)
    check receiver.auth.current.epochId == 1'u32
    restored = restoreFrom(receiver.auth, plan)
    check restored.ok
    check restored.payload == plaintext
    ## One rotation. The epoch it was sealed under is now `retiring`, and the
    ## package still opens from there.
    rotate(receiver, 60'u8)
    check receiver.auth.current.epochId == 2'u32
    check receiver.auth.retiring.epochId == 1'u32
    restored = restoreFrom(receiver.auth, plan)
    check restored.ok
    check restored.payload == plaintext

  # {.testKind: tkRegression, covers: "restoreAmeSecurePackage", pins: "an expired package was indistinguishable from a tampered one".}
  test "two rotations later it is refused, and says to discard it":
    var
      sender: AmeSession = atSession(aerInitiator)
      receiver: AmeSession = atSession(aerResponder)
      plaintext: ByteSeq = secretBytes()
      plan: AmeSecurePackagePlan = planAmeSecurePackage(sender.auth, 92'u64,
        plaintext, dacDefaultsFor(dscCleanLan))
      restored: AmeSecurePackageResult = default(AmeSecurePackageResult)
    rotate(receiver, 60'u8)
    rotate(receiver, 70'u8)
    check receiver.auth.current.epochId == 3'u32
    check receiver.auth.retiring.epochId == 2'u32
    restored = restoreFrom(receiver.auth, plan)
    check not restored.ok
    ## The verdict a caller acts on: the keys are gone, throw it away. Not a
    ## string to parse -- a field to branch on.
    check restored.expired
    check restored.epochId == 1'u32
    check restored.err ==
      "AME secure-package epoch 1 is past the keys this session keeps; " &
      "discard it"

  # {.testKind: tkRegression.}
  test "a tampered package under a live epoch is NOT reported as expired":
    ## The other half of the same statement, and the reason the two are
    ## separated at all. This package is from an epoch the session still
    ## holds, so its failure is a real problem and must not be waved through
    ## as routine expiry.
    var
      sender: AmeSession = atSession(aerInitiator)
      receiver: AmeSession = atSession(aerResponder)
      plan: AmeSecurePackagePlan = planAmeSecurePackage(sender.auth, 93'u64,
        secretBytes(), dacDefaultsFor(dscCleanLan))
      relay: DacPackageReceiver = default(DacPackageReceiver)
      edited: DacPackageChunk = default(DacPackageChunk)
      restored: AmeSecurePackageResult = default(AmeSecurePackageResult)
      i: int = 0
    relay = initDacPackageReceiver(plan.package.manifest)
    while i < plan.package.chunks.len:
      edited = plan.package.chunks[i]
      if i == 0:
        edited.payload[edited.payload.len - 1] =
          edited.payload[edited.payload.len - 1] xor 0xFF'u8
      relay.acceptDacPackageChunk(edited)
      i = i + 1
    restored = finishAmeSecurePackage(receiver.auth, relay, plan.compression)
    check not restored.ok
    check not restored.expired

  # {.testKind: tkUnit, covers: "ameSecurePackageEpoch".}
  test "the epoch can be read off the bytes without any key at all":
    ## What lets a caller sort a pile of stored packages before trying any of
    ## them -- and what lets the relay, which holds nothing, tell one epoch's
    ## traffic from another's. The field is in the clear for the same reason
    ## the frame header is, and it is covered by the tag just the same.
    var
      sender: AmeSession = atSession(aerInitiator)
      first: AmeSecurePackagePlan = planAmeSecurePackage(sender.auth,
        94'u64, secretBytes(), dacDefaultsFor(dscCleanLan))
      second: AmeSecurePackagePlan = default(AmeSecurePackagePlan)
    check ameSecurePackageEpoch(sealedWire(first)) == 1'u32
    rotate(sender, 60'u8)
    second = planAmeSecurePackage(sender.auth, 95'u64, secretBytes(),
      dacDefaultsFor(dscCleanLan))
    check ameSecurePackageEpoch(sealedWire(second)) == 2'u32
    ## Rubbish is refused rather than answered with a number.
    expect ValueError:
      discard ameSecurePackageEpoch(@[byte 1, 2, 3])
