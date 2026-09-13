## -------------------------------------------------------------------------
## AME Header Protection Tests <- what the counter looks like from outside
## -------------------------------------------------------------------------
##
## The AME header travels in the clear because a receiver has to read it
## before it knows which keys to reach for. Everything in it is authenticated,
## and one field of it is now also masked: the sequence number.
##
## The reason is narrow and worth stating, because "encrypt the header" is NOT
## the reason. The sequence counts up by one per frame, forever, which makes
## it the one field that links two sightings of a flow together:
##
##   relay in    seq 41, 42, 43, 44 ...
##   relay out   seq 41, 42, 43, 44 ...   <- obviously the same conversation
##
## Masking it breaks that link. These tests check the three things that have
## to be true for it to be worth anything:
##
##   1. the number on the wire is not the number the sender used
##   2. the number the RECEIVER ends up with is the number the sender used
##   3. editing the masked bytes still breaks the frame, exactly as before
##
## Point 3 is the one most easily lost. Masking is not authentication and was
## never meant to be -- the tag always covered the real sequence and still
## does, so an edit produces a frame that fails to open rather than a frame
## that opens at the wrong position.

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/header_protection
import ../../src/protocols/ame/level2/session
import ../../src/protocols/ame/level2/wire
import runePragmas

const
  hpKems: AmeKemAlgorithms = [akaX25519, akaFireSaber]

proc hpLayout(): AmeSuiteLayout =
  result = defaultAmeLayout(hpKems)

proc hpTier(L: AmeSuiteLayout): AmeMaskTier =
  result = initAmeMaskTier(L, 1'u32, initAmeTierMasks(0b11000000'u8,
    occupiedAmeMask(L.ciphers.length), occupiedAmeMask(L.macs.length),
    occupiedAmeMask(L.hashes.length), occupiedAmeMask(L.signatures.length),
    occupiedAmeMask(L.kdfs.length)))

proc hpAuth(role: AmeEndpointRole, seed: byte = 7'u8): AmeAuthPackage =
  ## role/seed: one endpoint. Two calls with the same seed are the two ends of
  ## one session; a different seed is a stranger.
  var
    layout: AmeSuiteLayout = hpLayout()
    tier: AmeMaskTier = hpTier(layout)
    state: AmeExchangeState = initAmeExchangeState(hpKems)
  applyAmeExchange(state, initAmeExchangeRequest(hpKems, tier,
    0b11000000'u8), [@[seed, 2'u8, 3'u8, 4'u8], @[seed, 6'u8, 7'u8, 8'u8]])
  result = initAmeAuthPackage(layout, tier, state, endpointRole = role)

proc hpSession(role: AmeEndpointRole, seed: byte = 7'u8): AmeSession =
  result = initAmeSession(hpAuth(role, seed), peerTrustRequired = false)

suite "AME header protection":
  # {.testKind: tkRegression, covers: "maskAmeFrameHeader", pins: "the frame counter travelled in the clear".}
  test "the counter on the wire does not count":
    ## Eight frames are sealed at sequences 0..7. If masking were not
    ## happening, the wire would read 0,1,2,...,7 and this check would find
    ## every one of them in place. For all eight to match by accident the
    ## masks would have to collide on 256 bits at once.
    var
      sender: AmeSession = hpSession(aerInitiator)
      frame: ByteSeq = @[]
      inPlace: int = 0
      i: int = 0
    while i < 8:
      frame = sealAmeTcpFrame(sender, @[byte 1, 2, 3])
      if decodeAmeFrameHeader(frame).sequence == uint32(i):
        inPlace = inPlace + 1
      i = i + 1
    check inPlace < 8

  # {.testKind: tkUnit, covers: "unmaskedAmeFrameSequence".}
  test "the key puts the counter back":
    var
      sender: AmeSession = hpSession(aerInitiator)
      frame: ByteSeq = @[]
      i: int = 0
    while i < 8:
      frame = sealAmeTcpFrame(sender, @[byte 9])
      check unmaskedAmeFrameSequence(frame, sender.headerKeySend) ==
        uint32(i)
      i = i + 1

  # {.testKind: tkUnit, covers: "maskAmeFrameHeader".}
  test "masking twice returns the frame that went in":
    ## XOR is its own inverse and the sample is taken from a part of the frame
    ## the mask never touches, so there is no separate unmask routine to get
    ## the wrong way round.
    var
      sender: AmeSession = hpSession(aerInitiator)
      frame: ByteSeq = sealAmeTcpFrame(sender, @[byte 4, 5, 6])
      original: ByteSeq = frame
    maskAmeFrameHeader(frame, sender.headerKeySend)
    check frame != original
    maskAmeFrameHeader(frame, sender.headerKeySend)
    check frame == original

  # {.testKind: tkUnit.}
  test "the same payload twice gives two different masks":
    ## The mask is drawn from the authentication tag, which is a fresh
    ## unpredictable value on every frame. If it were drawn from the sequence
    ## instead, the counter would be back in the clear one step removed.
    var
      sender: AmeSession = hpSession(aerInitiator)
      first: ByteSeq = sealAmeTcpFrame(sender, @[byte 1, 1, 1, 1])
      second: ByteSeq = sealAmeTcpFrame(sender, @[byte 1, 1, 1, 1])
    check @(first[ameHeaderMaskOffset ..<
      ameHeaderMaskOffset + ameHeaderMaskLen]) !=
      @(second[ameHeaderMaskOffset ..<
        ameHeaderMaskOffset + ameHeaderMaskLen])

  # {.testKind: tkIntegration.}
  test "a masked frame still opens at the right position":
    var
      sender: AmeSession = hpSession(aerInitiator)
      receiver: AmeSession = hpSession(aerResponder)
      frame: ByteSeq = @[]
      opened: AmeOpenResult = default(AmeOpenResult)
      i: int = 0
    while i < 4:
      frame = sealAmeTcpFrame(sender, @[byte uint8(i)])
      opened = openAmeTcpFrame(receiver, frame)
      check opened.ok
      check opened.packet.payload == @[byte uint8(i)]
      check opened.packet.ameSequence == uint32(i)
      i = i + 1

  # {.testKind: tkEdgeCase, pins: "masking must not be mistaken for authentication".}
  test "editing the masked counter still breaks the frame":
    ## Masking buys privacy from someone WATCHING and nothing at all against
    ## someone EDITING. The real sequence was always covered by the tag, so a
    ## flipped bit here changes the sequence this side recovers, that number
    ## goes into the tag input, and the frame fails to open.
    var
      sender: AmeSession = hpSession(aerInitiator)
      receiver: AmeSession = hpSession(aerResponder)
      frame: ByteSeq = sealAmeTcpFrame(sender, @[byte 3, 3, 3])
      opened: AmeOpenResult = default(AmeOpenResult)
    frame[ameHeaderMaskOffset] = frame[ameHeaderMaskOffset] xor 0x01'u8
    opened = openAmeTcpFrame(receiver, frame)
    check not opened.ok

  # {.testKind: tkEdgeCase.}
  test "a stranger's key recovers the wrong counter":
    ## The header key comes from the epoch, so someone who did not take part
    ## in the exchange cannot produce the mask. Eight frames again, for the
    ## same reason as the first test.
    var
      sender: AmeSession = hpSession(aerInitiator, 7'u8)
      stranger: AmeSession = hpSession(aerResponder, 200'u8)
      frame: ByteSeq = @[]
      matched: int = 0
      i: int = 0
    check sender.headerKeySend != stranger.headerKeyRecv
    while i < 8:
      frame = sealAmeTcpFrame(sender, @[byte 2])
      if unmaskedAmeFrameSequence(frame, stranger.headerKeyRecv) ==
          uint32(i):
        matched = matched + 1
      i = i + 1
    check matched < 8

  # {.testKind: tkUnit, covers: "refreshAmeHeaderKeys".}
  test "the two directions do not share a header key":
    ## One key per direction, for the same reason the ratchet has two lanes:
    ## a frame this side sent must not be reflectable back at it looking like
    ## a frame it received.
    var
      initiator: AmeSession = hpSession(aerInitiator)
      responder: AmeSession = hpSession(aerResponder)
    check initiator.headerKeySend.len == ameProtectionKeyLen
    check initiator.headerKeyRecv.len == ameProtectionKeyLen
    check initiator.headerKeySend != initiator.headerKeyRecv
    ## The two endpoints agree across the link, though: what one seals with is
    ## what the other opens with.
    check initiator.headerKeySend == responder.headerKeyRecv
    check initiator.headerKeyRecv == responder.headerKeySend

suite "AME session id rotation":
  # {.testKind: tkIntegration, covers: "beginAmeSessionIdRotation".}
  test "both sides end up answering to the same new id":
    var
      client: AmeSession = hpSession(aerInitiator)
      server: AmeSession = hpSession(aerResponder)
      before: uint64 = client.sessionId
      request: ByteSeq = @[]
      assign: ByteSeq = @[]
      adopted: uint64 = 0'u64
    check server.sessionId == before
    request = beginAmeSessionIdRotation(client, acrDac)
    ## Asking changes nothing yet. Until the answer arrives the client has no
    ## id but the one it started with.
    check client.sessionId == before
    assign = answerAmeSessionIdRotation(server, request, acrDac)
    check server.sessionId != before
    adopted = finishAmeSessionIdRotation(client, assign, acrDac)
    check adopted == server.sessionId
    check client.sessionId == server.sessionId
    check client.sessionId != before

  # {.testKind: tkUnit, covers: "adoptAmeSessionId".}
  test "rotating the label re-derives no keys":
    ## The id in the header is a routing label. The id every key is bound to
    ## is `auth.sessionId`, and that one never moves. If these two were ever
    ## collapsed into one field, rotating would silently change every derived
    ## key and the session would go deaf.
    var
      client: AmeSession = hpSession(aerInitiator)
      server: AmeSession = hpSession(aerResponder)
      authBefore: uint64 = client.auth.sessionId
      sendKey: ByteSeq = client.headerKeySend
      recvKey: ByteSeq = client.headerKeyRecv
      request: ByteSeq = beginAmeSessionIdRotation(client, acrDac)
      assign: ByteSeq = answerAmeSessionIdRotation(server, request, acrDac)
    discard finishAmeSessionIdRotation(client, assign, acrDac)
    check client.auth.sessionId == authBefore
    check client.headerKeySend == sendKey
    check client.headerKeyRecv == recvKey

  # {.testKind: tkIntegration.}
  test "traffic keeps flowing across the rotation":
    var
      client: AmeSession = hpSession(aerInitiator)
      server: AmeSession = hpSession(aerResponder)
      request: ByteSeq = @[]
      assign: ByteSeq = @[]
      frame: ByteSeq = @[]
      opened: AmeOpenResult = default(AmeOpenResult)
    frame = sealAmeDacFrame(client, @[byte 1])
    check openAmeDacFrame(server, frame).ok
    request = beginAmeSessionIdRotation(client, acrDac)
    assign = answerAmeSessionIdRotation(server, request, acrDac)
    discard finishAmeSessionIdRotation(client, assign, acrDac)
    frame = sealAmeDacFrame(client, @[byte 2])
    opened = openAmeDacFrame(server, frame)
    check opened.ok
    check opened.packet.payload == @[byte 2]
    check opened.packet.sessionId == server.sessionId

  # {.testKind: tkRegression, covers: "acceptsSessionId", pins: "a datagram sealed before the rotation was dropped after it".}
  test "a frame sealed under the old id still opens for a while":
    ## Datagrams reorder, so a data frame sealed before the assign message can
    ## easily land after it. On the stream carrier this never happens -- order
    ## is guaranteed -- which is why the window exists for DAC and costs one
    ## integer rather than a second set of keys.
    var
      client: AmeSession = hpSession(aerInitiator)
      server: AmeSession = hpSession(aerResponder)
      overtaken: ByteSeq = @[]
      request: ByteSeq = @[]
      assign: ByteSeq = @[]
      opened: AmeOpenResult = default(AmeOpenResult)
    ## Sealed FIRST, under the old id, and held back.
    overtaken = sealAmeDacFrame(client, @[byte 7, 7])
    request = beginAmeSessionIdRotation(client, acrDac)
    assign = answerAmeSessionIdRotation(server, request, acrDac)
    discard finishAmeSessionIdRotation(client, assign, acrDac)
    check server.previousSessionIdFramesLeft > 0
    ## Now it turns up, late, carrying an id the server has already moved off.
    opened = openAmeDacFrame(server, overtaken)
    check opened.ok
    check opened.packet.payload == @[byte 7, 7]

  # {.testKind: tkEdgeCase, covers: "consumeSessionIdGrace".}
  test "the old id is forgotten once the window runs out":
    var
      client: AmeSession = hpSession(aerInitiator)
      server: AmeSession = hpSession(aerResponder)
      overtaken: ByteSeq = sealAmeDacFrame(client, @[byte 8])
      request: ByteSeq = beginAmeSessionIdRotation(client, acrDac)
      assign: ByteSeq = @[]
      opened: AmeOpenResult = default(AmeOpenResult)
      i: int = 0
    assign = answerAmeSessionIdRotation(server, request, acrDac)
    discard finishAmeSessionIdRotation(client, assign, acrDac)
    while i < ameSessionIdGraceFrames:
      check openAmeDacFrame(server, sealAmeDacFrame(client, @[byte 1])).ok
      i = i + 1
    check server.previousSessionIdFramesLeft == 0
    check server.previousSessionId == 0'u64
    ## Past the window the late frame is refused rather than opened. That is
    ## the right answer: it costs one datagram the transport can re-send, and
    ## the alternative is answering to an old label forever.
    opened = openAmeDacFrame(server, overtaken)
    check not opened.ok
    check opened.err == "AME frame binding mismatch"

  # {.testKind: tkEdgeCase, covers: "deriveAmeSessionIdCandidate".}
  test "an assigned id is never zero and never the one in use":
    var
      server: AmeSession = hpSession(aerResponder)
      candidate: uint64 = 0'u64
      i: uint32 = 0'u32
    while i < 16'u32:
      candidate = deriveAmeSessionIdCandidate(server, i)
      check candidate != 0'u64
      check candidate != server.sessionId
      i = i + 1'u32
    ## Bumping the attempt gives a different answer, which is what lets a
    ## server holding many sessions at once skip an id it already handed out.
    check deriveAmeSessionIdCandidate(server, 0'u32) !=
      deriveAmeSessionIdCandidate(server, 1'u32)
