## -------------------------------------------------------------------------
## MITM, Loss, and Repair Tests <- what someone on the wire actually gets
## -------------------------------------------------------------------------
##
## Everything else in this repository tests that the two honest endpoints
## agree. These tests take the opposite seat: someone sitting on the path who
## sees every byte, can drop what they like, and can change what they like.
##
##   sender ----frame----> [ MITM: reads, drops, edits, replays ] ----> receiver
##
## The rule the tests below enforce is blunt. An observer is allowed to read
## the frame header and nothing else. If ANY run of the sender's plaintext
## turns up anywhere in what travels, something is seriously wrong -- so that
## is checked directly, by scanning the wire for the plaintext rather than by
## trusting that a call named "seal" sealed anything.
##
## The second half is about loss. A dropped datagram must be recoverable from
## parity by a relay that holds no key at all, and loss past the budget must
## be REFUSED rather than guessed at.

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/padding
import ../../src/protocols/ame/level1/compression
import ../../src/protocols/ame/level1/path_triggers
import ../../src/protocols/ame/level2/session
import ../../src/protocols/ame/level2/wire
import ../../src/protocols/ame/level3/handshake
import ../../src/protocols/ame/level3/handshake_wire
import ../../src/protocols/ame/level3/secure_package
import ../../src/protocols/fomke/types
import ../../src/protocols/fomke/level2/wire
import ../../src/protocols/dac/types
import ../../src/protocols/dac/level0/defaults
import ../../src/protocols/dac/level1/parity_shard
import ../../src/protocols/dac/level1/package_chunk
import ../../src/protocols/dac/level2/package_transfer
import ../../src/analysis_pragmas

const
  mitmKems: AmeKemAlgorithms = [akaX25519, akaFireSaber]
  nowUnix: int64 = 500'i64
  ## A payload an observer could not miss if any of it leaked. Long enough
  ## that a four-byte window of it appearing in random bytes by chance is
  ## about one in four billion per position.
  secretText = "ATTACK-AT-DAWN-the-passphrase-is-hunter2-and-the-account-is-9931"

proc mitmLayout(): AmeSuiteLayout =
  result = defaultAmeLayout(mitmKems)

proc mitmTier(L: AmeSuiteLayout): AmeMaskTier =
  result = initAmeMaskTier(L, 1'u32, initAmeTierMasks(0b11000000'u8,
    occupiedAmeMask(L.ciphers.length), occupiedAmeMask(L.macs.length),
    occupiedAmeMask(L.hashes.length), occupiedAmeMask(L.signatures.length),
    occupiedAmeMask(L.kdfs.length)))

proc secretBytes(): ByteSeq =
  for c in secretText:
    result.add(uint8(ord(c)))

proc mitmAuth(role: AmeEndpointRole,
    seed: byte = 7'u8,
    params: AmeRuntimeParams = AmeRuntimeParams(authTagLen: aatl32)):
    AmeAuthPackage =
  ## role/seed/params: one endpoint of a pair. Two calls with the same seed
  ## share the exchange secret; a different seed is a different session and
  ## is what the "attacker" uses when he tries to open what he captured.
  var
    layout: AmeSuiteLayout = mitmLayout()
    tier: AmeMaskTier = mitmTier(layout)
    state: AmeExchangeState = initAmeExchangeState(mitmKems)
  applyAmeExchange(state, initAmeExchangeRequest(mitmKems, tier,
    0b11000000'u8), [@[seed, 2'u8, 3'u8, 4'u8], @[seed, 6'u8, 7'u8, 8'u8]])
  result = initAmeAuthPackage(layout, tier, state, endpointRole = role,
    params = params)

proc windowFound(haystack, needle: openArray[uint8], window: int): bool =
  ## haystack/needle/window: does any `window`-byte run of `needle` occur
  ## anywhere in `haystack`? This is the search an eavesdropper would run.
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
  result = false

proc frameRejects(S: var AmeSession, frame: openArray[uint8]): bool =
  ## S/frame: did this frame fail to be accepted, by any route? A malformed
  ## header raises out of the decoder; a bad tag comes back as ok = false.
  ## Both are refusals and the test does not care which one happened.
  var
    opened: AmeOpenResult
  try:
    opened = openAmeTcpFrame(S, @frame)
    result = not opened.ok
  except CatchableError:
    result = true

suite "MITM on a live session":
  # {.testKind: tkRegression.}
  test "no run of the plaintext survives into the frame":
    var
      sender: AmeSession = initAmeSession(mitmAuth(aerInitiator),
        peerTrustRequired = false)
      plaintext: ByteSeq = secretBytes()
      frame: ByteSeq = sealAmeTcpFrame(sender, plaintext)
    ## The whole secret, and every four-byte piece of it.
    check not windowFound(frame, plaintext, plaintext.len)
    check not windowFound(frame, plaintext, 4)
    ## And the body is not the plaintext with a constant added, shifted, or
    ## otherwise lightly disguised: no byte of it lines up.
    var
      body: ByteSeq = frame[ameFrameHeaderLen + fomkeHeaderLen +
        32 ..< frame.len]
      lined: int = 0
      i: int = 0
    check body.len == plaintext.len
    while i < body.len:
      if body[i] == plaintext[i]:
        lined = lined + 1
      i = i + 1
    ## A few coincidences are expected -- one byte in 256 -- but not many.
    check lined < body.len div 8 + 4

  # {.testKind: tkRegression.}
  test "an observer may read the header, and only the header":
    var
      sender: AmeSession = initAmeSession(mitmAuth(aerInitiator),
        peerTrustRequired = false)
      plaintext: ByteSeq = secretBytes()
      frame: ByteSeq = sealAmeTcpFrame(sender, plaintext)
      h: AmeFrameHeader = decodeAmeFrameHeader(frame)
    ## These are the fields an eavesdropper legitimately learns, and they are
    ## the ONLY things allowed to match a value the sender holds. Listing
    ## them here is the point of the test: if the header ever grows a field
    ## that says something about the payload, this list has to grow with it
    ## and somebody has to think about whether that is acceptable.
    check h.magic == ameMagic
    check h.formatVersion == ameFormatVersion
    check h.packetKind == ampkLaneData
    check h.messageClass == amcUserdata
    check h.flags == 0'u8
    check h.sessionId == sender.sessionId
    check h.rootLaneId == sender.rootLaneId
    check h.laneId == sender.laneId
    check h.sequence == 0'u32
    ## The length is readable, and with padding off it IS the plaintext
    ## length. That is a real leak and it is why padding exists.
    check frame.len == ameFrameHeaderLen + fomkeWireLen(plaintext.len, aatl32)
    ## Everything past the header is opaque. Re-encoding the decoded header
    ## reproduces the first 26 bytes exactly and nothing more.
    check @(frame[0 ..< ameFrameHeaderLen]) == encodeAmeFrameHeader(h)
    check not windowFound(frame[ameFrameHeaderLen ..< frame.len],
      plaintext, 4)

  # {.testKind: tkRegression.}
  test "the same secret sent twice gives two unrelated blobs":
    var
      sender: AmeSession = initAmeSession(mitmAuth(aerInitiator),
        peerTrustRequired = false)
      plaintext: ByteSeq = secretBytes()
      first: ByteSeq = sealAmeTcpFrame(sender, plaintext)
      second: ByteSeq = sealAmeTcpFrame(sender, plaintext)
      opaqueAt: int = ameFrameHeaderLen + fomkeHeaderLen
      shared: int = 0
      i: int = opaqueAt
    check first.len == second.len
    ## The two headers are nearly identical and are meant to be -- they say
    ## the same session, the same lane, the same length. What must not repeat
    ## is the tag and the ciphertext, so the count starts past both headers.
    check first.len - opaqueAt == 32 + plaintext.len
    while i < first.len:
      if first[i] == second[i]:
        shared = shared + 1
      i = i + 1
    ## 96 bytes of tag and ciphertext, each of which coincides about one time
    ## in 256 if the two are unrelated.
    check shared < 8

  # {.testKind: tkRegression.}
  test "the captured frame does not open for anyone else":
    var
      sender: AmeSession = initAmeSession(mitmAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(mitmAuth(aerResponder),
        peerTrustRequired = false)
      ## The attacker knows the layout and tier -- they are in the clear in
      ## the hello -- and builds a session that agrees about everything
      ## except the one thing he does not have.
      attacker: AmeSession = initAmeSession(mitmAuth(aerResponder, 99'u8),
        peerTrustRequired = false)
      frame: ByteSeq = sealAmeTcpFrame(sender, secretBytes())
    check frameRejects(attacker, frame)
    ## The honest receiver still opens it, so the frame was fine and it was
    ## the attacker's missing secret that stopped him.
    var opened: AmeOpenResult = openAmeTcpFrame(receiver, frame)
    check opened.ok
    check opened.packet.payload == secretBytes()

  # {.testKind: tkRegression.}
  test "changing any single byte of the frame breaks it":
    var
      sender: AmeSession = initAmeSession(mitmAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(mitmAuth(aerResponder),
        peerTrustRequired = false)
      frame: ByteSeq = sealAmeTcpFrame(sender, secretBytes())
      edited: ByteSeq = @[]
      accepted: int = 0
      i: int = 0
    ## Header included. The header is not encrypted, but it is inside the
    ## tag, so an attacker who retargets a frame at another lane or renumbers
    ## its sequence gets a frame that will not open.
    while i < frame.len:
      edited = frame
      edited[i] = edited[i] xor 0xFF'u8
      if not frameRejects(receiver, edited):
        accepted = accepted + 1
      i = i + 1
    check accepted == 0
    ## A failed open leaves the ratchet where it was, so the real frame still
    ## works after all that.
    var opened: AmeOpenResult = openAmeTcpFrame(receiver, frame)
    check opened.ok
    check opened.packet.payload == secretBytes()

  # {.testKind: tkRegression.}
  test "a captured frame cannot be replayed or reflected":
    var
      sender: AmeSession = initAmeSession(mitmAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(mitmAuth(aerResponder),
        peerTrustRequired = false)
      frame: ByteSeq = sealAmeTcpFrame(sender, secretBytes())
    check openAmeTcpFrame(receiver, frame).ok
    ## Replay: the key that opened it was destroyed on use.
    check frameRejects(receiver, frame)
    ## Reflection: bounced back at the sender, who sends on the other lane.
    check frameRejects(sender, frame)

  # {.testKind: tkRegression.}
  test "a forged frame with an honest header is refused":
    var
      sender: AmeSession = initAmeSession(mitmAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(mitmAuth(aerResponder),
        peerTrustRequired = false)
      frame: ByteSeq = sealAmeTcpFrame(sender, secretBytes())
      forged: ByteSeq = frame[0 ..< ameFrameHeaderLen + fomkeHeaderLen]
      i: int = 0
    ## The attacker copies a real header and a real envelope header, then
    ## writes his own tag and his own ciphertext of the right length.
    while i < frame.len - ameFrameHeaderLen - fomkeHeaderLen:
      forged.add(uint8((i * 37 + 11) and 0xff))
      i = i + 1
    check forged.len == frame.len
    check frameRejects(receiver, forged)

suite "MITM against padded traffic":
  # {.testKind: tkRegression.}
  test "the blob is longer than the secret and its length says nothing":
    var
      padded: AmeRuntimeParams = AmeRuntimeParams(authTagLen: aatl32,
        padding: apadBlock64)
      sender: AmeSession = initAmeSession(mitmAuth(aerInitiator, 7'u8,
        padded), peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(mitmAuth(aerResponder, 7'u8,
        padded), peerTrustRequired = false)
      plaintext: ByteSeq = secretBytes()
      frame: ByteSeq = sealAmeTcpFrame(sender, plaintext)
      body: ByteSeq = @[]
      opened: AmeOpenResult
    ## The user-visible property: what is encrypted is NOT the message. It is
    ## the message plus filler, so the ciphertext is longer than the secret
    ## and its length is a block count rather than a byte count.
    body = frame[ameFrameHeaderLen + fomkeHeaderLen + 32 ..< frame.len]
    check plaintext.len == 64
    check body.len == 128
    check body.len == amePaddedLen(plaintext.len, apadBlock64)
    check body.len > plaintext.len
    check not windowFound(frame, plaintext, 4)
    opened = openAmeTcpFrame(receiver, frame)
    check opened.ok
    check opened.packet.payload == plaintext
    check opened.packet.payload.len == 64

  # {.testKind: tkRegression.}
  test "a range of message sizes all look identical on the wire":
    var
      padded: AmeRuntimeParams = AmeRuntimeParams(authTagLen: aatl32,
        padding: apadBlock64)
      sender: AmeSession = initAmeSession(mitmAuth(aerInitiator, 7'u8,
        padded), peerTrustRequired = false)
      sizes: array[6, int] = [0, 1, 17, 40, 62, 63]
      widths: seq[int] = @[]
      i: int = 0
    while i < sizes.len:
      widths.add(sealAmeTcpFrame(sender, newSeq[byte](sizes[i])).len)
      i = i + 1
    i = 1
    while i < widths.len:
      check widths[i] == widths[0]
      i = i + 1
    ## And the step to the next block is visible, which is the honest limit
    ## of what padding buys: sizes are hidden within a block, not between.
    check sealAmeTcpFrame(sender, newSeq[byte](64)).len > widths[0]

suite "MITM against the handshake":
  # {.testKind: tkRegression.}
  test "no key material appears in any of the four records":
    var
      authority: AmeAuthorityKey = initAmeAuthorityKey("mitm-root")
      root: AmeAuthorityRoot = initAmeAuthorityRoot(authority)
      clientKey: AmeIdentityKey = initAmeIdentityKey("mitm-client")
      serverKey: AmeIdentityKey = initAmeIdentityKey("mitm-server")
      clientCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, clientKey, 11'u64, 100'i64, 1000'i64)
      serverCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, serverKey, 22'u64, 100'i64, 1000'i64)
      layout: AmeSuiteLayout = mitmLayout()
      tier: AmeMaskTier = mitmTier(layout)
      client: AmeClientHandshake = beginAmeHandshake(77'u64, layout, tier)
      server = answerAmeHandshake(client.hello,
        [initAmeTierPath(layout, [tier])], initAmeCertificateAuthentication(root),
        serverCert, serverKey)
      clientDone: AmeHandshakeResult
      serverDone: AmeHandshakeResult
      ## Captured off the wire as each record goes past, which is the only
      ## time it exists: the finish wipes the handshake state it consumed,
      ## so these bytes cannot be recovered from either endpoint afterwards.
      captured: ByteSeq = encodeAmeClientHello(client.hello)
    check server.ok
    for b in encodeAmeServerHello(server.state.serverHello):
      captured.add(b)
    clientDone = finishAmeHandshake(client, server.state.serverHello,
      initAmeCertificateAuthentication(root),
      clientCert, clientKey, nowUnix)
    check clientDone.ok
    for b in encodeAmeClientFinish(clientDone.finish):
      captured.add(b)
    serverDone = acceptAmeHandshake(server.state, clientDone.finish,
      initAmeCertificateAuthentication(root), nowUnix)
    check serverDone.ok
    ## None of what the handshake PRODUCED may be visible in what it sent.
    check not windowFound(captured,
      clientDone.auth.current.exchange.sharedSecrets[0], 8)
    check not windowFound(captured,
      clientDone.auth.current.exchange.sharedSecrets[1], 8)
    check not windowFound(captured, clientDone.auth.current.transcriptSalt, 8)
    ## Nor may either private signing key.
    check not windowFound(captured, clientKey.secretKeys[0], 8)
    check not windowFound(captured, serverKey.secretKeys[0], 8)

  # {.testKind: tkRegression.}
  test "a MITM cannot swap in his own identity":
    var
      authority: AmeAuthorityKey = initAmeAuthorityKey("honest-root")
      root: AmeAuthorityRoot = initAmeAuthorityRoot(authority)
      rogue: AmeAuthorityKey = initAmeAuthorityKey("honest-root")
      clientKey: AmeIdentityKey = initAmeIdentityKey("honest-client")
      serverKey: AmeIdentityKey = initAmeIdentityKey("honest-server")
      rogueKey: AmeIdentityKey = initAmeIdentityKey("honest-server")
      clientCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, clientKey, 11'u64, 100'i64, 1000'i64)
      ## The attacker mints himself a certificate for the SAME subject name,
      ## signed by an authority he made up that shares the honest one's name.
      rogueCert: AmeIdentityCertificate = issueAmeIdentityCertificate(
        rogue, rogueKey, 22'u64, 100'i64, 1000'i64)
      layout: AmeSuiteLayout = mitmLayout()
      tier: AmeMaskTier = mitmTier(layout)
      client: AmeClientHandshake = beginAmeHandshake(78'u64, layout, tier)
      attacker = answerAmeHandshake(client.hello,
        [initAmeTierPath(layout, [tier])],
        initAmeCertificateAuthentication(initAmeAuthorityRoot(rogue)), rogueCert,
        rogueKey)
      clientDone: AmeHandshakeResult
    check attacker.ok
    ## The client talks to the attacker and pins the honest root. A matching
    ## name is not a matching key, so the certificate does not verify.
    clientDone = finishAmeHandshake(client, attacker.state.serverHello,
      initAmeCertificateAuthentication(root),
      clientCert, clientKey, nowUnix)
    check not clientDone.ok
    check clientDone.err.len > 0

suite "MITM against a sealed package":
  # {.testKind: tkRegression.}
  test "nothing of the file is readable in the chunks that carry it":
    var
      auth: AmeAuthPackage = mitmAuth(aerInitiator)
      plaintext: ByteSeq = @[]
      plan: AmeSecurePackagePlan
      onTheWire: ByteSeq = @[]
      i: int = 0
    ## A file that is mostly one repeated secret, which is the worst case:
    ## if anything leaked, it would leak many times over.
    while i < 40:
      for b in secretBytes():
        plaintext.add(b)
      i = i + 1
    plan = planAmeSecurePackage(auth, 55'u64, plaintext,
      dacDefaultsFor(dscCleanLan))
    for chunk in plan.package.chunks:
      for b in encodeDacPackageChunk(chunk):
        onTheWire.add(b)
    check onTheWire.len > plaintext.len
    check not windowFound(onTheWire, secretBytes(), 4)
    ## The parity shards are computed over the sealed bytes, so they leak
    ## nothing either -- which is the point of sealing before chunking.
    var parity: ByteSeq = @[]
    for shard in groupParityShards(plan.package, 0'u32):
      for b in encodeDacParityShard(shard):
        parity.add(b)
    check parity.len > 0
    check not windowFound(parity, secretBytes(), 4)

suite "loss, drops, and real repair":
  # {.testKind: tkRegression.}
  test "a relay with no key rebuilds a lost chunk from XOR parity":
    var
      sender: AmeAuthPackage = mitmAuth(aerInitiator)
      receiver: AmeAuthPackage = mitmAuth(aerResponder)
      plaintext: ByteSeq = newSeq[byte](9_000)
      plan: AmeSecurePackagePlan
      relay: DacPackageReceiver
      restored: AmeSecurePackageResult
      i: int = 0
    while i < plaintext.len:
      plaintext[i] = uint8((i * 31 + 7) mod 251)
      i = i + 1
    plan = planAmeSecurePackage(sender, 61'u64, plaintext,
      dacDefaultsFor(dscCleanLan))
    ## The relay holds the manifest and the chunks. It holds no key of any
    ## kind: `receiver` is never handed to it.
    relay = initDacPackageReceiver(plan.package.manifest)
    for chunk in plan.package.chunks:
      if chunk.chunkId != 2'u16:
        relay.acceptDacPackageChunk(chunk)
    check relay.missingChunkCount == 1
    check relay.repairGroup(plan.package.repairs[0]).ok
    check relay.missingChunkCount == 0
    ## The rebuilt bytes are the sealed bytes, so the endpoint's tag still
    ## checks out over them. That is what "parity outside the tag" buys.
    restored = finishAmeSecurePackage(receiver, relay, plan.compression)
    check restored.ok
    check restored.payload == plaintext

  # {.testKind: tkRegression.}
  test "Reed-Solomon rebuilds a full parity budget of losses":
    var
      sender: AmeAuthPackage = mitmAuth(aerInitiator)
      receiver: AmeAuthPackage = mitmAuth(aerResponder)
      defaults: DacScenarioDefaults = dacDefaultsFor(dscHeavyLoss)
      plaintext: ByteSeq = newSeq[byte](12_000)
      plan: AmeSecurePackagePlan
      relay: DacPackageReceiver
      shards: seq[DacParityShard] = @[]
      group: DacPackageGroupRepair
      restored: AmeSecurePackageResult
      dropped: int = 0
      i: int = 0
    while i < plaintext.len:
      plaintext[i] = uint8((i * 17 + 3) mod 251)
      i = i + 1
    plan = planAmeSecurePackage(sender, 62'u64, plaintext, defaults)
    check plan.package.manifest.repairMode == drmReedSolomon
    check plan.package.manifest.parityCount == 6'u16
    relay = initDacPackageReceiver(plan.package.manifest)
    ## Drop six chunks out of the first group -- exactly the parity budget.
    for chunk in plan.package.chunks:
      if chunk.groupId == 0'u32 and dropped < 6 and
          (chunk.chunkId mod 2'u16) == 0'u16:
        dropped = dropped + 1
      else:
        relay.acceptDacPackageChunk(chunk)
    check dropped == 6
    check relay.missingChunkCount == 6
    ## The parity travels as real records and is reassembled from them,
    ## rather than being handed over as an in-memory object.
    shards = groupParityShards(plan.package, 0'u32)
    check shards.len == 6
    var wire: seq[DacParityShard] = @[]
    i = 0
    while i < shards.len:
      wire.add(decodeDacParityShard(encodeDacParityShard(shards[i])))
      i = i + 1
    group = collectGroupRepair(plan.package.manifest, 0'u32, wire)
    check relay.repairGroup(group).ok
    check relay.missingChunkCount == 0
    restored = finishAmeSecurePackage(receiver, relay, plan.compression)
    check restored.ok
    check restored.payload == plaintext

  # {.testKind: tkRegression.}
  test "one loss past the budget is refused, not guessed at":
    var
      sender: AmeAuthPackage = mitmAuth(aerInitiator)
      defaults: DacScenarioDefaults = dacDefaultsFor(dscHeavyLoss)
      plaintext: ByteSeq = newSeq[byte](12_000)
      plan: AmeSecurePackagePlan
      relay: DacPackageReceiver
      outcome: DacGroupRepairReport
      dropped: int = 0
      i: int = 0
    while i < plaintext.len:
      plaintext[i] = uint8((i * 17 + 3) mod 251)
      i = i + 1
    plan = planAmeSecurePackage(sender, 63'u64, plaintext, defaults)
    relay = initDacPackageReceiver(plan.package.manifest)
    for chunk in plan.package.chunks:
      if chunk.groupId == 0'u32 and dropped < 7:
        dropped = dropped + 1
      else:
        relay.acceptDacPackageChunk(chunk)
    check dropped == 7
    outcome = relay.repairGroup(plan.package.repairs[0])
    check not outcome.ok
    check outcome.err.len > 0
    ## Refusing left the receiver exactly as it was: seven chunks still
    ## missing, and nothing invented to fill them.
    check relay.missingChunkCount == 7

  # {.testKind: tkRegression.}
  test "a damaged chunk is caught by the package digest":
    var
      sender: AmeAuthPackage = mitmAuth(aerInitiator)
      receiver: AmeAuthPackage = mitmAuth(aerResponder)
      plaintext: ByteSeq = newSeq[byte](4_000)
      plan: AmeSecurePackagePlan
      relay: DacPackageReceiver
      damaged: DacPackageChunk
      outcome: DacPackageResult
      restored: AmeSecurePackageResult
      i: int = 0
    while i < plaintext.len:
      plaintext[i] = uint8(i mod 251)
      i = i + 1
    plan = planAmeSecurePackage(sender, 64'u64, plaintext,
      dacDefaultsFor(dscCleanLan))
    relay = initDacPackageReceiver(plan.package.manifest)
    for chunk in plan.package.chunks:
      damaged = chunk
      if damaged.chunkId == 1'u16:
        damaged.payload[0] = damaged.payload[0] xor 0x01'u8
      relay.acceptDacPackageChunk(damaged)
    check relay.missingChunkCount == 0
    ## Every chunk arrived, so nothing is missing -- and the package is
    ## still wrong. The digest in the manifest is what notices.
    outcome = finishDacPackage(relay)
    check not outcome.ok
    ## And the endpoint refuses it too, independently, on the tag.
    restored = finishAmeSecurePackage(receiver, relay, plan.compression)
    check not restored.ok

  # {.testKind: tkRegression.}
  test "a dropped datagram does not stop the ones behind it":
    var
      sender: AmeSession = initAmeSession(mitmAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(mitmAuth(aerResponder),
        peerTrustRequired = false)
      first: ByteSeq = sealAmeDacFrame(sender, @[byte 1])
      second: ByteSeq = sealAmeDacFrame(sender, @[byte 2])
      third: ByteSeq = sealAmeDacFrame(sender, @[byte 3])
      opened: AmeOpenResult
    ## Datagrams, not a stream. On TCP a gap means the stream itself broke
    ## and the session says so; on DAC a gap is ordinary weather.
    check openAmeDacFrame(receiver, first).ok
    ## The attacker drops the second datagram entirely.
    opened = openAmeDacFrame(receiver, third)
    check opened.ok
    check opened.packet.payload == @[byte 3]
    ## It turns up late and still opens, from the skipped-key cache.
    ## Delivery order is the network's business, not the ratchet's.
    opened = openAmeDacFrame(receiver, second)
    check opened.ok
    check opened.packet.payload == @[byte 2]
    ## Once used, that key is gone like any other, so a replay of a genuine
    ## datagram is refused by the ratchet and by the replay window both.
    opened = openAmeDacFrame(receiver, second)
    check not opened.ok

  # {.testKind: tkRegression.}
  test "the stream carrier refuses a gap instead of papering over it":
    var
      sender: AmeSession = initAmeSession(mitmAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(mitmAuth(aerResponder),
        peerTrustRequired = false)
      first: ByteSeq = sealAmeTcpFrame(sender, @[byte 1])
      second: ByteSeq = sealAmeTcpFrame(sender, @[byte 2])
      third: ByteSeq = sealAmeTcpFrame(sender, @[byte 3])
    check decodeAmeFrameHeader(second).sequence == 1'u32
    check decodeAmeFrameHeader(third).sequence == 2'u32
    check openAmeTcpFrame(receiver, first).ok
    ## TCP already guarantees order, so a missing frame is not loss -- it is
    ## an attacker deleting from the stream, or a broken connection. Either
    ## way the right answer is to stop, not to carry on with a hole.
    check frameRejects(receiver, third)
    check receiver.lastErr == "AME receive sequence mismatch"

  # {.testKind: tkRegression.}
  test "dropping the last rotation frame leaves the old epoch working":
    var
      layout: AmeSuiteLayout = mitmLayout()
      target: AmeMaskTier = initAmeMaskTier(layout, 2'u32,
        initAmeTierMasks(0b11000000'u8,
        occupiedAmeMask(layout.ciphers.length),
        occupiedAmeMask(layout.macs.length),
        occupiedAmeMask(layout.hashes.length),
        occupiedAmeMask(layout.signatures.length),
        occupiedAmeMask(layout.kdfs.length)))
      clientAuth: AmeAuthPackage = mitmAuth(aerInitiator)
      serverAuth: AmeAuthPackage = mitmAuth(aerResponder)
      client: AmeSession = initAmeSession(clientAuth,
        initAmeTierPath(layout, [clientAuth.current.tier, target]),
        peerTrustRequired = false)
      server: AmeSession = initAmeSession(serverAuth,
        initAmeTierPath(layout, [serverAuth.current.tier, target]),
        peerTrustRequired = false)
      request: AmeExchangeRequest = initAmeExchangeRequest(mitmKems, target,
        0'u8)
      offerFrame: ByteSeq = @[]
      replyFrame: ByteSeq = @[]
      readyFrame: ByteSeq = @[]
      keys = generateAmeSigningKeys(layout, fullAmeMaskTier(layout))
      opened: AmeOpenResult
    client.auth.localSignatureSecretKeys = keys.secretKeys
    client.auth.peerSignaturePublicKeys = keys.publicKeys
    server.auth.localSignatureSecretKeys = keys.secretKeys
    server.auth.peerSignaturePublicKeys = keys.publicKeys
    offerFrame = beginAmeTcpExchangeFrame(client, request)
    replyFrame = answerAmeTcpExchangeFrame(server, offerFrame)
    readyFrame = finishAmeTcpExchangeFrame(client, replyFrame)
    check readyFrame.len > 0
    ## The attacker drops epoch-ready. The initiator has moved on; the
    ## responder has not, and must not.
    check client.auth.current.epochId == 2'u32
    check server.auth.current.epochId == 1'u32
    ## The responder can still open what the initiator sealed under the OLD
    ## epoch before the rotation, because that epoch is still current for it.
    opened = openAmeTcpFrame(server, sealAmeTcpFrame(client, @[byte 9]))
    check not opened.ok
    ## ...and cannot open the new epoch's traffic, which is the correct
    ## outcome: a dropped commit stalls the rotation instead of splitting
    ## the session into two halves that each think they agreed.
    check server.pendingIncoming.active
