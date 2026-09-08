## -------------------------------------------------------------------------
## AME Session API <- the entry points nothing else was calling
## -------------------------------------------------------------------------
##
## Four parts of AME's public surface had no caller anywhere: the certificate
## codec, the carrier-agnostic frame and rotation calls, the clock-driven tier
## triggers, and the abort path for a rotation that is already half done.
##
## Untested is not the same as broken, but it is the same as unknown, and
## these four are load-bearing:
##
##   encodeAmeIdentityCertificate  the only way a certificate reaches another
##                                 machine, and the trust model assumes it
##   sealAmeFrame(S, carrier, p)   the path taken when the carrier comes from
##                                 a config file rather than a type
##   setTimeTrigger/feedElapsedMs  half the rotation policy; only the
##                                 byte-count half had ever run
##   cancelIncomingAmeSessionExchange
##                                 what a responder does when a rotation it
##                                 answered never gets confirmed

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/signatures
import ../../src/protocols/ame/level1/path_triggers
import ../../src/protocols/ame/level2/session
import ../../src/protocols/ame/level2/carriers
import ../../src/protocols/ame/level3/handshake
import ../../src/analysis_pragmas

const
  apiKems: AmeKemAlgorithms = [akaFireSaber, akaX25519, akaFireSaber]
  nowUnix: int64 = 500'i64
  validFrom: int64 = 100'i64
  validUntil: int64 = 1000'i64

proc apiLayout(): AmeSuiteLayout =
  result = defaultAmeLayout(apiKems)

proc apiTier(L: AmeSuiteLayout, id: uint32, kem: uint8): AmeMaskTier =
  result = initAmeMaskTier(L, id, initAmeTierMasks(kem,
    occupiedAmeMask(L.ciphers.length), occupiedAmeMask(L.macs.length),
    occupiedAmeMask(L.hashes.length), occupiedAmeMask(L.signatures.length),
    occupiedAmeMask(L.kdfs.length)))

proc apiAuth(role: AmeEndpointRole = aerInitiator): AmeAuthPackage =
  var
    layout: AmeSuiteLayout = apiLayout()
    tier: AmeMaskTier = apiTier(layout, 1'u32, 0b10000000'u8)
    state: AmeExchangeState = initAmeExchangeState(apiKems)
  applyAmeExchange(state, initAmeExchangeRequest(apiKems, tier,
    0b10000000'u8), [@[byte 9, 8, 7, 6, 5, 4, 3, 2]])
  result = initAmeAuthPackage(layout, tier, state, endpointRole = role)

proc apiUpgradeSession(role: AmeEndpointRole = aerInitiator): AmeSession =
  var
    auth: AmeAuthPackage = apiAuth(role)
    target: AmeMaskTier = apiTier(auth.current.layout, 2'u32, 0b11000000'u8)
    path: AmeTierPath = initAmeTierPath(auth.current.layout,
      [auth.current.tier, target])
  result = initAmeSession(auth, path, peerTrustRequired = false)

proc installSignaturePeers(A, B: var AmeSession) {.role: actor.} =
  var
    aKeys = generateAmeSigningKeys(A.auth.current.layout,
      fullAmeMaskTier(A.auth.current.layout))
    bKeys = generateAmeSigningKeys(B.auth.current.layout,
      fullAmeMaskTier(B.auth.current.layout))
  A.auth.localSignatureSecretKeys = aKeys.secretKeys
  A.auth.peerSignaturePublicKeys = bKeys.publicKeys
  B.auth.localSignatureSecretKeys = bKeys.secretKeys
  B.auth.peerSignaturePublicKeys = aKeys.publicKeys

proc upgradeRequest(S: AmeSession): AmeExchangeRequest {.role: configurator.} =
  result = initAmeExchangeRequest(apiKems,
    apiTier(S.auth.current.layout, 2'u32, 0b11000000'u8), 0b01000000'u8)

suite "AME certificate codec":
  test "an authority certificate survives a round trip and still verifies":
    var
      authority: AmeAuthorityKey = initAmeAuthorityKey("codec-root")
      root: AmeAuthorityRoot = initAmeAuthorityRoot(authority)
      identity: AmeIdentityKey = initAmeIdentityKey("codec-peer")
      certificate: AmeIdentityCertificate = issueAmeIdentityCertificate(
        authority, identity, 77'u64, validFrom, validUntil)
      encoded: ByteSeq = encodeAmeIdentityCertificate(certificate)
      decoded: AmeIdentityCertificate
      trust: AmePeerTrustResult
    check encoded.len > 0
    decoded = decodeAmeIdentityCertificate(encoded)
    check decoded.serial == certificate.serial
    check decoded.authority == certificate.authority
    check decoded.subject == certificate.subject
    check decoded.validFromUnix == certificate.validFromUnix
    check decoded.validUntilUnix == certificate.validUntilUnix
    check decoded.signingKeys.len == certificate.signingKeys.len
    check decoded.authorityProofs.len == certificate.authorityProofs.len
    ## The point of moving a certificate is that the far side can check it.
    ## A round trip that loses a proof would still compare equal field by
    ## field, so the verification is the assertion that matters.
    trust = verifyAmeIdentityCertificate(decoded, root, nowUnix)
    check trust.err == ""
    check trust.ok
    check encodeAmeIdentityCertificate(decoded) == encoded

  test "a pinned descriptor round trips through the same codec":
    var
      identity: AmeIdentityKey = initAmeIdentityKey("codec-pinned")
      descriptor: AmeIdentityCertificate = pinnedIdentityDescriptor(identity,
        validFrom, validUntil)
      encoded: ByteSeq = encodeAmeIdentityCertificate(descriptor)
      decoded: AmeIdentityCertificate = decodeAmeIdentityCertificate(encoded)
      pin: AmePinnedPeerIdentity = pinnedPeerIdentity(identity)
    ## The unsigned shape has no authority and no serial, and the codec has
    ## to keep it that way rather than normalizing it into a certificate.
    check decoded.serial == 0'u64
    check decoded.authority == ""
    check decoded.authorityProofs.len == 0
    check decoded.subject == "codec-pinned"
    check verifyPinnedPeerIdentity(decoded, pin, nowUnix).ok

  test "the decoder refuses truncated, extended, and altered bytes":
    var
      authority: AmeAuthorityKey = initAmeAuthorityKey("codec-bad")
      identity: AmeIdentityKey = initAmeIdentityKey("codec-bad-peer")
      encoded: ByteSeq = encodeAmeIdentityCertificate(
        issueAmeIdentityCertificate(authority, identity, 5'u64, validFrom,
          validUntil))
      mutated: ByteSeq = @[]
    expect ValueError:
      discard decodeAmeIdentityCertificate(encoded[0 .. encoded.len - 2])
    ## Trailing bytes are rejected too: the decoder checks that the cursor
    ## landed exactly on the end, so nothing can ride along behind a valid
    ## certificate.
    mutated = encoded
    mutated.add(0'u8)
    expect ValueError:
      discard decodeAmeIdentityCertificate(mutated)
    ## A flipped bit inside the label fails as a shape error; one inside a
    ## proof decodes but must not verify.
    mutated = encoded
    mutated[0] = mutated[0] xor 0xff'u8
    expect ValueError:
      discard decodeAmeIdentityCertificate(mutated)

  test "an incomplete certificate never encodes":
    var
      certificate: AmeIdentityCertificate
    expect ValueError:
      discard encodeAmeIdentityCertificate(certificate)

suite "carrier chosen while running":
  test "sealAmeFrame and openAmeFrame agree with the typed calls":
    var
      sender: AmeSession = initAmeSession(apiAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(apiAuth(aerResponder),
        peerTrustRequired = false)
      payload: ByteSeq = @[byte 1, 2, 3, 4, 5, 6, 7, 8, 9]
      frame: ByteSeq = @[]
      opened: AmeOpenResult
    frame = sealAmeFrame(sender, acrTcp, payload)
    opened = openAmeFrame(receiver, acrTcp, frame)
    check opened.ok
    check opened.packet.payload == payload
    check opened.packet.carrier == acrTcp

  test "the DAC carrier answers the same runtime call":
    var
      sender: AmeSession = initAmeSession(apiAuth(aerInitiator),
        peerTrustRequired = false)
      receiver: AmeSession = initAmeSession(apiAuth(aerResponder),
        peerTrustRequired = false)
      payload: ByteSeq = @[byte 40, 41, 42]
      opened: AmeOpenResult
    opened = openAmeFrame(receiver, acrDac,
      sealAmeFrame(sender, acrDac, payload))
    check opened.ok
    check opened.packet.payload == payload
    check opened.packet.carrier == acrDac

  test "a whole rotation runs through the carrier-agnostic calls":
    var
      client: AmeSession = apiUpgradeSession(aerInitiator)
      server: AmeSession = apiUpgradeSession(aerResponder)
      offerFrame: ByteSeq = @[]
      replyFrame: ByteSeq = @[]
      readyFrame: ByteSeq = @[]
    installSignaturePeers(client, server)
    offerFrame = beginAmeExchangeFrame(client, acrTcp, upgradeRequest(client))
    replyFrame = answerAmeExchangeFrame(server, acrTcp, offerFrame)
    check server.pendingIncoming.active
    readyFrame = finishAmeExchangeFrame(client, acrTcp, replyFrame)
    check client.auth.current.epochId == 2'u32
    check server.auth.current.epochId == 1'u32
    confirmAmeExchangeFrame(server, acrTcp, readyFrame)
    check server.auth.current.epochId == 2'u32
    check server.auth.current.tier.masks.kem == 0b11000000'u8
    check client.auth.current.transcriptSalt == server.auth.current.transcriptSalt

  test "a rotation over DAC reaches the same epoch":
    var
      client: AmeSession = apiUpgradeSession(aerInitiator)
      server: AmeSession = apiUpgradeSession(aerResponder)
      readyFrame: ByteSeq = @[]
    installSignaturePeers(client, server)
    readyFrame = finishAmeExchangeFrame(client, acrDac,
      answerAmeExchangeFrame(server, acrDac,
        beginAmeExchangeFrame(client, acrDac, upgradeRequest(client))))
    confirmAmeExchangeFrame(server, acrDac, readyFrame)
    check server.auth.current.epochId == 2'u32
    check client.auth.current.exchange.sharedSecrets[1] ==
      server.auth.current.exchange.sharedSecrets[1]

suite "rotation triggers driven by the clock":
  test "an elapsed-time trigger becomes due exactly at its threshold":
    var
      connection: AmeSession = apiUpgradeSession()
      step: AmeTierStep
    ## The clock is fed as a READING, not as a delta -- unlike the byte
    ## counter next door, which accumulates. Feeding 4999 and then 1 would
    ## leave the session at one millisecond, not five seconds.
    connection.path.setTimeTrigger(1, 5000'u64)
    step = connection.feedAmeElapsedMs(4999'u64)
    check not step.available
    step = connection.feedAmeElapsedMs(5000'u64)
    check step.available
    check step.targetTier.tierId == 2'u32
    check step.exchangeMask == 0b01000000'u8
    check connection.lastTrigger.available

  test "the offer stands until it is claimed, and the clock never runs back":
    var
      connection: AmeSession = apiUpgradeSession()
      step: AmeTierStep
    connection.path.setTimeTrigger(1, 100'u64)
    step = connection.feedAmeElapsedMs(100'u64)
    check step.available
    ## A due tier stays on offer until something claims it. Withdrawing it
    ## on the next clock reading would mean a caller that polls twice before
    ## acting silently loses the rotation.
    step = connection.feedAmeElapsedMs(900'u64)
    check step.available
    check step.targetTier.tierId == 2'u32
    ## A reading that goes backwards is ignored rather than believed, so a
    ## peer feeding a stale clock cannot un-due a tier.
    step = connection.feedAmeElapsedMs(0'u64)
    check step.available

  test "the clock and the byte counter drive the same path independently":
    var
      connection: AmeSession = apiUpgradeSession()
      step: AmeTierStep
    ## Time alone must not move a tier whose trigger counts bytes.
    connection.path.setTrigger(1, 4'u64)
    step = connection.feedAmeElapsedMs(1_000_000'u64)
    check not step.available
    step = connection.recordTransferredBytes(4'u64 * ameBytesPerMiB)
    check step.available

  test "a manual tier waits for a request, and a disabled one never comes":
    var
      connection: AmeSession = apiUpgradeSession()
      step: AmeTierStep
    connection.path.setManualTrigger(1)
    check not connection.feedAmeElapsedMs(9_000_000'u64).available
    check not connection.recordTransferredBytes(
      999'u64 * ameBytesPerMiB).available
    step = connection.requestAmeTier(2'u32)
    check step.available
    check step.targetTier.tierId == 2'u32

    connection = apiUpgradeSession()
    connection.path.setTimeTrigger(1, 10'u64)
    connection.path.disableTrigger(1)
    check not connection.feedAmeElapsedMs(9_000_000'u64).available
    ## Disabled stops the automatic offer, not the deliberate one.
    check connection.requestAmeTier(2'u32).available

  test "a trigger outside the tier path is refused rather than ignored":
    var
      connection: AmeSession = apiUpgradeSession()
    expect ValueError:
      connection.path.setTimeTrigger(7, 10'u64)
    expect ValueError:
      connection.path.setManualTrigger(-1)
    expect ValueError:
      connection.path.disableTrigger(2)

suite "abandoning a rotation midway":
  test "a cancelled candidate leaves the responder on its old epoch":
    var
      client: AmeSession = apiUpgradeSession(aerInitiator)
      server: AmeSession = apiUpgradeSession(aerResponder)
      offerFrame: ByteSeq = @[]
      replyFrame: ByteSeq = @[]
      readyFrame: ByteSeq = @[]
    installSignaturePeers(client, server)
    offerFrame = beginAmeExchangeFrame(client, acrTcp, upgradeRequest(client))
    replyFrame = answerAmeExchangeFrame(server, acrTcp, offerFrame)
    readyFrame = finishAmeExchangeFrame(client, acrTcp, replyFrame)
    ## The responder has a candidate epoch staged but has never opened a
    ## frame under it, which is exactly the state an abort has to handle:
    ## key material exists, nothing has used it yet.
    check server.pendingIncoming.active
    check server.fomke.pending.active
    cancelIncomingAmeSessionExchange(server)
    check not server.pendingIncoming.active
    check not server.fomke.pending.active
    check not server.fomkeCandidateActive
    check server.auth.current.epochId == 1'u32
    ## The epoch-ready frame arrives after the abort. It must not be able to
    ## resurrect the candidate the responder just threw away.
    expect CatchableError:
      confirmAmeExchangeFrame(server, acrTcp, readyFrame)
    check server.auth.current.epochId == 1'u32

  test "the old epoch still carries traffic after an abort":
    var
      client: AmeSession = apiUpgradeSession(aerInitiator)
      server: AmeSession = apiUpgradeSession(aerResponder)
      payload: ByteSeq = @[byte 5, 5, 5, 5]
      opened: AmeOpenResult
    installSignaturePeers(client, server)
    ## Abort after answering but before the initiator finishes, which is the
    ## case a timeout actually produces: both sides are still on epoch 1 and
    ## ordinary traffic has to keep flowing as though nothing happened.
    discard answerAmeExchangeFrame(server, acrTcp,
      beginAmeExchangeFrame(client, acrTcp, upgradeRequest(client)))
    cancelIncomingAmeSessionExchange(server)
    check client.auth.current.epochId == 1'u32
    check server.auth.current.epochId == 1'u32
    opened = openAmeFrame(server, acrTcp, sealAmeFrame(client, acrTcp, payload))
    check opened.err == ""
    check opened.ok
    check opened.packet.payload == payload

  test "cancelling when nothing is pending changes nothing":
    var
      server: AmeSession = apiUpgradeSession(aerResponder)
    check not server.pendingIncoming.active
    cancelIncomingAmeSessionExchange(server)
    check not server.pendingIncoming.active
    check server.auth.current.epochId == 1'u32
