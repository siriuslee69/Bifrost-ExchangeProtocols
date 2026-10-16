## -------------------------------------------------------------------------
## AME Change Requests <- either side asks, the other answers, both switch
## -------------------------------------------------------------------------
##
## What these tests hold down:
##
##   order      every layout is kept in wire-id order, whatever order it
##              was written in; bytes out of order are refused
##   repeats    two X25519 in one layout are two instances with own keys
##   by name    a request names algorithms; the bits follow from the layout
##   ids        the KEMs that run an exchange travel as their ids; each id
##              feeds an instance being switched on first, then the lowest
##   proof      default: a tag under the current epoch (the AM1P way);
##              signed on request or when `ameSignedExchanges` says so
##   change     ciphers, MACs, KDFs (and XHKDF's branches) switch together,
##              at the confirmation, on both sides
##   deny       a request below the responder's minimum gets a deny; the
##              requester stays on its old algorithms and may send again
##   wait       from its request until the answer the requester sends
##              nothing; a responder that replied sends nothing until
##              epoch-ready
##
## The session pair: layout KEMs [FireSaber, FireSaber, X25519], ciphers
## [XChaCha20, Gimli], KDFs [BLAKE3, GimliXof], and so on; the first slot
## of every family switched on at the start.

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/config
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/secret_stack
import ../../src/protocols/ame/level2/framing
import ../../src/protocols/ame/level3/handshake
import ../../src/protocols/fomke/types
import ../../src/protocols/fomke/level0/xhkdf
import runePragmas

const
  pairKems: AmeKemAlgorithms = [akaX25519, akaFireSaber, akaFireSaber]

proc pairAuth(role: AmeEndpointRole): AmeAuthPackage {.role: configurator.} =
  ## role: one end of the test pair (see the header).
  var
    layout: AmeSuiteLayout = initAmeSuiteLayout(pairKems,
      initAmeCipherAlgorithms([acaGimli, acaXChaCha20]),
      initAmeMacAlgorithms([amaGimli, amaBlake3]),
      initAmeHashAlgorithms([ahaShake256, ahaBlake3]),
      initAmeSignatureAlgorithms([asaFalcon512, asaEd25519]),
      initAmeKdfAlgorithms([akfaGimliXof, akfaBlake3]))
    tier: AmeMaskTier = initAmeMaskTier(layout, 1'u32,
      initAmeTierMasks(0b10000000'u8, 0b10000000'u8, 0b10000000'u8,
        0b10000000'u8, 0b10000000'u8, 0b10000000'u8))
    state: AmeExchangeState = initAmeExchangeState(layout.kems)
  applyAmeExchange(state, layout, initAmeExchangeRequest(layout.kems, tier,
    tier.masks.kem), [@[byte 9, 8, 7, 6]])
  result = initAmeAuthPackage(layout, tier, state, endpointRole = role)

proc pairSessions(): tuple[a, b: AmeSession] {.role: configurator.} =
  ## Two ends that trust each other's signature keys.
  var
    aKeys: tuple[publicKeys: seq[ByteSeq], secretKeys: seq[ByteSeq]] = (
      publicKeys: @[], secretKeys: @[])
    bKeys: tuple[publicKeys: seq[ByteSeq], secretKeys: seq[ByteSeq]] = (
      publicKeys: @[], secretKeys: @[])
  result.a = initAmeSession(pairAuth(aerInitiator), peerTrustRequired = false)
  result.b = initAmeSession(pairAuth(aerResponder), peerTrustRequired = false)
  aKeys = generateAmeSigningKeys(result.a.auth.current.layout,
    fullAmeMaskTier(result.a.auth.current.layout))
  bKeys = generateAmeSigningKeys(result.b.auth.current.layout,
    fullAmeMaskTier(result.b.auth.current.layout))
  result.a.auth.localSignatureSecretKeys = aKeys.secretKeys
  result.a.auth.peerSignaturePublicKeys = bKeys.publicKeys
  result.b.auth.localSignatureSecretKeys = bKeys.secretKeys
  result.b.auth.peerSignaturePublicKeys = aKeys.publicKeys

proc switchVia(requester, responder: var AmeSession,
    r: AmeExchangeRequest) {.role: orchestrator.} =
  ## requester/responder/r: one whole accepted change over TCP frames.
  var
    ready: ByteSeq = @[]
  ready = finishAmeTcpExchangeFrame(requester, answerAmeTcpExchangeFrame(
    responder, beginAmeTcpExchangeFrame(requester, r)))
  confirmAmeTcpExchangeFrame(responder, ready)

proc talks(a, b: var AmeSession): bool {.role: orchestrator.} =
  ## a/b: true when one frame goes each way and opens.
  result = openAmeTcpFrame(b, sealAmeTcpFrame(a, [byte 1, 2, 3])).ok and
    openAmeTcpFrame(a, sealAmeTcpFrame(b, [byte 4, 5, 6])).ok

suite "AME layouts: one order":
  # {.testKind: tkUnit, covers: "sortedByWireId".}
  test "a layout written in any order is kept in wire-id order":
    var
      L: AmeSuiteLayout = pairAuth(aerInitiator).current.layout
    check L.kems.algorithms[0] == akaFireSaber      # 0x01
    check L.kems.algorithms[1] == akaFireSaber      # 0x01
    check L.kems.algorithms[2] == akaX25519         # 0x0F
    check L.ciphers.algorithms[0] == acaXChaCha20   # 0x01
    check L.ciphers.algorithms[1] == acaGimli       # 0x02

  # {.testKind: tkEdgeCase, covers: "requireWireOrder".}
  test "layout bytes out of wire-id order are refused":
    var
      L: AmeSuiteLayout = pairAuth(aerInitiator).current.layout
      bytes: ByteSeq = encodeAmeSuiteLayout(L)
    check decodeAmeSuiteLayout(bytes).kems.algorithms[2] == akaX25519
    ## KEM ids sit at bytes 2..4: 01 01 0F. Swap the last two.
    bytes[3] = 0x0F'u8
    bytes[4] = 0x01'u8
    expect ValueError:
      discard decodeAmeSuiteLayout(bytes)

  # {.testKind: tkUnit, covers: "ameSelectionMask".}
  test "algorithms named twice select two instances":
    var
      L: AmeSuiteLayout = pairAuth(aerInitiator).current.layout
    check ameSelectionMask(L.kems, [akaFireSaber]) == 0b10000000'u8
    check ameSelectionMask(L.kems, [akaFireSaber, akaFireSaber]) ==
      0b11000000'u8
    check ameSelectionMask(L.kems, [akaX25519]) == 0b00100000'u8
    expect ValueError:
      discard ameSelectionMask(L.kems, [akaMlKem768])

  # {.testKind: tkUnit, covers: "generateAmeExchangeKeys".}
  test "two instances of one algorithm get two different keys":
    var
      L: AmeSuiteLayout = defaultAmeLayout([akaX25519, akaX25519])
      keys: AmeExchangeKeys = generateAmeExchangeKeys(L.kems,
        initAmeExchangeRequest(L.kems, fullAmeMaskTier(L), 0b11000000'u8))
    check keys.publicKeys.len == 2
    check keys.publicKeys[0] != keys.publicKeys[1]

suite "AME change requests":
  # {.testKind: tkIntegration, covers: "ameAddExchangeRequest".}
  test "one more exchange for one KEM, by name, adds to its stack":
    var
      p: tuple[a, b: AmeSession] = pairSessions()
      before: uint32 = p.a.auth.current.exchange.generation[0]
    switchVia(p.a, p.b, ameAddExchangeRequest(p.a, [akaFireSaber]))
    check p.a.auth.current.epochId == 2'u32
    check p.b.auth.current.epochId == 2'u32
    check p.a.auth.current.exchange.generation[0] == before + 1'u32
    check talks(p.a, p.b)

  # {.testKind: tkIntegration, covers: "ameSelection|fomkeKdfFor".}
  test "ciphers, MACs and KDFs switch together, XHKDF branches included":
    var
      p: tuple[a, b: AmeSession] = pairSessions()
      t: AmeMaskTier = ameSelection(p.a,
        ciphers = [acaXChaCha20, acaGimli], macs = [amaBlake3, amaGimli],
        kdfs = [akfaBlake3, akfaGimliXof])
    when xbGimli in xhkdfBranchesBuilt:
      check p.a.fomke.kdf.branches == {xbBlake3}
    switchVia(p.a, p.b, ameChangeRequest(p.a, t))
    check p.a.auth.current.tier.masks.cipher == 0b11000000'u8
    check p.b.auth.current.tier.masks.cipher == 0b11000000'u8
    check p.a.fomke.kdf.branches == p.b.fomke.kdf.branches
    when xbGimli in xhkdfBranchesBuilt:
      check p.a.fomke.kdf.branches == {xbBlake3, xbGimli}
    check talks(p.a, p.b)

  # {.testKind: tkIntegration, covers: "ameChangeRequest".}
  test "the responder may ask too, and a change may switch things off":
    var
      p: tuple[a, b: AmeSession] = pairSessions()
      up: AmeMaskTier = ameSelection(p.b, kems = [akaFireSaber, akaX25519],
        ciphers = [acaXChaCha20, acaGimli])
      down: AmeMaskTier = default(AmeMaskTier)
    switchVia(p.b, p.a, ameChangeRequest(p.b, up))
    check p.a.auth.current.tier.masks.kem == 0b10100000'u8
    check talks(p.a, p.b)
    down = ameSelection(p.a, ciphers = [acaGimli])
    switchVia(p.a, p.b, ameChangeRequest(p.a, down))
    check p.b.auth.current.tier.masks.cipher == 0b01000000'u8
    check talks(p.a, p.b)

suite "AME change requests: deny and wait":
  # {.testKind: tkIntegration, covers: "ameExchangeDenyReason|denyAmeSessionExchange".}
  test "a request below the responder's minimum is denied; nothing changes":
    ## Switching FireSaber off leaves X25519 alone: no post-quantum KEM.
    ## The responder requires one, so it answers with a deny.
    var
      p: tuple[a, b: AmeSession] = pairSessions()
      saved: BifrostConfig = currentBifrostConfig()
      strict: BifrostConfig = currentBifrostConfig()
      offer: ByteSeq = @[]
      answer: ByteSeq = @[]
    offer = beginAmeTcpExchangeFrame(p.a, ameChangeRequest(p.a,
      ameSelection(p.a, kems = [akaX25519])))
    strict.ameMinPqKems = 1
    applyBifrostConfig(strict)
    answer = answerAmeTcpExchangeFrame(p.b, offer)
    applyBifrostConfig(saved)
    check not p.b.pendingIncoming.active
    check finishAmeTcpExchangeFrame(p.a, answer).len == 0
    check p.a.lastExchangeDenial.len > 0
    check not p.a.pendingExchange.active
    check p.a.auth.current.epochId == 1'u32
    check p.b.auth.current.epochId == 1'u32
    check talks(p.a, p.b)

  # {.testKind: tkEdgeCase, covers: "requireAmeMaySend".}
  test "a requester sends nothing until its request is answered":
    var
      p: tuple[a, b: AmeSession] = pairSessions()
      offer: ByteSeq = beginAmeTcpExchangeFrame(p.a,
        ameAddExchangeRequest(p.a, [akaFireSaber]))
      reply: ByteSeq = @[]
      ready: ByteSeq = @[]
    expect ValueError:
      discard sealAmeTcpFrame(p.a, [byte 1])
    reply = answerAmeTcpExchangeFrame(p.b, offer)
    ## The responder replied and is switching: it waits for epoch-ready.
    expect ValueError:
      discard sealAmeTcpFrame(p.b, [byte 2])
    ready = finishAmeTcpExchangeFrame(p.a, reply)
    ## The requester got its answer: it may send, on the new algorithms.
    check sealAmeTcpFrame(p.a, [byte 3]).len > 0
    confirmAmeTcpExchangeFrame(p.b, ready)
    check sealAmeTcpFrame(p.b, [byte 4]).len > 0

suite "AME exchange requests: ids on the wire":
  # {.testKind: tkUnit, covers: "encodeAmeExchangeRequest".}
  test "the KEMs that run an exchange travel as their ids":
    var
      p: tuple[a, b: AmeSession] = pairSessions()
      r: AmeExchangeRequest = default(AmeExchangeRequest)
      bytes: ByteSeq = @[]
    ## Switch the second FireSaber on (it must run an exchange) and ask for
    ## one more on the first: two exchanges, both FireSaber.
    r = ameChangeRequest(p.a, ameSelection(p.a,
      kems = [akaFireSaber, akaFireSaber]), exchanges = [akaFireSaber])
    bytes = encodeAmeExchangeRequest(r)
    ## tier (10) | n | ids | proof | tag length | padding
    check bytes.len == ameExchangeRequestFixedLen + 2
    check bytes[10] == 2'u8
    check bytes[11] == 0x01'u8
    check bytes[12] == 0x01'u8
    check bytes[13] == uint8(ord(aepFrame))

  # {.testKind: tkEdgeCase, covers: "exchangeMaskFromIds".}
  test "an id feeds the instance being switched on before one already on":
    var
      L: AmeKemAlgorithms = initAmeKemAlgorithms([akaX25519, akaX25519])
    ## Only the first X25519 is on; the target switches the second on too.
    check exchangeMaskFromIds(L, 0b11000000'u8, 0b10000000'u8,
      [akaX25519]) == 0b01000000'u8
    check exchangeMaskFromIds(L, 0b11000000'u8, 0b10000000'u8,
      [akaX25519, akaX25519]) == 0b11000000'u8
    ## Both on already: the lowest one.
    check exchangeMaskFromIds(L, 0b11000000'u8, 0b11000000'u8,
      [akaX25519]) == 0b10000000'u8
    expect ValueError:
      discard exchangeMaskFromIds(L, 0b10000000'u8, 0b10000000'u8,
        [akaX25519, akaX25519])

  # {.testKind: tkEdgeCase, covers: "decodeAmeExchangeRequest".}
  test "a request naming a KEM the target does not switch on is refused":
    var
      p: tuple[a, b: AmeSession] = pairSessions()
      bytes: ByteSeq = encodeAmeExchangeRequest(
        ameAddExchangeRequest(p.a, [akaFireSaber]))
    bytes[11] = uint8(ord(akaX25519))   # X25519 is in the layout, but off
    expect ValueError:
      discard decodeAmeExchangeRequest(p.a.auth.current.layout.kems,
        p.a.auth.current.tier.masks.kem, bytes)

suite "AME exchange requests: proof":
  # {.testKind: tkIntegration, covers: "proveExchangeSubject".}
  test "by default a request is proved by the frame tag alone":
    var
      p: tuple[a, b: AmeSession] = pairSessions()
      r: AmeExchangeRequest = ameAddExchangeRequest(p.a, [akaFireSaber])
    check r.proof == aepFrame
    switchVia(p.a, p.b, r)
    check p.b.auth.current.epochId == 2'u32
    check talks(p.a, p.b)

  # {.testKind: tkIntegration, covers: "proveExchangeSubject".}
  test "signed = true proves it with signatures instead":
    var
      p: tuple[a, b: AmeSession] = pairSessions()
    switchVia(p.a, p.b, ameAddExchangeRequest(p.a, [akaFireSaber],
      signed = true))
    check p.b.auth.current.epochId == 2'u32
    check talks(p.a, p.b)

  # {.testKind: tkEdgeCase, covers: "exchangeProofError".}
  test "a signed request needs signature keys":
    var
      p: tuple[a, b: AmeSession] = pairSessions()
    p.a.auth.localSignatureSecretKeys = @[]
    expect ValueError:
      discard beginAmeTcpExchangeFrame(p.a, ameAddExchangeRequest(p.a,
        [akaFireSaber], signed = true))

  # {.testKind: tkIntegration, covers: "ameRequestPolicyError".}
  test "ameSignedExchanges = true denies an unsigned request":
    var
      p: tuple[a, b: AmeSession] = pairSessions()
      saved: BifrostConfig = currentBifrostConfig()
      strict: BifrostConfig = currentBifrostConfig()
      offer: ByteSeq = beginAmeTcpExchangeFrame(p.a,
        ameAddExchangeRequest(p.a, [akaFireSaber]))
      answer: ByteSeq = @[]
    strict.ameSignedExchanges = true
    applyBifrostConfig(strict)
    answer = answerAmeTcpExchangeFrame(p.b, offer)
    applyBifrostConfig(saved)
    check finishAmeTcpExchangeFrame(p.a, answer).len == 0
    check p.a.lastExchangeDenial.len > 0
    check p.b.auth.current.epochId == 1'u32
    check talks(p.a, p.b)
