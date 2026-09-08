## -------------------------------------------------------------------------
## AME Mask Tier Tests <- immutable layouts, exact masks, and KEM transitions
## -------------------------------------------------------------------------

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/derivation
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/path_triggers
import ../../src/protocols/ame/level2/protection
import ../../src/protocols/ame/level2/agreement
import ../../src/protocols/ame/level2/trust
import ../../src/analysis_pragmas

const
  repeatedFireSaber: AmeKemAlgorithms = [
    akaFireSaber, akaFireSaber, akaFireSaber
  ]

proc exactLayout(): AmeSuiteLayout =
  result = initAmeSuiteLayout(repeatedFireSaber,
    initAmeCipherAlgorithms([acaXChaCha20, acaGimli]),
    initAmeMacAlgorithms([amaBlake3, amaGimli]),
    initAmeHashAlgorithms([ahaBlake3, ahaShake256]),
    initAmeSignatureAlgorithms([asaEd25519, asaFalcon512]),
    initAmeKdfAlgorithms([akfaBlake3, akfaGimliXof]))

proc exactTier(L: AmeSuiteLayout, id: uint32, kem,
    other: uint8): AmeMaskTier {.role: configurator.} =
  result = initAmeMaskTier(L, id,
    initAmeTierMasks(kem, other, other, other, other, other))

suite "AME immutable layouts and mask tiers":
  # {.testKind: tkUnit.}
  test "layout and tier have separate canonical encodings":
    var
      L: AmeSuiteLayout = exactLayout()
      t: AmeMaskTier = exactTier(L, 17'u32, 0b10100000'u8, 0b11000000'u8)
      layoutBytes: ByteSeq = encodeAmeSuiteLayout(L)
      tierBytes: ByteSeq = encodeAmeMaskTier(t)
    check layoutsEquivalent(L, decodeAmeSuiteLayout(layoutBytes))
    check tiersEquivalent(t, decodeAmeMaskTier(L, tierBytes))
    check tierBytes == @[byte 1, 17, 0, 0, 0, 0b10100000,
      0b11000000, 0b11000000, 0b11000000, 0b11000000, 0b11000000]

  # {.testKind: tkUnit.}
  test "every tier mask must select occupied slots":
    var L: AmeSuiteLayout = exactLayout()
    expect ValueError:
      discard initAmeMaskTier(L, 1'u32,
        initAmeTierMasks(0'u8, 0b10000000'u8, 0b10000000'u8,
          0b10000000'u8, 0b10000000'u8, 0b10000000'u8))
    expect ValueError:
      discard initAmeMaskTier(L, 1'u32,
        initAmeTierMasks(0b00010000'u8, 0b10000000'u8, 0b10000000'u8,
          0b10000000'u8, 0b10000000'u8, 0b10000000'u8))

  # {.testKind: tkEdgeCase.}
  test "duplicate active hash and KDF overlays are rejected per tier":
    var
      L: AmeSuiteLayout = initAmeSuiteLayout(repeatedFireSaber,
        initAmeCipherAlgorithms([acaXChaCha20]),
        initAmeMacAlgorithms([amaBlake3]),
        initAmeHashAlgorithms([ahaBlake3, ahaBlake3]),
        initAmeSignatureAlgorithms([asaEd25519]),
        initAmeKdfAlgorithms([akfaGimliXof, akfaGimliXof]))
    expect ValueError:
      discard initAmeMaskTier(L, 1'u32,
        initAmeTierMasks(0b10000000'u8, 0b10000000'u8, 0b10000000'u8,
          0b11000000'u8, 0b10000000'u8, 0b10000000'u8))
    expect ValueError:
      discard initAmeMaskTier(L, 1'u32,
        initAmeTierMasks(0b10000000'u8, 0b10000000'u8, 0b10000000'u8,
          0b10000000'u8, 0b10000000'u8, 0b11000000'u8))

  # {.testKind: tkUnit.}
  test "exchange request carries target masks but no algorithm layout":
    var
      L: AmeSuiteLayout = exactLayout()
      t: AmeMaskTier = exactTier(L, 9'u32, 0b10100000'u8, 0b10000000'u8)
      request: AmeExchangeRequest = initAmeExchangeRequest(L.kems, t,
        0b10100000'u8)
      encoded: ByteSeq = encodeAmeExchangeRequest(request)
      decoded: AmeExchangeRequest = decodeAmeExchangeRequest(L.kems, encoded)
    check encoded.len == ameExchangeRequestLen
    check tiersEquivalent(decoded.targetTier, t)
    check decoded.exchangeMask == 0b10100000'u8
    check selectedAlgorithmCount(decoded) == 2

  # {.testKind: tkUnit.}
  test "newly activated KEM slots require exchange while selected slots may rekey":
    var
      L: AmeSuiteLayout = exactLayout()
      current: AmeMaskTier = exactTier(L, 1'u32, 0b10000000'u8,
        0b10000000'u8)
      target: AmeMaskTier = exactTier(L, 2'u32, 0b11000000'u8,
        0b11000000'u8)
    expect ValueError:
      validateAmeTierTransition(L, current, target, 0'u8, 0b10000000'u8)
    validateAmeTierTransition(L, current, target, 0b01000000'u8,
      0b10000000'u8)
    validateAmeTierTransition(L, target, target, 0b10000000'u8,
      0b11000000'u8)
    expect ValueError:
      validateAmeTierTransition(L, target, target, 0b00100000'u8,
        0b11000000'u8)

  # {.testKind: tkUnit.}
  test "rekey preserves every unselected established secret":
    var
      L: AmeSuiteLayout = exactLayout()
      t: AmeMaskTier = exactTier(L, 3'u32, 0b11000000'u8, 0b10000000'u8)
      state: AmeExchangeState = initAmeExchangeState(L.kems)
      first: AmeExchangeRequest = initAmeExchangeRequest(L.kems, t,
        0b11000000'u8)
      second: AmeExchangeRequest = initAmeExchangeRequest(L.kems, t,
        0b10000000'u8)
      preserved: ByteSeq = @[]
      before: ByteSeq = @[]
    applyAmeExchange(state, first, [@[byte 1, 2], @[byte 3, 4]])
    preserved = state.sharedSecrets[1] & @[]
    before = deriveAmeMasterKey(state, L, t)
    applyAmeExchange(state, second, [@[byte 9, 9]])
    check state.activeMask == 0b11000000'u8
    check state.generation[0] == 2'u32
    check state.generation[1] == 1'u32
    check state.sharedSecrets[1] == preserved
    check deriveAmeMasterKey(state, L, t) != before

  # {.testKind: tkUnit.}
  test "repeated KEM slots perform independent exchanges":
    var
      L: AmeSuiteLayout = exactLayout()
      t: AmeMaskTier = exactTier(L, 1'u32, 0b11100000'u8,
        0b10000000'u8)
      request: AmeExchangeRequest = initAmeExchangeRequest(L.kems, t,
        t.masks.kem)
      receiver: AmeExchangeKeys = generateAmeExchangeKeys(L.kems, request)
      sender: AmeExchangeResult = sealAmeExchange(L.kems, request,
        receiver.publicKeys)
      opened: seq[ByteSeq] = openAmeExchange(L.kems, request,
        sender.envelopes, receiver.secretKeys)
    check opened == sender.sharedSecrets
    check opened[0] != opened[1]

  # {.testKind: tkUnit.}
  test "Frodo1344 tier exchange derives the same shared secret":
    var
      L: AmeSuiteLayout = defaultAmeLayout(initAmeKemAlgorithms([
        akaFrodo1344Aes]))
      t: AmeMaskTier = fullAmeMaskTier(L)
      request: AmeExchangeRequest = initAmeExchangeRequest(L.kems, t,
        t.masks.kem)
      receiver: AmeExchangeKeys = generateAmeExchangeKeys(L.kems, request)
      sender: AmeExchangeResult = sealAmeExchange(L.kems, request,
        receiver.publicKeys)
      opened: seq[ByteSeq] = openAmeExchange(L.kems, request,
        sender.envelopes, receiver.secretKeys)
    check opened == sender.sharedSecrets

  # {.testKind: tkUnit.}
  test "ordered tier path emits newly activated KEM masks":
    var
      L: AmeSuiteLayout = exactLayout()
      t1: AmeMaskTier = exactTier(L, 10'u32, 0b10000000'u8,
        0b10000000'u8)
      t2: AmeMaskTier = exactTier(L, 20'u32, 0b11000000'u8,
        0b11000000'u8)
      t3: AmeMaskTier = exactTier(L, 30'u32, 0b11100000'u8,
        0b11000000'u8)
      path: AmeTierPath = initAmeTierPath(L, [t1, t2, t3])
      step: AmeTierStep
    setCurrentAmeTier(path, t1)
    path.setTrigger(1, 200'u64)
    step = path.feedTransferredBytes(199'u64 * ameBytesPerMiB)
    check not step.available
    step = path.feedTransferredBytes(1'u64 * ameBytesPerMiB)
    check step.available
    check step.targetTier.tierId == 20'u32
    check step.exchangeMask == 0b01000000'u8
    path.claimAmeTier(step)
    path.completeAmeTier(t2)
    step = path.requestTier(30'u32, 0b10000000'u8)
    check step.exchangeMask == 0b10100000'u8

  # {.testKind: tkUnit.}
  test "protection and hashes bind both layout and tier masks":
    var
      L: AmeSuiteLayout = exactLayout()
      t1: AmeMaskTier = exactTier(L, 1'u32, 0b10000000'u8,
        0b10000000'u8)
      t2: AmeMaskTier = exactTier(L, 2'u32, 0b10000000'u8,
        0b11000000'u8)
      state: AmeExchangeState = initAmeExchangeState(L.kems)
      request: AmeExchangeRequest = initAmeExchangeRequest(L.kems, t1,
        t1.masks.kem)
      sealed: tuple[message: AmeProtectedMessage, nonce: ByteSeq]
      opened: tuple[ok: bool, payload: ByteSeq]
      message: ByteSeq = @[byte 4, 8, 15, 16, 23, 42]
    applyAmeExchange(state, request, [@[byte 1, 3, 3, 7]])
    sealed = protectAmeMessage(L, t1, state, message, @[byte 9])
    opened = openAmeMessage(L, t1, state, sealed.nonce, sealed.message,
      @[byte 9])
    check opened.ok
    check opened.payload == message
    check hashAmeTier(L, t1, message) != hashAmeTier(L, t2, message)
    opened = openAmeMessage(L, t2, state, sealed.nonce, sealed.message,
      @[byte 9])
    check not opened.ok

  # {.testKind: tkUnit.}
  test "agreement accepts exact layouts and binds the proposed initial tier":
    var
      L: AmeSuiteLayout = exactLayout()
      t: AmeMaskTier = exactTier(L, 7'u32, 0b10000000'u8,
        0b10000000'u8)
      proposal: AmeAgreementProposal = initAmeAgreementProposal(7'u32, L, t)
      path: AmeTierPath = initAmeTierPath(L, [t])
      decoded: AmeAgreementProposal = decodeAmeAgreementProposal(
        encodeAmeAgreementProposal(proposal))
      accepted: AmeAgreementDecision = decideAmeAgreement(decoded, [path])
      decision: AmeAgreementDecision = decodeAmeAgreementDecision(
        encodeAmeAgreementDecision(accepted))
    check decision.accepted
    check verifyAmeAgreementDecision(proposal, decision)
    check tiersEquivalent(decoded.initialTier, t)

  # {.testKind: tkUnit.}
  test "agreement decisions and trust handoff remain canonical":
    var
      decision: AmeAgreementDecision
      trust: AmePeerTrustResult
    decision.proposalId = 1'u32
    decision.accepted = true
    decision.selectionHash = newSeq[byte](32)
    decision.reason = "not canonical"
    expect ValueError:
      discard encodeAmeAgreementDecision(decision)
    trust = initVerifiedAmePeerTrust("root-a", "peer-a", [asaEd25519])
    check trust.ok
    expect ValueError:
      discard initVerifiedAmePeerTrust("", "peer-a", [asaEd25519])
