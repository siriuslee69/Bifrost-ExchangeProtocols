## -------------------------------------------------------------------------
## AME Mask Tier Tests <- immutable layouts, exact masks, and KEM transitions
## -------------------------------------------------------------------------

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/derivation
import ../../src/protocols/ame/level1/secret_stack
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/path_triggers
import ../../src/protocols/ame/level2/protection
import ../../src/protocols/ame/level2/agreement
import ../../src/protocols/ame/level2/trust
import runePragmas

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
    applyAmeExchange(state, L, first, [@[byte 1, 2], @[byte 3, 4]])
    preserved = state.stackedSecrets[1] & @[]
    before = deriveAmeMasterKey(state, L, t)
    applyAmeExchange(state, L, second, [@[byte 9, 9]])
    check state.activeMask == 0b11000000'u8
    check state.generation[0] == 2'u32
    check state.generation[1] == 1'u32
    check state.stackedSecrets[1] == preserved
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
    applyAmeExchange(state, L, request, [@[byte 1, 3, 3, 7]])
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

suite "AME secrets stack instead of being replaced":
  # {.testKind: tkRegression, covers: "stackAmeSecret", pins: "a rotation used to throw away everything the slot had agreed before".}
  test "a slot keeps everything it has agreed, not just the last thing":
    ## What this pins.
    ##
    ## A slot used to hold the secret it last agreed. Rotating replaced it, so
    ## an attacker who recovered THAT ONE secret -- a KEM broken later, a bad
    ## random number -- read the epoch, and every exchange before it had
    ## protected nothing.
    ##
    ## Both states below end on the same fresh secret. Only their histories
    ## differ, and that has to be enough to make their keys different.
    var
      L: AmeSuiteLayout = exactLayout()
      t: AmeMaskTier = exactTier(L, 1'u32, 0b10000000'u8, 0b10000000'u8)
      request: AmeExchangeRequest = initAmeExchangeRequest(L.kems, t,
        0b10000000'u8)
      a: AmeExchangeState = initAmeExchangeState(L.kems)
      b: AmeExchangeState = initAmeExchangeState(L.kems)
      shared: ByteSeq = @[byte 9, 9, 9, 9, 9, 9, 9, 9]
    applyAmeExchange(a, L, request, [@[byte 1, 1, 1, 1]])
    applyAmeExchange(b, L, request, [@[byte 2, 2, 2, 2]])
    ## The same fresh secret arrives at both, on top of different pasts.
    applyAmeExchange(a, L, request, [shared])
    applyAmeExchange(b, L, request, [shared])
    check a.generation[0] == 2'u32
    check b.generation[0] == 2'u32
    check a.stackedSecrets[0] != b.stackedSecrets[0]
    check deriveAmeMasterKey(a, L, t) != deriveAmeMasterKey(b, L, t)

  # {.testKind: tkUnit, covers: "stackAmeSecret".}
  test "what a slot stores is never the secret it was handed":
    ## The stored value is a one-way image of the secret and everything before
    ## it. Reading the state gives an attacker the stack, never the exchange.
    var
      L: AmeSuiteLayout = exactLayout()
      t: AmeMaskTier = exactTier(L, 1'u32, 0b10000000'u8, 0b10000000'u8)
      request: AmeExchangeRequest = initAmeExchangeRequest(L.kems, t,
        0b10000000'u8)
      state: AmeExchangeState = initAmeExchangeState(L.kems)
      secret: ByteSeq = @[byte 4, 8, 15, 16, 23, 42]
    applyAmeExchange(state, L, request, [secret])
    check state.stackedSecrets[0].len > 0
    check state.stackedSecrets[0] != secret

  # {.testKind: tkRegression, covers: "applyAmeExchange", pins: "a provisioned AM1M secret used to prove identity and touch no key".}
  test "the provisioned secret changes every key, not just the proof":
    ## AM1M hands both sides a secret out of band. It used to authenticate the
    ## handshake and go nowhere near a traffic key, so a broken KEM took the
    ## whole session and the shared secret did nothing to stop it.
    ##
    ## Same exchanges here, same fresh secrets, different provisioned secret.
    ## The keys have to part company.
    var
      L: AmeSuiteLayout = exactLayout()
      t: AmeMaskTier = exactTier(L, 1'u32, 0b10000000'u8, 0b10000000'u8)
      request: AmeExchangeRequest = initAmeExchangeRequest(L.kems, t,
        0b10000000'u8)
      a: AmeExchangeState = initAmeExchangeState(L.kems)
      b: AmeExchangeState = initAmeExchangeState(L.kems)
      none: AmeExchangeState = initAmeExchangeState(L.kems)
      secret: ByteSeq = @[byte 7, 7, 7, 7]
    applyAmeExchange(a, L, request, [secret], @[byte 1, 2, 3, 4])
    applyAmeExchange(b, L, request, [secret], @[byte 4, 3, 2, 1])
    applyAmeExchange(none, L, request, [secret])
    check a.stackedSecrets[0] != b.stackedSecrets[0]
    check deriveAmeMasterKey(a, L, t) != deriveAmeMasterKey(b, L, t)
    ## And a mode with no provisioned secret at all is a third answer again,
    ## never accidentally equal to one that has one.
    check none.stackedSecrets[0] != a.stackedSecrets[0]
    check none.stackedSecrets[0] != b.stackedSecrets[0]

  # {.testKind: tkUnit, covers: "ameStackDepth".}
  test "the stack only ever gets deeper, and reports its shallowest slot":
    ## Depth is what a rotation buys, and the honest number is the SHALLOWEST
    ## chosen slot: an attacker picks which slot to work on, not the defender.
    var
      L: AmeSuiteLayout = exactLayout()
      t: AmeMaskTier = exactTier(L, 1'u32, 0b11000000'u8, 0b10000000'u8)
      both: AmeExchangeRequest = initAmeExchangeRequest(L.kems, t,
        0b11000000'u8)
      firstOnly: AmeExchangeRequest = initAmeExchangeRequest(L.kems, t,
        0b10000000'u8)
      state: AmeExchangeState = initAmeExchangeState(L.kems)
      i: int = 0
    applyAmeExchange(state, L, both, [@[byte 1], @[byte 2]])
    check ameStackDepth(state, 0b11000000'u8) == 1'u32
    ## Three more rotations, but only on slot 0. The pair is still one deep,
    ## because slot 1 is, and that is the slot worth attacking.
    while i < 3:
      applyAmeExchange(state, L, firstOnly, [@[byte uint8(10 + i)]])
      i = i + 1
    check ameStackDepth(state, 0b10000000'u8) == 4'u32
    check ameStackDepth(state, 0b01000000'u8) == 1'u32
    check ameStackDepth(state, 0b11000000'u8) == 1'u32

  # {.testKind: tkEdgeCase, covers: "applyAmeExchange".}
  test "stacking costs no forward secrecy":
    ## The old stack is erased as the new one is built, and the new one is a
    ## one-way image of it. So the state after a rotation cannot produce the
    ## key the epoch before it used -- exactly as before this change, where the
    ## old secret was erased instead.
    var
      L: AmeSuiteLayout = exactLayout()
      t: AmeMaskTier = exactTier(L, 1'u32, 0b10000000'u8, 0b10000000'u8)
      request: AmeExchangeRequest = initAmeExchangeRequest(L.kems, t,
        0b10000000'u8)
      state: AmeExchangeState = initAmeExchangeState(L.kems)
      before: ByteSeq = @[]
      stackBefore: ByteSeq = @[]
    applyAmeExchange(state, L, request, [@[byte 1, 1, 1, 1]])
    before = deriveAmeMasterKey(state, L, t)
    stackBefore = state.stackedSecrets[0] & @[]
    applyAmeExchange(state, L, request, [@[byte 2, 2, 2, 2]])
    ## Nothing of the old epoch is left in the state.
    check state.stackedSecrets[0] != stackBefore
    check deriveAmeMasterKey(state, L, t) != before
