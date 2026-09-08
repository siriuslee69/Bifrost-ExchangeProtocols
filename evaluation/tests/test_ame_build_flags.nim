## -------------------------------------------------------------------------
## AME Build Flag Tests <- what -d:bifrostKems and -d:bifrostCarriers change
## -------------------------------------------------------------------------
##
## This file compiles under every flag combination and checks the same rules
## each time, so the slim builds are verified by the very same tests as the
## full one. Run it plain for the full library, or with flags, e.g.
##
##   nimble testMinimalAme
##
## Kyber and X25519 are the two families the minimal profile keeps, so the
## positive checks below use them; the exclusion checks name a family only
## when this build actually left it out.

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/ame
import ../../src/protocols/fomke/types
import ../../src/protocols/config
import ../../src/analysis_pragmas

const
  minimalKems: AmeKemAlgorithms = [akaKyber768, akaX25519]

proc tagLenSession(n: AmeAuthTagLen,
    role: AmeEndpointRole = aerInitiator): AmeSession =
  ## n: a ready session whose epoch carries the given tag length. Both sides
  ## of a test build one, so agreement is explicit rather than assumed.
  ## role: traffic keys are direction-bound, so a sender and its receiver
  ## must hold opposite roles or nothing they exchange will open.
  var
    L: AmeSuiteLayout = defaultAmeLayout(minimalKems)
    tier: AmeMaskTier = fullAmeMaskTier(L)
    st: AmeExchangeState = initAmeExchangeState(minimalKems)
  applyAmeExchange(st, initAmeExchangeRequest(minimalKems, tier, tier.masks.kem),
    [@[byte 9, 8, 7, 6, 5, 4, 3, 2], @[byte 1, 2, 3, 4, 5, 6, 7, 8]])
  result = initAmeSession(initAmeAuthPackage(L, tier, st,
    endpointRole = role, params = AmeRuntimeParams(authTagLen: n)),
    peerTrustRequired = false)

proc minimalLayout(): AmeSuiteLayout {.role: configurator.} =
  ## The smallest complete layout the minimal profile can still describe.
  result = initAmeSuiteLayout(minimalKems,
    initAmeCipherAlgorithms([acaXChaCha20]),
    initAmeMacAlgorithms([amaBlake3]),
    initAmeHashAlgorithms([ahaBlake3]),
    initAmeSignatureAlgorithms([asaEd25519]),
    initAmeKdfAlgorithms([akfaBlake3]))

suite "AME build flags":
  # {.testKind: tkUnit.}
  test "the build set answers for every KEM slot":
    check ameKemBuilt(akaKyber768) == (akfKyber in ameKemsBuilt)
    check ameKemBuilt(akaX25519) == (akfX25519 in ameKemsBuilt)
    check ameKemBuilt(akaMcEliece6688) == (akfMcEliece in ameKemsBuilt)
    check ameKemFamily(akaKyber1024) == akfKyber
    check ameKemFamily(akaLightSaber) == akfSaber
    check ameKemFamilyName(akfMcEliece) == "mceliece"

  # {.testKind: tkIntegration.}
  test "the wire meaning of every slot survives a slim build":
    ## Slot numbers are protocol, not build configuration: a node that lacks
    ## McEliece must still agree with a full node on what byte 0x0E means.
    check ord(akaKyber768) == 0x08
    check ord(akaMcEliece6688) == 0x0E
    check ameKemName(akaMcEliece6688) == "Classic-McEliece-6688128f"

  # {.testKind: tkUnit.}
  test "a constant and a value reach the same code":
    ## The constant form is settled while compiling, the value form by one
    ## `case` while running. Both must produce usable material.
    var
      a: AmeKemAlgorithm = akaX25519
      byConstant: AmeKemKeypair = ameKemKeypair(akaX25519)
      byValue: AmeKemKeypair = ameKemKeypair(a)
      sealed: AmeKemCipher = sealAmeKem(a, byConstant.publicKey)
      shared: ByteSeq = openAmeKem(akaX25519, sealed, byConstant.secretKey)
    check byConstant.publicKey.len > 0
    check byValue.publicKey.len == byConstant.publicKey.len
    check shared == sealed.sharedSecret

  # {.testKind: tkUnit.}
  test "a Kyber slot encapsulates and decapsulates to one secret":
    var
      kp: AmeKemKeypair = ameKemKeypair(akaKyber768)
      sealed: AmeKemCipher = sealAmeKem(akaKyber768, kp.publicKey)
      shared: ByteSeq = openAmeKem(akaKyber768, sealed, kp.secretKey)
    check sealed.envelope.ciphertext.len > 0
    check shared == sealed.sharedSecret

  # {.testKind: tkEdgeCase.}
  test "a layout of built families is accepted":
    var L: AmeSuiteLayout = minimalLayout()
    check L.kems.length == 2'u8
    check decodeAmeKemAlgorithms(encodeAmeKemAlgorithms(L.kems)) == L.kems

  when akfMcEliece notin ameKemsBuilt:
    # {.testKind: tkEdgeCase.}
    test "an excluded family is refused before any key material":
      ## Three gates, all closed: naming it locally, decoding a peer naming
      ## it, and calling it outright. The call below goes through a variable
      ## on purpose: written as the constant `ameKemKeypair(akaMcEliece6688)`
      ## it would not compile at all, which is the stricter of the two gates
      ## and cannot be caught by a running test.
      var excluded: AmeKemAlgorithm = akaMcEliece6688
      expect ValueError:
        discard initAmeKemAlgorithms([akaMcEliece6688])
      expect ValueError:
        discard decodeAmeKemAlgorithms(@[1'u8, uint8(ord(akaMcEliece6688))])
      expect ValueError:
        discard ameKemKeypair(excluded)

  # {.testKind: tkUnit.}
  test "the process defaults name only KEMs this build can run":
    ## `currentBifrostConfig` builds its layout on first use. If that layout
    ## named a family the flags left out, every slim build would fail the
    ## moment anything read the defaults, e.g. enabling FOMKE on a session.
    var c: BifrostConfig = currentBifrostConfig()
    check c.ameLayout.kems.length >= 1'u8
    for i in 0 ..< int(c.ameLayout.kems.length):
      check ameKemBuilt(c.ameLayout.kems[i])
    validateAmeTier(c.ameLayout, c.ameInitialTier)

  # {.testKind: tkUnit.}
  test "a full build keeps the defaults it has always had":
    when ameKemsBuilt == {akfX25519, akfKyber, akfSaber, akfNtru, akfFrodo,
        akfMcEliece}:
      check defaultAmeKemSlots() == @[akaFireSaber, akaX25519]

  # {.testKind: tkUnit.}
  test "the signature build set answers for every slot":
    check ameSigBuilt(asaEd25519) == (asfEd25519 in ameSigsBuilt)
    check ameSigBuilt(asaFalcon512) == (asfFalcon in ameSigsBuilt)
    check ameSigFamilies(asaDilithium65) == {asfDilithium}
    check ameSigFamilies(asaEd25519Falcon512Hybrid) == {asfEd25519, asfFalcon}

  # {.testKind: tkUnit.}
  test "a hybrid slot needs both of its families":
    ## A hybrid is only usable when Ed25519 AND Falcon are both compiled,
    ## which is why the build set is compared as a set, not a single family.
    check ameSigBuilt(asaEd25519Falcon1024Hybrid) ==
      ({asfEd25519, asfFalcon} <= ameSigsBuilt)

  when {asfEd25519, asfFalcon} <= ameSigsBuilt:
    # {.testKind: tkUnit.}
    test "a hybrid signs twice and both halves must verify":
      var
        kp: AmeSigKeypair = ameSigKeypair(asaEd25519Falcon512Hybrid)
        msg: ByteSeq = @[byte 1, 2, 3, 4]
        sig: ByteSeq = signAmeMessage(asaEd25519Falcon512Hybrid, msg,
          kp.secretKey)
      check verifyAmeMessage(asaEd25519Falcon512Hybrid, msg, sig, kp.publicKey)
      sig[^1] = sig[^1] xor 0xff'u8
      check not verifyAmeMessage(asaEd25519Falcon512Hybrid, msg, sig,
        kp.publicKey)

  # {.testKind: tkUnit.}
  test "an Ed25519 slot signs and verifies through both call shapes":
    var
      a: AmeSignatureAlgorithm = asaEd25519
      kp: AmeSigKeypair = ameSigKeypair(asaEd25519)
      msg: ByteSeq = @[byte 9, 8, 7]
      sig: ByteSeq = signAmeMessage(a, msg, kp.secretKey)
    check verifyAmeMessage(asaEd25519, msg, sig, kp.publicKey)

  # {.testKind: tkUnit.}
  test "the symmetric build set answers for every slot":
    check ameCipherBuilt(acaXChaCha20) == (aspChaCha20 in ameSymBuilt)
    check ameMacBuilt(amaPoly1305) == (aspPoly1305 in ameSymBuilt)
    check ameHashBuilt(ahaShake256) == (aspSha3 in ameSymBuilt)
    check ameKdfBuilt(akfaArgon2id) == (aspArgon2 in ameSymBuilt)
    check ameHashPrimitive(ahaSha3) == ameHashPrimitive(ahaShake256)

  # {.testKind: tkUnit.}
  test "BLAKE3 is always compiled because AME needs it internally":
    ## Tag normalization and Argon2's salt both go through BLAKE3, so no
    ## flag combination may remove it.
    check aspBlake3 in ameSymBuilt
    check ameHashBuilt(ahaBlake3)
    check blake3AmeHash(@[byte 1, 2, 3], 32).len == 32

  # {.testKind: tkUnit.}
  test "a stream cipher seals and opens with the same call":
    var
      key: ByteSeq = blake3AmeHash(@[byte 1], 32)
      nonce: ByteSeq = blake3AmeHash(@[byte 2], 24)
      msg: ByteSeq = @[byte 10, 20, 30, 40]
      sealed: ByteSeq = ameCipherXor(acaXChaCha20, key, nonce, msg)
    check sealed != msg
    check ameCipherXor(acaXChaCha20, key, nonce, sealed) == msg

  # {.testKind: tkUnit.}
  test "the carrier set answers for both carriers":
    check ameCarrierBuilt(acrTcp) == (acrTcp in ameCarriersBuilt)
    check ameCarrierBuilt(acrDac) == (acrDac in ameCarriersBuilt)

  when acrDac notin ameCarriersBuilt:
    # {.testKind: tkEdgeCase.}
    test "an excluded carrier is refused before the session is consulted":
      ## The gate closes on the carrier tag itself, so an empty session is
      ## enough: nothing reaches the epoch checks behind it.
      var S: AmeSession
      expect ValueError:
        discard sealAmeFrame(S, acrDac, @[byte 1, 2, 3])

  when acrTcp notin ameCarriersBuilt:
    # {.testKind: tkEdgeCase.}
    test "an excluded carrier is refused before the session is consulted":
      var S: AmeSession
      expect ValueError:
        discard sealAmeFrame(S, acrTcp, @[byte 1, 2, 3])

suite "AME runtime parameters":
  # {.testKind: tkUnit.}
  test "only the three defined tag lengths exist":
    check ord(aatl16) == 16
    check ord(aatl24) == 24
    check ord(aatl32) == 32
    check ameAuthTagLenFromId(24'u8) == aatl24
    expect ValueError:
      discard ameAuthTagLenFromId(20'u8)
    expect ValueError:
      discard ameAuthTagLenFromId(1'u8)

  # {.testKind: tkUnit.}
  test "the tag length changes the sealed frame by exactly its difference":
    ## Same payload, same layout, three tag lengths: the frame shrinks by the
    ## bytes the tag gives up and by nothing else.
    var
      lens: array[3, int]
      i: int = 0
    for n in [aatl16, aatl24, aatl32]:
      var
        S: AmeSession = tagLenSession(n)
        frame: ByteSeq = sealAmeTcpFrame(S, @[byte 1, 2, 3, 4])
      lens[i] = frame.len
      i = i + 1
    check lens[1] - lens[0] == 8
    check lens[2] - lens[1] == 8

  # {.testKind: tkUnit.}
  test "a frame seals and opens under a shortened tag":
    var
      sender: AmeSession = tagLenSession(aatl16)
      receiver: AmeSession = tagLenSession(aatl16, aerResponder)
      payload: ByteSeq = @[byte 7, 7, 7]
      frame: ByteSeq = sealAmeTcpFrame(sender, payload)
      opened: AmeOpenResult = openAmeTcpFrame(receiver, frame)
    check opened.ok
    check opened.packet.payload == payload

  # {.testKind: tkEdgeCase.}
  test "a peer using a different tag length fails to authenticate":
    ## The length is inside the authenticated input, so a mismatch is not a
    ## parse error that could be papered over: it simply does not verify.
    var
      sender: AmeSession = tagLenSession(aatl16)
      receiver: AmeSession = tagLenSession(aatl32, aerResponder)
      frame: ByteSeq = sealAmeTcpFrame(sender, @[byte 1])
      opened: AmeOpenResult = openAmeTcpFrame(receiver, frame)
    check not opened.ok

  # {.testKind: tkEdgeCase.}
  test "a truncated frame is refused whatever length was agreed":
    var
      sender: AmeSession = tagLenSession(aatl32)
      receiver: AmeSession = tagLenSession(aatl32, aerResponder)
      frame: ByteSeq = sealAmeTcpFrame(sender, @[byte 1, 2])
      short: ByteSeq = frame
    ## The frame carries no length field any more, so a byte lopped off the
    ## end is not a parse error -- it is simply one byte less ciphertext, and
    ## what refuses it is the tag. That is the better of the two failures:
    ## the check that rejects it is the authenticated one.
    short.setLen(short.len - 1)
    check not openAmeTcpFrame(receiver, short).ok
    ## Cut past the tag and there is nothing left to authenticate, so the
    ## decoder stops before any key work happens.
    short.setLen(fomkeHeaderLen)
    expect ValueError:
      discard openAmeTcpFrame(receiver, short)
    ## The whole frame still opens, so the truncations were what failed.
    check openAmeTcpFrame(receiver, frame).ok

  # {.testKind: tkUnit.}
  test "setting a tag length stages it instead of breaking the live epoch":
    var S: AmeSession = tagLenSession(aatl32)
    check ameParams(S).authTagLen == aatl32
    setAmeAuthTagLen(S, aatl16)
    check ameParams(S).authTagLen == aatl32
    check nextAmeParams(S).authTagLen == aatl16
    var other: AmeSession = tagLenSession(aatl32)
    check sealAmeTcpFrame(S, @[byte 1]).len ==
      sealAmeTcpFrame(other, @[byte 1]).len
