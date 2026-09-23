## -------------------------------------------------------------------------
## AME Handshake Flag Tests <- what -d:bifrostHandshakes keeps and refuses
## -------------------------------------------------------------------------
##
## Compiled once per mode list by `nimble testHandshakeFlags`. Every build
## checks the same four things:
##
##   1  every mode it carries completes a whole handshake
##   2  a left-out mode's constructor does not compile
##   3  a left-out mode byte from the wire is refused while decoding
##   4  a left-out mode in a default-built value is refused at the start
##
## AM1A needs an authority, AM1S and AM1P+S a pinned key, AM1P only a secret.
## One small proc per mode builds both ends' material, so no test body has
## to branch on the mode.

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/path_triggers
import ../../src/protocols/ame/level3/handshake
import ../../src/protocols/ame/level3/handshake_wire
import runePragmas

const
  nowUnix: int64 = 500'i64
  validFrom: int64 = 100'i64
  validUntil: int64 = 1000'i64
  flagKems: AmeKemAlgorithms = [akaX25519]

type
  Ends = object
    ## Both ends' authentication and identity material for one mode.
    c: AmeAuthentication
    s: AmeAuthentication
    cDesc: AmeIdentityCertificate
    sDesc: AmeIdentityCertificate
    cKey: AmeIdentityKey
    sKey: AmeIdentityKey

proc flagSecret(): ByteSeq {.role: helper.} =
  ## A fixed 32-byte provisioned secret.
  var
    i: int = 0
  result = newSeq[byte](32)
  while i < result.len:
    result[i] = byte(i + 1)
    i = i + 1

proc pinnedEnds(L: AmeSuiteLayout): Ends {.role: configurator.} =
  ## L: two identities that pin each other (the AM1S / AM1P+S material).
  result.cKey = initAmeIdentityKey("flag-client", L.signatures)
  result.sKey = initAmeIdentityKey("flag-server", L.signatures)
  result.cDesc = pinnedIdentityDescriptor(result.cKey, validFrom, validUntil)
  result.sDesc = pinnedIdentityDescriptor(result.sKey, validFrom, validUntil)

proc endsFor(m: AmeTrustMode, L: AmeSuiteLayout): Ends {.role: configurator.} =
  ## m/L: both ends for mode m. Only called for modes this build carries;
  ## each branch names its constructor only when that mode is compiled.
  var
    authority: AmeAuthorityKey = default(AmeAuthorityKey)
  case m
  of atmAuthorityCertificate:
    when atmAuthorityCertificate in ameModesBuilt:
      result = pinnedEnds(L)
      authority = initAmeAuthorityKey("flag-root", L.signatures)
      result.cDesc = issueAmeIdentityCertificate(authority, result.cKey, 1'u64,
        validFrom, validUntil)
      result.sDesc = issueAmeIdentityCertificate(authority, result.sKey, 2'u64,
        validFrom, validUntil)
      result.c = initAmeCertificateAuthentication(initAmeAuthorityRoot(authority))
      result.s = result.c
  of atmPinnedPeerKey:
    when atmPinnedPeerKey in ameModesBuilt:
      result = pinnedEnds(L)
      result.c = initAmePinnedAuthentication(pinnedPeerIdentity(result.sKey))
      result.s = initAmePinnedAuthentication(pinnedPeerIdentity(result.cKey))
  of atmPreSharedKey:
    when atmPreSharedKey in ameModesBuilt:
      result.c = initAmePskAuthentication("flag", flagSecret())
      result.s = result.c
  of atmPreSharedPinned:
    when atmPreSharedPinned in ameModesBuilt:
      result = pinnedEnds(L)
      result.c = initAmePskPinnedAuthentication("flag", flagSecret(),
        pinnedPeerIdentity(result.sKey))
      result.s = initAmePskPinnedAuthentication("flag", flagSecret(),
        pinnedPeerIdentity(result.cKey))

proc roundTrip(m: AmeTrustMode): string {.role: orchestrator.} =
  ## m: one whole handshake in mode m, through the wire codecs. "" = ok.
  var
    L: AmeSuiteLayout = defaultAmeLayout(flagKems)
    t: AmeMaskTier = fullAmeMaskTier(L)
    e: Ends = endsFor(m, L)
    client: AmeClientHandshake = beginAmeHandshake(21'u64, L, t, a = e.c)
    answered: tuple[ok: bool, state: AmeServerHandshake, err: string] = (
      ok: false, state: default(AmeServerHandshake), err: "")
    done: AmeHandshakeResult = default(AmeHandshakeResult)
  answered = answerAmeHandshake(decodeAmeClientHello(encodeAmeClientHello(
    client.hello)), [initAmeTierPath(L, [t])], e.s, e.sDesc, e.sKey)
  if not answered.ok:
    return answered.err
  done = finishAmeHandshake(client, decodeAmeServerHello(L,
    encodeAmeServerHello(answered.state.serverHello)), e.c, e.cDesc, e.cKey,
    nowUnix)
  if not done.ok:
    return done.err
  result = acceptAmeHandshake(answered.state, decodeAmeClientFinish(
    encodeAmeClientFinish(done.finish)), nowUnix).err

proc someBuiltMode(): AmeTrustMode {.role: configurator.} =
  ## The first mode this build carries, to make a hello that encodes. The
  ## flag refuses an empty list, so the walk always finds one.
  var
    m: AmeTrustMode = high(AmeTrustMode)
  while m notin ameModesBuilt:
    m = pred(m)
  result = m

suite "AME handshake flags":
  # {.testKind: tkIntegration, covers: "beginAmeHandshake".}
  test "every mode this build carries completes a handshake":
    for m in AmeTrustMode:
      if m in ameModesBuilt:
        checkpoint($m)
        check roundTrip(m) == ""

  # {.testKind: tkEdgeCase, covers: "initAmePskAuthentication".}
  test "a left-out mode's constructor does not compile":
    check compiles(initAmePskAuthentication("x", flagSecret())) ==
      (atmPreSharedKey in ameModesBuilt)
    check compiles(initAmePinnedAuthentication(
      default(AmePinnedPeerIdentity))) == (atmPinnedPeerKey in ameModesBuilt)
    check compiles(initAmeCertificateAuthentication(
      default(AmeAuthorityRoot))) == (atmAuthorityCertificate in ameModesBuilt)
    check compiles(initAmePskPinnedAuthentication("x", flagSecret(),
      default(AmePinnedPeerIdentity))) == (atmPreSharedPinned in ameModesBuilt)

  # {.testKind: tkEdgeCase, covers: "decodeAmeClientHello".}
  test "a left-out mode byte from the wire is refused":
    var
      L: AmeSuiteLayout = defaultAmeLayout(flagKems)
      e: Ends = endsFor(someBuiltMode(), L)
      wire: ByteSeq = encodeAmeClientHello(beginAmeHandshake(22'u64, L,
        fullAmeMaskTier(L), a = e.c).hello)
    ## Byte 12 is the mode (magic 4 + version 0 + session id 8; see
    ## handshake_wire.nim). Rewrite it to every mode in turn.
    for m in AmeTrustMode:
      wire[12] = uint8(ord(m))
      if m notin ameModesBuilt:
        checkpoint($m)
        expect ValueError:
          discard decodeAmeClientHello(wire)

  # {.testKind: tkEdgeCase, covers: "ameModeBuiltError".}
  test "a default value naming a left-out mode is refused at the start":
    var
      L: AmeSuiteLayout = defaultAmeLayout(flagKems)
    check ameModeBuiltError(someBuiltMode()) == ""
    if atmAuthorityCertificate notin ameModesBuilt:
      expect ValueError:
        discard beginAmeHandshake(23'u64, L, fullAmeMaskTier(L))
