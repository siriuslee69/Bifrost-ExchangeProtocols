## -------------------------------------------------------------------------
## Downgrade <- can a man in the middle make two honest ends accept LESS?
## -------------------------------------------------------------------------
##
## A downgrade attack does not break the cipher. It edits the conversation so
## that both ends settle on something weaker than they would have chosen: an
## older suite, a shorter tag, no padding, a lower tier, no authentication.
##
## The handshake says it cannot happen, because every field is part of one
## record that both sides sign and derive their keys from (handshake_transcript).
## Here that claim is tested the hard way. For each of the four trust modes:
##
##   honest run:   hello ──▶ answer ──▶ finish ──▶ accept        (4 records)
##
##   for every byte of every record, and for every mask in `masks`:
##       change that byte, hand the changed record to the next step, and ask:
##
##        refused      one side said no                        the good answer
##        same result  both ends accepted and hold the same    the byte was NOT in
##                     suite, tier, parameters and keys        the record: a finding
##        DOWNGRADED   both accepted, but suite, tier or       the thing this file
##                     parameters differ from the honest run   exists to rule out
##        split        both accepted but the keys differ       (first frame fails)
##        CRASH        a Defect escaped the decoder            a finding
##
## The test fails on DOWNGRADED or CRASH. "same result" positions are listed:
## a byte nobody checks is a byte an attacker may use as a signal or a carrier.

import std/[unittest, strutils, monotimes, times]

import ../../src/protocols/types
import ../../src/protocols/config
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/path_triggers
import ../../src/protocols/ame/level3/handshake
import ../../src/protocols/ame/level3/handshake_wire
import runePragmas

const
  kems: AmeKemAlgorithms = [akaX25519, akaFireSaber]
  nowUnix: int64 = 500'i64
  validFrom: int64 = 100'i64
  validUntil: int64 = 1000'i64
  stride {.intdefine: "downgradeStride".}: int = 1
    ## 1 = every byte. A larger number samples every n-th byte (quicker).
  masks: array[2, byte] = [0x01'u8, 0x80'u8]

type
  Setup = object
    label: string
    cA: AmeAuthentication
    sA: AmeAuthentication
    cDesc: AmeIdentityCertificate
    sDesc: AmeIdentityCertificate
    cKey: AmeIdentityKey
    sKey: AmeIdentityKey

  Honest = object
    layout: AmeSuiteLayout
    tier: AmeMaskTier
    client: AmeClientHandshake
    answered: tuple[ok: bool, state: AmeServerHandshake, err: string]
    clientDone: AmeHandshakeResult
    rec: array[3, ByteSeq]   ## the wire bytes of records 1, 2, 3

  Fate = enum
    fRefused, fSame, fDowngraded, fSplit, fCrash

  Tally = object
    counts: array[Fate, int]
    same: seq[string]        ## where an edit changed nothing
    bad: seq[string]         ## downgraded or crashed

proc layoutOf(): AmeSuiteLayout {.role: configurator.} =
  result = defaultAmeLayout(kems)

proc tierOf(L: AmeSuiteLayout): AmeMaskTier {.role: configurator.} =
  result = initAmeMaskTier(L, 1'u32, initAmeTierMasks(0b11000000'u8,
    occupiedAmeMask(L.ciphers.length), occupiedAmeMask(L.macs.length),
    occupiedAmeMask(L.hashes.length), occupiedAmeMask(L.signatures.length),
    occupiedAmeMask(L.kdfs.length)))

proc secretOf(): ByteSeq {.role: helper.} =
  var
    i: int = 0
  result = newSeq[byte](32)
  while i < result.len:
    result[i] = byte(i + 9)
    i = i + 1

proc setupAm1a(): Setup {.role: configurator.} =
  var
    authority: AmeAuthorityKey = initAmeAuthorityKey("dg-root")
    root: AmeAuthorityRoot = initAmeAuthorityRoot(authority)
  result.label = "AM1A"
  result.cKey = initAmeIdentityKey("dg-client")
  result.sKey = initAmeIdentityKey("dg-server")
  result.cDesc = issueAmeIdentityCertificate(authority, result.cKey, 11'u64,
    validFrom, validUntil)
  result.sDesc = issueAmeIdentityCertificate(authority, result.sKey, 22'u64,
    validFrom, validUntil)
  result.cA = initAmeCertificateAuthentication(root)
  result.sA = initAmeCertificateAuthentication(root)

proc setupAm1s(): Setup {.role: configurator.} =
  result.label = "AM1S"
  result.cKey = initAmeIdentityKey("dg-client")
  result.sKey = initAmeIdentityKey("dg-server")
  result.cDesc = pinnedIdentityDescriptor(result.cKey, validFrom, validUntil)
  result.sDesc = pinnedIdentityDescriptor(result.sKey, validFrom, validUntil)
  result.cA = initAmePinnedAuthentication(pinnedPeerIdentity(result.sKey))
  result.sA = initAmePinnedAuthentication(pinnedPeerIdentity(result.cKey))

proc setupAm1p(): Setup {.role: configurator.} =
  result.label = "AM1P"
  result.cA = initAmePskAuthentication("dg-psk", secretOf())
  result.sA = initAmePskAuthentication("dg-psk", secretOf())

proc setupAm1ps(): Setup {.role: configurator.} =
  result.label = "AM1P+S"
  result.cKey = initAmeIdentityKey("dg-client")
  result.sKey = initAmeIdentityKey("dg-server")
  result.cDesc = pinnedIdentityDescriptor(result.cKey, validFrom, validUntil)
  result.sDesc = pinnedIdentityDescriptor(result.sKey, validFrom, validUntil)
  result.cA = initAmePskPinnedAuthentication("dg-psk", secretOf(),
    pinnedPeerIdentity(result.sKey))
  result.sA = initAmePskPinnedAuthentication("dg-psk", secretOf(),
    pinnedPeerIdentity(result.cKey))

proc honestRun(S: Setup): Honest {.role: orchestrator.} =
  ## S: one honest handshake, kept in pieces so a record can be changed and
  ## the rest replayed from a COPY of the state that stood before it.
  var
    H: Honest = Honest()
  H.layout = layoutOf()
  H.tier = tierOf(H.layout)
  H.client = beginAmeHandshake(77'u64, H.layout, H.tier, a = S.cA)
  H.rec[0] = encodeAmeClientHello(H.client.hello)
  H.answered = answerAmeHandshake(decodeAmeClientHello(H.rec[0]),
    [initAmeTierPath(H.layout, [H.tier])], S.sA, S.sDesc, S.sKey)
  H.rec[1] = encodeAmeServerHello(H.answered.state.serverHello)
  var
    c0: AmeClientHandshake = H.client
  H.clientDone = finishAmeHandshake(c0, decodeAmeServerHello(H.layout, H.rec[1]),
    S.cA, S.cDesc, S.cKey, nowUnix)
  H.rec[2] = encodeAmeClientFinish(H.clientDone.finish)
  result = H

proc flipped(B: ByteSeq, pos: int, mask: byte): ByteSeq {.role: helper.} =
  result = B
  result[pos] = result[pos] xor mask

proc secretsOf(R: AmeHandshakeResult): ByteSeq {.role: helper.} =
  ## everything the two sides must agree on, as one byte string
  for s in R.auth.current.exchange.stackedSecrets:
    result.add(s)
  result.add(R.auth.current.transcriptSalt)

proc fateOf(H: Honest, c, s: AmeHandshakeResult): Fate {.role: truthBuilder.} =
  ## c/s: the two ends' results of a changed run, judged against the honest one.
  if not (c.ok and s.ok):
    return fRefused
  if c.auth.current.layout != H.layout or s.auth.current.layout != H.layout or
      c.auth.current.tier != H.tier or s.auth.current.tier != H.tier or
      c.auth.current.params != H.clientDone.auth.current.params or
      s.auth.current.params != H.clientDone.auth.current.params:
    return fDowngraded
  if secretsOf(c) != secretsOf(s):
    return fSplit
  result = fSame

proc runChanged(S: Setup, H: Honest, rec: int, pos: int,
    mask: byte): Fate {.role: orchestrator.} =
  ## rec/pos/mask: change one byte of record `rec` (0, 1 or 2) on the wire and
  ## replay the steps from there, on copies of the honest state.
  var
    answered: tuple[ok: bool, state: AmeServerHandshake, err: string] = H.answered
    client: AmeClientHandshake = H.client
    cDone: AmeHandshakeResult = H.clientDone
    sDone: AmeHandshakeResult = AmeHandshakeResult()
    wire: ByteSeq = flipped(H.rec[rec], pos, mask)
  result = fRefused
  try:
    if rec == 0:
      answered = answerAmeHandshake(decodeAmeClientHello(wire),
        [initAmeTierPath(H.layout, [H.tier])], S.sA, S.sDesc, S.sKey)
      if not answered.ok:
        return fRefused
    if rec <= 1:
      var
        sh: ByteSeq = encodeAmeServerHello(answered.state.serverHello)
      if rec == 1:
        sh = wire
      cDone = finishAmeHandshake(client, decodeAmeServerHello(H.layout, sh),
        S.cA, S.cDesc, S.cKey, nowUnix)
      if not cDone.ok:
        return fRefused
    var
      fin: ByteSeq = encodeAmeClientFinish(cDone.finish)
    if rec == 2:
      fin = wire
    sDone = acceptAmeHandshake(answered.state, decodeAmeClientFinish(fin), nowUnix)
    result = fateOf(H, cDone, sDone)
  except CatchableError:
    result = fRefused
  except Defect:
    result = fCrash

proc sweep(S: Setup, H: Honest, rec: int, T: var Tally) {.role: actor.} =
  ## Every byte of record `rec`, every mask.
  var
    pos: int = 0
    m: int = 0
    f: Fate = fRefused
  while pos < H.rec[rec].len:
    m = 0
    while m < masks.len:
      f = runChanged(S, H, rec, pos, masks[m])
      T.counts[f] = T.counts[f] + 1
      if f == fSame:
        T.same.add("rec" & $(rec + 1) & "@" & $pos & "^" & toHex(int(masks[m]), 2))
      if f in {fDowngraded, fCrash}:
        T.bad.add($f & " rec" & $(rec + 1) & "@" & $pos & "^" & toHex(int(masks[m]), 2))
      m = m + 1
    pos = pos + stride

proc report(S: Setup, H: Honest, T: Tally, ms: int64) {.role: dataWriter.} =
  echo "  ", S.label, "  records ", H.rec[0].len, "/", H.rec[1].len, "/",
    H.rec[2].len, " B  refused=", T.counts[fRefused], " same=", T.counts[fSame],
    " downgraded=", T.counts[fDowngraded], " split=", T.counts[fSplit],
    " crash=", T.counts[fCrash], "  (", ms, " ms)"
  if T.same.len > 0:
    echo "     edits that changed nothing (first 12): ",
      T.same[0 ..< min(12, T.same.len)].join(" ")

proc attackMode(S: Setup): Tally {.role: orchestrator.} =
  var
    H: Honest = honestRun(S)
    t0: MonoTime = getMonoTime()
  doAssert H.answered.ok and H.clientDone.ok
  sweep(S, H, 0, result)
  sweep(S, H, 1, result)
  sweep(S, H, 2, result)
  report(S, H, result, (getMonoTime() - t0).inMilliseconds)

suite "downgrade by editing the handshake":
  # {.testKind: tkFuzz, covers: "answerAmeHandshake",
  #   pins: "a man in the middle must not be able to make both ends accept less".}
  test "AM1A: no single-bit edit of any record yields a weaker accepted handshake":
    var
      T: Tally = attackMode(setupAm1a())
    check T.counts[fDowngraded] == 0
    check T.counts[fCrash] == 0
    check T.bad.len == 0

  # {.testKind: tkFuzz, covers: "answerAmeHandshake".}
  test "AM1S: no single-bit edit of any record yields a weaker accepted handshake":
    var
      T: Tally = attackMode(setupAm1s())
    check T.counts[fDowngraded] == 0
    check T.counts[fCrash] == 0
    check T.bad.len == 0

  # {.testKind: tkFuzz, covers: "answerAmeHandshake".}
  test "AM1P: no single-bit edit of any record yields a weaker accepted handshake":
    var
      T: Tally = attackMode(setupAm1p())
    check T.counts[fDowngraded] == 0
    check T.counts[fCrash] == 0
    check T.bad.len == 0

  # {.testKind: tkFuzz, covers: "answerAmeHandshake".}
  test "AM1P+S: no single-bit edit of any record yields a weaker accepted handshake":
    var
      T: Tally = attackMode(setupAm1ps())
    check T.counts[fDowngraded] == 0
    check T.counts[fCrash] == 0
    check T.bad.len == 0

proc setupNamed(n: int): Setup {.role: configurator.} =
  ## n: 0 AM1A, 1 AM1S, 2 AM1P, 3 AM1P+S
  case n
  of 0: result = setupAm1a()
  of 1: result = setupAm1s()
  of 2: result = setupAm1p()
  else: result = setupAm1ps()

proc answered(C: Setup, Sv: Setup, supportedKems: AmeKemAlgorithms): tuple[
    ok: bool, state: AmeServerHandshake, err: string] {.role: orchestrator.} =
  ## C/Sv/supportedKems: a client of setup C says hello to a server of setup Sv
  ## that only lists the layout built from `supportedKems`.
  var
    L: AmeSuiteLayout = layoutOf()
    t: AmeMaskTier = tierOf(L)
    Ls: AmeSuiteLayout = defaultAmeLayout(supportedKems)
    client: AmeClientHandshake = beginAmeHandshake(78'u64, L, t, a = C.cA)
  result = answerAmeHandshake(decodeAmeClientHello(
    encodeAmeClientHello(client.hello)),
    [initAmeTierPath(Ls, [tierOf(Ls)])], Sv.sA, Sv.sDesc, Sv.sKey)

suite "downgrade by choosing a weaker mode or layout":
  # {.testKind: tkEdgeCase, covers: "answerAmeHandshake",
  #   pins: "a responder configured for one trust mode must not accept another".}
  test "a responder only answers a hello of its OWN trust mode (all 12 mismatches refused)":
    var
      c: int = 0
      s: int = 0
      r: tuple[ok: bool, state: AmeServerHandshake, err: string] = (
        ok: false, state: default(AmeServerHandshake), err: "")
      refused: int = 0
    while c < 4:
      s = 0
      while s < 4:
        r = answered(setupNamed(c), setupNamed(s), kems)
        if c == s:
          check r.ok
        else:
          check not r.ok
          refused = refused + 1
        s = s + 1
      c = c + 1
    check refused == 12

  # {.testKind: tkEdgeCase, covers: "answerAmeHandshake".}
  test "a hello that lists an algorithm the responder does not offer is refused":
    var
      r: tuple[ok: bool, state: AmeServerHandshake, err: string] = (
        ok: false, state: default(AmeServerHandshake), err: "")
    r = answered(setupAm1a(), setupAm1a(), [akaX25519, akaMlKem768])
    check not r.ok
    check "does not offer" in r.err
    r = answered(setupAm1p(), setupAm1p(), [akaX25519, akaMlKem768])
    check not r.ok

  # {.testKind: tkEdgeCase, covers: "answerAmeHandshake",
  #   pins: "a client may ask for classical-only keys unless the responder sets a floor".}
  test "a classical-only selection is accepted at floor 0 and refused at floor 1":
    var
      L: AmeSuiteLayout = layoutOf()
      classical: AmeMaskTier = initAmeMaskTier(L, 1'u32, initAmeTierMasks(
        0b01000000'u8, occupiedAmeMask(L.ciphers.length),   ## slot 1 = X25519 (slot 0 = FireSaber)
        occupiedAmeMask(L.macs.length), occupiedAmeMask(L.hashes.length),
        occupiedAmeMask(L.signatures.length), occupiedAmeMask(L.kdfs.length)))
      S: Setup = setupAm1a()
      saved: BifrostConfig = currentBifrostConfig()
      floor1: BifrostConfig = currentBifrostConfig()
      client: AmeClientHandshake = beginAmeHandshake(79'u64, L, classical,
        a = S.cA)
      hello: AmeClientHello = decodeAmeClientHello(
        encodeAmeClientHello(client.hello))
      r: tuple[ok: bool, state: AmeServerHandshake, err: string] = (
        ok: false, state: default(AmeServerHandshake), err: "")
    floor1.ameMinPqKems = 1
    r = answerAmeHandshake(hello, [initAmeTierPath(L, [tierOf(L)])], S.sA,
      S.sDesc, S.sKey)
    ## the shipped default: no floor, so the classical-only hello is answered
    check saved.ameMinPqKems == 0
    check r.ok
    applyBifrostConfig(floor1)
    r = answerAmeHandshake(hello, [initAmeTierPath(L, [tierOf(L)])], S.sA,
      S.sDesc, S.sKey)
    applyBifrostConfig(saved)
    check not r.ok
    check "post-quantum" in r.err
