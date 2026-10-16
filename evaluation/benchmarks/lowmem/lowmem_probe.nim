## -------------------------------------------------------------------------
## Low-Memory Probe <- one whole AME session in the smallest shape we can
## -------------------------------------------------------------------------
##
## This program is not a test of correctness. It is a yardstick: it runs
## exactly what a tiny device has to run, and nothing else, so the size of
## the finished program and the most memory it ever held can be read off.
##
##   step                                what it costs
##   ─────────────────────────────────   ─────────────────────────────────
##   1  build the layout (which KEMs…)   a few hundred bytes
##   2  client hello  (AM1P: sealed)     one KEM keypair per KEM slot
##   3  server answers                   one KEM seal per KEM slot
##   4  client finishes, server accepts  (AM1P+S: plus one signature each)
##   5  seal one frame, open it          one frame buffer
##
## Which mode runs is chosen while compiling, exactly like the library:
##
##   -d:lowmemMode=psk       AM1P    shared secret only
##   -d:lowmemMode=pskSig    AM1P+S  shared secret AND pinned signature key
##   -d:lowmemMode=sig       AM1S    signatures only (pinned identities)
##
## The KEM slots are whatever this build carries, lightest first:
##
##   LightSaber if Saber is in -d:bifrostKems (else ML-KEM-768 if ML-KEM is),
##   then X25519 if it is there.
##
## At the end it prints one line the benchmark runner reads:
##
##   LOWMEM ok=1 heap=41234 stack=9120 frame=79
##
## heap and stack are exact only with -d:lowmemMeter (the runner sets it):
## that links `memory_meter.c`, which counts every malloc'd byte and paints
## the stack. Without it both print 0.

import ../../../src/protocols/types
import ../../../src/protocols/ame/types
import ../../../src/protocols/ame/level1/algorithms
import ../../../src/protocols/ame/level1/exchange_paths
import ../../../src/protocols/ame/level1/suites
import ../../../src/protocols/ame/level1/path_triggers
import ../../../src/protocols/ame/level2/session
import ../../../src/protocols/ame/level2/framing
import ../../../src/protocols/ame/level3/handshake
import runePragmas

const
  lowmemMode* {.strdefine.}: string = "psk"
    ## psk | pskSig | sig -- which AM1 handshake this probe runs.
  nowUnix: int64 = 500'i64
  validFrom: int64 = 100'i64
  validUntil: int64 = 1000'i64
  sessionId: uint64 = 7'u64

when defined(lowmemMeter):
  {.compile: "memory_meter.c".}
  {.passL: "-Wl,--wrap=malloc,--wrap=free,--wrap=calloc,--wrap=realloc".}
  proc meterHeapPeak(): csize_t {.role: dataFetcher, importc, cdecl.}
  proc meterStackPaint() {.role: dataWriter, importc, cdecl.}
  proc meterStackUsed(): csize_t {.role: dataFetcher, importc, cdecl.}
else:
  proc meterHeapPeak(): csize_t {.role: helper.} = 0
  proc meterStackPaint() {.role: helper.} = discard
  proc meterStackUsed(): csize_t {.role: helper.} = 0

proc probeKems(): seq[AmeKemAlgorithm] {.role: configurator.} =
  ## The lightest KEM slots this build carries: LightSaber (or ML-KEM-768 when
  ## Saber is left out), then X25519.
  when akfSaber in ameKemsBuilt:
    result.add(akaLightSaber)
  elif akfMlKem in ameKemsBuilt:
    result.add(akaMlKem768)
  when akfX25519 in ameKemsBuilt:
    result.add(akaX25519)

proc probeSecret(): ByteSeq {.role: helper.} =
  ## A fixed 32-byte provisioned secret; the value does not matter here.
  var
    i: int = 0
  result = newSeq[byte](32)
  while i < result.len:
    result[i] = byte(i * 7 + 3)
    i = i + 1

proc probeTier(L: AmeSuiteLayout): AmeMaskTier {.role: configurator.} =
  ## L: every slot of the layout switched on.
  result = fullAmeMaskTier(L)

proc probeAuth(own, peer: AmeIdentityKey): AmeAuthentication {.
    role: configurator.} =
  ## own/peer: the two identities; unused by the plain AM1P mode.
  when lowmemMode == "psk":
    result = initAmePskAuthentication("probe", probeSecret())
  elif lowmemMode == "pskSig":
    result = initAmePskPinnedAuthentication("probe", probeSecret(),
      pinnedPeerIdentity(peer))
  elif lowmemMode == "sig":
    result = initAmePinnedAuthentication(pinnedPeerIdentity(peer))
  else:
    {.error: "lowmemMode must be psk, pskSig or sig".}

proc runProbe(): tuple[ok: bool, frame: int] {.role: orchestrator.} =
  ## One handshake, then one frame each way.
  var
    L: AmeSuiteLayout = defaultAmeLayout(initAmeKemAlgorithms(probeKems()))
    t: AmeMaskTier = probeTier(L)
    cKey: AmeIdentityKey = default(AmeIdentityKey)
    sKey: AmeIdentityKey = default(AmeIdentityKey)
    cDesc: AmeIdentityCertificate = default(AmeIdentityCertificate)
    sDesc: AmeIdentityCertificate = default(AmeIdentityCertificate)
    cAuth: AmeAuthentication = default(AmeAuthentication)
    sAuth: AmeAuthentication = default(AmeAuthentication)
    client: AmeClientHandshake = default(AmeClientHandshake)
    answered: tuple[ok: bool, state: AmeServerHandshake, err: string] = (
      ok: false, state: default(AmeServerHandshake), err: "")
    cDone: AmeHandshakeResult = default(AmeHandshakeResult)
    sDone: AmeHandshakeResult = default(AmeHandshakeResult)
    path: AmeTierPath = initAmeTierPath(L, [t])
    a: AmeSession = default(AmeSession)
    b: AmeSession = default(AmeSession)
    frame: ByteSeq = @[]
    opened: AmeOpenResult = default(AmeOpenResult)
  when lowmemMode != "psk":
    cKey = initAmeIdentityKey("probe-client", L.signatures)
    sKey = initAmeIdentityKey("probe-server", L.signatures)
    cDesc = pinnedIdentityDescriptor(cKey, validFrom, validUntil)
    sDesc = pinnedIdentityDescriptor(sKey, validFrom, validUntil)
  cAuth = probeAuth(cKey, sKey)
  sAuth = probeAuth(sKey, cKey)
  client = beginAmeHandshake(sessionId, L, t, a = cAuth)
  answered = answerAmeHandshake(client.hello, [path], sAuth, sDesc, sKey)
  if not answered.ok:
    echo "LOWMEM answer failed: ", answered.err
    return
  cDone = finishAmeHandshake(client, answered.state.serverHello, cAuth,
    cDesc, cKey, nowUnix)
  if not cDone.ok:
    echo "LOWMEM finish failed: ", cDone.err
    return
  sDone = acceptAmeHandshake(answered.state, cDone.finish, nowUnix)
  if not sDone.ok:
    echo "LOWMEM accept failed: ", sDone.err
    return
  a = initAmeSession(cDone.auth, path, sessionId, peerTrust = cDone.peerTrust)
  b = initAmeSession(sDone.auth, path, sessionId, peerTrust = sDone.peerTrust)
  frame = sealAmeDacFrame(a, [byte 1, 2, 3, 4, 5, 6, 7, 8])
  opened = openAmeDacFrame(b, frame)
  result.ok = opened.ok
  result.frame = frame.len

proc main() {.role: metaOrchestrator.} =
  ## Paint, run, read: the probe runs in the frame the paint just left.
  var
    r: tuple[ok: bool, frame: int] = (ok: false, frame: 0)
    stack: csize_t = 0
  meterStackPaint()
  r = runProbe()
  stack = meterStackUsed()
  echo "LOWMEM ok=", ord(r.ok), " heap=", meterHeapPeak(), " stack=", stack,
    " frame=", r.frame
  if not r.ok:
    quit(1)

when isMainModule:
  main()
