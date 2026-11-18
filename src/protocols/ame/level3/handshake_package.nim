## Handshake packages <- large AME records carried by native DAC shards.
## AME(kind=0x13, session, step) | DAC kind u8 | existing DAC message body.
## Shards are untrusted until the reconstructed handshake authenticates them.
import std/[tables, times, os, strutils]
import runePragmas
import ../../types
import ../../relay/restriction_address
import ../types
import ../level2/wire
import ./handshake_transport
import ../../dac/types
import ../../dac/level0/[transport, defaults, wire_helpers]
import ../../dac/level2/package_transfer
import ../../dac/level3/link

const
  ameHandshakePackageMaxBytes* = 524288'u32
  ameHandshakePackageSlots* = 128
    ## half-received handshake messages held at once, all senders together
  ameHandshakePackagePerSource* = 3
    ## ... and by ONE sender: an IPv4 address, or an IPv6 /64 (see sourceGroup)
  ameHandshakePackageLifetime* = 20.0

type
  HandshakePackage {.role: truthState, expectedCount: [0, 128],
      lifeCycle: 20000.} = ref object
    link: DacLink
    touched: float
    born: float
    group: string

  AmeHandshakePackages* {.role: truthState.} = object
    entries: Table[string, HandshakePackage]

  AmeHandshakeFeed* {.role: preparedData.} = object
    ok*: bool
    done*: bool
    payload*: ByteSeq
    err*: string

proc handshakePackageLimits(): DacPackageLimits {.role: configurator.} =
  ## Bound unauthenticated allocations independently of application packages.
  result = defaultDacPackageLimits()
  result.maxPackageBytes = ameHandshakePackageMaxBytes
  result.maxChunks = 512

proc ameHandshakeDatagrams*(A: openArray[uint8]): seq[ByteSeq] {.
    role: orchestrator, tag: "appApi".} =
  ## A: complete AME handshake; output is MTU-sized AME/DAC, with XOR repair.
  var
    f = decodeAmeHandshakeFrame(A)
    d = dacDefaultsFor(dscCleanLan)
    sender: DacLink = default(DacLink)
    messages: seq[DacTaggedMessage] = @[]
    body: ByteSeq = @[]
    id: uint64 = f.sessionId xor ((uint64(f.step) + 1) shl 56)
  if A.len <= 1200:
    return @[@A]
  if id == 0: id = 1
  sender = initDacLink(d, id, limits = handshakePackageLimits())
  messages = beginDacPackage(sender, id, A, 0)
  for msg in messages:
    body = @[uint8(ord(msg.kind))]
    body.add msg.body
    result.add encodeAmeFrame(ampkHandshakePackage, amcControl, 0,
      f.sessionId, 0, 0, f.step, body)

proc sendAmeHandshakeDac*(sock: DacSocket, remote: DacAddress,
    A: openArray[uint8]) {.role: dataWriter, tag: "appApi".} =
  ## sock/remote/A: send every native DAC shard; no alternate carrier is used.
  var
    frames = ameHandshakeDatagrams(A)
  for frame in frames:
    sendDacFrameBytes(sock, remote, frame)
    if frames.len > 1: sleep(1)

proc expireHandshakePackages(S: var AmeHandshakePackages, now: float) {.
    role: actor.} =
  ## S/now: reclaim incomplete, unauthenticated packages within 20 seconds.
  var
    stale: seq[string] = @[]
  for key, entry in S.entries:
    if now - entry.touched > ameHandshakePackageLifetime: stale.add key
  for key in stale: S.entries.del(key)

proc sourceGroup(source: string): string {.role: sanitizer, tag: "appApi".} =
  ## source: where a datagram came from, as "dac://1.2.3.4:5678", "1.2.3.4:5678",
  ## "[2001:db8::1]:5678" or a bare host. Gives the text that stands for ONE
  ## sender: the port is dropped (one machine has 60 000 of them) and an IPv6
  ## address counts as its /64 (one customer owns 2^64 of them).
  var
    h: string = source
    shut: int = 0
  if h.startsWith("dac://"):
    h = h[6 .. ^1]
  if h.startsWith("["):
    shut = h.find(']')
    if shut > 0:
      h = h[1 ..< shut]
  elif h.count(':') == 1:
    h = h[0 ..< h.find(':')]
  result = hostGroupKey(h)

proc ameHandshakePackageCount*(S: AmeHandshakePackages): int {.role: parser,
    tag: "appApi".} =
  ## S: how many half-received handshake messages are held now.
  result = S.entries.len

proc groupCounts(S: AmeHandshakePackages): Table[string, int] {.role: parser.} =
  ## S: how many packages each sender group holds.
  for e in S.entries.values:
    result[e.group] = result.getOrDefault(e.group, 0) + 1

proc oldestKeyOf(S: AmeHandshakePackages, group: string): string {.role: parser.} =
  ## S/group: the key of the OLDEST package this group holds ("" when none).
  var
    best: float = 0.0
  for key, e in S.entries:
    if e.group == group and (result.len == 0 or e.born < best):
      result = key
      best = e.born

proc biggestGroup(C: Table[string, int]): string {.role: parser.} =
  ## C: the group that holds the most packages (the first one met on a tie).
  var
    most: int = 0
  for g, n in C:
    if n > most:
      most = n
      result = g

proc makeRoom(S: var AmeHandshakePackages, group: string) {.role: actor.} =
  ## S/group: room for ONE new package of this sender group. Never refuses.
  ##
  ##   the group already holds its share   its OWN oldest package goes
  ##   the table is full                   the oldest package of whoever holds
  ##                                       the most goes (the flooder, not the
  ##                                       honest client with one)
  ##
  ## Refusing instead would let 16 datagrams every 20 seconds, sent by anyone
  ## (a spoofed address will do), keep every new client out of the server.
  var
    counts: Table[string, int] = groupCounts(S)
    victim: string = ""
  if counts.getOrDefault(group, 0) >= ameHandshakePackagePerSource:
    victim = oldestKeyOf(S, group)
  elif S.entries.len >= ameHandshakePackageSlots:
    victim = oldestKeyOf(S, biggestGroup(counts))
  if victim.len > 0:
    S.entries.del(victim)

proc feedAmeHandshakeDatagram*(S: var AmeHandshakePackages,
    A: openArray[uint8], source: string): AmeHandshakeFeed {.
    role: orchestrator, tag: "appApi".} =
  ## S/A/source: reassemble per address, session AND step; bound every package.
  var
    f: AmeDecodedFrame = default(AmeDecodedFrame)
    original: AmeHandshakeFrame = default(AmeHandshakeFrame)
    kind: DacMessageKind = dmkUnknown
    key: string = ""
    entry: HandshakePackage = nil
    step: DacLinkStep = default(DacLinkStep)
    now: float = epochTime()
  try:
    f = decodeAmeFrame(A)
    if f.header.packetKind != ampkHandshakePackage:
      return AmeHandshakeFeed(ok: true, done: true, payload: @A)
    if f.header.flags != 0 or f.header.messageClass != amcControl or
        f.header.sessionId == 0 or f.header.rootLaneId != 0 or
        f.header.laneId != 0 or f.header.sequence > ameHandshakeStepFinish or
        f.payload.len < 2 or A.len > 1280:
      return AmeHandshakeFeed(err: "invalid AME handshake shard")
    kind = dacMessageKindFromId(f.payload[0])
    if kind notin {dmkPackageManifest, dmkPackageChunk, dmkParityShard}:
      return AmeHandshakeFeed(err: "unexpected DAC handshake message")
    S.expireHandshakePackages(now)
    key = source & "/" & $f.header.sessionId & "/" & $f.header.sequence
    if not S.entries.hasKey(key) and kind != dmkPackageManifest:
      return AmeHandshakeFeed(ok: true)
    if not S.entries.hasKey(key):
      S.makeRoom(sourceGroup(source))
      entry = HandshakePackage(link: initDacLink(dacDefaultsFor(dscCleanLan),
        f.header.sessionId, limits = handshakePackageLimits()), touched: now,
        born: now, group: sourceGroup(source))
      S.entries[key] = entry
    entry = S.entries[key]
    step = feedDacMessage(entry.link, kind, f.payload[1 .. ^1], 0)
    entry.touched = now
    if step.kind == dlkPackageFailed or step.err.len > 0:
      S.entries.del(key)
      return AmeHandshakeFeed(err: "DAC handshake package rejected: " & step.err)
    if step.kind != dlkPackageComplete:
      return AmeHandshakeFeed(ok: true)
    S.entries.del(key)
    original = decodeAmeHandshakeFrame(step.payload)
    if original.sessionId != f.header.sessionId or original.step != f.header.sequence:
      return AmeHandshakeFeed(err: "AME handshake package binding changed")
    result = AmeHandshakeFeed(ok: true, done: true, payload: step.payload)
  except CatchableError as exc:
    if key.len > 0: S.entries.del(key)
    result = AmeHandshakeFeed(err: exc.msg)

proc recvAmeHandshakeDac*(sock: DacSocket, remote: DacAddress,
    timeoutMs: int): DacFrameBytesResult {.role: dataFetcher, tag: "appApi".} =
  ## sock/remote/timeoutMs: one complete handshake from exactly the pinned endpoint.
  var
    inbox: AmeHandshakePackages = default(AmeHandshakePackages)
    got: DacFrameBytesResult = default(DacFrameBytesResult)
    fed: AmeHandshakeFeed = default(AmeHandshakeFeed)
    deadline: float = epochTime() + float(timeoutMs) / 1000.0
    remaining: int = 0
    frames: int = 0
  while frames < 2048:
    remaining = int((deadline - epochTime()) * 1000)
    if remaining <= 0:
      return DacFrameBytesResult(err: "AME handshake deadline expired")
    got = recvDacFrameBytes(sock, 65507, remaining)
    if not got.ok: return got
    frames = frames + 1
    if formatDacAddress(got.remote) != formatDacAddress(remote): continue
    fed = inbox.feedAmeHandshakeDatagram(got.payload, formatDacAddress(remote))
    if not fed.ok: return DacFrameBytesResult(err: fed.err)
    if fed.done: return DacFrameBytesResult(ok: true, remote: got.remote, payload: fed.payload)
  result = DacFrameBytesResult(err: "too many AME handshake datagrams")
