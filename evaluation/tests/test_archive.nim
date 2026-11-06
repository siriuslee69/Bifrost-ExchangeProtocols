## -------------------------------------------------------------------------
## Archive Tests <- password to master key, sealed records, log records
## -------------------------------------------------------------------------
##
##   what is checked                                   suite
##   ------------------------------------------------  ---------------------
##   byte layouts: sizes, round trips, positions       "archive layouts"
##   password -> keys; refused settings                "archive keys"
##   sealed records: label, place, key, bytes bound    "archive sealed records"
##   master key and space entries of an account        "archive account"
##   log records: two members, wrong space, reuse      "archive log"
##   a new device from nothing but the password        "archive new device"
##
## Argon2id runs with the built-in minimum (64 MiB, 3 passes): the slowest
## part of this file, about a second per derivation.

import std/unittest

import ../../src/protocols/types
import ../../src/protocols/ame/types
import ../../src/protocols/ame/level1/exchange_paths
import ../../src/protocols/ame/level1/secret_stack
import ../../src/protocols/ame/level1/suites
import ../../src/protocols/ame/level1/tier_aead
import ../../src/protocols/ame/level2/seal_open
import ../../src/protocols/archive
import runePragmas

const
  aKems: AmeKemAlgorithms = [akaX25519, akaFireSaber]
  testMemoryKiB: uint32 = archiveMinMemoryKiB

proc aAuth(role: AmeEndpointRole, seed: byte): AmeAuthPackage =
  var
    layout: AmeSuiteLayout = defaultAmeLayout(aKems)
    tier: AmeMaskTier = initAmeMaskTier(layout, 1'u32, initAmeTierMasks(
      0b11000000'u8, occupiedAmeMask(layout.ciphers.length),
      occupiedAmeMask(layout.macs.length), occupiedAmeMask(layout.hashes.length),
      occupiedAmeMask(layout.signatures.length),
      occupiedAmeMask(layout.kdfs.length)))
    state: AmeExchangeState = initAmeExchangeState(aKems)
  applyAmeExchange(state, layout, initAmeExchangeRequest(aKems, tier,
    0b11000000'u8), [@[seed, 2'u8, 3'u8, 4'u8], @[seed, 6'u8, 7'u8, 8'u8]])
  result = initAmeAuthPackage(layout, tier, state, endpointRole = role)

proc pw(s: string): ByteSeq =
  result = toBytesArchive(s)

proc testSettings(): ArchivePasswordSettings =
  result = newArchivePasswordSettings(testMemoryKiB)

suite "archive layouts":
  # {.testKind: tkUnit, covers: "encodeArchiveSettings|decodeArchiveSettings".}
  test "settings are 42 bytes and read back":
    var
      S: ArchivePasswordSettings = testSettings()
      A: ByteSeq = encodeArchiveSettings(S)
      back: ArchivePasswordSettings = decodeArchiveSettings(A)
    check A.len == archiveSettingsBytes
    check back.memoryKiB == S.memoryKiB
    check back.passes == S.passes
    check back.parallelism == S.parallelism
    check back.userSalt == S.userSalt

  # {.testKind: tkUnit, covers: "encodeArchivePosition".}
  test "position bytes match Example 1 of records.nim":
    var
      P: ArchivePosition = ArchivePosition(gen: 1'u16, lane: 0xA1B2C3D4'u32,
        epoch: 2'u32, index: 255'u16)
    check encodeArchivePosition(P) == @[byte 0xD4, 0xC3, 0xB2, 0xA1, 0x01,
      0x00, 0x02, 0x00, 0x00, 0x00, 0xFF, 0x00]
    check decodeArchivePosition(encodeArchivePosition(P)) == P

  # {.testKind: tkEdgeCase, covers: "nextArchivePosition".}
  test "the last index of an epoch is followed by index 0 of the next":
    var
      P: ArchivePosition = ArchivePosition(gen: 1'u16, lane: 7'u32,
        epoch: 4'u32, index: 254'u16)
    P = nextArchivePosition(P, 256'u16)
    check P.epoch == 4'u32 and P.index == 255'u16
    P = nextArchivePosition(P, 256'u16)
    check P.epoch == 5'u32 and P.index == 0'u16

  # {.testKind: tkRegression, covers: "archiveRecordLayout".}
  test "the record suite is the pinned one, whatever the build defaults":
    var
      L: AmeSuiteLayout = archiveRecordLayout()
    check L.ciphers.length == 3'u8
    check L.macs.length == 2'u8
    check ameTierKeyMaterialLen(L, fullAmeMaskTier(L)) > 5 * 32

suite "archive keys":
  # {.testKind: tkUnit, covers: "deriveArchiveLogin".}
  test "the same password gives the same keys; auth and wrap differ":
    var
      S: ArchivePasswordSettings = testSettings()
      a: ArchiveLoginKeys = deriveArchiveLogin(pw("Fluss-Ampel-Kiesel"), "alice", S)
      b: ArchiveLoginKeys = deriveArchiveLogin(pw("Fluss-Ampel-Kiesel"), "alice", S)
      other: ArchiveLoginKeys = deriveArchiveLogin(pw("Fluss-Ampel-Kiesel"), "bob", S)
    check a.authKey.len == 32 and a.wrapKey.len == 32
    check a.authKey == b.authKey and a.wrapKey == b.wrapKey
    check a.authKey != a.wrapKey
    check other.wrapKey != a.wrapKey

  # {.testKind: tkEdgeCase, covers: "archiveSettingsError".}
  test "settings below the built-in minimum are refused":
    var
      S: ArchivePasswordSettings = testSettings()
    S.memoryKiB = 1024'u32
    check archiveSettingsError(S).len > 0
    expect ValueError:
      discard deriveArchiveLogin(pw("x"), "alice", S)
    S = testSettings()
    S.passes = 1'u32
    check archiveSettingsError(S).len > 0

  # {.testKind: tkEdgeCase, covers: "deriveArchiveLogin".}
  test "a password that is not UTF-8 is refused":
    expect ValueError:
      discard deriveArchiveLogin(@[byte 0xFF, 0xFE], "alice", testSettings())

  # {.testKind: tkUnit, covers: "deriveArchiveSubKey".}
  test "sub keys differ by name and by key generation":
    var
      M: ByteSeq = newArchiveMasterKey()
    check deriveArchiveSubKey(M, "vault", 1'u16) != deriveArchiveSubKey(M, "devices", 1'u16)
    check deriveArchiveSubKey(M, "vault", 1'u16) != deriveArchiveSubKey(M, "vault", 2'u16)
    check deriveArchiveSubKey(M, "vault", 1'u16) == deriveArchiveSubKey(M, "vault", 1'u16)

suite "archive sealed records":
  # {.testKind: tkUnit, covers: "sealArchiveRecord|openArchiveRecord".}
  test "a record opens with the same key, label and place, and nothing else":
    var
      K: ByteSeq = newArchiveMasterKey()
      other: ByteSeq = newArchiveMasterKey()
      A: ByteSeq = sealArchiveRecord(K, "ARCHIVE-TEST-v1", pw("here"), 7'u16,
        pw("secret body"))
      opened: tuple[ok: bool, record: ArchiveRecord] = openArchiveRecord(K,
        "ARCHIVE-TEST-v1", pw("here"), A)
    check A.len == 51 + 11
    check archiveRecordNum(A) == 7'u16
    check opened.ok
    check opened.record.num == 7'u16
    check opened.record.body == pw("secret body")
    check not openArchiveRecord(other, "ARCHIVE-TEST-v1", pw("here"), A).ok
    check not openArchiveRecord(K, "ARCHIVE-OTHER-v1", pw("here"), A).ok
    check not openArchiveRecord(K, "ARCHIVE-TEST-v1", pw("there"), A).ok

  # {.testKind: tkEdgeCase, covers: "openArchiveRecord".}
  test "every single changed byte makes the record refuse":
    var
      K: ByteSeq = newArchiveMasterKey()
      A: ByteSeq = sealArchiveRecord(K, "ARCHIVE-TEST-v1", pw("p"), 1'u16,
        pw("abc"))
      B: ByteSeq = @[]
      i: int = 0
      refused: int = 0
    while i < A.len:
      B = A
      B[i] = B[i] xor 0x01'u8
      if not openArchiveRecord(K, "ARCHIVE-TEST-v1", pw("p"), B).ok:
        refused = refused + 1
      i = i + 1
    check refused == A.len
    check not openArchiveRecord(K, "ARCHIVE-TEST-v1", pw("p"), A[0 .. 20]).ok

  # {.testKind: tkProperty, covers: "sealArchiveRecord".}
  test "sealing the same value twice gives different bytes (fresh salt)":
    var
      K: ByteSeq = newArchiveMasterKey()
    check sealArchiveRecord(K, "ARCHIVE-TEST-v1", pw("p"), 1'u16, pw("same")) !=
      sealArchiveRecord(K, "ARCHIVE-TEST-v1", pw("p"), 1'u16, pw("same"))

suite "archive account":
  # {.testKind: tkIntegration, covers: "sealArchiveMasterKey|openArchiveMasterKey".}
  test "a password change reseals the master key; the master key stays":
    var
      S1: ArchivePasswordSettings = testSettings()
      S2: ArchivePasswordSettings = testSettings()
      old: ArchiveLoginKeys = deriveArchiveLogin(pw("old words here"), "alice", S1)
      fresh: ArchiveLoginKeys = deriveArchiveLogin(pw("new words here"), "alice", S2)
      M: ByteSeq = newArchiveMasterKey()
      A1: ByteSeq = sealArchiveMasterKey(old.wrapKey, "alice", 1'u16, M)
      A2: ByteSeq = sealArchiveMasterKey(fresh.wrapKey, "alice", 1'u16, M)
      o1: tuple[ok: bool, keyGen: uint16, masterKey: ByteSeq] =
        openArchiveMasterKey(old.wrapKey, "alice", A1)
      o2: tuple[ok: bool, keyGen: uint16, masterKey: ByteSeq] =
        openArchiveMasterKey(fresh.wrapKey, "alice", A2)
    check A1.len == 83
    check o1.ok and o2.ok
    check o1.masterKey == M and o2.masterKey == M
    check o2.keyGen == 1'u16
    check not openArchiveMasterKey(old.wrapKey, "alice", A2).ok
    check not openArchiveMasterKey(old.wrapKey, "mallory", A1).ok

  # {.testKind: tkUnit, covers: "sealArchiveSpaceEntry|openArchiveSpaceEntry".}
  test "a space entry carries the secret, the suite and the app's bytes":
    var
      V: ByteSeq = deriveArchiveSubKey(newArchiveMasterKey(), archiveVaultKeyName, 1'u16)
      id: ByteSeq = newArchiveSpaceId()
      space: ArchiveSpace = initArchiveSpace(id, newArchiveMasterKey(), 3'u16,
        epochSize = 128'u16, tagLen = aatl16)
      A: ByteSeq = sealArchiveSpaceEntry(V, space, pw("bob@example"))
      back: tuple[ok: bool, space: ArchiveSpace, meta: ByteSeq] =
        openArchiveSpaceEntry(V, id, A)
    check back.ok
    check back.meta == pw("bob@example")
    check back.space.secret == space.secret
    check back.space.gen == 3'u16
    check back.space.epochSize == 128'u16
    check back.space.tagLen == aatl16
    check encodeAmeSuiteLayout(back.space.layout) == encodeAmeSuiteLayout(space.layout)
    check not openArchiveSpaceEntry(V, newArchiveSpaceId(), A).ok

suite "archive log":
  # {.testKind: tkIntegration, covers: "deriveArchiveSpaceSecret|sealArchiveLog|openArchiveLog".}
  test "two members derive the same space secret and open each other's records":
    var
      alice: AmeSession = initAmeSession(aAuth(aerInitiator, 9'u8),
        peerTrustRequired = false)
      bob: AmeSession = initAmeSession(aAuth(aerResponder, 9'u8),
        peerTrustRequired = false)
      id: ByteSeq = newArchiveSpaceId()
      sa: ArchiveSpace = initArchiveSpace(id,
        deriveArchiveSpaceSecret(alice.fomke, id, 1'u16), 1'u16)
      sb: ArchiveSpace = initArchiveSpace(id,
        deriveArchiveSpaceSecret(bob.fomke, id, 1'u16), 1'u16)
      P: ArchivePosition = ArchivePosition(gen: 1'u16, lane: newArchiveLane(),
        epoch: 0'u32, index: 0'u16)
      A: ByteSeq = sealArchiveLog(sa, P, pw("hello bob"))
      opened: tuple[ok: bool, position: ArchivePosition, body: ByteSeq,
        err: string] = openArchiveLog(sb, A)
    check sa.secret == sb.secret
    check sa.secret != alice.fomke.tightKey
    check deriveArchiveSpaceSecret(alice.fomke, id, 2'u16) != sa.secret
    check A.len == archiveLogHeaderBytes + 32 + 9
    check archiveLogGen(A) == 1'u16
    check opened.ok
    check opened.position == P
    check opened.body == pw("hello bob")

  # {.testKind: tkEdgeCase, covers: "openArchiveLog".}
  test "a record moved to another space, or changed, does not open":
    var
      secret: ByteSeq = newArchiveMasterKey()
      s1: ArchiveSpace = initArchiveSpace(newArchiveSpaceId(), secret, 1'u16)
      s2: ArchiveSpace = initArchiveSpace(newArchiveSpaceId(), secret, 1'u16)
      P: ArchivePosition = ArchivePosition(gen: 1'u16, lane: 5'u32,
        epoch: 0'u32, index: 3'u16)
      A: ByteSeq = sealArchiveLog(s1, P, pw("x"))
      B: ByteSeq = A
    check openArchiveLog(s1, A).ok
    check not openArchiveLog(s2, A).ok
    B[11] = B[11] xor 0x01'u8
    check not openArchiveLog(s1, B).ok

  # {.testKind: tkEdgeCase, covers: "sealArchiveLog".}
  test "a position past the epoch size or of another generation is refused":
    var
      s: ArchiveSpace = initArchiveSpace(newArchiveSpaceId(),
        newArchiveMasterKey(), 2'u16, epochSize = 16'u16)
    expect ValueError:
      discard sealArchiveLog(s, ArchivePosition(gen: 2'u16, lane: 1'u32,
        epoch: 0'u32, index: 16'u16), pw("x"))
    expect ValueError:
      discard sealArchiveLog(s, ArchivePosition(gen: 1'u16, lane: 1'u32,
        epoch: 0'u32, index: 0'u16), pw("x"))

  # {.testKind: tkProperty, covers: "sealArchiveLog".}
  test "a reused position gives other bytes, so no nonce repeats":
    var
      s: ArchiveSpace = initArchiveSpace(newArchiveSpaceId(),
        newArchiveMasterKey(), 1'u16)
      P: ArchivePosition = ArchivePosition(gen: 1'u16, lane: 1'u32,
        epoch: 0'u32, index: 0'u16)
      A: ByteSeq = sealArchiveLog(s, P, pw("first text"))
      B: ByteSeq = sealArchiveLog(s, P, pw("other text"))
    check A[13 .. 28] != B[13 .. 28]
    check A[29 + 32 .. ^1] != B[29 + 32 .. ^1]
    check openArchiveLog(s, A).body == pw("first text")
    check openArchiveLog(s, B).body == pw("other text")

suite "archive new device":
  # {.testKind: tkIntegration, covers: "deriveArchiveLogin|openArchiveMasterKey|openArchiveSpaceEntry|openArchiveLog".}
  test "a lost phone: the new one opens the old record with the password only":
    var
      settings: ArchivePasswordSettings = testSettings()
      M: ByteSeq = newArchiveMasterKey()
      login: ArchiveLoginKeys = deriveArchiveLogin(pw("six random words please ok"),
        "alice", settings)
      space: ArchiveSpace = initArchiveSpace(newArchiveSpaceId(),
        newArchiveMasterKey(), 1'u16)
      P: ArchivePosition = ArchivePosition(gen: 1'u16, lane: newArchiveLane(),
        epoch: 0'u32, index: 0'u16)
      # what the server holds after the old phone is gone:
      storedSettings: ByteSeq = encodeArchiveSettings(settings)
      storedMaster: ByteSeq = sealArchiveMasterKey(login.wrapKey, "alice", 1'u16, M)
      storedEntry: ByteSeq = sealArchiveSpaceEntry(
        deriveArchiveSubKey(M, archiveVaultKeyName, 1'u16), space, @[])
      storedLog: ByteSeq = sealArchiveLog(space, P, pw("from the old phone"))
      # the new phone:
      newLogin: ArchiveLoginKeys = deriveArchiveLogin(pw("six random words please ok"),
        "alice", decodeArchiveSettings(storedSettings))
      master: tuple[ok: bool, keyGen: uint16, masterKey: ByteSeq] =
        openArchiveMasterKey(newLogin.wrapKey, "alice", storedMaster)
      entry: tuple[ok: bool, space: ArchiveSpace, meta: ByteSeq] =
        openArchiveSpaceEntry(deriveArchiveSubKey(master.masterKey,
          archiveVaultKeyName, master.keyGen), space.spaceId, storedEntry)
    clearArchiveLogin(login)
    check master.ok
    check entry.ok
    check openArchiveLog(entry.space, storedLog).body == pw("from the old phone")

suite "archive sending lane":
  # {.testKind: tkUnit, covers: "nextArchiveSend".}
  test "positions count up and roll into the next epoch":
    var
      L: ArchiveSendLane = initArchiveSendLane(9'u32, 1'u16, epochSize = 4'u16,
        reserveStep = 2'u16)
      seen: seq[(uint32, uint16)] = @[]
      P: ArchivePosition = default(ArchivePosition)
      i: int = 0
    while i < 6:
      P = nextArchiveSend(L).position
      seen.add((P.epoch, P.index))
      i = i + 1
    check seen == @[(0'u32, 0'u16), (0'u32, 1'u16), (0'u32, 2'u16),
      (0'u32, 3'u16), (1'u32, 0'u16), (1'u32, 1'u16)]
    check P.lane == 9'u32 and P.gen == 1'u16

  # {.testKind: tkUnit, covers: "nextArchiveSend".}
  test "a save is asked for once per reserveStep, before the first of them":
    var
      L: ArchiveSendLane = initArchiveSendLane(9'u32, 1'u16, reserveStep = 4'u16)
      saves: seq[bool] = @[]
      i: int = 0
    while i < 9:
      saves.add(nextArchiveSend(L).mustSave)
      i = i + 1
    check saves == @[true, false, false, false, true, false, false, false, true]

  # {.testKind: tkRegression, covers: "resumeArchiveSendLane", pins: "a crash reuses a position".}
  test "after a crash the lane goes on past everything it may have sealed":
    var
      L: ArchiveSendLane = initArchiveSendLane(9'u32, 1'u16, reserveStep = 4'u16)
      saved: ByteSeq = @[]
      step: ArchiveSendStep = default(ArchiveSendStep)
      used: seq[uint64] = @[]
      i: int = 0
      back: ArchiveSendLane = default(ArchiveSendLane)
    while i < 6:
      step = nextArchiveSend(L)
      if step.mustSave: saved = step.state
      used.add(archiveNumberOf(step.position, L.epochSize))
      i = i + 1
    check saved.len == archiveSendStateBytes
    back = resumeArchiveSendLane(saved)
    check back.lane == 9'u32 and back.gen == 1'u16
    step = nextArchiveSend(back)
    check archiveNumberOf(step.position, back.epochSize) == 8'u64
    check archiveNumberOf(step.position, back.epochSize) notin used
    check step.mustSave

  # {.testKind: tkUnit, covers: "renewArchiveSendLane".}
  test "a new generation keeps the lane number and starts at 0":
    var
      L: ArchiveSendLane = initArchiveSendLane(9'u32, 1'u16)
      R: ArchiveSendLane = default(ArchiveSendLane)
    discard nextArchiveSend(L)
    R = renewArchiveSendLane(L, 2'u16)
    check R.lane == 9'u32 and R.gen == 2'u16
    check nextArchiveSend(R).position == ArchivePosition(gen: 2'u16, lane: 9'u32,
      epoch: 0'u32, index: 0'u16)

suite "archive reading lane":
  # {.testKind: tkUnit, covers: "noteArchiveRead".}
  test "in order, a gap, the late ones, a duplicate":
    var
      R: ArchiveReadLane = initArchiveReadLane(5'u32, 1'u16, epochSize = 4'u16)
      at = proc (n: uint64): ArchivePosition = archivePositionOf(1'u16, 5'u32, n, 4'u16)
    check noteArchiveRead(R, at(0)) == arsInOrder
    check noteArchiveRead(R, at(1)) == arsInOrder
    check noteArchiveRead(R, at(5)) == arsAfterGap
    check R.missing == @[2'u64, 3, 4]
    check noteArchiveRead(R, at(3)) == arsLate
    check R.missing == @[2'u64, 4]
    check noteArchiveRead(R, at(3)) == arsDuplicate
    check noteArchiveRead(R, at(1)) == arsDuplicate
    check noteArchiveRead(R, at(6)) == arsInOrder

  # {.testKind: tkEdgeCase, covers: "noteArchiveRead".}
  test "a record of another lane or generation is refused":
    var
      R: ArchiveReadLane = initArchiveReadLane(5'u32, 1'u16)
    expect ValueError:
      discard noteArchiveRead(R, ArchivePosition(gen: 1'u16, lane: 6'u32))
    expect ValueError:
      discard noteArchiveRead(R, ArchivePosition(gen: 2'u16, lane: 5'u32))

  # {.testKind: tkUnit, covers: "archiveHeldBack".}
  test "a member says it saw more than arrived: the rest is owed":
    var
      R: ArchiveReadLane = initArchiveReadLane(5'u32, 1'u16, epochSize = 8'u16)
      at = proc (n: uint64): ArchivePosition = archivePositionOf(1'u16, 5'u32, n, 8'u16)
    discard noteArchiveRead(R, at(0))
    discard noteArchiveRead(R, at(2))
    check archiveHeldBack(R, at(2)) == 1'u64
    check archiveHeldBack(R, at(4)) == 3'u64
    check archiveHeldBack(R, at(0)) == 0'u64

suite "archive devices and lanes":
  # {.testKind: tkUnit, covers: "sealArchiveDevices|openArchiveDevices".}
  test "the device list keeps removed devices":
    var
      K: ByteSeq = deriveArchiveSubKey(newArchiveMasterKey(), archiveDevicesKeyName, 1'u16)
      D: seq[ArchiveDevice] = @[
        ArchiveDevice(deviceId: newArchiveDeviceId(), addedMs: 1'u64, removedMs: 0'u64),
        ArchiveDevice(deviceId: newArchiveDeviceId(), addedMs: 2'u64, removedMs: 9'u64)]
      A: ByteSeq = sealArchiveDevices(K, "alice", 1'u16, D)
      back: tuple[ok: bool, devices: seq[ArchiveDevice]] = openArchiveDevices(K, "alice", A)
    check A.len == 51 + 1 + 64
    check back.ok
    check back.devices == D
    check not openArchiveDevices(K, "bob", A).ok

  # {.testKind: tkIntegration, covers: "sealArchiveLaneRecord|openArchiveLaneRecord|archiveLaneOwner".}
  test "a new device finds the lanes of an old one; another member cannot fake one":
    var
      mine: ByteSeq = deriveArchiveSubKey(newArchiveMasterKey(), archiveLanesKeyName, 1'u16)
      theirs: ByteSeq = deriveArchiveSubKey(newArchiveMasterKey(), archiveLanesKeyName, 1'u16)
      space: ByteSeq = newArchiveSpaceId()
      oldPhone: ByteSeq = newArchiveDeviceId()
      rec: ByteSeq = sealArchiveLaneRecord(mine, space, 77'u32, 1'u16, oldPhone, 5'u64)
      forged: ByteSeq = sealArchiveLaneRecord(theirs, space, 88'u32, 1'u16, oldPhone, 5'u64)
      opened: tuple[ok: bool, deviceId: ByteSeq, createdMs: uint64] =
        openArchiveLaneRecord(mine, space, 77'u32, rec)
      own: seq[uint32] = @[]
    check rec.len == 75
    check opened.ok and opened.deviceId == oldPhone and opened.createdMs == 5'u64
    check not openArchiveLaneRecord(mine, space, 78'u32, rec).ok
    check not openArchiveLaneRecord(mine, space, 88'u32, forged).ok
    own.add(77'u32)
    check archiveLaneOwner(own, 77'u32, []) == aloOwn
    check archiveLaneOwner(own, 88'u32, decodeArchiveLaneList(
      encodeArchiveLaneList([88'u32]))) == aloPeer
    check archiveLaneOwner(own, 99'u32, [99'u32, 77'u32]) == aloConflict
