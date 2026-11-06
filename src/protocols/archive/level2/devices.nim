## -------------------------------------------------------------------------
## Archive Devices <- a user's device list, and "this lane is one of mine"
## -------------------------------------------------------------------------
##
## Two sealed records (../level1/sealed) a multi-device account keeps, so a
## NEW device knows which lanes its user wrote on OLD devices, even on a
## device that is long gone:
##
##   record        label                key (sub key)  place               num
##   ------------  -------------------  -------------  ------------------  ------
##   device list   "ARCHIVE-DEVICES-v1" "devices"      userId              keyGen
##   lane record   "ARCHIVE-LANE-v1"    "lanes"        spaceId | lane u32  keyGen
##
## ╭─ ❧ Def. 1: the body of a device list 🌊
##
##   count u8 | count × ( deviceId 16 | addedMs u64 | removedMs u64 )   = 1 + 32·n
##
## A removed device keeps its entry with removedMs > 0. Deleting it would
## make its lanes look like another member's.
##
## ╭─ ❧ Def. 2: the body of a lane record, fixed 24 B 🐦‍🔥
##
##   deviceId 16 | createdMs u64
##
## One per own lane, written by the device the first time it writes into a
## space. The lane number is in the place, so the tag covers it.
##
##   new device:  "lanes" ──opens──▶ every lane record of the space
##                ──▶ own lanes ──▶ archiveLaneOwner (./lanes)

import ../../types
import ../../ame/level0/bytes
import ../types
import ../level1/keys
import ../level1/sealed
import runePragmas
import var_invariants

const
  archiveDevicesLabel* = "ARCHIVE-DEVICES-v1"
  archiveLaneLabel* = "ARCHIVE-LANE-v1"
  archiveDevicesKeyName* = "devices"
  archiveLanesKeyName* = "lanes"
  archiveDeviceEntryBytes = archiveDeviceIdBytes + 16

proc newArchiveDeviceId*(): ByteSeq {.role: dataFetcher, tag: "archive|appApi".} =
  ## 16 random bytes a device makes for itself at its first start.
  result = archiveRandom(archiveDeviceIdBytes)

proc encodeArchiveDevices*(D: openArray[ArchiveDevice]): ByteSeq {.
    role: dataWriter, tag: "archive|wire", needs: D.len <= 255.} =
  ## D: Def. 1.
  result.add(uint8(D.len))
  for d in D:
    if d.deviceId.len != archiveDeviceIdBytes:
      raise newException(ValueError, "archive deviceId must be 16 bytes")
    appendAmeBytes(result, d.deviceId)
    appendAmeU64(result, d.addedMs)
    appendAmeU64(result, d.removedMs)

proc decodeArchiveDevices*(A: openArray[uint8]): seq[ArchiveDevice] {.
    role: parser, tag: "archive|wire".} =
  ## A: Def. 1. Raises when the length does not match the count.
  var
    i: int = 0
    o: int = 1
  if A.len == 0 or A.len != 1 + archiveDeviceEntryBytes * int(A[0]):
    raise newException(ValueError, "archive device list is malformed")
  while i < int(A[0]):
    result.add(ArchiveDevice(deviceId: @(A.toOpenArray(o, o + 15)),
      addedMs: readAmeU64(A, o + 16), removedMs: readAmeU64(A, o + 24)))
    o = o + archiveDeviceEntryBytes
    i = i + 1

proc sealArchiveDevices*(devicesKey: openArray[uint8], userId: string,
    keyGen: uint16, D: openArray[ArchiveDevice]): ByteSeq {.role: encryptor,
    tag: "archive|appApi|cryptoBoundary".} =
  ## devicesKey: sub key "devices". userId/keyGen/D: whose list, which keys.
  result = sealArchiveRecord(devicesKey, archiveDevicesLabel,
    toBytesArchive(userId), keyGen, encodeArchiveDevices(D))

proc openArchiveDevices*(devicesKey: openArray[uint8], userId: string,
    A: openArray[uint8]): tuple[ok: bool, devices: seq[ArchiveDevice]] {.
    role: decryptor, tag: "archive|appApi|cryptoBoundary".} =
  ## devicesKey/userId/A: the stored list. Nothing here raises.
  var
    opened: tuple[ok: bool, record: ArchiveRecord] = (false, ArchiveRecord())
  opened = openArchiveRecord(devicesKey, archiveDevicesLabel,
    toBytesArchive(userId), A)
  if not opened.ok:
    return
  try:
    result = (true, decodeArchiveDevices(opened.record.body))
  except ValueError:
    result = (false, @[])

proc archiveLanePlace(spaceId: openArray[uint8], lane: uint32): ByteSeq {.
    role: helper, inline.} =
  ## spaceId/lane: where a lane record is stored, bound into its tag.
  result = @spaceId
  appendAmeU32(result, lane)

proc sealArchiveLaneRecord*(lanesKey, spaceId: openArray[uint8], lane: uint32,
    keyGen: uint16, deviceId: openArray[uint8], createdMs: uint64): ByteSeq {.
    role: encryptor, tag: "archive|appApi|cryptoBoundary",
    needs: deviceId.len == archiveDeviceIdBytes.} =
  ## lanesKey: sub key "lanes". The rest: Def. 2 and where it is stored.
  var
    body: ByteSeq = @deviceId
  appendAmeU64(body, createdMs)
  result = sealArchiveRecord(lanesKey, archiveLaneLabel,
    archiveLanePlace(spaceId, lane), keyGen, body)

proc openArchiveLaneRecord*(lanesKey, spaceId: openArray[uint8], lane: uint32,
    A: openArray[uint8]): tuple[ok: bool, deviceId: ByteSeq, createdMs: uint64] {.
    role: decryptor, tag: "archive|appApi|cryptoBoundary".} =
  ## lanesKey/spaceId/lane/A: one stored lane record. ok = false when it is
  ## not this user's, or not for this lane.
  var
    opened: tuple[ok: bool, record: ArchiveRecord] = (false, ArchiveRecord())
  opened = openArchiveRecord(lanesKey, archiveLaneLabel,
    archiveLanePlace(spaceId, lane), A)
  if not opened.ok or opened.record.body.len != 24:
    return
  result = (true, opened.record.body[0 .. 15], readAmeU64(opened.record.body, 16))
