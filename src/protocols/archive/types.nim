## -------------------------------------------------------------------------
## Archive Types <- what a sealed record, a log record and a space look like
## -------------------------------------------------------------------------
##
## The archive family seals data that is STORED: on a server that must not
## read it, for years. It knows nothing about databases, users or servers.
## It turns keys and bytes into sealed bytes and back. Who keeps them, and
## who may fetch them, is the caller's business (Nebel's boxes).
##
##   password ──▶ login secret ──▶ auth key        (shown to a server)
##                              └▶ wrap key        (opens the master key)
##   master key (random) ──▶ sub keys, one per job, as many as needed
##   FOMKE tight key ──▶ space secret ──▶ epoch key ──▶ one log record
##
## Def. 1 (space): one set of log records that a fixed group of members can
##   open. A chat of two users is one space; so is one user's password vault,
##   or one mailbox.
## Def. 2 (lane): the sending line of ONE device in one space, a random u32.
##   Only that device seals on it, so two devices never share a key.
## Def. 3 (epoch): a run of `epochSize` records on one lane, with its own key.
## Def. 4 (position): (gen, lane, epoch, index). Names one log record.
## Def. 5 (sealed record): one value sealed under a key, a label and a place
##   (see level1/sealed.nim): a wrapped master key, a space entry, ...

import ../types
import ../ame/types
import runePragmas

const
  archiveRecordVersion* = 1'u8
    ## The first byte of every sealed record and log record.
  archiveKeyBytes* = 32
    ## Every archive key, secret and salt of a password: 32 bytes.
  archiveSaltBytes* = 16
    ## The fresh random salt in front of every sealed record and log record.
  archiveRecordTagBytes* = 32
    ## Sealed records always carry a 32-byte tag.
  archiveRecordHeaderBytes* = 19
    ## ver u8 | num u16 | salt 16
  archiveLogHeaderBytes* = 29
    ## ver u8 | gen u16 | lane u32 | epoch u32 | index u16 | salt 16
  archivePositionBytes* = 12
    ## lane u32 | gen u16 | epoch u32 | index u16
  archiveSettingsBytes* = 42
    ## ver u8 | memoryKiB u32 | passes u32 | parallelism u8 | userSalt 32
  archiveSpaceIdBytes* = 16
  archiveDefaultEpochSize* = 256'u16
  archiveDefaultReserveStep* = 16'u16
    ## a sending lane saves its counter once per 16 records
  archiveMaxMissing* = 4096
    ## a reading lane remembers at most this many missing records
  archiveDeviceIdBytes* = 16
  archiveSendStateBytes* = 19
    ## ver u8 | lane u32 | gen u16 | epochSize u16 | reservedUntil u64
    ## | reserveStep u16 (level2/lanes.nim, Def. 1)
  archiveMinMemoryKiB* = 65_536'u32
    ## 64 MiB. The client refuses fewer, whatever a server hands out.
  archiveMinPasses* = 3'u32
  archiveDefaultMemoryKiB* = 262_144'u32
    ## 256 MiB, about a second on a phone.

type
  ArchivePasswordSettings* {.role: configurator,
      tag: "archive|cryptoBoundary|types".} = object
    ## How a password becomes the login secret. Not secret; kept on the
    ## server so a new device can make the same secret (42 bytes on disk).
    memoryKiB*: uint32
    passes*: uint32
    parallelism*: uint8
    userSalt*: ByteSeq
      ## 32 random bytes made once per account

  ArchiveLoginKeys* {.role: preparedData,
      tag: "archive|cryptoBoundary|types".} = object
    ## The two keys a password gives. Erase both after use.
    authKey*: ByteSeq
      ## proves to a server who is asking; the server keeps only a hash
    wrapKey*: ByteSeq
      ## opens the record that holds the master key; never leaves the device

  ArchiveRecord* {.role: preparedData, tag: "archive|types".} = object
    ## One opened sealed record.
    num*: uint16
      ## what the caller numbered it with: a key generation, a space
      ## generation, 0 when there is nothing to count
    body*: ByteSeq

  ArchivePosition* {.role: preparedData, tag: "archive|types".} = object
    ## Def. 4. Where one log record sits.
    gen*: uint16
    lane*: uint32
    epoch*: uint32
    index*: uint16

  ArchiveSpace* {.role: truthState, tag: "archive|cryptoBoundary|types",
      expectedCount: [0, -1], lifeCycle: lcSession.} = object
    ## What every member of a space holds to seal and open its log records.
    ## One per (space, generation) a device has open.
    spaceId*: ByteSeq
    gen*: uint16
    secret*: ByteSeq
      ## the space secret: 32 bytes, the same for every member
    epochSize*: uint16
    layout*: AmeSuiteLayout
    tier*: AmeMaskTier
    tagLen*: AmeAuthTagLen

  ArchiveSendLane* {.role: truthState, tag: "archive|types",
      expectedCount: [0, -1], lifeCycle: lcSession.} = object
    ## Def. 2 seen from the one device that writes the lane: where the next
    ## record goes, and how far ahead positions are already reserved on disk.
    ## One per (space, generation) this device writes into.
    lane*: uint32
    gen*: uint16
    epochSize*: uint16
    next*: uint64
      ## the next record's number on this lane: epoch * epochSize + index
    reservedUntil*: uint64
      ## the first number NOT yet saved as reserved. A device that restarts
      ## goes on from here, so nothing below it is ever sealed twice.
    reserveStep*: uint16
      ## how many numbers one save reserves (fewer saves, a few gaps on crash)

  ArchiveSendStep* {.role: preparedData, tag: "archive|types".} = object
    ## What `nextArchiveSend` hands out. When `mustSave` is true, the caller
    ## writes `state` to disk BEFORE it seals at `position`.
    position*: ArchivePosition
    mustSave*: bool
    state*: ByteSeq

  ArchiveReadLane* {.role: truthState, tag: "archive|types",
      expectedCount: [0, -1], lifeCycle: lcSession.} = object
    ## Def. 2 seen from a reader: which records of one lane arrived, which
    ## are missing. One per (space, generation, lane) a device reads.
    lane*: uint32
    gen*: uint16
    epochSize*: uint16
    next*: uint64
      ## one past the highest number seen
    missing*: seq[uint64]
      ## numbers below `next` that have not arrived, oldest first
    givenUp*: uint64
      ## missing numbers dropped because the list was full

  ArchiveReadStep* = enum
    arsInOrder,
      ## the next number, as expected
    arsAfterGap,
      ## further ahead; the numbers in between are now missing
    arsLate,
      ## a missing number arrived after all
    arsDuplicate
      ## seen before, or older than anything still missing: drop it

  ArchiveLaneOwner* = enum
    aloOwn,
      ## one of this user's devices writes it (its lane record says so)
    aloPeer,
      ## another member writes it
    aloConflict
      ## not this user's by its records, yet its first record names one of
      ## this user's lanes: a lane record was hidden, or a member lies

  ArchiveDevice* {.role: preparedData, tag: "archive|types".} = object
    ## One entry of a user's device list. A removed device is marked, never
    ## deleted, so its old lanes stay known as the user's own.
    deviceId*: ByteSeq
      ## 16 random bytes the device made for itself
    addedMs*: uint64
    removedMs*: uint64
      ## 0 while the device is in use

  ArchiveLogRecord* {.role: rawData, tag: "archive|types".} = object
    ## One log record as it lies on a server, split into its fields.
    position*: ArchivePosition
    salt*: ByteSeq
    tag*: ByteSeq
    ciphertext*: ByteSeq
