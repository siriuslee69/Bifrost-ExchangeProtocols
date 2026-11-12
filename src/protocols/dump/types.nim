## -------------------------------------------------------------------------
## Dump Types <- what the dump holds: messages waiting to be written down
## -------------------------------------------------------------------------
##
## The dump is the hand-over point between the network and whoever keeps the
## data. Bifrost opens a frame; what came out waits here, in memory, until the
## caller says it is safely on disk.
##
##   network ──▶ offerDump ──▶ [ waiting ] ──grabDump──▶ [ in the caller's hands ]
##                                 ▲                          │             │
##                                 └────── giveBackDump ──────┘             │
##                                                              settleDump ─┘
##                                                              (memory freed)
##
## Def. 1 (stream): one line of messages, named by the feeder: "relay/7",
##   "box/space/c0ffee". Numbers are counted per stream.
## Def. 2 (number): the place of a message in its stream, from 1. A feeder that
##   has one (a sender's own counter) gives it; 0 asks the dump to count.
## Def. 3 (settled): the keeper confirmed this number is on disk. A settled
##   number is never accepted again, so a message resent after a crash is
##   recognised and skipped.
## Def. 4 (ticket): names one batch handed out by `grabDump`.
##
## No disk and no database here. Bifrost hands the bytes out and takes the
## word "settled" back.

import std/[deques, tables]

import ../types
import runePragmas

const
  dumpRecordVersion* = 1'u8
    ## The first byte of an encoded record.
  dumpNameMax* = 512
    ## longest stream or sender name, in bytes
  dumpDefaultMaxRecords* = 4096
  dumpDefaultMaxBytes* = 64 * 1024 * 1024
  dumpDefaultMaxStreams* = 65536
    ## streams the dump remembers at once. Each costs a few dozen bytes for as
    ## long as it is remembered, and a feeder may name as many as it likes.
  dumpMaxAhead* = 4096
    ## settled numbers remembered above a gap, per stream

type
  DumpRecord* {.role: rawData, tag: "dump|types",
      expectedCount: [0, 4096], lifeCycle: lcJob.} = object
    ## One message on its way to a disk.
    stream*: string
    number*: uint64
    atMs*: uint64
      ## when it arrived, on the feeder's clock
    sender*: string
      ## who the link proved it came from
    body*: ByteSeq

  DumpOffer* = enum
    doTaken,
      ## it waits in the dump now
    doDuplicate,
      ## this number is waiting, in somebody's hands, or settled
    doFull,
      ## no room: nothing was thrown out, the sender must slow down or resend
    doRefused
      ## it can never fit: too large, or a name that is too long

  DumpOffered* {.role: preparedData, tag: "dump|types".} = object
    ## The answer to one offer.
    state*: DumpOffer
    number*: uint64
      ## the number it has (given, or counted by the dump)

  DumpBatch* {.role: preparedData, tag: "dump|types".} = object
    ## What `grabDump` hands out. Empty `records` means nothing was waiting.
    ticket*: uint64
    records*: seq[DumpRecord]

  DumpLine* {.role: memory, tag: "dump|types",
      expectedCount: [0, -1], lifeCycle: lcSession.} = object
    ## What the dump remembers about one stream.
    settled*: uint64
      ## every number up to here is on disk
    ahead*: seq[uint64]
      ## settled numbers above a gap, smallest first
    held*: seq[uint64]
      ## numbers waiting or in somebody's hands
    nextAuto*: uint64
      ## what the dump counts next when the feeder gave no number
    givenUp*: uint64
      ## gaps closed by force because `ahead` was full

  DumpBuffer* {.role: memory, tag: "dump|types",
      expectedCount: 1, lifeCycle: lcForever.} = object
    ## The whole dump of one program.
    maxRecords*: int
    maxBytes*: int
    maxStreams*: int
      ## most streams remembered; a record for one more is answered doFull
    bytes*: int
      ## bytes of every record not settled yet
    count*: int
      ## records not settled yet
    waiting*: Deque[DumpRecord]
    grabbed*: Table[uint64, seq[DumpRecord]]
    lines*: Table[string, DumpLine]
    nextTicket*: uint64
