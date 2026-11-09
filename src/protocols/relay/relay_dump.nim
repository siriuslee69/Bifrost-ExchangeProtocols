## -------------------------------------------------------------------------
## Relay Dump <- a frame the relay delivered here, handed to the dump
## -------------------------------------------------------------------------
##
##   feedOpenedRelayFrame ──▶ RelayStep (event = reDelivered)
##                                 │ dumpDelivered
##                                 ▼
##                            DumpBuffer ──▶ the keeper writes it to disk
##
## Only a frame addressed to this node ends here. Everything else the relay
## passes on and never keeps.

import std/strutils

import ../ame/types
import ../dump/types
import ../dump/level1/buffer
import ./relay_node
import runePragmas

proc relayDumpStream*(origin: uint64): string {.role: helper, inline,
    tag: "relay|dump".} =
  ## origin: who sent the frame. One stream per origin, so that sender's own
  ## order stays visible.
  result = "relay/" & toHex(origin).toLowerAscii()

proc dumpDelivered*(D: var DumpBuffer, step: RelayStep, sender: string,
    atMs: uint64): DumpOffered {.role: actor, tag: "relay|dump|appApi".} =
  ## D: the dump. step: what the relay made of one frame. sender: the name the
  ## link proved. atMs: the clock. Anything but a delivery is refused.
  if step.event != reDelivered or not step.frame.ok:
    return DumpOffered(state: doRefused)
  result = D.offerDump(DumpRecord(stream: relayDumpStream(step.frame.origin),
    atMs: atMs, sender: sender, body: step.frame.payload))
