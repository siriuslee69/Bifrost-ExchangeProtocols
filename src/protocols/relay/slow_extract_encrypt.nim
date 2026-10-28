## -------------------------------------------------------------------------
## relaySlowExtractEncrypt <- every link opened completely, the payload read
##                            (and judged), then sealed again for the next
## -------------------------------------------------------------------------
##
## The relay is a full participant here: it holds the keys of every link and
## SEES what passes. That is the point -- use it when the middle machine must
## decide on the content (narrow a caller's rights, refuse a request,
## rewrite a field). Use relayFastExtraFrame when it must not.
##
##   phone ==link A==> relay ==link B==> nas
##           |                |               |
##           AME frame (A)    open with A     open with B
##           [ RSE | data ]   inspect(data)   [ RSE | data ]
##                            seal with B
##
##   what           relayFastExtraFrame        relaySlowExtractEncrypt
##   -------------  -------------------------  --------------------------
##   per hop        16 address bytes           the whole frame
##   relay reads    target, origin             target, origin, PAYLOAD
##   end to end     a second handshake inside  not needed (each link is
##                  (the relay cannot read)    its own AME session)
##   overhead       42 B ART header            22 B envelope + AME frame
##
## Neighbours, the directory, permission and the way onward are shared with
## relayFastExtraFrame: see relay_node.nim. The envelope's bytes:
## slow_envelope.nim, Def. 1.
##
## Example 1. A relay that lets a phone read from the nas but never write:
##
##   proc readOnly(identity: string, f: var AmeRouteFrame): bool =
##     result = identity != "phone" or f.payload.len == 0 or
##       f.payload[0] != opWrite
##
##   var R = initRelaySlowExtractEncrypt(0x10'u64, inspect = readOnly)
##   R.addRelayTarget(0x20'u64, "nas", ["phone"])
##   ...admit phone and nas exactly as for relayFastExtraFrame...
##   var step = R.feedRelaySlowExtractEncrypt(fromAddress, datagram, nowMs)
##   for s in step.send: sendTo(s.address, s.frame)
##
## A client sends with `sealSlowForward(link, carrier, target, payload)` and
## reads what arrives with `openSlowFrame(link, carrier, datagram)`.

import ../transport/types as transport_types
import ./slow_envelope
import ./relay_node
import runePragmas

type
  ## RelaySlowExtractEncrypt: one node of relaySlowExtractEncrypt.
  RelaySlowExtractEncrypt* {.role: truthState, expectedCount: 1,
      lifeCycle: lcForever.} = object of RelayNode

proc initRelaySlowExtractEncrypt*(selfId: uint64,
    capacity: int = relayCapacity,
    inspect: RelayInspect = nil): RelaySlowExtractEncrypt {.
    role: configurator, tag: "appApi".} =
  ## selfId: this node's own id; frames for it are delivered here.
  ## capacity: how many neighbours fit; a ceiling, not a target.
  ## inspect: sees every forward before it is passed on (see RelayInspect);
  ##   nil passes every forward that Def. 3 of relay_node.nim allows.
  setupRelayNode(result, rkSlowExtractEncrypt, selfId, capacity, inspect)

proc feedRelaySlowExtractEncrypt*(R: var RelaySlowExtractEncrypt, slot: int,
    frame: openArray[uint8], nowMs: uint32): RelayStep {.
    role: orchestrator, tag: "appApi".} =
  ## R: the node. slot: the neighbour the datagram came from.
  ## frame: an AME data frame carrying an envelope, or an AME kind 0x14
  ##   directory question -- told apart by the clear AME header.
  ## nowMs: caller's millisecond clock (return notes expire by it).
  ## Nothing here raises, so a neighbour cannot stop the node with junk.
  if droppedFromEmptySlot(R, slot, result):
    return
  if isAmeRouteControl(frame):
    return feedRelayControl(R, slot, frame)
  result = feedOpenedRelayFrame(R, slot, openSlowFrame(
    R.neighbours[slot].session, R.neighbours[slot].carrier, frame), nowMs)

proc feedRelaySlowExtractEncrypt*(R: var RelaySlowExtractEncrypt,
    source: transport_types.UdpAddress, frame: openArray[uint8],
    nowMs: uint32): RelayStep {.role: orchestrator, tag: "appApi".} =
  ## R: the node. source: the address the datagram came from; it names the
  ## neighbour, and with it the keys. A stranger's datagram is dropped.
  result = feedRelaySlowExtractEncrypt(R, relaySlotOf(R, source), frame,
    nowMs)
