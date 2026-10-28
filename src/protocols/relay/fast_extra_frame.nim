## -------------------------------------------------------------------------
## relayFastExtraFrame <- one link per neighbour; only an outer "ART" frame
##                        around the payload is opened and sealed again
## -------------------------------------------------------------------------
##
## A client makes ONE handshake, with its relay, and then:
##
##   asks it "whom may I reach?"     AME frame kind 0x14, FOMKE-sealed
##   sends through it                outer "ART" route frames
##
## Through the relays it runs an end-to-end AM1S or AM1P handshake with the
## target, and later the session that handshake opens. Those records are
## the route frames' PAYLOAD, which no relay can open:
##
##   phone ==link A==> relay 1 ==link B==> relay 2 ==link C==> nas
##     |                  |                   |                  |
##     ART[A: to 0x20]    open with A,        open with B,       target is
##     + E2E hello        seal with B         seal with C        me: E2E
##                        (only the 16-byte address is touched)  hello
##
## Cost per hop: two Gimli calls to open the 16 address bytes, two to seal
## them again. The payload is not copied into any key operation.
##
## Neighbours, the directory, permission and the way onward are shared with
## relaySlowExtractEncrypt: see relay_node.nim. The bytes of an ART frame:
## docs/routing.md, section 4.
##
## Example 1. A relay with a phone and a nas:
##
##   var R = initRelayFastExtraFrame(0x10'u64)
##   R.addRelayTarget(0x20'u64, "nas", ["phone"])
##   discard R.admitRelayNeighbour(linkWithPhone, 0x30'u64, "phone",
##     phoneAddress, acrDac)
##   discard R.admitRelayNeighbour(linkWithNas, 0x20'u64, "nas",
##     nasAddress, acrDac)
##   var step = R.feedRelayFastExtraFrame(fromAddress, datagram, nowMs)
##   for s in step.send: sendTo(s.address, s.frame)

import ../transport/types as transport_types
import ../ame/level2/route_wire
import ./relay_node
import runePragmas

type
  ## RelayFastExtraFrame: one node of relayFastExtraFrame.
  RelayFastExtraFrame* {.role: truthState, expectedCount: 1,
      lifeCycle: lcForever.} = object of RelayNode

proc initRelayFastExtraFrame*(selfId: uint64,
    capacity: int = relayCapacity): RelayFastExtraFrame {.
    role: configurator, tag: "appApi".} =
  ## selfId: this node's own id; frames for it are delivered here.
  ## capacity: how many neighbours fit; a ceiling, not a target.
  setupRelayNode(result, rkFastExtraFrame, selfId, capacity)

proc feedRelayFastExtraFrame*(R: var RelayFastExtraFrame, slot: int,
    frame: openArray[uint8], nowMs: uint32): RelayStep {.
    role: orchestrator, tag: "appApi".} =
  ## R: the node. slot: the neighbour the datagram came from.
  ## frame: an ART route frame, or an AME kind 0x14 directory question --
  ##   told apart by its first bytes.
  ## nowMs: caller's millisecond clock (return notes expire by it).
  ## Nothing here raises, so a neighbour cannot stop the node with junk.
  if droppedFromEmptySlot(R, slot, result):
    return
  if not isAmeRouteFrame(frame):
    return feedRelayControl(R, slot, frame)
  result = feedOpenedRelayFrame(R, slot,
    openAmeRouteFrame(R.neighbours[slot].session, frame), nowMs)

proc feedRelayFastExtraFrame*(R: var RelayFastExtraFrame,
    source: transport_types.UdpAddress, frame: openArray[uint8],
    nowMs: uint32): RelayStep {.role: orchestrator, tag: "appApi".} =
  ## R: the node. source: the address the datagram came from; it names the
  ## neighbour, and with it the keys. A stranger's datagram is dropped.
  result = feedRelayFastExtraFrame(R, relaySlotOf(R, source), frame, nowMs)
