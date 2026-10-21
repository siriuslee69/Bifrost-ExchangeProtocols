## -------------------------------------------------------------------------
## relaySlowExtractEncrypt Example <- a relay that reads what it carries and
##                                    refuses writes from the phone
## -------------------------------------------------------------------------
##
##   phone (0x30) ==link A==> relay (0x10) ==link B==> nas (0x20)
##   192.0.2.30:40030         198.51.100.10:47656       192.0.2.20:40020
##
##   1. phone sends "R:/notes" (a read)   -> the relay lets it through
##   2. phone sends "W:/notes" (a write)  -> the relay refuses it
##
## Unlike relayFastExtraFrame there is no second, end-to-end handshake: each
## link is its own AME session, and the relay opens one and seals the other.
## That is exactly what lets it judge the content -- and why the nas must
## trust the relay.

import std/strutils

import bifrost_exchange_protocols
import ./relay_links

const
  idRelay: uint64 = 0x10'u64
  idNas: uint64 = 0x20'u64
  idPhone: uint64 = 0x30'u64

proc bytesOf(s: string): ByteSeq =
  ## s: text sent as bytes.
  result = newSeq[uint8](s.len)
  for i, c in s:
    result[i] = uint8(c)

proc textOf(A: openArray[uint8]): string =
  ## A: bytes shown as text.
  result = newString(A.len)
  for i, b in A:
    result[i] = char(b)

proc noWrites(identity: string, f: var AmeRouteFrame): bool =
  ## The relay's rule: a phone may read, but not write ("W:" in front).
  result = identity != "phone" or not textOf(f.payload).startsWith("W:")

when isMainModule:
  var
    a: tuple[left, right: AmeSession] = linkPair()   # phone <-> relay
    b: tuple[left, right: AmeSession] = linkPair()   # nas   <-> relay
    phoneAt: UdpAddress = initTransportAddress("192.0.2.30", 40030'u16)
    nasAt: UdpAddress = initTransportAddress("192.0.2.20", 40020'u16)
    relayAt: UdpAddress = initTransportAddress("198.51.100.10", 47656'u16)
    relay: RelaySlowExtractEncrypt = initRelaySlowExtractEncrypt(idRelay,
      inspect = noWrites)
    nasNode: RelaySlowExtractEncrypt = initRelaySlowExtractEncrypt(idNas, 1)
    step: RelayStep = default(RelayStep)
    answer: AmeRouteFrame = default(AmeRouteFrame)

  relay.addRelayTarget(idNas, "nas", ["phone"])
  doAssert relay.admitRelayNeighbour(a.right, idPhone, "phone", phoneAt,
    acrDac).ok
  doAssert relay.admitRelayNeighbour(b.right, idNas, "nas", nasAt, acrDac).ok
  doAssert nasNode.admitRelayNeighbour(b.left, idRelay, "relay", relayAt,
    acrDac, router = true).ok

  ## 1. A read: the relay opens it, its rule says yes, it seals it for B.
  step = relay.feedRelaySlowExtractEncrypt(phoneAt,
    a.left.sealSlowForward(acrDac, idNas, bytesOf("R:/notes")), 0'u32)
  echo "relay read     \"", textOf(step.frame.payload), "\" -> ", step.event
  step = nasNode.feedRelaySlowExtractEncrypt(relayAt, step.send[0].frame,
    0'u32)
  echo "nas got        \"", textOf(step.frame.payload), "\" from 0x",
    toHex(step.frame.origin, 2)

  ## 2. A write: refused, and the refusal goes back to the phone's address.
  step = relay.feedRelaySlowExtractEncrypt(phoneAt,
    a.left.sealSlowForward(acrDac, idNas, bytesOf("W:/notes")), 0'u32)
  doAssert step.send[0].address == phoneAt
  answer = a.left.openSlowFrame(acrDac, step.send[0].frame)
  echo "relay refused  \"W:/notes\" -> phone hears ", answer.kind, " ",
    answer.refusal
