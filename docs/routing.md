# Routing through AME routers

╭⟢ 1. What it is, in plain words 🌊
├⟢ 2. Using it 🐦‍🔥
├⟢ 3. The words ✦
├⟢ 4. The bytes 🍣
├⟢ 5. Who may send to whom ⟡
├⟢ 6. Where a forward goes, hop by hop ❧
├⟢ 7. What each layer protects, and what it does not ⌜guide⌟
╰⟢ 8. Limits and edge cases ୨୧

## 1. What it is, in plain words 🌊

A phone wants to talk to a home server. Before this, it had two options:
make a handshake with the home server itself (and find a way to reach it),
or send bytes through a relay that does not understand them.

Now there is a third. The phone makes ONE handshake, with a router. Then it
asks the router "who may I reach?", picks one, and hands the router a
message for it. The router passes it on over its own session with the next
machine. That machine may be the target, or another router.

```text
  phone ==session A==> router 1 ==session B==> router 2 ==session C==> nas
          one handshake          set up by the routers, not by the phone
```

Each `==X==>` is one AME session. Each router opens the message with one
session and seals it again with the next. **Every router can read the
message.** That is the trade: no handshake with the far end, but trust in
every router on the way. When a router must not read it, put an
end-to-end AME session inside the payload.

## 2. Using it 🐦‍🔥

The client side (phone):

```nim
import bifrost_exchange_protocols

# `phone` is the AME session the handshake with the router produced.
send(router, phone.sealAmeRouteAsk(acrDac))           # who may I reach?
var got = phone.openAmeRouteFrame(acrDac, recv(router))
for e in got.entries: echo e.id, " ", e.name           # 32 "nas"

send(router, phone.sealAmeRouteForward(acrDac, 0x20'u64, payload))
```

The receiving side (nas) answers whoever wrote:

```nim
var m = nas.openAmeRouteFrame(acrDac, recv(router))
if m.ok and m.kind == arkDeliver:
  send(router, nas.sealAmeRouteForward(acrDac, m.origin, answer))
```

The router side owns sockets and handshakes; the router module only
decides:

```nim
var R = initAmeRouter()
R.addAmeRouteTarget(0x20'u64, "nas", ["phone"])      # directory line
var slot = R.admitAmeRoutePeer(sessionWithPhone, 0x30'u64, "phone",
  acrDac).slot                                         # after the handshake

var step = R.feedAmeRouteFrame(slot, datagram, nowMs)
for s in step.send:
  sendTo(addressOf(s.slot), s.frame)
```

A datagram on a router link is a route frame when byte 4 of its header
(the packet kind) is `0x14`; send every other kind where it went before.

Runnable: `nimble exampleRouter`. Tests: `evaluation/tests/test_ame_router.nim`
(in `nimble test`).

## 3. The words ✦

**Def. 1 (route id).** A u64 that names one machine for routing. `0` is
reserved: it means "not filled in".

**Def. 2 (peer).** One neighbour of a router, with a finished AME session,
held in a numbered SLOT. It has a route id and an **identity**: a name the
caller proved during the handshake (a pin name, an authority name).

**Def. 3 (router peer).** A peer marked `router = true`. Its origin ids are
believed. A client's never are: the router writes the client's own id.

**Def. 4 (target).** A line in a router's directory:

```text
  id      name     visibleTo            via
  0x20    "nas"    ["phone", "laptop"]  0x11     <- behind router 0x11
  0x21    "cam"    ["*"]                0        <- connects here itself
```

`"*"` shows the line to everyone. `via = 0` means the target is a peer of
this router.

**Def. 5 (return note).** A short-lived memory: "origin X wrote from
behind router peer R to target T". It is made when a forward arrives from
a router peer, lives 120 seconds after the last such forward, and is the
only way T's answer finds X. At most 256 are kept; the oldest is replaced.

**Def. 6 (hops).** A counter in every forward. A client starts it at 6.
Each router takes one. At zero the forward is refused.

## 4. The bytes 🍣

### 4.1 The outside: an ordinary AME control frame

```text
  offset  size  field
  ------  ----  ------------------------------------------------------
  0       26    AME header. Byte 4 (kind) = 0x14 Route. Byte 5 = class
                Control. Sequence (offset 22) masked as on every frame.
  26      13    FOMKE envelope
  39      16+   tag
  55      n     ciphertext: the route message below, sealed
```

An observer sees "a route frame" and its length. Nothing else.

### 4.2 Inside: the route message

The first plaintext byte says which of five messages it is:

```text
  kind  name       sent by            body after the kind byte
  ----  ---------  -----------------  -------------------------------------
  0x01  ask        anyone -> router   start u16
  0x02  directory  router -> asker    start u16 | total u16 | count u8 |
                                      count x (id u64 | len u8 | name)
  0x03  forward    anyone -> router   route block (24) | hops u8 | payload
  0x04  deliver    router -> target   route block (24) | hops u8 | payload
  0x05  refuse     router -> sender   route block (24) | reason u8
```

Refusal reasons:

```text
  0x01  no route      no such id, OR not visible to you (deliberately
                      the same answer, so ids cannot be probed)
  0x02  hops spent    the forward came in with hops = 0
  0x03  unreachable   known and allowed, but that link could not take
                      it right now (try again later)
```

### 4.3 The route block: the ids, sealed once more

```text
  offset  0 ........ 7   8 ........ 15  16 ............. 23
          target id      origin id      tag
          u64 LE         u64 LE         8 bytes
          \___ sealed with Gimli __/
```

```text
  message   target                  origin
  -------   ----------------------  ------------------------------------
  forward   where it should go      0 from a client (the router fills
                                    it); the real origin between routers
  deliver   the receiver itself     who sent it
  refuse    what was refused        who it is being refused to
```

How the 16 bytes are sealed, step by step (Gimli: a 48-byte state, mixed by
one fixed routine called the permutation):

```text
  state  = nonce (16 bytes) | key (32 bytes)
  mix the state
  sealed = first 16 bytes of the state XOR (target | origin)
  first 16 bytes of the state := sealed
  last byte of the state      := last byte XOR 0x01   ("last block")
  mix the state
  tag    = first 8 bytes of the state
```

The nonce:

```text
  offset  0  1  2  3   4     5..7      8 ........ 11   12..15
          A  M  R  B   kind  00 00 00  AME sequence    00 00 00 00
                                       u32 LE
```

The key is the session's **route key**: derived once per epoch per
direction, beside the header-protection key, with the label
`AME-ROUTE-BLOCK-v1`. A frame counter never repeats inside one epoch and
direction, so (key, nonce) never repeats.

Example 1. phone (0x30) -> router -> nas (0x20), payload "hi":

```text
  phone -> router   kind 0x03 | block(target 0x20, origin 0) | 06 | 68 69
  router -> nas     kind 0x04 | block(target 0x20, origin 0x30) | 05 | 68 69
                               ^ a NEW block: other session, other key,
                                 other frame counter
```

## 5. Who may send to whom ⟡

```text
  sender         target                      allowed when
  -------------  --------------------------  ----------------------------------
  a router peer  anything                    always: the router before it
                                             already checked
  a client       a directory line            its identity is in `visibleTo`
                                             (or `visibleTo` has "*")
  a client       another peer of this        the reverse is allowed: that
                 router                      peer may write to the client.
                                             Whoever may write to you may be
                                             answered.
  a client       an origin from far away     a live return note says that
                                             origin wrote to THIS client
```

Example 2. Directory `nas visibleTo ["phone"]`. The phone may write to the
nas. The nas has no line naming the phone, and may still answer it, by the
third rule.

The directory a client receives lists exactly the lines it may see; the
page holds at most 24, and `start`/`total` say where it is:

```text
  ask start 0   -> start 0,  total 50, 24 entries
  ask start 24  -> start 24, total 50, 24 entries
  ask start 48  -> start 48, total 50,  2 entries
  ask start 99  -> start 50, total 50,  0 entries     <- past the end: empty
```

## 6. Where a forward goes, hop by hop ❧

At every router, in this order:

```text
  forward arrives on slot s
        |
        v
  open with the session in s ------------- fails -> drop, no answer
        |
        v
  origin := s's id (client) or the block's origin (router peer)
        |
        v
  hops = 0 ? ----------------------------- yes  -> refuse "hops spent"
        |
        v
  allowed (section 5)? ------------------- no   -> refuse "no route"
        |
        v
  1. a peer with that id here?            -> deliver to it
  2. a line with via = router R?          -> forward to R
  3. a return note for that id?           -> forward to the router it came from
  4. none, or it would go back out s      -> refuse "no route"
        |
        v
  seal for the next slot ----------------- fails -> refuse "unreachable"
        |
        v
  came from a router peer? -> make / refresh the return note
```

Example 3. Two routers and the way back:

```text
  router 1: line  0x20 "nas" visibleTo ["phone"] via 0x11
            peers phone 0x30, router2 0x11 (router)
  router 2: line  0x20 "nas" visibleTo ["router1"]
            peers router1 0x10 (router), nas 0x20

  phone   -> R1   forward 0x20                  rule: directory line
  R1      -> R2   forward 0x20 from 0x30         line via 0x11
  R2      -> nas  deliver 0x20 from 0x30         peer here; note "0x30 via R1"
  nas     -> R2   forward 0x30                   rule: return note
  R2      -> R1   forward 0x30 from 0x20         return note
  R1      -> phone deliver 0x30 from 0x20        peer here
```

A refusal from a later router travels back the same way: a router that
gets a refusal from a router peer passes it on toward its `origin`.

## 7. What each layer protects, and what it does not ⌜guide⌟

```text
  layer         protects against                       does not
  ------------  -------------------------------------  -----------------------
  FOMKE (the    anyone on the wire: reading, editing,  the router itself -- it
  session)      replaying, telling kinds apart         holds the key
  route block   a target id that was not sealed for    the router -- it holds
                THIS frame, kind and direction; ids    this key too
                re-used across frames
  hops          loops between routers                  a router that resets it
  return notes  a target answering origins that never  a router lying about
                wrote to it                            origins (router peers
                                                       are trusted)
```

The 8-byte tag: forging it means guessing 64 bits, online, one frame per
guess, with every wrong guess dropped silently -- and the guess has to be
made from inside an authenticated session in the first place.

## 8. Limits and edge cases ୨୧

```text
  what                          limit / behaviour
  ----------------------------  ----------------------------------------------
  route id 0                    reserved; refused by addAmeRouteTarget and
                                admitAmeRoutePeer
  one id, two slots             refused: "AME route id is already connected"
  neighbours per router         512 by default (initAmeRouter(capacity))
  name length                   32 bytes
  directory page                24 entries, about 1 KB of body
  forward overhead              26 bytes before the payload (kind, block, hops)
  return notes                  256, 120 s after the last refresh
  frame from an empty slot      dropped, counted in `dropped`
  deliver/directory at a router dropped: not meant for a router
  refusal from a client         dropped
  a released slot               session and keys erased; a return note
                                remembers a router's ID, not its slot, so a
                                reused slot never inherits a note
```

The payload size is the carrier's business. Over DAC a forward is one
datagram, so keep `payload + 26 + ameFrameOverheadBytes(S)` under the link
MTU.
