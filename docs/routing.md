# relayFastExtraFrame: routing through relays

One of three relays (README, "Three relays, side by side"). The shared part
-- neighbours, directory, permission, the way onward -- is
`src/protocols/relay/relay_node.nim`; relaySlowExtractEncrypt uses the same
rules with a different frame (`slow_envelope.nim`).

╭⟢ 1. What it is, in plain words 🌊
├⟢ 2. Using it 🐦‍🔥
├⟢ 3. The words ✦
├⟢ 4. The bytes 🍣
├⟢ 5. Replay ⟡
├⟢ 6. Who may send to whom ❧
├⟢ 7. Where a forward goes, hop by hop ❧
├⟢ 8. What is hidden, and from whom ⌜guide⌟
╰⟢ 9. Limits and edge cases ୨୧

## 1. What it is, in plain words 🌊

A phone wants to talk to a home server it cannot reach directly. It makes
ONE ordinary AME handshake: with a router. That gives the two of them a
shared secret and an AME session -- a **link**.

On that link the phone can now send two different things:

```text
  "AME" frame   a message for the ROUTER ITSELF, sealed by FOMKE as always
                (e.g. "which targets may I reach?")
  "ART" frame   a message for someone BEHIND the router: a route frame
```

A route frame encrypts only the ADDRESS -- who it is for and who it is
from, 16 bytes -- with the link's key. The payload behind it is passed on
byte for byte. The phone puts its own end-to-end AME handshake (AM1S or
AM1P) with the target in that payload, and later the session that
handshake opens. No router holds that key.

```text
  phone ==link A==> router 1 ==link B==> router 2 ==link C==> nas
          |                  |                  |
          address sealed     address opened     address opened
          with A             with A, sealed     with B, sealed
                             again with B       again with C
          payload: the phone<->nas handshake, then session frames,
                   the same bytes on every link
```

Every node checks the address: if the target is its own id, the payload is
for it; otherwise it passes the frame on, one hop closer.

So:

```text
  a watcher on one link    sees neither target nor origin
  a router                 sees target and origin, never the content
  only phone and nas       can read the content
```

## 2. Using it 🐦‍🔥

Every node -- relay or endpoint -- is a `RelayFastExtraFrame` with its own
route id. An endpoint simply has one link, to its relay.

```nim
import bifrost_exchange_protocols

# A finished AME handshake with the router gave `link` (an AmeSession).
var me = initRelayFastExtraFrame(0x30'u64)            # my route id
discard me.admitRelayNeighbour(link, 0x10'u64, "router1", relayAddr,
  acrDac, router = true)

# 1. Ask the router itself whom I may reach (an ordinary AME frame).
send(router, link.sealAmeRouteAsk(acrDac))
var dir = link.openAmeRouteDirectory(acrDac, recv(router))
for e in dir.entries: echo e.id, " ", e.name           # 32 "nas"

# 2. Send through it: the payload is my end-to-end AME frame with the nas.
send(router, link.sealAmeRouteForward(0x20'u64, e2eFrame))

# 3. Whatever comes back:
var datagram = recv(router)
var step = me.feedRelayFastExtraFrame(relayAddr, datagram, nowMs)
if step.event == reDelivered:
  handleEndToEnd(step.frame.origin, step.frame.payload)
```

The program owns sockets and link handshakes; the relay module only
decides. It is fed with the address a datagram came FROM (that address
names the neighbour, and with it the link keys), and every frame it
returns names the address it must go TO:

```nim
var R = initRelayFastExtraFrame(0x10'u64)
R.addRelayTarget(0x20'u64, "nas", ["phone"])          # directory line
discard R.admitRelayNeighbour(linkWithPhone, 0x30'u64, "phone", phoneAddr,
  acrDac)                                               # after the handshake

# ART frames and directory questions (AME kind 0x14) go in the same way
var step = R.feedRelayFastExtraFrame(fromAddress, datagram, nowMs)
for s in step.send:
  sendTo(s.address, s.frame)
```

Runnable, with a real end-to-end AM1P handshake through the router:
`nimble exampleRelayFast`. Tests:
`evaluation/tests/test_relay_fast_extra_frame.nim` (in `nimble test`).

## 3. The words ✦

**Def. 1 (link).** An ordinary AME session between two neighbours. Its
handshake proves who the neighbour is. Beside its FOMKE keys, every epoch
of it derives a **route key** per direction (label `AME-ROUTE-BLOCK-v1`).

**Def. 2 (route id).** A u64 that names one node. `0` is reserved: it
means "not filled in".

**Def. 3 (node).** Anything holding a `RelayFastExtraFrame`: a relay, or an
endpoint with one link. Its own id is `selfId`.

**Def. 4 (peer).** One neighbour of a node, in a numbered SLOT, with its
link session, its route id and its **identity**: the name the caller proved
during the link handshake (a pin name, an authority name).

**Def. 5 (router peer).** A peer marked `router = true`. Its origin ids are
believed. A client's never are: the first router writes the client's own,
proved id.

**Def. 6 (target).** A line in a node's directory:

```text
  id      name     visibleTo            via
  0x20    "nas"    ["phone", "laptop"]  0x11     <- behind router 0x11
  0x21    "cam"    ["*"]                0        <- a peer of this node
```

**Def. 7 (return note).** A short-lived memory: "origin X wrote from behind
router peer R to target T". It is made when a forward from a router peer is
passed on, lives 120 seconds after the last such forward, and is the only
way T's answer finds X. At most 256 are kept; the oldest is replaced.

**Def. 8 (hops).** A counter in every forward. A client starts it at 6.
Each router takes one. At zero the forward is refused.

## 4. The bytes 🍣

### 4.1 The route frame

```text
  offset  size  field
  ------  ----  ---------------------------------------------------------
  0       3     magic "ART"
  3       1     version 0x01
  4       1     kind: 0x01 forward, 0x02 refuse
  5       1     forward: hops left    refuse: reason
  6       8     session id, u64 LE    -- which link
  14      4     route counter, u32 LE -- this link's, one per frame
  18      16    target id + origin id, sealed
  34      8     tag
  42      n     payload (forward only)
```

42 bytes in front of the payload. Refusal reasons:

```text
  0x01  no route      no such id, OR not visible to you (deliberately the
                      same answer, so ids cannot be probed)
  0x02  hops spent    the forward came in with hops = 0
  0x03  unreachable   known and allowed, but that link could not take it
                      right now (try again later)
```

```text
  kind      target                   origin
  --------  -----------------------  -------------------------------------
  forward   where it should end up   0 from a client (the first router
                                     fills it); the real origin after that
  refuse    what was refused         who it is being refused to
```

### 4.2 Sealing the 16 address bytes, with Gimli

Gimli is a 48-byte state, mixed by one fixed routine (the permutation).

```text
  state  = nonce (16 bytes) | route key (32 bytes)
  mix the state
  sealed = first 16 bytes of the state XOR (target | origin)
  first 16 bytes of the state := sealed
  last byte of the state      := last byte XOR 0x01   ("last block")
  mix the state
  tag    = first 8 bytes of the state
```

The nonce is the frame's own clear header:

```text
  byte   0 1 2  3    4     5             6  7   8 ....... 11   12 ..... 15
         A R T  01   kind  hops/reason   00 00  counter u32    payload len
```

So the 8-byte tag covers both ids, the kind, the hop count or reason, the
counter and the payload LENGTH. It does not cover the payload's CONTENT;
the end-to-end session does that at the far end, with its own tag. The
session id (offset 6) is not in the nonce; it is checked against the link,
and an edited one makes the frame drop.

Example 1. phone (0x30) -> router -> nas (0x20), payload P:

```text
  phone -> router  ART 01 | 01 | 06 | link A id | A ctr 7  | seal_A(20.., 00..) | P
  router -> nas    ART 01 | 01 | 05 | link B id | B ctr 91 | seal_B(20.., 30..) | P
                                 ^ hops - 1                 ^ new key, new nonce
```

### 4.3 The directory question (inside FOMKE)

An ordinary AME frame, kind `0x14`, sealed by the link's ratchet. Inside:

```text
  ask        01 | start u16
  directory  02 | start u16 | total u16 | count u8 |
                  count x (id u64 | name length u8 | name, <= 32 bytes)
```

A page holds at most 24 entries (about 1 KB):

```text
  ask start 0   -> start 0,  total 50, 24 entries
  ask start 24  -> start 24, total 50, 24 entries
  ask start 48  -> start 48, total 50,  2 entries
  ask start 99  -> start 50, total 50,  0 entries     <- past the end: empty
```

## 5. Replay ⟡

Each link side counts its route frames (`nextRouteCounter`) and keeps the
last 64 counters it accepted from its peer (`routeReplay`):

```text
  frame 41 arrives        -> tag ok, 41 is new        -> accepted
  frame 41 arrives again  -> tag ok, 41 already seen  -> dropped
  frame 39 after 41       -> tag ok, 39 is new        -> accepted (late)
  frame 30 after 100      -> older than the window    -> dropped
```

The counter is in the nonce, so editing it breaks the tag. The window moves
only AFTER the tag checked out, so a forged counter cannot push honest
frames out of it. A replay is stopped at the first router it reaches; it
never costs the next link anything and never reaches the target.

This counter never gets out of step the way a ratchet can: it is only a
nonce, and the route key does not change per frame. Any counter ahead of
the last one is fine, however far ahead -- losing frames costs nothing.

The end-to-end session inside has its own protection against replay
(FOMKE's), so a replayed payload would be refused at the target even if it
were re-wrapped in a new route frame.

## 6. Who may send to whom ❧

> The per-relay restriction modes (group, listed, profile) and how devices set
> them are described in [restriction.md](restriction.md).

```text
  sender         target                      allowed when
  -------------  --------------------------  ----------------------------------
  anyone         this node itself            always: the end-to-end handshake
                                             decides
  a router peer  anything                    always: the router before it
                                             already checked
  a client       a directory line            its identity is in `visibleTo`
                                             (or `visibleTo` has "*")
  a client       another peer of this node   the reverse is allowed: that peer
                                             may write to the client. Whoever
                                             may write to you may be answered.
  a client       an origin from far away     a live return note says that
                                             origin wrote to THIS client
```

## 7. Where a forward goes, hop by hop ❧

At every node, in this order:

```text
  route frame arrives on slot s
        |
        v
  open the address with s's route key -- fails / replay -> drop, no answer
        |
        v
  origin := s's id (client) or the frame's origin (router peer)
        |
        v
  target is my own id? ---------------------- yes  -> delivered here
        |
        v
  hops = 0 ? -------------------------------- yes  -> refuse "hops spent"
        |
        v
  allowed (section 6)? ---------------------- no   -> refuse "no route"
        |
        v
  1. a peer with that id here?             -> forward to it
  2. a line with via = router R?           -> forward to R
  3. a return note for that id?            -> forward to the router it came from
  4. none, or it would go back out s       -> refuse "no route"
        |
        v
  seal the address for the next link ------ fails -> refuse "unreachable"
        |
        v
  came from a router peer? -> make / refresh the return note
```

Example 2. Two routers and the way back:

```text
  router 1: line  0x20 "nas" visibleTo ["phone"] via 0x11
            peers phone 0x30, router2 0x11 (router)
  router 2: line  0x20 "nas" visibleTo ["router1"]
            peers router1 0x10 (router), nas 0x20

  phone   -> R1    forward 0x20                 rule: directory line
  R1      -> R2    forward 0x20 from 0x30       line via 0x11
  R2      -> nas   forward 0x20 from 0x30       peer here; note "0x30 via R1"
  nas              0x20 is me                   delivered
  nas     -> R2    forward 0x30                 rule: return note
  R2      -> R1    forward 0x30 from 0x20       return note
  R1      -> phone forward 0x30 from 0x20       peer here
  phone            0x30 is me                   delivered
```

A refusal from a later router travels back the same way: a node that gets
a refusal from a router peer passes it on toward its `origin`, or keeps it
when the origin is itself.

## 8. What is hidden, and from whom ⌜guide⌟

```text
  who                      sees                         does not see
  -----------------------  ---------------------------  --------------------
  a watcher on one link    that a route frame passed,   target, origin,
                           its length, the link's       content
                           counter
  a router                 target, origin, length       content
  the target               origin (by id), content      the path it took
```

Limits, said plainly:

- **The payload is the same bytes on every link.** Someone watching BOTH
  sides of a router can match a frame going in to one coming out by its
  payload, and so learn where it went. This is the price of not encrypting
  the payload per hop.
- **Length is visible.** Padding inside the end-to-end session helps.
- **The tag does not cover the payload's content.** Someone on a link can
  swap the payload for other bytes of the same length; the frame is passed
  on and the target's end-to-end session refuses it. That is the same as
  dropping it, which they could do anyway.
- **Routers are trusted about origins** when they are marked as router
  peers. Mark only routers you run.

## 9. Limits and edge cases ୨୧

```text
  what                            limit / behaviour
  ------------------------------  --------------------------------------------
  route id 0                      reserved; refused everywhere
  a peer with the node's own id   refused by admitRelayNeighbour
  one id, two slots               refused: "relay id is already connected"
  one address, two slots          refused: "relay address is already connected"
  datagram from an unknown        dropped: "relay slot is empty" (also after
  address                         a NAT gives the client a new port)
  neighbours per node             512 by default
                                  (initRelayFastExtraFrame(id, capacity))
  name length                     32 bytes
  directory page                  24 entries, about 1 KB of body
  route frame overhead            42 bytes
  route counter                   2^32 - 1 frames per link, then a new
                                  handshake ("AME route counter is exhausted")
  replay window                   64 frames per link side
  return notes                    256, 120 s after the last refresh
  frame from an empty slot        dropped, counted in `dropped`
  refusal from a client           dropped
  while a link rotates its epoch  route frames wait, like every other frame
                                  (the route key changes with the epoch)
  a released slot                 session and keys erased; a return note
                                  remembers a router's ID, not its slot
```

Over DAC a route frame is one datagram, so keep the payload under the link
MTU minus 42.
