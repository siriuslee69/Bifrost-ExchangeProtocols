# Restriction modes: who may talk to whom on a relay

A relay that carries traffic between machines has two separate questions to
answer. They are kept apart on purpose, because they are different things:

```text
  question 1: HOW is a frame carried?     -> the RELAY MODE       (3 modes)
  question 2: WHO may reach WHOM?         -> the RESTRICTION MODE (3 modes + open)

  relay mode: what the machine in the middle can READ and must re-seal
  restriction mode: which pairs of neighbours a frame may pass between
```

Both are chosen per relay. A relay always has one relay mode, and at most
one restriction mode in force.

## 1. The three relay modes (implemented)

These carry frames. They are described in the README ("Three relays") and
in `docs/routing.md`. Repeated here so the two axes can be compared.

```text
  relay mode               module                        the middle machine ...
  -----------------------  ----------------------------  --------------------------
  relaySuperFastUDP        relay/super_fast_udp.nim      moves bytes, holds no key
  relayFastExtraFrame      relay/fast_extra_frame.nim    re-seals 16 address bytes
  relaySlowExtractEncrypt  relay/slow_extract_encrypt.nim opens, reads, re-seals all
```

## 2. The restriction modes (and open)

Each restriction mode answers "may this frame pass from neighbour A to
neighbour B?" in its own way. The table is the one to read first.

```text
  mode        decides by                          set by          cost
  ----------  ----------------------------------  --------------  -----------------
  rmOpen      nothing: every pair may talk        operator        none
  rmGroup     one group object: members,          an endpoint     one link per member
              endpoints, and the links between    (control frame)
  rmListed    the target's accept and reject      the target      a list per target
              lists of SOURCE ADDRESSES           device
  rmAllowed   the target's allowed list: who      the target      a list per target
              may reach it (empty = nobody)       device
```

### 2.1 Addresses in compact form

Every list is made of addresses, so each one is stored in the smallest form
that keeps its meaning. The relay converts a neighbour's address ONCE, when it
joins, and compares bytes after that.

```text
  Def. 1 (SourceAddr): one address a frame can arrive from.

  family   what follows                        size
  -------  ----------------------------------  ----------------------------
  0        nothing: any host (text "*")        0 bytes
  4        IPv4, packed: four uint8            4 bytes   (10, 0, 0, 49)
  6        IPv6, network order: sixteen uint8  16 bytes  (2001:db8::1)

  port     uint16; 0 matches any port          2 bytes
```

Text forms accepted when the operator writes a list:

```text
  IPv4   10.0.0.49            four parts, each 0 to 255
  IPv6   2001:db8::1          eight groups, "::" once for a run of zero groups
         2001:0db8:0:0:0:0:0:1 the same address written in full
         ::ffff:10.0.0.49    an IPv4 tail, written as dotted quad
  any    *                    any host (family 0)
```

A relay prints an address back in full IPv6 form, so an operator can compare
two addresses by eye: `2001:0db8:0000:0000:0000:0000:0000:0001`. With a port,
IPv6 goes in brackets, as in `[2001:0db8:0000:0000:0000:0000:0000:0001]:47656`,
so the port cannot be read as the last group.

### 2.2 rmGroup: one object, members and endpoints

Def. 2. The group is ONE object held by the relay:

```text
  GroupBook
  ---------------------------------------------
  members    every device a server claimed     [phone, laptop, cam]
  endpoints  every server that claimed some   [nas, cam-server]
  links      (member, endpoint) index pairs    (0,0) (1,0) (2,1)

  phone -> nas        allowed    (link 0: phone, nas)
  nas   -> phone      allowed    the same link, the other way
  phone -> laptop     REFUSED    no link joins two members
```

A member talks to an endpoint only over a link, and never to another
member. One device may belong to one endpoint only: a claim that names a
device already linked elsewhere is refused. A server that claims again
replaces only its own links.

Memory: a member is one name and a link is two small numbers.

### 2.3 rmListed: accept and reject lists of addresses

Def. 3. Each connection keeps two lists of SOURCE ADDRESSES. Reject wins over
accept. An empty accept list accepts every address that is not rejected.

```text
  nas: reject 203.0.113.9:0        (port 0 = any port)

  frame from 203.0.113.9  -> nas     REFUSED  (reject matches)
  frame from 198.51.100.4 -> nas     allowed  (no accept list, not rejected)
```

This mode can name exact addresses and ports. It costs a list per
connection, so it is the one to keep small.

### 2.4 rmAllowed: who may reach ME

Def. 4. Each connection keeps ONE list: the senders allowed to reach it.

```text
  allowed list     who may send TO this connection
  empty list       nobody may reach it (the default for a new connection)
  outbound         unrestricted: a connection on an empty list can still
                   send to any connection that allows it

  phone:  allowed = []            nobody reaches the phone
  nas:    allowed = [phone]       the phone reaches the nas

  phone -> nas     allowed     (nas names the phone)
  nas   -> phone   REFUSED     (phone's list is empty)
  laptop -> nas    REFUSED     (nas does not name the laptop)
```

The list names SENDERS, never receivers. A device changes only its own list,
so nobody else's connection moves when it does.

## 3. Choosing a mode

### At compile time

One define, `bifrostRestriction`, decides which modes are in the binary.
A mode that is not compiled in has no code: its checks, its update and its
scan are behind a `when`.

```text
  -d:bifrostRestriction=all              every mode (default)
  -d:bifrostRestriction=group            only the group object
  -d:bifrostRestriction=listed           only the accept and reject lists
  -d:bifrostRestriction=allowed          only the allowed lists
  -d:bifrostRestriction=group,allowed    any comma-separated set
```

The data shape and the wire codec are always compiled. A relay built for one
mode therefore still reads what other modes' devices send, and says which
mode it lacks, rather than failing to parse.

### At run time

When the binary has the mode, the operator switches it on with
`setRelayRestriction(R, mode)`. When the binary does not, the call returns
the reason and the mode stays as it was:

```text
  setRelayRestriction(R, rmGroup)   -> ""                          (switched on)
  setRelayRestriction(R, rmListed)  -> "not compiled into this relay"
                                       (the relay stays where it was)
```

## 4. How a device sets its part: AME kind 0x17

A device changes its own part by sending ONE AME control frame, kind `0x17`,
on its link to the relay. The frame is sealed by the link's ratchet like
every control frame. Bifrost reads it; no application sees it, and the relay
acknowledges it with a frame of the same kind.

```text
  offset  field
  ------  ----------------------------------------------------------------
  0       version: 1 = update, 2 = acknowledgement
  1       op (update only): 1 listed, 2 allowed, 3 group
  2...    the op's payload

  listed   u8 accept count | addresses | u8 reject count | addresses
  allowed  u8 count | addresses
  group    u8 count | (u16 length | member identity) per member
           the sender is the endpoint; every member is claimed by it

  address  = u8 family | bytes for that family | u16 port
             family 0: no bytes        family 4: 4 bytes
             family 6: 16 bytes
```

A body that is cut short, has an unknown version, op or family, or a count
above the limit (32 addresses, 255 members) is refused with a reason. A
refused update gets no answer.

## 5. What is refused, and how

Every relay forward goes through one check, `restrictionAllows`, in the step
that decides where a frame goes next. The check runs at EVERY relay on the
way, against the neighbour the frame is about to go to. A frame delivered to
the relay itself is not checked, because there is no second party.

A refused frame gets an answer, but not every time:

```text
  Def. 5 (answer gap): the least time between two answers to one neighbour.
         Default 1000 ms. Each neighbour has its own clock.

  restricted frame arrives from neighbour N at time t
     |
     +-- N was never answered, or t - last answer >= gap?
     |     yes -> answer N: "no route" (arrNoRoute), last answer = t
     |     no  -> drop silently
     |
     +-- counted in `restricted` either way
```

The answer is the same one a missing route gets. A sender cannot tell "this
target is restricted" from "this target does not exist", so the answer reveals
nothing about who is connected. The gap stops a sender from using the relay
as a reflector, while still telling an honest sender that its frame went
nowhere.

```text
  setRestrictionAnswerMs(R, 1000)   one answer per second per neighbour (default)
  setRestrictionAnswerMs(R, 0)      never answer; every refusal is silent
```

The book (the group object and every connection's lists) is kept through
**Geist**, the storage library. `attachRestrictionBook(R, dir)` reads it when
the relay starts, and every accepted update is saved before the
acknowledgement goes out. A save that fails refuses the update, so the device
never believes a change that the relay would forget on restart.

## 6. The super-fast relay: an operator's list

`relaySuperFastUDP` holds no key and reads no frame, so a device cannot set
its part. Its restriction comes from the operator, and is checked on the
client's address before the client takes a table slot:

```text
  setSuperFastRestriction(F, mode, rules)

  rmOpen      default: every client passes, no address is parsed
  rmListed    rules.accept / rules.reject on client addresses
  rmAllowed   rules.allowed: the clients that may send to the NAS
  rmGroup     REFUSED: the group comes from control frames, which this relay
              never opens
```

A refused client takes no slot, so a stranger sending from many addresses
cannot use up the table. Refused datagrams are dropped and counted in
`restricted`, **never answered**: this relay carries bytes the NAS reads, and
there is no reply format a client would read as a refusal. Adding one would
change the wire, so it is left for a decision.

While a restriction is set, the client's address text is converted to the
compact form for each datagram. The default `rmOpen` never does this.

## 7. Relay mode against restriction mode

```text
  relay mode               group    listed   allowed   notes
  -----------------------  -------  -------  --------  -----------------------------
  relaySuperFastUDP        no       yes *    yes *     * operator's list only; no
                                                        answers (section 6)
  relayFastExtraFrame      yes      yes      yes       answers by the gap (section 5)
  relaySlowExtractEncrypt  yes      yes      yes       the same check, the same answer
```

Tests, one file per row:

```text
  evaluation/tests/test_restriction_address.nim     text forms, matching
  evaluation/tests/test_relay_restriction.nim       codec, every mode, the answer gap
  evaluation/tests/test_relay_slow_restriction.nim  relaySlowExtractEncrypt
  evaluation/tests/test_relay_super_fast_restriction.nim  the operator's list
```

## 8. Limits

- The check is per HOP: it compares two neighbours of this relay. A frame
  that passes through several relays is checked at each one, not end to end.
- Connections are matched by the address a frame ARRIVED FROM. Behind a NAT
  that is the NAT's address, so a rule names the translated address.
- A neighbour whose address is a host name, not an IP, is refused at join:
  the relay cannot compare a name to an address.
- Group, listed and allowed name devices by identity (the pinned name the
  handshake proved). A device that reconnects under the same identity keeps
  its entries.
- Nothing here removes a device from the relay. Restrictions decide who may
  talk to whom; who may connect at all is decided by the handshake and its pins.
