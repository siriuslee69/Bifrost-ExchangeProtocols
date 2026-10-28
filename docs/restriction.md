# Restriction modes: who may talk to whom on a relay

A relay that carries traffic between machines has two separate questions to
answer. They are kept apart on purpose, because they are different things:

```text
  question 1: HOW is a frame carried?     -> the RELAY MODE      (3 modes)
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

## 2. The three restriction modes (and open)

Each restriction mode answers "may this frame pass from neighbour A to
neighbour B?" in its own way. The table is the one to read first.

```text
  mode        decides by                          cost                   good for
  ----------  ----------------------------------  ---------------------  ----------------------------
  rmOpen      nothing: every pair may talk        none                   a relay with no need
  rmGroup     one sequence of (member, server)    one short entry per   many clients, one server
                                                  member                 behind the relay
  rmListed    per recipient: accept and reject    a list per recipient   versatile; lists to keep
              lists of SOURCE ADDRESSES                                  up to date
  rmProfile   a profile index chosen by the       one small index per    targets that change
              device, naming a predefined set     device                 quickly
```

### 2.1 rmGroup: one sequence of pairs

Def. 1. One entry names a member and the one server it may talk to. Two
devices may exchange frames only when an entry names them as
(member, server) in either order.

```text
  entries:  (phone, nas)    (laptop, nas)    (cam, nas)

  phone  -> nas        allowed   (phone, nas)
  nas    -> phone      allowed   (phone, nas), reverse
  phone  -> laptop     REFUSED   no entry pairs them
```

The server declares its own members, with a control frame (see section 4).
A member already claimed by another server is refused. One sequence, one
short record per member: this is the cheapest mode for many clients.

### 2.2 rmListed: accept and reject lists of addresses

Def. 2. The recipient keeps two lists of SOURCE ADDRESSES, the address a
frame arrived FROM at this relay. Reject wins over accept. An empty accept
list accepts every address that is not rejected.

```text
  nas: reject 203.0.113.9:0        (port 0 = any port; host "*" = any host)

  frame from 203.0.113.9  -> nas     REFUSED  (reject matches)
  frame from 198.51.100.4 -> nas     allowed  (no accept list, not rejected)
```

This is the mode that can name exact addresses and ports. It costs a list
per recipient, so it is the one to keep small.

### 2.3 rmProfile: a predefined target set, chosen by index

Def. 3. The operator fixes a table of target sets when the relay starts.
Profile 0 is the empty set: a device on it reaches nobody. Each device
carries one index into that table, and may reach exactly the identities in
the set it names.

```text
  operator's table:   profiles[0] = []           (nobody)
                      profiles[1] = [nas]        (the server)
                      profiles[2] = [nas, cam]   (the server and the camera)

  phone chose 1:  phone -> nas     allowed
                  phone -> cam     REFUSED
  phone chose 2:  phone -> cam     allowed       (one byte changed, no re-key)
```

This is the mode for targets that change often: the device switches its
index, and nothing else about its connection moves.

## 3. Choosing a mode

### At compile time

One define, `bifrostRestriction`, decides which modes are in the binary.
A mode that is not compiled in has no code: its checks, its update and its
rule scan are behind a `when`.

```text
  -d:bifrostRestriction=all              every mode (default)
  -d:bifrostRestriction=group            only the group sequence
  -d:bifrostRestriction=listed           only the accept and reject lists
  -d:bifrostRestriction=profile          only the predefined profiles
  -d:bifrostRestriction=group,profile    any comma-separated set
```

The data shape and the wire codec are always compiled. A relay built for one
mode therefore still reads what other modes' devices send, and says which
mode it lacks, rather than failing to parse.

### At run time

When the binary has the mode, the operator switches it on with
`setRelayRestriction(R, mode)`. When the binary does not, the call returns
the reason and the mode stays as it was:

```text
  setRelayRestriction(R, rmGroup)   -> ""                       (switched on)
  setRelayRestriction(R, rmListed)  -> "not compiled into this relay"
                                       (the relay stays in rmGroup)
```

## 4. How a device sets its part: AME kind 0x17

A device changes its own restriction by sending ONE AME control frame, kind
`0x17`, on its link to the relay. The frame is sealed by the link's ratchet
like every control frame. Bifrost reads it; no application sees it, and the
relay acknowledges it with a frame of the same kind.

```text
  offset  field
  ------  ----------------------------------------------------------------
  0       version: 1 = update, 2 = acknowledgement
  1       op (update only): 1 listed, 2 profile, 3 group
  2...    the op's payload

  listed   u8 accept count | rules | u8 reject count | rules
  profile  u8 index
  group    u8 count | (u16 length | member identity) per member
           the sender is the server; every member is claimed by it

  rule = u16 host length | host bytes | u16 port
```

A body that is cut short, has an unknown version or op, or a count above the
limit (32 rules, 255 members) is refused with a reason. A refused update gets
no answer.

## 5. What is refused, and how

A forward that a restriction refuses is dropped **silently**: the relay sends
nothing back. An answer would tell the sender that the relay exists and what
it knows, and a junk sender learns nothing from silence. The drop is counted
in `restricted`, separately from ordinary drops.

Every relay forward goes through one check, `restrictionAllows`, in the step
that decides where a frame goes next. A frame delivered to the relay itself
is not checked against restrictions, because there is no second party.

The book (groups, lists, profiles, and the operator's profile table) is kept
through **Geist**, the storage library. `attachRestrictionBook(R, dir)` reads
it when the relay starts, and every accepted update is saved before the
acknowledgement goes out. A save that fails refuses the update, so the device
never believes a change that the relay would forget on restart.

## 6. Relay mode against restriction mode

```text
  relay mode               group    listed    profile    notes
  -----------------------  -------  --------  ---------  ------------------------------
  relaySuperFastUDP        no       no        no         no keys: it cannot read kind
                                                         0x17, so devices cannot set
                                                         their part. A list set by the
                                                         operator is possible later.
  relayFastExtraFrame      yes      yes       yes        tested: tests/test_relay_restriction.nim
  relaySlowExtractEncrypt  yes      yes       yes        the same check and the same
                                                         control path; no test of its own yet
```

`relaySuperFastUDP` holds no key, so it cannot read a device's restriction
frame and cannot apply one. Its restriction would have to come from the
operator, not from the devices.

## 7. Limits

- The check is per HOP: it compares two neighbours of this relay. A frame
  that passes through several relays is checked at each one, not end to end.
- rmListed compares the address a frame arrived FROM. Behind a NAT that is
  the NAT's address, so the rule names the translated address.
- rmProfile and rmGroup name devices by identity (the pinned name the
  handshake proved). A device that reconnects under the same identity keeps
  its entries.
- Nothing here removes a device from the relay. Restrictions decide who may
  talk to whom; who may connect at all is decided by the handshake and its pins.
