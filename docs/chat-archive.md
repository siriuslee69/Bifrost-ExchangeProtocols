# Chat archive (draft) 🗄️

**Status: design draft. Nothing in this file is implemented yet.** Every
byte layout below is a proposal and may still change.

A messenger needs two things that pull in different directions:

```text
  posting box   two users swap messages while one of them is offline
  archive       a user opens every old message at any time, on any device
```

FOMKE (Forward-Only Message Key Extension) erases each message key after use,
so a seized device opens no older message. An archive is the opposite: it is
there so that old messages CAN be opened. A chat with an archive therefore
gains nothing from FOMKE on its messages. It only pays for it: each user has
to open every message and upload it a second time under an archive key.

This draft drops that second upload. Each message is stored **once**, and that
one copy is both the posting box entry and the archive entry, for both users.
Only symmetric keys are stored. Asymmetric algorithms (KEMs) appear only for a
short moment, inside a normal AME handshake, and are erased right after it.

A chat that must keep forward secrecy stays a plain FOMKE session with no
archive. This draft covers chats WITH an archive only.

## Definitions ✦

Terms from the README (`XHKDF`, `KEM`, `AEAD`, `AAD`, `seal`, `open`, `erase`,
`refuse`, `layout`, `tier`, `slot`, `TK`, `u8/u16/u32/u64` little-endian) keep
their meaning.

- `user` := one person with one account.
- `device` := one installation of the app. A user may have several.
- `server` := the machine that stores the records. It holds no key that
  opens a message.
- `chat` := the conversation of exactly two users.
- `chatId` := 16 random bytes that name one chat. Chosen by the user who
  opens the chat.
- `passphrase` := what the user types to unlock the archive on a new device.
- `UAK` := user archive key, 32 bytes. Made from the passphrase. Known only
  to the user's own devices. Never stored anywhere.
- `vault` := the records on the server that only one user can open: the
  user's device list and one vault entry per chat.
- `CAS` := chat archive secret, 32 bytes. One per chat and generation. Both
  users of the chat hold the same CAS.
- `generation` := one numbered CAS of a chat, starting at 1. A new
  generation is made by a fresh KEM exchange ("CAS renewal").
- `lane` := the sending line of ONE device in ONE chat, named by a `u32`.
  Every lane has its own counter.
- `epoch` := a run of `E` messages on one lane (`E` = `epochSize`, default
  256). Each epoch has its own key.
- `K_e` := epoch key, 32 bytes. One per (generation, lane, epoch).
- `index` := the position of a message inside its epoch, `0 .. E-1`.
- `position` := the four numbers that name one message
  `(gen, lane, epoch, index)` inside one chatId.
- `key block` := the bytes one message key expands into: nonce, one key per
  switched-on cipher slot, one key per switched-on MAC slot. Same as FOMKE
  Step 3.
- `salt` := 16 random bytes made fresh for every record that is sealed.
- `read pointer` := per user and chat: the last position the user has read,
  per lane.

## 1. Where everything lives ⟡

```text
 ┌─ posting box (FOMKE, user ↔ user) ─────────────────────────────────────┐
 │  only at chat start and at CAS renewal:                                 │
 │  AME handshake records, CAO1 (chat open), CAA1 (chat accept)            │
 │  -> deleted by the server once picked up. Nothing stays.               │
 └─────────────────────────────────────────────────────────────────────────┘
 ┌─ vault of user A (server, only A can open) ────────────────────────────┐
 │  CAU1  how to turn A's passphrase into UAK      (unencrypted, 1×)       │
 │  CAD1  A's device list                          (sealed with UAK, 1×)   │
 │  CAV1  CAS of chat X, generation g              (sealed with UAK,       │
 │                                                  1× per chat and gen)   │
 └─────────────────────────────────────────────────────────────────────────┘
 ┌─ vault of user B ──────────────────────────────────────────────────────┐
 │  the same three kinds, sealed with B's own UAK                          │
 └─────────────────────────────────────────────────────────────────────────┘
 ┌─ chat store of chat X (server, A and B can open) ──────────────────────┐
 │  CAM1  one record per message, stored ONCE for both users               │
 │  CAR1  read pointer of A, read pointer of B     (unencrypted)           │
 └─────────────────────────────────────────────────────────────────────────┘
```

What has to be written back, and how often:

```text
event                    who writes what                         how often
───────────────────────  ──────────────────────────────────────  ─────────────────────
a message is sent        sender: one CAM1                         per message
a message is read        reader: CAR1 (the read pointer)          whenever it moves
chat start               each user: one CAV1                      once per chat
CAS renewal              each user: one CAV1                      rare (see 5.5)
a device joins           that device: CAD1 rewritten              once per device
an epoch ends            nobody: K_e is derived, not stored       never
```

The reader's one CAV1 at chat start rides along with the reader's first CAR1.
No extra request is needed for it.

## 2. The key ladder ⟡

```text
passphrase ──Argon2id──▶ UAK                    (only on the user's devices)
                          │
                          │ opens
                          ▼
              CAV1 ──▶ CAS(g)                   (both users of the chat)
                          │
                          │ XHKDF, one call per epoch
                          ▼
                     K_e(g, lane, e)            (both users of the chat)
                          │
                          │ XHKDF, one call per message, with the salt
                          ▼
                     key block ──▶ seal / open one CAM1
```

### 2.1 Every derivation

```text
UAK         = XHKDF( Argon2id(passphrase, userSalt, params),
                     "CHAT-USER-KEY-v1" )                                -> 32 B

CAS(g)      = XHKDF( TK(n) of the A↔B AME session,
                     "CHAT-ARCHIVE-KEY-v1", chatId, g )                  -> 32 B

K_e         = XHKDF( CAS(g),
                     "CHAT-EPOCH-KEY-v1", chatId, g, lane, e )           -> 32 B

key block   = XHKDF( K_e,
                     "CHAT-MESSAGE-KEY-v1", chatId, g, lane, e,
                     index, salt )            -> ameTierKeyMaterialLen(L, t) B

vault key   = XHKDF( UAK,
                     "CHAT-VAULT-KEY-v1", chatId, g, salt )
                                              -> key block of the vault tier

device list = XHKDF( UAK, "CHAT-DEVICES-KEY-v1", salt )
  key                                         -> key block of the vault tier

lane        = first 4 bytes of XHKDF( UAK, "CHAT-LANE-v1", deviceId, chatId )
```

Every input carries its own label. No two jobs share a key, the same rule
that keeps EK and SK apart in FOMKE (README, "Why EK and SK are two keys").
CAS is the archive's version of SK: a secret that is **stored**, so it must
never be a key that a rotation also uses. It is a one-way image of TK under
its own label. Knowing CAS tells nothing about TK, EK or any FOMKE message
key.

The **vault tier** is fixed by the record version: version 1 means
`tmeAeadAmeLayout` (README, "The building blocks") with every slot switched
on and a 32-byte tag. A vault entry has to open before anything else is known,
so its tier cannot be stored inside it.

The **chat tier** (layout, tier, tag length) is agreed in CAO1 and stored in
every CAV1 of that generation.

### 2.2 What exists, and when it is erased

```text
value        size  made                              erased
───────────  ────  ────────────────────────────────  ──────────────────────────────
passphrase   var.  typed by the user                 right after Argon2id
UAK          32    unlocking the app                 when the app locks
TK(n) path   —     the A↔B AME session               the session is closed right
                                                     after CAS is derived; it is
                                                     not needed again until renewal
CAS(g)       32    chat start / renewal              never stored unwrapped; in
                                                     memory only while the chat
                                                     is open
K_e          32    when a lane enters epoch e        when the epoch ends or the
                                                     chat closes
key block    var.  sealing / opening one CAM1        right after that record
```

### 2.3 Why the epoch keys are derived and not stored ⌜guide⌟

An earlier sketch stored each epoch key wrapped under CAS (`wrap(CAS, K_e)`,
72 bytes per epoch). With a purely symmetric CAS, that buys nothing:

```text
                                stored wrap(CAS, random K_e)   K_e = XHKDF(CAS, ...)
───────────────────────────── ──────────────────────────────  ─────────────────────
holder of CAS + server data    opens every epoch              opens every epoch
holder of one K_e               opens that one epoch           opens that one epoch
bytes per epoch                 72                             0
writes per epoch                1                              0
can repeat a nonce on crash     yes, needs a salt              no
delete one epoch for good       yes (delete the wrap)          no, only a generation
```

The only gain is deleting single epochs for good. Deleting a whole
generation does the same job (see 5.6), so the epoch keys are derived.

Epochs still exist for two reasons:

1. A sending device holds only the K_e of its current epoch. A memory dump
   taken during the day shows one epoch of one lane, not CAS.
2. They are the unit the server pages by: "give me epoch 41 of lane X".

The real security reset is the **CAS renewal** (5.5), because only it adds
fresh KEM secrets.

## 3. Records: byte layouts ⟡

Every record starts with `ver` (`u8`, = 1). These records stay on a server
for many years. A version byte is the only way to read an old one after the
format has changed. Magic bytes are not needed: the server table a record
sits in already names its kind.

### 3.1 CAM1 message record: header **29 B**

```text
offset 0     1      3        7        11      13             29          29+T
       +-----+------+--------+--------+-------+--------------+-----------+------------+
       | ver | gen  | lane   | epoch  | index | salt         | tag       | ciphertext |
       | u8  | u16  | u32    | u32    | u16   | 16 B random  | T bytes   | n bytes    |
       +-----+------+--------+--------+-------+--------------+-----------+------------+
Total = 29 + T + n      (T is 16, 24 or 32 = tag length of the chat tier)
```

The header is unencrypted. The server reads `gen`, `lane`, `epoch`, `index`
to store and page records. It cannot change them: the tag covers them.

The tag covers: the label `"CHAT-MESSAGE-v1"`, the `chatId`, the whole
29-byte header, the chat layout, the chat tier, the tag length, and the
ciphertext. The `chatId` is not in the record; both sides know it. A record
moved into another chat therefore fails to open.

Absent on purpose:

- **No nonce.** It is the front of the key block, as in FOMKE Step 3.
- **No length.** The ciphertext is whatever follows the tag.
- **No sender.** A lane belongs to one device. See 4.3 for how a reader
  tells its own lanes from the other user's.
- **No hash of the previous record.** The index counts up without gaps on
  each lane, and the tag covers it. A deleted record shows up as a gap, and a
  changed or moved record fails to open. A hash chain would add 16 bytes and
  catch nothing more. A withheld LAST record is caught by `seen` (3.2), not
  by a chain.

#### Why the salt costs 16 bytes per message ⚠️

Without the salt, a position always gives the same key block, and so the
same nonce. Two different messages under one nonce leak the XOR of both
plaintexts, through every switched-on cipher. That happens whenever a device
reuses a counter:

```text
 the app crashes after sealing message 17, before saving the counter
 a phone is restored from last week's backup
 the same deviceId ends up on two devices
            │
            ▼
 two DIFFERENT messages at position (g, lane, e, 17)
```

With the salt, the second message gets a different key block. No nonce is
repeated. The server keeps a position **write-once**: it refuses the second
record, and the device moves its counter past it. The device also saves its
counter BEFORE sealing (for example by reserving 16 indexes at a time). The
salt is the safety net for when that saving fails.

### 3.2 CAM1 sealed body

```text
offset 0      1          9       10
       +------+----------+-------+-----------------------------------+
       | kind | timeMs   | flags | content (depends on kind)         |
       | u8   | u64      | u8    |                                   |
       +------+----------+-------+-----------------------------------+
```

- `timeMs`: the sender's clock, milliseconds since 1970. It is used for the
  display order across lanes. It is sealed, so the server does not see it.
- `flags` bit 0: padded. The body was rounded up to whole 64-byte blocks
  before sealing; the last byte counts the filler (the same rule as
  AME padding).

A `ref` is the 12-byte position of another message in the same chat:

```text
       +--------+------+--------+-------+
       | lane   | gen  | epoch  | index |
       | u32    | u16  | u32    | u16   |      = 12 B
       +--------+------+--------+-------+
```

```text
kind  name         content
────  ───────────  ────────────────────────────────────────────────────────────
1     text         UTF-8 text, the rest of the body
2     attachment   packageId (16) | fileKey (32) | size u64
                   | u16 + name (UTF-8) | u16 + media type (ASCII)
                   -> the file itself is an ASP secure package sealed with
                      fileKey, stored and fetched on its own
3     edit         ref (12) | new UTF-8 text
4     delete       ref (12)  -> asks the server to drop that record and the
                               other user to hide it
5     seen         count u8 | count × ref (12)
                   -> "I have read up to here, on these lanes". It is sealed,
                      so the server cannot fake it. A reader who is told
                      "seen up to 40" but finds only 38 records knows the
                      server is holding two back.
```

An attachment is sealed with its own random `fileKey`. A large file then
never has to be loaded to show the chat, and the server can store it apart.

### 3.3 CAV1 vault entry: header **19 B**

One per (user, chatId, gen). The server stores it under exactly those three.

```text
offset 0     1      3              19          19+T
       +-----+------+--------------+-----------+--------------------+
       | ver | gen  | salt         | tag       | sealed body        |
       | u8  | u16  | 16 B random  | T = 32    |                    |
       +-----+------+--------------+-----------+--------------------+

sealed body:
       +---------+-----------+-------------+-------------+--------+------------------+
       | CAS     | epochSize | u16 + chat  | u16 + chat  | tagLen | u16 + peer       |
       | 32 B    | u16       | layout      | tier        | u8     | handle (UTF-8)   |
       +---------+-----------+-------------+-------------+--------+------------------+
```

The key block comes from `vault key` (2.1). The tag covers the label
`"CHAT-VAULT-v1"`, the `chatId`, the header and the ciphertext.

The salt makes each rewrite safe. A new passphrase, for example, means every
CAV1 is sealed again under a new UAK, and each one gets a new salt.

### 3.4 CAU1 user record: fixed **42 B**, unencrypted

```text
offset 0     1           5            9       10                    42
       +-----+-----------+------------+-------+---------------------+
       | ver | memoryKiB | iterations | lanes | userSalt            |
       | u8  | u32       | u32        | u8    | 32 B random         |
       +-----+-----------+------------+-------+---------------------+
```

The Argon2id settings and salt a new device needs BEFORE it can make the
UAK. Nothing in it is secret. `lanes` here is Argon2's parallelism, not a
chat lane.

### 3.5 CAD1 device list: header **19 B**

```text
       +-----+------+--------------+-----------+------------------------------+
       | ver | 0    | salt         | tag       | sealed: count u8             |
       | u8  | u16  | 16 B random  | T = 32    |  | count × (deviceId 16       |
       |     |      |              |           |  |          | addedMs u64)    |
       +-----+------+--------------+-----------+------------------------------+
```

The same frame as CAV1, so one routine reads both. `gen` is always 0, and the
key comes from `device list key` (2.1).

### 3.6 CAR1 read pointer: **3 + 12·count B**, unencrypted

```text
       +-----+--------+------------------------------+
       | ver | count  | count × ref (12)             |
       | u8  | u16    |                              |
       +-----+--------+------------------------------+
```

One per (user, chatId). The server uses it for "unread" counts and push
notifications, so it can read it. What the server learns from it, it learns
anyway from which records a device fetches. This record is the posting box:
"new" means every record past the pointer.

### 3.7 CAO1 chat open / CAA1 chat accept (posting box only)

These travel as FOMKE messages inside the A↔B AME session. The server never
stores them past pickup.

```text
CAO1   ver u8 | chatId 16 | gen u16 | epochSize u16
              | u16 + chat layout | u16 + chat tier | tagLen u8
CAA1   ver u8 | chatId 16 | gen u16 | answer u8      (1 = accept, 0 = refuse)
```

Both users derive `CAS(gen)` only after CAA1 with `answer = 1`.

## 4. Flows ⟡

### 4.1 Chat start (once per chat)

```text
 A                               server                               B
 │  AMC2 hello  ─────────────▶  posting box of B  (waits until B is online)
 │                                                    ─────────────▶  │
 │  ◀─────────────  posting box of A  ◀────────────────  AMS2 hello   │
 │  AMF2 finish ─────────────▶                        ─────────────▶  │
 │      ── the A↔B AME session is up, FOMKE seals what follows ──     │
 │  CAO1 chatId, gen=1, E, tier ─────────────────────────────────▶    │
 │  ◀──────────────────────────────────────────── CAA1 accept         │
 │                                                                    │
 │  CAS(1) = XHKDF(TK, "CHAT-ARCHIVE-KEY-v1", chatId, 1)  (both sides)│
 │  session closed, TK erased                                         │
 │                                                                    │
 │  CAV1 (sealed with UAK_A) ──▶  vault A                             │
 │                                vault B  ◀── CAV1 (sealed with UAK_B)
 │                                             + CAR1 (one request)   │
```

The handshake needs 1.5 round trips through the posting box, and each one may
wait for the other user to come online. **Not tried yet:** whether the AME
handshake as it stands tolerates hours between its records (cookie lifetime
in AMR2, timeouts).

### 4.2 Sending one message

```text
1. position = (g, myLane, e, i)          i = next index on my lane
2. save i+1 to disk                      before sealing (3.1)
3. K_e      = derived once per epoch, kept while the epoch runs
4. salt     = 16 random bytes
5. key block = XHKDF(K_e, "CHAT-MESSAGE-KEY-v1", ..., i, salt)
6. seal body -> CAM1, erase key block
7. upload CAM1                           the server refuses a used position
8. i = E-1 ?  -> next message starts epoch e+1 at index 0, erase K_e
```

### 4.3 Reading, and telling own lanes from the other user's

```text
for each CAM1 past my read pointer:
  K_e       = XHKDF(CAS(gen), ..., lane, epoch)     cache per (gen, lane, epoch)
  key block = XHKDF(K_e, ..., index, salt)
  open -> body                                      tag wrong -> refuse, report

whose lane is it?
  my lanes = { XHKDF(UAK, "CHAT-LANE-v1", deviceId, chatId) | deviceId in CAD1 }
  lane in my lanes  -> written by me (another of my devices)
  otherwise          -> written by the other user
```

Because both users hold CAS, the other user COULD write into one of my
lanes. I would notice it: the lane is mine, but the record is not in my
devices' sent history. Between two users, "one of us two wrote this" is
enough, since each knows what they wrote. A group chat would need more (see
6, point 4).

A lane is different in every chat, so the server cannot link one device
across chats. The chance that two lane numbers collide in one chat is about
1 in 4 billion per pair of devices. The server refuses a lane that the other
account already wrote to; the device then makes a new `deviceId`.

### 4.4 A new device

```text
passphrase + CAU1 ──Argon2id──▶ UAK
UAK ──opens──▶ CAD1 ──▶ add my new deviceId, reseal with a new salt, upload
UAK ──opens──▶ every CAV1 ──▶ CAS of every chat and generation
CAS ──▶ K_e ──▶ every CAM1                       full history, no help needed
```

### 4.5 CAS renewal (the security reset)

```text
1. A and B run a new AME session (or a rotation with a new KEM exchange)
2. CAO1 with gen+1 -> CAA1
3. CAS(gen+1) from the new TK; each user writes one new CAV1
4. new messages use gen+1; old records keep their gen and stay readable
```

An attacker who stole CAS(g) reads nothing of `gen+1`. That generation comes
from fresh KEM secrets the attacker never saw. Suggested triggers: a device
is removed from CAD1, a passphrase change, or a fixed time (for example 30
days).

### 4.6 Deleting

```text
delete one message      kind 4 + the server drops that CAM1
                        -> relies on the server actually deleting it
delete a whole chat     both users delete every CAV1 of that chatId
                        -> without CAS, the records left on any copy are noise
```

Deleting for good, against a server that keeps copies, works only per
generation. A chat that needs that more often renews CAS more often.

## 5. What the server can do, and what stops it

```text
the server ...                          stopped by
──────────────────────────────────────  ────────────────────────────────────────
reads a message                         holds no CAS, no UAK
changes or moves a record               tag over header + chatId
drops a record in the middle            gap in the index of that lane
holds back the newest records           `seen` (kind 5) from the other user
replays a record                        write-once position; same bytes twice = one
learns who writes to whom               ✗ it sees the two accounts of a chat.
                                          Lanes differ per chat, so devices are
                                          not linked across chats.
learns when and how much                ✗ it sees record times and sizes.
                                          Padding (flags bit 0) blurs the sizes.
guesses the passphrase from CAU1+CAV1   Argon2id settings in CAU1; a weak
                                          passphrase stays the weakest point
```

## 6. Sizes

```text
item                                         bytes (T = 32)     bytes (T = 16)
───────────────────────────────────────────  ─────────────────  ──────────────
one text message, stored                     29 + 32 + 10 + t   29 + 16 + 10 + t
                                             = 71 + t           = 55 + t
per epoch                                    0                  0
per chat and user (CAV1, short peer name)    ~ 19 + 32 + 45 + layout + tier
per user (CAU1)                              42
per user (CAD1, d devices)                   19 + 32 + 1 + 24·d
read pointer (2 lanes)                       3 + 24 = 27
```

The same message with the first approach (each user receives it via FOMKE and
uploads it again under an archive key):

```text
                            first approach               this draft
──────────────────────────  ───────────────────────────  ─────────────────
copies stored               2 (one per user)             1
uploads per message         3 (send + 2 write-backs)     1
asymmetric data stored      archive wrap per epoch       none
                            (~1 - 6 KB with hybrid KEMs)
```

## 7. Open decisions ⌜guide⌟

1. **Salt or no salt.** 16 bytes per message buy safety against a reused
   counter (crash, restored backup). Without it, one restored phone backup is
   enough to leak plaintext. The draft keeps the salt.
2. **epochSize.** The draft uses 256. A smaller value makes a stolen K_e
   worth less. A larger value means fewer derivations when scrolling through
   a long history. Either way it costs no bytes.
3. **The read pointer, unencrypted or sealed.** Unencrypted lets the server
   send "unread" counts. Sealed hides read times, but the server then sends
   pushes blind.
4. **Group chats.** With more than two users, "one of us wrote it" is no
   longer enough. Every member's lanes would need a key only that member
   holds, plus a way for the others to check it (a signature, that is,
   asymmetric again, or one MAC key per reader).
5. **Asynchronous chat start.** Whether AME's handshake works with hours
   between AMC2 and AMF2 (4.1).
6. **Where the code goes.** A new module family `src/protocols/chat/` beside
   `fomke/`, with the records in level 0, derivation and sealing in level 1
   (calling `ame/level1/tier_aead.nim`, the one place that seals), and the
   flows in level 2.
