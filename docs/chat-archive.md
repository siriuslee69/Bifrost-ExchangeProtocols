# Chat archive (draft) 🗄️

**Status: the crypto is built** (`src/protocols/archive/`, tests in `evaluation/tests/test_archive.nim`); **storage, boxes and sync are Nebel's** (`Nebel-DecentralizedDB/docs/boxes.md`). Every
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

A user who loses every device opens the whole archive again from a new one,
with nothing but their user name and password. No key has to be kept on a
device or on paper.

A chat that must keep forward secrecy stays a plain FOMKE session with no
archive. This draft covers chats WITH an archive only.

## Definitions ✦

Terms from the README (`XHKDF`, `KEM`, `AEAD`, `AAD`, `seal`, `open`, `erase`,
`refuse`, `layout`, `tier`, `slot`, `TK`, `u8/u16/u32/u64` little-endian) keep
their meaning.

- `user` := one person with one account.
- `userId` := the account's name on the server. It never changes. It is not
  secret.
- `device` := one installation of the app. A user may have several.
- `deviceId` := 16 random bytes a device makes for itself when it is first
  set up.
- `server` := the machine that stores the records. It holds no key that
  opens a message.
- `chat` := the conversation of exactly two users.
- `chatId` := 16 random bytes that name one chat. Chosen by the user who
  opens the chat.
- `password` := what the user types to unlock the archive on any device.
- `KEK` := key-encryption key, 32 bytes. Made from password, userId and
  userSalt. Its only job is to open CAK1. Never stored anywhere.
- `DMK` := data master key, 32 bytes, made of random bytes once at sign-up.
  Every other key of the user is derived from it. Stored only inside CAK1.
- `UAK` := user archive key, 32 bytes, derived from the DMK. Opens the
  user's vault.
- `vault` := the records on the server that only one user can open: the
  wrapped DMK, the device list, one vault entry per chat, one lane record per
  own lane.
- `CAS` := chat archive secret, 32 bytes. One per chat and generation. Both
  users of the chat hold the same CAS.
- `generation` := one numbered CAS of a chat, starting at 1. A new
  generation is made by a fresh KEM exchange ("CAS renewal").
- `lane` := the sending line of ONE device in ONE chat, named by a random
  `u32`. Every lane has its own counter.
- `own lane` := a lane that one of the user's own devices writes to.
- `epoch` := a run of `E` messages on one lane (`E` = `epochSize`, default
  256). Each epoch has its own key.
- `K_e` := epoch key, 32 bytes. One per (generation, lane, epoch).
- `index` := the position of a message inside its epoch, `0 .. E-1`.
- `position` := the four numbers that name one message,
  `(gen, lane, epoch, index)`, inside one chatId.
- `key block` := the bytes one message key expands into: nonce, one key per
  switched-on cipher slot, one key per switched-on MAC slot. Same as FOMKE
  Step 3.
- `salt` := 16 random bytes made fresh for every record that is sealed.
- `read pointer` := per user and chat: the last position the user has read,
  per lane.

## 1. Where everything lives ⟡

```text
 ┌─ posting box (user ↔ user) ────────────────────────────────────────────┐
 │  only at chat start and at CAS renewal:                                 │
 │  AME handshake records (KEM exchange, authentication), then             │
 │  CAO1 (chat open), CAA1 (chat accept), sealed by FOMKE                  │
 │  -> deleted by the server once picked up. Nothing stays.               │
 └─────────────────────────────────────────────────────────────────────────┘
 ┌─ vault of user A (server, only A can open) ────────────────────────────┐
 │  CAU1  Argon2id settings + userSalt         (unencrypted, 1×)           │
 │  CAK1  the DMK, wrapped with KEK            (1×)                        │
 │  CAD1  A's device list                      (sealed with UAK, 1×)       │
 │  CAV1  CAS of chat X, generation g          (sealed with UAK,           │
 │                                              1× per chat and gen)       │
 │  CAL1  "lane L in chat X is one of mine"    (sealed with UAK,           │
 │                                              1× per own lane)           │
 └─────────────────────────────────────────────────────────────────────────┘
 ┌─ vault of user B ──────────────────────────────────────────────────────┐
 │  the same five kinds, sealed with B's own keys                          │
 └─────────────────────────────────────────────────────────────────────────┘
 ┌─ chat store of chat X (server, A and B can open) ──────────────────────┐
 │  CAM1  one record per message, stored ONCE for both users               │
 │  CAR1  read pointer of A, read pointer of B     (unencrypted)           │
 └─────────────────────────────────────────────────────────────────────────┘
```

What has to be written back, and how often:

```text
event                       who writes what                        how often
──────────────────────────  ─────────────────────────────────────  ──────────────────────
a message is sent           sender: one CAM1                        per message
a message is read           reader: CAR1 (the read pointer)         whenever it moves
chat start                  each user: one CAV1                     once per chat
a device first writes       that device: one CAL1                   once per device
  into a chat                                                         and chat
CAS renewal                 each user: one CAV1                     rare (see 4.5)
a device joins / leaves     that device: CAD1 rewritten             once per device
password change             the user: CAU1 + CAK1                   when the user wants
full key change             the user: CAK1, CAD1, every CAV1,       after a suspected
                            every CAL1 (see 4.6)                      leak only
an epoch ends               nobody: K_e is derived, not stored      never
```

Nothing above needs a request of its own:

- The reader's CAV1 at chat start goes along with the reader's first CAR1.
- A device's CAL1 goes along with the first CAM1 it writes into that chat.

## 2. The key ladder ⟡

```text
password + userId + userSalt
          │
       Argon2id
          │
          ▼
         KEK ──opens──▶ CAK1 ──▶ DMK            (only on the user's devices)
                                  │
                                  │ XHKDF, one label per job
                                  ▼
                                 UAK
                                  │
                                  │ opens
                                  ▼
                      CAV1 ──▶ CAS(g)           (both users of the chat)
                                  │
                                  │ XHKDF, one call per epoch
                                  ▼
                             K_e(g, lane, e)    (both users of the chat)
                                  │
                                  │ XHKDF, one call per message, with the salt
                                  ▼
                             key block ──▶ seal / open one CAM1
```

### 2.1 Why the password does not make the DMK directly ⌜guide⌟

The password only opens CAK1. Everything else hangs on the DMK, which is
random and never changes on a password change:

```text
event                        DMK made from the password      DMK random, in CAK1
───────────────────────────  ──────────────────────────────  ────────────────────
password changed             reseal CAD1, every CAV1,        reseal CAK1 only
                             every CAL1 (hundreds)           (1 record)
the app dies halfway         some records under the old      nothing is halfway:
                             key, some under the new one     the new CAK1 replaces
                             -> both keys needed             the old in one step
```

The cost is one record of 83 bytes.

A password change is therefore NOT a key change. It protects nothing that an
attacker already had. Someone who once held the old password AND the server's
data already holds the DMK. For that case there is the **full key change**
(4.6).

### 2.2 Every derivation

These are the labels the code uses (`src/protocols/archive/`, Bifrost).
The code calls the chat a **space** (one chat, one mailbox, one password
vault), the chatId a **spaceId**, the CAS the **space secret**, and the KEK
the **wrap key**:

```text
login secret = Argon2id( NFKC(password),
                         userSalt | len(userId) | userId, settings in CAU1 )
authKey      = XHKDF( login secret, "ARCHIVE-AUTH-KEY-v1" )   -> 32 B, to the
                                                                 server (hash)
KEK (wrapKey)= XHKDF( login secret, "ARCHIVE-WRAP-KEY-v1" )   -> 32 B
                                                   deriveArchiveLogin

DMK          = 32 random bytes, made once at sign-up (and at a full key change)
                                                   newArchiveMasterKey
sub key      = XHKDF( DMK, "ARCHIVE-SUB-KEY-v1" | name | keyGen )   -> 32 B
               names: "vault" (CAV1), "devices" (CAD1), "lanes" (CAL1), ...
                                                   deriveArchiveSubKey

CAS(g)       = TK child "ARCHIVE-SPACE-KEY-v1" | chatId | g          -> 32 B
                                                   deriveArchiveSpaceSecret
K_e          = XHKDF( CAS(g), "ARCHIVE-EPOCH-KEY-v1"
                      | chatId | g | lane | e )                     -> 32 B
                                                   deriveArchiveEpochKey
key block    = XHKDF( K_e, "ARCHIVE-MESSAGE-KEY-v1"
                      | chatId | position (12 B) | salt )   (CAM1, sealArchiveLog)

key block of = XHKDF( key, "ARCHIVE-RECORD-KEY-v1"
  any vault           | label | place | num | salt )       (sealArchiveRecord)
  record
```

The UAK of the first drafts is gone: every vault record is sealed directly
under a sub key of the DMK, and its label and place go into its key block.
`authKey` is new: it is how the server checks who logs in. The server
stores only its hash, so it learns nothing that opens CAK1.

Every input carries its own label. No two jobs share a key, the same rule
that keeps EK and SK apart in FOMKE (README, "Why EK and SK are two keys").
CAS is the archive's version of SK: a secret that is **stored**, so it must
never be a key that a rotation also uses. It is a one-way image of TK under
its own label. Knowing CAS tells nothing about TK, EK or any FOMKE message
key.

`NFKC` is Unicode normalisation: the same password always becomes the same
bytes, whichever keyboard typed it.

```text
 "ä" typed on a phone      -> 1 code point   U+00E4
 "ä" typed as a + ¨        -> 2 code points  U+0061 U+0308
 both after NFKC           -> U+00E4         same KEK, same DMK
```

Without it, a user with an umlaut in the password could be locked out on a
new device.

`userId` and `userSalt` are not secret. They only make sure that two users
with the same password still get different KEKs, and that a table of guesses
built for one user is worth nothing for another.

The **vault tier** is fixed by the record version: version 1 means
`tmeAeadAmeLayout` (README, "The building blocks") with every slot switched
on and a 32-byte tag. A vault record has to open before anything else is
known, so its tier cannot be stored inside it.

The **chat tier** (layout, tier, tag length) is agreed in CAO1 and stored in
every CAV1 of that generation.

### 2.3 What exists, and when it is erased

```text
value        size  made                              erased
───────────  ────  ────────────────────────────────  ──────────────────────────────
password     var.  typed by the user                 right after Argon2id
KEK          32    right after Argon2id              right after CAK1 is opened
DMK          32    opening CAK1                      when the app locks
UAK          32    derived from the DMK              when the app locks
TK(n) path   —     the A↔B AME session               the session is closed right
                                                     after CAS is derived; it is
                                                     not needed again until renewal
CAS(g)       32    chat start / renewal              never stored unwrapped; in
                                                     memory only while the chat
                                                     is open
K_e          32    when a lane enters epoch e        when the epoch ends or the
                                                     chat closes
key block    var.  sealing / opening one record      right after that record
```

### 2.4 Why the epoch keys are derived and not stored ⌜guide⌟

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
generation does the same job (see 4.8), so the epoch keys are derived.

Epochs still exist for two reasons:

1. A sending device holds only the K_e of its current epoch. A memory dump
   taken during the day shows one epoch of one lane, not CAS.
2. They are the unit the server pages by: "give me epoch 41 of lane X".

The real security reset is the **CAS renewal** (4.5), because only it adds
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

The tag covers: the label `"ARCHIVE-LOG-v1"`, the `chatId`, the whole
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
                   -> "I have read up to here, on these lanes of YOURS". It
                      is sealed, so the server cannot fake it. A reader who is
                      told "seen up to 40" but finds only 38 records knows the
                      server is holding two back.
6     lanes        count u8 | count × lane u32
                   -> "these are all lanes of MY user in this chat that I
                      know of, this one included". It is always the FIRST
                      message on a new lane. See 4.3.
```

An attachment is sealed with its own random `fileKey`. A large file then
never has to be loaded to show the chat, and the server can store it apart.

### 3.3 The vault frame: header **19 B**

CAK1, CAV1, CAD1 and CAL1 all use this one frame, so one routine reads them
all. Only the key, the label and what is inside differ.

```text
offset 0     1      3              19          51
       +-----+------+--------------+-----------+--------------------+
       | ver | num  | salt         | tag       | sealed body        |
       | u8  | u16  | 16 B random  | T = 32    |                    |
       +-----+------+--------------+-----------+--------------------+

record  num means   key from (2.2)        label               place (in the tag)
──────  ──────────  ────────────────────  ────────────────  ──────────────────────
CAK1    keyGen      wrapKey               "ARCHIVE-MASTER-v1" (userId)
CAV1    gen         sub key "vault"       "ARCHIVE-SPACE-v1"  (chatId)
CAD1    keyGen      sub key "devices"     app label         (userId)
CAL1    keyGen      sub key "lanes"       app label         (chatId | lane)
```

The tag covers the label, the "stored under" values, the 19-byte header and
the ciphertext. A record copied into another slot therefore fails to open.
The salt makes each rewrite safe: every reseal gets a new salt, and so a new
key block.

### 3.4 CAU1 user record: fixed **42 B**, unencrypted

```text
offset 0     1           5            9       10                    42
       +-----+-----------+------------+-------+---------------------+
       | ver | memoryKiB | iterations | lanes | userSalt            |
       | u8  | u32       | u32        | u8    | 32 B random         |
       +-----+-----------+------------+-------+---------------------+
```

The Argon2id settings and salt a new device needs BEFORE it can make the
KEK. Nothing in it is secret. `lanes` here is Argon2's parallelism, not a
chat lane.

The **client** chooses these values, never the server, and the client has
fixed lowest values built in. If a server hands out weaker values at login,
a different KEK comes out, CAK1 does not open, and nothing is lost. At sign-up
and at a password change, the client writes its own values.

### 3.5 CAK1 wrapped master key: fixed **83 B**

```text
offset 0     1        3              19          51          83
       +-----+--------+--------------+-----------+-----------+
       | ver | keyGen | salt         | tag       | DMK       |
       | u8  | u16    | 16 B random  | 32 B      | 32 B,     |
       |     |        |              |           | sealed    |
       +-----+--------+--------------+-----------+-----------+
```

`keyGen` counts full key changes, starting at 1. A password change keeps
`keyGen` and the DMK; only salt, tag and ciphertext change.

The server holds the new CAK1 BESIDE the old one until the client confirms
that the new one opens. Only then is the old one dropped. A crash or a lost
connection in the middle cannot lock the user out.

### 3.6 CAV1 vault entry: **51 B + body**

```text
sealed body:
       +---------+-----------+-------------+-------------+--------+------------------+
       | CAS     | epochSize | u16 + chat  | u16 + chat  | tagLen | u16 + peer       |
       | 32 B    | u16       | layout      | tier        | u8     | handle (UTF-8)   |
       +---------+-----------+-------------+-------------+--------+------------------+
```

### 3.7 CAD1 device list: **51 + 1 + 32·d B**

```text
sealed body:
       +----------+-------------------------------------------------+
       | count u8 | count × ( deviceId 16 | addedMs u64             |
       |          |           | removedMs u64 )                     |
       +----------+-------------------------------------------------+
```

`removedMs` = 0 means the device is still in use. A removed device is
**marked, never deleted**, so its old lanes stay known as own lanes.

### 3.8 CAL1 lane record: fixed **75 B**

One per own lane: each device writes one the first time it sends into a
chat. This is how a new device finds the lanes of the user's OLD devices, even
the lanes of a device that is long gone.

```text
sealed body:
       +-------------+------------+
       | deviceId    | createdMs  |
       | 16 B        | u64        |
       +-------------+------------+      51 + 24 = 75 B
```

The lane number itself is not in the body: it is part of "stored under"
(user, chatId, lane), and the tag covers it.

### 3.9 CAR1 read pointer: **3 + 12·count B**, unencrypted

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

### 3.10 CAO1 chat open / CAA1 chat accept (posting box only)

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
 │  CAS(1) = TK child "ARCHIVE-SPACE-KEY-v1" | chatId | 1  (both sides)│
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
0. no lane yet in this chat?
     lane = random u32; the server refuses one already in use -> draw again
     first CAM1 on it is kind 6 (lanes), uploaded with this device's CAL1
1. position = (g, myLane, e, i)          i = next index on my lane
2. save i+1 to disk                      before sealing (3.1)
3. K_e      = derived once per epoch, kept while the epoch runs
4. salt     = 16 random bytes
5. key block = XHKDF(K_e, "ARCHIVE-MESSAGE-KEY-v1", ..., i, salt)
6. seal body -> CAM1, erase key block
7. upload CAM1                           the server refuses a used position
8. i = E-1 ?  -> next message starts epoch e+1 at index 0, erase K_e
```

A lane is a random number per chat, so the server cannot link one device
across chats. It does not depend on any key either, so it stays the same
through a password change and a full key change.

### 4.3 Reading, and telling own lanes from the other user's

```text
for each CAM1 past my read pointer:
  K_e       = XHKDF(CAS(gen), ..., lane, epoch)     cache per (gen, lane, epoch)
  key block = XHKDF(K_e, ..., index, salt)
  open -> body                                      tag wrong -> refuse, report
```

Opening needs no list of lanes at all: the lane number is in every header,
and CAS is the same for both users. The list is only needed to show who
wrote a message:

```text
mine     = every lane with a CAL1 in my vault            (all my devices, ever)
theirs   = every other lane

cross-checks, against a server that hides one of my CAL1:
  a lane in "theirs" whose first message (kind 6) names one of MY lanes   -> warn
  a lane in "theirs" that the other user lists in a `seen` (kind 5)
    as one of MY lanes                                                    -> warn
```

Hiding a CAL1 can make my own old messages look as if the other user wrote
them. The server cannot read or change any of them. The two cross-checks
catch it as soon as I had a second device, or as soon as the other user has
read one of the lane's messages.

Because both users hold CAS, the other user COULD start a lane and write
anything into it. It shows up as THEIR lane, never as mine: "mine" comes
only from my own vault, which only I can seal. Between two users this is
enough. A group chat needs more (see 7, point 4).

### 4.4 A new device (the old one is lost)

```text
userId + password ──▶ fetch CAU1 + CAK1
password + CAU1 ──Argon2id──▶ KEK ──opens──▶ CAK1 ──▶ DMK ──▶ UAK
UAK ──opens──▶ CAD1   ──▶ add my new deviceId, reseal with a new salt, upload
UAK ──opens──▶ every CAV1 ──▶ CAS of every chat and generation
UAK ──opens──▶ every CAL1 ──▶ which lanes were mine, on every old device
CAS ──▶ K_e ──▶ every CAM1                       full history, no help needed
```

Nothing has to be kept on any device. This is also the weak point: anyone
who holds the server's data and guesses the password does the same (see 5).

### 4.5 CAS renewal (the security reset of one chat)

```text
1. A and B run a new AME session (or a rotation with a new KEM exchange)
2. CAO1 with gen+1 -> CAA1
3. CAS(gen+1) from the new TK; each user writes one new CAV1
4. new messages use gen+1; old records keep their gen and stay readable
```

An attacker who stole CAS(g) reads nothing of `gen+1`. That generation comes
from fresh KEM secrets the attacker never saw. Suggested triggers: a device
is removed from CAD1, a full key change, or a fixed time (for example 30
days).

### 4.6 Password change and full key change

```text
password change (routine)              full key change (after a suspected leak)
─────────────────────────────────────  ──────────────────────────────────────────
new password, new userSalt             new password, new userSalt
same DMK, same keyGen                  NEW random DMK, keyGen + 1 -> new UAK
write CAU1 + CAK1                      write CAU1 + CAK1
                                       reseal CAD1, every CAV1, every CAL1
                                         under the new UAK
                                       CAS renewal in every chat (4.5)
1 + 1 records                          2 + 1 + chats + own lanes records,
                                         plus one renewal per chat
```

The full key change has to renew every CAS too. An attacker who held the
old DMK has already opened every old CAV1. Without a renewal they would keep
reading every new message.

### 4.7 Removing a device

```text
1. CAD1: set removedMs of that device, reseal
2. its CAL1 records stay: its old messages still show as mine
3. CAS renewal in every chat (4.5): the removed device knew every CAS
```

### 4.8 Deleting

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
reads a message                         holds no CAS, no DMK
changes or moves a record               tag over header + where it is stored
drops a record in the middle            gap in the index of that lane
holds back the newest records           `seen` (kind 5) from the other user
replays a record                        write-once position; same bytes twice = one
hides one of my CAL1                    cross-checks in 4.3 (warns; my old
                                          messages look like the other user's
                                          until then)
hands out weak Argon2id settings        the client's built-in lowest values
learns who writes to whom               ✗ it sees the two accounts of a chat.
                                          Lanes are random per chat, so devices
                                          are not linked across chats.
learns when and how much                ✗ it sees record times and sizes.
                                          Padding (flags bit 0) blurs the sizes.
guesses the password from CAU1+CAK1     ✗ only the password's strength and
                                          Argon2id stop it. This is the price of
                                          "nothing kept on any device".
```

The last line is the one that matters most. The server, or anyone who copies
its data, may guess offline: as often as they like, with nothing to slow them
down. userId, e-mail and userSalt add nothing here, because the server knows
all three.

```text
password                           strength (rough)   offline against Argon2id (1 GiB)
─────────────────────────────────  ─────────────────  ────────────────────────────────
a typical password                 30 - 40 bit        falls
6 words, picked by dice            ~ 77 bit           holds
```

So the client should only accept passwords of about 77 bit or more, for
example by suggesting six random words. A chat is as strong as the weaker of
the two users' passwords: either CAV1 opens the same CAS.

## 6. Sizes

```text
item                                         bytes (T = 32)     bytes (T = 16)
───────────────────────────────────────────  ─────────────────  ──────────────
one text message, stored                     29 + 32 + 10 + t   29 + 16 + 10 + t
                                             = 71 + t           = 55 + t
per epoch                                    0                  0
per chat and user (CAV1, short peer name)    ~ 51 + 45 + layout + tier
per own lane (CAL1)                          75
per user (CAU1 + CAK1)                       42 + 83 = 125
per user (CAD1, d devices)                   51 + 1 + 32·d
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
6. **E-mail in the KEK.** Left out in this draft: it adds no secret (the
   server knows it), and every e-mail change would mean a new CAK1. If it goes
   in, it must be trimmed and lower-cased first.
7. **An optional recovery key.** 32 random bytes shown once as 24 words, mixed
   into the KEK. The server could then guess nothing, but losing both the
   words and every device loses the archive. Left out in this draft, as
   "nothing kept anywhere" was the goal; it could be offered per user.
8. **Where the code goes.** A new module family `src/protocols/chat/` beside
   `fomke/`, with the records in level 0, derivation and sealing in level 1
   (calling `ame/level1/tier_aead.nim`, the one place that seals), and the
   flows in level 2.

## 8. Where each part is built ⟡

Bifrost holds the protocol: every key, every byte layout, and every rule of
the ORDER of records. It never writes to a disk. It hands out the bytes that
must be kept, and takes them back. Nebel keeps them (its boxes) and moves
them between machines.

```text
job                                   Bifrost (src/protocols/archive/)      Nebel keeps
────────────────────────────────────  ────────────────────────────────────  ──────────────────
password -> authKey + wrapKey         deriveArchiveLogin                    CAU1 (settings)
master key record (CAK1)              sealArchiveMasterKey / open...        the record
sub keys                              deriveArchiveSubKey                   nothing
space entry (CAV1)                    sealArchiveSpaceEntry / open...       the record
device list (CAD1)                    sealArchiveDevices / open...          the record
lane record (CAL1)                    sealArchiveLaneRecord / open...       the record
space secret (CAS)                    deriveArchiveSpaceSecret              nothing
one message (CAM1)                    sealArchiveLog / openArchiveLog       the record
where the next message goes           nextArchiveSend (mustSave -> state)   the 19-byte state
restart after a crash                 resumeArchiveSendLane                 hands the state back
gaps, late, duplicate, held back      noteArchiveRead, archiveHeldBack      nothing (memory)
whose lane                            archiveLaneOwner, ...LaneList         nothing
the order a box keeps, who may        --                                    boxes (docs/boxes.md
  write, push, intervals                                                      in Nebel)
```

The sending order, with the save that must come first:

```text
step = nextArchiveSend(lane)
if step.mustSave:  keep step.state on disk      <- Nebel, BEFORE sealing
record = sealArchiveLog(space, step.position, body)
upload record                                    <- Nebel's box: write-once
```
