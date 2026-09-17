# ╭⟢ The Soak 🌊

A test asks "does this work once". A soak asks "does this still work after
an hour, with dozens of peers, on a wire that loses things". They find
different faults, and everything in this file was found by the second kind.

```
evaluation/soak/
├── soak_common.nim   the payload, the identity, the counters, the clock
├── soak_server.nim   the side being measured
├── soak_client.nim   the traffic, and the losses
└── soak_run.nim      starts the processes and waits
```

---

## ╭⟢ Running it 🍣

```sh
nimble soak                                   # two minutes, default shape
nimble soak --seconds=3600 --clients=4        # an hour, four client processes
nimble soak --loss=0 --churn=0 --peers=8      # throughput, nothing induced
```

`nimble soak` builds three programs into `build/soak/` and runs the third,
which starts the other two. Everything after the task name is passed through,
and `--name=value` and `--name:value` both work.

| switch | what it decides | default |
|---|---|---|
| `--seconds` | how long the run lasts | 120 |
| `--servers` | how many server **processes** | 1 |
| `--clients` | how many client **processes** | 2 |
| `--workers` | worker pairs inside each server process | 4 |
| `--peers` | peers inside each client process | 12 |
| `--capacity` | peer slots per worker | 8 |
| `--loss` | parts per million dropped, each direction | 20000 |
| `--size` | largest package body, in bytes | 32000 |
| `--min-size` | smallest package body, in bytes | 256 |
| `--churn` | packages before a peer tears down and rebuilds | 40 |
| `--idle` | milliseconds of quiet before a slot may be reclaimed | 15000 |
| `--lane` | which scenario the links start in | cleanLan |
| `--report` | seconds between report lines | 15 |
| `--dump-slots` | server only: print every slot's state each second | 0 |
| `--recv-buffer` | server only: bytes the kernel queues per socket | 4194304 |

Total peer slots is `servers × workers × capacity`. Total peers wanting them
is `clients × peers`. Making the second bigger than the first is how slot
reclamation is put under pressure; the runner prints both numbers when it
starts so the shape of a run is in its own log.

---


**`--dump-slots=1`** is how finding 3 was caught, and it is worth knowing
about. `live=32` is a number, not an explanation: a relay full because it is
busy and a relay full because nothing will let go look identical from outside.
The dump prints four readings per slot instead:

```
w0 slots  0:out-- rnd2 age148  1:----- rnd0 age28  2:----- rnd0 age97 ...
          ^ ^^^   ^^^^ ^^^^^^
          | |     |    milliseconds since anything was HEARD from this peer
          | |     repair rounds spent on the outgoing package
          | out = still sending, in = still receiving, - = idle
          slot index
```

A slot with `out` set and `age` far past the idle window is a link that cannot
let go. A slot that is idle in BOTH directions and whose `age` never grows
past a hundred milliseconds is a link talking to itself, which is exactly what
finding 3 turned out to be.

## ╭⟢ What the processes are 🐦‍🔥

```
soak_run
  ├─ soak_server  on 127.0.0.10   ports 41000, 41001, 41002, ...
  ├─ soak_server  on 127.0.0.11   ports 42000, 42001, 42002, ...
  ├─ soak_client  peers bound across 127.0.0.1 .. 127.0.0.8
  ├─ soak_client  the same, a second process
  └─ soak_client  the same, a third
```

These are separate operating-system processes with separate heaps, separate
garbage collectors and separate address spaces. The bytes between them go
through the kernel's UDP path on real, separately routed IP addresses -- the
whole of `127.0.0.0/8` is local on Linux, and `127.0.0.10` is as much its own
address as any other.

**What this does not prove.** There is one kernel, one network stack and no
physical link. A run here says nothing about a driver, an MTU, a switch, or a
path that actually has a queue on it.

### One server worker is two threads and two sockets

```
worker i
├─ accept thread ── socket on  port + 2i      ── ameDacServerHandshake()
│                      |                          gives a live AmeSession
│                      v
│                  handover queue (one lock)
│                      |
└─ serve thread ─── socket on  port + 2i + 1  ── admitAmeDacPeer()
                       |                         pumpAmeDacEndpoint()
                       |                         tickAmeDacEndpoint()
                       v                         sweepAmeDacRelay()
                   verify the package, echo a receipt back
```

Two sockets, because `ameDacServerHandshake` owns the socket while it runs:
it reads datagrams and discards anything that is not the record it is waiting
for. Pointing it at the socket that carries live traffic would silently eat
that traffic. Bifrost has no demultiplexer that lets one socket do both, so
the soak gives the handshake its own port. A client knocks on `port + 2i` and
then talks to `port + 2i + 1` **from the same client socket** -- the relay
keys peers by the client's address, so the session the handshake produced is
the session the data socket finds.

Everything is share-nothing except two things: the handover queue, which is
one lock held for exactly one append, and the counters, which are atomics.

---

## ╭⟢ How a package proves itself 🌊

The server verifies what arrives. It has never met the sender's variables, so
"is this the right payload" cannot be answered by comparing against a copy.
Instead every package states who sent it and which package it is, and the rest
is a ramp computed from those two numbers:

```
byte:   0    1    2    3    4       8            16          20
       +----+----+----+----+--------+------------+-----------+--------
       | S  | O  | A  | K  | peerTag| packageId  |  bodyLen  | ramp...
       +----+----+----+----+--------+------------+-----------+--------
        magic, 4 bytes      u32 LE   u64 LE       u32 LE      bodyLen
```

The receiver reads the header, recomputes the ramp from `peerTag` and
`packageId`, and compares. A single flipped byte fails that comparison, and so
does a package assembled out of the wrong chunks.

---

## ╭⟢ Reading a report line 🍣

Every process prints one tagged line per interval. Counters at zero are left
out, so a clean line is a short line.

```
srv0  t=600.0s  handshakes=312  pkg-done=18204  bytes-done=291266048
      dg-sent=74112  dg-recv=402118  relay-drop=1204  swept=98
      live=61  rss=11684K  heap=1K
```

| what | means |
|---|---|
| `pkg-done` / `bytes-done` | packages the server received whole and verified |
| `pkg-acked` | packages the client saw acknowledged |
| `pkg-timeout` | packages the client gave up on |
| `echo-done` | receipts the client received back and verified |
| `dg-sent` / `dg-recv` | datagrams on the wire |
| `dg-dropped` | datagrams the client threw away on purpose |
| `relay-drop` | datagrams the relay refused (no session, or did not open) |
| `swept` | slots reclaimed from peers that went quiet |
| `admit-fail` | handshakes that finished and then found no room |
| `hs-failed` | handshakes refused; on a client, mostly the accept gate |
| `live` | peer slots occupied right now, added across workers |
| `rss` / `heap` | real memory from the operating system, and Nim's own |

**A pass** is: `MISMATCH` absent, `EXCEPTION` absent, `pkg-done` still
climbing on the last line, and `rss` settled rather than climbing without end.
The runner prints `soak: every process finished clean` and returns zero.

---

## ╭⟢ What it found 🐦‍🔥

### 1. A lossy path killed an AME session permanently

**The worst of them, and it needed a soak to see.** Within about ten seconds of
2% induced loss, every session on the run stopped working, for good:

```
AME DAC control AME authentication failed: FOMKE skipped-key cache is full
AME DAC control AME authentication failed: FOMKE message gap exceeds the reorder window
```

The ratchet keeps the key of any message it had to jump over, so that one
arriving **late** still opens. Reordering takes those keys back out again when
the message turns up. **Loss never does.** A lost datagram is not re-sent by
DAC -- DAC re-sends the CHUNK, inside a new frame at a new position -- so the
key for the old frame waits forever for something that will never exist:

```
  frames 100..130 sealed and sent
     104 and 117 lost on the path
     their keys are held, waiting
     DAC re-sends those chunks as frames 131 and 132
     nothing will ever claim 104 or 117 again
```

The cache filled with keys for messages that were never coming, and then
refused every later gap. Neither side could tell: the client's datagrams were
simply dropped, which looks exactly like a path that got worse.

Three things were wrong at once, and all three are fixed:

- **Nothing evicted a dead key.** `forgetUnreachableFomkeSkipped` now erases
  any held key whose message is further behind than `reorderCeiling`, which is
  the widest this lane will ever agree a path reorders. Further behind than
  that is not late; it is gone.
- **The cache was capped by the moving window, not by the ceiling.** Those are
  different quantities: the ceiling is the memory bound the lane was built
  with, the window is how far ahead a message may sit. A path that went quiet
  narrowed its window towards four and could then no longer hold the keys it
  was already holding. The cap is the ceiling now.
- **A full cache refused instead of making room.** It gives up its oldest held
  key now -- the one least likely to arrive. Giving a key up costs one message
  that a carrier re-sends. Refusing cost the whole session.

The derivation bound a wide window would otherwise amplify is untouched: a
message further ahead than `reorderWindow` is still refused before any key is
derived, which is the rule that was protecting against a forger.

On top of that, `applyLinkStep` now calls `discardAmeSessionSkipped` when a
package completes or fails. That is the moment it becomes knowable that
nothing outstanding can still be useful, and it is the only place that knows
it -- FOMKE says so itself. It also unblocks rekeying, because a KEM upgrade
refuses to run while any skipped key is outstanding.

Measured on the same run, same settings: **170 packages and everything dead
after ten seconds → 1,114 packages and still climbing after forty-five.**

Pinned by two regression tests in `evaluation/tests/test_fomke.nim`.

### 2. A sender never gave up, so one dead peer pinned a relay slot for good

**Found by the long run, and worse than it sounds.** Two minutes in, both
servers reported all sixty-four slots occupied while every client peer was
shut out. The slots were held by links whose peer had gone.

The receiver could always give up: when its repair rounds are spent and chunks
are still missing it says so and closes the receive. The SENDER had no such
rule. Once `dacSenderRepairDue` stopped returning true -- which is all that
happens when the rounds run out -- it simply stopped speaking, and
`outgoing.active` stayed true with nothing left that could ever clear it:

```
  server echoes a receipt  ──▶  peer has closed its socket
           |                    rounds spent, nothing acknowledged
           |                    nothing more is sent
           v                    nothing clears outgoing
  the link is never idle
  dacSlotReclaimable refuses to take it, correctly
  the slot is held until the process ends
```

The rule that pinned it is itself right: a slot whose link has either
direction active must never be taken, whatever pressure the table is under.
The hole was that one direction could be active forever.

`dacSenderGaveUp` is the sender's half of the sentence the receiver already
spoke: every round spent, twice the repair wait passed since the last one,
nothing acknowledged -- the package is lost, `abandonDacPackage` releases it,
and the link goes idle so its slot can be reused. Twice the wait rather than
once, because the last round still has to be answered: the parity has to
arrive, be used, and the receipt has to come back. The wait is measured
receipt latency, so two of them is comfortably more than one round trip.

Nobody is told. The peer never acknowledged anything, so there is nobody
listening to tell.

Pinned by two tests in `evaluation/tests/test_dac_link_giveup.nim`: one that a
sender whose peer vanished lets go, and one that a sender being acknowledged
normally never does.

### 3. A finished package left its receipt still asking to be sent, for ever

**The one that was actually stopping the servers.** The other two findings made
the run survivable; this one is why it stopped anyway. It took a per-slot dump
to see, because from outside it looked exactly like health: every slot
occupied, memory flat, nothing raised.

The ACK window slides over ARRIVALS only, never over a hole. That is
deliberate and right -- a sequence pushed below the base can never appear in a
receipt again, and the sender would spend repair rounds on chunks already
delivered. But the window belonged to one package, and the package used to end
without it:

```
  base                    the package is complete, and yet
   |  X  .  X  X          pending = 2, so the batch is still due
         ^                -> a receipt every deadline
         the hole that       -> the batch slides nowhere
         parity filled       -> so it happens again, and again
```

Every package repaired from parity -- the **normal** case under loss -- ends
with a hole somewhere in its window. So every such package left a batch that
would ask to be sent every `ackMaxDelayMs`, about ten sealed datagrams a
second per link, for the life of the process, to a peer that had usually
stopped listening.

It cost far more than bandwidth. `tickAmeDacRelay` refreshes a slot's
`lastSeenMs` whenever its link produced anything, so a link talking to itself
kept looking alive:

```
  receipt emitted  ──▶  step has messages  ──▶  lastSeenMs = now
                                                 |
                              dacSlotReclaimable needs quiet
                                                 |
                              so the slot is never quiet
                              never reclaimed, never reused
```

Both servers reached all sixty-four slots held by peers that had gone, refused
every peer that was still there, and sat there sending nine hundred and
sixty-seven datagrams a second into nothing. The report line said `live=32`,
`rss` flat, no errors.

`endDacIncoming` ends the two things together. One last receipt still goes out
and that one is load-bearing -- a `damVerified` receiver carries its commit
count in every receipt, which is how a sender whose commit message was lost
still learns the package landed. No other mode gets one, because no other mode
has a reason: they have all just sent a commit, and a NACK-only receiver that
saw a clean run must stay silent.

Same run, same settings, before and after:

| | before | after |
|---|---|---|
| packages verified | 2,878, frozen at t=135 | **17,159, still climbing at t=270** |
| bytes verified | 70 MB | **414 MB** |
| handshakes served | 73, frozen | **521** |
| slots reclaimed | 22, frozen | **319** |
| datagrams sent | 288,548 and accelerating | **85,969** |
| datagrams received | 127,485, frozen | **870,121** |

The send-to-receive ratio is the tell. A receiver that sends twice what it
reads is not a receiver.

Pinned by "a package repaired from parity leaves nothing still asking to be
sent" in `evaluation/tests/test_dac_link_giveup.nim`.
### 4. The worst loss was the one nobody induced

The soak drops 2% of datagrams on purpose. The kernel was quietly dropping
more than that, in a far more damaging shape, and nothing in the program could
see it.

A UDP socket has ONE queue. Everything that arrives while the program is busy
elsewhere waits in it, and when it is full the kernel throws the next datagram
away without telling anybody — no error, no signal, nothing on the wire. It is
counted, and only in two places:

```
  /proc/net/snmp   the RcvbufErrors column, for the whole machine
  /proc/net/udp    the last column, per socket
```

Reading them mid-run: **295,324** receive-buffer errors on the machine, and
every one of the soak's data sockets climbing. The default queue is 208 KB
here (`net.core.rmem_default`) — generous for one conversation, small for one
listener carrying forty-eight peers' chunked packages.

**Why a burst is worse than the same loss scattered.** A full queue drops
everything until it drains, so the losses arrive in runs. The ratchet refuses
a gap wider than the reordering it has measured, and a run of losses is
exactly such a gap — so socket-buffer overflow, not the induced loss, was what
produced nearly every FOMKE window refusal in a run.

`openDacListener` takes `recvBufferBytes` now, and `setUdpReceiveBuffer`
explains the arithmetic. The kernel may give less than asked: Linux doubles
the value for its own bookkeeping and then caps it at `net.core.rmem_max`, so
a four-megabyte request on a machine capped at four megabytes gives four. That
is not an error and is not reported — a smaller queue is still a queue.

Measured, same 72-second run, same peers, same induced loss:

| | 208 KB, the default | 4 MB |
|---|---|---|
| kernel drops, 8 sockets | **2,787** | **2** |
| packages verified | 10,707 | **14,363** |
| bytes verified | 258 MB | **345 MB** |
| packages failed | 235 | **146** |

A third more work done, from one socket option. Worth saying plainly: this is
not a protocol fix, it is a deployment one. Any server built on this needs to
size its queue, and the library now lets it.
### 5. A reclaimed slot is silent — still open

When `sweepAmeDacRelay` reclaims a slot, the peer is never told. It keeps
sending into a relay that has no session for it, and every datagram is dropped
without a reply. From the peer's side that is indistinguishable from a path
that started losing everything.

Dropping in silence is **correct** as far as it goes: replying to a datagram
from an address that holds no session is a reflection vector, and refusing to
is the right default. But it leaves a peer with no way to learn the truth, and
the only thing it can do is wait out its own timeout -- once per package,
forever.

The soak measures the cost. In a run over-subscribed on slots, peers spent
roughly **80% of the run waiting on links that were already gone.**

The usual answer is a stateless reset: a token the peer handed over in advance,
returned when its session is not found, smaller than the datagram that
triggered it so it amplifies nothing. Bifrost has no such thing. **This is a
design decision, not a bug, and it has not been made.** The soak client works
around it by giving up on a session after two packages time out in a row.

### 6. A handshake could finish and then find no room

`admitAmeDacPeer` can refuse -- the relay holds a fixed number of live links,
which is the point of it. But by then the handshake has already run: two round
trips, a KEM exchange, and a session that is now thrown away. The client does
not know, because its own handshake returned a working session.

This is the server's to arrange, not the protocol's, and the soak server shows
the arrangement: its accept thread reads the live count its serve thread
publishes and does not answer at all when there is no room. A client that gets
no answer retries, which is the behaviour it already has for a lost record.

With the gate in: `admit-fail` 22 → 11, `relay-drop` roughly halved, packages
per run 1,114 → 1,398 on identical settings.

### 7. Two sockets, because there is no demultiplexer

Noted above and worth stating plainly: one socket cannot carry both a
handshake and live traffic, because the handshake driver consumes and discards
whatever it is not waiting for. Any real server has to either split the ports,
as this one does, or grow a demultiplexer that reads the frame kind first.

### 8. Things that held up

- **No payload ever arrived wrong.** Not once, across every run.
- **Nothing escaped a loop.** No exception reached a thread boundary, across
  every run, including the ones where every session on the machine was dead.
- **A refused gap is rare, and it is survivable.** The one FOMKE refusal still
  possible -- a burst of losses wider than the reorder window -- fired 24
  times in 205,000 datagrams. It is not recoverable within the session (a
  refused message advances nothing, so the next one is further ahead still),
  but the sweep and the client's own give-up put the peer back on a fresh
  session, which is what DTLS does too. Narrowing the window is now floored at
  the number of keys the lane is holding, so a lane that has recently seen
  gaps no longer shrinks its way into one.
- **Memory settled.** Server RSS sits around 7–11 MB and stops moving; Nim's
  own heap reading stays at one or two kilobytes because the traffic is all
  short-lived sequences.
- **Throughput, with nothing induced:** 54,186 packages and 442 MB in 24
  seconds across four peers, every byte verified -- about 18 MB/s of sealed,
  ratcheted, chunked traffic over loopback, with 8.5% of datagrams lost to
  kernel socket-buffer overrun and repaired.
- **`sweepAmeDacRelay` works,** and this is the first thing that has ever
  called it. Slots are reclaimed, sessions are erased before the slot is
  handed on, and a link mid-transfer is never taken. It could not do its job
  until finding 2 was fixed, because a link nobody let go of never became
  reclaimable -- but the sweep itself was never the thing at fault.
- **The reclamation rule is right.** `dacSlotReclaimable` refuses to take a
  slot whose link has either direction still active, whatever pressure the
  table is under. Every sweep observed was of a link that really had stopped.

---


## ╭⟢ What forty-six minutes looks like 🍣

Two server processes, three client processes, 48 peers over eight loopback
addresses, 112 peer slots, 2% induced loss each way, a fresh handshake every
sixty packages, packages of 256 to 48,000 bytes.

```sh
nimble soak --seconds=2700 --servers=2 --clients=3 --workers=4 \
            --peers=16 --capacity=14 --loss=20000 --size=48000 \
            --churn=60 --idle=12000 --report=120
```

```
  packages verified byte for byte    626,122
  bytes verified                      15.08 GB
  datagrams received                  22.8 million
  datagrams sent                       3.08 million
  handshakes served                   12,729
  relay slots reclaimed               12,053
  payload mismatches                  0
  escaped exceptions                  0
```

Ending with `soak: every process finished clean`.

### Memory, which is the whole reason to run it this long

```
  minutes:      2      8     14     22     30     38     46
  server 0:  15.9   17.5   17.7   18.0   18.4   18.4   18.6   MB
  server 1:  14.9   16.9   17.1   17.3   17.6   17.7   17.8   MB
  client 0:  33.1   40.4   44.3   46.6   48.4   49.2   49.4   MB
```

Read the DIFFERENCES rather than the values. Server 0 grew 1.6 MB in its first
six minutes and 1.1 MB over the thirty-eight after that; in its last eight
minutes it grew 172 KB, while opening and tearing down hundreds more sessions.
That is a curve flattening, not a line rising — the shape of an allocator
settling into its working set, not of something being kept.

Nim's own heap reading stays at one or two kilobytes throughout, on both
sides, because none of this traffic outlives the routine that made it.

## ╭⟢ Two numbers worth writing down 🌊

### How many slots a peer actually costs

More than one, and nothing says so anywhere. A peer that goes away leaves its
slot behind for the whole idle window, because there is no way to say goodbye:
`releaseAmeDacPeer` frees the slot on the side that calls it, and nothing
crosses the wire. So a server sizing its table by peer count will size it
wrong.

```
  slots needed  =  live peers  +  live peers x (idleMs / seconds between reconnects)
                   ^^^^^^^^^^^     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                   the ones          the ones that have gone and are still
                   talking           holding a slot until it ages out
```

Worked through, with the numbers from a soak run: 48 peers, each reconnecting
about every 30 seconds, `idleMs` of 20000.

```
  48  +  48 x (20 / 30)  =  48 + 32  =  80 slots, for 48 peers
```

That run was given 64. It sat permanently full, with most of those slots
holding peers that had gone, and turned away the peers that were still there.

Finding 3 was making this far worse than the arithmetic says -- a slot whose
link was still chattering never became reclaimable at all -- but the
arithmetic is real on its own, and stays true with that fixed. The same run
after the fix reclaimed 319 slots instead of 22 and served 521 handshakes
instead of 73, and STILL ran at capacity: the table was also sized for the
wrong number.

Three ways out, and the third is the real one:

```
  more slots        capacity above the arithmetic above
  shorter idleMs    but see the coupling below -- it has a floor
  say goodbye       a peer that closes politely tells the server, and the
                    slot is free at once instead of in twenty seconds
```

Bifrost has no goodbye. That is the same missing sentence as the stateless
reset in finding 3 -- one direction of it, anyway -- and worth deciding once
for both.

### The idle window has a floor


The idle window and the client's package timeout are **coupled**, and nothing
in the code says so.

A sender that has spent its repair rounds goes quiet while still believing it
is connected. If the server's `--idle` is shorter than that silence, the slot
is reclaimed underneath a peer that is about to try again:

```
  repairRounds × repairWaitMs        how long a sender can be quiet
  + the client's package timeout     before it gives up and retries
  ─────────────────────────────────
  must be LESS than idleMs
```

With the defaults that is roughly four seconds of possible silence, so an
`--idle` below about five seconds reclaims live peers. Above fifteen it does
not. The soak defaults to 15000 for that reason.
