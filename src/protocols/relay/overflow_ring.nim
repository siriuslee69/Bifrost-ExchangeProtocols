## -------------------------------------------------------------------------
## overflow_ring <- a small fixed-width box that holds what cannot leave yet
## -------------------------------------------------------------------------
##
## A relay that is crowded would otherwise drop EVERYTHING it cannot send this
## instant. This box holds the newest few instead, so a short burst is smoothed
## out rather than lost.
##
##   width = 4 (the box never grows; its width is set once, when it is made)
##
##   empty:        [ . ][ . ][ . ][ . ]
##   after 3 in:   [ a ][ b ][ c ][ . ]      a leaves first
##   after 5 in:   [ e ][ b ][ c ][ d ]      a was thrown out to make room for e
##                    ^ oldest is b now
##
## "Throw out the OLDEST": the freshest datagrams are the ones worth keeping.
## Anything held here is something the carrier above can ask for again (DAC
## repair), so keeping more would spend memory to save what is recoverable.
##
## Width 0 means no box at all: every `addLast` is refused and counted.
##
## One memory cost: `width` slots, allocated once, never again.

import runePragmas
import var_invariants

type
  ## OverflowRing: `width` slots, a front and a count.
  ## dropped: items thrown out (to make room) or refused (width 0).
  OverflowRing*[T] {.role: memory, expectedCount: 1,
      lifeCycle: lcForever.} = object
    slots: seq[T]
    head: int
    used: int
    dropped*: uint64

proc initOverflowRing*[T](width: int): OverflowRing[T] {.role: configurator,
    needs: width >= 0.} =
  ## width: how many items fit. 0 = nothing is held.
  result.slots = newSeq[T](width)

proc width*[T](B: OverflowRing[T]): int {.role: parser, inline.} =
  ## B: the fixed number of slots.
  result = B.slots.len

proc len*[T](B: OverflowRing[T]): int {.role: parser, inline.} =
  ## B: how many items are held now.
  result = B.used

proc isFull*[T](B: OverflowRing[T]): bool {.role: parser, inline.} =
  ## B: true when the next `addLast` would throw the oldest out.
  result = B.used >= B.slots.len

proc popFirst*[T](B: var OverflowRing[T]): T {.role: actor, needs: B.used > 0.} =
  ## B: the OLDEST item, removed.
  result = B.slots[B.head]
  B.slots[B.head] = default(T)
  B.head = (B.head + 1) mod B.slots.len
  B.used = B.used - 1

proc peekFirst*[T](B: OverflowRing[T]): T {.role: parser, needs: B.used > 0.} =
  ## B: the oldest item, left in place.
  result = B.slots[B.head]

proc addLast*[T](B: var OverflowRing[T], item: T): bool {.role: actor.} =
  ## B/item: put the item last. When the box is full the OLDEST is thrown out
  ## and counted first. false only for width 0 (the item itself is refused and
  ## counted); true otherwise.
  if B.slots.len == 0:
    B.dropped = B.dropped + 1'u64
    return false
  if B.used >= B.slots.len:
    discard popFirst(B)
    B.dropped = B.dropped + 1'u64
  B.slots[(B.head + B.used) mod B.slots.len] = item
  B.used = B.used + 1
  result = true
