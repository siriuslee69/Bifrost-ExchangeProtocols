## ---------------------------------------------------------------------
## Wait readable <- wait for sockets, however many there are
## ---------------------------------------------------------------------
##
##   waitReadable(fds, 200)     "wake me when one of these has a datagram, or
##                               after 200 ms"
##
## After the call `fds` holds ONLY the sockets that have something to read,
## and the answer is how many that are.
##
## WHY NOT Nim's `selectRead`. It keeps its list in a fixed-size table, and
## what happens to a socket that does not fit depends on the machine:
##
##   machine   table holds     a socket that does not fit
##   --------  --------------  ---------------------------------------------
##   Linux     numbers 0-1023  its number is written PAST THE END of the
##                             table. A build with glibc's fortify checks
##                             stops the program ("bit out of range 0 -
##                             FD_SETSIZE on fd_set": every client loses its
##                             service); a build without them overwrites
##                             whatever lies next to the table and goes on
##   Windows   64 sockets      it is left out without a word, and whatever
##                             arrives on it is never read
##
## A program does not need 1024 sockets to meet the Linux case: it needs ONE
## socket whose number is above 1023, which any process holding many files
## and connections has. Bifrost's own `recvUdpDatagram` and `readAvailableSocket`
## wait through this module for that reason. A forwarder built for 1024 clients
## owns 1026 sockets, so both cases are one busy day away.
## This module has no such table:
##
##   Linux and others   `poll`, which takes a list of any length
##   Windows            the sockets asked in groups of 60, without waiting,
##                      again every 2 ms until one answers or the time is up
##
## The Windows way costs up to 2 ms of delay when nothing is ready; it is
## the price of not losing a client.

import std/[nativesockets, os]
import runePragmas

when defined(posix):
  import std/posix
else:
  import std/[monotimes, times]

const
  waitGroupSize*: int = 60
    ## Windows: the most sockets one `select` is given (its table holds 64).
  waitStepMs*: int = 2
    ## Windows: how long to rest between two rounds when nothing is ready.

when defined(posix):
  proc pollReadable(fds: var seq[SocketHandle], timeoutMs: int): int {.
      role: helper, tag: "networkSurface".} =
    ## fds/timeoutMs: `poll` over the whole list. A socket that reports an
    ## error or a hang-up counts as ready too: reading it shows the error,
    ## which is what `select` does as well.
    var
      P: seq[TPollfd] = @[]
      ready: seq[SocketHandle] = @[]
      i: int = 0
      n: cint = 0
    if fds.len == 0:
      if timeoutMs > 0:
        sleep(timeoutMs)
      return 0
    P = newSeq[TPollfd](fds.len)
    while i < fds.len:
      P[i].fd = cint(fds[i])
      P[i].events = POLLIN
      i = i + 1
    n = poll(addr P[0], Tnfds(P.len), cint(timeoutMs))
    i = 0
    while n > 0 and i < P.len:
      if P[i].revents != 0:
        ready.add fds[i]
      i = i + 1
    fds = ready
    result = ready.len

else:
  proc readyNow(fds: seq[SocketHandle]): seq[SocketHandle] {.role: helper,
      tag: "networkSurface".} =
    ## fds: the ready ones, found by asking `waitGroupSize` sockets at a time
    ## and not waiting.
    var
      group: seq[SocketHandle] = @[]
      at: int = 0
    while at < fds.len:
      group = fds[at ..< min(at + waitGroupSize, fds.len)]
      if selectRead(group, 0) > 0:
        result.add group
      at = at + waitGroupSize

  proc pollReadable(fds: var seq[SocketHandle], timeoutMs: int): int {.
      role: helper, tag: "networkSurface".} =
    ## fds/timeoutMs: the groups asked again every `waitStepMs` until one is
    ## ready or the time is up (a negative time waits for ever).
    var
      began: MonoTime = getMonoTime()
      ready: seq[SocketHandle] = @[]
    ready = readyNow(fds)
    while ready.len == 0 and (timeoutMs < 0 or
        (getMonoTime() - began).inMilliseconds < timeoutMs):
      sleep(waitStepMs)
      ready = readyNow(fds)
    fds = ready
    result = ready.len

proc waitReadable*(fds: var seq[SocketHandle], timeoutMs: int): int {.
    role: helper, tag: "appApi|networkSurface".} =
  ## fds: the sockets to watch; afterwards only the ready ones are left.
  ## timeoutMs: the longest wait; 0 asks once and does not wait.
  ## Answers how many are ready: 0 when the time ran out or the wait was cut
  ## short by a signal (the caller's loop simply comes round again).
  result = pollReadable(fds, timeoutMs)
