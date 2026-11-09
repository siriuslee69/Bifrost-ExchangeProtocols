## -------------------------------------------------------------------------
## DNS MX <- "which server takes mail for this domain", as bytes
## -------------------------------------------------------------------------
##
## The question, for domain "a.b", type MX (15), class IN (1):
##
##   +--------+-------+-------+-------+-------+-------+
##   | id     | flags | qd=1  | an=0  | ns=0  | ar=0  |   12 bytes, big-endian
##   +--------+-------+-------+-------+-------+-------+
##   | 01 'a' 01 'b' 00 | 00 0F | 00 01 |
##   +------------------+-------+-------+
##
## An answer repeats the question, then records. A name may end in a pointer
## (two bytes starting with bits 11) to a name earlier in the packet. A pointer
## must point backwards, and at most 16 are followed, so a bad packet cannot
## send the reader in circles.

import std/[algorithm, strutils]

import runePragmas

const
  dnsTypeMx = 15
  dnsMaxPointers = 16

type
  MxRecord* {.role: preparedData, tag: "mail|types".} = object
    ## One mail server of a domain. Lower preference is tried first.
    preference*: int
    host*: string

proc encodeMxQuery*(domain: string, id: uint16): seq[uint8] {.role: dataWriter,
    tag: "mail|wire".} =
  ## domain/id: the question above. Raises on a name DNS cannot carry.
  result = @[uint8(id shr 8), uint8(id and 255), 1'u8, 0'u8, 0'u8, 1'u8, 0'u8,
    0'u8, 0'u8, 0'u8, 0'u8, 0'u8]
  for part in domain.strip(chars = {'.'}).split('.'):
    if part.len == 0 or part.len > 63:
      raise newException(ValueError, "not a domain name: " & domain)
    result.add(uint8(part.len))
    for c in part: result.add(uint8(ord(c)))
  result.add([0'u8, 0'u8, 15'u8, 0'u8, 1'u8])

proc readDnsLabel(A: openArray[uint8], o: int, labels: var seq[string]): int {.
    role: parser, inline.} =
  ## A/o/labels: one plain label at o, added to labels. Returns where it ends.
  var
    n: int = int(A[o])
  if n > 63 or o + 1 + n > A.len:
    raise newException(ValueError, "dns label runs out")
  labels.add(newString(n))
  copyMem(addr labels[^1][0], unsafeAddr A[o + 1], n)
  result = o + 1 + n

proc readDnsName(A: openArray[uint8], start: int): tuple[name: string, next: int] {.
    role: parser.} =
  ## A/start: one name. `next` is where the record goes on. Raises when broken.
  var
    o: int = start
    jumps: int = 0
    target: int = 0
    labels: seq[string] = @[]
  result.next = -1
  while true:
    if o >= A.len:
      raise newException(ValueError, "dns name runs out")
    if (int(A[o]) and 0xC0) != 0xC0:
      if A[o] == 0'u8:
        break
      o = readDnsLabel(A, o, labels)
      continue
    if o + 1 >= A.len or jumps >= dnsMaxPointers:
      raise newException(ValueError, "dns name has bad pointers")
    if result.next < 0: result.next = o + 2
    target = ((int(A[o]) and 0x3F) shl 8) or int(A[o + 1])
    if target >= o:
      raise newException(ValueError, "dns pointer goes forward")
    o = target
    jumps = jumps + 1
  if result.next < 0: result.next = o + 1
  result.name = labels.join(".").toLowerAscii()

proc u16At(A: openArray[uint8], o: int): int {.role: parser, inline.} =
  ## A/o: two big-endian bytes. Raises when they are not there.
  if o + 2 > A.len:
    raise newException(ValueError, "dns packet runs out")
  result = (int(A[o]) shl 8) or int(A[o + 1])

proc decodeMxAnswer*(A: openArray[uint8], id: uint16): seq[MxRecord] {.
    role: parser, tag: "mail|wire".} =
  ## A: the answer packet. id: the question's number. Hosts, best first.
  ## Raises on anything malformed or on a DNS error.
  var
    o: int = 12
    i: int = 0
    kind: int = 0
    size: int = 0
  if u16At(A, 0) != int(id) or (u16At(A, 2) and 0x800F) != 0x8000:
    raise newException(ValueError, "dns answer is not for this question, or says no")
  while i < u16At(A, 4):
    o = readDnsName(A, o).next + 4
    i = i + 1
  i = 0
  while i < u16At(A, 6):
    o = readDnsName(A, o).next
    kind = u16At(A, o)
    size = u16At(A, o + 8)
    if o + 10 + size > A.len:
      raise newException(ValueError, "dns record runs out")
    if kind == dnsTypeMx:
      result.add(MxRecord(preference: u16At(A, o + 10),
        host: readDnsName(A, o + 12).name))
    o = o + 10 + size
    i = i + 1
  result.sort(proc (a, b: MxRecord): int = cmp(a.preference, b.preference))
