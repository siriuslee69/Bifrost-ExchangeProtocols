## -------------------------------------------------------------------------
## Restriction address <- the one routine of the address reader that needs a Bifrost type
## -------------------------------------------------------------------------
##
## The address reader itself (IPv4 and IPv6 text, the compact `SourceAddr`,
## `::ffff:` folding, `hostGroupKey`) moved on 2026-11-19 to Fylgia-Utils:
## `protocols/intake/address.nim`. A sender's address is read in Bifrost, Nebel,
## Fjord and Torii, and a limit that counts "per address" is only as good as the
## one place that says which addresses are the SAME sender.
##
## What stays here is the one routine that needs Bifrost's own UDP address type.

import ../transport/types as transport_types
import runePragmas
import protocols/intake/address

proc sourceOfAddress*(a: transport_types.UdpAddress): tuple[ok: bool,
    src: SourceAddr, err: string] {.role: sanitizer.} =
  ## a: the address a neighbour's datagrams arrive from.
  result = sourceOf(a.host, a.port)
