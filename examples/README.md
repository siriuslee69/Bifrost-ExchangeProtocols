# Bifrost Examples

Run all examples through Nimble so binaries stay under `build/examples/`:

```text
nimble examples
```

Run the AME mask-tier path example:

```text
nimble exampleAmeExactPath
```

Avoid raw `nim c -r examples/...` here.

`ame_exact_path.nim` demonstrates:

```text
immutable algorithm layout -> ordered mask tiers -> data trigger
```

Each family and tier path may contain up to eight slots. Repeated KEM
algorithms are independent.

Run the relayFastExtraFrame example:

```text
nimble exampleRelayFast
```

`relay_fast_extra_frame.nim` demonstrates:

```text
phone ==link A==> relay ==link B==> nas
  ask        (AME frame, for the relay)    -> [0x20 "nas"]
  AM1P       (inside ART route frames)     -> phone <-> nas, end to end
  "hello nas" on that session              -> the relay only re-seals
                                              the 16-byte address
  every datagram is fed with the address it came from
```

Run the relaySlowExtractEncrypt example:

```text
nimble exampleRelaySlow
```

`relay_slow_extract_encrypt.nim` demonstrates:

```text
phone ==link A==> relay ==link B==> nas
  "R:/notes"   relay opens it, its rule says yes  -> nas gets it
  "W:/notes"   relay opens it, its rule says no   -> phone hears arrNoRoute
```

`relay_links.nim` is not an example of its own: it makes the link pairs
both examples use.

One handshake per neighbour, with the router only. See
[docs/routing.md](../docs/routing.md).
