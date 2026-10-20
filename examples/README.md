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

Run the AME router example:

```text
nimble exampleRouter
```

`ame_router.nim` demonstrates:

```text
phone ==link A==> router ==link B==> nas
  ask        (AME frame, for the router)   -> [0x20 "nas"]
  AM1P       (inside ART route frames)     -> phone <-> nas, end to end
  "hello nas" on that session              -> the router only re-seals
                                              the 16-byte address
```

One handshake per neighbour, with the router only. See
[docs/routing.md](../docs/routing.md).
