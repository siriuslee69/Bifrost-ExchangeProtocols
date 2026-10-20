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
phone ==A==> router ==B==> nas
  ask      -> [0x20 "nas"]
  forward  -> nas receives "hello nas" from 0x30
  answer   -> phone receives "hi phone" from 0x20
```

One handshake per neighbour, with the router only. See
[docs/routing.md](../docs/routing.md).
