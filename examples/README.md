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
