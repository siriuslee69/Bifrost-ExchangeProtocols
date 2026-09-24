# Third-Party Licenses

This repository is intentionally unlicensed at the root. Treat it and any
submodule marked `UNLICENSED` as private/internal unless a separate license grant
is provided. Source dependencies are kept as git submodules so their code,
history, and license files stay separate from Bifrost source.

## Direct Source Submodules

```text
+-------------------------+-------------------------------+----------------------------+
| Path                    | Purpose                       | License evidence           |
+-------------------------+-------------------------------+----------------------------+
| submodules/Fylgia-Utils | shared Nim utility helpers    | LICENSE.txt: Unlicense     |
| submodules/Tyr-Crypto   | crypto primitives and wrappers| nimble file: Unlicense     |
| submodules/SIMD-Nexus   | SIMD helper layer             | LICENSE: Unlicense         |
| submodules/Eir-CompressionAndECC | compression/ECC helpers | LICENSE: Unlicense (from ed3ba8a) |
| submodules/Rune-Pragmas  | role/tag pragma definitions   | UNLICENSE: Unlicense       |
| submodules/Nimble-Tasks  | shared nimble tasks (build)   | UNLICENSE: Unlicense       |
| submodules/Otter-RepoEvaluation | evaluation tooling (dev) | LICENSE.txt: Unlicense |
+-------------------------+-------------------------------+----------------------------+
```

Release rule:
- keep these dependencies as submodules, not copied source;
- keep their upstream license files with the submodule checkout;
- `submodules/Eir-CompressionAndECC` is Unlicense from commit ed3ba8a on; a
  pin older than that is the earlier proprietary license, so release from a
  pin at or after it. Its vendored LZ4 and Zstandard keep their BSD licenses;
- for any private/unlicensed submodule, either exclude it from public release
  artifacts or obtain and record explicit redistribution permission first.

## Package Dependencies

```text
+----------+-----------------------------------+----------------------------------+
| Package  | Why                               | License evidence                 |
+----------+-----------------------------------+----------------------------------+
| nimsimd  | SIMD intrinsics for SIMD-Nexus and| nimsimd.nimble: MIT. `nimble`    |
|          | Tyr-Crypto (>= 1.3.2)             | installs it; nix/package.nix     |
|          |                                   | fetches a pinned copy            |
+----------+-----------------------------------+----------------------------------+
```

MIT asks that its copyright and permission notice travel with copies. A
release bundle that ships nimsimd code (it is compiled into any SIMD build)
includes the nimsimd license text next to this file.

## Optional Nested Submodules

Some direct dependencies declare their own nested submodules for optional or
extended builds, such as OpenSSL, libsodium, liboqs, PQClean, LZ4, and Zstd.
Bifrost's verified default build/test path does not require those nested
checkouts to be initialized.

If a release enables optional features that compile those nested dependencies,
initialize them recursively and include their upstream license files in the
release bundle.
