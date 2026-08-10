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
| submodules/Eir-CompressionAndECC | compression/ECC helpers | nimble file: UNLICENSED |
+-------------------------+-------------------------------+----------------------------+
```

Release rule:
- keep these dependencies as submodules, not copied source;
- keep their upstream license files with the submodule checkout;
- do not redistribute copied source or binaries containing
  `submodules/Eir-CompressionAndECC` by default because its package metadata
  marks it as `UNLICENSED` and no root license file is present in the currently
  pinned checkout;
- for any private/unlicensed submodule, either exclude it from public release
  artifacts or obtain and record explicit redistribution permission first.

## Optional Nested Submodules

Some direct dependencies declare their own nested submodules for optional or
extended builds, such as OpenSSL, libsodium, liboqs, PQClean, LZ4, and Zstd.
Bifrost's verified default build/test path does not require those nested
checkouts to be initialized.

If a release enables optional features that compile those nested dependencies,
initialize them recursively and include their upstream license files in the
release bundle.
