{ pkgs ? import <nixpkgs> {} }:

let
  nimsimdSrc = pkgs.fetchFromGitHub {
    owner = "guzba";
    repo = "nimsimd";
    rev = "3f6b2668ffb0867d0bf786a658b817763e611350";
    hash = "sha256-FO7ty/NIE/fNfGiiEaoAHLEb26fQCqai5V0ERYbEPTs=";
  };
in
pkgs.stdenv.mkDerivation {
  pname = "bifrost-exchange-protocols";
  version = "0.1.0";
  src = pkgs.lib.cleanSource ../.;

  nativeBuildInputs = [
    pkgs.nim
  ];

  buildPhase = ''
    export HOME="$TMPDIR"
    nim c \
      --app:lib \
      --nimcache:nimcache_nix \
      --outdir:build/lib \
      --path:src \
      --path:submodules/Rune-Pragmas/meta \
      --path:submodules/Fylgia-Utils/src \
      --path:submodules/Tyr-Crypto/src \
      --path:submodules/Tyr-Crypto \
      --path:submodules/SIMD-Nexus/src \
      --path:${nimsimdSrc}/src \
      --path:submodules/Eir-CompressionAndECC/src \
      -d:release \
      src/bifrost_exchange_protocols.nim
  '';

  installPhase = ''
    mkdir -p "$out/lib" "$out/share/bifrost" "$out/share/nimble/pkgs/bifrost_exchange_protocols/src"
    cp build/lib/libbifrost_exchange_protocols.* "$out/lib/"
    find src -type f \( \
      -name '*.cpp' -o \
      -name '*.kt' -o \
      -name '*.kts' -o \
      -name '*.md' -o \
      -name '*.mk' -o \
      -name '*.nim' -o \
      -name '*.pro' -o \
      -name '*.xml' \
    \) -exec cp --parents '{}' "$out/share/nimble/pkgs/bifrost_exchange_protocols/" \;
    cp config.toml "$out/share/bifrost/config.toml"
  '';
}
