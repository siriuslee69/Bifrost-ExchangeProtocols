{ pkgs ? import <nixpkgs> {} }:

let
  nimsimdSrc = pkgs.fetchFromGitHub {
    owner = "guzba";
    repo = "nimsimd";
    rev = "3f6b2668ffb0867d0bf786a658b817763e611350";
    hash = "sha256-FO7ty/NIE/fNfGiiEaoAHLEb26fQCqai5V0ERYbEPTs=";
  };
  commonPaths = [
    "--path:src"
    "--path:submodules/Fylgia-Utils/src"
    "--path:submodules/Tyr-Crypto/src"
    "--path:submodules/Tyr-Crypto"
    "--path:submodules/SIMD-Nexus/src"
    "--path:${nimsimdSrc}/src"
    "--path:submodules/Eir-CompressionAndECC/src"
  ];
in
pkgs.stdenv.mkDerivation {
  pname = "bifrost-tls-check";
  version = "0.1.0";
  src = pkgs.lib.cleanSource ../.;

  nativeBuildInputs = [
    pkgs.nim
    pkgs.openssl
    pkgs.pkg-config
  ];

  buildInputs = [
    pkgs.openssl
  ];

  buildPhase = ''
    export HOME="$TMPDIR"
    mkdir -p build/tests

    nim c \
      --nimcache:nimcache_tls_transport \
      --out:build/tests/test_transport_ops_tls \
      ${builtins.concatStringsSep " \\\n      " commonPaths} \
      --threads:on \
      -d:ssl \
      -r \
      tests/test_transport_ops.nim

  '';

  installPhase = ''
    touch "$out"
  '';
}
