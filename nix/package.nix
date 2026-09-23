{ pkgs ? import <nixpkgs> {}
, preset ? "default"   # configs/<preset>.toml: what gets compiled
}:

let
  ## One source: configs/default.toml. [project] names the package; the
  ## chosen preset decides what is compiled (config.nims applies it).
  config = builtins.fromTOML (builtins.readFile ../configs/default.toml);
  project = config.project;

  nimsimdSrc = pkgs.fetchFromGitHub {
    owner = "guzba";
    repo = "nimsimd";
    rev = "3f6b2668ffb0867d0bf786a658b817763e611350";
    hash = "sha256-FO7ty/NIE/fNfGiiEaoAHLEb26fQCqai5V0ERYbEPTs=";
  };
in
pkgs.stdenv.mkDerivation {
  pname = if preset == "default" then project.name else "${project.name}-${preset}";
  version = project.version;
  meta.description = "${project.description} (preset: ${preset})";
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
      -d:preset=${preset} \
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
    cp -r configs "$out/share/bifrost/configs"
  '';
}
