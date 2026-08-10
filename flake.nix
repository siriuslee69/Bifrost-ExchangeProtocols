{
  description = "Bifrost Exchange Protocols";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system: f system nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (_: pkgs: {
        default = pkgs.callPackage ./nix/package.nix { };
        bifrost-exchange-protocols = pkgs.callPackage ./nix/package.nix { };
      });

      devShells = forAllSystems (_: pkgs:
        let
          sodiumLibPath = pkgs.lib.makeLibraryPath [ pkgs.libsodium ];
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              nim
              git
              gcc
              binutils
              gnumake
              pkg-config
              cmake
              autoconf
              automake
              libtool
              zig
              libsodium
            ];

            shellHook = ''
              export CC=${pkgs.gcc}/bin/gcc
              export AR=${pkgs.binutils}/bin/ar
              export LIBSODIUM_LIB_DIRS=${pkgs.libsodium}/lib
              export LD_LIBRARY_PATH=${sodiumLibPath}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
              echo "Bifrost Nix shell ready."
              echo "libsodium: $LIBSODIUM_LIB_DIRS"
            '';
          };
        });

      checks = forAllSystems (system: pkgs: {
        package = self.packages.${system}.default;
        tls = pkgs.callPackage ./nix/tls-check.nix { };
        module = pkgs.callPackage ./nix/module-check.nix {
          nixpkgsPath = nixpkgs.outPath;
          module = self.nixosModules.default;
        };
      });

      nixosModules.default = import ./nix/module.nix;
      nixosModules.bifrost-exchange-protocols = import ./nix/module.nix;
    };
}
