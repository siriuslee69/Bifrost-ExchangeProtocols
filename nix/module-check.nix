{ pkgs ? import <nixpkgs> {}
, nixpkgsPath ? pkgs.path
, module ? import ./module.nix
}:

let
  evalConfig = import "${nixpkgsPath}/nixos/lib/eval-config.nix";

  mergeEval = evalConfig {
    system = pkgs.stdenv.hostPlatform.system;
    modules = [
      module
      ({ ... }: {
        system.stateVersion = "26.05";
        programs.bifrost-exchange-protocols = {
          enable = true;
          installPackage = false;
          package = pkgs.hello;

          settings = {
            maxTcpFrameBytes = 16777216;
            defaultTimeoutMs = 4000;
            defaultAmeInboxCapacity = 64;
            peerTrustRequired = true;
            fomke.fomkePregeneration = false;
          };

          profiles.server.settings = {
            maxDacFrameBytes = 8388608;
          };

          profiles.client = {
            mode = "replace";
            settings = {
              defaultTimeoutMs = 2000;
            };
          };

          profiles.disabled = {
            enable = false;
            settings.role = "ignored";
          };
        };
      })
    ];
  };
  mergeEtc = mergeEval.config.environment.etc;
  globalToml = mergeEtc."bifrost/config.toml".source;
  serverToml = mergeEtc."bifrost/profiles/server.toml".source;
  clientToml = mergeEtc."bifrost/profiles/client.toml".source;

  externalGlobal = pkgs.writeText "bifrost-module-global.toml" ''
    role = "global-external"
  '';
  externalProfile = pkgs.writeText "bifrost-module-profile.toml" ''
    role = "profile-external"
  '';

  externalEval = evalConfig {
    system = pkgs.stdenv.hostPlatform.system;
    modules = [
      module
      ({ ... }: {
        system.stateVersion = "26.05";
        programs.bifrost-exchange-protocols = {
          enable = true;
          installPackage = false;
          package = pkgs.hello;
          configFile = externalGlobal;
          profiles.external = {
            configFile = externalProfile;
            target = "bifrost/profiles/external.toml";
          };
        };
      })
    ];
  };
  externalEtc = externalEval.config.environment.etc;

  invalidGlobal = builtins.tryEval (
    (evalConfig {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        module
        ({ ... }: {
          system.stateVersion = "26.05";
          programs.bifrost-exchange-protocols = {
            enable = true;
            installPackage = false;
            package = pkgs.hello;
            configFile = externalGlobal;
            settings.transport.timeoutMs = 1;
          };
        })
      ];
    }).config.system.build.toplevel
  );

  invalidProfile = builtins.tryEval (
    (evalConfig {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        module
        ({ ... }: {
          system.stateVersion = "26.05";
          programs.bifrost-exchange-protocols = {
            enable = true;
            installPackage = false;
            package = pkgs.hello;
            profiles.bad = {
              configFile = externalProfile;
              settings.role = "bad";
            };
          };
        })
      ];
    }).config.system.build.toplevel
  );
in
assert builtins.hasAttr "bifrost/config.toml" mergeEtc;
assert builtins.hasAttr "bifrost/profiles/server.toml" mergeEtc;
assert builtins.hasAttr "bifrost/profiles/client.toml" mergeEtc;
assert !builtins.hasAttr "bifrost/profiles/disabled.toml" mergeEtc;
assert builtins.toString externalEtc."bifrost/config.toml".source == builtins.toString externalGlobal;
assert builtins.toString externalEtc."bifrost/profiles/external.toml".source == builtins.toString externalProfile;
assert invalidGlobal.success == false;
assert invalidProfile.success == false;
pkgs.runCommand "bifrost-module-check" { } ''
  set -eu

  grep -Fqx "defaultTimeoutMs = 4000" ${globalToml}
  grep -Fqx "maxTcpFrameBytes = 16777216" ${globalToml}
  grep -Fqx "defaultAmeInboxCapacity = 64" ${globalToml}
  grep -Fqx "peerTrustRequired = true" ${globalToml}
  grep -Fqx "[fomke]" ${globalToml}
  grep -Fqx "fomkePregeneration = false" ${globalToml}

  grep -Fqx "defaultTimeoutMs = 4000" ${serverToml}
  grep -Fqx "maxTcpFrameBytes = 16777216" ${serverToml}
  grep -Fqx "defaultAmeInboxCapacity = 64" ${serverToml}
  grep -Fqx "peerTrustRequired = true" ${serverToml}
  grep -Fqx "maxDacFrameBytes = 8388608" ${serverToml}

  grep -Fqx "defaultTimeoutMs = 2000" ${clientToml}
  if grep -Fq 'peerTrustRequired = true' ${clientToml}; then
    echo "replace profile unexpectedly inherited global AME settings" >&2
    exit 1
  fi
  if grep -Fq "defaultAmeInboxCapacity = 64" ${clientToml}; then
    echo "replace profile unexpectedly inherited global fomke settings" >&2
    exit 1
  fi
  if grep -Fq 'maxTcpFrameBytes = 16777216' ${clientToml}; then
    echo "replace profile unexpectedly inherited global transport settings" >&2
    exit 1
  fi

  cp ${serverToml} "$out"
''
