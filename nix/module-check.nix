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
            transport.timeoutMs = 4000;
            transport.maxTcpFrameBytes = 16777216;
            aec.inboxCapacity = 64;
            ame.peerTrustRequired = true;
          };

          profiles.server.settings = {
            role = "server";
            dac.bind = "0.0.0.0:47655";
          };

          profiles.client = {
            mode = "replace";
            settings = {
              role = "client";
              transport.timeoutMs = 2000;
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

  grep -Fqx '[transport]' ${globalToml}
  grep -Fqx 'timeoutMs = 4000' ${globalToml}
  grep -Fqx 'maxTcpFrameBytes = 16777216' ${globalToml}
  grep -Fqx '[aec]' ${globalToml}
  grep -Fqx 'inboxCapacity = 64' ${globalToml}
  grep -Fqx '[ame]' ${globalToml}
  grep -Fqx 'peerTrustRequired = true' ${globalToml}

  grep -Fqx 'role = "server"' ${serverToml}
  grep -Fqx '[transport]' ${serverToml}
  grep -Fqx 'timeoutMs = 4000' ${serverToml}
  grep -Fqx 'maxTcpFrameBytes = 16777216' ${serverToml}
  grep -Fqx '[aec]' ${serverToml}
  grep -Fqx 'inboxCapacity = 64' ${serverToml}
  grep -Fqx '[ame]' ${serverToml}
  grep -Fqx 'peerTrustRequired = true' ${serverToml}
  grep -Fqx '[dac]' ${serverToml}
  grep -Fqx 'bind = "0.0.0.0:47655"' ${serverToml}

  grep -Fqx 'role = "client"' ${clientToml}
  grep -Fqx '[transport]' ${clientToml}
  grep -Fqx 'timeoutMs = 2000' ${clientToml}
  if grep -Fq 'peerTrustRequired = true' ${clientToml}; then
    echo "replace profile unexpectedly inherited global AME settings" >&2
    exit 1
  fi
  if grep -Fq 'inboxCapacity = 64' ${clientToml}; then
    echo "replace profile unexpectedly inherited global AEC settings" >&2
    exit 1
  fi
  if grep -Fq 'maxTcpFrameBytes = 16777216' ${clientToml}; then
    echo "replace profile unexpectedly inherited global transport settings" >&2
    exit 1
  fi

  cp ${serverToml} "$out"
''
