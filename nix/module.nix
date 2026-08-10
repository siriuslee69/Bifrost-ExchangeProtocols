{ config, lib, pkgs, ... }:

let
  cfg = config.programs.bifrost-exchange-protocols;
  tomlFormat = pkgs.formats.toml { };

  hasSettings = settings: settings != { };

  generatedToml = name: settings:
    tomlFormat.generate "bifrost-${name}.toml" settings;

  effectiveProfileSettings = profileCfg:
    if profileCfg.mode == "replace" then
      profileCfg.settings
    else
      lib.recursiveUpdate cfg.settings profileCfg.settings;

  effectiveProfileSource = name: profileCfg:
    if profileCfg.configFile != null then
      profileCfg.configFile
    else
      generatedToml name (effectiveProfileSettings profileCfg);

  mkProfileOptions = with lib; { name, ... }: {
    options = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Generate this named Bifrost profile.";
      };

      mode = mkOption {
        type = types.enum [ "merge" "replace" ];
        default = "merge";
        description = "Merge global settings into this profile, or replace them.";
      };

      target = mkOption {
        type = types.str;
        default = "bifrost/profiles/${name}.toml";
        description = "Path below /etc for the generated or external profile.";
      };

      settings = mkOption {
        type = tomlFormat.type;
        default = { };
        description = "Declarative Bifrost user/profile TOML settings.";
      };

      configFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "External profile config file. Mutually exclusive with settings.";
      };
    };
  };
in
{
  options.programs.bifrost-exchange-protocols = with lib; {
    enable = mkEnableOption "Bifrost exchange protocol library and generated configs";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./package.nix { };
      description = "Bifrost package to expose through environment.systemPackages.";
    };

    installPackage = mkOption {
      type = types.bool;
      default = true;
      description = "Add the Bifrost package to environment.systemPackages.";
    };

    target = mkOption {
      type = types.str;
      default = "bifrost/config.toml";
      description = "Path below /etc for the global generated Bifrost config.";
    };

    settings = mkOption {
      type = tomlFormat.type;
      default = { };
      example = {
        maxTcpFrameBytes = 16777216;
        maxDacFrameBytes = 16777216;
        defaultAecInboxCapacity = 64;
        defaultTimeoutMs = 4000;
        peerTrustRequired = true;
      };
      description = "Declarative global Bifrost TOML settings.";
    };

    configFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "External global config file. Mutually exclusive with settings.";
    };

    profiles = mkOption {
      type = types.attrsOf (types.submodule mkProfileOptions);
      default = { };
      description = "Named user/client/server Bifrost profile configs.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions =
      [
        {
          assertion = !(cfg.configFile != null && hasSettings cfg.settings);
          message = "programs.bifrost-exchange-protocols: configFile and settings are mutually exclusive.";
        }
      ]
      ++
      (lib.mapAttrsToList (name: profileCfg: {
        assertion = !(profileCfg.configFile != null && hasSettings profileCfg.settings);
        message = "programs.bifrost-exchange-protocols.profiles.${name}: configFile and settings are mutually exclusive.";
      }) cfg.profiles);

    environment.systemPackages = lib.mkIf cfg.installPackage [ cfg.package ];

    environment.etc =
      (lib.optionalAttrs (cfg.configFile != null || hasSettings cfg.settings) {
        "${cfg.target}".source =
          if cfg.configFile != null then cfg.configFile else generatedToml "global" cfg.settings;
      })
      //
      (lib.mapAttrs'
        (name: profileCfg:
          lib.nameValuePair profileCfg.target {
            source = effectiveProfileSource name profileCfg;
          })
        (lib.filterAttrs (_: profileCfg: profileCfg.enable) cfg.profiles));
  };
}
