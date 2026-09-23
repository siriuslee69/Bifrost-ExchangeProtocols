{ config, lib, pkgs, ... }:

let
  cfg = config.programs.bifrost-exchange-protocols;
  project = (builtins.fromTOML (builtins.readFile ../configs/default.toml)).project;
  tomlFormat = pkgs.formats.toml { };

  ## Presets: configs/<name>.toml, one per kind of device. The SAME file
  ## chooses what the package compiles (-d:preset=<name>) and, through its
  ## [runtime] table, what /etc/bifrost/config.toml says. One source.
  ##
  ##   configs/default.toml --+
  ##   configs/<preset>.toml -+--> [runtime] --> /etc/bifrost/config.toml
  ##   settings (below) ------+                   (settings win)
  ##   configs/<preset>.toml ----> [define] ---> package build flags
  presetNames = map (lib.removeSuffix ".toml")
    (builtins.filter (lib.hasSuffix ".toml")
      (builtins.attrNames (builtins.readDir ../configs)));

  presetRuntime = name:
    (builtins.fromTOML (builtins.readFile (../configs + "/${name}.toml"))).runtime or { };

  effectiveGlobalSettings = lib.recursiveUpdate
    (lib.recursiveUpdate (presetRuntime "default") (presetRuntime cfg.preset))
    cfg.settings;

  hasSettings = settings: settings != { };

  generatedToml = name: settings:
    tomlFormat.generate "bifrost-${name}.toml" settings;

  effectiveProfileSettings = profileCfg:
    if profileCfg.mode == "replace" then
      profileCfg.settings
    else
      lib.recursiveUpdate effectiveGlobalSettings profileCfg.settings;

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
    enable = mkEnableOption "${project.name} ${project.version}: ${project.description}";

    preset = mkOption {
      type = types.enum presetNames;
      default = "default";
      example = "iot";
      description = ''
        Build preset from configs/: what the package compiles and the
        runtime values written to the global config. Settings below are
        laid over the preset's [runtime] table.
      '';
    };

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./package.nix { preset = cfg.preset; };
      defaultText = lib.literalExpression
        "pkgs.callPackage ./package.nix { preset = cfg.preset; }";
      description = "Bifrost package, built with the chosen preset.";
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
        defaultAmeInboxCapacity = 64;
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
      {
        "${cfg.target}".source =
          if cfg.configFile != null then cfg.configFile
          else generatedToml "global" effectiveGlobalSettings;
      }
      //
      (lib.mapAttrs'
        (name: profileCfg:
          lib.nameValuePair profileCfg.target {
            source = effectiveProfileSource name profileCfg;
          })
        (lib.filterAttrs (_: profileCfg: profileCfg.enable) cfg.profiles));
  };
}
