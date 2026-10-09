# NixOS module for the wgmesh coordinator (the control plane: enrollment,
# configuration distribution, relay assignment and observation).
#
# The coordinator speaks plain HTTP and is meant to listen on the loopback
# address; TLS, ACME and the public name belong to a reverse proxy in front of
# it (see docs/nixos-modules.md for a Caddy example). `openFirewall` therefore
# defaults to false.
#
# It holds no private keys -- only public keys, hashes and assignments -- so it
# takes no capabilities and needs no credentials.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.wgmesh.coordinator;

  toml = pkgs.formats.toml { };

  stateDir = toString cfg.stateDir;
  stateDirName = baseNameOf stateDir;

  databasePath = "${stateDir}/coordinator.db";

  renderedSettings = lib.recursiveUpdate cfg.settings {
    # The defaults this module is responsible for: a loopback listener, and a
    # database inside the state directory systemd hands the service.
    api = (cfg.settings.api or { }) // {
      listen = cfg.settings.api.listen or "127.0.0.1:8080";
    };
    database = (cfg.settings.database or { }) // {
      url = cfg.settings.database.url or "sqlite://${databasePath}?mode=rwc";
    };
  };

  apiListen = renderedSettings.api.listen;
  apiPort =
    if lib.hasInfix ":" apiListen then
      lib.toInt (lib.last (lib.splitString ":" apiListen))
    else
      null;
in
{
  options.services.wgmesh.coordinator = {
    enable = lib.mkEnableOption "the wgmesh coordinator";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.wgmesh;
      defaultText = lib.literalExpression "pkgs.wgmesh";
      description = "The wgmesh package to run.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "wgmesh";
      description = "User the coordinator runs as. It is created if it does not exist.";
    };

    stateDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/wgmesh";
      description = ''
        State directory. systemd provides it as the service's StateDirectory,
        and the SQLite database lives here unless `settings.database.url` says
        otherwise.
      '';
    };

    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        Use this file as /etc/wgmesh/coordinator.toml instead of rendering
        `settings`. When set, `settings` is ignored.
      '';
    };

    settings = lib.mkOption {
      type = toml.type;
      default = { };
      description = ''
        The coordinator configuration, rendered verbatim into
        /etc/wgmesh/coordinator.toml. A one-to-one mirror of the TOML format;
        the configuration reference is the only schema you need.
      '';
      example = lib.literalExpression ''
        {
          api.public_url = "https://wgmesh.example.com";
          policy.default_auto_approve = false;
        }
      '';
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Open the listen port of `settings.api.listen` (TCP). Leave this off and
        publish the coordinator through a reverse proxy instead: the API is
        meant to be reached over TLS.
      '';
    };

    logLevel = lib.mkOption {
      type = lib.types.enum [
        "error"
        "warn"
        "info"
        "debug"
        "trace"
      ];
      default = cfg.settings.log.level or "info";
      defaultText = lib.literalExpression ''"info"'';
      description = "Log level, passed to the coordinator as WGMESH__LOG__LEVEL.";
    };

    backup = {
      enable = lib.mkEnableOption "periodic SQLite backups of the coordinator database";

      startAt = lib.mkOption {
        type = lib.types.str;
        default = "daily";
        description = "systemd calendar expression for the backup timer.";
      };

      directory = lib.mkOption {
        type = lib.types.str;
        default = "/var/backup/wgmesh";
        description = ''
          Directory the backup is written to. Copy it off the machine: the
          database holds public keys and hashes, so a leaked backup is not
          catastrophic, but losing it costs a re-enrollment of every node.
        '';
      };

      databasePath = lib.mkOption {
        type = lib.types.str;
        default = databasePath;
        defaultText = lib.literalExpression ''"''${config.services.wgmesh.coordinator.stateDir}/coordinator.db"'';
        description = ''
          Database file to back up. Change it if `settings.database.url` does
          not point at the default location.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = apiPort != null;
        message = "services.wgmesh.coordinator: settings.api.listen must be <address>:<port>, got: ${apiListen}";
      }
      {
        assertion = !cfg.openFirewall || apiPort != null;
        message = "services.wgmesh.coordinator: openFirewall is set but settings.api.listen has no port: ${apiListen}";
      }
      {
        assertion = lib.hasPrefix "/var/lib/" stateDir;
        message = "services.wgmesh.coordinator: stateDir must be below /var/lib (it is the name systemd's StateDirectory= provides): ${stateDir}";
      }    ];

    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.user;
    };
    users.groups.${cfg.user} = { };

    environment.etc."wgmesh/coordinator.toml".source =
      if cfg.configFile != null then
        cfg.configFile
      else
        toml.generate "coordinator.toml" renderedSettings;

    systemd.services.wgmeshd = {
      description = "wgmesh coordinator";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      environment = {
        WGMESH__LOG__LEVEL = cfg.logLevel;
      };

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/wgmeshd run --config /etc/wgmesh/coordinator.toml";
        User = cfg.user;
        Group = cfg.user;
        StateDirectory = stateDirName;
        StateDirectoryMode = "0750";
        RuntimeDirectory = stateDirName;
        RuntimeDirectoryMode = "0750";
        Restart = "always";
        RestartSec = 5;

        # Control plane only: no capabilities, no kernel configuration.
        AmbientCapabilities = [ "" ];
        CapabilityBoundingSet = [ "" ];
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
        ];

        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectControlGroups = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectClock = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        NoNewPrivileges = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" ];
      };
    };

    networking.firewall.allowedTCPPorts = lib.optional (cfg.openFirewall && apiPort != null) apiPort;

    systemd.tmpfiles.rules = lib.mkIf (cfg.enable && cfg.backup.enable) [
      "d ${cfg.backup.directory} 0700 ${cfg.user} ${cfg.user} -"
    ];

    systemd.services.wgmesh-coordinator-backup = lib.mkIf cfg.backup.enable {
      description = "wgmesh coordinator SQLite backup";
      startAt = cfg.backup.startAt;
      serviceConfig = {
        Type = "oneshot";
        User = cfg.user;
        Group = cfg.user;
        ReadWritePaths = [ cfg.backup.directory ];
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
      };
      script = ''
        ${pkgs.sqlite}/bin/sqlite3 ${lib.escapeShellArg cfg.backup.databasePath} ".backup '${cfg.backup.directory}/coordinator.db'"
      '';
    };
  };
}
