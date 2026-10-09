# NixOS module for the wgmesh relay (the data plane that carries traffic
# between nodes that cannot reach each other directly).
#
# The skeleton is the agent's, with two differences that matter: the relay never
# touches the kernel's network configuration, so it asks for no capabilities at
# all, and it opens the UDP port range its slots are allocated from rather than
# a single port.
#
# Secrets (the enrollment token) arrive as a systemd credential and are named
# through the environment, never in the configuration file -- see agent.nix for
# the mechanics.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.wgmesh.relay;

  toml = pkgs.formats.toml { };

  stateDir = toString cfg.stateDir;
  stateDirName = baseNameOf stateDir;

  renderedSettings = lib.recursiveUpdate cfg.settings {
    # systemd gives the service StateDirectory=<stateDirName>, so the relay has
    # to look for its state (and its generated signing key) in the same place.
    state = (cfg.settings.state or { }) // {
      dir = stateDir;
    };
  };

  credentialEnvironment = lib.optionalAttrs (cfg.enrollmentTokenFile != null) {
    WGMESH__ENROLLMENT__TOKEN_FILE = "%d/enrollment-token";
  };

  portRange = cfg.settings.relay.port_range or [ ];
  portRangeValid = lib.isList portRange && lib.length portRange == 2;
in
{
  options.services.wgmesh.relay = {
    enable = lib.mkEnableOption "the wgmesh relay";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.wgmesh;
      defaultText = lib.literalExpression "pkgs.wgmesh";
      description = "The wgmesh package to run.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "wgmesh";
      description = "User the relay runs as. It is created if it does not exist.";
    };

    stateDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/wgmesh";
      description = ''
        State directory. systemd provides it as the service's StateDirectory,
        and the module points the relay's `state.dir` at it. The relay's
        Ed25519 signing key is generated here on first start unless it is
        provisioned.
      '';
    };

    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        Use this file as /etc/wgmesh/relay.toml instead of rendering
        `settings`. When set, `settings` is ignored.
      '';
    };

    settings = lib.mkOption {
      type = toml.type;
      default = { };
      description = ''
        The relay configuration, rendered verbatim into /etc/wgmesh/relay.toml.
        A one-to-one mirror of the TOML format; the configuration reference is
        the only schema you need.
      '';
      example = lib.literalExpression ''
        {
          relay = {
            listen = "0.0.0.0";
            port_range = [ 51820 51999 ];
          };
          coordinator = {
            url = "https://wgmesh.example.com";
            spki_sha256 = "…";
          };
        }
      '';
    };

    enrollmentTokenFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        File holding the relay's enrollment token. Loaded as the
        `enrollment-token` credential and referenced as
        WGMESH__ENROLLMENT__TOKEN_FILE=%d/enrollment-token.
      '';
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Open `settings.relay.port_range` (UDP) in the firewall. The relays' slot
        sockets are bound inside that range.
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
      description = "Log level, passed to the relay as WGMESH__LOG__LEVEL.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.configFile != null || (cfg.settings.coordinator.spki_sha256 or "") != "";
        message = "services.wgmesh.relay: settings.coordinator.spki_sha256 is required unless configFile is set";
      }
      {
        assertion = cfg.configFile != null || (cfg.settings.coordinator.url or "") != "";
        message = "services.wgmesh.relay: settings.coordinator.url is required unless configFile is set";
      }
      {
        assertion = !cfg.openFirewall || portRangeValid;
        message = "services.wgmesh.relay: openFirewall is set but settings.relay.port_range is not a [from to] pair";
      }
      {
        assertion = lib.hasPrefix "/var/lib/" stateDir;
        message = "services.wgmesh.relay: stateDir must be below /var/lib (it is the name systemd's StateDirectory= provides): ${stateDir}";
      }
    ];

    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.user;
    };
    users.groups.${cfg.user} = { };

    environment.etc."wgmesh/relay.toml".source =
      if cfg.configFile != null then
        cfg.configFile
      else
        toml.generate "relay.toml" renderedSettings;

    systemd.services.wgmesh-relayd = {
      description = "wgmesh relay";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      environment = credentialEnvironment // {
        WGMESH__LOG__LEVEL = cfg.logLevel;
      };

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/wgmesh-relayd run --config /etc/wgmesh/relay.toml";

        # `drain` stops taking new assignments and moves the ones it holds to
        # another relay: the maintenance switch for a live relay.
        ExecReload = "${cfg.package}/bin/wgmesh-relayd drain";

        User = cfg.user;
        Group = cfg.user;
        StateDirectory = stateDirName;
        StateDirectoryMode = "0750";
        RuntimeDirectory = stateDirName;
        RuntimeDirectoryMode = "0750";
        Restart = "always";
        RestartSec = 5;

        LoadCredential = lib.optionals (cfg.enrollmentTokenFile != null) [
          "enrollment-token:${toString cfg.enrollmentTokenFile}"
        ];

        # The relay forwards datagrams it receives; it never configures the
        # kernel, so it needs no capabilities at all.
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

    networking.firewall.allowedUDPPortRanges = lib.optionals (cfg.openFirewall && portRangeValid) [
      {
        from = lib.elemAt portRange 0;
        to = lib.elemAt portRange 1;
      }
    ];
  };
}
