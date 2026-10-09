# NixOS module for the wgmesh agent (the node side of the mesh).
#
# `settings` is a free-form mirror of the agent's TOML file. The module renders
# it as-is and never re-declares the schema, so there is exactly one place where
# the configuration format is defined. Only the few values the module itself has
# to act on -- the firewall port, whether this node forwards traffic, the log
# level, the state directory -- are read back out of `settings` or written into
# it.
#
# Secrets never appear in the configuration file. They are handed to the
# service with systemd's LoadCredential= and named through the environment as
# `%d/<name>`. systemd resolves specifiers in Environment= (see
# config_parse_environ -> unit_env_printf in src/core/load-fragment.c) and `d`
# is the credentials-directory specifier, so the value the service reads is
# /run/credentials/<unit>/<name>.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.wgmesh.agent;

  toml = pkgs.formats.toml { };

  stateDir = toString cfg.stateDir;
  stateDirName = baseNameOf stateDir;

  # Values the module knows first-hand, so the user does not have to repeat
  # them and cannot let them disagree with the unit. A hand-written file
  # supplied through `configFile` is used untouched.
  moduleManaged = {
    # systemd gives the service StateDirectory=<stateDirName>, so the agent has
    # to look for its state in the same place.
    state = (cfg.settings.state or { }) // {
      dir = stateDir;
    };
  }
  // lib.optionalAttrs cfg.forwarding.enable {
    # The module sets the forwarding sysctls declaratively. The agent would set
    # them too -- and would restore the old values on exit -- so it is told to
    # keep its hands off them.
    forwarding = (cfg.settings.forwarding or { }) // {
      enabled = true;
      sysctl = false;
    };
  };

  renderedSettings = lib.recursiveUpdate cfg.settings moduleManaged;

  credentialEnvironment =
    lib.optionalAttrs (cfg.enrollmentTokenFile != null) {
      WGMESH__ENROLLMENT__TOKEN_FILE = "%d/enrollment-token";
    }
    // lib.optionalAttrs (cfg.apiKeyFile != null) {
      WGMESH__INTERFACE__API_KEY_FILE = "%d/api-key";
    }
    // lib.optionalAttrs (cfg.wireguardKeyFile != null) {
      WGMESH__INTERFACE__PRIVATE_KEY_FILE = "%d/wg-key";
    };

  listenPort = cfg.settings.interface.listen_port or 0;
in
{
  options.services.wgmesh.agent = {
    enable = lib.mkEnableOption "the wgmesh agent";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.wgmesh;
      defaultText = lib.literalExpression "pkgs.wgmesh";
      description = "The wgmesh package to run.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "wgmesh";
      description = "User the agent runs as. It is created if it does not exist.";
    };

    stateDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/wgmesh";
      description = ''
        State directory. systemd provides it as the service's StateDirectory,
        and the module points the agent's `state.dir` at it.
      '';
    };

    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        Use this file as /etc/wgmesh/agent.toml instead of rendering
        `settings`. When set, `settings` is ignored and anything the module
        would have written into the file has to be there already.
      '';
    };

    settings = lib.mkOption {
      type = toml.type;
      default = { };
      description = ''
        The agent configuration, rendered verbatim into
        /etc/wgmesh/agent.toml. This is a one-to-one mirror of the TOML
        format: no key is re-declared here, so the configuration reference is
        the only schema you need.
      '';
      example = lib.literalExpression ''
        {
          coordinator = {
            url = "https://wgmesh.example.com";
            spki_sha256 = "…";
            network = "prod";
          };
          interface.listen_port = 51820;
          peers.exit_peer = "gw";
          route.prefixes = [ "10.77.0.0/16" ];
        }
      '';
    };

    enrollmentTokenFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        File holding the enrollment (join) token. It is loaded as the systemd
        credential `enrollment-token` and reaches the agent as
        WGMESH__ENROLLMENT__TOKEN_FILE=%d/enrollment-token, so the token's path
        is not part of the configuration file.
      '';
    };

    apiKeyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        File holding the agent's Ed25519 private key, loaded as the
        `api-key` credential. Leave unset to let the agent generate the key
        under its state directory.
      '';
    };

    wireguardKeyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        File holding the tunnel's X25519 private key, loaded as the `wg-key`
        credential. Set it when the key is provisioned (sops-nix, agenix) and
        must not be generated locally.
      '';
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Open `settings.interface.listen_port` (UDP) in the firewall. A
        listen_port of 0 picks a random port at runtime, which cannot be
        opened ahead of time -- pin the port to use this.
      '';
    };

    forwarding = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = cfg.settings.forwarding.enabled or false;
        defaultText = lib.literalExpression "false";
        description = ''
          Make this node forward traffic that is not addressed to it, so peers
          can reach networks behind it. Sets net.ipv4.ip_forward and
          net.ipv6.conf.all.forwarding, turns off the firewall's FORWARD
          filtering, and relaxes the reverse path check.
        '';
      };

      firewall = lib.mkOption {
        type = lib.types.enum [
          "off"
          "manage"
        ];
        default = "off";
        description = ''
          "manage" adds an nftables table (`inet wgmesh-forward`) that accepts
          forwarding between the tunnel interface and `trustedInterfaces`.
          "off" leaves the host firewall alone.
        '';
      };

      trustedInterfaces = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [
          "eth0"
          "br-lan"
        ];
        description = ''
          Interfaces forwarding is allowed to and from, used when
          `forwarding.firewall = "manage"`.
        '';
      };
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
      description = "Log level, passed to the agent as WGMESH__LOG__LEVEL.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.configFile != null || (cfg.settings.coordinator.spki_sha256 or "") != "";
        message = "services.wgmesh.agent: settings.coordinator.spki_sha256 is required unless configFile is set";
      }
      {
        assertion = cfg.configFile != null || (cfg.settings.coordinator.url or "") != "";
        message = "services.wgmesh.agent: settings.coordinator.url is required unless configFile is set";
      }
      {
        assertion = !(cfg.openFirewall && listenPort == 0);
        message = "services.wgmesh.agent: openFirewall is set but settings.interface.listen_port is 0 (a random port cannot be opened ahead of time)";
      }
      {
        # nftables is off by default in NixOS, and a table added to a ruleset
        # that is never loaded is a silent no-op. Refuse instead of doing
        # nothing.
        assertion = cfg.forwarding.firewall != "manage" || config.networking.nftables.enable;
        message = ''
          services.wgmesh.agent: forwarding.firewall = "manage" adds an nftables table, but
          networking.nftables.enable is false, so the table would never be loaded. Set
          networking.nftables.enable = true, or leave forwarding.firewall = "off".
        '';
      }
      {
        # The rule the module adds is written as an nftables set, and an empty
        # set -- `iifname { }` -- is a syntax error that rejects the whole
        # ruleset when nftables loads it.
        assertion =
          !(cfg.forwarding.enable && cfg.forwarding.firewall == "manage")
          || cfg.forwarding.trustedInterfaces != [ ];
        message = ''
          services.wgmesh.agent: forwarding.firewall = "manage" needs at least one
          interface in forwarding.trustedInterfaces: the rule nftables gets is a set,
          and an empty set is a syntax error.
        '';
      }
      {
        assertion = lib.hasPrefix "/var/lib/" stateDir;
        message = "services.wgmesh.agent: stateDir must be below /var/lib (it is the name systemd's StateDirectory= provides): ${stateDir}";
      }
    ];

    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.user;
    };
    users.groups.${cfg.user} = { };

    environment.etc."wgmesh/agent.toml".source =
      if cfg.configFile != null then
        cfg.configFile
      else
        toml.generate "agent.toml" renderedSettings;

    systemd.services.wgmesh-agent = {
      description = "wgmesh agent";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      environment = credentialEnvironment // {
        WGMESH__LOG__LEVEL = cfg.logLevel;
      };

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/wgmesh run --config /etc/wgmesh/agent.toml";
        User = cfg.user;
        Group = cfg.user;
        StateDirectory = stateDirName;
        StateDirectoryMode = "0750";
        RuntimeDirectory = stateDirName;
        RuntimeDirectoryMode = "0750";
        Restart = "always";
        RestartSec = 5;

        # The token and the keys exist only as credentials: PID 1 reads them
        # before dropping privileges, and the service sees them under
        # /run/credentials/wgmesh-agent.service/.
        LoadCredential =
          lib.optionals (cfg.enrollmentTokenFile != null) [
            "enrollment-token:${toString cfg.enrollmentTokenFile}"
          ]
          ++ lib.optionals (cfg.apiKeyFile != null) [ "api-key:${toString cfg.apiKeyFile}" ]
          ++ lib.optionals (cfg.wireguardKeyFile != null) [
            "wg-key:${toString cfg.wireguardKeyFile}"
          ];

        # Creating the interface and programming routes needs CAP_NET_ADMIN and
        # nothing else.
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_NETLINK"
        ];

        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectControlGroups = true;
        ProtectKernelModules = true;
        ProtectClock = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        NoNewPrivileges = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" ];
      };
    };

    networking.firewall.allowedUDPPorts = lib.optional (cfg.openFirewall && listenPort != 0) listenPort;

    # Declarative sysctl: written even when it already holds the wanted value,
    # so a different firewall backend or a kernel default cannot change the
    # behaviour silently.
    boot.kernel.sysctl = lib.mkIf cfg.forwarding.enable {
      "net.ipv4.ip_forward" = 1;
      "net.ipv6.conf.all.forwarding" = 1;
    };

    # Forwarding has to survive in the host firewall: nftables' FORWARD chain
    # must not filter, and strict reverse-path filtering would drop the
    # asymmetric traffic a tunnel produces.
    networking.firewall.filterForward = lib.mkIf cfg.forwarding.enable false;
    networking.firewall.checkReversePath = lib.mkIf cfg.forwarding.enable "loose";

    networking.nftables.tables.wgmesh-forward = lib.mkIf (
      cfg.forwarding.enable && cfg.forwarding.firewall == "manage"
    ) {
      family = "inet";
      content = ''
        chain forward {
          type filter hook forward priority filter; policy accept;
          iifname { ${toString cfg.forwarding.trustedInterfaces} } oifname "${
            cfg.settings.interface.name or "wg0"
          }" accept
          iifname "${cfg.settings.interface.name or "wg0"}" oifname { ${toString cfg.forwarding.trustedInterfaces} } accept
        }
      '';
    };
  };
}
