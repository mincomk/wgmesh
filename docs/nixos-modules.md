# NixOS modules

wgmesh ships three NixOS modules. They are independent: a node runs the agent,
a relay host runs the relay, a control-plane host runs the coordinator, and any
combination of them can live on one machine.

```nix
{
  inputs.wgmesh.url = "github:mincomk/wgmesh";
  # ...
  imports = [ inputs.wgmesh.nixosModules.default ];
}
```

`nixosModules.default` imports all three; `nixosModules.agent`, `.relay` and
`.coordinator` import one each. Each module is off until `enable = true`.

A design rule runs through all three: **`settings` is a one-to-one mirror of the
component's TOML configuration file.** The module does not re-declare the
configuration schema, it renders `settings` verbatim into
`/etc/wgmesh/<component>.toml`. The option tables below therefore describe the
NixOS-specific surface only — for the keys that go inside `settings`, the
component's own configuration reference is the schema. `settings` is typed by
`lib.types.toml`, which accepts arbitrary nesting of TOML values and rejects
values TOML cannot express.

## Quick start

### A node

```nix
services.wgmesh.agent = {
  enable = true;

  settings = {
    coordinator = {
      url = "https://wgmesh.example.com";
      spki_sha256 = "9f2c…";           # wgmesh pin https://wgmesh.example.com
      network = "prod";
    };
    interface.listen_port = 51820;

    # Send everything through the gateway peer, but keep only the corporate
    # ranges in the kernel's routing table.
    peers.exit_peer = "gw";
    route.prefixes = [ "10.77.0.0/16" "192.168.5.0/24" ];
  };

  enrollmentTokenFile = config.sops.secrets."wgmesh/token".path;
  openFirewall = true;
};
```

### A node that routes for the mesh behind it

```nix
services.wgmesh.agent = {
  enable = true;
  settings.coordinator.url = "https://wgmesh.example.com";
  settings.coordinator.spki_sha256 = "9f2c…";
  settings.forwarding.enabled = true;

  forwarding = {
    enable = true;
    firewall = "manage";
    trustedInterfaces = [ "eth0" ];
  };
};
```

`forwarding.enable` makes the module set `net.ipv4.ip_forward` and
`net.ipv6.conf.all.forwarding`, turn off the firewall's FORWARD filtering, relax
the reverse path check, and (with `firewall = "manage"`) add an nftables table
that accepts forwarding between the tunnel and `trustedInterfaces`.

### A relay

```nix
services.wgmesh.relay = {
  enable = true;
  settings = {
    relay.listen = "0.0.0.0";
    relay.port_range = [ 51820 51999 ];
    coordinator.url = "https://wgmesh.example.com";
    coordinator.spki_sha256 = "9f2c…";
  };
  enrollmentTokenFile = config.sops.secrets."wgmesh/relay-token".path;
  openFirewall = true;                 # opens the UDP port range
};
```

### A coordinator

```nix
services.wgmesh.coordinator = {
  enable = true;
  settings.api.public_url = "https://wgmesh.example.com";
  # Listens on 127.0.0.1:8080 by default and is published by a reverse proxy.
};

services.caddy = {
  enable = true;
  virtualHosts."wgmesh.example.com".extraConfig = "reverse_proxy 127.0.0.1:8080";
};
```

The coordinator speaks plain HTTP and holds no private keys, so it is meant to
sit behind a TLS terminator. Node certificates are pinned by SPKI
(`settings.coordinator.spki_sha256`), and ACME renewals reuse the key, so the
pin survives certificate rotation.

## `services.wgmesh.agent`

| Option | Type | Default | Meaning |
|---|---|---|---|
| `enable` | bool | `false` | Run the agent. |
| `package` | package | `pkgs.wgmesh` | Package to run. |
| `user` | str | `"wgmesh"` | User the service runs as; created if missing. |
| `stateDir` | path | `"/var/lib/wgmesh"` | State directory. Provided as the unit's `StateDirectory=` and written into `settings.state.dir`. |
| `configFile` | path or null | `null` | Use this file as `/etc/wgmesh/agent.toml` instead of rendering `settings`. |
| `settings` | TOML | `{ }` | The agent configuration, rendered verbatim. |
| `enrollmentTokenFile` | path or null | `null` | Enrollment token, loaded as the `enrollment-token` credential. |
| `apiKeyFile` | path or null | `null` | Ed25519 device key, loaded as the `api-key` credential. |
| `wireguardKeyFile` | path or null | `null` | X25519 tunnel key, loaded as the `wg-key` credential. |
| `openFirewall` | bool | `false` | Open `settings.interface.listen_port` (UDP). |
| `forwarding.enable` | bool | `settings.forwarding.enabled` | Route traffic for the mesh. |
| `forwarding.firewall` | `"off"` \| `"manage"` | `"off"` | Whether the module adds its own nftables table. |
| `forwarding.trustedInterfaces` | list of str | `[ ]` | Interfaces forwarding is allowed to and from. |
| `logLevel` | `error`…`trace` | `settings.log.level` | Passed as `WGMESH__LOG__LEVEL`. |

Installed as `systemd.services.wgmesh-agent`, running
`wgmesh run --config /etc/wgmesh/agent.toml`.

### Keys the module writes for you

Two settings are filled in by the module, because letting the user repeat them
only lets them disagree with the unit:

- `state.dir` — always set to `stateDir`, so the agent and systemd's
  `StateDirectory=` agree.
- `forwarding.enabled` (set to `true`) and `forwarding.sysctl` (set to `false`)
  — only when `forwarding.enable` is on. The module owns the forwarding sysctls,
  and the agent is told not to touch them.

A `configFile` is used untouched; the module writes nothing into a file it did
not generate.

## `services.wgmesh.relay`

| Option | Type | Default | Meaning |
|---|---|---|---|
| `enable` | bool | `false` | Run the relay. |
| `package` | package | `pkgs.wgmesh` | Package to run. |
| `user` | str | `"wgmesh"` | User the service runs as. |
| `stateDir` | path | `"/var/lib/wgmesh"` | State directory; the relay's signing key is generated here on first start. |
| `configFile` | path or null | `null` | Use this file as `/etc/wgmesh/relay.toml`. |
| `settings` | TOML | `{ }` | The relay configuration, rendered verbatim. |
| `enrollmentTokenFile` | path or null | `null` | Relay enrollment token, loaded as the `enrollment-token` credential. |
| `openFirewall` | bool | `false` | Open `settings.relay.port_range` (UDP). |

There is no `logLevel` option here, unlike the agent and the coordinator. The
relay's TOML schema has no `[log]` table (`docs/blueprint.md` §5, and
`RelaySettings` in `wgmesh-config`), and the settings types reject unknown keys,
so a `WGMESH__LOG__LEVEL` pointed at `log.level` would make the relay refuse its
own configuration rather than set its verbosity. The option comes back when the
relay's schema has a table to read it from — the module does not invent one.

Installed as `systemd.services.wgmesh-relayd`, running
`wgmesh-relayd run --config /etc/wgmesh/relay.toml`, with
`ExecReload = wgmesh-relayd drain`: `systemctl reload wgmesh-relayd` stops
taking new assignments and moves the ones it holds to another relay, which is
how a relay is taken out of service without dropping traffic.

## `services.wgmesh.coordinator`

| Option | Type | Default | Meaning |
|---|---|---|---|
| `enable` | bool | `false` | Run the coordinator. |
| `package` | package | `pkgs.wgmesh` | Package to run. |
| `user` | str | `"wgmesh"` | User the service runs as. |
| `stateDir` | path | `"/var/lib/wgmesh"` | State directory; the SQLite database lives here. |
| `configFile` | path or null | `null` | Use this file as `/etc/wgmesh/coordinator.toml`. |
| `settings` | TOML | `{ }` | The coordinator configuration, rendered verbatim. |
| `openFirewall` | bool | `false` | Open the listen port of `settings.api.listen` (TCP). Off by default: publish it through a reverse proxy. |
| `logLevel` | `error`…`trace` | `settings.log.level` | Passed as `WGMESH__LOG__LEVEL`. |
| `backup.enable` | bool | `false` | Periodic SQLite backup. |
| `backup.startAt` | str | `"daily"` | systemd calendar expression for the backup timer. |
| `backup.directory` | str | `"/var/backup/wgmesh"` | Where the backup is written. |
| `backup.databasePath` | str | `<stateDir>/coordinator.db` | Database file to back up. |

Defaults the module fills in when `settings` does not say otherwise:
`api.listen = "127.0.0.1:8080"` and
`database.url = "sqlite://<stateDir>/coordinator.db?mode=rwc"`.

Installed as `systemd.services.wgmeshd`, running
`wgmeshd run --config /etc/wgmesh/coordinator.toml`.

The backup unit runs `sqlite3 <db> ".backup '<directory>/coordinator.db'"` as
`backup.startAt`. The database holds public keys, hashes and assignments, so a
leaked backup is not catastrophic — but losing it costs a re-enrollment of every
node, so copy the directory off the machine.

## Secrets

No secret is ever named in a configuration file. Secret files are loaded by
systemd with `LoadCredential=` and reach the component through the environment:

| Option | Credential name | Environment variable |
|---|---|---|
| `enrollmentTokenFile` | `enrollment-token` | `WGMESH__ENROLLMENT__TOKEN_FILE` |
| `apiKeyFile` | `api-key` | `WGMESH__INTERFACE__API_KEY_FILE` |
| `wireguardKeyFile` | `wg-key` | `WGMESH__INTERFACE__PRIVATE_KEY_FILE` |

The variable's value is `%d/<name>`. `%d` is systemd's specifier for the
credentials directory and PID 1 expands it while reading the unit (specifier
resolution does run for `Environment=`), so the service sees
`/run/credentials/<unit>/<name>` — a path it, and only it, can read.

That means anything can supply the file: sops-nix, agenix, a hand-placed file,
or a Kubernetes secret mounted for the unit. Since the path is not part of the
configuration, there is nothing in the file to leak or to keep in sync.

## Hardening

| | agent | relay | coordinator |
|---|---|---|---|
| `AmbientCapabilities` / `CapabilityBoundingSet` | `CAP_NET_ADMIN` | none | none |
| `RestrictAddressFamilies` | `AF_INET AF_INET6 AF_NETLINK` | `AF_INET AF_INET6` | `AF_INET AF_INET6` |
| `ProtectSystem` | `strict` | `strict` | `strict` |
| `NoNewPrivileges` | yes | yes | yes |
| `PrivateTmp`, `PrivateDevices`, `ProtectHome` | yes | yes | yes |
| `ProtectKernelModules`, `ProtectControlGroups`, `ProtectClock` | yes | yes | yes |
| `ProtectKernelTunables` | no | yes | yes |
| `MemoryDenyWriteExecute`, `LockPersonality`, `RestrictSUIDSGID` | yes | yes | yes |
| `SystemCallFilter` | `@system-service` | `@system-service` | `@system-service` |

The agent is the only component that configures the kernel — it creates the
WireGuard interface and programs routes — and `CAP_NET_ADMIN` with `AF_NETLINK`
is the whole of what that needs. `ProtectKernelTunables` is deliberately not set
for the agent: when the module is not managing forwarding, the agent may have to
write the sysctl itself. The relay and the coordinator touch neither the kernel
nor the host's network configuration, so they run with no capabilities at all.

## Forwarding

`services.wgmesh.agent.forwarding.enable = true` writes all four of these, so
none of the behaviour depends on a default that another module can change:

```nix
boot.kernel.sysctl = {
  "net.ipv4.ip_forward" = 1;
  "net.ipv6.conf.all.forwarding" = 1;
};
networking.firewall.filterForward = false;      # nftables' FORWARD chain
networking.firewall.checkReversePath = "loose"; # strict rp_filter drops tunnel traffic
```

`filterForward` and `checkReversePath` already default to the wanted values, and
they are written out anyway: the first is only honoured by the nftables firewall
backend, and the second is easy to tighten globally.

With `forwarding.firewall = "manage"` the module adds the `inet wgmesh-forward`
table, which accepts forwarding between the tunnel interface and
`trustedInterfaces`. Its set elements are comma separated — nftables rejects
`{ eth0 eth1 }` — and the module asserts that `trustedInterfaces` is not empty,
because `{ }` is a syntax error that would take the whole ruleset down with it.

## Tests

The end-to-end tests are NixOS VM tests, so they need a machine that can run
KVM:

```console
$ nix build .#checks.x86_64-linux.e2e
$ nix build .#checks.x86_64-linux.relay-unit
$ nix build .#checks.x86_64-linux.forwarding
$ nix flake check                     # also runs the dependency check
```

`deps` needs nothing but a Nix store; the three VM tests need `/dev/kvm`. The
flake tracks `github:NixOS/nixpkgs/nixos-unstable` and the repository does not
commit a `flake.lock`, so the first run fetches whatever the channel points at
that day -- run `nix flake lock` once and commit the lock file to pin it.

| Check | What it stands up | What it asserts |
|---|---|---|
| `deps` | nothing | `cargo xtask check-deps` over the source tree. |
| `e2e` | one router (coordinator + relay), two agent nodes | both agents come up through the relay and then promote to a direct path; node A can ping node B over the tunnel. |
| `relay-unit` | one relay, one coordinator | the relay's slot sockets answer, and `drain` hands the relay's assignments back. |
| `forwarding` | three nodes, one of them an exit peer | the exit peer carries `0.0.0.0/0` in AllowedIPs and nobody else does; the kernel routing table has no `default` route, only the chosen prefixes; a host behind the exit peer is reachable. |
