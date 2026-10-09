---
title: wgmesh CLI output contract
---

# `wgmesh` output contract

This document fixes what the binary prints and which exit code it leaves behind, so that scripts —
and the integration tests in `crates/wgmesh-cli/tests/cli.rs` — can rely on it. Anything here that
changes is a breaking change, and the tests change with it.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | the command did what it says |
| 1 | a runtime failure: no state, a lock already held, a device that refused, an unavailable backend |
| 2 | the command line itself is wrong, or the command needs `--yes` and did not get it |
| 3 | the configuration is invalid |

`config check` exits 3 when it printed at least one `error:` line and 0 when it printed only
`warning:` lines or nothing at all. `run` exits 3 before it touches anything, and prints **every**
problem it found rather than the first one.

## Global options

```
wgmesh [--config PATH] [--state-dir PATH] [--backend kernel|simulated] <command>
```

- `--config` defaults to `/etc/wgmesh/agent.toml`. A file that is not there is not an error: the
  defaults are a configuration, and `config check` and `run` are the commands that then say what is
  missing. A file that *is* there wins over the defaults, and the environment
  (`WGMESH__SECTION__KEY`) wins over the file.
- `--state-dir` overrides `[state] dir` from the configuration, and everything downstream — the
  state file, the keys under `secrets/`, the lock under `run/` — follows it.
- `--backend` picks what is behind the ports. `kernel` is the default and is the real device;
  `simulated` is the offline double described below.

## The two backends

`--backend simulated` runs the whole pipeline against the simulated coordination plane and the
simulated device in `crates/wgmesh-cli/src/simulated.rs`. It reads one file,
`<state-dir>/simulated-world.json`, which says what the coordinator would hand out:

```json
{
  "device": 7, "network": "prod", "tunnel_ip": "10.77.0.7/16",
  "network_bands": ["10.77.0.0/16"], "routes": ["10.77.0.0/16"],
  "peers": [ { "id": 8, "name": "B", "public_key": "<base64>",
               "allowed": ["10.77.0.8/32"], "endpoint": "203.0.113.9:41287" } ],
  "version": 1, "token": "tok"
}
```

It exists so that enrol → converge → status can be exercised where the kernel device cannot be —
inside a container without `CAP_NET_ADMIN`, and in CI — and it is a test double, not a second
product: it never opens a socket and never pretends a packet moved.

`--backend kernel` needs the kernel WireGuard adapter, which at this commit does not yet implement
this workspace's `wgmesh_ports::WireGuard` and `Routes`. Until it does, every command that needs a
device says so instead of converging nothing:

```
$ wgmesh --backend kernel run
the kernel backend is not available in this build: the WireGuard adapter does not yet implement
this workspace's ports; run with --backend simulated
```

Commands that read only files — `config`, `key`, `state`, `trust`, `pin`, and `status` — work on
either backend.

## Human-readable output

`status`:

```
device       d_7  (network prod)
interface    wg0  10.77.0.7/16
coordinator  https://wgmesh.example.com  last sync 1760000000
relay        relay-2  slot 51903
peers        2
  B  8  10.77.0.8/32  direct  203.0.113.9:41287  handshake 3s ago  rx - tx -
```

`path` is one of `unknown`, `relayed`, `direct`. `handshake` is `never` until the device reports
one, and it is what decides the path: a handshake inside the last three minutes is `direct`, an
older one is `relayed`, and none at all is `unknown`.

`peers` adds the AllowedIPs that were programmed and the policy that produced them:

```
policy  peer
  B  8  path direct  allowed 10.77.0.8/32
```

`routes` lists only the routes this agent installed:

```
10.77.0.0/16         main     -
```

`routes plan` prints the change set from `wgmesh_core::plan_routes` and applies nothing:

```
add     10.77.0.0/16   table main
remove  192.168.5.0/24 table main
```

`routes reset` removes every route this agent owns and prints how many went.

`config show` prints the effective configuration as TOML with every default filled in;
`config defaults` prints the same for an empty configuration; `config check` prints one line per
problem and then a summary:

```
error: coordinator.spki_sha256: an SPKI pin is 64 hex characters, and 4 were given
warning: route.prefixes is empty; no route will be installed
2 problems (1 error, 1 warning)
```

`key show` prints the key pair in the encoding `wg(8)` writes:

```
private_key: eEnZ...=
public_key:  hFh2...=
```

The private key is a secret and this command prints it on purpose: it is the one command whose job
is to show the key, and it exists so that an operator can hand the WireGuard half to another tool.
`key show --kind api` prints the identity pair instead.

`state reset` prints `state cleared at <path>; the next run re-enrols with the same keys`.
`trust show` prints both pins and whether they agree.

## JSON output

Every `--json` command prints exactly one JSON document on stdout and nothing else; logs go to
stderr. Each carries `"schema": 1`.

`status --json`:

```json
{
  "schema": 1,
  "device_id": "7",
  "network": "prod",
  "interface": "wg0",
  "tunnel_ip": "10.77.0.7/16",
  "coordinator": {
    "url": "https://wgmesh.example.com",
    "spki_sha256": "9f2c..",
    "last_sync_unix": 1760000000,
    "config_version": 1
  },
  "relay": { "assigned": "2", "slot_port": 51903 },
  "peers": [
    {
      "id": "8",
      "name": "B",
      "wg_pubkey": "AAAA..=",
      "endpoint": "203.0.113.9:41287",
      "path": "direct",
      "last_handshake_unix": 1760000042,
      "handshake_age_secs": 3,
      "allowed_ips": ["10.77.0.8/32"],
      "rx_bytes": null,
      "tx_bytes": null
    }
  ]
}
```

`rx_bytes` and `tx_bytes` are `null` on a backend that has no kernel behind it.

`peers --json` carries the policy and the programmed AllowedIPs:

```json
{
  "schema": 1,
  "policy": "peer",
  "exit_peer": null,
  "peers": [ { "id": "8", "name": "B", "path": "direct",
               "endpoint": "203.0.113.9:41287",
               "allowed_ips": ["10.77.0.8/32"],
               "handshake_age_secs": 3 } ]
}
```

`routes --json`:

```json
{ "schema": 1, "table": "main", "proto": "wgmesh",
  "routes": [ { "prefix": "10.77.0.0/16", "table": "main", "metric": null } ] }
```

`config check --json`, `config show --json`, `config defaults --json`, `key show --json`,
`state show --json`, `trust show --json`, `relays --json` and `doctor --json` follow the same
rule: `schema` first, then the facts the human form shows, with `errors` and `warnings` arrays
where there are problems.

## The pipeline this contract exists for

```
wgmesh join --token "$TOKEN"
wgmesh run &
wgmesh status --json | jq -e '.peers[0].path'
```

`tests/cli.rs` runs exactly this, with `--backend simulated`, and asserts that `status --json`
carries the peer's path, endpoint and handshake age.
