# The `wgmesh` command line — its output contract

Every assertion in `crates/wgmesh-cli/tests/cli.rs` is a clause of this document. If a field name, a
document shape or an exit code changes here, it changes there in the same commit: the scripts that
read this output cannot see the commit that broke them, so the test is where the promise is kept.

## Where the configuration comes from

Three layers, in increasing precedence, resolved before any command acts:

1. the file named by `--config` (default `/etc/wgmesh/agent.toml`), when it exists;
2. the environment, as `WGMESH__<SECTION>__<KEY>` — the section and the key separated by a double
   underscore (`WGMESH__TRAVERSAL__KEEPALIVE_SECS=40`);
3. the command line.

A configuration file that is not there is not an error: the defaults are a complete configuration,
which is what makes `config defaults`, `key show` and `state reset` work on a host that has never
been configured. `config check` and `run` are the commands that then report what is missing.

Secrets never appear in the file. The enrollment token is named, not written:

| how | where |
|---|---|
| `--token TOKEN` / `--token-file PATH` | the command line, on `join` |
| `WGMESH__ENROLLMENT__TOKEN_FILE=/run/credentials/wgmesh-agent.service/enrollment-token` | what `nix/modules/agent.nix` sets, pointing at the systemd credential |
| `[enrollment] token_file = "…"` | the configuration file, for a hand-written deployment |

The token file is read from the *resolved* configuration, so the environment layer reaches it
exactly as it reaches every other value.

## Exit codes

| code | when |
|---|---|
| `0` | the command did what it was asked |
| `1` | a runtime failure: no state to show, no device behind the configured backend, a coordinator that cannot be reached, `pin` without the HTTPS client |
| `2` | the command line asks for something the binary will not do: `join` with no token anywhere, `key rotate` / `state reset` / `trust rotate` without `--yes`, an unknown flag or subcommand |
| `3` | the configuration does not validate. **Every** problem is reported in one run, not just the first, and `run` refuses to start |

## stdout, stderr and the JSON envelope

`--json` puts exactly one document on stdout and nothing else, so `wgmesh … --json | jq …` never
has to skip a log line. Logs go to stderr. Every document carries `"schema": 1`, and the schema
version is what a reader checks before it trusts a field.

The human form is the same facts for a person to read: aligned columns, `-` for a value that is not
known, `yes`/`no` for a boolean.

## The commands

| command | JSON | human |
|---|---|---|
| `join [--token T \| --token-file P] [--json]` | `device_id`, `addresses[]`, `relay`, `config_version`, `peers` | `enrolled as device 7 on prod` / `addresses 10.77.0.7/16` |
| `run [--check]` | — | `--check` prints `configuration ok; nothing was started` and exits without starting; otherwise the daemon runs until `SIGINT`, holding the lock at `<state>/run/agent.lock` |
| `status [--json]` | `device_id`, `network`, `interface`, `tunnel_ip`, `coordinator{url,spki_sha256,last_sync_unix,config_version}`, `relay{assigned,slot_port}`, `peers[]` | one aligned block per peer |
| `peers [--json]` | `policy` (`peer`\|`any`), `exit_peer`, `peers[]` | `policy peer` and one line per peer |
| `routes [--json]` | `table`, `proto` (`wgmesh`), `routes[]{prefix,table,metric}` | one `prefix  table` line per route, or `no routes installed by wgmesh` |
| `routes plan` | — (prints the plan as text even with `--json`) | `add     <prefix>  table <table>` / `remove  …`, or `nothing to do` |
| `routes reset` | — | `removed N routes` |
| `relays [--json]` | `pool`, `assigned`, `slot_port`, `slots[]{relay,port}` | `pool any  assigned -  slot -` |
| `config show [--json]` | `settings` (the effective settings) | the TOML document, defaults filled in |
| `config defaults [--json]` | `settings` (the built-in defaults) | the TOML document |
| `config check [--json]` | `errors[]{path,message}`, `warnings[]{path,message}` | `error: <path>: <message>` lines and a `N problems (N errors, N warnings)` summary, or `configuration ok` |
| `key show [--json] [--kind wg\|api]` | `private_key`, `public_key` | `private_key: …` / `public_key:  …` |
| `key rotate --yes` | — | the new public key, and a reminder that peers must converge again |
| `state show [--json]` | `state` (the persisted document) | the state file, byte for byte |
| `state reset --yes` | — | `state cleared at …; the next run re-enrols with the same keys` |
| `trust show [--json]` | `configured`, `pinned`, `matches` | `configured`/`pinned`/`match yes\|no` |
| `trust rotate --yes` | — | the pin, now the configuration's |
| `doctor [--json]` | `checks[]{name,status,detail}` | `<status> <name> <detail>` |
| `pin <url> [--json]` | `url`, `pin`, `error` | — |

### `peer` objects, wherever they appear

`status`, `peers` and the state share one peer shape:

```json
{
  "id": "8", "name": "B", "wg_pubkey": "…base64…",
  "endpoint": "203.0.113.9:41287",
  "path": "direct", "last_handshake_unix": 1791557407, "handshake_age_secs": 12,
  "allowed_ips": ["10.77.0.8/32"], "rx_bytes": 4096, "tx_bytes": 8192
}
```

`path` is `unknown`, `relayed` or `direct`, and it is read from the last handshake: a handshake
inside 180 s is a direct path, an older one is relayed, none at all is unknown. `endpoint`,
`last_handshake_unix`, `handshake_age_secs`, `rx_bytes` and `tx_bytes` are `null` when the device
cannot say — which is the normal answer between a restart and the first handshake.

### `doctor`'s checks

M0's `doctor` reuses the configuration validation rather than duplicating it, and reports five
checks in a fixed order: `configuration`, `backend`, `state`, `wireguard key`, `forwarding`. Each
carries `status` `ok`, `warn` or `fail`. A check that `fail`s exits `1` (`doctor found problems`);
`warn` does not. NAT diagnosis and a routing check are M2's.

### What the kernel backend does not do yet

`--backend kernel` is the default, and this build has no adapter behind it: `wgmesh-wireguard`
carries the routing table, the forwarding sysctls and the firewall, but nothing yet implements the
`WireGuard` port that programs peers and the `Routes` port, and `wgmesh-client` — the HTTPS
coordinator — is still a stub. So a command that needs the device (`run`) fails with a message that
names `--backend simulated`, and commands that only read the configuration or the state
(`status`, `config`, `key`, `state`, `trust`, `doctor`) answer on either backend. `pin` needs the
HTTPS client and says so instead of printing a pin nobody verified. Each of those is a refusal
rather than a pretence, and the message names the thing that is missing.

## The relay's own binary

`wgmesh-relayd` is a separate program with its own `--help` contract, and it is not a `wgmesh`
subcommand:

```
wgmesh-relayd [--config PATH] [--state-dir PATH] enroll | run | status | drain | keyset
```

`enroll` needs `--coordinator` and `--token`, and refuses rather than registering while the signed
HTTPS enrollment exchange has no client. `run` serves the assignment in `--assignment-file` (the
stopgap until `wgmesh-client` fetches `GET /v1/relay/assignment`) and stops on `SIGTERM` or
`SIGINT`. `status` and `keyset` print what the running relay last wrote to `<state-dir>/status`;
`drain` writes `<state-dir>/drain` (`--off` clears it) for `ExecReload=`. Its own contract is held
still by `crates/wgmesh-relay/tests/relayd_cli.rs`.
