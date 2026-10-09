# wgmesh

wgmesh builds a WireGuard mesh out of nodes that mostly cannot reach each other
directly. Each node runs a WireGuard interface whose peers are programmed from a
desired state; a coordinator hands out relay assignments and observed public
endpoints; and a relay — a separate binary, on a separate host — forwards encrypted
packets between nodes that cannot punch a direct path. Direct paths are probed,
preferred while they work, and returned to when they come back.

Two properties shape the architecture.

- **The core is pure.** `wgmesh-core` decides things — how to rank candidates, what
  to do on the next event, how a relay routes a packet, which routes to install —
  and it decides them as values: no I/O, no async, no clock, no OS. It is therefore
  testable without a kernel and without a network, and `cargo xtask check-deps`
  fails the build if a crate like `tokio`, `reqwest` or `libc` ever appears
  anywhere in its dependency tree.
- **A default route never reaches the routing table.** The relay moves packets
  between peers; it does not become a node's default gateway, and a catch-all
  belongs to a peer's `AllowedIPs` rather than to the kernel's default route.

Configuration, state and secrets are three separate files with three different
owners: configuration is a person's, state is the machine's, and secrets are
nobody's to edit. Setup, state and key files are documented in the blueprint.

## Building and testing

Rust 1.85 or newer (the workspace is edition 2024); the pinned channel in
`rust-toolchain.toml` is `stable`.

```console
$ cargo build --workspace
$ cargo test --workspace
$ cargo fmt --all --check
$ cargo clippy --workspace --all-targets -- -D warnings
```

## Repository checks

Two checks encode rules that would otherwise live in a reviewer's memory. CI runs
exactly these commands, so a local run and a CI run are the same run.

```console
$ cargo xtask check-deps     # the dependency table below
$ cargo xtask check-style    # no file-level comments, no Hangul in Rust sources
```

`check-deps` holds the dependency table literally and compares it against
`cargo metadata`: every crate below may use only the internal crates and the
external crates its own row names, and `wgmesh-core` must not reach `tokio`,
`reqwest`, `axum`, `sqlx`, `hyper`, `rustls`, `netlink`, `libc` or `nix` at any
depth. Development dependencies are exempt — they do not ship.

`check-style` forbids file-level comments (`//!`) and any Hangul in `.rs` files
under `crates/` and `xtask/`, comments included. Source comments are English.

## Layout

| Path | What it is |
|---|---|
| `crates/wgmesh-core` | The pure domain: mac1, packet classification, the hole-punch state machine, relay routing, `AllowedIPs` and route planning. Its only dependency is `blake2`. |
| `crates/wgmesh-ports` | The traits the use cases depend on, and the error taxonomy they speak. |
| `crates/wgmesh-app` | The use cases. Knows `wgmesh-core` and `wgmesh-ports`, and nothing else. |
| `crates/wgmesh-config` | Configuration loading, defaults and validation. |
| `crates/wgmesh-state` | The state file: the one the machine owns, written atomically. |
| `crates/wgmesh-secrets` | Key files, mode `0600`, raw bytes or base64. |
| `crates/wgmesh-proto` | The wire types of the coordinator API, and signing canonicalization. |
| `crates/wgmesh-wireguard` | The kernel WireGuard adapter (netlink) and the route adapter. |
| `crates/wgmesh-client` | The HTTPS client for the coordinator API, with SPKI pinning. |
| `crates/wgmesh-coordinator` | Coordinator application and the `wgmeshd` binary. |
| `crates/wgmesh-relay` | Relay forwarding engine, UDP driver and the `wgmesh-relayd` binary. |
| `crates/wgmesh-cli` | The `wgmesh` binary: the composition root that wires adapters to use cases. |
| `xtask` | The repository checks above, as a crate. |
| `docs` | The design documents. |

## Design documents

The design comes first, and the code follows it.

- [`docs/blueprint.md`](docs/blueprint.md) — the implementation blueprint: workspace
  and dependency rules, the file split between configuration, state and secrets, the
  configuration schemas with every default, the `AllowedIPs` and routing policy, the
  coordinator and relay, the CLI, the NixOS modules, the test strategy and the
  milestone order.
- [`docs/coordinator-design.md`](docs/coordinator-design.md) — the coordination
  plane: why the coordinator and the relay are separate services, identity and
  enrollment, relay slot assignment, observation and hole punching, failover and
  reassignment.
