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

## How a relay finds the destination

A relay routes in one of two layouts, and which one it uses is a configuration
switch (`relay.one_port`).

- **A port per pair** (the default). Each device holds a slot socket and is paired with
  one counterpart, so the port a datagram arrives on names both ends — the sender and
  where it is going. The relay never reads a byte of the payload.
- **One port per node** (`relay.one_port = true`). A node keeps a single socket and may
  be paired with many peers, so the ingress port can only say who *sent* a packet. Where
  it is *going* comes out of the packet: a handshake (type 1 or 2) names its recipient
  through `mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[..offsetof(mac1)])`,
  and everything else (types 2, 3, 4) through `receiver_index`. The relay learns which
  device owns which index by watching the handshakes it carries — a table of an index and
  a device id, never a key and never a plaintext — and that table refreshes itself,
  because WireGuard rekeys roughly every two minutes and a rekey picks a fresh index. A
  packet whose destination tag names nothing in the keyset or in that table is dropped and
  counted `rejected`.

Neither layout is a substitute for WireGuard's own cryptography. An attacker who guesses a
slot port can send packets, but cannot read one, cannot forge one that passes `mac1`, and
cannot open a session — none of that is the relay's to give. The exposure left by a guess
is bandwidth and CPU.

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
$ cargo xtask check-deps     # the dependency table of the blueprint, section 1.1
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
| `crates/wgmesh-relay` | Relay forwarding engine, UDP driver and the `wgmesh-relayd` binary. Two routing layouts: a port per pair, or one port per node with `mac1`/`receiver_index` routing (`relay.one_port`). |
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
