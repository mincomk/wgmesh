# wgmesh — M0 report

M0 is the milestone that has to prove the shape of the thing before any of it is
wired to a kernel: a workspace with enforced boundaries, a pure core, and two
nodes that come up **through a relay** and move to a **direct path** when one can
be built — and fall back when it cannot.

This document is the milestone's review artifact. It says what is in the
repository, what was verified on the Attacca Computer and how, what could not be
verified here and what the evidence for that is, and what was found along the
way.

- Branch: `m0/promotion-conformance` (based on `m0/scaffold`)
- Every command in this document was run on the Attacca Computer on 2026-10-09.

---

## 1. What is in the repository

`main` currently carries the repository itself and the NixOS modules
(`nix/modules/{agent,coordinator,relay}.nix`, `flake.nix`, `nix/tests/*.nix`,
`docs/nixos-modules.md`). The Rust workspace lives on `m0/scaffold`, which this
branch builds on.

### On `m0/scaffold`

| Crate | State |
|---|---|
| `wgmesh-core` | **Real.** mac1, packet classification, the hole-punch state machine, relay routing, `AllowedIPs` and route planning. Pure: no I/O, no clock, no OS. |
| `wgmesh-ports`, `wgmesh-app`, `wgmesh-config`, `wgmesh-state`, `wgmesh-secrets`, `wgmesh-proto`, `wgmesh-wireguard`, `wgmesh-client`, `wgmesh-coordinator`, `wgmesh-relay`, `wgmesh-cli` | **Stubs** (one line each) — these are the other M0 steps, still landing. |
| `xtask` | Real: `check-deps` and `check-style`. |
| CI | `.github/workflows/ci.yml`: fmt, clippy `-D warnings`, `cargo test --workspace --locked`, `cargo xtask check-deps`, `cargo xtask check-style`. |

### On this branch

| Path | What it is |
|---|---|
| `crates/wgmesh-core` | The state machine's `Event::Handshake` handling **fixed** (§5), plus three unit tests pinning the fixed semantics. |
| `crates/wgmesh-conformance` | **New.** The M0 conformance lab: the harness, the four scenarios, and the two lab processes it drives (`lab-coordinator`, `lab-relayd`). |
| `wgmesh-M0-report.md` | This document. |

`crates/wgmesh-conformance` also carries the lab's own minimal coordinator and
relay binaries. They exist because the gate has to be runnable while
`wgmesh-coordinator` and `wgmesh-relay` are stubs; when those land, the two lab
binaries should be deleted and the harness pointed at them. The engine is not
duplicated: relay routing is `wgmesh_core::RelayTable` and the path decision is
`wgmesh_core::step` — the lab only supplies sockets, processes and a NAT.

---

## 2. The three layers, and what each one proves

### 2.1 Pure unit tests (no sockets, no processes)

`cargo test --workspace --locked` — 33 unit tests, all passing:

- **27 in `wgmesh-core`**: mac1 signing/verification, packet classification,
  candidate ranking, the state machine's transitions (assignment → punch after
  `punch_delay` → direct → backoff after `punch_window`), relay routing
  (unknown ingress, unassigned pair, malformed packet, source pinning and its
  staleness window), the `AllowedIPs`/`PeerSpec` diff, and ten routing-policy
  tests asserting that a default route is **never** installed.
- **6 in `wgmesh-conformance::coordinator`**: pair homing only after both ends
  name each other, the punch armed only once both ends are observed, the fleet
  spread, re-homing on a silent relay, no assignment when no relay is healthy,
  and a compile-time source check that the coordinator's own production source
  constructs no UDP socket.

These run in milliseconds and need nothing from the host.

### 2.2 Fake-adapter integration (processes, sockets, no kernel)

The lab runs real processes over real UDP sockets on `127.0.0.1`:

- **`lab-coordinator`** — control plane only, in-memory state, HTTP/1.1 over TCP.
- **`lab-relayd`** ×2 — one per relay; one UDP slot per served device.
- **Agents** — in-process, behind a simulated NAT.

Two stand-ins, both deliberate and both narrow:

- **Kernel WireGuard** becomes a stand-in that keeps exactly one property, quoted
  from `wg(8)`: *"This endpoint will be updated automatically to the most recent
  source IP address and port of correctly authenticated packets from the peer."*
  It verifies the `mac1` on every handshake it accepts, so only authenticated
  traffic moves the endpoint. It does no other crypto and is not a WireGuard
  device.
- **`mac1`-derived routing** becomes a 2-byte destination tag in front of each
  relayed packet, which the relay strips. The relay *does* verify the packet's
  `mac1` against the destination's key (the keyset check), so the `mac1`
  computation is exercised on the wire; what is stood in for is the lookup from
  `mac1` to device, which in M0 is the ingress slot port anyway.

**NAT is simulated explicitly, not approximated** (`crate::nat`): the RFC 4787
axes are each a switch — endpoint-independent vs endpoint-dependent **mapping**,
and endpoint-independent vs address/port-dependent **filtering** — plus a mapping
idle timeout, so keep-alives matter.

### 2.3 Loopback UDP, measured

#### The campaign table

Each row is a full run: a coordinator process, a two-relay fleet, two agents each
behind its own NAT, and the whole sequence — relayed first, then the punch.

```console
$ cargo test -p wgmesh-conformance --test promotion -- --test-threads=1 --nocapture
```

```
        cone + cone       -> Direct / Direct    (start Relayed/Relayed, mappings A=1 B=1, attempts 0/0, relay forwarded 14)
        cone + restricted -> Direct / Direct    (start Relayed/Relayed, mappings A=1 B=1, attempts 0/0, relay forwarded 15)
  restricted + cone       -> Direct / Direct    (start Relayed/Relayed, mappings A=1 B=1, attempts 0/0, relay forwarded 14)
  restricted + restricted -> Direct / Direct    (start Relayed/Relayed, mappings A=1 B=1, attempts 0/0, relay forwarded 14)
   symmetric + symmetric  -> Relayed / Relayed  (start Relayed/Relayed, mappings A=2 B=2, attempts 1/1, probe 5.0s, backoff 28s/28s, relay forwarded 29)
```

Each row asserts more than the final path:

1. **Both ends start `Path::Relayed`**, over the relay the coordinator assigned —
   and the relay is forwarding (its counter grows).
2. **A direct path is promoted** for every NAT pair that can be punched, and both
   ends report `Path::Direct`.
3. **`symmetric + symmetric` never promotes.** The punch runs for `punch_window`
   = 5.0s, the state machine reverts to `Path::Relayed` with `attempts = 1`, and
   the pending backoff is the first table entry (30s, read at 28s remaining) —
   and the relay's counter continues to grow, so the relayed path really resumed.
4. The **mapping counts are the structural reason**: an endpoint-independent
   mapping is one external port for every destination (A=1, B=1), while a
   symmetric NAT creates a fresh external port per destination (A=2, B=2), which
   is exactly why the address the relay observed is not reachable from the other
   side.

This reproduces the table the Python lab printed, row for row:

| NAT pair | `wgmesh-nat-lab.py` | `wgmesh-conformance` |
|---|---|---|
| cone + cone | `direct / direct` | `Direct / Direct` |
| restricted + restricted | `direct / direct` | `Direct / Direct` |
| cone + restricted | `direct / direct` | `Direct / Direct` |
| restricted + cone | `direct / direct` | `Direct / Direct` |
| symmetric + symmetric | `relay / relay` | `Relayed / Relayed` |

#### A relay dies

```console
$ cargo test -p wgmesh-conformance --test fleet -- --nocapture
```

Two pairs, both symmetric so both stay on their relay and the relay's liveness is
observable from outside: pair (101,102) homed on `relay-1`, pair (103,104) on
`relay-2`. `relay-1` is then killed with SIGKILL.

```
killing relay-1 (the home of pair 101/102)
after the kill: pair 101/102 on Some("relay-2"), pair 103/104 on Some("relay-2"), relay-1 healthy=Some(false)
```

The test asserts five things:

- the cut pair **acted on two assignments** (relay-1, then relay-2) while the
  untouched pair acted on exactly one — the deterministic evidence that the cut
  and the re-homing both happened, independent of sampling;
- the cut pair **is reachable again** within the window, and its longest run of
  samples with no authenticated packet is longer than the untouched pair's (2–5
  samples against 0). "Reachable" is a trailing 1.5s window, which hides the
  first part of any outage, so this corroborates the counter rather than
  replacing it;
- the pair on the surviving relay is **never re-homed and never disturbed**;
- the coordinator's state shows `relay-1` unhealthy and both pairs homed on
  `relay-2`;
- the survivor's forwarded counter keeps growing, so the recovered path really is
  going through it.

#### The coordinator opens no data-path socket

```console
$ cargo test -p wgmesh-conformance --test coordinator_udp -- --nocapture
```

```
UDP sockets: harness=6, relays=2, coordinator=0 (TCP on the coordinator: 1)
```

The check is structural, not behavioural: `/proc/<pid>/fd` gives the socket inodes
a process owns, `/proc/net/udp` and `/proc/net/udp6` give the inodes that are UDP
sockets in this namespace, and the intersection is what that process holds. It is
run against the **coordinator process**, the **two relay processes** (positive
control: UDP slots exist), and the **test process itself** (positive control: the
agents' sockets), while the coordinator is carrying a live relayed session. The
coordinator's UDP set is empty and its TCP set is not. In the same test file the
coordinator crate also asserts, over its own embedded source, that no production
file constructs a `UdpSocket`.

#### How to run all of it

The lab spawns the real binaries, so they must be built first — `cargo test`
builds them too, but building explicitly fails fast and legibly:

```console
$ cargo build --workspace
$ cargo test --workspace --locked                      # unit + conformance, parallel
$ cargo test -p wgmesh-conformance -- --test-threads=1 --nocapture   # scenarios one at a time, with the table
```

Scenarios run one at a time in the `--test-threads=1` form: each starts a
coordinator and a two-relay fleet on loopback, and the timings they assert are
wall-clock ones (the suite takes about a minute that way, and about half that in parallel).

---

## 3. What could not be verified here, and the evidence

### 3.1 Kernel WireGuard and the netlink path — not verifiable in this VM

The Attacca Computer cannot create a WireGuard interface. Every claim below was
run on it:

```console
$ grep CapEff /proc/self/status
CapEff:	0000000000000000                 # and CapPrm likewise: no capabilities at all

$ ip link add dev wgprobe type wireguard
RTNETLINK answers: Operation not permitted

$ ls /lib/modules/                          # also: /sys/module has no wireguard
ls: cannot access '/lib/modules/': No such file or directory

$ command -v wg
(no output: wg is not installed)
```

So: no `NET_ADMIN` in any namespace we can reach, no module tree to load
`wireguard.ko` from, and no userspace `wg` tool either. `/dev/net/tun` exists and
unprivileged user namespaces are enabled (`/proc/sys/user/max_user_namespaces` =
7909), but neither helps without a module or a userspace implementation.

**Consequence:** `wgmesh-wireguard` (the netlink adapter and the route adapter)
cannot be integration-tested here. Its kernel-facing behaviour — peer
programming, endpoint updates, `AllowedIPs` install, and the assertion that no
default route ever reaches the routing table — must be verified on a host with
`NET_ADMIN` and the `wireguard` module. The route *planning* half is covered by
the pure tests in `wgmesh-core::route`, which need no kernel.

### 3.2 Real NAT hardware — not verifiable here by construction

The lab's NAT is a simulator. It is specified rather than approximated, which
makes the *conclusions* meaningful, but it is not a NAT: no vendor's
hairpinning, filtering and mapping-timer quirks are modelled, and only IPv4 on
loopback is exercised.

**What this means for the claim:** the promotion sequence's *logic* is verified —
the state machine, the observation exchange, the punch, the fallback and the
back-off all run for real against real sockets. What is not verified is that a
particular residential router behaves like the model. The next step up is a
host with two network namespaces, each behind a real `nftables`/`iptables` NAT
(it needs `NET_ADMIN` in a user namespace, which this VM cannot give), and after
that real hardware.

### 3.3 NixOS modules — not verifiable here

```console
$ command -v nix nixos-rebuild nix-build
(no output: none installed)
```

`nix/modules/*.nix` and `nix/tests/*.nix` are merged on `main`, but this VM has no
Nix, so they were neither evaluated nor run. `docs/nixos-modules.md` carries their
own run instructions.

### 3.4 WireGuard's cryptography — out of scope, and unverified

The lab authenticates `mac1` for real (it computes the keyed BLAKE2s and the relay
verifies it with the core's own verifier), but there is no Noise handshake, no
key exchange and no transport encryption anywhere in the lab. Nothing in M0
claims otherwise.

---

## 4. What the numbers are not

- The lab runs in **compressed time**: persistent keepalive is 200ms rather than
  WireGuard's 25s, so a scenario completes in seconds. The state machine's own
  timings (`punch_delay` 2s, `punch_window` 5s, backoff 30s/120s/600s) are the
  design's, unmodified, and a promotion test asserts them.
- `probe_secs` is measured between the first agent entering the probe and the
  first observing the fallback, sampled every 25ms — it is a wall-clock
  observation of the 5s window, not an exact timer.
- The campaign's mapping counts include every mapping the NAT created for the
  internal port, including ones used only during the punch.

---

## 5. What the gate found: a backoff that could not arm

The conformance suite earned its place immediately. With the state machine as it
stood, `symmetric + symmetric` **never fell back**: the run ended with both ends
stuck in a probe loop, `attempts = 0`, `Path::Unknown`, and the relay forwarding
nothing more.

The cause was in `wgmesh-core`'s `Event::Handshake` handling, which reset the
attempt counter and the next-attempt time on *any* authenticated packet:

```rust
state.path = match state.relay { Some(relay) if via == relay => Relayed, _ => Direct };
state.attempts = 0;
state.phase = Phase::Idle { next_attempt: at };
```

A packet arriving **over the relay** therefore cleared the backoff the moment the
fallback armed it. The sequence was: probe for 5s → fall back and arm 30s → the
relayed session resumes within ~200ms → that handshake resets `attempts` to 0 and
`next_attempt` to *now* → the next tick probes again. `punch_window` after
`punch_window`, forever, with a backoff that never grew — and, because
`next_attempt` was reset to the handshake time, the initial `punch_delay` was
skipped too.

The fix distinguishes the two cases: only a **direct** handshake is evidence that
the direct path works. A relayed handshake leaves the pending schedule alone, and
if it arrives while a probe is in flight it counts as what it is — a failed probe:

```rust
let direct = match state.relay { Some(relay) => via != relay, None => true };
state.active = Some(via);
if direct {
    state.path = Path::Direct;
    state.attempts = 0;
    state.phase = Phase::Idle { next_attempt: at };
} else {
    state.path = Path::Relayed;
    if matches!(state.phase, Phase::Probing { .. }) {
        state.attempts = state.attempts.saturating_add(1);
        let next_attempt = at.plus(state.backoff_for(cfg));
        state.phase = Phase::Idle { next_attempt };
    }
}
```

Three unit tests pin the semantics: a relayed handshake must not pull the punch
forward, must not reset an armed backoff, and must end a probe in flight. With the
fix, the symmetric row reads `attempts 1/1, probe 5.0s, backoff 28s` and the
relayed path goes back to carrying traffic.

**This is the kind of finding M0 exists to produce.** It is not visible in the
pure tests (each transition is individually correct) and not visible in a single
NAT-pair run (it needs a punch that fails *while* a relayed session is up).

---

## 6. Environment

```
Linux attacca-vm-2f739facf14c43fb8c50d806d2c1b482-0 6.18.35 x86_64
rustc 1.99.0 (b940084d7 2026-09-28)   cargo 1.99.0    9 cores, 10 GiB RAM
```

The repository's own checks, run on this branch:

```console
$ cargo fmt --all --check                     # clean
$ cargo clippy --workspace --all-targets -- -D warnings   # clean
$ cargo test --workspace --locked             # 33 unit tests + 8 conformance tests, green
$ cargo xtask check-deps                      # ok
$ cargo xtask check-style                     # ok
```

CI ran the same five commands on a GitHub-hosted runner for pull request #10
(`m0/conformance` -> `main`) and passed: run 37919613490, 46s, success.

---

## 7. What M0 still owes

This branch closes the promotion gate and records the milestone; it does not
complete M0. Still to land, in the order the milestone lists them:

1. `wgmesh-proto`, `wgmesh-client` (wire types and the HTTPS client), and the
   coordinator's real API — the lab's own control plane stands in until then.
2. `wgmesh-config`, `wgmesh-state`, `wgmesh-secrets` — and with them the
   coordinator's persistence (the lab keeps its state in memory).
3. `wgmesh-wireguard` — the netlink adapter, which needs a host with `NET_ADMIN`
   and the `wireguard` module to be tested at all.
4. `wgmesh-coordinator` and `wgmesh-relay` as real applications; at that point
   `lab-coordinator` and `lab-relayd` are deleted and the harness is pointed at
   the binaries the product ships.
5. The `wgmesh` CLI as the composition root.

The scenarios in `crates/wgmesh-conformance/tests/` are the acceptance test for
point 4: they should not change, only the processes they start.
