# wgmesh — M0 report

M0 is the milestone that has to prove the shape of the thing before any of it is
wired to a kernel: a workspace with enforced boundaries, a pure core, and two
nodes that come up **through a relay** and move to a **direct path** when one can
be built — and fall back when it cannot.

This document is the milestone's review artifact. It says what is in the
repository, what was verified on the Attacca Computer and how, what could not be
verified here and what the evidence for that is, and what was found along the
way.

| | |
|---|---|
| Where | `mincomk/wgmesh`, branch `m0/conformance` → pull request **#10** → `main` |
| Cut from | `main` at `2c8987d`, 2026-10-09 |
| Every command here was run on | the Attacca Computer, 2026-10-09 |
| CI | GitHub Actions `.github/workflows/ci.yml`, run **37935872816** on pull request #10 |

---

## 1. What is in the repository

`main` is moving while M0 lands, and this branch was cut from `2c8987d`: the
table below says what each crate was *then*. Everything M0 is still missing is
in a pull request of its own.

| Crate | State | Where |
|---|---|---|
| `wgmesh-core` | **Real.** mac1 signing and verification, packet classification, candidate ranking, the hole-punch state machine, relay routing, the `AllowedIPs`/`PeerSpec` diff, and route planning that never installs a default route. Pure: no I/O, no clock, no OS. | `main`, 27 unit tests |
| `wgmesh-ports`, `wgmesh-app` | **Real.** The ports, and the agent use cases that call them. | `main` (PR #11), 10 tests |
| `wgmesh-config`, `wgmesh-state`, `wgmesh-secrets` | **Real.** Configuration, state documents, the secret store. | `main` (PR #16, #17), 41 + 23 + 29 unit tests |
| `wgmesh-proto` | **Real.** The wire types, the signing preimage and the join token. | `main` (PR #13) |
| `wgmesh-coordinator` + `wgmeshd` | **Real.** SQLite store with migrations, the service, the HTTP API and the daemon, with its own end-to-end test. | `main` (PR #13) |
| `wgmesh-wireguard` | Stub | PR #5 (open) |
| `wgmesh-relay` + `wgmesh-relayd` | Stub | PR #8 (open) |
| `wgmesh-client` | Stub | PR #9 (open) |
| `wgmesh-cli` | Stub | PR #14 (open) |
| `wgmesh-conformance` | **New on this branch.** The M0 gate: the lab, the four scenarios and the two lab processes it drives. | this pull request |
| `xtask` | `check-deps` (the crate dependency table, enforced) and `check-style` | `main` |
| `nix/`, `flake.nix`, `docs/nixos-modules.md` | On `main`; **not evaluable on this Computer** (§4.3) | `main` |
| `.github/workflows/ci.yml` | fmt, clippy `-D warnings`, `cargo test --workspace --locked`, `cargo xtask check-deps`, `cargo xtask check-style` | `main` |

"Stub" means the crate directory, its `Cargo.toml` and a one-line `lib.rs` /
`main.rs` exist, so the workspace, the members list and the dependency table are
settled; its implementation is the step that owns it. Every crate's permitted
dependencies are a row of `xtask/src/deps.rs`, and `cargo xtask check-deps` fails
the build over an undeclared edge.

### On this branch

| Path | What it is |
|---|---|
| `crates/wgmesh-conformance` | The lab: the harness, the NAT, the two lab processes, and the four scenarios. |
| `crates/wgmesh-core` | The state machine's `Event::Handshake` handling **fixed** (§5), plus three unit tests pinning the fixed semantics. |
| `crates/wgmesh-conformance/src/agent.rs` | The lab agent now measures its own probe window and only reports a *direct* path as degraded (§5). |
| `wgmesh-M0-report.md` | This document. |

`crates/wgmesh-conformance` also carries the lab's own minimal coordinator and
relay binaries — `lab-coordinator` and `lab-relayd`. They exist because the gate
has to be runnable while `wgmesh-coordinator` and `wgmesh-relay` are still stubs.
When those land (PR #13, PR #8) the two lab binaries should be deleted and the
harness pointed at the binaries the product ships; the scenarios should not
change then, only the processes they start. In the meantime the engine is not
duplicated: relay routing is `wgmesh_core::RelayTable` and the path decision is
`wgmesh_core::step`.

---

## 2. The three layers, and what each one proves

### 2.1 Pure unit tests (no sockets, no processes)

`cargo test --workspace --locked`, the targets that are not stubs:

| Target | Tests |
|---|---|
| `wgmesh-core` (lib) | 27 |
| `wgmesh-config` (lib) | 40 |
| `wgmesh-secrets` (lib) | 29 |
| `wgmesh-state` (lib) | 23 passed, 2 ignored |
| `wgmesh-conformance` (lib) | 6 |

In `wgmesh-core` those 27 are mac1 signing and verification, packet
classification, candidate ranking, the state machine's transitions
(assignment → punch after `punch_delay` → direct → backoff after `punch_window`),
relay routing (unknown ingress, unassigned pair, malformed packet, source pinning
and its staleness window), the `AllowedIPs`/`PeerSpec` diff, and routing policy,
including that a default route is never planned.

In `wgmesh-conformance` the 6 are: pair homing only after both ends name each
other, the punch armed only once both ends are observed, the fleet spread,
re-homing on a silent relay, no assignment when no relay is healthy, and a
source check that **no file the coordinator's own process is built from
constructs a UDP socket** -- scanned over the control plane (the module, its
transport, its wire types and the binary) with `nat.rs` as a positive control,
so a scan that reads nothing cannot pass as a clean coordinator.

These run in milliseconds and need nothing from the host.

### 2.2 Fake-adapter integration (processes, sockets, no kernel)

`wgmesh-app`'s `tests/startup.rs` (10 tests) drives the agent use cases against
`wgmesh-ports`' fakes — no kernel, no network, no clock.

The lab is the second layer, and it runs **real processes over real UDP sockets
on `127.0.0.1`**:

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

```text
        cone + cone       -> Direct / Direct   (start Relayed/Relayed, mappings A=1 B=1, attempts 0/0, probe -, backoff -/-, relay forwarded 14)
        cone + restricted -> Direct / Direct   (start Relayed/Relayed, mappings A=1 B=1, attempts 0/0, probe -, backoff -/-, relay forwarded 15)
  restricted + cone       -> Direct / Direct   (start Relayed/Relayed, mappings A=1 B=1, attempts 0/0, probe -, backoff -/-, relay forwarded 16)
  restricted + restricted -> Direct / Direct   (start Relayed/Relayed, mappings A=1 B=1, attempts 0/0, probe -, backoff -/-, relay forwarded 14)
   symmetric + symmetric  -> Relayed / Relayed  (start Relayed/Relayed, mappings A=2 B=2, attempts 1/1, probe 5.0s, backoff 27s/27s, relay forwarded 35)

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 35.12s
```

Each row asserts more than the final path:

1. **Both ends start `Path::Relayed`**, over the relay the coordinator assigned.
2. **A direct path is promoted** for every NAT pair that can be punched, and both
   ends report `Path::Direct`.
3. **`symmetric + symmetric` never promotes.** The punch runs for `punch_window`
   = 5.0s, the state machine reverts to `Path::Relayed` with `attempts = 1`, and
   the pending backoff is the first table entry (30s, read at 27s remaining) —
   and the relay's forwarded counter **grows after the fallback was observed**,
   so the relayed path really resumed rather than merely having carried traffic
   before the punch.
4. The **probe window is measured by the agents, not by the harness**: each end
   records when its first probe began and when a probe gave up, inside the state
   machine's own tick, and the campaign reads those two instants off the agent.
   A descheduled test thread therefore cannot lose the moment -- and cannot
   report a probe window it never saw.
5. The **mapping counts are the structural reason**: an endpoint-independent
   mapping is one external port for every destination (A=1, B=1), while a
   symmetric NAT creates a fresh external port per destination (A=2, B=2), which
   is exactly why the address the relay observed is not reachable from the other
   side.

The backoff's *growth* is pinned one layer down, in `wgmesh-core`:
`failed_punch_falls_back_then_retries_with_backoff` runs a second failed attempt
and asserts the next-attempt time moves out by the second table entry (120s, not
30s), and `a_relayed_handshake_does_not_reset_an_armed_backoff` asserts a relayed
handshake arriving mid-backoff leaves it armed.

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

```text
killing relay-1 (the home of pair 101/102)
after the kill: pair 101/102 on Some("relay-2"), pair 103/104 on Some("relay-2"), relay-1 healthy=Some(false)
longest unreachable run: pair 101/102 21 samples, pair 103/104 0 samples

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 13.03s
```

Two pairs, both symmetric so both stay on their relay and the relay's liveness is
observable from outside: pair (101,102) homed on `relay-1`, pair (103,104) on
`relay-2`. `relay-1` is then killed with SIGKILL.

The test asserts five things:

- the cut pair **acted on two assignments** (relay-1, then relay-2) while the
  untouched pair acted on exactly one — the deterministic evidence that the cut
  and the re-homing both happened, independent of sampling;
- the cut pair **is reachable again** within the window, and its longest run of
  samples with no authenticated packet is longer than the untouched pair's
  (21 samples against 0 in the run above -- the re-homing window the lab's 3s
  relay timeout sets). "Reachable" is a trailing 1.5s window,
  which hides the first part of any outage, so this corroborates the counter
  rather than replacing it;
- the pair on the surviving relay is **never re-homed and never disturbed**;
- the coordinator's state shows `relay-1` unhealthy and both pairs homed on
  `relay-2`;
- the survivor's forwarded counter keeps growing, so the recovered path really is
  going through it.

#### The coordinator opens no data-path socket

```console
$ cargo test -p wgmesh-conformance --test coordinator_udp -- --nocapture
```

```text
UDP sockets: harness=6, relays=2, coordinator=0 (TCP on the coordinator: 1)

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.90s
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

**This is the lab's coordinator.** The structural claim about the *product's*
coordinator (`wgmesh-coordinator`, PR #13) has to be re-run against that binary
when it lands; the check is written so that pointing it at another process is all
that changes.

#### How to run all of it

The lab spawns the real binaries, so they must be built first — `cargo test`
builds them too, but building explicitly fails fast and legibly:

```console
$ cargo build --workspace --locked
$ cargo test --workspace --locked                      # unit + conformance, in parallel
$ cargo test -p wgmesh-conformance -- --test-threads=1 --nocapture   # scenarios one at a time, with the table
```

Scenarios run one at a time in the `--test-threads=1` form: each starts a
coordinator and a two-relay fleet on loopback, and the timings they assert are
wall-clock ones. On this Computer the sequential form takes about a minute; the
parallel form in `cargo test --workspace` takes about half that, and CI takes
longer still.

---

## 3. What could not be verified here, and the evidence

### 3.1 Kernel WireGuard and the netlink path — not verifiable in this VM

The Attacca Computer cannot create a WireGuard interface, and cannot even give
itself a network namespace to try in. Every line below was run on it, 2026-10-09:

```console
$ grep CapEff /proc/self/status
CapEff:	0000000000000000                 # and CapPrm likewise: no capabilities at all

$ unshare -n true
unshare: unshare failed: Operation not permitted

$ ls /lib/modules/
ls: cannot access '/lib/modules/': No such file or directory

$ ls -d /sys/module/wireguard
ls: cannot access '/sys/module/wireguard': No such file or directory

$ command -v wg modprobe
(no output: neither is installed)

$ command -v ip
(no output: iproute2 is not installed either, so `ip link add ... type wireguard`
 cannot be demonstrated on this VM at all)

$ ls -l /dev/net/tun
crw-rw-rw- 1 root root 10, 200 ... /dev/net/tun

$ cat /proc/sys/user/max_user_namespaces
7909
```

So: no capabilities in any namespace we can reach (and `unshare -n` is refused
rather than merely unprivileged), no module tree to load `wireguard.ko` from, no
userspace `wg` tool, and no `ip` to drive netlink with. `/dev/net/tun` exists and
unprivileged user namespaces are *enabled*, but neither helps without a module or
a userspace implementation.

**Consequence:** `wgmesh-wireguard` (the netlink adapter and the route adapter)
cannot be integration-tested here. Its kernel-facing behaviour — peer
programming, endpoint updates, `AllowedIPs` install, and the assertion that no
default route ever reaches the routing table — must be verified on a host with
`NET_ADMIN` and the `wireguard` module. The route *planning* half is covered by
the pure tests in `wgmesh-core`, which need no kernel.

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
(it needs `NET_ADMIN` in a user namespace, which this VM cannot give — §3.1), and
after that real hardware.

### 3.3 NixOS modules — not verifiable here

```console
$ command -v nix nixos-rebuild nix-build
(no output: none installed)
$ ls /dev/kvm
ls: cannot access '/dev/kvm': No such file or directory
```

`nix/modules/*.nix`, `flake.nix` and `nix/tests/*.nix` are on `main`, but this VM
has no Nix and no KVM, so they were neither evaluated nor run here.
`docs/nixos-modules.md` carries their own run instructions, and the `nixosTest`
VMs they describe need a host with Nix and KVM.

### 3.4 WireGuard's cryptography — out of scope, and unverified

The lab authenticates `mac1` for real (it computes the keyed BLAKE2s and the
relay verifies it with the core's own verifier), but there is no Noise handshake,
no key exchange and no transport encryption anywhere in the lab. Nothing in M0
claims otherwise.

---

## 4. What the numbers are not

- The lab runs in **compressed time**: persistent keepalive is 200ms rather than
  WireGuard's 25s and a relay that has been silent for 3s is treated as gone
  (ten missed heartbeats), so a scenario completes in seconds. The state machine's own
  timings (`punch_delay` 2s, `punch_window` 5s, backoff 30s/120s/600s) are the
  design's, unmodified, and a promotion test asserts them. The *start* path a
  row reports is the path each agent first had, recorded by the agent itself, so
  "both ends start relayed" is a fact about the state machine rather than about
  when the harness happened to look.
- `probe_secs` is measured by the agents themselves, between the moment they
  entered the probe and the moment a probe gave up, at the tick interval's
  resolution (25ms) — an observation of the 5s window on the state machine's own
  clock, not an exact timer.
- The relay's forwarded counter in the first line of a campaign reads 0 because
  the coordinator's view of a relay's stats comes from its heartbeat, which is
  300ms apart; the counter at the end of the run is what the assertions use.
- The campaign's mapping counts include every mapping the NAT created for the
  internal port, including ones used only during the punch.
- The scenarios are wall-clock tests over processes, so they are timing-sensitive
  by nature. Their waits are generous (20–30s where the sequence itself takes a
  few seconds), and the two claims that must not be sampling artefacts — the
  cut pair's assignment count and the untouched pair's — are counters, not
  samples.

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

### 5.1 A quiet relay is not a degraded path

The second finding came out of running the scenario rather than reading it, and
it is the reason this branch touches the lab's agent at all.

The lab's agent declares `Event::Degraded` when the peer has been quiet for
`DOWN_AFTER` (2s) while the state machine is idle on a known path. Before the
first punch the state machine *is* idle on a known path — the relay — so a
relayed session whose keepalives jitter past two seconds, which a loaded machine
produces, was reported as degraded. `Degraded` reverts to the relay and **arms
the backoff**, so that reading postponed the *first punch* by the whole first
backoff (30s). The symmetric scenario then never punched at all: `attempts 1/1`,
no probe, one NAT mapping, and a `Relayed / Relayed` row that failed on the
mapping count — which is the row's entire point, since a symmetric NAT is
proved by the *second* mapping it has to create for the punch.

The lab now treats only a **direct** path as degradable, which is what the
event means: `wgmesh-core` calls it `degraded_direct_path_reverts_to_the_relay`.
A quiet relay is the fallback, not a failure.

The flake also moved the measurement: `probe_secs` used to be sampled by the
harness's polling loop, so a starved thread could lose the probe window and
report `None` — a failure that says nothing about the state machine. The window
is now recorded by the agent, in the state machine's own tick, and read from
there.

Whether the *shipping* agent should behave the same way when a relayed path goes
quiet — the lab's `DOWN_AFTER` is a lab constant, and the app's event loop has
its own policy to choose — is an open question for the app step, not something
this branch settles.

---

## 6. Environment

```
Linux 6.18.35 x86_64 GNU/Linux
rustc 1.99.0 (b940084d7 2026-09-28)   cargo 1.99.0 (5f94df478 2026-08-27)
9 cores, 10 GiB RAM
```

The repository's own checks, run on this branch:

```console
$ cargo fmt --all --check                                  # clean
$ cargo clippy --workspace --all-targets --locked -- -D warnings   # clean
$ cargo build --workspace --locked                         # ok
$ cargo test --workspace --locked                          # all targets green
$ cargo xtask check-deps                                   # ok
$ cargo xtask check-style                                  # ok
```

`cargo test --workspace --locked` reports, target by target: 27 (`wgmesh-core`) +
41 (`wgmesh-config`) + 29 (`wgmesh-secrets`) + 23 and 2 ignored (`wgmesh-state`)
+ 17 (`wgmesh-proto`) + 11 (`wgmesh-coordinator`'s own integration test) + 10
(`wgmesh-app` startup) + 6 (`wgmesh-conformance` lib) + 6 + 1 + 1
(`wgmesh-conformance` promotion, fleet, coordinator_udp) passed, 0 failed; the
crates that are still stubs contribute none, and doc-tests are empty.

CI runs the same five commands on a GitHub-hosted runner, on two cores. The run
for this branch passed: run 37935872816, `fmt, clippy, test, checks` in 1m37s --
the conformance scenarios included. (The only change since that run is these two
sentences.)

---

## 7. What M0 still owes

This branch closes the promotion gate and records the milestone; it does not
complete M0. Still to land, in the order the milestone lists them:

1. `wgmesh-client` — the pinned HTTPS client (PR #9). `wgmesh-proto` and the
   coordinator itself have landed (PR #13), so the lab's own control plane is
   now the *only* thing standing between the scenarios and the real processes.
2. `wgmesh-relay` as a real application (PR #8). Then `lab-coordinator` and
   `lab-relayd` are deleted and the harness is pointed at the binaries the
   product ships: `wgmeshd` for the control plane and `wgmesh-relayd` for the
   data plane. The scenarios in `crates/wgmesh-conformance/tests/` are that
   step's acceptance test — they should not change, only the processes they
   start. Two claims have to be re-run there, against the real binaries: the
   coordinator's no-UDP-socket check, and the relay's slot-per-device forwarding.
3. `wgmesh-wireguard` — the netlink adapter (PR #5), which needs a host with
   `NET_ADMIN` and the `wireguard` module to be tested at all.
4. `wgmesh-cli` as the composition root (PR #14).
