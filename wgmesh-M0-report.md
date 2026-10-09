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
| Cut from | `main` at `263a8fb`, 2026-10-09 |
| Every command here was run on | the Attacca Computer, 2026-10-09 |
| CI | GitHub Actions `.github/workflows/ci.yml`, run **37924930042** on pull request #10 |

---

## 1. What is in the repository

`main` carries the workspace, its dependency rules and its CI, the NixOS layer,
and the M0 crates that have landed so far. The rest of M0 is in flight as
parallel pull requests, so this table says which crate is real **today** and
where the others are.

| Crate | State | Where |
|---|---|---|
| `wgmesh-core` | **Real.** mac1 signing and verification, packet classification, candidate ranking, the hole-punch state machine, relay routing, the `AllowedIPs`/`PeerSpec` diff, and route planning that never installs a default route. Pure: no I/O, no clock, no OS. | `main`, 27 unit tests |
| `wgmesh-ports`, `wgmesh-app` | **Real.** The ports, and the agent use cases that call them. | `main` (PR #11), 10 tests |
| `wgmesh-config`, `wgmesh-state`, `wgmesh-secrets` | **Real.** Configuration, state documents, the secret store. | `main` (PR #16), 40 + 23 + 29 unit tests |
| `wgmesh-wireguard` | Stub | PR #5 (open) |
| `wgmesh-relay` + `wgmesh-relayd` | Stub | PR #8 (open) |
| `wgmesh-proto`, `wgmesh-client` | Stub | PR #9 (open) |
| `wgmesh-coordinator` + `wgmeshd` | Stub | PR #13 (open) |
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
source check that the coordinator's own production source constructs no
UDP socket.

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
        cone + restricted -> Direct / Direct   (start Relayed/Relayed, mappings A=1 B=1, attempts 0/0, probe -, backoff -/-, relay forwarded 12)
  restricted + cone       -> Direct / Direct   (start Relayed/Relayed, mappings A=1 B=1, attempts 0/0, probe -, backoff -/-, relay forwarded 14)
  restricted + restricted -> Direct / Direct   (start Relayed/Relayed, mappings A=1 B=1, attempts 0/0, probe -, backoff -/-, relay forwarded 14)
   symmetric + symmetric  -> Relayed / Relayed  (start Relayed/Relayed, mappings A=2 B=2, attempts 1/1, probe 5.0s, backoff 28s/28s, relay forwarded 24)

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 56.73s
```

Each row asserts more than the final path:

1. **Both ends start `Path::Relayed`**, over the relay the coordinator assigned.
2. **A direct path is promoted** for every NAT pair that can be punched, and both
   ends report `Path::Direct`.
3. **`symmetric + symmetric` never promotes.** The punch runs for `punch_window`
   = 5.0s, the state machine reverts to `Path::Relayed` with `attempts = 1`, and
   the pending backoff is the first table entry (30s, read at 28s remaining) —
   and the relay's forwarded counter keeps growing, so the relayed path really
   resumed.
4. The **mapping counts are the structural reason**: an endpoint-independent
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
longest unreachable run: pair 101/102 4 samples, pair 103/104 0 samples

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 11.28s
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
  (4 samples against 0 in the run above). "Reachable" is a trailing 1.5s window,
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

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 31.64s
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
  WireGuard's 25s, so a scenario completes in seconds. The state machine's own
  timings (`punch_delay` 2s, `punch_window` 5s, backoff 30s/120s/600s) are the
  design's, unmodified, and a promotion test asserts them.
- `probe_secs` is measured between the first agent entering the probe and the
  first observing the fallback, sampled every 25ms — it is a wall-clock
  observation of the 5s window, not an exact timer.
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
40 (`wgmesh-config`) + 29 (`wgmesh-secrets`) + 23 and 2 ignored (`wgmesh-state`)
+ 6 (`wgmesh-conformance` lib) + 10 (`wgmesh-app` startup) + 6 + 1 + 1
(`wgmesh-conformance` promotion, fleet, coordinator_udp) passed, 0 failed; the
remaining targets are the stubs, and doc-tests are empty.

CI runs the same five commands on a GitHub-hosted runner. The run for the head of this branch passed: run 37924930042, `fmt, clippy, test, checks` in 1m7s. (The only change since that run is these two sentences.)

---

## 7. What M0 still owes

This branch closes the promotion gate and records the milestone; it does not
complete M0. Still to land, in the order the milestone lists them:

1. `wgmesh-proto` and `wgmesh-client` — the wire types and the pinned HTTPS
   client (PR #9), and with them the coordinator's real API. The lab's own
   control plane stands in until then.
2. `wgmesh-coordinator` and `wgmesh-relay` as real applications (PR #13, PR #8) —
   at that point `lab-coordinator` and `lab-relayd` are deleted and the harness
   is pointed at the binaries the product ships. The scenarios in
   `crates/wgmesh-conformance/tests/` are that step's acceptance test: they
   should not change, only the processes they start. The coordinator's
   no-UDP-socket claim must be re-run against the real `wgmeshd` there.
3. `wgmesh-wireguard` — the netlink adapter (PR #5), which needs a host with
   `NET_ADMIN` and the `wireguard` module to be tested at all.
4. `wgmesh-cli` as the composition root (PR #14).
5. `wgmesh-config`, `wgmesh-state`, `wgmesh-secrets` landed (PR #16) — the
   coordinator's own persistence, and the config/state/secrets split, are
   therefore available to the steps above.
