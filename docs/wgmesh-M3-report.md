# wgmesh — M3 report: the candidate classes and the symmetric NAT

The thread step **"IPv6·LAN·UPnP 후보와 대칭 NAT 대응, M3 보고서"**, on top of the M3 relay work.

| | |
|---|---|
| Where | `mincomk/wgmesh`, PR **#22** → `main`, branch `m3/candidate-classes-and-symmetric-nat` |
| Base | `main` at the time of writing (the config/state/secrets and NixOS-module merges are in it) |
| Local | `cargo test --workspace` → **160 tests, 160 passed**; clippy, `check-deps`, `check-style`, `fmt --check` all clean |
| Crate surface | `wgmesh-core` (the pure half), `wgmesh-ports` (two new ports), `wgmesh-app` (discovery and the traversal round), `wgmesh-config` (the settings translation) |

Everything below was run on this Computer. Nothing is asserted from reading the design; where something is
an assumption rather than a measurement, it says so.

---

## 1. What the step asked for

1. The five candidate classes, ordered `Lan → Ipv6 → Observed → Mapping → Relay`, freshest first inside a class.
2. `ipv6 = false` produces no IPv6 candidate; `lan_candidates = false` drops the LAN one.
3. `upnp = false` — the default — means NAT-PMP and UPnP-IGD are never attempted at all.
4. A symmetric NAT is answered with **fallback plus backoff**: the direct attempt is bounded by
   `punch_window` (default 5 s, shorter than the relay mapping's life), the path goes straight back to the
   relay, and repeated failures retreat 30 s → 2 m → 10 m.
5. A direct path that later dies is detected from the absence of handshakes (`Event::Degraded`), returns to
   the relay slot, and heals within one round trip of the relay re-observing the peer.
6. Port prediction (the birthday attack) is **out of scope** and stays on the list of next steps.

## 2. The design, in one paragraph

`wgmesh-core` decides; `wgmesh-ports` names the interactions; `wgmesh-app` is the sequence. So the split is:
**which candidates exist** is a pure function (`DiscoveryPolicy`, `DiscoverySources`, `discover`,
`best_candidate`), **which one to try** is `rank` — which already existed and is unchanged — and **what the
node can know about itself** is two new ports, `InterfaceInventory` (addresses and listen port, a syscall)
and `PortMapper` (the router, a conversation, and one that is never started unless asked for).

The state machine already had the shape of a retreat: `punch_delay`, `punch_window`, and a bounded
`backoff` list. What it did not have was a working retreat, because of the defect in §4.

## 3. What is proven, criterion by criterion

| criterion | how it is proved |
|---|---|
| `Lan → Ipv6 → Observed → Mapping → Relay`, freshest first inside a class | `wgmesh-core::candidates::tests::candidates_are_ordered_lan_ipv6_observed_mapping_relay` and `within_one_class_the_newest_candidate_comes_first` — pure, no ports |
| `ipv6 = false` makes no IPv6 candidate | `ipv6_off_produces_no_ipv6_candidate` — and the next class takes over rather than the list being skipped |
| `lan_candidates = false` drops the LAN candidate | `lan_off_drops_the_lan_candidate`, `both_local_classes_off_leaves_the_relay_as_the_best_candidate`, `an_observed_address_survives_both_switches_being_off` |
| `upnp = false` never touches the router | `wgmesh-app::agent::discovery::tests::upnp_off_never_speaks_to_the_gateway` asserts the mapper's **call count is zero**, not that the candidate was filtered out. `wgmesh-config`'s `the_candidate_switches_default_to_upnp_off_and_both_local_classes_on` pins that off is also the default |
| a refusing gateway costs one class, not the round | `a_gateway_that_refuses_costs_the_mapping_class_and_nothing_else`; `an_unreadable_interface_fails_the_round_instead_of_looking_empty` pins the other side of that judgement |
| a symmetric NAT falls back after `punch_window` and retreats 30 s / 2 m / 10 m | `wgmesh-app/tests/symmetric_nat.rs::a_symmetric_nat_returns_to_the_relay_after_the_window_and_retreats_thirty_two_ten` — punches at 2 s, 37 s, 162 s, 767 s; waits of 30 s, 120 s, 600 s; the peer endpoint is the relay after each failure |
| a cone NAT is promoted to and then left alone | `a_cone_nat_promotes_the_direct_path_and_then_stops_probing` — one punch, `attempts == 0`, no punch reports |
| a dead direct path degrades and heals in one round trip | `a_direct_path_that_goes_quiet_degrades_and_heals_over_the_relay_in_one_round_trip` — still `Direct` at 183 s (idle paths look dead for the first two minutes, so they must not be bounced), `Relayed` at 184 s, relay handshakes again immediately, and a candidate observed at or after the degrade inside the 30 s sync interval |
| the local classes reach the endpoint chooser | `a_lan_candidate_outranks_the_relay_observed_address` and `switching_lan_candidates_off_puts_the_peer_back_on_the_relay` — the same world, one policy switch, two outcomes |
| a re-pin moves the endpoint and nothing else | `a_re_pin_carries_the_key_the_allowed_ips_and_the_keepalive_through` — key, AllowedIPs and the 25 s keepalive survive every move |
| the endpoint is a switch, not a second path | the same test, plus `Effect::SetPeerEndpoint`'s documentation: a WireGuard peer has one endpoint, so "verify, then switch" is impossible by construction |

### The assertions have teeth

A test that cannot fail is not evidence, so four load-bearing claims were mutation-checked against the real
tree and then reverted:

| mutation | what failed |
|---|---|
| a relayed handshake clears the retreat again (the pre-fix behaviour) | `a_relayed_handshake_does_not_reset_an_armed_retreat` and the integration retreat test |
| `upnp = false` still calls the mapper | `upnp_off_never_speaks_to_the_gateway` |
| `discover` ignores `lan_candidates` | `lan_off_drops_the_lan_candidate` |
| `degraded` always returns false | `a_direct_path_that_goes_quiet_degrades_and_heals_over_the_relay_in_one_round_trip` |

## 4. The defect the retreat depended on

`Event::Handshake` cleared the attempt counter for *any* handshake, including one that arrived over the
relay. The persistent keepalive produces a relayed handshake every 25 s, so on a pair that cannot be punched
the counter was reset as fast as it was armed: the retreat stalled at 30 seconds forever and the 2 and 10
minute steps were unreachable. The criterion in §1.4 could not have held.

Only a handshake over the direct endpoint clears the counter now. A relayed handshake *during* a probe counts
as a failed attempt; one outside a probe leaves the pending schedule where it was, so neither the punch delay
nor an armed retreat is moved by relayed traffic. `a_relayed_handshake_does_not_pull_the_punch_forward`,
`a_relayed_handshake_does_not_reset_an_armed_retreat` and `a_relayed_handshake_during_a_probe_counts_as_a_failed_attempt`
pin the three cases.

**This is the same defect PR #10 (`m0/conformance`) found and fixed on its own branch.** The two fixes are
semantically identical and one of them has to win when both branches land; the tests in this branch are the
superset (they add the "outside a probe" case and the arithmetic test of the whole schedule).

## 5. What is verified *only* over the fakes, and what that does not prove

This is the part the next phase has to read carefully.

| claim | what is actually behind it |
|---|---|
| a punch fails on a symmetric NAT | a `NatSim` in the test file that decides whether a packet arrives, and a fake kernel that completes a handshake only when it does. **No real NAT was involved.** |
| the endpoint returns to the relay | `FakeWireGuard::apply`, an in-memory map. The kernel path — netlink, and what a real interface does with an endpoint change mid-session — was never executed here |
| the relay re-observes within one round trip | a harness that reports what the relay *would* report on the sync cadence. The real observation path is the coordinator's, and it is not wired in this branch |
| UPnP is never attempted | a call count on a fake gateway. **No UPnP or NAT-PMP adapter exists yet**, so the claim is about the decision, not about the packets |
| IPv6 candidates help | the class is derived and ranked from an inventory port whose only implementation is a fake. **No `InterfaceInventory` adapter was written**, so nothing here reads a real interface |
| LAN candidates win | the same: ranking and policy are proven; reading `192.168.x.x` off an interface is not |
| the keepalive keeps the mapping alive | the literature and `wg(8)`; not measured, because no NAT was |

Also untouched by this step: the mac1/`receiver_index` relay routing of the previous M3 step is still only
compiled, not exercised on the wire.

## 6. Port prediction is out of scope

**Symmetric NAT port prediction (the birthday attack) is deliberately not implemented, and it is not a gap
in this step.** It is the first item of §8 for a reason: it costs a burst of packets to every candidate port
range — traffic that is loud, that some carriers rate-limit, and that buys a path only against a NAT whose
port-allocation function is guessable, which the ones that matter are not. Fallback plus backoff is what the
blueprint asks for here, and it is what the mesh does: the relay carries the pair, and a punch is retried at
30 s, 2 m, 10 m and then every 10 minutes for as long as the pair is up.

## 7. The environment this was verified in

Honest bookkeeping, because it changes how much the checks above are worth:

- This Computer has **no CAP_NET_ADMIN and no netns**, so no kernel WireGuard and no namespace-based NAT
  simulation. Every kernel and network claim above is over the fakes; that is a property of the environment,
  not a shortcut.
- The machine **restarted several times during this step** and its `/home` volume filled to 100 %, which
  killed a build mid-link and lost a working tree once. The final state — commit `563add5` on the branch,
  PR #22 — was re-created and re-run after the last restart: **160 tests passed, clippy clean,
  `check-deps` and `check-style` clean** on that tree. As part of recovering space, the stale `target/`
  build caches of five *finished* jobs in this thread were deleted; no sources and no git state were touched.
- CI on PR #22 is the first run of the same checks in a clean, stable environment. Where CI and this report
  disagree, CI is right.

## 8. The next phase: field verification

This is the handover. The order is the order of what a broken assumption costs.

1. **Two nodes behind one NAT, same LAN** (a laptop and a desktop at home). Proves the `Lan` class end to end:
   the address is read off a real interface, the peer is reachable at it, and traffic stops crossing the relay.
   Watch: does the kernel accept an endpoint change while a relay session is up, or does it need the peer
   re-applied — `dispatch` re-applies on every move, and that is the thing to confirm.
2. **Two nodes with global IPv6, no NAT in front.** Proves the `Ipv6` class and, more usefully, that a mesh
   can skip the whole punch dance. Watch: `AllowedIPs` and the route policy — an IPv6 candidate needs an
   IPv6 prefix the routing policy actually installs.
3. **A pair behind symmetric NAT** — two mobile-tethered hosts, or carrier-grade NAT. This is the scenario
   §1.4 is about. Watch: the relay never stops carrying the pair (that is success), the retreat really is
   30 s → 2 m → 10 m in the logs, and the relay's slot mapping survives the idle gaps.
4. **A consumer router with UPnP on.** The only way to find out whether the adapter is worth writing. Watch:
   whether the mapped port actually accepts an inbound handshake, and how long the router honours the
   lifetime that was asked for.
5. **A direct path that dies under traffic** (pull the peer's cable, or kill its Wi-Fi). Proves the degrade
   deadline against real `persistent-keepalive` behaviour and a real `RejectAfterTime`, which is the number
   the whole detection rests on.
6. **The relay's one-port routing** (the previous M3 step): two real peers through `wgmesh-relayd`, and
   `mac1`/`receiver_index` judged against real WireGuard packets rather than against the parser.
7. **The NixOS VM tests** (`nix/tests/{e2e,forwarding,relay}.nix`), which this Computer cannot run.

For 1–5 the measurement to take is the same: for each pair, the sequence of `Path` transitions with
timestamps, the endpoint the kernel holds at each one, and whether the relay's byte counters stay flat while
the direct path is up. That is the difference between "it reconnected" and "it stopped using the relay".

## 9. Next steps (the list, not a plan)

1. **Symmetric NAT port prediction** — deferred on purpose; see §6.
2. An `InterfaceInventory` adapter over netlink (or `/proc/net/if_inet6` and `getifaddrs`), so the LAN and
   IPv6 classes exist outside a test.
3. A NAT-PMP/UPnP-IGD adapter, which is only worth writing once §8.4 says the mapping is honoured.
4. Wire the coordinator's observations and the relay-slot resolution into the daemon's loop — the runner
   takes both as arguments today, and the caller that produces them is the composition root.
5. `report_punch`, so a symmetric NAT is visible from the coordinator rather than only in a node's log.

---

*Companion artifacts: `wgmesh-M0-report.md`, the M1 and M2 reports, and the blueprint in `docs/`.*
