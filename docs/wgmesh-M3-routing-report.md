---
title: wgmesh M3 report — one port per node, routed by mac1 and receiver_index
---

# wgmesh M3 report — one port per node, routed by mac1 and receiver_index

**TL;DR** — a relay can now serve **one UDP socket per node** and route N² pairs through
it: the destination is read out of the packet (`mac1` for a handshake, `receiver_index` for
everything else) and the sender is taken from the ingress slot port. The decision lives in
`wgmesh-core` (`RelayTable::route_one_port`), the relay engine gained a `one_port` switch
that drives it, and both are covered — core unit tests plus four integration tests over
real 127.0.0.1 UDP. `cargo test --workspace --locked` (65 tests), `cargo xtask check-deps`,
`cargo xtask check-style` and `clippy -D warnings` are all green.

**This routing has never been exercised with a real WireGuard packet** — see §5. The
previous lab substituted a 2-byte destination tag for exactly this job, and nothing in this
change alters that: what is verified here is the routing arithmetic and the relay's
forwarding path, not WireGuard's own framing or cryptography.

## 1. Where the work is

| Item | Value |
|---|---|
| Repository | `https://github.com/mincomk/wgmesh` (public) |
| Branch | `job/98c81d35ac4c44ed83efec414c8905b8/wgmesh` |
| Base | `origin/m0/relay-engine` (the relay engine, one commit over `a181f2e`), with `wgmesh-core`'s one-port router taken from `origin/m3/one-port-routing` |
| Commands run | `cargo test --workspace --locked`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo xtask check-deps`, `cargo xtask check-style`, `cargo fmt --all --check` |

The one-port judgement was authored on `origin/m3/one-port-routing` as
`crates/wgmesh-core/src/router.rs` and never reached the relay: that branch sits on a
skeleton with no engine in it. This branch puts the two together, and adds the half that
was missing — a relay that actually routes that way.

## 2. What changed

| File | What it is now |
|---|---|
| `crates/wgmesh-core/src/router.rs` | New (909 lines). `sender_index`/`receiver_index` offsets, `Keyset` (`PublicKey` → device, MAC key derived once), `SessionTable`, `RelayCounters`, and `RelayTable::route_one_port` |
| `crates/wgmesh-core/src/lib.rs` | `RelayTable` carries `keyset`, `sessions` and `counters`; `router` is a module and is re-exported |
| `crates/wgmesh-relay/src/config.rs` | `RelayConfig::one_port: bool`, default `false` |
| `crates/wgmesh-relay/src/engine.rs` | `one_port()` accessor, `sessions()` accessor, `apply_keyset()` (the network's public keys are handed to the core, which needs them to verify a `mac1`), the one-port branch in `handle()`, and a `rejected` counter on `Counters` |
| `crates/wgmesh-relay/src/main.rs` | `relay.toml` accepts `one_port` (or `[relay] mode`), the start-up line names the layout, `status` and the heartbeat print `rejected` |
| `crates/wgmesh-relay/tests/one_port_udp.rs` | New. Four integration tests over real UDP |
| `crates/wgmesh-relay/Cargo.toml` | `blake2` as a **development** dependency, so the tests can mint real `mac1` values |
| `README.md` | "How a relay finds the destination": both layouts, the formulas, and what an attacker who guesses a port can and cannot do |
| `Cargo.lock` | The development edge above (CI runs `--locked`) |

The default is unchanged: a relay that is not told otherwise still serves a port per pair,
and the fourteen existing engine tests pass untouched.

## 3. How the destination is decided

```
mac1       = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[..offsetof(mac1)])
             type 1 (148B) or type 2 (92B) -> the first keyset key that verifies wins
receiver_index  type 2 at offset 8, type 3 and type 4 at offset 4 -> SessionTable -> device
```

The relay never reads past those header fields, and it never writes a byte: what leaves is
exactly what arrived, at the length it arrived. Where the layout is switched on, the port a
packet arrives on is used for one thing only — the identity of the **sender** — because
WireGuard deliberately leaves the sender out of the packet (`docs/coordinator-design.md`
§4.6).

The **session index table** is fed by handshakes the relay actually carried: a handshake
whose `mac1` resolved, between an assigned pair, with somewhere to deliver. An entry is an
index, a device id and a timestamp — `SessionTable::ENTRY_BYTES` is asserted to be smaller
than a 32-byte key, so a key could not fit in one — and it refreshes itself: a rekey picks a
fresh index and the device's previous index stops naming anything immediately, while an
index nobody refreshes ages out after `SESSION_TTL` (180 s, WireGuard's `RejectAfterTime`;
a rekey is expected roughly every 120 s, `RekeyAfterTime`).

A packet whose destination tag names nothing — a `mac1` that matches no key in the keyset, or
an index with no live session — is dropped and counted **`rejected`**. Nothing is learned
from a packet the relay does not carry.

## 4. What is verified, and by which test

Core, `cargo test -p wgmesh-core` (36 tests, of which 12 are the one-port module):

| Acceptance criterion | Test |
|---|---|
| `mac1` picks the destination exactly | `mac1_picks_the_destination_out_of_the_keyset` |
| `mac1` says no to a wrong key and a wrong shape | `mac1_refuses_the_wrong_key_and_the_wrong_shape` (wrong key; a transport or cookie packet; 147 and 91 bytes; empty; right shape with a wrong tag) |
| Type 1 (148 B), type 2 (92 B), type 3 and type 4 (≥32 B) each map to the right destination | `every_message_type_maps_to_its_destination` |
| The session table is fed by handshakes | `a_session_index_is_learned_from_the_handshake_that_carries_it` |
| The table refreshes itself on a rekey (~2 min) and ages out | `the_session_table_refreshes_itself_when_the_initiator_rekeys` |
| An index is not stolen from a live owner | `an_index_is_never_stolen_from_its_live_owner_but_may_be_reused_once_stale` |
| The table holds an index and a device id and nothing else, structurally | `the_session_table_holds_indices_and_device_ids_and_nothing_else` |
| An unknown destination tag is dropped and counted `rejected` | `a_destination_outside_the_keyset_is_rejected_and_counted` |
| Only assigned pairs move | `one_port_mode_still_forwards_only_assigned_pairs` |
| Nothing is learned from a packet that is not carried | `nothing_is_learned_from_a_packet_that_is_not_carried` |
| A slot whose source moved is refused until the pin goes stale | `one_port_mode_refuses_a_slot_whose_source_moved` |
| The decision is header-only, and no byte is added | `the_relay_decides_on_the_header_alone_and_never_adds_a_byte` |

Relay, `cargo test -p wgmesh-relay --test one_port_udp` (4 tests, real 127.0.0.1 UDP —
`UdpSlotSockets`, the same socket path a deployed relay runs):

| Test | What it shows |
|---|---|
| `one_socket_per_node_and_the_destination_comes_out_of_the_packet` | Three nodes, three bound sockets, two pairs through A's single socket. A's initiation reaches B (destination from `mac1`), A's initiation to C leaves the same socket, B's response comes back on `mac1`, and A's transport reaches B on `receiver_index` learned from that response. `forwarded` +4, `forwarded_bytes` = 148+148+92+96, `rejected` +0 |
| `one_port_mode_forwards_only_assigned_pairs` | B's perfectly valid handshake addressed to C does not move — `(B, C)` is not an assigned pair. `drops.not_assigned` +1, `rejected` +0, and C receives nothing |
| `a_destination_tag_outside_the_keyset_is_dropped_and_counted_rejected` | A handshake for a public key outside the keyset, a handshake whose `mac1` was corrupted on the wire, and a transport packet naming a dead index: all three dropped, `rejected` +3, B receives nothing |
| `the_session_table_is_learned_from_carried_handshakes_and_refreshes_on_rekey` | An unaddressed packet teaches the table nothing; a carried initiation attributes A's index to A and says nothing about B; a rekey 120 s later replaces A's index rather than adding one |

Whole workspace: `cargo test --workspace --locked` → 65 passed, 0 failed.
`cargo xtask check-deps: ok`, `cargo xtask check-style: ok`,
`cargo clippy --workspace --all-targets -- -D warnings` → clean.

What this buys, stated as the security property rather than as a comment: an attacker who
learns a slot's port can send packets, but cannot read one, cannot forge one that passes
`mac1`, and cannot open a session, because the relay holds no key and no plaintext. The
exposure left by a wrong guess is bandwidth and CPU — the packets are dropped upstream by
WireGuard, but they were relayed first.

## 5. What is NOT verified — read this before trusting §4

1. **No real WireGuard packet has ever been through this routing.** Every handshake in the
   tests is a 148- or 92-byte buffer with a genuine `mac1` (hashed by the same core function
   the relay verifies with) and zeros everywhere else. `wg(8)` was not involved, no Noise
   handshake was performed, and no packet here would be accepted by a WireGuard peer.
   **The previous lab put a 2-byte destination tag in the same place**; this work replaces
   the design of that substitution but does not measure the real thing.
2. **Offsets are from the protocol document**, not from a captured packet: type 2's
   `receiver_index` at offset 8, types 3 and 4 at offset 4, `mac1` in the last 32 bytes with
   the MAC taken over everything before it. A capture of a real handshake would settle it.
3. **The kernel path was not exercised under load.** The tests are loopback UDP with a
   handful of datagrams; MTU, offload, IPv6 sockets and burst behaviour are untested here.
4. Everything the earlier milestones could not verify still cannot be verified on this
   Computer: no `CAP_NET_ADMIN`, no `netns`, no `nix`, no `/dev/kvm`.

## 6. The first real-machine verification should check

1. Two nodes with `relay.one_port = true`, one WireGuard handshake between them, and a
   tcpdump on the relay showing which peer each packet left for.
2. A third node paired with the first, proving both peers are served by one socket and that
   an unpaired pair still does not move.
3. The session table across a rekey (roughly two minutes of traffic): the index changes, the
   old one stops being used, and the relay never needs a packet of its own to learn it.
4. `rejected` on a relay that is handed a packet addressed outside its keyset.
5. The same three checks with the layout switched off, to confirm the port-per-pair path is
   unchanged on real hardware.

## 7. Real WireGuard packets, measured through `route_one_port` (2026-10-09)

Everything in §4 was measured with buffers this repository built. This section was measured
with bytes nobody here wrote.

### 7.1 Where the capture came from

Two WireGuard peers running **boringtun 0.7.1** — an independent implementation (Cloudflare's),
not this repository's constants — performed a genuine Noise_IKpsk2 handshake over loopback UDP
and then sent tunnel traffic through the session it established. A second pair ran with the
responder configured to consider itself under load, so that it answered an initiation whose
`mac2` did not verify with a **cookie reply**. While both exchanges ran:

```
sudo tcpdump -i lo -s0 -U -w wg-handshake.pcap \
  'udp port 51901 or udp port 51902 or udp port 51903 or udp port 51904'
```

The machine was this Computer (Attacca Computer, Linux 6.18.35). The capture — 1,010 bytes,
seven datagrams — is committed at `crates/wgmesh-relay/tests/data/wg-handshake.pcap`, with
`tests/data/README.md` recording the command and the two static public keys the peers used
(a static public key is never on the wire, so it cannot be read out of the file).

| # | Direction | Type | Bytes |
|---|---|---|---|
| 1 | 51901 → 51902 | 1, initiation | 148 |
| 2 | 51902 → 51901 | 2, response | 92 |
| 3 | 51901 → 51902 | 4, transport (keepalive) | 32 |
| 4 | 51901 → 51902 | 4, transport (keepalive) | 32 |
| 5 | 51901 → 51902 | 4, transport (a 31-byte tunnel packet, padded) | 64 |
| 6 | 51903 → 51904 | 1, initiation | 148 |
| 7 | 51904 → 51903 | 3, cookie reply | 64 |

### 7.2 What the capture settles

**The offsets are the ones `router.rs` reads.** Read off datagrams 1, 2, 5, 6 and 7 rather than
from the protocol document:

| Field | Where the capture puts it | `router.rs` |
|---|---|---|
| message type | byte 0, with three zero bytes after it, on every type | `classify` |
| initiation `sender_index` | 4 | `OFF_INDEX` |
| response `sender_index` | 4 | `OFF_INDEX` |
| response `receiver_index` | 8 | `OFF_RECEIVER_OF_RESPONSE` |
| cookie reply `receiver_index` | 4 | `OFF_INDEX` |
| transport `receiver_index` | 4 | `OFF_INDEX` |
| `mac1` | first 16 bytes of the packet's last 32 | `verify_mac1` |
| sizes | 148 / 92 / 64 / ≥32 | `MessageKind::size_floor` |

The indices are not merely in the right place; they are each other's. The response's
`receiver_index` at 8 is the initiation's `sender_index` at 4; the transport's `receiver_index`
at 4 is the response's `sender_index` at 4; the cookie reply's `receiver_index` at 4 is the
second initiation's `sender_index` at 4. A field read one byte off would not line up.

**`mac1` is keyed by the recipient, in both directions.** `verify_mac1` — this repository's
`HASH(LABEL_MAC1 || key)` and MAC — accepts the captured initiation under the *responder's*
static public key and rejects it under the initiator's, and accepts the captured response under
the *initiator's* key and rejects it under the responder's. Corrupting one bit before `mac1`'s
last byte breaks it; corrupting `mac2` does not. That is the assumption §3 states, confirmed by
an implementation that interoperates with the kernel's.

**The packets route.** `crates/wgmesh-relay/tests/wireguard_capture.rs` replays the capture
through `RelayTable::route_one_port` with the two peers' static public keys in a keyset:

- datagram 1 from the initiator's slot → `Forward { from: initiator, to: responder }`, resolved
  by `mac1` alone;
- datagram 2 from the responder's slot → `Forward { from: responder, to: initiator }` — also by
  `mac1`, keyed by the other peer — and carrying it is what teaches the relay the responder's
  session index;
- datagrams 3–5 from the initiator's slot → `Forward { from: initiator, to: responder }`,
  resolved by `receiver_index` through that learned session;
- datagram 6 from the second initiator's slot → `Forward` on `mac1`; datagram 7, the cookie
  reply, back the other way on the `receiver_index` of the initiation it answers;
- and flipping one bit of the real initiation's `mac1` makes the same table drop it, so the
  assertions are reading the field rather than agreeing with themselves.

The test adds no dependency — a pcap is a 24-byte header and `(16-byte record header, frame)`
pairs, so it parses the file itself — and it runs as part of `cargo test --workspace`.

### 7.3 What is still not measured

1. **This is not the kernel.** The bytes are WireGuard's, produced by an implementation that
   interoperates with the kernel's, but no kernel `wireguard` interface, no `wg(8)` and no
   kernel module produced any of them. The kernel's own framing has still not been captured on
   this Computer, and §5.1–5.2's caveat narrows rather than closes: the offsets and the `mac1`
   derivation are now measured, the *kernel's* copy of them is not.
2. **The kernel path is closed here, and why.** `ip link add dev wgX type wireguard` inside this
   Computer's namespaces fails with `Unknown device type`: the kernel registers no `wireguard`
   link kind, there is no `/lib/modules`, and a container cannot load one. Worth recording
   because the earlier milestones reported the blunter reason: **a network namespace *is*
   available here** — `unshare -rn --map-root-user` succeeds, `sudo` is available, `/dev/net/tun`
   is present and `ip tuntap add` works inside that namespace. It is the `wireguard` link type,
   and only that, which is missing. Nothing else in M0–M3 was blocked by netns.
3. A kernel capture remains the one measurement this Computer cannot take; §6 is still the
   checklist for it, and `tests/data/README.md` records what a kernel capture would have to
   reproduce to replace the boringtun one.
