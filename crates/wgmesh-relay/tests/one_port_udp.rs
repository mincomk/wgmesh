#![allow(clippy::unwrap_used, clippy::expect_used)]

// The M3 layout over real 127.0.0.1 UDP: one socket per node, with the destination read out
// of the packet rather than out of the port it arrived on. The datagrams travel through the
// kernel's UDP stack into the relay's slot sockets and out again, so what these tests prove
// is the path a deployed relay runs.
//
// What is *not* real here, and must not be read into these tests: the packets. The handshake
// headers carry a genuine `mac1` -- `HASH(LABEL_MAC1 || recipient.public)`, hashed by the
// same core function the relay verifies with -- so the routing decision is the real one, but
// nothing here is encrypted by, or would be accepted by, a WireGuard implementation. No
// WireGuard peer, kernel module or `wg(8)` was involved. See
// `docs/wgmesh-M3-routing-report.md`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use blake2::digest::{KeyInit, Mac, Update};
use wgmesh_relay::wgmesh_core::{DeviceId, Mac1, Millis, PublicKey, mac1_key};
use wgmesh_relay::{
    Assignment, Keyset, KeysetNetwork, KeysetPeer, PairAssignment, RelayConfig, RelayEngine,
    SlotAssignment, UdpSlotSockets,
};

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const LONG: Duration = Duration::from_secs(2);
const A: u32 = 1;
const B: u32 = 2;
const C: u32 = 3;

fn address(port: u16) -> SocketAddr {
    SocketAddr::new(LOCAL, port)
}

fn public_key(device: u32) -> PublicKey {
    PublicKey::from_bytes([device as u8; 32])
}

// A WireGuard handshake initiation: type 1, 148 bytes, `mac1` keyed by the *recipient*.
fn initiation(recipient: u32, sender_index: u32) -> Vec<u8> {
    let mut packet = vec![0_u8; 148];
    packet[0] = 1;
    packet[4..8].copy_from_slice(&sender_index.to_le_bytes());
    seal_mac1(&mut packet, recipient);
    packet
}

// A WireGuard handshake response: type 2, 92 bytes, `mac1` also keyed by the recipient.
fn response(recipient: u32, sender_index: u32) -> Vec<u8> {
    let mut packet = vec![0_u8; 92];
    packet[0] = 2;
    packet[4..8].copy_from_slice(&sender_index.to_le_bytes());
    seal_mac1(&mut packet, recipient);
    packet
}

// A WireGuard transport message: type 4, `receiver_index` at offset 4, the 32-byte floor.
fn transport(receiver_index: u32, length: usize) -> Vec<u8> {
    let mut packet = vec![0x5a_u8; length.max(32)];
    packet[0] = 4;
    packet[4..8].copy_from_slice(&receiver_index.to_le_bytes());
    packet
}

// `mac1 = MAC(HASH(LABEL_MAC1 || recipient.public), msg[..offsetof(mac1)])`, written into the
// last 32 bytes of the packet exactly as WireGuard defines it and as the core verifies it.
fn seal_mac1(packet: &mut [u8], recipient: u32) {
    let key = mac1_key(&public_key(recipient));
    let offset = packet.len() - 32;
    let mut mac = <Mac1 as KeyInit>::new_from_slice(&key).unwrap();
    Update::update(&mut mac, &packet[..offset]);
    let tag = mac.finalize().into_bytes();
    packet[offset..offset + 16].copy_from_slice(&tag);
}

struct Peer {
    socket: UdpSocket,
}

impl Peer {
    fn bind() -> Self {
        let socket = UdpSocket::bind(address(0)).unwrap();
        socket.set_nonblocking(true).unwrap();
        Self { socket }
    }

    fn send(&self, to: SocketAddr, payload: &[u8]) {
        let sent = self.socket.send_to(payload, to).unwrap();
        assert_eq!(sent, payload.len());
    }

    fn try_recv(&self) -> Option<(Vec<u8>, SocketAddr)> {
        let mut buffer = vec![0_u8; 4096];
        match self.socket.recv_from(&mut buffer) {
            Ok((length, from)) => Some((buffer[..length].to_vec(), from)),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => None,
            Err(error) => panic!("recv_from: {error}"),
        }
    }

    fn recv_within(&self, budget: Duration) -> Option<(Vec<u8>, SocketAddr)> {
        let deadline = Instant::now() + budget;
        loop {
            if let Some(datagram) = self.try_recv() {
                return Some(datagram);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

fn keyset(devices: &[u32]) -> Keyset {
    Keyset {
        networks: vec![KeysetNetwork {
            id: 1,
            name: "prod".to_string(),
            peers: devices
                .iter()
                .map(|device| KeysetPeer {
                    device_id: *device,
                    wg_pubkey: vec![*device as u8; 32],
                })
                .collect(),
        }],
    }
}

fn assignment(slots: &[u32], pairs: &[(u32, u32)], keys: &[u32]) -> Assignment {
    Assignment {
        generation: 1,
        slots: slots
            .iter()
            .map(|device| SlotAssignment {
                device_id: *device,
                port: 0,
            })
            .collect(),
        pairs: pairs
            .iter()
            .map(|(a, b)| PairAssignment {
                device_a: *a,
                device_b: *b,
            })
            .collect(),
        keyset: keyset(keys),
    }
}

// A relay in the one-port layout: A, B and C each hold a single slot, and A is paired with
// both B and C -- the N^2 shape the layout exists for.
fn one_port_fixture() -> (RelayEngine<UdpSlotSockets>, Peer, Peer, Peer, u16, u16, u16) {
    let mut config = RelayConfig {
        relay_id: "relay_test".to_string(),
        coordinator: Some("https://coordinator.invalid".to_string()),
        pps_per_slot: 10_000,
        mbit_per_slot: 100,
        ..RelayConfig::default()
    };
    config.one_port = true;
    let mut engine = RelayEngine::new(UdpSlotSockets::new(LOCAL), config);
    let at = Millis::from_millis(1_000);
    engine
        .on_assignment(assignment(&[A, B, C], &[(A, B), (A, C)], &[A, B, C]), at)
        .unwrap();
    let a_port = engine.slot_port(DeviceId(A)).unwrap();
    let b_port = engine.slot_port(DeviceId(B)).unwrap();
    let c_port = engine.slot_port(DeviceId(C)).unwrap();
    (
        engine,
        Peer::bind(),
        Peer::bind(),
        Peer::bind(),
        a_port,
        b_port,
        c_port,
    )
}

fn pump_until(engine: &mut RelayEngine<UdpSlotSockets>, at: Millis, expected: usize) {
    let deadline = Instant::now() + LONG;
    let mut handled = 0;
    while handled < expected {
        handled += engine.pump(at);
        if handled >= expected {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "only {handled} of {expected} datagrams reached the relay"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(handled, expected);
}

// A node announces itself by sending on its own slot before any session exists: the relay
// pins the source address -- which is what lets the first handshake be carried -- and drops
// the packet, because its `receiver_index` names no live session yet.
fn pin(engine: &mut RelayEngine<UdpSlotSockets>, peer: &Peer, slot: u16, at: Millis) {
    peer.send(address(slot), &transport(0xdead_beef, 32));
    pump_until(engine, at, 1);
}

#[test]
fn one_socket_per_node_and_the_destination_comes_out_of_the_packet() {
    let (mut engine, a, b, c, a_port, b_port, c_port) = one_port_fixture();
    let at = Millis::from_millis(1_000);

    // N nodes, N sockets: one per node, not one per pair or one per direction.
    assert_eq!(engine.slots().len(), 3);
    let bound = engine.sockets().bound_ports();
    assert_eq!(bound.len(), 3, "one socket per node, and no more");
    assert_eq!(
        engine.pairs().len(),
        2,
        "A-B and A-C, both through A's one port"
    );

    pin(&mut engine, &b, b_port, at);
    pin(&mut engine, &c, c_port, at);
    let base = engine.counters();

    // A's single socket carries traffic to *both* of its peers: the destination is the
    // mac1, not the port.
    let to_b = initiation(B, 0xaaaa);
    a.send(address(a_port), &to_b);
    pump_until(&mut engine, at, 1);
    let (received, from) = b
        .recv_within(LONG)
        .expect("B receives the handshake addressed to its key");
    assert_eq!(received, to_b, "the relay forwards the datagram unchanged");
    assert_eq!(from, address(b_port));

    let to_c = initiation(C, 0xcccc);
    a.send(address(a_port), &to_c);
    pump_until(&mut engine, at, 1);
    let (received, from) = c
        .recv_within(LONG)
        .expect("C receives the handshake addressed to its key");
    assert_eq!(received, to_c);
    assert_eq!(from, address(c_port));

    // B's response names A through mac1, and teaches the relay B's own sender index.
    let back = response(A, 0xbbbb);
    b.send(address(b_port), &back);
    pump_until(&mut engine, at, 1);
    let (received, _) = a
        .recv_within(LONG)
        .expect("A receives the response addressed to its key");
    assert_eq!(received, back);

    // A transport packet has no mac1: its destination is the receiver_index, learned from
    // the handshake above.
    let payload = transport(0xbbbb, 96);
    a.send(address(a_port), &payload);
    pump_until(&mut engine, at, 1);
    let (received, _) = b
        .recv_within(LONG)
        .expect("B receives the transport packet naming its index");
    assert_eq!(received, payload);

    let moved = engine.counters();
    assert_eq!(moved.forwarded - base.forwarded, 4);
    assert_eq!(
        moved.forwarded_bytes - base.forwarded_bytes,
        (148 + 148 + 92 + 96) as u64
    );
    assert_eq!(
        moved.rejected - base.rejected,
        0,
        "every packet after the pin named a destination"
    );
}

#[test]
fn one_port_mode_forwards_only_assigned_pairs() {
    let (mut engine, _a, b, c, _a_port, b_port, c_port) = one_port_fixture();
    let at = Millis::from_millis(1_000);
    pin(&mut engine, &b, b_port, at);
    pin(&mut engine, &c, c_port, at);
    let base = engine.counters();

    // B->C resolves perfectly well -- C is in the keyset -- and still does not move,
    // because (B, C) is not an assigned pair.
    let to_c = initiation(C, 0xbbbb);
    b.send(address(b_port), &to_c);
    pump_until(&mut engine, at, 1);
    assert!(c.recv_within(Duration::from_millis(200)).is_none());

    let moved = engine.counters();
    assert_eq!(moved.forwarded, base.forwarded);
    assert_eq!(
        moved.drops.not_assigned - base.drops.not_assigned,
        1,
        "the pair was not assigned"
    );
    assert_eq!(moved.rejected, base.rejected, "the destination was known");
}

#[test]
fn a_destination_tag_outside_the_keyset_is_dropped_and_counted_rejected() {
    let (mut engine, a, b, _c, a_port, b_port, _c_port) = one_port_fixture();
    let at = Millis::from_millis(1_000);
    pin(&mut engine, &b, b_port, at);
    let base = engine.counters();

    // A handshake addressed to a key no network member holds: neither the routing decision
    // nor the drop is in doubt.
    a.send(address(a_port), &initiation(9, 0xaaaa));
    pump_until(&mut engine, at, 1);
    // ... a handshake whose mac1 was minted for the right key but corrupted on the wire
    let mut corrupted = initiation(B, 0xaaaa);
    corrupted[116] ^= 0x01;
    a.send(address(a_port), &corrupted);
    pump_until(&mut engine, at, 1);
    // ... and a transport packet naming an index no live session claims
    a.send(address(a_port), &transport(0xfeed_face, 64));
    pump_until(&mut engine, at, 1);

    assert!(b.recv_within(Duration::from_millis(200)).is_none());

    let moved = engine.counters();
    assert_eq!(moved.forwarded, base.forwarded);
    assert_eq!(
        moved.rejected - base.rejected,
        3,
        "each was counted `rejected`"
    );
    assert_eq!(
        moved.drops.unknown_destination - base.drops.unknown_destination,
        3
    );
}

#[test]
fn the_session_table_is_learned_from_carried_handshakes_and_refreshes_on_rekey() {
    let (mut engine, a, b, _c, a_port, b_port, _c_port) = one_port_fixture();
    let at = Millis::from_millis(1_000);
    pin(&mut engine, &b, b_port, at);
    assert_eq!(
        engine.sessions().len(),
        0,
        "an unaddressed keepalive teaches the relay nothing"
    );

    a.send(address(a_port), &initiation(B, 0xaaaa));
    pump_until(&mut engine, at, 1);
    assert_eq!(
        engine.sessions().entries().collect::<Vec<_>>(),
        vec![(0xaaaa, DeviceId(A))],
        "the initiation attributed A's index to A, and says nothing about B"
    );
    assert!(
        b.recv_within(LONG).is_some(),
        "the handshake reached B with no session index involved"
    );

    // A rekey, about two minutes later, picks a fresh index. The old one stops naming
    // anyone: the table refreshes with the traffic, and nothing else drives it.
    let rekey = at.plus(Duration::from_secs(120));
    a.send(address(a_port), &initiation(B, 0xbbbb));
    pump_until(&mut engine, rekey, 1);
    let rows: Vec<(u32, DeviceId)> = engine.sessions().entries().collect();
    assert_eq!(rows, vec![(0xbbbb, DeviceId(A))]);
    assert_eq!(
        engine.sessions().len(),
        1,
        "one device holds one index, not two"
    );
    // B receives the rekeyed handshake on the index-free path, so the table is not the only
    // thing that moved: the packet itself was routed by mac1 alone.
    assert!(b.recv_within(LONG).is_some());
}
