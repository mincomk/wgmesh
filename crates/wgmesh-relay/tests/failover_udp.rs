#![allow(clippy::unwrap_used, clippy::expect_used)]

// Two relays and the pair that moves between them, over real 127.0.0.1 UDP sockets.
//
// `engine_udp.rs` proves one relay forwards correctly. What this file proves is the
// property the fleet depends on: a pair is only ever served by the relay its assignment
// names, moving that pair to another relay starts working there without restarting
// anything, and the pairs left on the first relay keep working untouched. The reference
// behaviour is the relay-fleet lab, where re-homing a pair recovers the session in 0.3s.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use wgmesh_relay::wgmesh_core::{DeviceId, Millis};
use wgmesh_relay::{
    Assignment, Drop, Keyset, KeysetNetwork, KeysetPeer, PairAssignment, RelayConfig, RelayEngine,
    SlotAssignment, UdpSlotSockets,
};

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const LONG: Duration = Duration::from_secs(2);

fn address(port: u16) -> SocketAddr {
    SocketAddr::new(LOCAL, port)
}

// A WireGuard transport message: type 4, and any length at or above the 32-byte floor.
fn transport(length: usize) -> Vec<u8> {
    let mut packet = vec![0x5a_u8; length];
    packet[0] = 4;
    packet
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

// Slot ports are asked for as 0, so the operating system picks them and two relays can
// run side by side in one process without fighting over a port.
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

    fn recv_within(&self, budget: Duration) -> Option<Vec<u8>> {
        let deadline = Instant::now() + budget;
        let mut buffer = vec![0_u8; 4096];
        loop {
            match self.socket.recv_from(&mut buffer) {
                Ok((length, _)) => return Some(buffer[..length].to_vec()),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("recv_from: {error}"),
            }
        }
    }
}

struct Relay {
    name: &'static str,
    engine: RelayEngine<UdpSlotSockets>,
}

impl Relay {
    fn start(name: &'static str) -> Self {
        let engine = RelayEngine::new(
            UdpSlotSockets::new(LOCAL),
            RelayConfig {
                relay_id: name.to_string(),
                ..RelayConfig::default()
            },
        );
        Self { name, engine }
    }

    fn assign(&mut self, slots: &[u32], pairs: &[(u32, u32)], keys: &[u32], at: Millis) {
        self.engine
            .on_assignment(assignment(slots, pairs, keys), at)
            .unwrap();
    }

    fn slot(&self, device: u32) -> SocketAddr {
        address(
            self.engine
                .slot_port(DeviceId(device))
                .unwrap_or_else(|| panic!("{} has no slot for device {device}", self.name)),
        )
    }

    fn pump_until(&mut self, at: Millis, expected: usize) {
        let deadline = Instant::now() + LONG;
        let mut handled = 0;
        while handled < expected {
            handled += self.engine.pump(at);
            if handled >= expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{} carried only {handled} of {expected} datagrams",
                self.name
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn forwarded(&self) -> u64 {
        self.engine.counters().forwarded
    }
}

// A pair announces itself on a relay: each side has to send once before the relay knows
// where to deliver to it. Returns what the far side received.
fn announce_and_send(
    relay: &mut Relay,
    a: &Peer,
    b: &Peer,
    device_a: u32,
    device_b: u32,
    at: Millis,
) {
    let a_slot = relay.slot(device_a);
    let b_slot = relay.slot(device_b);
    b.send(b_slot, &transport(64));
    relay.pump_until(at, 1);
    a.send(a_slot, &transport(64));
    relay.pump_until(at, 1);
}

#[test]
fn a_re_homed_pair_starts_working_on_the_new_relay_without_a_restart() {
    let at = Millis::from_millis(1_000);
    let mut relay_one = Relay::start("relay_1");
    let mut relay_two = Relay::start("relay_2");
    let a = Peer::bind();
    let b = Peer::bind();

    // The pair is placed on relay-1 and works there.
    relay_one.assign(&[1, 2], &[(1, 2)], &[1, 2], at);
    announce_and_send(&mut relay_one, &a, &b, 1, 2, at);
    assert!(b.recv_within(LONG).is_some(), "relay-1 carries the pair");
    assert_eq!(relay_one.forwarded(), 1);

    // The coordinator re-homes the pair to relay-2. Nothing is restarted: relay-2 had
    // never been given this pair, and it serves it as soon as the assignment lands.
    let moved = at.plus(Duration::from_millis(500));
    relay_two.assign(&[1, 2], &[(1, 2)], &[1, 2], moved);
    announce_and_send(&mut relay_two, &a, &b, 1, 2, moved);

    assert!(
        b.recv_within(LONG).is_some(),
        "the pair is served by the relay it was moved to"
    );
    assert_eq!(
        relay_two.forwarded(),
        1,
        "the new relay carries the pair with no restart and no re-enrolment"
    );
}

#[test]
fn the_pair_left_behind_is_no_longer_carried_by_the_old_relay() {
    let at = Millis::from_millis(1_000);
    let mut relay_one = Relay::start("relay_1");
    let mut relay_two = Relay::start("relay_2");
    let a = Peer::bind();
    let b = Peer::bind();
    let c = Peer::bind();
    let d = Peer::bind();

    relay_one.assign(&[1, 2, 3, 4], &[(1, 2), (3, 4)], &[1, 2, 3, 4], at);
    relay_two.assign(&[1, 2, 3, 4], &[(1, 2), (3, 4)], &[1, 2, 3, 4], at);
    announce_and_send(&mut relay_one, &a, &b, 1, 2, at);
    announce_and_send(&mut relay_one, &c, &d, 3, 4, at);
    assert!(b.recv_within(LONG).is_some());
    assert!(d.recv_within(LONG).is_some());

    // The pair (1,2) moves to relay-2; (3,4) stays where it was. relay-1's assignment is
    // the only thing that changed, and it is exactly the assignment the coordinator would
    // push after a re-home.
    let moved = at.plus(Duration::from_millis(500));
    relay_one.assign(&[1, 2, 3, 4], &[(3, 4)], &[1, 2, 3, 4], moved);
    relay_two.assign(&[1, 2, 3, 4], &[(1, 2), (3, 4)], &[1, 2, 3, 4], moved);

    // The moved pair now only travels through relay-2...
    let a_slot = relay_one.slot(1);
    a.send(a_slot, &transport(64));
    relay_one.pump_until(moved, 1);
    assert_eq!(
        relay_one.engine.counters().drops.not_assigned,
        1,
        "a relay that no longer holds the pair drops instead of forwarding it"
    );
    assert!(
        b.recv_within(Duration::from_millis(150)).is_none(),
        "the old relay never carries a pair it was not assigned"
    );

    // ...and the pair that stayed is untouched: it still forwards through relay-1, and
    // the relay's own counters show nothing else changed.
    let forwarded_before = relay_one.forwarded();
    announce_and_send(&mut relay_one, &c, &d, 3, 4, moved);
    assert!(
        d.recv_within(LONG).is_some(),
        "the pair that was not re-homed keeps its path"
    );
    assert_eq!(relay_one.forwarded(), forwarded_before + 1);
}

#[test]
fn a_relay_reports_the_pairs_it_is_serving_so_the_coordinator_can_see_the_move() {
    let at = Millis::from_millis(1_000);
    let mut relay_one = Relay::start("relay_1");
    let mut relay_two = Relay::start("relay_2");

    relay_one.assign(&[1, 2], &[(1, 2)], &[1, 2], at);
    let moved = at.plus(Duration::from_millis(500));
    relay_one.assign(&[1, 2], &[], &[1, 2], moved);
    relay_two.assign(&[1, 2], &[(1, 2)], &[1, 2], moved);

    let reports = relay_two.engine.tick(moved);
    let heartbeat = reports
        .iter()
        .find_map(|report| match report {
            wgmesh_relay::Report::Heartbeat(heartbeat) => Some(heartbeat.clone()),
            _ => None,
        })
        .expect("every batch carries a heartbeat");
    assert_eq!(heartbeat.relay_id, "relay_2");
    assert_eq!(heartbeat.pairs, 1);
    assert_eq!(heartbeat.slots, 2);
    assert_eq!(relay_one.engine.status(moved).pairs, Vec::new());
}

#[test]
fn a_relay_that_lost_its_keyset_refuses_the_pair_it_was_carrying() {
    let at = Millis::from_millis(1_000);
    let mut relay_one = Relay::start("relay_1");
    let a = Peer::bind();
    let b = Peer::bind();

    relay_one
        .engine
        .on_assignment(
            Assignment {
                generation: 1,
                slots: vec![
                    SlotAssignment {
                        device_id: 1,
                        port: 0,
                    },
                    SlotAssignment {
                        device_id: 2,
                        port: 0,
                    },
                ],
                pairs: vec![PairAssignment {
                    device_a: 1,
                    device_b: 2,
                }],
                keyset: keyset(&[1, 2]),
            },
            at,
        )
        .unwrap();
    announce_and_send(&mut relay_one, &a, &b, 1, 2, at);
    assert!(b.recv_within(LONG).is_some());

    // The coordinator has been unreachable past the TTL, so the keyset it holds may name
    // devices that were revoked since. The default policy is to carry nothing with it.
    let expired = at.plus(Duration::from_secs(301));
    let a_slot = relay_one.slot(1);
    a.send(a_slot, &transport(64));
    relay_one.pump_until(expired, 1);
    assert_eq!(relay_one.engine.counters().drops.keyset_stale, 1);
    assert!(b.recv_within(Duration::from_millis(150)).is_none());
    assert_eq!(
        relay_one.engine.counters().drops.get(Drop::KeysetUnknown),
        0,
        "the refusal is the expiry, not the destination"
    );
}
