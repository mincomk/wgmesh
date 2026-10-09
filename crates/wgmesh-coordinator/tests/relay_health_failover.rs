#![allow(clippy::unwrap_used, clippy::expect_used)]

// The fleet's failover, end to end on one machine: the coordinator's decisions, the
// assignment it hands a relay, and datagrams actually crossing 127.0.0.1.
//
// The reference is the relay-fleet lab, where a pair re-homed off a dead relay recovers
// in 0.3s. What these tests put under assertion is the coordinator half of that: three
// missed heartbeats move a pair, the pair left on another relay does not move, a working
// pair is never disturbed by a relay that is merely back, and a relay that says it is
// draining hands its pairs over and takes no new ones.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wgmesh_app::coordinator::ports::{
    DeviceState, Directory, NewDevice, NewNetwork, NewRelay, Placement, RelayState,
};
use wgmesh_app::coordinator::{Heartbeat, PlacePolicy};
use wgmesh_coordinator::clock::FixedClock;
use wgmesh_coordinator::service::Services;
use wgmesh_coordinator::store::Sqlite;
use wgmesh_core::{DeviceId, Millis, PublicKey, RelayId};
use wgmesh_proto::api::AssignmentResponse;
use wgmesh_proto::{decode_key, parse_device_id};
use wgmesh_relay::{
    Assignment, Keyset, KeysetNetwork, KeysetPeer, PairAssignment, RelayConfig, RelayEngine,
    SlotAssignment, UdpSlotSockets,
};

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const T0: u64 = 1_760_000_000_000;
const LONG: Duration = Duration::from_secs(2);

// The coordinator's own policy: 15s between heartbeats, and a relay is gone after three
// of them in a row are missed.
fn policy() -> PlacePolicy {
    PlacePolicy::default()
}

fn gone_after() -> Duration {
    let policy = policy();
    Duration::from_millis(policy.heartbeat_timeout.0 * u64::from(policy.reassign_after_misses))
}

struct Fleet {
    store: Arc<Sqlite>,
    services: Services,
    network: u32,
    _dir: tempfile::TempDir,
}

impl Fleet {
    async fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let url = format!(
            "sqlite://{}?mode=rwc",
            dir.path().join("coordinator.db").display()
        );
        let store = Arc::new(Sqlite::open(&url, 4).await.expect("open"));
        store.migrate().await.expect("migrate");
        let network = store
            .insert_network(&NewNetwork {
                name: "prod".to_string(),
                cidr: "10.77.0.0/16".to_string(),
                mtu: 1420,
                relay_policy: "any".to_string(),
                created_at: Millis::from_millis(T0),
            })
            .await
            .expect("network");
        let clock = Arc::new(FixedClock::new(Millis::from_millis(T0)));
        let services = Services::new(store.clone(), clock);
        Self {
            store,
            services,
            network: network.id,
            _dir: dir,
        }
    }

    async fn relay(&self, name: &str, host: &str) -> RelayId {
        let key = name.as_bytes()[name.len() - 1];
        let relay = self
            .store
            .insert_relay(&NewRelay {
                name: name.to_string(),
                api_pubkey: PublicKey::from_bytes([key; 32]),
                state: RelayState::Active,
                endpoint_host: host.to_string(),
                port_range: "51900-51999".to_string(),
                region: Some("ap-northeast-2".to_string()),
                provider: Some("vultr".to_string()),
                operator: None,
                created_at: Millis::from_millis(T0),
            })
            .await
            .expect("relay");
        self.store
            .link_relay_network(relay.id, self.network)
            .await
            .expect("link");
        relay.id
    }

    async fn device(&self, name: &str, key: u8) -> DeviceId {
        let device = self
            .store
            .insert_device(&NewDevice {
                network_id: self.network,
                name: name.to_string(),
                wg_pubkey: PublicKey::from_bytes([key; 32]),
                api_pubkey: PublicKey::from_bytes([key + 100; 32]),
                tunnel_ip: format!("10.77.0.{key}"),
                state: DeviceState::Active,
                advertised: Vec::new(),
                created_at: Millis::from_millis(T0),
            })
            .await
            .expect("device");
        self.store
            .set_device_state(device.id, DeviceState::Active)
            .await
            .expect("activate");
        device.id
    }

    /// Every node opens a slot on every relay of the pool, so a re-assignment needs no new
    /// round trip. The coordinator hands out the port and the relay binds exactly it, so
    /// each relay gets its own block and no two devices share one.
    async fn slots(&self, relay: RelayId, devices: &[DeviceId], base: u16) {
        for (index, device) in devices.iter().enumerate() {
            self.store
                .assign_slot(relay, *device, base + index as u16)
                .await
                .expect("slot");
        }
    }

    async fn heartbeat(&self, relay: RelayId, draining: bool, at: Millis) {
        self.services
            .ingest_heartbeat()
            .execute(
                relay,
                &Heartbeat {
                    at,
                    agent_version: Some("0.1.0".to_string()),
                    traffic: Vec::new(),
                    draining,
                },
            )
            .await
            .expect("heartbeat");
    }

    async fn assign(&self, left: DeviceId, right: DeviceId) -> Option<RelayId> {
        self.services
            .assign_pair()
            .execute(left, right)
            .await
            .expect("assign")
    }

    async fn pair_relay(&self, left: DeviceId, right: DeviceId) -> Option<RelayId> {
        self.store.relay_for_pair(left, right).await.expect("pair")
    }

    fn now(&self) -> Millis {
        self.services.clock.now()
    }

    /// The assignment the coordinator actually answers `GET /v1/relay/assignment` with.
    async fn assignment(&self, relay: RelayId) -> Assignment {
        let response = self
            .services
            .relay_assignment(relay)
            .await
            .expect("assignment");
        engine_assignment(&response)
    }

    async fn is_draining(&self, relay: RelayId) -> bool {
        self.store
            .relay_by_id(relay)
            .await
            .expect("relay")
            .expect("known relay")
            .draining
    }
}

/// The relay's copy of the assignment, built from the wire response rather than from the
/// store, so what is applied to the engine is what the relay would really be handed.
fn engine_assignment(response: &AssignmentResponse) -> Assignment {
    Assignment {
        generation: 1,
        slots: response
            .slots
            .iter()
            .map(|slot| SlotAssignment {
                device_id: parse_device_id(&slot.device_id).expect("slot device").0,
                port: slot.udp_port,
            })
            .collect(),
        pairs: response
            .pairs
            .iter()
            .map(|pair| PairAssignment {
                device_a: parse_device_id(&pair.a).expect("pair a").0,
                device_b: parse_device_id(&pair.b).expect("pair b").0,
            })
            .collect(),
        keyset: Keyset {
            networks: response
                .networks
                .iter()
                .map(|network| KeysetNetwork {
                    id: network.id,
                    name: network.name.clone(),
                    peers: network
                        .peers
                        .iter()
                        .map(|peer| KeysetPeer {
                            device_id: parse_device_id(&peer.device_id).expect("keyset device").0,
                            wg_pubkey: decode_key(&peer.wg_pubkey)
                                .map(|key| key.as_bytes().to_vec())
                                .unwrap_or_default(),
                        })
                        .collect(),
                })
                .collect(),
        },
    }
}

struct RelayHost {
    engine: RelayEngine<UdpSlotSockets>,
}

impl RelayHost {
    fn start(name: &str) -> Self {
        Self {
            engine: RelayEngine::new(
                UdpSlotSockets::new(LOCAL),
                RelayConfig {
                    relay_id: name.to_string(),
                    ..RelayConfig::default()
                },
            ),
        }
    }

    fn apply(&mut self, assignment: Assignment, at: Millis) {
        self.engine
            .on_assignment(assignment, at)
            .expect("assignment");
    }

    fn slot(&self, device: DeviceId) -> SocketAddr {
        SocketAddr::new(
            LOCAL,
            self.engine
                .slot_port(device)
                .expect("the relay has the slot"),
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
            assert!(Instant::now() < deadline, "the relay carried nothing");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn self_forwarded(&self) -> u64 {
        self.engine.counters().forwarded
    }
}

struct Peer {
    socket: UdpSocket,
}

impl Peer {
    fn bind() -> Self {
        let socket = UdpSocket::bind(SocketAddr::new(LOCAL, 0)).unwrap();
        socket.set_nonblocking(true).unwrap();
        Self { socket }
    }

    // WireGuard transport shape: type 4, at or above the 32-byte floor.
    fn send(&self, to: SocketAddr) {
        let mut payload = vec![0x5a_u8; 64];
        payload[0] = 4;
        let sent = self.socket.send_to(&payload, to).unwrap();
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

/// A pair on a relay: both sides announce themselves on their own slot first, because a
/// relay only learns where to deliver by watching the source address a device sends from.
fn carry_traffic(
    relay: &mut RelayHost,
    left: &Peer,
    right: &Peer,
    a: DeviceId,
    b: DeviceId,
    at: Millis,
) {
    let a_slot = relay.slot(a);
    let b_slot = relay.slot(b);
    right.send(b_slot);
    relay.pump_until(at, 1);
    left.send(a_slot);
    relay.pump_until(at, 1);
}

#[tokio::test]
async fn three_missed_heartbeats_re_home_the_pair_and_the_path_recovers() {
    let fleet = Fleet::new().await;
    let relay_one = fleet.relay("relay-1", "198.51.100.4").await;
    let relay_two = fleet.relay("relay-2", "198.51.100.5").await;
    let relay_three = fleet.relay("relay-3", "198.51.100.6").await;

    let a = fleet.device("a", 1).await;
    let b = fleet.device("b", 2).await;
    let c = fleet.device("c", 3).await;
    let d = fleet.device("d", 4).await;

    let at = fleet.now();
    for (index, relay) in [relay_one, relay_two, relay_three].into_iter().enumerate() {
        fleet
            .slots(relay, &[a, b, c, d], 54_000 + 100 * index as u16)
            .await;
        fleet.heartbeat(relay, false, at).await;
    }

    // Two pairs, placed by the rule: the first takes relay-1, the second takes the idle
    // relay-2 rather than piling onto the one already carrying a pair.
    assert_eq!(fleet.assign(a, b).await, Some(relay_one));
    assert_eq!(fleet.assign(c, d).await, Some(relay_two));

    // Both pairs are really carrying traffic, each through the relay it was given.
    let mut one = RelayHost::start("relay-1");
    let mut two = RelayHost::start("relay-2");
    one.apply(fleet.assignment(relay_one).await, at);
    two.apply(fleet.assignment(relay_two).await, at);
    let (pa, pb, pc, pd) = (Peer::bind(), Peer::bind(), Peer::bind(), Peer::bind());
    carry_traffic(&mut one, &pa, &pb, a, b, at);
    assert!(pb.recv_within(LONG).is_some(), "relay-1 carries (a,b)");
    carry_traffic(&mut two, &pc, &pd, c, d, at);
    assert!(pd.recv_within(LONG).is_some(), "relay-2 carries (c,d)");

    // relay-1 stops answering. The other two keep reporting, so only the one relay is
    // late -- which is exactly what a broken relay looks like from the control plane.
    let later = at.plus(gone_after() + Duration::from_secs(1));
    fleet.heartbeat(relay_two, false, later).await;
    fleet.heartbeat(relay_three, false, later).await;

    let moved = fleet
        .services
        .ingest_heartbeat()
        .sweep(later)
        .await
        .expect("sweep");

    assert_eq!(
        moved.len(),
        1,
        "only the pair on the relay that went quiet moves: {moved:?}"
    );
    assert_eq!(moved[0].from, relay_one);
    assert_eq!(moved[0].to, Some(relay_three));
    assert_eq!(fleet.pair_relay(a, b).await, Some(relay_three));
    assert_eq!(
        fleet.pair_relay(c, d).await,
        Some(relay_two),
        "the pair on the relay that was never late keeps its assignment"
    );

    // Both peers are given the same relay. One side alone is not a path.
    let config_a = fleet
        .services
        .build_config()
        .execute(a)
        .await
        .expect("config a");
    let config_b = fleet
        .services
        .build_config()
        .execute(b)
        .await
        .expect("config b");
    let peer_b = config_a
        .peers
        .iter()
        .find(|peer| peer.id == b)
        .expect("b is a peer of a");
    let peer_a = config_b
        .peers
        .iter()
        .find(|peer| peer.id == a)
        .expect("a is a peer of b");
    assert_eq!(peer_b.relay, Some(relay_three));
    assert_eq!(peer_a.relay, Some(relay_three));
    assert_eq!(peer_b.relay, peer_a.relay);
    assert!(
        peer_b.endpoint.is_some() && peer_a.endpoint.is_some(),
        "both sides are pointed at a slot on that relay"
    );

    // The path comes back: the new relay is handed the pair, and traffic crosses it.
    let mut three = RelayHost::start("relay-3");
    let reassigned = fleet.assignment(relay_three).await;
    assert!(
        reassigned
            .pairs
            .iter()
            .any(|pair| pair.device_a == a.0 && pair.device_b == b.0),
        "the new relay is told about the pair"
    );
    three.apply(reassigned, later);
    carry_traffic(&mut three, &pa, &pb, a, b, later);
    assert!(
        pb.recv_within(LONG).is_some(),
        "the pair works on the relay it was moved to"
    );

    // The relay it left is no longer handed the pair...
    let stale = fleet.assignment(relay_one).await;
    assert!(
        !stale
            .pairs
            .iter()
            .any(|pair| pair.device_a == a.0 && pair.device_b == b.0),
        "the relay that went quiet is not told to carry the pair any more"
    );

    // ...and the pair that stayed where it was still works on its own relay: both
    // directions cross it, and nothing else does.
    let before = two.self_forwarded();
    carry_traffic(&mut two, &pc, &pd, c, d, later);
    assert!(pd.recv_within(LONG).is_some());
    assert_eq!(two.self_forwarded(), before + 2);
}

#[tokio::test]
async fn a_working_pair_is_never_moved_by_a_relay_that_is_merely_back() {
    let fleet = Fleet::new().await;
    let relay_one = fleet.relay("relay-1", "198.51.100.4").await;
    let relay_two = fleet.relay("relay-2", "198.51.100.5").await;
    fleet.relay("relay-3", "198.51.100.6").await;

    let a = fleet.device("a", 1).await;
    let b = fleet.device("b", 2).await;
    let at = fleet.now();
    for (index, relay) in relays(&fleet).await.into_iter().enumerate() {
        fleet
            .slots(relay, &[a, b], 54_000 + 100 * index as u16)
            .await;
        fleet.heartbeat(relay, false, at).await;
    }

    let assigned = fleet.assign(a, b).await;
    assert_eq!(assigned, Some(relay_one), "the pair lands on relay-1");

    // Every relay is healthy, including the idle ones a fresh choice would prefer: the
    // pair stays where it is rather than being shuffled onto a quieter relay.
    let later = at.plus(Duration::from_secs(60));
    for relay in relays(&fleet).await {
        fleet.heartbeat(relay, false, later).await;
    }
    assert!(
        fleet
            .services
            .ingest_heartbeat()
            .sweep(later)
            .await
            .expect("sweep")
            .is_empty(),
        "a healthy fleet moves nothing"
    );
    assert_eq!(fleet.assign(a, b).await, Some(relay_one));
    assert_eq!(fleet.pair_relay(a, b).await, Some(relay_one));

    // The sticky rule is what the choice returns even when another relay looks better.
    let chosen = fleet
        .services
        .select_relay()
        .execute(a, b, None)
        .await
        .expect("select");
    assert_eq!(
        chosen,
        Some(relay_one),
        "a pair already on relay-1 is not moved to the idle relay-2"
    );
    assert_ne!(chosen, Some(relay_two));
    assert_eq!(fleet.pair_relay(a, b).await, Some(relay_one));
}

#[tokio::test]
async fn a_draining_relay_hands_its_pairs_over_and_takes_no_new_ones() {
    let fleet = Fleet::new().await;
    let relay_one = fleet.relay("relay-1", "198.51.100.4").await;
    let relay_two = fleet.relay("relay-2", "198.51.100.5").await;
    let relay_three = fleet.relay("relay-3", "198.51.100.6").await;

    let a = fleet.device("a", 1).await;
    let b = fleet.device("b", 2).await;
    let c = fleet.device("c", 3).await;
    let d = fleet.device("d", 4).await;

    let at = fleet.now();
    for (index, relay) in [relay_one, relay_two, relay_three].into_iter().enumerate() {
        fleet
            .slots(relay, &[a, b, c, d], 54_000 + 100 * index as u16)
            .await;
        fleet.heartbeat(relay, false, at).await;
    }
    assert_eq!(fleet.assign(a, b).await, Some(relay_one));
    assert_eq!(fleet.assign(c, d).await, Some(relay_two));

    // The operator runs `wgmesh-relayd drain` on relay-1; the relay says so on its next
    // heartbeat, and that is the whole notification the coordinator needs.
    let draining = at.plus(Duration::from_secs(5));
    fleet.heartbeat(relay_one, true, draining).await;
    assert!(fleet.is_draining(relay_one).await);

    let moved = fleet
        .services
        .ingest_heartbeat()
        .sweep(draining)
        .await
        .expect("sweep");
    assert_eq!(
        moved.len(),
        1,
        "the draining relay's pair is handed over: {moved:?}"
    );
    assert_eq!(moved[0].from, relay_one);
    assert_eq!(moved[0].to, Some(relay_three));
    assert_eq!(fleet.pair_relay(a, b).await, Some(relay_three));
    assert_eq!(
        fleet.pair_relay(c, d).await,
        Some(relay_two),
        "another relay's pair is untouched by the drain"
    );

    // And no new pair is placed on a relay that is on its way out.
    let new_pair = fleet.assign(a, c).await;
    assert_ne!(new_pair, Some(relay_one));
    assert_ne!(fleet.pair_relay(a, c).await, Some(relay_one));

    // Clearing the drain puts it back in service.
    let back = draining.plus(Duration::from_secs(5));
    fleet.heartbeat(relay_one, false, back).await;
    assert!(!fleet.is_draining(relay_one).await);
}

async fn relays(fleet: &Fleet) -> Vec<RelayId> {
    fleet
        .store
        .relays_of(fleet.network)
        .await
        .expect("relays")
        .into_iter()
        .map(|relay| relay.id)
        .collect()
}
