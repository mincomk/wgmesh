// # wgmesh-coordinator
//
// The coordinator is a **control plane**: it decides which relay a pair of
// devices is homed on, learns each device's observed source address from that
// relay, and tells the two ends when to punch. It never carries a packet.
//
// That is a structural property, not a promise: no type in this crate holds a
// `UdpSocket`, `wgmesh-control` offers no UDP transport, and the conformance
// tests check the running process's own socket table to confirm it.
//
// State is in memory. The M0 coordinator is deliberately the smallest thing
// that can home a pair and re-home it when a relay dies; persistence (SQLite)
// and signed device authentication are M1/M2 work.

use std::collections::BTreeMap;
use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::control::{
    Assigned, DeviceKey, DeviceSync, DeviceSyncResponse, DeviceView, Pair, PairView,
    RelayDirective, RelayHeartbeat, RelayStateView, RelayStats, RelayView, StateView,
};

/// A relay that has been silent for longer than this is treated as gone and its
/// pairs are re-homed.
///
/// The lab's heartbeats are 300ms apart, so this is ten missed heartbeats: long
/// enough that a loaded machine does not re-home a relay that was merely
/// descheduled, short enough that a scenario which kills one still settles in
/// seconds.
pub const RELAY_TIMEOUT: Duration = Duration::from_millis(3000);

type PairKey = (u32, u32);

fn pair_key(a: u32, b: u32) -> PairKey {
    if a <= b { (a, b) } else { (b, a) }
}

#[derive(Debug, Default)]
struct RelayState {
    last_seen: Option<Instant>,
    slots: BTreeMap<u32, u16>,
    observations: BTreeMap<u32, SocketAddr>,
    stats: RelayStats,
}

impl RelayState {
    fn healthy(&self, now: Instant) -> bool {
        self.last_seen
            .map(|seen| now.saturating_duration_since(seen) <= RELAY_TIMEOUT)
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone)]
struct DeviceState {
    public_key: [u8; 32],
    peer: u32,
}

pub struct Coordinator {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    relays: BTreeMap<String, RelayState>,
    devices: BTreeMap<u32, DeviceState>,
    pair_relay: BTreeMap<PairKey, String>,
    generation: u64,
}

impl Default for Coordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl Coordinator {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
        }
    }

    /// A relay checking in: fold in its slots, observations and counters, then
    /// answer with what it is responsible for.
    pub fn heartbeat(&self, heartbeat: RelayHeartbeat) -> RelayDirective {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        {
            let relay = inner.relays.entry(heartbeat.id.clone()).or_default();
            relay.last_seen = Some(now);
            for slot in &heartbeat.slots {
                relay.slots.insert(slot.device, slot.port);
            }
            for observation in &heartbeat.observations {
                if let Some(addr) = crate::control::parse_socket_addr(&observation.addr) {
                    relay.observations.insert(observation.device, addr);
                }
            }
            relay.stats = heartbeat.stats;
        }
        inner.reassign(now);
        inner.directive_for(&heartbeat.id)
    }

    /// An agent checking in: enroll or refresh it, then tell it where its pair
    /// is homed and what to punch at.
    pub fn device_sync(&self, sync: DeviceSync) -> DeviceSyncResponse {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        let public_key = crate::control::decode32(&sync.public_key).unwrap_or([0u8; 32]);
        inner.devices.insert(
            sync.device,
            DeviceState {
                public_key,
                peer: sync.peer,
            },
        );
        inner.reassign(now);
        inner.view_for(sync.device, now)
    }

    pub fn state(&self) -> StateView {
        let inner = self.inner.lock().unwrap();
        inner.state_view(Instant::now())
    }
}

impl Inner {
    /// A pair exists once both ends exist and each names the other.
    fn pair_keys(&self) -> Vec<PairKey> {
        let mut keys = Vec::new();
        for (device, state) in &self.devices {
            let peer = state.peer;
            if peer <= *device {
                continue;
            }
            if self.devices.get(&peer).map(|other| other.peer) == Some(*device) {
                keys.push(pair_key(*device, peer));
            }
        }
        keys
    }

    fn healthy_relays(&self, now: Instant) -> Vec<String> {
        self.relays
            .iter()
            .filter(|(_, relay)| relay.healthy(now))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Home every pair on a healthy relay.
    ///
    /// The homing is a *pure function* of the enrolled pair set and the healthy
    /// relay list: the pair at position `i` of the sorted pair list goes to
    /// `healthy[i % healthy.len()]`. Pure, so it is deterministic and a test can
    /// assert where a pair lands -- but also so that a change in the pair set
    /// can re-home a pair, which M1's health-weighted homing will make sticky.
    ///
    /// With a two-relay fleet, losing one moves only the dead relay's pairs: the
    /// survivor is the only healthy relay, so every pair hashes to it and the
    /// pairs that were already there do not change.
    fn reassign(&mut self, now: Instant) {
        let healthy = self.healthy_relays(now);
        let live = self.pair_keys();
        let mut homing = BTreeMap::new();
        if !healthy.is_empty() {
            for (index, key) in live.iter().enumerate() {
                homing.insert(*key, healthy[index % healthy.len()].clone());
            }
        }
        if homing != self.pair_relay {
            self.generation += 1;
        }
        self.pair_relay = homing;
    }

    fn devices_of_pairs_on(&self, relay_id: &str) -> Vec<u32> {
        let mut devices = Vec::new();
        for (key, relay) in &self.pair_relay {
            if relay != relay_id {
                continue;
            }
            for device in [key.0, key.1] {
                if !devices.contains(&device) {
                    devices.push(device);
                }
            }
        }
        devices.sort_unstable();
        devices
    }

    fn directive_for(&self, relay_id: &str) -> RelayDirective {
        let mut pairs = Vec::new();
        for (key, relay) in &self.pair_relay {
            if relay == relay_id {
                pairs.push(Pair { a: key.0, b: key.1 });
            }
        }
        let devices = self
            .devices_of_pairs_on(relay_id)
            .into_iter()
            .filter_map(|device| {
                self.devices.get(&device).map(|state| DeviceKey {
                    device,
                    public_key: crate::control::encode(&state.public_key),
                })
            })
            .collect();
        RelayDirective {
            generation: self.generation,
            devices,
            pairs,
        }
    }

    fn view_for(&self, device: u32, now: Instant) -> DeviceSyncResponse {
        let peer = self
            .devices
            .get(&device)
            .map(|state| state.peer)
            .unwrap_or(0);
        let key = pair_key(device, peer);
        let assigned = self.pair_relay.get(&key).and_then(|relay_id| {
            let relay = self.relays.get(relay_id)?;
            if !relay.healthy(now) {
                // The relay that owns this pair is gone and nothing has taken
                // it over yet: report no assignment rather than an address that
                // cannot work.
                return None;
            }
            Some(Assigned {
                relay_id: relay_id.clone(),
                slot_addr: relay
                    .slots
                    .get(&device)
                    .map(|port| format!("127.0.0.1:{port}")),
                peer_device: peer,
                peer_public_key: self
                    .devices
                    .get(&peer)
                    .map(|state| crate::control::encode(&state.public_key)),
                peer_observed: relay.observations.get(&peer).map(|addr| addr.to_string()),
                punch: relay.observations.contains_key(&device)
                    && relay.observations.contains_key(&peer),
            })
        });
        let slot_addrs = self
            .relays
            .iter()
            .filter_map(|(id, relay)| {
                relay
                    .slots
                    .get(&device)
                    .map(|port| (id.clone(), format!("127.0.0.1:{port}")))
            })
            .collect();
        DeviceSyncResponse {
            device,
            peer,
            generation: self.generation,
            relays: self
                .relays
                .iter()
                .map(|(id, relay)| RelayView {
                    id: id.clone(),
                    healthy: relay.healthy(now),
                })
                .collect(),
            slot_addrs,
            assigned,
        }
    }

    fn state_view(&self, now: Instant) -> StateView {
        StateView {
            generation: self.generation,
            relays: self
                .relays
                .iter()
                .map(|(id, relay)| RelayStateView {
                    id: id.clone(),
                    healthy: relay.healthy(now),
                    slots: relay.slots.clone(),
                    observations: relay
                        .observations
                        .iter()
                        .map(|(device, addr)| (*device, addr.to_string()))
                        .collect(),
                    stats: relay.stats,
                })
                .collect(),
            devices: self
                .devices
                .iter()
                .map(|(device, state)| DeviceView {
                    device: *device,
                    public_key: crate::control::encode(&state.public_key),
                    peer: state.peer,
                })
                .collect(),
            pairs: self
                .pair_relay
                .iter()
                .map(|(key, relay_id)| PairView {
                    a: key.0,
                    b: key.1,
                    relay_id: relay_id.clone(),
                })
                .collect(),
        }
    }
}

// ------------------------------------------------------------------ process --

// The coordinator as a process: bind a TCP listener, announce the port it got,
// and answer the control-plane routes. Nothing here opens a data-path socket.
pub fn run() {
    let mut listen = "127.0.0.1:0".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--listen" {
            listen = args.next().unwrap_or(listen);
        }
    }

    let listener =
        TcpListener::bind(&listen).unwrap_or_else(|error| panic!("bind {listen}: {error}"));
    let addr = listener.local_addr().expect("local_addr");
    // The line the harness waits for: the port is ephemeral, so it is announced
    // rather than guessed.
    println!("lab-coordinator listening {addr}");
    std::io::stdout().flush().ok();

    let coordinator = Arc::new(Coordinator::new());
    crate::http::serve(listener, move |request| route(&coordinator, request));
}

fn route(coordinator: &Coordinator, request: crate::http::Request) -> crate::http::Response {
    let path = request.path.split('?').next().unwrap_or("");
    match (request.method.as_str(), path) {
        ("GET", "/healthz") => crate::http::Response::text(200, b"ok".to_vec()),
        ("GET", "/v1/state") => crate::http::Response::json(&coordinator.state()),
        ("POST", "/v1/relays/heartbeat") => {
            match serde_json::from_slice::<RelayHeartbeat>(&request.body) {
                Ok(heartbeat) => crate::http::Response::json(&coordinator.heartbeat(heartbeat)),
                Err(error) => crate::http::Response::error(400, &format!("bad heartbeat: {error}")),
            }
        }
        ("POST", _) if path.starts_with("/v1/devices/") && path.ends_with("/sync") => {
            let device = path
                .trim_start_matches("/v1/devices/")
                .trim_end_matches("/sync");
            match serde_json::from_slice::<DeviceSync>(&request.body) {
                Ok(sync) if device.parse::<u32>() == Ok(sync.device) => {
                    crate::http::Response::json(&coordinator.device_sync(sync))
                }
                Ok(sync) => crate::http::Response::error(
                    400,
                    &format!("path device {device} is not body device {}", sync.device),
                ),
                Err(error) => crate::http::Response::error(400, &format!("bad sync: {error}")),
            }
        }
        _ => crate::http::Response::error(404, "no such route"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{Observation, SlotReport};

    fn sync(device: u32, peer: u32) -> DeviceSync {
        DeviceSync {
            device,
            public_key: crate::control::encode(&[device as u8; 32]),
            peer,
        }
    }

    fn heartbeat(id: &str, slots: &[(u32, u16)], observations: &[(u32, &str)]) -> RelayHeartbeat {
        RelayHeartbeat {
            id: id.to_string(),
            slots: slots
                .iter()
                .map(|(device, port)| SlotReport {
                    device: *device,
                    port: *port,
                })
                .collect(),
            observations: observations
                .iter()
                .map(|(device, addr)| Observation {
                    device: *device,
                    addr: (*addr).to_string(),
                })
                .collect(),
            stats: RelayStats::default(),
        }
    }

    #[test]
    fn a_pair_is_homed_once_both_ends_name_each_other() {
        let coordinator = Coordinator::new();
        coordinator.heartbeat(heartbeat("relay-1", &[(1, 51001), (2, 51002)], &[]));

        let response = coordinator.device_sync(sync(1, 2));
        assert!(response.assigned.is_none(), "peer has not enrolled yet");

        coordinator.device_sync(sync(2, 1));
        let response = coordinator.device_sync(sync(1, 2));
        let assigned = response.assigned.expect("pair is homed");
        assert_eq!(assigned.relay_id, "relay-1");
        assert_eq!(assigned.slot_addr.as_deref(), Some("127.0.0.1:51001"));
        assert_eq!(assigned.peer_device, 2);
        assert!(!assigned.punch, "no observation yet");
    }

    #[test]
    fn both_observations_arm_the_punch() {
        let coordinator = Coordinator::new();
        coordinator.device_sync(sync(1, 2));
        coordinator.device_sync(sync(2, 1));
        coordinator.heartbeat(heartbeat("relay-1", &[], &[]));
        coordinator.heartbeat(heartbeat(
            "relay-1",
            &[(1, 51001), (2, 51002)],
            &[(1, "127.0.0.1:40001")],
        ));
        let response = coordinator.device_sync(sync(1, 2));
        assert!(!response.assigned.as_ref().unwrap().punch);
        coordinator.heartbeat(heartbeat(
            "relay-1",
            &[(1, 51001), (2, 51002)],
            &[(1, "127.0.0.1:40001"), (2, "127.0.0.1:40002")],
        ));
        let response = coordinator.device_sync(sync(1, 2));
        let assigned = response.assigned.unwrap();
        assert!(assigned.punch);
        assert_eq!(assigned.peer_observed.as_deref(), Some("127.0.0.1:40002"));
    }

    #[test]
    fn pairs_spread_over_the_fleet_and_survive_a_relay_loss() {
        let coordinator = Coordinator::new();
        for (device, peer) in [(1, 2), (3, 4)] {
            coordinator.device_sync(sync(device, peer));
            coordinator.device_sync(sync(peer, device));
        }
        coordinator.heartbeat(heartbeat("relay-1", &[], &[]));
        coordinator.heartbeat(heartbeat("relay-2", &[], &[]));
        let state = coordinator.state();
        assert_eq!(state.pairs.len(), 2);
        let relay_of = |a: u32| {
            state
                .pairs
                .iter()
                .find(|pair| pair.a == a)
                .map(|pair| pair.relay_id.clone())
        };
        assert_eq!(relay_of(1).as_deref(), Some("relay-1"));
        assert_eq!(relay_of(3).as_deref(), Some("relay-2"));

        // relay-1 goes silent: only its pair moves.
        let rehomed = {
            let mut inner = coordinator.inner.lock().unwrap();
            inner.relays.get_mut("relay-1").unwrap().last_seen =
                Some(Instant::now() - RELAY_TIMEOUT - Duration::from_millis(1));
            inner.reassign(Instant::now());
            inner.state_view(Instant::now())
        };
        assert_eq!(rehomed.pairs.len(), 2);
        for pair in &rehomed.pairs {
            assert_eq!(pair.relay_id, "relay-2");
        }
    }

    #[test]
    fn a_pair_is_not_rehomed_while_its_relay_answers() {
        let coordinator = Coordinator::new();
        coordinator.device_sync(sync(1, 2));
        coordinator.device_sync(sync(2, 1));
        coordinator.heartbeat(heartbeat("relay-1", &[], &[]));
        coordinator.heartbeat(heartbeat("relay-2", &[], &[]));
        let before = coordinator.state();
        coordinator.heartbeat(heartbeat("relay-1", &[], &[]));
        let after = coordinator.state();
        assert_eq!(before.pairs, after.pairs);
    }

    #[test]
    fn no_healthy_relay_means_no_assignment() {
        let coordinator = Coordinator::new();
        coordinator.device_sync(sync(1, 2));
        coordinator.device_sync(sync(2, 1));
        assert!(coordinator.device_sync(sync(1, 2)).assigned.is_none());

        coordinator.heartbeat(heartbeat("relay-1", &[], &[]));
        assert!(coordinator.device_sync(sync(1, 2)).assigned.is_some());

        {
            let mut inner = coordinator.inner.lock().unwrap();
            inner.relays.get_mut("relay-1").unwrap().last_seen =
                Some(Instant::now() - RELAY_TIMEOUT - Duration::from_millis(1));
        }
        assert!(coordinator.device_sync(sync(1, 2)).assigned.is_none());
    }

    /// Drop comment-only lines, so a comment that merely *says* "no UDP socket"
    /// cannot be mistaken for code -- and, the other way, a trailing comment
    /// stays in, because over-reporting costs a look while under-reporting
    /// costs the claim.
    fn code_lines(source: &str) -> String {
        source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The structural half of the coordinator's contract, checkable without a
    /// running process and independent of the conformance suite's `/proc`
    /// inspection: no file the coordinator's own process is built from
    /// constructs a UDP socket.
    ///
    /// The positive control matters as much as the claim. `agent.rs`, `nat.rs`
    /// and `relay.rs` are the lab's data-path stand-ins and legitimately hold
    /// UDP sockets, so they are not part of this scan -- which means the same
    /// scan has to find their sockets, or a scanner that reads nothing would
    /// pass as a clean coordinator.
    #[test]
    fn no_coordinator_source_file_constructs_a_udp_socket() {
        let control_plane: [(&str, &str); 8] = [
            ("lib.rs", include_str!("lib.rs")),
            ("coordinator.rs", include_str!("coordinator.rs")),
            ("http.rs", include_str!("http.rs")),
            ("msg.rs", include_str!("msg.rs")),
            ("hex.rs", include_str!("hex.rs")),
            ("wire.rs", include_str!("wire.rs")),
            ("proc.rs", include_str!("proc.rs")),
            (
                "bin/lab-coordinator.rs",
                include_str!("bin/lab-coordinator.rs"),
            ),
        ];
        for (name, source) in control_plane {
            // Only the production half: this very test contains the pattern it
            // searches for, and `#[cfg(test)]` marks where the code stops.
            let production = code_lines(source.split("#[cfg(test)]").next().unwrap_or(source));
            assert!(
                !production.contains("UdpSocket"),
                "{name} names a UDP socket"
            );
            assert!(
                !production.contains("udp_socket"),
                "{name} names a udp socket in lowercase"
            );
        }

        // Positive control: the same scan, over a file that does hold sockets.
        let nat = code_lines(
            include_str!("nat.rs")
                .split("#[cfg(test)]")
                .next()
                .unwrap_or(""),
        );
        assert!(
            nat.contains("UdpSocket"),
            "the scan must find the lab NAT's own UDP sockets in nat.rs, or it proves nothing"
        );
    }
}
