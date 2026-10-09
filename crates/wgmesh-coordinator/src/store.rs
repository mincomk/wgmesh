use std::collections::BTreeMap;
use std::path::Path;

use rand::Rng as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;

use wgmesh_config::coordinator as settings;
use wgmesh_proto::{
    AssignmentView, ConfigEvent, ConfigSnapshot, KeysetNetwork, KeysetPeer, NetworkView, PairEntry,
    PeerState, PeerView, RelayAssignment, RelayState, RelayView, SlotEntry, SlotView,
};

/// The channel depth a node must fall behind by before it is told it missed
/// events and should re-read the snapshot. Push is an optimisation over the
/// poll, never a replacement for it.
const EVENT_BACKLOG: usize = 64;

fn event_channel() -> broadcast::Sender<ConfigEvent> {
    broadcast::channel(EVENT_BACKLOG).0
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// SHA-256 of a join token, hex encoded. The plaintext is never stored, so a
/// stolen database yields no usable token.
pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn random_base32(len: usize) -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

pub fn new_device_id() -> String {
    format!("d_{}", random_base32(8))
}

pub fn new_relay_id() -> String {
    format!("relay_{}", random_base32(6).to_lowercase())
}

/// A fresh join token in the documented shape.
pub fn new_join_token(kind: TokenKind) -> String {
    let word = match kind {
        TokenKind::Device => "WGMESH",
        TokenKind::Relay => "WGMESH-RELAY",
    };
    format!(
        "{word}-{}-{}-{}",
        random_base32(4),
        random_base32(4),
        random_base32(4)
    )
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenKind {
    Device,
    Relay,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Network {
    pub id: u32,
    pub name: String,
    pub cidr: String,
    pub mtu: u16,
    pub first_host: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub wg_pubkey: String,
    pub api_pubkey: String,
    pub tunnel_ip: String,
    pub state: PeerState,
    #[serde(default)]
    pub advertised: Vec<String>,
    pub created_at: u64,
    pub last_seen_at: Option<u64>,
    /// relay id → UDP port this device sends to on that relay.
    pub slots: BTreeMap<String, u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Relay {
    pub id: String,
    pub name: String,
    pub api_pubkey: String,
    pub endpoint_host: String,
    pub port_range: [u16; 2],
    pub state: RelayState,
    pub region: Option<String>,
    pub last_heartbeat_at: Option<u64>,
    /// Heartbeats missing in a row. Reaching the policy's threshold re-homes
    /// every pair this relay carries.
    pub misses: u32,
    pub forwarded_packets: u64,
    pub forwarded_bytes: u64,
    pub throttled_packets: u64,
    pub dropped_packets: u64,
}

impl Relay {
    pub fn is_healthy(&self) -> bool {
        self.state == RelayState::Active
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinToken {
    pub token_hash: String,
    pub kind: TokenKind,
    pub auto_approve: bool,
    pub max_uses: u32,
    pub uses: u32,
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
    pub created_by: String,
}

impl JoinToken {
    pub fn is_usable(&self, now: u64) -> bool {
        self.revoked_at.is_none() && self.expires_at > now && self.uses < self.max_uses
    }
}

/// The coordinator's whole world: one network, its devices, its relay fabric
/// and the assignments between them.
///
/// Every mutation that a node can observe goes through `bump`, which advances
/// the generation, recomputes the etag and publishes the event — so a pushed
/// event and a polled snapshot can always be ordered against each other.
#[derive(Debug, Serialize, Deserialize)]
pub struct Store {
    pub generation: u64,
    pub etag: String,
    pub network: Network,
    pub tokens: Vec<JoinToken>,
    pub devices: BTreeMap<String, Device>,
    pub relays: BTreeMap<String, Relay>,
    /// unordered pair → the relay both ends are told to use.
    pub assignments: BTreeMap<(String, String), String>,
    pub default_auto_approve: bool,
    /// `relay id:device id` → the source address that relay last saw the
    /// device come from.
    #[serde(default)]
    pub observations: BTreeMap<String, (String, u16, u64)>,
    pub keyset_ttl_secs: u64,
    #[serde(skip, default = "event_channel")]
    events: broadcast::Sender<ConfigEvent>,
}

impl Store {
    pub fn new(settings: &settings::Settings) -> Self {
        let mut store = Self {
            generation: 1,
            etag: "cfg-1".to_owned(),
            network: Network {
                id: 1,
                name: settings.network.name.clone(),
                cidr: settings.network.cidr.clone(),
                mtu: settings.network.mtu,
                first_host: settings.network.first_host,
            },
            tokens: Vec::new(),
            devices: BTreeMap::new(),
            relays: BTreeMap::new(),
            assignments: BTreeMap::new(),
            default_auto_approve: settings.policy.default_auto_approve,
            observations: BTreeMap::new(),
            keyset_ttl_secs: settings.relay.keyset_ttl_secs,
            events: event_channel(),
        };
        store.etag = store.compute_etag();
        store
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ConfigEvent> {
        self.events.subscribe()
    }

    fn compute_etag(&self) -> String {
        format!("cfg-{}", self.generation)
    }

    fn bump(
        &mut self,
        kind: &str,
        message: String,
        peer_id: Option<String>,
        relay_id: Option<String>,
    ) {
        self.generation += 1;
        self.etag = self.compute_etag();
        let event = ConfigEvent {
            kind: kind.to_owned(),
            generation: self.generation,
            etag: self.etag.clone(),
            peer_id,
            relay_id,
            message,
        };
        // A send with no subscribers is not an error: it means nobody is
        // listening, which is exactly when the poll carries the change.
        let _ = self.events.send(event);
    }

    pub fn issue_token(
        &mut self,
        kind: TokenKind,
        auto_approve: bool,
        max_uses: u32,
        ttl_secs: u64,
        created_by: &str,
    ) -> String {
        let token = new_join_token(kind);
        self.tokens.push(JoinToken {
            token_hash: token_hash(&token),
            kind,
            auto_approve,
            max_uses,
            uses: 0,
            expires_at: now_unix() + ttl_secs,
            revoked_at: None,
            created_by: created_by.to_owned(),
        });
        token
    }

    pub fn token_for_hash(&self, hash: &str) -> Option<&JoinToken> {
        self.tokens.iter().find(|token| token.token_hash == hash)
    }

    /// Spend one use of a token. The check and the increment happen together
    /// under the store lock, so two racing joins cannot both take the last use.
    pub fn consume_token(&mut self, hash: &str, now: u64) -> Option<JoinToken> {
        let index = self
            .tokens
            .iter()
            .position(|token| token.token_hash == hash)?;
        if !self.tokens[index].is_usable(now) {
            return None;
        }
        self.tokens[index].uses += 1;
        Some(self.tokens[index].clone())
    }

    fn next_tunnel_ip(&self) -> Option<String> {
        let (base, bits) = self.network.cidr.split_once('/')?;
        let mut octets: [u8; 4] = base.parse::<std::net::Ipv4Addr>().ok()?.octets();
        let used: Vec<String> = self
            .devices
            .values()
            .map(|device| device.tunnel_ip.clone())
            .collect();
        for host in self.network.first_host..=254u8 {
            octets[3] = host;
            let candidate = format!("{}/{}", std::net::Ipv4Addr::from(octets), bits);
            if !used.iter().any(|existing| existing == &candidate) {
                return Some(candidate);
            }
        }
        None
    }

    /// Register a device. `state` is `pending` unless the token or the policy
    /// says otherwise — a leaked token then costs nothing until an operator
    /// approves.
    pub fn join(
        &mut self,
        request: &wgmesh_proto::JoinRequest,
        now: u64,
    ) -> Result<Device, JoinError> {
        let hash = token_hash(&request.token);
        let token = self.token_for_hash(&hash).ok_or(JoinError::UnknownToken)?;
        if token.kind != TokenKind::Device {
            return Err(JoinError::WrongTokenKind);
        }
        if token.expires_at <= now {
            return Err(JoinError::UnknownToken);
        }
        if token.uses >= token.max_uses {
            return Err(JoinError::UnknownToken);
        }
        let auto_approve = token.auto_approve || self.default_auto_approve;
        self.consume_token(&hash, now)
            .ok_or(JoinError::UnknownToken)?;

        if self
            .devices
            .values()
            .any(|device| device.wg_pubkey == request.wg_pubkey)
        {
            return Err(JoinError::DuplicateKey);
        }
        let tunnel_ip = self.next_tunnel_ip().ok_or(JoinError::NetworkFull)?;
        let id = new_device_id();
        let device = Device {
            id: id.clone(),
            name: request.name.clone(),
            wg_pubkey: request.wg_pubkey.clone(),
            api_pubkey: request.api_pubkey.clone(),
            tunnel_ip,
            state: if auto_approve {
                PeerState::Active
            } else {
                PeerState::Pending
            },
            advertised: request.advertised.clone(),
            created_at: now,
            last_seen_at: None,
            slots: BTreeMap::new(),
        };
        self.devices.insert(id.clone(), device.clone());
        self.assign_slots(&id);
        self.reconcile_assignments();
        self.bump(
            "approved",
            format!(
                "device {} ({}) joined as {}",
                device.name,
                device.id,
                device.state.as_str()
            ),
            Some(id),
            None,
        );
        Ok(device)
    }

    pub fn approve(&mut self, device_id: &str) -> bool {
        let Some(device) = self.devices.get_mut(device_id) else {
            return false;
        };
        if device.state != PeerState::Pending {
            return false;
        }
        device.state = PeerState::Active;
        let name = device.name.clone();
        self.reconcile_assignments();
        self.bump(
            "approved",
            format!("device {name} ({device_id}) approved"),
            Some(device_id.to_owned()),
            None,
        );
        true
    }

    /// Revoke a device. It leaves every peer list and every keyset, and the
    /// kernel drops its packets the moment the peer entry is removed.
    pub fn revoke_device(&mut self, device_id: &str) -> bool {
        let Some(device) = self.devices.get_mut(device_id) else {
            return false;
        };
        if device.state == PeerState::Revoked {
            return false;
        }
        device.state = PeerState::Revoked;
        let name = device.name.clone();
        self.assignments
            .retain(|(a, b), _| a != device_id && b != device_id);
        self.reconcile_assignments();
        self.bump(
            "revoked",
            format!("device {name} ({device_id}) revoked"),
            Some(device_id.to_owned()),
            None,
        );
        true
    }

    pub fn enroll_relay(
        &mut self,
        request: &wgmesh_proto::RelayEnrollRequest,
        now: u64,
    ) -> Result<Relay, JoinError> {
        let hash = token_hash(&request.token);
        let token = self.token_for_hash(&hash).ok_or(JoinError::UnknownToken)?;
        if token.kind != TokenKind::Relay {
            return Err(JoinError::WrongTokenKind);
        }
        self.consume_token(&hash, now)
            .ok_or(JoinError::UnknownToken)?;

        let id = new_relay_id();
        let relay = Relay {
            id: id.clone(),
            name: request.name.clone(),
            api_pubkey: request.api_pubkey.clone(),
            endpoint_host: request.endpoint_host.clone(),
            port_range: request.port_range,
            state: RelayState::Active,
            region: request.region.clone(),
            last_heartbeat_at: Some(now),
            misses: 0,
            forwarded_packets: 0,
            forwarded_bytes: 0,
            throttled_packets: 0,
            dropped_packets: 0,
        };
        self.relays.insert(id.clone(), relay.clone());
        self.assign_slots_everywhere();
        self.reconcile_assignments();
        self.bump(
            "approved",
            format!("relay {} ({id}) enrolled", relay.name),
            None,
            Some(id),
        );
        Ok(relay)
    }

    /// Give every active device a slot on this relay.
    pub fn assign_slots(&mut self, device_id: &str) {
        let relays: Vec<(String, [u16; 2])> = self
            .relays
            .values()
            .filter(|relay| relay.is_healthy())
            .map(|relay| (relay.id.clone(), relay.port_range))
            .collect();
        let taken: Vec<(String, u16)> = self
            .devices
            .iter()
            .filter(|(id, _)| id.as_str() != device_id)
            .flat_map(|(_, device)| {
                device
                    .slots
                    .iter()
                    .map(|(relay_id, port)| (relay_id.clone(), *port))
            })
            .collect();
        let Some(device) = self.devices.get_mut(device_id) else {
            return;
        };
        for (relay_id, [low, high]) in relays {
            if device.slots.contains_key(&relay_id) {
                continue;
            }
            let port = pick_port(low, high, |candidate| {
                taken.iter().any(|(taken_relay, taken_port)| {
                    taken_relay == &relay_id && *taken_port == candidate
                })
            });
            device.slots.insert(relay_id, port);
        }
    }

    pub fn assign_slots_everywhere(&mut self) {
        let ids: Vec<String> = self.devices.keys().cloned().collect();
        for id in ids {
            self.assign_slots(&id);
        }
    }

    /// Give every active pair a relay, keeping the one it already has. A
    /// reassignment is an interruption, so it only happens when the relay can
    /// no longer carry the pair.
    pub fn reconcile_assignments(&mut self) {
        let active: Vec<String> = self
            .devices
            .values()
            .filter(|device| device.state == PeerState::Active)
            .map(|device| device.id.clone())
            .collect();
        let healthy: Vec<String> = self
            .relays
            .values()
            .filter(|relay| relay.is_healthy())
            .map(|relay| relay.id.clone())
            .collect();
        self.assignments.retain(|(a, b), relay| {
            active.contains(a) && active.contains(b) && healthy.contains(relay)
        });
        for (index, a) in active.iter().enumerate() {
            for b in active.iter().skip(index + 1) {
                let key = ordered_pair(a, b);
                if self.assignments.contains_key(&key) {
                    continue;
                }
                // Prefer a relay both ends already hold a slot on, so the
                // punch can start without waiting for a new slot.
                let choice = healthy
                    .iter()
                    .find(|relay| {
                        self.devices
                            .get(a)
                            .is_some_and(|device| device.slots.contains_key(*relay))
                            && self
                                .devices
                                .get(b)
                                .is_some_and(|device| device.slots.contains_key(*relay))
                    })
                    .cloned()
                    .or_else(|| healthy.first().cloned());
                if let Some(relay) = choice {
                    self.assignments.insert(key, relay);
                }
            }
        }
    }

    pub fn relay_of_pair(&self, a: &str, b: &str) -> Option<&String> {
        self.assignments.get(&ordered_pair(a, b))
    }

    /// Move every pair off `relay_id` and onto another healthy relay.
    pub fn rehome_pairs(&mut self, relay_id: &str) -> Vec<String> {
        let candidates: Vec<String> = self
            .relays
            .values()
            .filter(|relay| relay.is_healthy() && relay.id != relay_id)
            .map(|relay| relay.id.clone())
            .collect();
        let Some(target) = candidates
            .iter()
            .find(|candidate| {
                self.assignments
                    .values()
                    .filter(|relay| *relay == *candidate)
                    .count()
                    < self
                        .assignments
                        .values()
                        .filter(|relay| *relay == relay_id)
                        .count()
            })
            .cloned()
            .or_else(|| candidates.first().cloned())
        else {
            return Vec::new();
        };
        let moved: Vec<(String, String)> = self
            .assignments
            .iter()
            .filter(|(_, relay)| *relay == relay_id)
            .map(|(pair, _)| pair.clone())
            .collect();
        for pair in &moved {
            self.assignments.insert(pair.clone(), target.clone());
        }
        if !moved.is_empty() {
            self.bump(
                "reassigned",
                format!("{} pair(s) moved from {relay_id} to {target}", moved.len()),
                None,
                Some(target),
            );
        }
        moved.into_iter().map(|(a, _)| a).collect()
    }

    /// Notice a relay that has stopped answering and re-home its pairs.
    pub fn check_relay_health(
        &mut self,
        now: u64,
        timeout_secs: u64,
        threshold: u32,
    ) -> Vec<String> {
        let stale: Vec<String> = self
            .relays
            .values()
            .filter(|relay| relay.state == RelayState::Active)
            .filter(|relay| match relay.last_heartbeat_at {
                Some(last) => now.saturating_sub(last) > timeout_secs,
                None => true,
            })
            .map(|relay| relay.id.clone())
            .collect();
        let mut rehomed = Vec::new();
        for relay_id in stale {
            if let Some(relay) = self.relays.get_mut(&relay_id) {
                relay.misses += 1;
                if relay.misses < threshold {
                    continue;
                }
                relay.state = RelayState::Retired;
            }
            rehomed.extend(self.rehome_pairs(&relay_id));
        }
        rehomed
    }

    pub fn observe(&mut self, relay_id: &str, device_id: &str, ip: &str, port: u16, seen_at: u64) {
        let Some(device) = self.devices.get_mut(device_id) else {
            return;
        };
        device.last_seen_at = Some(seen_at);
        let key = format!("{relay_id}:{device_id}");
        self.observations
            .insert(key, (ip.to_owned(), port, seen_at));
    }

    /// The endpoint a peer was last seen at through the relay the pair uses.
    /// An observation from a different relay is useless when the NAT is
    /// symmetric, so it is deliberately ignored.
    pub fn observed_endpoint(&self, pair_relay: &str, device_id: &str) -> Option<String> {
        let key = format!("{pair_relay}:{device_id}");
        self.observations
            .get(&key)
            .map(|(ip, port, _)| format!("{ip}:{port}"))
    }

    pub fn heartbeat(
        &mut self,
        relay_id: &str,
        heartbeat: &wgmesh_proto::RelayHeartbeat,
        now: u64,
    ) {
        if let Some(relay) = self.relays.get_mut(relay_id) {
            relay.last_heartbeat_at = Some(now);
            relay.misses = 0;
            relay.forwarded_packets = heartbeat.forwarded_packets;
            relay.forwarded_bytes = heartbeat.forwarded_bytes;
            relay.throttled_packets = heartbeat.throttled_packets;
            relay.dropped_packets = heartbeat.dropped_packets;
        }
    }

    pub fn set_relay_state(&mut self, relay_id: &str, state: RelayState) -> bool {
        let Some(relay) = self.relays.get_mut(relay_id) else {
            return false;
        };
        relay.state = state;
        let name = relay.name.clone();
        self.reconcile_assignments();
        self.bump(
            "relay",
            format!("relay {name} ({relay_id}) is now {state:?}"),
            None,
            Some(relay_id.to_owned()),
        );
        true
    }

    fn network_view(&self) -> NetworkView {
        NetworkView {
            name: self.network.name.clone(),
            cidr: self.network.cidr.clone(),
            mtu: self.network.mtu,
        }
    }

    fn peer_view(&self, device: &Device) -> PeerView {
        PeerView {
            device_id: device.id.clone(),
            name: device.name.clone(),
            wg_pubkey: device.wg_pubkey.clone(),
            tunnel_ip: device.tunnel_ip.clone(),
            state: device.state,
            advertised: device.advertised.clone(),
            endpoint: None,
        }
    }

    fn relay_view(&self, relay: &Relay) -> RelayView {
        RelayView {
            relay_id: relay.id.clone(),
            name: relay.name.clone(),
            endpoint_host: relay.endpoint_host.clone(),
            region: relay.region.clone(),
            state: relay.state,
        }
    }

    /// What one device needs: the peers it may reach, the slot it sends from on
    /// every relay, and which relay each of its pairs is on.
    pub fn snapshot_for(&self, device_id: &str) -> Option<ConfigSnapshot> {
        let device = self.devices.get(device_id)?;
        let mut peers = Vec::new();
        for other in self.devices.values() {
            if other.id == device_id || other.state != PeerState::Active {
                continue;
            }
            if device.state != PeerState::Active {
                continue;
            }
            let mut view = self.peer_view(other);
            if let Some(relay) = self.relay_of_pair(device_id, &other.id) {
                view.endpoint = self.observed_endpoint(relay, &other.id);
            }
            peers.push(view);
        }
        let mut assignments = Vec::new();
        for peer in &peers {
            if let Some(relay) = self.relay_of_pair(device_id, &peer.device_id) {
                assignments.push(AssignmentView {
                    peer_id: peer.device_id.clone(),
                    relay_id: relay.clone(),
                });
            }
        }
        Some(ConfigSnapshot {
            etag: self.etag.clone(),
            generation: self.generation,
            network: self.network_view(),
            device: self.peer_view(device),
            peers,
            slots: device
                .slots
                .iter()
                .map(|(relay_id, udp_port)| SlotView {
                    relay_id: relay_id.clone(),
                    udp_port: *udp_port,
                })
                .collect(),
            assignments,
            relays: self
                .relays
                .values()
                .map(|relay| self.relay_view(relay))
                .collect(),
        })
    }

    /// What one relay needs: its slots, the pairs it may carry, and the public
    /// keys that let it read a handshake's destination.
    pub fn relay_assignment(&self, relay_id: &str) -> Option<RelayAssignment> {
        let relay = self.relays.get(relay_id)?;
        let slots = self
            .devices
            .values()
            .filter_map(|device| {
                device.slots.get(relay_id).map(|port| SlotEntry {
                    device_id: device.id.clone(),
                    udp_port: *port,
                })
            })
            .collect();
        let pairs = self
            .assignments
            .iter()
            .filter(|(_, assigned)| assigned.as_str() == relay_id)
            .map(|((a, b), _)| PairEntry {
                a: a.clone(),
                b: b.clone(),
            })
            .collect();
        let keyset = vec![KeysetNetwork {
            network: self.network.name.clone(),
            peers: self
                .devices
                .values()
                .filter(|device| device.state == PeerState::Active)
                .map(|device| KeysetPeer {
                    device_id: device.id.clone(),
                    wg_pubkey: device.wg_pubkey.clone(),
                })
                .collect(),
        }];
        Some(RelayAssignment {
            relay_id: relay.id.clone(),
            slots,
            pairs,
            networks: keyset,
            keyset_ttl_secs: self.keyset_ttl_secs,
        })
    }

    /// Whether this device is allowed to be served at all.
    pub fn api_pubkey_of_device(&self, device_id: &str) -> Option<(String, PeerState)> {
        self.devices
            .get(device_id)
            .map(|device| (device.api_pubkey.clone(), device.state))
    }

    pub fn api_pubkey_of_relay(&self, relay_id: &str) -> Option<(String, RelayState)> {
        self.relays
            .get(relay_id)
            .map(|relay| (relay.api_pubkey.clone(), relay.state))
    }

    pub fn save_to(&self, path: &Path) -> std::io::Result<()> {
        let text = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path)
    }

    pub fn load_from(path: &Path, settings: &settings::Settings) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|error| {
                tracing::warn!(%error, "coordinator state is unreadable; starting empty");
                Self::new(settings)
            }),
            Err(_) => Self::new(settings),
        }
    }
}

fn ordered_pair(a: &str, b: &str) -> (String, String) {
    if a <= b {
        (a.to_owned(), b.to_owned())
    } else {
        (b.to_owned(), a.to_owned())
    }
}

fn pick_port(low: u16, high: u16, taken: impl Fn(u16) -> bool) -> u16 {
    let span = u32::from(high) - u32::from(low) + 1;
    let mut rng = rand::thread_rng();
    for _ in 0..128 {
        let candidate = low + (rng.gen_range(0..span) as u16);
        if !taken(candidate) {
            return candidate;
        }
    }
    // Fall back to the first free port rather than handing out a collision.
    (low..=high)
        .find(|candidate| !taken(*candidate))
        .unwrap_or(low)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum JoinError {
    #[error("the join token is not usable")]
    UnknownToken,
    #[error("the join token is for a different kind of member")]
    WrongTokenKind,
    #[error("a device with this WireGuard key already exists")]
    DuplicateKey,
    #[error("the network has no free tunnel address")]
    NetworkFull,
}
