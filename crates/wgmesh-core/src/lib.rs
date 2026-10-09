#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use blake2::digest::consts::U16;
use blake2::digest::{Digest, KeyInit, Mac, Update};
use blake2::{Blake2s256, Blake2sMac};

pub mod doctor;
pub mod natprobe;
pub mod rate;
pub mod route;
pub use doctor::*;
pub use natprobe::*;
pub use rate::*;
pub use route::*;

const LABEL_MAC1: &[u8] = b"mac1----";

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub const LEN: usize = 32;

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "..")
    }
}

pub type Mac1Key = [u8; 32];

pub type Mac1 = Blake2sMac<U16>;

pub fn mac1_key(responder: &PublicKey) -> Mac1Key {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, LABEL_MAC1);
    Digest::update(&mut hasher, responder.as_bytes());
    hasher.finalize().into()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageKind {
    Initiation,
    Response,
    CookieReply,
    Transport,
}

impl MessageKind {
    pub const fn size_floor(self) -> usize {
        match self {
            Self::Initiation => 148,
            Self::Response => 92,
            Self::CookieReply => 64,
            Self::Transport => 32,
        }
    }
}

pub fn classify(packet: &[u8]) -> Option<MessageKind> {
    let kind = match *packet.first()? {
        1 => MessageKind::Initiation,
        2 => MessageKind::Response,
        3 => MessageKind::CookieReply,
        4 => MessageKind::Transport,
        _ => return None,
    };
    (packet.len() >= kind.size_floor()).then_some(kind)
}

pub fn verify_mac1(packet: &[u8], key: &Mac1Key) -> bool {
    if !matches!(
        classify(packet),
        Some(MessageKind::Initiation | MessageKind::Response)
    ) {
        return false;
    }
    let Some(offset) = packet.len().checked_sub(32) else {
        return false;
    };
    let Ok(mut mac) = <Mac1 as KeyInit>::new_from_slice(key) else {
        return false;
    };
    Update::update(&mut mac, &packet[..offset]);
    mac.verify_slice(&packet[offset..offset + 16]).is_ok()
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Millis(pub u64);

impl Millis {
    pub const ZERO: Self = Self(0);

    pub const fn from_millis(ms: u64) -> Self {
        Self(ms)
    }

    pub const fn from_secs(secs: u64) -> Self {
        Self(secs * 1000)
    }

    pub const fn as_millis(self) -> u64 {
        self.0
    }

    pub fn plus(self, span: Duration) -> Self {
        Self(self.0.saturating_add(span.as_millis() as u64))
    }

    pub fn elapsed_since(self, earlier: Self) -> Duration {
        Duration::from_millis(self.0.saturating_sub(earlier.0))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct DeviceId(pub u32);

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Endpoint(SocketAddr);

impl Endpoint {
    pub const fn new(addr: SocketAddr) -> Self {
        Self(addr)
    }

    pub const fn addr(self) -> SocketAddr {
        self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct RelayId(pub u16);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CandidateKind {
    Lan,
    Ipv6,
    Observed,
    Mapping,
    Relay,
}

impl CandidateKind {
    const fn rank(self) -> u8 {
        match self {
            Self::Lan => 0,
            Self::Ipv6 => 1,
            Self::Observed => 2,
            Self::Mapping => 3,
            Self::Relay => 4,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Candidate {
    pub kind: CandidateKind,
    pub endpoint: Endpoint,
    pub observed_at: Millis,
}

pub fn rank(candidates: &[Candidate]) -> Vec<Candidate> {
    let mut ranked = candidates.to_vec();
    ranked.sort_by(|a, b| {
        a.kind
            .rank()
            .cmp(&b.kind.rank())
            .then_with(|| b.observed_at.cmp(&a.observed_at))
    });
    ranked
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    Idle { next_attempt: Millis },
    Probing { since: Millis },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Effect {
    SetPeerEndpoint(Endpoint),
    SendHandshake,
    ReportObservation(Endpoint),
}

#[derive(Clone, Debug)]
pub enum Event {
    Assignment {
        relay: Endpoint,
        at: Millis,
    },
    Observed {
        endpoint: Endpoint,
        kind: CandidateKind,
        at: Millis,
    },
    Handshake {
        via: Endpoint,
        at: Millis,
    },
    Degraded {
        at: Millis,
    },
    Tick {
        at: Millis,
    },
}

#[derive(Clone, Debug)]
pub struct TraversalConfig {
    pub punch_delay: Duration,
    pub punch_window: Duration,
    pub backoff: Vec<Duration>,
}

impl Default for TraversalConfig {
    fn default() -> Self {
        Self {
            punch_delay: Duration::from_secs(2),
            punch_window: Duration::from_secs(5),
            backoff: vec![
                Duration::from_secs(30),
                Duration::from_secs(120),
                Duration::from_secs(600),
            ],
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Path {
    Unknown,
    Relayed,
    Direct,
}

#[derive(Clone, Debug)]
pub struct Traversal {
    pub phase: Phase,
    pub attempts: u32,
    pub path: Path,
    pub relay: Option<Endpoint>,
    pub active: Option<Endpoint>,
    pub candidates: Vec<Candidate>,
}

impl Traversal {
    pub const fn new() -> Self {
        Self {
            phase: Phase::Idle {
                next_attempt: Millis::ZERO,
            },
            attempts: 0,
            path: Path::Unknown,
            relay: None,
            active: None,
            candidates: Vec::new(),
        }
    }

    fn backoff_for(&self, cfg: &TraversalConfig) -> Duration {
        let index = (self.attempts as usize).saturating_sub(1);
        *cfg.backoff.get(index).unwrap_or(&Duration::from_secs(600))
    }

    fn pin(&mut self, endpoint: Endpoint) -> Effect {
        self.active = Some(endpoint);
        Effect::SetPeerEndpoint(endpoint)
    }
}

impl Default for Traversal {
    fn default() -> Self {
        Self::new()
    }
}

pub fn step(state: &mut Traversal, event: Event, cfg: &TraversalConfig) -> Vec<Effect> {
    match event {
        Event::Assignment { relay, at } => {
            state.relay = Some(relay);
            state
                .candidates
                .retain(|c| matches!(c.kind, CandidateKind::Lan | CandidateKind::Ipv6));
            state.phase = Phase::Idle {
                next_attempt: at.plus(cfg.punch_delay),
            };
            state.path = Path::Relayed;
            vec![state.pin(relay), Effect::SendHandshake]
        }
        Event::Observed { endpoint, kind, at } => {
            state.candidates.retain(|c| c.endpoint != endpoint);
            state.candidates.push(Candidate {
                kind,
                endpoint,
                observed_at: at,
            });
            vec![]
        }
        Event::Handshake { via, at } => {
            state.path = match state.relay {
                Some(relay) if via == relay => Path::Relayed,
                _ => Path::Direct,
            };
            state.attempts = 0;
            state.active = Some(via);
            state.phase = Phase::Idle { next_attempt: at };
            vec![]
        }
        Event::Degraded { at } => {
            state.attempts = state.attempts.saturating_add(1);
            state.path = Path::Relayed;
            state.phase = Phase::Idle {
                next_attempt: at.plus(state.backoff_for(cfg)),
            };
            match state.relay {
                Some(relay) => vec![state.pin(relay), Effect::SendHandshake],
                None => vec![],
            }
        }
        Event::Tick { at } => match state.phase {
            Phase::Probing { since } => {
                if at.elapsed_since(since) < cfg.punch_window {
                    return vec![];
                }
                state.attempts = state.attempts.saturating_add(1);
                state.phase = Phase::Idle {
                    next_attempt: at.plus(state.backoff_for(cfg)),
                };
                state.path = Path::Relayed;
                match state.relay {
                    Some(relay) => vec![state.pin(relay), Effect::SendHandshake],
                    None => vec![],
                }
            }
            Phase::Idle { next_attempt } => {
                if at < next_attempt || state.path == Path::Direct {
                    return vec![];
                }
                let Some(best) = rank(&state.candidates)
                    .into_iter()
                    .find(|candidate| candidate.kind != CandidateKind::Relay)
                else {
                    state.phase = Phase::Idle {
                        next_attempt: at.plus(state.backoff_for(cfg)),
                    };
                    return vec![];
                };
                state.phase = Phase::Probing { since: at };
                state.path = Path::Unknown;
                vec![state.pin(best.endpoint), Effect::SendHandshake]
            }
        },
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Allowed {
    V4([u8; 4], u8),
    V6([u8; 16], u8),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PeerSpec {
    pub id: DeviceId,
    pub key: PublicKey,
    pub allowed: Vec<Allowed>,
    pub endpoint: Option<Endpoint>,
    pub keepalive: Option<Duration>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Change {
    Add(PeerSpec),
    Update(PeerSpec),
    Remove(DeviceId),
}

pub fn diff(desired: &[PeerSpec], current: &BTreeMap<DeviceId, PeerSpec>) -> Vec<Change> {
    let mut changes = Vec::new();
    for spec in desired {
        match current.get(&spec.id) {
            None => changes.push(Change::Add(spec.clone())),
            Some(existing) if existing != spec => changes.push(Change::Update(spec.clone())),
            Some(_) => {}
        }
    }
    let wanted: BTreeSet<DeviceId> = desired.iter().map(|peer| peer.id).collect();
    for id in current.keys() {
        if !wanted.contains(id) {
            changes.push(Change::Remove(*id));
        }
    }
    changes
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DropReason {
    UnknownIngress,
    UnknownDestination,
    NotAssigned,
    SourceMoved,
    Malformed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Route {
    Forward {
        from: DeviceId,
        to: DeviceId,
        destination: Endpoint,
    },
    Drop(DropReason),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SlotEntry {
    pub port: u16,
    pub pinned_src: Option<Endpoint>,
    pub last_seen: Millis,
}

pub const SOURCE_PIN_WINDOW: Duration = Duration::from_secs(120);

#[derive(Clone, Debug, Default)]
pub struct RelayTable {
    slots: BTreeMap<DeviceId, SlotEntry>,
    assigned: BTreeSet<(DeviceId, DeviceId)>,
}

impl RelayTable {
    pub fn assign_slot(&mut self, device: DeviceId, port: u16) {
        let entry = self.slots.entry(device).or_insert(SlotEntry {
            port,
            pinned_src: None,
            last_seen: Millis::ZERO,
        });
        entry.port = port;
    }

    pub fn assign_pair(&mut self, a: DeviceId, b: DeviceId) {
        self.assigned.insert((a, b));
        self.assigned.insert((b, a));
    }

    pub fn slot_of(&self, device: DeviceId) -> Option<u16> {
        self.slots.get(&device).map(|entry| entry.port)
    }

    pub fn ingress(&self, port: u16) -> Option<DeviceId> {
        self.slots
            .iter()
            .find(|(_, entry)| entry.port == port)
            .map(|(device, _)| *device)
    }

    pub fn route(
        &mut self,
        ingress_port: u16,
        source: Endpoint,
        destination: DeviceId,
        packet: &[u8],
        at: Millis,
    ) -> Route {
        if classify(packet).is_none() {
            return Route::Drop(DropReason::Malformed);
        }
        let Some(from) = self.ingress(ingress_port) else {
            return Route::Drop(DropReason::UnknownIngress);
        };
        let Some(entry) = self.slots.get_mut(&from) else {
            return Route::Drop(DropReason::UnknownIngress);
        };
        let stale = at.elapsed_since(entry.last_seen) > SOURCE_PIN_WINDOW;
        if let Some(known) = entry.pinned_src
            && known != source
            && !stale
        {
            return Route::Drop(DropReason::SourceMoved);
        }
        entry.pinned_src = Some(source);
        entry.last_seen = at;

        if !self.assigned.contains(&(from, destination)) {
            return Route::Drop(DropReason::NotAssigned);
        }
        let Some(destination_entry) = self.slots.get(&destination) else {
            return Route::Drop(DropReason::UnknownDestination);
        };
        let Some(destination_endpoint) = destination_entry.pinned_src else {
            return Route::Drop(DropReason::UnknownDestination);
        };
        Route::Forward {
            from,
            to: destination,
            destination: destination_endpoint,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ep(port: u16) -> Endpoint {
        Endpoint::new(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port,
        ))
    }

    fn public_key(seed: u8) -> PublicKey {
        PublicKey::from_bytes([seed; 32])
    }

    fn handshake_bytes(len: usize, key: &Mac1Key) -> Vec<u8> {
        let mut packet = vec![0u8; len];
        packet[0] = 1;
        let offset = len - 32;
        let mut mac = <Mac1 as KeyInit>::new_from_slice(key).unwrap();
        Update::update(&mut mac, &packet[..offset]);
        packet[offset..offset + 16].copy_from_slice(&mac.finalize().into_bytes());
        packet
    }

    fn assigned(at: Millis) -> (Traversal, TraversalConfig, Endpoint, Endpoint) {
        let cfg = TraversalConfig::default();
        let mut state = Traversal::new();
        let relay = ep(9000);
        let peer = ep(9100);
        step(&mut state, Event::Assignment { relay, at }, &cfg);
        (state, cfg, relay, peer)
    }

    fn observe(state: &mut Traversal, cfg: &TraversalConfig, peer: Endpoint, at: Millis) {
        step(
            state,
            Event::Observed {
                endpoint: peer,
                kind: CandidateKind::Observed,
                at,
            },
            cfg,
        );
    }

    #[test]
    fn mac1_pins_the_intended_recipient() {
        let key = mac1_key(&public_key(7));
        let packet = handshake_bytes(148, &key);
        assert!(verify_mac1(&packet, &key));
        assert!(!verify_mac1(&packet, &mac1_key(&public_key(8))));
    }

    #[test]
    fn mac1_rejects_wrong_shape() {
        let key = mac1_key(&public_key(1));
        assert!(!verify_mac1(&[4u8; 32], &key));
        assert!(!verify_mac1(&[1u8; 64], &key));
        assert!(!verify_mac1(&[], &key));
        assert!(!verify_mac1(&[9u8; 148], &key));
    }

    #[test]
    fn candidate_ranking_prefers_lan_then_freshest() {
        let ranked = rank(&[
            Candidate {
                kind: CandidateKind::Relay,
                endpoint: ep(1),
                observed_at: Millis::from_secs(9),
            },
            Candidate {
                kind: CandidateKind::Lan,
                endpoint: ep(2),
                observed_at: Millis::from_secs(1),
            },
            Candidate {
                kind: CandidateKind::Observed,
                endpoint: ep(3),
                observed_at: Millis::from_secs(5),
            },
            Candidate {
                kind: CandidateKind::Observed,
                endpoint: ep(4),
                observed_at: Millis::from_secs(7),
            },
        ]);
        assert_eq!(ranked[0].endpoint, ep(2));
        assert_eq!(ranked[1].endpoint, ep(4));
        assert_eq!(ranked[2].endpoint, ep(3));
        assert_eq!(ranked[3].endpoint, ep(1));
    }

    #[test]
    fn assignment_arms_the_relay_path() {
        let (state, _cfg, relay, _peer) = assigned(Millis::ZERO);
        assert_eq!(state.path, Path::Relayed);
        assert_eq!(state.active, Some(relay));
        assert_eq!(
            state.phase,
            Phase::Idle {
                next_attempt: Millis::from_secs(2)
            }
        );
    }

    #[test]
    fn punch_starts_after_the_delay_and_holds_direct() {
        let (mut state, cfg, _relay, peer) = assigned(Millis::ZERO);
        observe(&mut state, &cfg, peer, Millis::from_secs(1));
        assert!(
            step(
                &mut state,
                Event::Tick {
                    at: Millis::from_secs(1)
                },
                &cfg
            )
            .is_empty()
        );

        let start = step(
            &mut state,
            Event::Tick {
                at: Millis::from_secs(2),
            },
            &cfg,
        );
        assert_eq!(
            start,
            vec![Effect::SetPeerEndpoint(peer), Effect::SendHandshake]
        );
        assert_eq!(
            state.phase,
            Phase::Probing {
                since: Millis::from_secs(2)
            }
        );
        assert_eq!(state.path, Path::Unknown);

        step(
            &mut state,
            Event::Handshake {
                via: peer,
                at: Millis::from_secs(3),
            },
            &cfg,
        );
        assert_eq!(state.path, Path::Direct);
        assert_eq!(state.attempts, 0);
        assert_eq!(state.active, Some(peer));
        assert!(
            step(
                &mut state,
                Event::Tick {
                    at: Millis::from_secs(600)
                },
                &cfg
            )
            .is_empty()
        );
    }

    #[test]
    fn failed_punch_falls_back_then_retries_with_backoff() {
        let (mut state, cfg, relay, peer) = assigned(Millis::ZERO);
        observe(&mut state, &cfg, peer, Millis::from_secs(1));
        step(
            &mut state,
            Event::Tick {
                at: Millis::from_secs(2),
            },
            &cfg,
        );
        assert_eq!(
            state.phase,
            Phase::Probing {
                since: Millis::from_secs(2)
            }
        );

        let fallback = step(
            &mut state,
            Event::Tick {
                at: Millis::from_secs(8),
            },
            &cfg,
        );
        assert_eq!(
            fallback,
            vec![Effect::SetPeerEndpoint(relay), Effect::SendHandshake]
        );
        assert_eq!(state.path, Path::Relayed);
        assert_eq!(state.attempts, 1);
        assert_eq!(
            state.phase,
            Phase::Idle {
                next_attempt: Millis::from_secs(38)
            }
        );

        assert!(
            step(
                &mut state,
                Event::Tick {
                    at: Millis::from_secs(20)
                },
                &cfg
            )
            .is_empty()
        );
        let retry = step(
            &mut state,
            Event::Tick {
                at: Millis::from_secs(40),
            },
            &cfg,
        );
        assert_eq!(
            retry,
            vec![Effect::SetPeerEndpoint(peer), Effect::SendHandshake]
        );
        assert_eq!(
            state.phase,
            Phase::Probing {
                since: Millis::from_secs(40)
            }
        );

        step(
            &mut state,
            Event::Tick {
                at: Millis::from_secs(60),
            },
            &cfg,
        );
        assert_eq!(state.attempts, 2);
        assert_eq!(
            state.phase,
            Phase::Idle {
                next_attempt: Millis::from_secs(180)
            }
        );
    }

    #[test]
    fn reassignment_drops_stale_observations_and_arms_the_new_relay() {
        let (mut state, cfg, _relay, peer) = assigned(Millis::ZERO);
        observe(&mut state, &cfg, peer, Millis::from_secs(1));
        assert_eq!(state.candidates.len(), 1);

        let effects = step(
            &mut state,
            Event::Assignment {
                relay: ep(9001),
                at: Millis::from_secs(10),
            },
            &cfg,
        );
        assert_eq!(
            effects,
            vec![Effect::SetPeerEndpoint(ep(9001)), Effect::SendHandshake]
        );
        assert_eq!(state.path, Path::Relayed);
        assert!(state.candidates.is_empty());
        assert_eq!(
            state.phase,
            Phase::Idle {
                next_attempt: Millis::from_secs(12)
            }
        );
    }

    #[test]
    fn degraded_direct_path_reverts_to_the_relay_and_backs_off() {
        let (mut state, cfg, relay, peer) = assigned(Millis::ZERO);
        observe(&mut state, &cfg, peer, Millis::from_secs(1));
        step(
            &mut state,
            Event::Tick {
                at: Millis::from_secs(2),
            },
            &cfg,
        );
        step(
            &mut state,
            Event::Handshake {
                via: peer,
                at: Millis::from_secs(3),
            },
            &cfg,
        );
        assert_eq!(state.path, Path::Direct);

        let revert = step(
            &mut state,
            Event::Degraded {
                at: Millis::from_secs(300),
            },
            &cfg,
        );
        assert_eq!(
            revert,
            vec![Effect::SetPeerEndpoint(relay), Effect::SendHandshake]
        );
        assert_eq!(state.path, Path::Relayed);
        assert_eq!(state.attempts, 1);
        assert_eq!(
            state.phase,
            Phase::Idle {
                next_attempt: Millis::from_secs(330)
            }
        );
    }

    #[test]
    fn no_candidates_keeps_the_relay_path() {
        let (mut state, cfg, _relay, _peer) = assigned(Millis::ZERO);
        let effects = step(
            &mut state,
            Event::Tick {
                at: Millis::from_secs(5),
            },
            &cfg,
        );
        assert!(effects.is_empty());
        assert_eq!(state.path, Path::Relayed);
        assert_eq!(state.attempts, 0);
        assert_eq!(
            state.phase,
            Phase::Idle {
                next_attempt: Millis::from_secs(35)
            }
        );
    }

    #[test]
    fn diff_adds_updates_and_removes() {
        let spec = |id: u32, port: u16| PeerSpec {
            id: DeviceId(id),
            key: public_key(id as u8),
            allowed: vec![Allowed::V4([10, 77, 0, id as u8], 32)],
            endpoint: Some(ep(port)),
            keepalive: Some(Duration::from_secs(25)),
        };
        let mut current = BTreeMap::new();
        current.insert(DeviceId(1), spec(1, 9100));
        current.insert(DeviceId(2), spec(2, 9101));

        let changes = diff(&[spec(1, 9100), spec(3, 9102)], &current);
        assert_eq!(
            changes,
            vec![Change::Add(spec(3, 9102)), Change::Remove(DeviceId(2))]
        );

        let changes = diff(&[spec(1, 9555)], &current);
        assert_eq!(
            changes,
            vec![Change::Update(spec(1, 9555)), Change::Remove(DeviceId(2))]
        );
    }

    #[test]
    fn relay_forwards_only_assigned_pairs_from_known_slots() {
        let mut table = RelayTable::default();
        table.assign_slot(DeviceId(1), 51901);
        table.assign_slot(DeviceId(2), 51902);
        table.assign_pair(DeviceId(1), DeviceId(2));

        let packet = vec![4u8; 64];
        assert_eq!(
            table.route(51901, ep(40001), DeviceId(2), &packet, Millis::from_secs(1)),
            Route::Drop(DropReason::UnknownDestination)
        );
        assert!(matches!(
            table.route(51902, ep(40002), DeviceId(1), &packet, Millis::from_secs(1)),
            Route::Forward { .. }
        ));
        assert_eq!(
            table.route(51901, ep(40001), DeviceId(2), &packet, Millis::from_secs(2)),
            Route::Forward {
                from: DeviceId(1),
                to: DeviceId(2),
                destination: ep(40002)
            }
        );
        assert_eq!(
            table.route(51999, ep(40001), DeviceId(2), &packet, Millis::from_secs(2)),
            Route::Drop(DropReason::UnknownIngress)
        );
        assert_eq!(
            table.route(
                51901,
                ep(40001),
                DeviceId(2),
                &[9u8; 16],
                Millis::from_secs(2)
            ),
            Route::Drop(DropReason::Malformed)
        );
    }

    #[test]
    fn relay_pins_the_source_address_until_it_goes_stale() {
        let mut table = RelayTable::default();
        table.assign_slot(DeviceId(1), 51901);
        table.assign_slot(DeviceId(2), 51902);
        table.assign_pair(DeviceId(1), DeviceId(2));
        let packet = vec![4u8; 64];
        table.route(51902, ep(40002), DeviceId(1), &packet, Millis::from_secs(1));
        assert!(matches!(
            table.route(51901, ep(40001), DeviceId(2), &packet, Millis::from_secs(2)),
            Route::Forward { .. }
        ));
        assert_eq!(
            table.route(51901, ep(40099), DeviceId(2), &packet, Millis::from_secs(3)),
            Route::Drop(DropReason::SourceMoved)
        );
        assert!(matches!(
            table.route(
                51901,
                ep(40099),
                DeviceId(2),
                &packet,
                Millis::from_secs(200)
            ),
            Route::Forward { .. }
        ));
    }

    #[test]
    fn unassigned_pair_is_dropped() {
        let mut table = RelayTable::default();
        table.assign_slot(DeviceId(1), 51901);
        table.assign_slot(DeviceId(2), 51902);
        table.assign_slot(DeviceId(3), 51903);
        table.assign_pair(DeviceId(1), DeviceId(2));
        table.route(
            51902,
            ep(40002),
            DeviceId(1),
            &[4u8; 64],
            Millis::from_secs(1),
        );
        table.route(
            51903,
            ep(40003),
            DeviceId(1),
            &[4u8; 64],
            Millis::from_secs(1),
        );
        assert_eq!(
            table.route(
                51901,
                ep(40001),
                DeviceId(3),
                &[4u8; 64],
                Millis::from_secs(2)
            ),
            Route::Drop(DropReason::NotAssigned)
        );
    }

    #[test]
    fn relay_rejects_packets_that_are_not_wireguard_shaped() {
        let mut table = RelayTable::default();
        table.assign_slot(DeviceId(1), 51901);
        table.assign_slot(DeviceId(2), 51902);
        table.assign_pair(DeviceId(1), DeviceId(2));
        table.route(
            51902,
            ep(40002),
            DeviceId(1),
            &[4u8; 64],
            Millis::from_secs(1),
        );
        assert_eq!(
            table.route(
                51901,
                ep(40001),
                DeviceId(2),
                &[0u8; 64],
                Millis::from_secs(2)
            ),
            Route::Drop(DropReason::Malformed)
        );
    }
}
