// The stand-in WireGuard device.
//
// It implements exactly one property of `wg(8)` -- roaming on authenticated
// packets -- plus enough framing to be routed by a relay:
//
// * every datagram it sends is `[dst port][ (2-byte device tag when relayed) ][wg packet]`
//   and goes to its NAT's internal port, so it never sees a public address of
//   its own;
// * every datagram it receives is `[source port][wg packet]`, the source port
//   being the *public* port the peer's datagram came from;
// * a handshake packet moves the peer's endpoint to that source port, but only
//   after `mac1` verifies against its own key -- "correctly authenticated
//   packets from the peer";
// * transport packets are accepted only inside a live session (no `mac1` is
//   carried on the wire for them, as in WireGuard).
//
// The traversal decision is *not* made here. It is `wgmesh_core::step` that
// decides when to point at the relay, when to punch, when to give up and what
// to back off to; this type converts its effects into packets and its events
// into calls.

use std::collections::BTreeSet;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::control::{DeviceSync, DeviceSyncResponse, http};
use wgmesh_core::{
    CandidateKind, Effect, Endpoint, Event, MessageKind, Millis, Path, Phase, PublicKey, Traversal,
    TraversalConfig, classify, mac1_key, step, verify_mac1,
};

use crate::wire::{build, loopback};

/// Persistent keepalive. WireGuard's is 25s; the lab runs in compressed time.
pub const KEEPALIVE: Duration = Duration::from_millis(200);
/// A session with no authenticated packet for this long is re-handshaken.
pub const REKEY: Duration = Duration::from_millis(2000);
/// A peer with no authenticated packet for this long reads as down.
pub const UP_WINDOW: Duration = Duration::from_millis(1500);
/// ... and the agent reports the path degraded after this.
pub const DOWN_AFTER: Duration = Duration::from_millis(2000);
pub const TICK_INTERVAL: Duration = Duration::from_millis(50);
const SYNC_EVERY_TICKS: u64 = 4;
const KEEPALIVE_EVERY_TICKS: u64 = 5;

static NONCE: AtomicU64 = AtomicU64::new(1);

pub struct AgentConfig {
    pub id: u32,
    pub peer_id: u32,
    pub public_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub coordinator: String,
    /// The port of this agent's NAT on its internal side; everything the agent
    /// sends goes there.
    pub nat_port: u16,
    pub traversal: TraversalConfig,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub id: u32,
    pub path: Path,
    pub attempts: u32,
    /// When the current probe started, in agent milliseconds.
    pub probing_since_ms: Option<u64>,
    /// When the next probe is due, in agent milliseconds.
    pub next_attempt_ms: Option<u64>,
    /// When this agent's *first* probe began, on the agent's own clock.
    ///
    /// The transitions are recorded where they happen, in the state machine's
    /// tick, rather than sampled by the harness: a descheduled test thread must
    /// not be able to make a punch window invisible.
    pub first_probe_ms: Option<u64>,
    /// When a probe gave up and the agent fell back to the relay.
    pub fallback_ms: Option<u64>,
    /// The path this agent reported the moment it first had one -- recorded by
    /// the agent, so "both ends start relayed" is a fact about the state
    /// machine rather than about when the harness happened to look.
    pub initial_path: Option<Path>,
    pub now_ms: u64,
    /// The port this agent currently sends to: the peer's public address on a
    /// direct path, this agent's own relay slot on a relayed one.
    pub endpoint: u16,
    pub via_relay: bool,
    pub up: bool,
    pub handshakes_in: u32,
    pub handshakes_out: u32,
    pub endpoint_changes: u32,
    pub assigned_relay: Option<String>,
    pub relay_slot: Option<u16>,
    pub relays: Vec<(String, bool)>,
    pub generation: u64,
    pub assignments: u32,
}

impl Snapshot {
    /// What the state machine will wait before probing again. `None` when
    /// nothing is pending -- a direct path holds, or the next attempt is due.
    pub fn pending_backoff(&self) -> Option<Duration> {
        self.next_attempt_ms
            .map(|next| next.saturating_sub(self.now_ms))
            .filter(|remaining| *remaining > 0)
            .map(Duration::from_millis)
    }
}

struct Peer {
    endpoint: u16,
    via_relay: bool,
    last_handshake: Option<Instant>,
    handshakes_in: u32,
    handshakes_out: u32,
    endpoint_changes: u32,
}

impl Peer {
    fn new() -> Self {
        Self {
            endpoint: 0,
            via_relay: true,
            last_handshake: None,
            handshakes_in: 0,
            handshakes_out: 0,
            endpoint_changes: 0,
        }
    }

    fn up(&self) -> bool {
        self.last_handshake
            .map(|at| at.elapsed() <= UP_WINDOW)
            .unwrap_or(false)
    }
}

impl Inner {
    /// Record the punch's own timeline -- when this generation's first probe
    /// began and when a probe gave up -- from the state machine's state.
    ///
    /// It is called wherever the machine is stepped, not only from the tick: a
    /// probe can end because a relayed handshake arrived mid-window, and a
    /// marker that watched ticks alone would miss exactly that case.
    fn note_punch(&mut self, at_ms: u64) {
        let probing = matches!(self.traversal.phase, Phase::Probing { .. });
        if self.first_probe_ms.is_none() && probing {
            self.first_probe_ms = Some(at_ms);
        }
        if self.fallback_ms.is_none()
            && self.last_probing
            && !probing
            && self.traversal.attempts > self.last_attempts
        {
            self.fallback_ms = Some(at_ms);
        }
        self.last_probing = probing;
        self.last_attempts = self.traversal.attempts;
    }
}

struct Inner {
    traversal: Traversal,
    peer: Peer,
    /// Every port this agent is reachable on through a relay: if a datagram
    /// arrives from one of them, it came over a relay, not directly.
    slot_ports: BTreeSet<u16>,
    assigned_relay: Option<String>,
    relay_slot: Option<u16>,
    observed_fed: bool,
    down_fired: bool,
    /// The first probe this generation started, and the moment a probe gave up.
    /// Reset with the generation, so a re-homed pair measures its own punch.
    first_probe_ms: Option<u64>,
    fallback_ms: Option<u64>,
    initial_path: Option<Path>,
    /// What the last look at the state machine saw, so the next look can tell
    /// what changed. A probe can end on an arriving handshake as well as on a
    /// tick, so the markers above are taken wherever the machine is stepped.
    last_probing: bool,
    last_attempts: u32,
    /// A freshly re-pointed peer gets this long to prove itself before a stale
    /// session counts as degraded. A deliberate probe window, followed by the
    /// fallback that re-points at the relay, is not a degradation -- and
    /// counting it as one would double-count the very failure the state machine
    /// already recorded as a failed attempt.
    grace_until: Option<Instant>,
    last_send: Option<Instant>,
    relays: Vec<(String, bool)>,
    generation: u64,
    /// How many relay assignments this agent has acted on. One per homing, so a
    /// pair that was cut and re-homed has two.
    assignments: u32,
}

pub struct Agent {
    pub id: u32,
    pub peer_id: u32,
    public_key: PublicKey,
    peer_key: PublicKey,
    coordinator: String,
    nat_port: u16,
    cfg: TraversalConfig,
    socket: Arc<UdpSocket>,
    inner: Arc<Mutex<Inner>>,
    running: Arc<AtomicBool>,
    started: Instant,
}

impl Agent {
    pub fn start(config: AgentConfig) -> Arc<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("agent: bind");
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("agent: read timeout");
        let agent = Arc::new(Self {
            id: config.id,
            peer_id: config.peer_id,
            public_key: PublicKey::from_bytes(config.public_key),
            peer_key: PublicKey::from_bytes(config.peer_public_key),
            coordinator: config.coordinator,
            nat_port: config.nat_port,
            cfg: config.traversal,
            socket: Arc::new(socket),
            inner: Arc::new(Mutex::new(Inner {
                traversal: Traversal::new(),
                peer: Peer::new(),
                slot_ports: BTreeSet::new(),
                assigned_relay: None,
                relay_slot: None,
                observed_fed: false,
                down_fired: false,
                first_probe_ms: None,
                fallback_ms: None,
                initial_path: None,
                last_probing: false,
                last_attempts: 0,
                grace_until: None,
                last_send: None,
                relays: Vec::new(),
                generation: 0,
                assignments: 0,
            })),
            running: Arc::new(AtomicBool::new(true)),
            started: Instant::now(),
        });
        {
            let agent = Arc::clone(&agent);
            thread::spawn(move || agent.receive_loop());
        }
        {
            let agent = Arc::clone(&agent);
            thread::spawn(move || agent.tick_loop());
        }
        agent
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn millis(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    pub fn up(&self) -> bool {
        self.inner.lock().unwrap().peer.up()
    }

    pub fn path(&self) -> Path {
        self.inner.lock().unwrap().traversal.path
    }

    /// The path this agent first reported, as the agent itself recorded it.
    pub fn initial_path(&self) -> Option<Path> {
        self.inner.lock().unwrap().initial_path
    }

    pub fn attempts(&self) -> u32 {
        self.inner.lock().unwrap().traversal.attempts
    }

    pub fn snapshot(&self) -> Snapshot {
        let inner = self.inner.lock().unwrap();
        let (probing_since_ms, next_attempt_ms) = match inner.traversal.phase {
            Phase::Probing { since } => (Some(since.as_millis()), None),
            Phase::Idle { next_attempt } => (None, Some(next_attempt.as_millis())),
        };
        Snapshot {
            id: self.id,
            path: inner.traversal.path,
            attempts: inner.traversal.attempts,
            probing_since_ms,
            next_attempt_ms,
            first_probe_ms: inner.first_probe_ms,
            fallback_ms: inner.fallback_ms,
            initial_path: inner.initial_path,
            now_ms: self.millis(),
            endpoint: inner.peer.endpoint,
            via_relay: inner.peer.via_relay,
            up: inner.peer.up(),
            handshakes_in: inner.peer.handshakes_in,
            handshakes_out: inner.peer.handshakes_out,
            endpoint_changes: inner.peer.endpoint_changes,
            assigned_relay: inner.assigned_relay.clone(),
            relay_slot: inner.relay_slot,
            relays: inner.relays.clone(),
            generation: inner.generation,
            assignments: inner.assignments,
        }
    }

    // ---------------------------------------------------------------- loops --

    fn receive_loop(self: Arc<Self>) {
        let mut buffer = vec![0u8; 2048];
        while self.running.load(Ordering::Relaxed) {
            let (len, _) = match self.socket.recv_from(&mut buffer) {
                Ok(value) => value,
                Err(error) => match error.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => continue,
                    _ => return,
                },
            };
            if len < 2 + 32 {
                continue;
            }
            let from = u16::from_be_bytes([buffer[0], buffer[1]]);
            self.received(&buffer[2..len], from);
        }
    }

    fn tick_loop(self: Arc<Self>) {
        let mut ticks: u64 = 0;
        while self.running.load(Ordering::Relaxed) {
            thread::sleep(TICK_INTERVAL);
            ticks += 1;
            if ticks % SYNC_EVERY_TICKS == 0 {
                self.sync();
            }
            self.tick();
            if ticks % KEEPALIVE_EVERY_TICKS == 0 {
                self.keepalive();
            }
        }
    }

    /// An authenticated datagram arrived. This is where `wg(8)`'s roaming
    /// happens, and where the state machine is told a path is alive.
    fn received(self: &Arc<Self>, packet: &[u8], from: u16) {
        let Some(kind) = classify(packet) else {
            return;
        };
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();

        match kind {
            MessageKind::Initiation | MessageKind::Response => {
                if !verify_mac1(packet, &mac1_key(&self.public_key)) {
                    return;
                }
            }
            MessageKind::CookieReply => return,
            MessageKind::Transport => {
                // No mac1 on the wire for these (as in WireGuard): they count
                // only inside a session this device already established.
                let live = inner
                    .peer
                    .last_handshake
                    .map(|at| now.duration_since(at) <= REKEY)
                    .unwrap_or(false);
                if !live {
                    return;
                }
            }
        }

        match kind {
            MessageKind::Initiation => inner.peer.handshakes_in += 1,
            MessageKind::Response => inner.peer.handshakes_in += 1,
            _ => {}
        }

        let via_relay = inner.slot_ports.contains(&from);
        if inner.peer.endpoint != from {
            inner.peer.endpoint_changes += 1;
        }
        inner.peer.endpoint = from;
        inner.peer.via_relay = via_relay;
        inner.peer.last_handshake = Some(now);
        inner.down_fired = false;
        inner.grace_until = None;

        let at = Millis::from_millis(self.millis());
        let effects = step(
            &mut inner.traversal,
            Event::Handshake {
                via: Endpoint::new(loopback(from)),
                at,
            },
            &self.cfg,
        );
        self.apply(&mut inner, effects);
        inner.note_punch(self.millis());
        if inner.initial_path.is_none() {
            inner.initial_path = Some(inner.traversal.path);
        }

        if matches!(kind, MessageKind::Initiation) {
            self.send(&mut inner, MessageKind::Response, from, via_relay);
        }
    }

    /// Drive the state machine's clock: probe when it says so, and report a path
    /// that was carrying traffic and has gone quiet.
    fn tick(self: &Arc<Self>) {
        let at = Millis::from_millis(self.millis());
        let at_ms = at.as_millis();
        let mut inner = self.inner.lock().unwrap();
        if inner.assigned_relay.is_none() {
            return;
        }
        let effects = step(&mut inner.traversal, Event::Tick { at }, &self.cfg);
        self.apply(&mut inner, effects);
        inner.note_punch(at_ms);

        let idle = matches!(inner.traversal.phase, Phase::Idle { .. });
        let known_path = inner.traversal.path != Path::Unknown;
        // Only a *direct* path can degrade: a quiet relay is the fallback, not a
        // failure, and calling it one before the first punch would postpone the
        // punch by a whole backoff.
        let direct = !inner.peer.via_relay;
        let stale = inner
            .peer
            .last_handshake
            .map(|seen| seen.elapsed() > DOWN_AFTER)
            .unwrap_or(false);
        let settled = inner
            .grace_until
            .map(|until| Instant::now() >= until)
            .unwrap_or(true);
        if idle && known_path && direct && stale && settled && !inner.down_fired {
            inner.down_fired = true;
            let effects = step(&mut inner.traversal, Event::Degraded { at }, &self.cfg);
            self.apply(&mut inner, effects);
            inner.note_punch(at.as_millis());
        }
    }

    fn keepalive(self: &Arc<Self>) {
        let mut inner = self.inner.lock().unwrap();
        if inner.assigned_relay.is_none() {
            return;
        }
        let due = inner
            .last_send
            .map(|at| at.elapsed() >= KEEPALIVE)
            .unwrap_or(true);
        if !due {
            return;
        }
        let fresh = inner
            .peer
            .last_handshake
            .map(|at| at.elapsed() <= REKEY)
            .unwrap_or(false);
        let kind = if fresh {
            MessageKind::Transport
        } else {
            MessageKind::Initiation
        };
        let (destination, via_relay) = (inner.peer.endpoint, inner.peer.via_relay);
        self.send(&mut inner, kind, destination, via_relay);
    }

    fn sync(self: &Arc<Self>) {
        let body = DeviceSync {
            device: self.id,
            public_key: crate::control::encode(self.public_key.as_bytes()),
            peer: self.peer_id,
        };
        let url = format!("{}/v1/devices/{}/sync", self.coordinator, self.id);
        if let Ok(response) = http::post_json::<_, DeviceSyncResponse>(&url, &body) {
            self.apply_sync(response);
        }
    }

    fn apply_sync(self: &Arc<Self>, response: DeviceSyncResponse) {
        let at = Millis::from_millis(self.millis());
        let mut inner = self.inner.lock().unwrap();
        inner.generation = response.generation;
        inner.relays = response
            .relays
            .iter()
            .map(|relay| (relay.id.clone(), relay.healthy))
            .collect();
        inner.slot_ports = response
            .slot_addrs
            .values()
            .filter_map(|addr| crate::control::parse_socket_addr(addr).map(|a| a.port()))
            .collect();

        let Some(assigned) = response.assigned else {
            return;
        };

        if let Some(slot) = assigned
            .slot_addr
            .as_ref()
            .and_then(|addr| crate::control::parse_socket_addr(addr))
        {
            let changed = inner.assigned_relay.as_deref() != Some(assigned.relay_id.as_str());
            if changed {
                inner.assigned_relay = Some(assigned.relay_id.clone());
                inner.relay_slot = Some(slot.port());
                inner.assignments += 1;
                inner.observed_fed = false;
                inner.down_fired = false;
                inner.first_probe_ms = None;
                inner.fallback_ms = None;
                inner.initial_path = None;
                // The relay may not have reported this slot back to us yet; the
                // assigned relay's slot is a relayed address by construction.
                inner.slot_ports.insert(slot.port());
                let effects = step(
                    &mut inner.traversal,
                    Event::Assignment {
                        relay: Endpoint::new(slot),
                        at,
                    },
                    &self.cfg,
                );
                self.apply(&mut inner, effects);
                inner.note_punch(self.millis());
            }
        }

        if assigned.punch && !inner.observed_fed {
            if let Some(address) = assigned
                .peer_observed
                .as_ref()
                .and_then(|addr| crate::control::parse_socket_addr(addr))
            {
                inner.observed_fed = true;
                let effects = step(
                    &mut inner.traversal,
                    Event::Observed {
                        endpoint: Endpoint::new(address),
                        kind: CandidateKind::Observed,
                        at,
                    },
                    &self.cfg,
                );
                self.apply(&mut inner, effects);
                inner.note_punch(self.millis());
            }
        }
    }

    // -------------------------------------------------------------- effects --

    fn apply(self: &Arc<Self>, inner: &mut Inner, effects: Vec<Effect>) {
        for effect in effects {
            match effect {
                Effect::SetPeerEndpoint(endpoint) => {
                    let port = endpoint.addr().port();
                    if inner.peer.endpoint != port {
                        inner.peer.endpoint_changes += 1;
                    }
                    inner.peer.endpoint = port;
                    inner.peer.via_relay = inner.slot_ports.contains(&port);
                    inner.grace_until = Some(Instant::now() + DOWN_AFTER);
                }
                Effect::SendHandshake => {
                    let (destination, via_relay) = (inner.peer.endpoint, inner.peer.via_relay);
                    self.send(inner, MessageKind::Initiation, destination, via_relay);
                }
                Effect::ReportObservation(_) => {}
            }
        }
    }

    fn send(&self, inner: &mut Inner, kind: MessageKind, destination: u16, via_relay: bool) {
        if destination == 0 {
            return;
        }
        let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
        let packet = build(kind, &self.peer_key, nonce, self.id as u8);
        let mut frame = Vec::with_capacity(packet.len() + 4);
        frame.extend_from_slice(&destination.to_be_bytes());
        if via_relay {
            // Stands in for the destination the real relay derives from mac1.
            frame.extend_from_slice(&(self.peer_id as u16).to_be_bytes());
        }
        frame.extend_from_slice(&packet);
        let _ = self.socket.send_to(&frame, loopback(self.nat_port));
        inner.last_send = Some(Instant::now());
        if matches!(kind, MessageKind::Initiation | MessageKind::Response) {
            inner.peer.handshakes_out += 1;
        }
    }
}
