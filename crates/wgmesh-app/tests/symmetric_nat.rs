#![allow(clippy::expect_used)]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use wgmesh_app::agent::traversal::{PeerTraversal, TraversalRunner};
use wgmesh_core::{
    DeviceId, Effect, Endpoint, Millis, Path, Phase, PublicKey, Traversal, TraversalConfig,
};
use wgmesh_ports::Observation;
use wgmesh_testkit::{FakeCoordinator, FakeWireGuard, NatProfile, NatSim, VirtualClock, block_on};

fn sip(port: u16) -> Endpoint {
    Endpoint::new(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        port,
    ))
}

const RELAY_PORT: u16 = 51901;
const PEER_PORT: u16 = 41287;
const RTT_MS: u64 = 200;
const KEEPALIVE_SECS: u64 = 25;
const SYNC_SECS: u64 = 30;

/// The outside world the agent is embedded in: a relay slot to use, a peer
/// whose external mapping the relay can observe, and a NAT that decides whether
/// a direct attempt actually arrives.
struct Harness {
    clock: VirtualClock,
    nat: NatSim,
    relay: Endpoint,
    peer_endpoint: Endpoint,
    wireguard: FakeWireGuard,
    coordinator: FakeCoordinator,
    runner: TraversalRunner<FakeWireGuard, FakeCoordinator, VirtualClock>,
    peer: PeerTraversal,
    log: Vec<(Millis, Vec<Effect>)>,
}

impl Harness {
    fn new(profile: NatProfile) -> Self {
        let clock = VirtualClock::new();
        let relay = sip(RELAY_PORT);
        let peer_endpoint = sip(PEER_PORT);
        let nat = NatSim::new(profile, relay, peer_endpoint);
        let keepalive = Duration::from_secs(KEEPALIVE_SECS);

        let wireguard = FakeWireGuard::new(
            DeviceId(2),
            nat.clone(),
            clock.clone(),
            Duration::from_millis(RTT_MS),
            keepalive,
        );
        let coordinator = FakeCoordinator::with_slot(relay);
        let runner = TraversalRunner::new(
            wireguard.clone(),
            coordinator.clone(),
            clock.clone(),
            TraversalConfig::default(),
            keepalive,
        );
        let peer = PeerTraversal::new(DeviceId(2), PublicKey::from_bytes([7; 32]), runner.config());

        Self {
            clock,
            nat,
            relay,
            peer_endpoint,
            wireguard,
            coordinator,
            runner,
            peer,
            log: Vec::new(),
        }
    }

    /// The relay knows the peer's external mapping from the moment the pair
    /// starts talking through it. The agent starts knowing nothing.
    fn start(&mut self) {
        self.coordinator
            .observe(Observation::new(self.peer_endpoint, self.clock.now()));
        self.step();
    }

    fn step(&mut self) {
        let now = self.clock.now();
        let effects = block_on(self.runner.step_peer(&mut self.peer)).expect("agent loop");
        if !effects.is_empty() {
            self.log.push((now, effects));
        }
        // The relay sees the peer's mapping only while the pair is actually
        // talking through it. This is the round trip that heals a cold path.
        if self.wireguard.current_endpoint() == Some(self.relay) {
            self.coordinator
                .observe(Observation::new(self.peer_endpoint, now));
        }
    }

    fn run_until(&mut self, target: Millis) {
        while self.clock.now() < target {
            self.clock.advance(Duration::from_secs(1));
            self.step();
        }
    }

    fn punch_times(&self) -> Vec<Millis> {
        self.log
            .iter()
            .filter(|(_, effects)| {
                effects.iter().any(|effect| {
                    matches!(effect, Effect::SetPeerEndpoint(endpoint) if *endpoint == self.peer_endpoint)
                })
            })
            .map(|(at, _)| *at)
            .collect()
    }
}

fn next_attempt(state: &Traversal) -> Millis {
    match state.phase {
        Phase::Idle { next_attempt } => next_attempt,
        Phase::Probing { .. } => panic!("expected the traversal to be waiting, not probing"),
    }
}

#[test]
fn a_symmetric_nat_falls_back_to_the_relay_after_the_window_and_then_backs_off() {
    let mut harness = Harness::new(NatProfile::Symmetric);
    harness.start();

    harness.run_until(Millis::from_secs(1));
    assert_eq!(harness.peer.state.path, Path::Relayed);
    assert_eq!(harness.peer.state.active, Some(harness.relay));

    harness.run_until(Millis::from_secs(2));
    assert_eq!(
        harness.peer.state.phase,
        Phase::Probing {
            since: Millis::from_secs(2)
        },
        "the direct attempt starts after punch_delay_secs"
    );
    assert_eq!(
        harness.wireguard.current_endpoint(),
        Some(harness.peer_endpoint),
        "the peer endpoint is the direct candidate now, and the relay path is broken for as long \
         as it stays there — a WireGuard peer has exactly one endpoint"
    );

    harness.run_until(Millis::from_secs(7));
    assert_eq!(harness.peer.state.path, Path::Relayed);
    assert_eq!(harness.peer.state.attempts, 1);
    assert_eq!(harness.wireguard.current_endpoint(), Some(harness.relay));
    assert_eq!(next_attempt(&harness.peer.state), Millis::from_secs(37));

    harness.run_until(Millis::from_secs(42));
    assert_eq!(harness.peer.state.attempts, 2);
    assert_eq!(harness.wireguard.current_endpoint(), Some(harness.relay));
    assert_eq!(next_attempt(&harness.peer.state), Millis::from_secs(162));

    harness.run_until(Millis::from_secs(167));
    assert_eq!(harness.peer.state.attempts, 3);
    assert_eq!(harness.wireguard.current_endpoint(), Some(harness.relay));
    assert_eq!(next_attempt(&harness.peer.state), Millis::from_secs(767));

    assert_eq!(
        harness.punch_times(),
        vec![
            Millis::from_secs(2),
            Millis::from_secs(37),
            Millis::from_secs(162)
        ],
        "each retry is the previous failure plus 30s, then 2m, then 10m"
    );
    let retreats: Vec<u64> = harness
        .punch_times()
        .windows(2)
        .map(|pair| pair[1].as_millis() - pair[0].as_millis())
        .collect();
    assert_eq!(retreats, vec![35_000, 125_000]);
}

#[test]
fn a_cone_nat_promotes_the_direct_path_and_then_leaves_it_alone() {
    let mut harness = Harness::new(NatProfile::Cone);
    harness.start();

    harness.run_until(Millis::from_secs(2));
    assert_eq!(
        harness.peer.state.phase,
        Phase::Probing {
            since: Millis::from_secs(2)
        }
    );

    harness.run_until(Millis::from_secs(3));
    assert_eq!(harness.peer.state.path, Path::Direct);
    assert_eq!(harness.peer.state.active, Some(harness.peer_endpoint));
    assert_eq!(
        harness.wireguard.current_endpoint(),
        Some(harness.peer_endpoint)
    );

    harness.run_until(Millis::from_secs(600));
    assert_eq!(harness.punch_times(), vec![Millis::from_secs(2)]);
    assert_eq!(harness.peer.state.attempts, 0);
}

#[test]
fn a_direct_path_that_goes_quiet_is_detected_and_heals_over_the_relay_within_one_round_trip() {
    let mut harness = Harness::new(NatProfile::Cone);
    harness.start();

    harness.run_until(Millis::from_secs(3));
    assert_eq!(harness.peer.state.path, Path::Direct);

    // The direct path stops carrying traffic. Nothing announces it; the
    // handshakes simply stop arriving.
    harness.nat.break_direct();
    harness.run_until(Millis::from_secs(78));

    let degraded_at = Millis::from_secs(78);
    assert_eq!(
        harness.peer.state.path,
        Path::Relayed,
        "a missing handshake must become Event::Degraded and put the peer endpoint back on the \
         relay slot"
    );
    assert_eq!(harness.peer.state.attempts, 1);
    assert_eq!(harness.wireguard.current_endpoint(), Some(harness.relay));
    assert_eq!(
        next_attempt(&harness.peer.state),
        degraded_at.plus(Duration::from_secs(30))
    );

    // One round trip would be 30s; the connection is already back well inside
    // it, and the relay has re-observed the peer in the meantime.
    harness.run_until(degraded_at.plus(Duration::from_secs(SYNC_SECS - 1)));

    assert_eq!(harness.peer.state.path, Path::Relayed);
    assert!(
        harness.peer.last_handshake >= Some(degraded_at),
        "the relay path must be carrying handshakes again"
    );
    let fresh = harness
        .peer
        .state
        .candidates
        .iter()
        .filter(|candidate| candidate.observed_at >= degraded_at)
        .count();
    assert!(
        fresh >= 1,
        "the relay slot must be re-observed within one round trip, not eventually"
    );
    assert!(
        harness
            .coordinator
            .observations()
            .iter()
            .any(|observation| observation.seen_at >= degraded_at)
    );
}
