// The candidate classes and the symmetric NAT, end to end over the fakes.
//
// What is simulated here is the one thing the agent cannot be told: whether a
// packet sent to an endpoint actually arrives. A `NatProfile::Symmetric` NAT
// gives the peer a different external mapping for every destination, so the
// address the relay observed is useless to this node, and a direct attempt to it
// produces no handshake. A cone NAT reuses one mapping, so it does.
//
// Every assertion below is about the shipped types: `TraversalRunner` for the
// round, `TraversePeers` for the state machine's effects, `FakeWireGuard` for the
// kernel, and the real `wgmesh_core::step` under all of it.

#![allow(clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use wgmesh_app::{Effect, PeerTraversal, TraversalRunner};
use wgmesh_core::{
    Allowed, Change, DeviceId, DiscoveryPolicy, DiscoverySources, Endpoint, Millis, Path, Phase,
    PublicKey, Traversal, TraversalConfig,
};
use wgmesh_ports::fake::{FakeCoordinator, FakeWireGuard, ManualClock, block_on};
use wgmesh_ports::{Clock, Observation, PeerStatus};

const DEVICE: DeviceId = DeviceId(2);
const PEER_KEY: PublicKey = PublicKey::from_bytes([7; 32]);
const TUNNEL_IP: Allowed = Allowed::V4([10, 77, 0, 2], 32);
const RELAY_PORT: u16 = 51901;
const PEER_PORT: u16 = 41287;
const KEEPALIVE: Duration = Duration::from_secs(25);
/// How often the relay reports what it has observed for this pair.
const SYNC_SECS: u64 = 30;

fn sip(port: u16) -> Endpoint {
    Endpoint::new(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        port,
    ))
}

fn lan(port: u16) -> Endpoint {
    Endpoint::new(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
        port,
    ))
}

/// What the network in front of the peer does with a packet addressed to it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum NatProfile {
    /// One external mapping, reused for every destination: the address the relay
    /// observed reaches the peer.
    Cone,
    /// A different mapping per destination: the observed address does not reach
    /// the peer, and neither does anything else we can predict.
    Symmetric,
}

/// Which endpoints actually deliver, and which stopped.
struct NatSim {
    profile: NatProfile,
    relay: Endpoint,
    observed: Endpoint,
    reachable: Vec<Endpoint>,
    direct_broken: bool,
}

impl NatSim {
    fn new(profile: NatProfile, relay: Endpoint, observed: Endpoint) -> Self {
        Self {
            profile,
            relay,
            observed,
            reachable: Vec::new(),
            direct_broken: false,
        }
    }

    /// Let traffic through to one endpoint, whatever the profile says.
    fn allow_through(&mut self, endpoint: Endpoint) {
        self.reachable.push(endpoint);
    }

    /// Take the direct path away without telling anyone.
    fn break_direct(&mut self) {
        self.direct_broken = true;
    }

    fn reaches(&self, endpoint: Endpoint) -> bool {
        if endpoint == self.relay {
            return true;
        }
        if self.direct_broken {
            return false;
        }
        if self.reachable.contains(&endpoint) {
            return true;
        }
        self.profile == NatProfile::Cone && endpoint == self.observed
    }
}

/// The world one agent runs in: a kernel, a coordinator, a clock, and a NAT.
///
/// The ports are leaked because the runner and the traversal borrow them for as
/// long as they live, and a test that has to keep the three of them in one struct
/// cannot also hold the borrows. The leak is per test and bounded by it.
struct Fixture {
    clock: &'static ManualClock,
    wireguard: &'static FakeWireGuard,
    coordinator: &'static FakeCoordinator,
    runner: TraversalRunner<'static, FakeWireGuard, FakeCoordinator, ManualClock>,
    peer: PeerTraversal<'static, FakeWireGuard, FakeCoordinator>,
    nat: NatSim,
    relay: Endpoint,
    peer_endpoint: Endpoint,
    /// Every round that did something, with the effects it produced.
    log: Vec<(Millis, Vec<Effect>)>,
    last_seeded_handshake: Option<Millis>,
    last_seeded_endpoint: Option<Endpoint>,
}

impl Fixture {
    fn new(profile: NatProfile) -> Self {
        let clock: &'static ManualClock = Box::leak(Box::new(ManualClock::new()));
        let wireguard: &'static FakeWireGuard = Box::leak(Box::new(FakeWireGuard::new()));
        let coordinator: &'static FakeCoordinator =
            Box::leak(Box::new(FakeCoordinator::new(DeviceId(1))));
        wireguard.set_listen_port(51820);

        let relay = sip(RELAY_PORT);
        let peer_endpoint = sip(PEER_PORT);
        let nat = NatSim::new(profile, relay, peer_endpoint);

        let runner = TraversalRunner::new(
            wireguard,
            coordinator,
            clock,
            TraversalConfig::default(),
            KEEPALIVE,
        );
        let peer = runner.peer(
            DEVICE,
            wgmesh_core::PeerSpec {
                id: DEVICE,
                key: PEER_KEY,
                allowed: vec![TUNNEL_IP],
                endpoint: None,
                keepalive: Some(KEEPALIVE),
            },
        );

        Self {
            clock,
            wireguard,
            coordinator,
            runner,
            peer,
            nat,
            relay,
            peer_endpoint,
            log: Vec::new(),
            last_seeded_handshake: None,
            last_seeded_endpoint: None,
        }
    }

    fn now(&self) -> Millis {
        self.clock.now()
    }

    /// The endpoint the kernel is currently sending to. A WireGuard peer has
    /// exactly one, which is the reason a punch and a fallback are switches
    /// rather than a period of trying both.
    fn endpoint(&self) -> Option<Endpoint> {
        self.wireguard
            .held()
            .get(&DEVICE)
            .and_then(|peer| peer.endpoint)
    }

    /// What the kernel knows before the agent looks at it.
    ///
    /// A handshake completes when the endpoint the kernel holds is one the
    /// network actually delivers to. The kernel initiates one as soon as the
    /// endpoint moves, and the persistent keepalive produces another every
    /// `KEEPALIVE` after that — which is exactly why relayed traffic keeps
    /// producing handshakes on a pair that cannot be punched.
    fn settle(&mut self) {
        let Some(endpoint) = self.endpoint() else {
            return;
        };
        if !self.nat.reaches(endpoint) {
            return;
        }
        let moved = self.last_seeded_endpoint != Some(endpoint);
        if !moved {
            if let Some(last) = self.last_seeded_handshake {
                if self.now().elapsed_since(last) < KEEPALIVE {
                    return;
                }
            }
        }
        self.last_seeded_handshake = Some(self.now());
        self.last_seeded_endpoint = Some(endpoint);
        self.wireguard.seed_status(PeerStatus {
            device: DEVICE,
            public_key: PEER_KEY,
            endpoint: Some(endpoint),
            allowed: vec![TUNNEL_IP],
            keepalive: Some(KEEPALIVE),
            last_handshake: Some(self.now()),
            rx_bytes: 0,
            tx_bytes: 0,
        });
    }

    /// What the relay has to report for this pair.
    ///
    /// It has been carrying the pair since before the agent started, and reports
    /// on the sync cadence while the pair is still going through it. Reporting
    /// every round would hand the agent a fresh observation for free, and the
    /// "heals within one round trip" claim below would then be a property of this
    /// harness rather than of the agent.
    fn observations(&self) -> Vec<Observation> {
        let first = self.now() == Millis::ZERO;
        let syncing = self.now().as_millis() % (SYNC_SECS * 1000) == 0;
        if !(first || (syncing && self.endpoint() == Some(self.relay))) {
            return Vec::new();
        }
        vec![Observation {
            device: DEVICE,
            endpoint: self.peer_endpoint,
            kind: wgmesh_core::CandidateKind::Observed,
            at: self.now(),
        }]
    }

    fn step(&mut self) {
        let at = self.now();
        self.settle();
        let observations = self.observations();
        let effects = block_on(
            self.runner
                .step(&mut self.peer, Some(self.relay), &observations),
        )
        .expect("one round of the agent loop");
        if !effects.is_empty() {
            self.log.push((at, effects));
        }
    }

    fn run_until(&mut self, target: Millis) {
        while self.now() < target {
            self.clock.advance(Duration::from_secs(1));
            self.step();
        }
    }

    /// One second of the loop, for the start of a test.
    fn start(&mut self) {
        self.step();
    }

    fn offer(&mut self, sources: &DiscoverySources, policy: DiscoveryPolicy) -> usize {
        self.runner
            .offer_candidates(&mut self.peer, sources, policy)
    }

    /// Every round whose effects pointed the peer at the direct candidate.
    fn punch_times(&self) -> Vec<Millis> {
        self.log
            .iter()
            .filter(|(_, effects)| {
                effects.iter().any(|effect| {
                    matches!(effect, Effect::SetPeerEndpoint(spec)
                        if spec.endpoint == Some(self.peer_endpoint))
                })
            })
            .map(|(at, _)| *at)
            .collect()
    }

    fn state(&self) -> &Traversal {
        self.peer.state()
    }

    fn path(&self) -> Path {
        self.peer.path()
    }

    fn next_attempt(&self) -> Millis {
        match self.state().phase {
            Phase::Idle { next_attempt } => next_attempt,
            Phase::Probing { .. } => panic!("expected the traversal to be waiting, not probing"),
        }
    }

    fn updates(&self) -> Vec<wgmesh_core::PeerSpec> {
        self.wireguard
            .applied()
            .into_iter()
            .filter_map(|change| match change {
                Change::Add(spec) | Change::Update(spec) => Some(spec),
                Change::Remove(_) => None,
            })
            .collect()
    }
}

fn lan_sources(endpoint: Endpoint) -> DiscoverySources {
    DiscoverySources {
        lan: vec![(endpoint, Millis::from_secs(1))],
        ..DiscoverySources::default()
    }
}

/// The acceptance criterion: the direct attempt is bounded by `punch_window`, the
/// path returns to the relay, and each failure retreats further.
#[test]
fn a_symmetric_nat_returns_to_the_relay_after_the_window_and_retreats_thirty_two_ten() {
    let mut fixture = Fixture::new(NatProfile::Symmetric);
    fixture.start();

    fixture.run_until(Millis::from_secs(1));
    assert_eq!(fixture.path(), Path::Relayed);
    assert_eq!(fixture.endpoint(), Some(fixture.relay));

    // The direct attempt starts after `punch_delay_secs`, and it is a switch: the
    // peer has one endpoint, so the relay path is gone for as long as it is on
    // the candidate. There is no state in which both are reachable.
    fixture.run_until(Millis::from_secs(2));
    assert_eq!(
        fixture.state().phase,
        Phase::Probing {
            since: Millis::from_secs(2)
        }
    );
    assert_eq!(fixture.endpoint(), Some(fixture.peer_endpoint));

    // The window closes 5 seconds later and the relay slot is written back.
    fixture.run_until(Millis::from_secs(7));
    assert_eq!(fixture.path(), Path::Relayed);
    assert_eq!(fixture.state().attempts, 1);
    assert_eq!(fixture.endpoint(), Some(fixture.relay));
    assert_eq!(fixture.next_attempt(), Millis::from_secs(37));

    // 30 seconds, then 2 minutes, then 10 minutes.
    fixture.run_until(Millis::from_secs(42));
    assert_eq!(fixture.state().attempts, 2);
    assert_eq!(fixture.endpoint(), Some(fixture.relay));
    assert_eq!(fixture.next_attempt(), Millis::from_secs(162));

    // The fourth attempt starts at 767 and its window closes at 772, where the
    // retreat is the last step of the schedule rather than an unbounded growth.
    fixture.run_until(Millis::from_secs(767));
    assert_eq!(fixture.endpoint(), Some(fixture.peer_endpoint));
    fixture.run_until(Millis::from_secs(772));
    assert_eq!(
        fixture.state().attempts,
        4,
        "the fourth failure has happened"
    );
    assert_eq!(fixture.endpoint(), Some(fixture.relay));
    assert_eq!(fixture.next_attempt(), Millis::from_secs(1372));

    let punches = fixture.punch_times();
    assert_eq!(
        punches,
        vec![
            Millis::from_secs(2),
            Millis::from_secs(37),
            Millis::from_secs(162),
            Millis::from_secs(767)
        ]
    );
    let retreats: Vec<u64> = punches
        .windows(2)
        .map(|pair| pair[1].as_millis() - pair[0].as_millis())
        .collect();
    assert_eq!(
        retreats,
        vec![35_000, 125_000, 605_000],
        "each retry is the previous failure plus 30s, 2m, then 10m"
    );

    // The retreat only means anything if the relayed handshakes that keep arriving
    // while it runs do not reset it. This is the state after the last one.
    assert_eq!(fixture.path(), Path::Relayed);
    assert!(
        fixture.peer.last_handshake().is_some(),
        "the relay path was carrying handshakes the whole time"
    );
}

/// The traversal moves the endpoint and nothing else.
#[test]
fn a_re_pin_carries_the_key_the_allowed_ips_and_the_keepalive_through() {
    let mut fixture = Fixture::new(NatProfile::Symmetric);
    fixture.start();
    fixture.run_until(Millis::from_secs(7));

    let updates = fixture.updates();
    assert!(!updates.is_empty());
    assert!(
        updates.iter().all(|spec| spec.allowed == vec![TUNNEL_IP]),
        "the AllowedIPs that program_allowed_ips assigned have to survive every re-pin"
    );
    assert!(updates.iter().all(|spec| spec.key == PEER_KEY));
    assert!(
        updates.iter().all(|spec| spec.keepalive == Some(KEEPALIVE)),
        "every peer carries the persistent keepalive, which is what makes the punch \
         simultaneous and keeps the relay mapping alive"
    );
}

/// A cone NAT is promoted to, and then left alone.
#[test]
fn a_cone_nat_promotes_the_direct_path_and_then_stops_probing() {
    let mut fixture = Fixture::new(NatProfile::Cone);
    fixture.start();

    fixture.run_until(Millis::from_secs(2));
    assert_eq!(
        fixture.state().phase,
        Phase::Probing {
            since: Millis::from_secs(2)
        }
    );

    fixture.run_until(Millis::from_secs(3));
    assert_eq!(fixture.path(), Path::Direct);
    assert_eq!(fixture.endpoint(), Some(fixture.peer_endpoint));

    fixture.run_until(Millis::from_secs(600));
    assert_eq!(fixture.punch_times(), vec![Millis::from_secs(2)]);
    assert_eq!(fixture.state().attempts, 0);
    assert_eq!(
        fixture.coordinator.punches().len(),
        0,
        "a working direct path is not reported as a failed punch"
    );
}

/// The direct path dies without saying so, and the agent notices.
#[test]
fn a_direct_path_that_goes_quiet_degrades_and_heals_over_the_relay_in_one_round_trip() {
    let mut fixture = Fixture::new(NatProfile::Cone);
    fixture.start();

    fixture.run_until(Millis::from_secs(3));
    assert_eq!(fixture.path(), Path::Direct);

    // The path stops carrying traffic. Nothing announces it; the handshakes
    // simply stop arriving. A live but idle path looks the same for the first two
    // minutes, so the agent has to wait out the teardown window before it may
    // call the path dead.
    fixture.nat.break_direct();

    fixture.run_until(Millis::from_secs(183));
    assert_eq!(
        fixture.path(),
        Path::Direct,
        "an idle path inside RejectAfterTime must not be bounced onto the relay"
    );

    fixture.run_until(Millis::from_secs(184));
    let degraded_at = Millis::from_secs(184);
    assert_eq!(
        fixture.path(),
        Path::Relayed,
        "a missing handshake becomes Event::Degraded and puts the peer endpoint back on the relay"
    );
    assert_eq!(fixture.state().attempts, 1);
    assert_eq!(fixture.endpoint(), Some(fixture.relay));
    assert_eq!(
        fixture.next_attempt(),
        degraded_at.plus(Duration::from_secs(30))
    );

    // One round trip is the sync interval: inside it the relay is carrying the
    // pair again, the kernel is handshaking again, and the slot has been observed
    // again, so a later probe has a fresh candidate to work with.
    fixture.run_until(degraded_at.plus(Duration::from_secs(SYNC_SECS - 3)));
    assert_eq!(fixture.path(), Path::Relayed);
    assert!(
        fixture.peer.last_handshake() >= Some(degraded_at),
        "the relay path must be carrying handshakes again"
    );

    fixture.run_until(degraded_at.plus(Duration::from_secs(SYNC_SECS - 1)));
    let fresh = fixture
        .state()
        .candidates
        .iter()
        .filter(|candidate| candidate.observed_at >= degraded_at)
        .count();
    assert!(
        fresh >= 1,
        "the relay slot must be re-observed within one round trip, not eventually"
    );
}

/// The LAN class outranks what the relay saw, and reaches the endpoint chooser.
#[test]
fn a_lan_candidate_outranks_the_relay_observed_address() {
    // The peer is behind a symmetric NAT, so the address the relay observed is
    // useless. The same-LAN address is not, and the ranking has to prefer it.
    let mut fixture = Fixture::new(NatProfile::Symmetric);
    let lan_endpoint = lan(PEER_PORT);
    fixture.nat.allow_through(lan_endpoint);
    fixture.start();

    assert_eq!(
        fixture.offer(&lan_sources(lan_endpoint), DiscoveryPolicy::default()),
        1
    );
    fixture.run_until(Millis::from_secs(3));

    assert_eq!(fixture.state().active, Some(lan_endpoint));
    assert_eq!(fixture.path(), Path::Direct);
    assert_eq!(fixture.endpoint(), Some(lan_endpoint));
}

/// The same world, with one class switched off, keeps the peer on the relay.
#[test]
fn switching_lan_candidates_off_puts_the_peer_back_on_the_relay() {
    let mut fixture = Fixture::new(NatProfile::Symmetric);
    let lan_endpoint = lan(PEER_PORT);
    // Reachable, so the only thing that can keep the agent off it is the policy.
    fixture.nat.allow_through(lan_endpoint);
    fixture.start();

    let policy = DiscoveryPolicy {
        lan_candidates: false,
        ipv6: true,
    };
    assert_eq!(fixture.offer(&lan_sources(lan_endpoint), policy), 0);

    fixture.run_until(Millis::from_secs(3));
    assert_eq!(
        fixture.endpoint(),
        Some(fixture.peer_endpoint),
        "with the Lan class off the agent falls back to the relay-observed endpoint"
    );

    fixture.run_until(Millis::from_secs(7));
    assert_eq!(fixture.path(), Path::Relayed);
    assert_eq!(fixture.endpoint(), Some(fixture.relay));
}
