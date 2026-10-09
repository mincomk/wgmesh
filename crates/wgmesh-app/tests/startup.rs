#![allow(clippy::unwrap_used, clippy::expect_used)]
// The acceptance tests for the agent's use cases.
//
// All of it runs on `wgmesh_ports::fake`: no kernel, no network, no filesystem, no real clock,
// and no async runtime — the fakes return futures that are always ready, so `block_on` is a poll
// loop and nothing more. `cargo test -p wgmesh-app` is the whole requirement.

use std::time::Duration;

use wgmesh_app::agent::{Agent, AgentSettings, Ports, TraversePeers};
use wgmesh_app::{AppError, Effect, dispatch};
use wgmesh_core::{
    Allowed, CandidateKind, Change, DeviceId, Endpoint, Event, Millis, Path, PeerSpec, Phase,
    PublicKey, RelayId, RouteChange, RouteSpec, RouteTable, TraversalConfig,
};
use wgmesh_ports::fake::{
    FakeCoordinator, FakeRoutes, FakeSecrets, FakeWireGuard, ManualClock, RecordingState, block_on,
    endpoint as ep, peer_record,
};
use wgmesh_ports::{
    Class, InterfaceSpec, JoinToken, Observation, PeerStatus, PersistedState, PortError, Spki,
    StateStore,
};

fn spki(seed: u8) -> Spki {
    Spki::from_bytes([seed; 32])
}

fn peer(id: u32, port: u16) -> PeerSpec {
    PeerSpec {
        id: DeviceId(id),
        key: PublicKey::from_bytes([id as u8; 32]),
        allowed: vec![Allowed::V4([10, 77, 0, id as u8], 32)],
        endpoint: Some(ep(port)),
        keepalive: Some(Duration::from_secs(25)),
    }
}

/// What the kernel would report about a peer that is already configured.
fn status(spec: &PeerSpec) -> PeerStatus {
    PeerStatus {
        device: spec.id,
        public_key: spec.key,
        endpoint: spec.endpoint,
        allowed: spec.allowed.clone(),
        keepalive: spec.keepalive,
        last_handshake: Some(Millis::from_secs(900)),
        rx_bytes: 0,
        tx_bytes: 0,
    }
}

fn route(prefix: Allowed) -> RouteSpec {
    RouteSpec::new(prefix, RouteTable::Main, None)
}

fn interface() -> InterfaceSpec {
    InterfaceSpec {
        name: String::from("wgmesh0"),
        mtu: None,
        listen_port: None,
        fwmark: None,
    }
}

type FixtureAgent<'a> =
    Agent<'a, FakeCoordinator, FakeWireGuard, FakeRoutes, FakeSecrets, RecordingState, ManualClock>;

struct Fixture {
    clock: ManualClock,
    secrets: FakeSecrets,
    state: RecordingState,
    coordinator: FakeCoordinator,
    wireguard: FakeWireGuard,
    routes: FakeRoutes,
    settings: AgentSettings,
}

impl Fixture {
    fn new() -> Self {
        Self {
            clock: ManualClock::at(Millis::from_secs(1_000)),
            secrets: FakeSecrets::new(9),
            state: RecordingState::new(),
            coordinator: FakeCoordinator::new(DeviceId(7)).with_assignment(RelayId(2), 51903),
            wireguard: FakeWireGuard::new(),
            routes: FakeRoutes::new(),
            settings: AgentSettings::new(interface(), spki(1))
                .with_join_token(JoinToken::new("one-time-token")),
        }
    }

    fn agent(&self) -> FixtureAgent<'_> {
        Agent::new(
            Ports {
                coordinator: &self.coordinator,
                wireguard: &self.wireguard,
                routes: &self.routes,
                secrets: &self.secrets,
                state: &self.state,
                clock: &self.clock,
            },
            self.settings.clone(),
        )
    }
}

/// Enroll, converge, reach the interface and the routing table.
#[test]
fn a_start_enrolls_converges_and_reaches_the_kernel() {
    let fixture = Fixture::new();

    // The coordinator wants peer 1 at a new endpoint and peer 3, which is new. The kernel holds
    // peer 1 at a stale endpoint and peer 2, which the coordinator no longer wants — so the
    // difference has one of each kind of change in it.
    let p1 = peer(1, 9101);
    let p3 = peer(3, 9103);
    fixture.coordinator.set_peers(vec![p1.clone(), p3.clone()]);
    fixture
        .coordinator
        .set_advertised(vec![Allowed::V4([192, 168, 5, 0], 24)]);
    fixture.wireguard.seed_status(status(&peer(1, 9555)));
    fixture.wireguard.seed_status(status(&peer(2, 9102)));

    // The table already carries one route we want and one we no longer do.
    fixture.routes.seed(route(Allowed::V4([10, 77, 0, 0], 16)));
    fixture.routes.seed(route(Allowed::V4([172, 16, 0, 0], 12)));

    let startup = block_on(fixture.agent().start()).expect("the agent starts");

    // It enrolled exactly once, and wrote down what came back.
    assert_eq!(fixture.coordinator.enroll_count(), 1);
    assert_eq!(startup.state.device, DeviceId(7));
    assert_eq!(startup.state.network, "test-net");
    assert_eq!(startup.state.tunnel_ip, Allowed::V4([10, 77, 0, 7], 16));
    assert_eq!(startup.state.coordinator.spki, spki(1));
    assert_eq!(startup.state.relay.assigned, Some(RelayId(2)));
    assert_eq!(startup.state.relay.slot_port, Some(51903));
    assert_eq!(startup.state.coordinator.etag.as_deref(), Some("cfg-1"));
    assert_eq!(
        fixture.coordinator.configs(),
        vec![Some(String::from("cfg-1"))]
    );

    // The interface came up, the tunnel address went on it, and the kernel was handed exactly
    // `core::diff`'s answer.
    assert_eq!(
        fixture.wireguard.interface().map(|spec| spec.name),
        Some(String::from("wgmesh0"))
    );
    assert_eq!(
        fixture.routes.addresses(),
        vec![Allowed::V4([10, 77, 0, 7], 16)]
    );
    assert_eq!(
        fixture.wireguard.applied(),
        vec![
            Change::Update(p1),
            Change::Add(p3),
            Change::Remove(DeviceId(2)),
        ]
    );
    let held: Vec<DeviceId> = fixture.wireguard.held().keys().copied().collect();
    assert_eq!(held, vec![DeviceId(1), DeviceId(3)]);

    // The routing table converged on its own inputs: the mesh band, what the peers advertise,
    // and nothing else.
    assert_eq!(
        fixture.routes.applied(),
        vec![
            RouteChange::Add(route(Allowed::V4([192, 168, 5, 0], 24))),
            RouteChange::Remove(route(Allowed::V4([172, 16, 0, 0], 12))),
        ]
    );
    assert_eq!(
        fixture.routes.installed(),
        vec![
            route(Allowed::V4([10, 77, 0, 0], 16)),
            route(Allowed::V4([192, 168, 5, 0], 24)),
        ]
    );

    // The peers the device remembers are the ones it just programmed, and the handshake time it
    // remembers is the one the kernel reported rather than a default.
    let remembered: Vec<DeviceId> = startup.state.peers.iter().map(|peer| peer.device).collect();
    assert_eq!(remembered, vec![DeviceId(1), DeviceId(3)]);
    assert_eq!(
        startup.state.peers[0].last_handshake,
        Some(Millis::from_secs(900)),
        "the kernel's last handshake reached the state"
    );
}

/// A pin that disagrees with the configuration stops the work, and only `trust rotate` moves it.
#[test]
fn a_pin_that_disagrees_with_the_state_stops_the_work() {
    let fixture = Fixture::new();
    let enrolled = PersistedState::enrolled(
        DeviceId(7),
        "test-net",
        Allowed::V4([10, 77, 0, 7], 16),
        spki(2),
        Millis::from_secs(900),
    );
    fixture
        .state
        .save(&enrolled)
        .expect("seed a state enrolled under another key");

    let error = block_on(fixture.agent().start()).expect_err("the pin disagrees");
    assert!(
        matches!(&error, AppError::TrustMismatch { .. }),
        "expected a trust mismatch, got {error}"
    );
    assert_eq!(error.class(), Class::Trust);
    assert!(!error.retryable());

    // Nothing was asked of the world beyond the key material: no configuration, no interface.
    assert_eq!(fixture.coordinator.enroll_count(), 0);
    assert!(fixture.coordinator.configs().is_empty());
    assert!(fixture.wireguard.interface().is_none());
    assert!(fixture.wireguard.applied().is_empty());
    assert!(fixture.routes.applied().is_empty());

    // Rotating the pin is a deliberate act, and it is the only thing that writes it.
    let rotated = fixture
        .agent()
        .rotate_trust(spki(1))
        .expect("rotate the pin");
    assert_eq!(rotated.coordinator.spki, spki(1));

    fixture.coordinator.set_peers(vec![peer(1, 9101)]);
    let startup = block_on(fixture.agent().start()).expect("the agent starts once the pin matches");
    assert_eq!(startup.state.coordinator.spki, spki(1));
    assert_eq!(fixture.coordinator.configs().len(), 1);

    // The seed, then the rotation, then the convergence.
    let saves = fixture.state.saves();
    assert_eq!(saves.len(), 3);
    assert_eq!(saves[1].coordinator.spki, spki(1));
    assert!(saves.iter().all(|saved| saved.device == DeviceId(7)));
}

/// Deleting the state file re-enrolls from scratch, with the same keys.
#[test]
fn clearing_the_state_re_enrolls_without_touching_the_keys() {
    let fixture = Fixture::new();
    fixture.coordinator.set_peers(vec![peer(1, 9101)]);
    block_on(fixture.agent().start()).expect("the first start");
    let first = fixture.state.state().expect("the state was written");

    // Delete the state file, and nothing else.
    fixture.state.clear().expect("clear the state");
    assert!(fixture.state.state().is_none());
    assert_eq!(fixture.state.clears(), 1);

    block_on(fixture.agent().start()).expect("the re-enrollment runs to the end");

    let enrolls = fixture.coordinator.enrolls();
    assert_eq!(enrolls.len(), 2, "the device enrolled again");
    assert_eq!(
        enrolls[0].signer, enrolls[1].signer,
        "the same API key enrolled both times"
    );
    assert_eq!(
        enrolls[0].wireguard, enrolls[1].wireguard,
        "the same WireGuard key was presented both times"
    );
    assert_eq!(
        fixture.secrets.generations(),
        1,
        "the key was minted once, not once per start"
    );
    assert_eq!(
        fixture.state.state().expect("the state came back").device,
        first.device
    );
}

/// The traversal state machine, and the kernel calls its effects turn into.
#[test]
fn the_traversal_state_machine_drives_the_kernel() {
    let fixture = Fixture::new();
    let mut traverse = TraversePeers::new(
        &fixture.wireguard,
        &fixture.coordinator,
        DeviceId(7),
        peer(1, 9101),
        TraversalConfig::default(),
    );

    // `Assignment` arms the relay path — in the state machine and in the kernel alike. The
    // handshake it asks for is a re-apply of the peer, which is what makes the kernel initiate.
    let effects = block_on(traverse.handle(Event::Assignment {
        relay: ep(9000),
        at: Millis::ZERO,
    }))
    .expect("assignment");
    assert_eq!(
        effects,
        vec![
            Effect::SetPeerEndpoint(peer(1, 9000)),
            Effect::SendHandshake(peer(1, 9000)),
        ]
    );
    assert_eq!(traverse.path(), Path::Relayed);
    assert_eq!(
        fixture.wireguard.applied(),
        vec![Change::Update(peer(1, 9000)), Change::Update(peer(1, 9000))]
    );

    // An observed endpoint is remembered, and nothing is tried before `punch_delay`.
    block_on(traverse.handle(Event::Observed {
        endpoint: ep(9200),
        kind: CandidateKind::Observed,
        at: Millis::from_secs(1),
    }))
    .expect("observed");
    assert!(
        block_on(traverse.handle(Event::Tick {
            at: Millis::from_secs(1)
        }))
        .expect("a tick before the delay")
        .is_empty()
    );
    assert_eq!(
        fixture.wireguard.applied().len(),
        2,
        "the kernel was left alone"
    );

    // At `punch_delay` the punch starts: the peer is re-pointed at the candidate, and the kick
    // reaches the kernel as another apply.
    let punch = block_on(traverse.handle(Event::Tick {
        at: Millis::from_secs(2),
    }))
    .expect("the punch starts");
    assert_eq!(
        punch,
        vec![
            Effect::SetPeerEndpoint(peer(1, 9200)),
            Effect::SendHandshake(peer(1, 9200)),
        ]
    );
    assert_eq!(traverse.path(), Path::Unknown);
    assert_eq!(
        fixture.wireguard.applied().last(),
        Some(&Change::Update(peer(1, 9200))),
        "the candidate endpoint reached the kernel"
    );

    // The handshake lands: the path is direct, and the traversal goes quiet.
    block_on(traverse.handle(Event::Handshake {
        via: ep(9200),
        at: Millis::from_secs(3),
    }))
    .expect("the handshake lands");
    assert_eq!(traverse.path(), Path::Direct);
    assert!(
        block_on(traverse.handle(Event::Tick {
            at: Millis::from_secs(600)
        }))
        .expect("a tick on a live direct path")
        .is_empty()
    );

    // `Degraded` sends traffic back through the relay and raises the backoff.
    let revert = block_on(traverse.handle(Event::Degraded {
        at: Millis::from_secs(700),
    }))
    .expect("the path degraded");
    assert_eq!(
        revert,
        vec![
            Effect::SetPeerEndpoint(peer(1, 9000)),
            Effect::SendHandshake(peer(1, 9000)),
        ]
    );
    assert_eq!(traverse.path(), Path::Relayed);
    assert_eq!(
        fixture.wireguard.applied().last(),
        Some(&Change::Update(peer(1, 9000))),
        "the relay endpoint reached the kernel again"
    );
    assert_eq!(traverse.traversal().attempts, 1);
    assert_eq!(
        traverse.traversal().phase,
        Phase::Idle {
            next_attempt: Millis::from_secs(730)
        },
        "30s of backoff after the first failure"
    );

    // The next round of probing fails too, and the wait is longer than the last one.
    block_on(traverse.handle(Event::Tick {
        at: Millis::from_secs(730),
    }))
    .expect("the second probe starts");
    assert_eq!(traverse.path(), Path::Unknown);
    block_on(traverse.handle(Event::Tick {
        at: Millis::from_secs(760),
    }))
    .expect("the punch window expires");
    assert_eq!(traverse.traversal().attempts, 2);
    assert_eq!(
        traverse.traversal().phase,
        Phase::Idle {
            next_attempt: Millis::from_secs(880)
        },
        "120s of backoff after the second failure"
    );
}

/// A default route never reaches the kernel, and the configuration that asks for one aborts
/// before the interface is touched at all.
#[test]
fn a_default_route_is_refused_before_any_change_reaches_the_kernel() {
    let fixture = Fixture::new();
    fixture.coordinator.set_peers(vec![peer(1, 9101)]);
    fixture
        .coordinator
        .with_network(vec![Allowed::V4([0, 0, 0, 0], 0)]);

    let error = block_on(fixture.agent().start()).expect_err("a default route is refused");
    assert!(
        matches!(&error, AppError::Routing(_)),
        "expected a routing refusal, got {error}"
    );
    assert_eq!(error.class(), Class::Fatal);
    assert!(fixture.routes.applied().is_empty());
    assert!(
        fixture.wireguard.applied().is_empty(),
        "the refusal came before the peers were programmed"
    );
    assert!(
        fixture.wireguard.held().is_empty(),
        "and no peer reached the interface either"
    );
}

/// A report becomes a coordinator call.
#[test]
fn a_report_observation_becomes_a_coordinator_call() {
    let fixture = Fixture::new();
    let observation = Observation {
        device: DeviceId(7),
        endpoint: ep(9200),
        kind: CandidateKind::Observed,
        at: Millis::from_secs(3),
    };
    block_on(dispatch(
        &fixture.wireguard,
        &fixture.coordinator,
        &Effect::ReportObservation(observation),
    ))
    .expect("the observation is reported");
    assert_eq!(fixture.coordinator.observations(), vec![observation]);
    assert!(
        fixture.wireguard.applied().is_empty(),
        "routes are not touched"
    );
}

/// A port failure keeps its class on the way out.
#[test]
fn a_port_failure_keeps_its_class() {
    let fixture = Fixture::new();
    fixture
        .coordinator
        .fail_with(PortError::transient("connection reset"));

    let error = block_on(fixture.agent().start()).expect_err("the coordinator is down");
    assert!(
        matches!(&error, AppError::Coordinator(_)),
        "expected a coordinator failure, got {error}"
    );
    assert_eq!(error.class(), Class::Transient);
    assert!(error.retryable());
    assert!(fixture.wireguard.applied().is_empty());

    fixture.coordinator.fail_with(PortError::trust(
        "the coordinator presented an unpinned key",
    ));
    let error = block_on(fixture.agent().start()).expect_err("the coordinator is not who it said");
    assert_eq!(error.class(), Class::Trust);
    assert!(!error.retryable());
}

/// A device with no state and no token has nothing to do.
#[test]
fn a_device_with_no_state_and_no_token_fails_clearly() {
    let mut fixture = Fixture::new();
    fixture.settings.join_token = None;
    let error = block_on(fixture.agent().start()).expect_err("there is nothing to enroll with");
    assert!(matches!(&error, AppError::MissingJoinToken), "{error}");
    assert_eq!(error.class(), Class::Fatal);
    assert_eq!(fixture.coordinator.enroll_count(), 0);
}

/// The heartbeat path a daemon would use: converge twice, and the second time names the version
/// it already has and changes nothing.
#[test]
fn a_second_convergence_is_a_no_op() {
    let fixture = Fixture::new();
    fixture.coordinator.set_peers(vec![peer(1, 9101)]);
    block_on(fixture.agent().start()).expect("the first start");
    let applied = fixture.wireguard.applied().len();
    let route_changes = fixture.routes.applied().len();

    // The coordinator has a newer configuration; the call names the version we already have.
    fixture.coordinator.set_etag("cfg-2");
    let state = fixture.state.state().expect("the state");
    let convergence = block_on(fixture.agent().converge(&state, Millis::from_secs(2_000)))
        .expect("the second convergence");

    assert!(convergence.peer_changes.is_empty());
    assert!(convergence.route_changes.is_empty());
    assert_eq!(fixture.wireguard.applied().len(), applied);
    assert_eq!(fixture.routes.applied().len(), route_changes);
    assert_eq!(convergence.state.coordinator.etag.as_deref(), Some("cfg-2"));
    assert_eq!(
        fixture.coordinator.configs(),
        vec![Some(String::from("cfg-1")), Some(String::from("cfg-1"))],
        "each call named the version the device already had"
    );
}

/// The kernel is the authority on what the kernel holds, not the state file.
#[test]
fn the_kernel_is_the_authority_on_what_it_holds() {
    let fixture = Fixture::new();
    fixture.coordinator.set_peers(vec![peer(1, 9101)]);

    // The state remembers peer 1 as configured, but the interface holds nothing — a rebuilt
    // interface, or a state file restored from a backup. A converge that trusted the state would
    // conclude there was nothing to do; one that asks the kernel produces the addition.
    let mut remembered = PersistedState::enrolled(
        DeviceId(7),
        "test-net",
        Allowed::V4([10, 77, 0, 7], 16),
        spki(1),
        Millis::ZERO,
    );
    remembered.peers.push(peer_record(
        DeviceId(1),
        Allowed::V4([10, 77, 0, 1], 32),
        Millis::from_secs(10),
    ));
    fixture
        .state
        .save(&remembered)
        .expect("seed a state that disagrees with the kernel");

    block_on(fixture.agent().start()).expect("the agent starts");
    assert_eq!(
        fixture.wireguard.applied(),
        vec![Change::Add(peer(1, 9101))],
        "the desired peer is an addition, because the kernel does not hold it"
    );

    let pinned: Vec<Endpoint> = fixture
        .wireguard
        .held()
        .values()
        .filter_map(|peer| peer.endpoint)
        .collect();
    assert_eq!(pinned, vec![ep(9101)]);
}
