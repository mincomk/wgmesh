// The agent's use cases: enroll, converge, traverse — and the startup sequence that runs them.
//
// Three use cases, and the order a device runs them in on boot:
//
// * `EnrollDevice` — trade a join token and a key for an identity, and remember it.
// * `ConvergeState` — fetch the desired world, turn it into the difference from the world the
//   kernel already has, and write that difference to the interface and the routing table.
// * `TraversePeers` — run one peer's traversal state machine, and turn the effects it asks for
//   into port calls.
//
// `Agent::start` is the sequence the daemon runs: make sure the device has keys, load the state,
// refuse to continue if the pin moved, enroll if there is nothing to resume, bring the interface
// up, converge. Nothing in this crate opens a socket, touches a kernel or reads a file — every
// interaction goes through a trait in `wgmesh-ports`, which is why the whole of it, startup
// sequence included, runs in `cargo test -p wgmesh-app` against the fakes.

use std::collections::BTreeMap;
use std::time::Duration;

use traversal::{DEFAULT_KEEPALIVE, TraversalRunner};
use wgmesh_core::Effect as TraversalEffect;
use wgmesh_core::{
    Allowed, AllowedIpsPolicy, CandidateKind, Change, DeviceId, DiscoveryPolicy, Event, Millis,
    Path, PeerSpec, RouteChange, RoutePrefixes, RouteSpec, RouteTable, RoutingError, Traversal,
    TraversalConfig, desired_routes, diff, plan_routes, program_allowed_ips, step,
};
use wgmesh_ports::{
    Clock, ConfigSnapshot, CoordinatorApi, EnrollRequest, InterfaceSpec, JoinToken, Observation,
    PeerRecord, PeerStatus, PersistedState, Routes, SecretStore, Spki, StateStore, WireGuard,
};

pub mod discovery;
pub mod effect;
pub mod error;
pub mod traversal;

pub use effect::{Effect, dispatch, dispatch_all};
pub use error::AppError;

/// The slice of configuration the agent needs, and the policy it runs under.
///
/// This is not `wgmesh-config`'s `Settings`; it is the part of it the use cases read. The
/// composition root maps one to the other, which is what keeps this crate's dependencies to
/// `wgmesh-core` and `wgmesh-ports` while the configuration file's schema stays free to grow.
#[derive(Clone, Debug)]
pub struct AgentSettings {
    /// The interface to bring up and keep converged.
    pub interface: InterfaceSpec,
    /// The coordination-plane key this device expects to find.
    pub coordinator_spki: Spki,
    /// The token to enroll with, for a device that has no state yet.
    pub join_token: Option<JoinToken>,
    /// What this device calls itself to the coordinator.
    pub hostname: Option<String>,
    /// How traversal should punch, wait and back off.
    pub traversal: TraversalConfig,
    /// Which peers may claim which addresses.
    pub allowed_ips: AllowedIpsPolicy,
    /// Which bands the kernel should route.
    pub route_prefixes: RoutePrefixes,
    /// Which table the routes go in.
    pub route_table: RouteTable,
    /// The route metric.
    pub route_metric: Option<u32>,
    /// The keepalive to ask peers for.
    pub peer_keepalive: Option<Duration>,
    /// Which candidate classes this node derives for itself.
    pub discovery: DiscoveryPolicy,
    /// Whether NAT-PMP and UPnP-IGD may be spoken to at all.
    ///
    /// Off by default, and off means off: `CandidateDiscovery` does not call the
    /// port mapper, so no request leaves the node. A mapping is an opportunistic
    /// extra candidate rather than a prerequisite for anything.
    pub upnp: bool,
    /// How long a port mapping is asked to live.
    pub mapping_lifetime: Duration,
}

impl AgentSettings {
    /// Settings for an interface and a coordinator pin, with the M0 policy.
    ///
    /// The defaults are the blueprint's M0 shape: every peer on its own prefixes, routes chosen
    /// automatically from the mesh's band and what the peers advertise, in the main table.
    pub fn new(interface: InterfaceSpec, coordinator_spki: Spki) -> Self {
        Self {
            interface,
            coordinator_spki,
            join_token: None,
            hostname: None,
            traversal: TraversalConfig::default(),
            allowed_ips: AllowedIpsPolicy::Peer,
            route_prefixes: RoutePrefixes::Auto,
            route_table: RouteTable::Main,
            route_metric: None,
            peer_keepalive: None,
            discovery: DiscoveryPolicy::default(),
            upnp: false,
            mapping_lifetime: Duration::from_secs(1800),
        }
    }

    /// Set the enrollment token.
    pub fn with_join_token(mut self, token: JoinToken) -> Self {
        self.join_token = Some(token);
        self
    }

    /// Set the hostname reported at enrollment.
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// Set the traversal timings.
    pub fn with_traversal(mut self, traversal: TraversalConfig) -> Self {
        self.traversal = traversal;
        self
    }

    /// Set the AllowedIPs policy.
    pub fn with_allowed_ips(mut self, allowed_ips: AllowedIpsPolicy) -> Self {
        self.allowed_ips = allowed_ips;
        self
    }

    /// Set which bands the kernel routes.
    pub fn with_route_prefixes(mut self, route_prefixes: RoutePrefixes) -> Self {
        self.route_prefixes = route_prefixes;
        self
    }

    /// Set which table the routes go in.
    pub fn with_route_table(mut self, route_table: RouteTable) -> Self {
        self.route_table = route_table;
        self
    }

    /// Set the route metric.
    pub fn with_route_metric(mut self, route_metric: u32) -> Self {
        self.route_metric = Some(route_metric);
        self
    }

    /// Set the keepalive asked of peers.
    pub fn with_peer_keepalive(mut self, keepalive: Duration) -> Self {
        self.peer_keepalive = Some(keepalive);
        self
    }

    /// Set which candidate classes this node derives for itself.
    pub fn with_discovery(mut self, discovery: DiscoveryPolicy) -> Self {
        self.discovery = discovery;
        self
    }

    /// Allow or forbid NAT-PMP and UPnP-IGD.
    pub fn with_upnp(mut self, upnp: bool) -> Self {
        self.upnp = upnp;
        self
    }

    /// Set how long a port mapping is asked to live.
    pub fn with_mapping_lifetime(mut self, mapping_lifetime: Duration) -> Self {
        self.mapping_lifetime = mapping_lifetime;
        self
    }
}

/// The adapters the agent talks to the world through.
pub struct Ports<'a, C, W, R, S, T, K>
where
    C: CoordinatorApi,
    W: WireGuard,
    R: Routes,
    S: SecretStore,
    T: StateStore,
    K: Clock,
{
    /// The coordination plane.
    pub coordinator: &'a C,
    /// The kernel WireGuard interface.
    pub wireguard: &'a W,
    /// The kernel routing table.
    pub routes: &'a R,
    /// The key material.
    pub secrets: &'a S,
    /// The state file.
    pub state: &'a T,
    /// The clock.
    pub clock: &'a K,
}

/// What one convergence did.
#[derive(Clone, Debug)]
pub struct Convergence {
    /// The state, with the version it converged to.
    pub state: PersistedState,
    /// The configuration the coordinator handed over.
    pub snapshot: ConfigSnapshot,
    /// The difference between those peers and the ones the kernel had.
    pub peer_changes: Vec<Change>,
    /// The difference between the desired routes and the installed ones.
    pub route_changes: Vec<RouteChange>,
}

/// What the startup sequence produced.
#[derive(Clone, Debug)]
pub struct Startup {
    /// The state the device is running from.
    pub state: PersistedState,
    /// What the last step did.
    pub convergence: Convergence,
}

/// The agent, holding its settings and its adapters.
pub struct Agent<'a, C, W, R, S, T, K>
where
    C: CoordinatorApi,
    W: WireGuard,
    R: Routes,
    S: SecretStore,
    T: StateStore,
    K: Clock,
{
    ports: Ports<'a, C, W, R, S, T, K>,
    settings: AgentSettings,
}

impl<'a, C, W, R, S, T, K> Agent<'a, C, W, R, S, T, K>
where
    C: CoordinatorApi,
    W: WireGuard,
    R: Routes,
    S: SecretStore,
    T: StateStore,
    K: Clock,
{
    /// Put an agent together.
    pub fn new(ports: Ports<'a, C, W, R, S, T, K>, settings: AgentSettings) -> Self {
        Self { ports, settings }
    }

    /// The settings the agent runs under.
    pub fn settings(&self) -> &AgentSettings {
        &self.settings
    }

    /// The startup sequence.
    ///
    /// 1. The settings are read before this runs; `--check` stops there.
    /// 2. Make sure the device has a WireGuard key, minting one if the store holds none.
    /// 3. Load the state. With none, enroll — and write what comes back.
    /// 4. Check the pin. If the state was enrolled under a different coordination-plane key than
    ///    the configuration expects, stop: this is the one failure that must not be retried
    ///    around.
    /// 5. Bring the interface up, put the tunnel address on it, and converge.
    /// 6. The event loop is the daemon's; `TraversePeers` is the unit it drives.
    pub async fn start(&self) -> Result<Startup, AppError> {
        let at = self.ports.clock.now();

        // 2. The keys, minted if this device has never run.
        self.ports
            .secrets
            .wireguard_public_key()
            .map_err(AppError::Secrets)?;

        // 3. Where we left off, or a fresh enrollment.
        let state = match self.ports.state.load().map_err(AppError::State)? {
            Some(state) => state,
            None => self.enroll(at).await?,
        };

        // 4. The pin.
        check_pin(&state, &self.settings)?;

        // 5. The interface, its address, and the world.
        self.ports
            .wireguard
            .ensure_interface(&self.settings.interface)
            .map_err(AppError::WireGuard)?;
        self.ports
            .routes
            .ensure_address(&state.tunnel_ip)
            .map_err(AppError::Routes)?;
        let convergence = self.converge(&state, at).await?;

        Ok(Startup {
            state: convergence.state.clone(),
            convergence,
        })
    }

    /// Enroll: trade the token and the keys for an identity.
    pub async fn enroll(&self, at: Millis) -> Result<PersistedState, AppError> {
        EnrollDevice::new(
            self.ports.coordinator,
            self.ports.secrets,
            self.ports.state,
            &self.settings,
        )
        .run(at)
        .await
    }

    /// Converge: bring the kernel to the desired world.
    pub async fn converge(
        &self,
        state: &PersistedState,
        at: Millis,
    ) -> Result<Convergence, AppError> {
        ConvergeState::new(
            self.ports.coordinator,
            self.ports.wireguard,
            self.ports.routes,
            self.ports.state,
            &self.settings,
        )
        .run(state, at)
        .await
    }

    /// A traversal for one peer.
    pub fn traverse(&self, device: DeviceId, peer: PeerSpec) -> TraversePeers<'a, W, C> {
        TraversePeers::new(
            self.ports.wireguard,
            self.ports.coordinator,
            device,
            peer,
            self.settings.traversal.clone(),
        )
    }

    /// A runner: the round-by-round loop over what `traverse` steps through.
    ///
    /// The keepalive is the configured one, or [`DEFAULT_KEEPALIVE`] when the
    /// settings name none — a traversal without a keepalive has nothing to make
    /// both sides send at once, and nothing to keep a NAT mapping alive.
    pub fn traversal_runner(&self) -> TraversalRunner<'a, W, C, K> {
        TraversalRunner::new(
            self.ports.wireguard,
            self.ports.coordinator,
            self.ports.clock,
            self.settings.traversal.clone(),
            self.settings.peer_keepalive.unwrap_or(DEFAULT_KEEPALIVE),
        )
    }

    /// Move the pinned coordination-plane key.
    ///
    /// This is the only thing in the agent that writes the pin after enrollment, and it is what
    /// `wgmesh trust --rotate` runs. There is no path that rotates the pin as a consequence of a
    /// failed connection: a coordinator that presents the wrong key is one this device refuses to
    /// talk to, not one it learns to trust.
    pub fn rotate_trust(&self, spki: Spki) -> Result<PersistedState, AppError> {
        let mut state = self
            .ports
            .state
            .load()
            .map_err(AppError::State)?
            .ok_or(AppError::NotEnrolled)?;
        state.coordinator.spki = spki;
        self.ports.state.save(&state).map_err(AppError::State)?;
        Ok(state)
    }
}

/// The pin, checked against the configuration.
fn check_pin(state: &PersistedState, settings: &AgentSettings) -> Result<(), AppError> {
    if state.coordinator.spki != settings.coordinator_spki {
        return Err(AppError::TrustMismatch {
            pinned: state.coordinator.spki,
            configured: settings.coordinator_spki,
        });
    }
    Ok(())
}

/// Enrollment: the first thing a device that has never enrolled does.
pub struct EnrollDevice<'a, C, S, T>
where
    C: CoordinatorApi,
    S: SecretStore,
    T: StateStore,
{
    coordinator: &'a C,
    secrets: &'a S,
    state: &'a T,
    settings: &'a AgentSettings,
}

impl<'a, C, S, T> EnrollDevice<'a, C, S, T>
where
    C: CoordinatorApi,
    S: SecretStore,
    T: StateStore,
{
    /// Put the use case together.
    pub fn new(
        coordinator: &'a C,
        secrets: &'a S,
        state: &'a T,
        settings: &'a AgentSettings,
    ) -> Self {
        Self {
            coordinator,
            secrets,
            state,
            settings,
        }
    }

    /// Enroll, and persist what comes back.
    ///
    /// The device's WireGuard key already exists — the startup sequence minted it — so a
    /// re-enrollment after the state file was deleted presents the same public key and the
    /// coordinator hands back the same device. That is the whole difference between a device
    /// that forgot where it was and a device that is new.
    pub async fn run(&self, at: Millis) -> Result<PersistedState, AppError> {
        let token = self
            .settings
            .join_token
            .clone()
            .ok_or(AppError::MissingJoinToken)?;
        let signer = self.secrets.public_key().map_err(AppError::Secrets)?;
        let wireguard = self
            .secrets
            .wireguard_public_key()
            .map_err(AppError::Secrets)?;
        let request = EnrollRequest {
            token,
            signer,
            wireguard,
            hostname: self.settings.hostname.clone(),
        };
        let enrollment = self
            .coordinator
            .enroll(request)
            .await
            .map_err(AppError::Coordinator)?;

        let mut state = PersistedState::enrolled(
            enrollment.device,
            enrollment.network,
            enrollment.tunnel_ip,
            self.settings.coordinator_spki,
            at,
        );
        state.coordinator.etag = enrollment.etag;
        if let Some(assignment) = enrollment.assignment {
            state.relay.assigned = Some(assignment.relay);
            state.relay.slot_port = Some(assignment.slot_port);
            state
                .relay
                .slots
                .insert(assignment.relay, assignment.slot_port);
        }
        self.state.save(&state).map_err(AppError::State)?;
        Ok(state)
    }
}

/// Convergence: the desired world, minus the world the kernel has, written to the kernel.
pub struct ConvergeState<'a, C, W, R, T>
where
    C: CoordinatorApi,
    W: WireGuard,
    R: Routes,
    T: StateStore,
{
    coordinator: &'a C,
    wireguard: &'a W,
    routes: &'a R,
    state: &'a T,
    settings: &'a AgentSettings,
}

impl<'a, C, W, R, T> ConvergeState<'a, C, W, R, T>
where
    C: CoordinatorApi,
    W: WireGuard,
    R: Routes,
    T: StateStore,
{
    /// Put the use case together.
    pub fn new(
        coordinator: &'a C,
        wireguard: &'a W,
        routes: &'a R,
        state: &'a T,
        settings: &'a AgentSettings,
    ) -> Self {
        Self {
            coordinator,
            wireguard,
            routes,
            state,
            settings,
        }
    }

    /// Fetch the configuration and write the difference.
    ///
    /// Two diffs, one after the other, because the interface and the routing table are two
    /// things. For the interface, the inputs are AllowedIPs — the policy decides them, `diff`
    /// finds the change, the adapter writes it. For the table, the inputs are the bands the
    /// configuration policy selects out of the mesh's own and what the peers advertise; the
    /// default route is not among them and cannot be, because `desired_routes` refuses it.
    pub async fn run(&self, state: &PersistedState, at: Millis) -> Result<Convergence, AppError> {
        check_pin(state, self.settings)?;

        let snapshot = self
            .coordinator
            .config(state.coordinator.etag.as_deref())
            .await
            .map_err(AppError::Coordinator)?;

        // The table first: a configuration the routing policy refuses must stop the work before
        // any part of it reaches the kernel, rather than leaving half of its effect behind.
        let desired_routes = desired_routes(
            &snapshot.network,
            &snapshot.advertised,
            &self.settings.route_prefixes,
            self.settings.route_table,
            self.settings.route_metric,
        )
        .map_err(AppError::Routing)?;

        // The interface: policy, then difference, then write.
        let desired_peers =
            program_peers(self.settings.allowed_ips, &snapshot.peers, self.settings)
                .map_err(AppError::Routing)?;
        let statuses = self.wireguard.status(&[]).map_err(AppError::WireGuard)?;
        let current: BTreeMap<DeviceId, PeerSpec> = statuses.iter().map(as_spec).collect();
        let peer_changes = diff(&desired_peers, &current);
        if !peer_changes.is_empty() {
            self.wireguard
                .apply(&peer_changes)
                .map_err(AppError::WireGuard)?;
        }

        // The table: same shape, different inputs.
        let installed = self.routes.installed().map_err(AppError::Routes)?;
        let route_changes = plan_routes(&desired_routes, &installed);
        if !route_changes.is_empty() {
            self.routes
                .apply(&route_changes)
                .map_err(AppError::Routes)?;
        }

        let mut next = state.clone();
        next.coordinator.etag = Some(snapshot.etag.clone());
        next.coordinator.last_sync = at;
        next.peers = records(&desired_peers, &statuses);
        next.routes = desired_routes.clone();
        self.state.save(&next).map_err(AppError::State)?;

        Ok(Convergence {
            state: next,
            snapshot,
            peer_changes,
            route_changes,
        })
    }
}

/// One peer's traversal.
///
/// A traversal is per peer: the state machine has one relay, one active endpoint and one punch
/// schedule, and those belong to a pair. The daemon holds one of these for each peer it is
/// trying to reach directly.
pub struct TraversePeers<'a, W, C>
where
    W: WireGuard,
    C: CoordinatorApi,
{
    wireguard: &'a W,
    coordinator: &'a C,
    device: DeviceId,
    peer: PeerSpec,
    timing: TraversalConfig,
    traversal: Traversal,
}

impl<'a, W, C> TraversePeers<'a, W, C>
where
    W: WireGuard,
    C: CoordinatorApi,
{
    /// A traversal for one peer, starting from `Unknown`.
    pub fn new(
        wireguard: &'a W,
        coordinator: &'a C,
        device: DeviceId,
        peer: PeerSpec,
        timing: TraversalConfig,
    ) -> Self {
        Self {
            wireguard,
            coordinator,
            device,
            peer,
            timing,
            traversal: Traversal::new(),
        }
    }

    /// The peer this traversal is for, as the interface should currently hold it.
    pub fn peer(&self) -> &PeerSpec {
        &self.peer
    }

    /// The traversal state.
    pub fn traversal(&self) -> &Traversal {
        &self.traversal
    }

    /// Which way traffic is going right now.
    pub fn path(&self) -> Path {
        self.traversal.path
    }

    /// Feed one event to the state machine and get back what it wants done.
    ///
    /// No port is touched: this is the decision, and it is separate from the doing so that it can
    /// be tested — and read — on its own.
    pub fn on_event(&mut self, event: Event) -> Vec<Effect> {
        let at = event_time(&event);
        let mut effects = Vec::new();
        for effect in step(&mut self.traversal, event, &self.timing) {
            match effect {
                TraversalEffect::SetPeerEndpoint(endpoint) => {
                    self.peer.endpoint = Some(endpoint);
                    effects.push(Effect::SetPeerEndpoint(self.peer.clone()));
                }
                TraversalEffect::SendHandshake => {
                    effects.push(Effect::SendHandshake(self.peer.clone()));
                }
                TraversalEffect::ReportObservation(endpoint) => {
                    // The core drops the kind: an endpoint we are told about is, by definition,
                    // an observation of our own source address.
                    effects.push(Effect::ReportObservation(Observation {
                        device: self.device,
                        endpoint,
                        kind: CandidateKind::Observed,
                        at,
                    }));
                }
            }
        }
        effects
    }

    /// Feed one event to the state machine, and perform what it wants done.
    pub async fn handle(&mut self, event: Event) -> Result<Vec<Effect>, AppError> {
        let effects = self.on_event(event);
        dispatch_all(self.wireguard, self.coordinator, &effects).await?;
        Ok(effects)
    }
}

/// When an event happened. Every event carries one; the state machine is given no other clock.
fn event_time(event: &Event) -> Millis {
    match event {
        Event::Assignment { at, .. }
        | Event::Observed { at, .. }
        | Event::Handshake { at, .. }
        | Event::Tick { at } => *at,
        Event::Degraded { at } => *at,
    }
}

/// The AllowedIPs the policy programs, applied to the peers the coordinator handed over.
fn program_peers(
    policy: AllowedIpsPolicy,
    peers: &[PeerSpec],
    settings: &AgentSettings,
) -> Result<Vec<PeerSpec>, RoutingError> {
    let assigned = program_allowed_ips(policy, peers)?;
    Ok(peers
        .iter()
        .map(|peer| {
            let allowed = assigned
                .iter()
                .find(|(device, _)| *device == peer.id)
                .map(|(_, allowed)| allowed.clone())
                .unwrap_or_default();
            PeerSpec {
                allowed,
                keepalive: peer.keepalive.or(settings.peer_keepalive),
                ..peer.clone()
            }
        })
        .collect())
}

/// A `PeerSpec` as `core::diff` sees it.
fn as_spec(status: &PeerStatus) -> (DeviceId, PeerSpec) {
    (
        status.device,
        PeerSpec {
            id: status.device,
            key: status.public_key,
            allowed: status.allowed.clone(),
            endpoint: status.endpoint,
            keepalive: status.keepalive,
        },
    )
}

/// What the device should remember about the peers it just programmed.
fn records(peers: &[PeerSpec], statuses: &[PeerStatus]) -> Vec<PeerRecord> {
    peers
        .iter()
        .map(|peer| {
            let status = statuses.iter().find(|status| status.device == peer.id);
            PeerRecord {
                device: peer.id,
                name: None,
                public_key: peer.key,
                tunnel_ip: tunnel_address(&peer.allowed),
                endpoint: status.and_then(|status| status.endpoint).or(peer.endpoint),
                // Which way traffic is going is the traversal's to know, not a convergence's:
                // one that guessed would write down a path this device never took.
                path: Path::Unknown,
                last_handshake: status.and_then(|status| status.last_handshake),
            }
        })
        .collect()
}

/// A peer's own address: the host prefix among its AllowedIPs, or its first prefix.
fn tunnel_address(allowed: &[Allowed]) -> Option<Allowed> {
    allowed
        .iter()
        .find(|prefix| is_host(prefix))
        .or_else(|| allowed.first())
        .cloned()
}

/// Whether a prefix addresses a single host.
fn is_host(prefix: &Allowed) -> bool {
    match prefix {
        Allowed::V4(_, mask) => *mask == 32,
        Allowed::V6(_, mask) => *mask == 128,
    }
}

/// The route types a caller of `ConvergeState` needs, re-exported for convenience.
pub type PlannedRoute = RouteSpec;
