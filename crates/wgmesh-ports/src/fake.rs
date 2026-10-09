// In-memory implementations of every port: `FakeWireGuard`, `FakeRoutes`, `FakeCoordinator`,
// `RecordingState`, `FakeSecrets` and `ManualClock`.
//
// The use-case layer is tested against these and nothing else — no kernel, no network, no
// filesystem, no real clock — which is the whole point of writing the agent against ports. They
// live in this crate rather than in a test module of the crate that uses them because they are
// implementations of *these* traits, and because the blueprint's dependency table gives this
// crate the one crate an async trait implementation needs (`async-trait`) while the crates that
// consume them may not name it. Every later layer — the coordinator, the relay, the CLI's
// integration tests — reuses them unchanged.
//
// They are recording fakes: each holds the state its real counterpart would, and keeps the list
// of calls it was given, so a test can assert both that the agent reached the right decision and
// that the decision arrived as the right instruction.
//
// `block_on` is here for the same reason: a future returned by an in-memory implementation is
// always ready, so a test needs no runtime — only a way to drive one future to completion, and
// `Waker::noop` plus a poll loop is that way.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use wgmesh_core::{
    Allowed, Change, DeviceId, Endpoint, Millis, Path, PeerSpec, PublicKey, RelayId, RouteChange,
    RouteSpec,
};

use crate::{
    ApiError, Clock, ConfigSnapshot, CoordinatorApi, EnrollRequest, Enrollment, InterfaceSpec,
    Observation, PeerStatus, PersistedState, PortError, PunchReport, RouteError, SecretError,
    SecretStore, Signature, Spki, StateError, StateStore, WireGuard, WireGuardError,
};

/// Take a lock, ignoring poisoning.
///
/// A test that panics while holding a fake's lock has already failed; the poison flag would only
/// turn the failure into a second, less useful one.
fn locked<T>(cell: &Mutex<T>) -> MutexGuard<'_, T> {
    match cell.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Drive one future to completion without a runtime.
///
/// Correct for the futures in this module, which never return `Pending`; a future that really
/// waited would spin here rather than block.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

/// A coordination plane held in memory.
pub struct FakeCoordinator {
    device: DeviceId,
    network: String,
    tunnel_ip: Allowed,
    assignment: Option<crate::RelayAssignment>,
    listen_port: u16,
    etag: Mutex<String>,
    network_bands: Mutex<Vec<Allowed>>,
    advertised: Mutex<Vec<Allowed>>,
    peers: Mutex<Vec<PeerSpec>>,
    enrolls: Mutex<Vec<EnrollRequest>>,
    configs: Mutex<Vec<Option<String>>>,
    observations: Mutex<Vec<Observation>>,
    punches: Mutex<Vec<PunchReport>>,
    rotations: Mutex<Vec<PublicKey>>,
    failure: Mutex<Option<PortError>>,
}

impl FakeCoordinator {
    /// A coordinator that will hand `device` to whoever enrolls.
    pub fn new(device: DeviceId) -> Self {
        Self {
            device,
            network: String::from("test-net"),
            tunnel_ip: Allowed::V4([10, 77, 0, 7], 16),
            assignment: None,
            listen_port: 51820,
            etag: Mutex::new(String::from("cfg-1")),
            network_bands: Mutex::new(vec![Allowed::V4([10, 77, 0, 0], 16)]),
            advertised: Mutex::new(Vec::new()),
            peers: Mutex::new(Vec::new()),
            enrolls: Mutex::new(Vec::new()),
            configs: Mutex::new(Vec::new()),
            observations: Mutex::new(Vec::new()),
            punches: Mutex::new(Vec::new()),
            rotations: Mutex::new(Vec::new()),
            failure: Mutex::new(None),
        }
    }

    /// The relay joining devices are paired with.
    pub fn with_assignment(mut self, relay: RelayId, slot_port: u16) -> Self {
        self.assignment = Some(crate::RelayAssignment { relay, slot_port });
        self
    }

    /// The tunnel address enrollment hands out.
    pub fn with_tunnel_ip(mut self, tunnel_ip: Allowed) -> Self {
        self.tunnel_ip = tunnel_ip;
        self
    }

    /// The bands the configuration snapshot carries as the mesh's own.
    pub fn with_network(&self, bands: Vec<Allowed>) {
        *locked(&self.network_bands) = bands;
    }

    /// Set the peers the next configuration snapshot carries.
    pub fn set_peers(&self, peers: Vec<PeerSpec>) {
        *locked(&self.peers) = peers;
    }

    /// Set the bands the next configuration snapshot carries as advertised.
    pub fn set_advertised(&self, bands: Vec<Allowed>) {
        *locked(&self.advertised) = bands;
    }

    /// Set the configuration version.
    pub fn set_etag(&self, etag: impl Into<String>) {
        *locked(&self.etag) = etag.into();
    }

    /// The UDP port the device is told it listens on.
    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }

    /// Make every call fail with this error until `clear_failure`.
    pub fn fail_with(&self, error: PortError) {
        *locked(&self.failure) = Some(error);
    }

    /// Stop failing.
    pub fn clear_failure(&self) {
        *locked(&self.failure) = None;
    }

    /// Every enrollment request that reached the coordinator, in order.
    pub fn enrolls(&self) -> Vec<EnrollRequest> {
        locked(&self.enrolls).clone()
    }

    /// How many enrollments were attempted.
    pub fn enroll_count(&self) -> usize {
        locked(&self.enrolls).len()
    }

    /// Every configuration request, as the etag it named.
    pub fn configs(&self) -> Vec<Option<String>> {
        locked(&self.configs).clone()
    }

    /// Every observation that was reported, in order.
    pub fn observations(&self) -> Vec<Observation> {
        locked(&self.observations).clone()
    }

    /// Every punch report that was sent, in order.
    pub fn punches(&self) -> Vec<PunchReport> {
        locked(&self.punches).clone()
    }

    /// Every rotation that was requested.
    pub fn rotations(&self) -> Vec<PublicKey> {
        locked(&self.rotations).clone()
    }

    fn check(&self) -> Result<(), ApiError> {
        match locked(&self.failure).as_ref() {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }
}

#[async_trait::async_trait]
impl CoordinatorApi for FakeCoordinator {
    async fn enroll(&self, request: EnrollRequest) -> Result<Enrollment, ApiError> {
        self.check()?;
        locked(&self.enrolls).push(request);
        Ok(Enrollment {
            device: self.device,
            network: self.network.clone(),
            tunnel_ip: self.tunnel_ip.clone(),
            assignment: self.assignment,
            etag: Some(locked(&self.etag).clone()),
        })
    }

    async fn config(&self, etag: Option<&str>) -> Result<ConfigSnapshot, ApiError> {
        self.check()?;
        locked(&self.configs).push(etag.map(String::from));
        Ok(ConfigSnapshot {
            etag: locked(&self.etag).clone(),
            network: locked(&self.network_bands).clone(),
            advertised: locked(&self.advertised).clone(),
            peers: locked(&self.peers).clone(),
        })
    }

    async fn report_observations(&self, observations: &[Observation]) -> Result<(), ApiError> {
        self.check()?;
        locked(&self.observations).extend_from_slice(observations);
        Ok(())
    }

    async fn report_punch(&self, report: PunchReport) -> Result<(), ApiError> {
        self.check()?;
        locked(&self.punches).push(report);
        Ok(())
    }

    async fn rotate(&self, key: PublicKey) -> Result<(), ApiError> {
        self.check()?;
        locked(&self.rotations).push(key);
        Ok(())
    }
}

/// A WireGuard interface held in memory.
#[derive(Default)]
pub struct FakeWireGuard {
    interface: Mutex<Option<InterfaceSpec>>,
    held: Mutex<BTreeMap<DeviceId, PeerSpec>>,
    statuses: Mutex<BTreeMap<DeviceId, PeerStatus>>,
    applied: Mutex<Vec<Change>>,
    listen_port: Mutex<u16>,
}

impl FakeWireGuard {
    /// An interface holding no peers.
    pub fn new() -> Self {
        Self::default()
    }

    /// Give the interface a peer, as if it were already configured.
    pub fn seed_peer(&self, peer: PeerSpec) {
        locked(&self.held).insert(peer.id, peer);
    }

    /// Give the interface a status record, as if the kernel reported it.
    pub fn seed_status(&self, status: PeerStatus) {
        locked(&self.statuses).insert(status.device, status);
    }

    /// The interface spec `ensure_interface` was given, if it was called.
    pub fn interface(&self) -> Option<InterfaceSpec> {
        locked(&self.interface).clone()
    }

    /// The peers the interface currently holds.
    pub fn held(&self) -> BTreeMap<DeviceId, PeerSpec> {
        locked(&self.held).clone()
    }

    /// Every change that was written, in order.
    pub fn applied(&self) -> Vec<Change> {
        locked(&self.applied).clone()
    }

    /// The listen port the interface reports.
    pub fn set_listen_port(&self, port: u16) {
        *locked(&self.listen_port) = port;
    }
}

impl WireGuard for FakeWireGuard {
    fn ensure_interface(&self, spec: &InterfaceSpec) -> Result<(), WireGuardError> {
        *locked(&self.interface) = Some(spec.clone());
        Ok(())
    }

    fn apply(&self, changes: &[Change]) -> Result<(), WireGuardError> {
        let mut held = locked(&self.held);
        let mut statuses = locked(&self.statuses);
        let mut applied = locked(&self.applied);
        for change in changes {
            applied.push(change.clone());
            match change {
                Change::Add(spec) | Change::Update(spec) => {
                    held.insert(spec.id, spec.clone());
                    // The kernel's report follows what was written: a status is what `status`
                    // would say next time, so a fake that left it behind would report a peer
                    // the interface no longer has, or miss one it just gained.
                    let entry = statuses.entry(spec.id).or_insert_with(|| PeerStatus {
                        device: spec.id,
                        public_key: spec.key,
                        endpoint: spec.endpoint,
                        allowed: spec.allowed.clone(),
                        keepalive: spec.keepalive,
                        last_handshake: None,
                        rx_bytes: 0,
                        tx_bytes: 0,
                    });
                    entry.public_key = spec.key;
                    entry.endpoint = spec.endpoint;
                    entry.allowed = spec.allowed.clone();
                    entry.keepalive = spec.keepalive;
                }
                Change::Remove(id) => {
                    held.remove(id);
                    statuses.remove(id);
                }
            }
        }
        Ok(())
    }

    fn status(&self, peers: &[DeviceId]) -> Result<Vec<PeerStatus>, WireGuardError> {
        let statuses = locked(&self.statuses);
        let reported = if peers.is_empty() {
            statuses.values().cloned().collect()
        } else {
            peers
                .iter()
                .filter_map(|peer| statuses.get(peer).cloned())
                .collect()
        };
        Ok(reported)
    }

    fn listen_port(&self) -> Result<u16, WireGuardError> {
        Ok(*locked(&self.listen_port))
    }
}

/// A routing table held in memory.
#[derive(Default)]
pub struct FakeRoutes {
    installed: Mutex<Vec<RouteSpec>>,
    addresses: Mutex<Vec<Allowed>>,
    applied: Mutex<Vec<RouteChange>>,
}

impl FakeRoutes {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Give the table a route, as if wgmesh had already installed it.
    pub fn seed(&self, route: RouteSpec) {
        locked(&self.installed).push(route);
    }

    /// The routes currently installed.
    pub fn installed(&self) -> Vec<RouteSpec> {
        locked(&self.installed).clone()
    }

    /// The addresses that were put on the interface.
    pub fn addresses(&self) -> Vec<Allowed> {
        locked(&self.addresses).clone()
    }

    /// Every change that was written, in order.
    pub fn applied(&self) -> Vec<RouteChange> {
        locked(&self.applied).clone()
    }
}

impl crate::Routes for FakeRoutes {
    fn ensure_address(&self, address: &Allowed) -> Result<(), RouteError> {
        let mut addresses = locked(&self.addresses);
        if !addresses.contains(address) {
            addresses.push(address.clone());
        }
        Ok(())
    }

    fn installed(&self) -> Result<Vec<RouteSpec>, RouteError> {
        Ok(locked(&self.installed).clone())
    }

    fn apply(&self, changes: &[RouteChange]) -> Result<(), RouteError> {
        let mut installed = locked(&self.installed);
        let mut applied = locked(&self.applied);
        for change in changes {
            applied.push(change.clone());
            match change {
                RouteChange::Add(route) => {
                    if !installed.contains(route) {
                        installed.push(route.clone());
                    }
                }
                RouteChange::Remove(route) => {
                    installed.retain(|held| held != route);
                }
            }
        }
        Ok(())
    }
}

/// A state store that keeps everything in memory and remembers being used.
#[derive(Default)]
pub struct RecordingState {
    state: Mutex<Option<PersistedState>>,
    saves: Mutex<Vec<PersistedState>>,
    clears: Mutex<usize>,
}

impl RecordingState {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty store holding `state`.
    pub fn holding(state: PersistedState) -> Self {
        let store = Self::new();
        *locked(&store.state) = Some(state);
        store
    }

    /// The state currently held.
    pub fn state(&self) -> Option<PersistedState> {
        locked(&self.state).clone()
    }

    /// Every state that was written, in order.
    pub fn saves(&self) -> Vec<PersistedState> {
        locked(&self.saves).clone()
    }

    /// How many times the state was cleared.
    pub fn clears(&self) -> usize {
        *locked(&self.clears)
    }
}

impl StateStore for RecordingState {
    fn load(&self) -> Result<Option<PersistedState>, StateError> {
        Ok(locked(&self.state).clone())
    }

    fn save(&self, state: &PersistedState) -> Result<(), StateError> {
        *locked(&self.state) = Some(state.clone());
        locked(&self.saves).push(state.clone());
        Ok(())
    }

    fn clear(&self) -> Result<(), StateError> {
        *locked(&self.state) = None;
        *locked(&self.clears) += 1;
        Ok(())
    }
}

/// Key material held in memory.
///
/// `sign` produces a deterministic 64-byte value derived from the key and the message. It is not
/// a signature and must never be mistaken for one; what it is good for is proving that a message
/// reached the store, that the same message produces the same result, and that the private half
/// is never handed out at all.
pub struct FakeSecrets {
    seed: u8,
    audit: Mutex<SecretAudit>,
}

#[derive(Default)]
struct SecretAudit {
    generations: usize,
    wg: Option<PublicKey>,
    api: Option<PublicKey>,
    lookups: usize,
    signed: Vec<Vec<u8>>,
}

impl FakeSecrets {
    /// A store that holds no key yet and mints one on the first look.
    pub fn new(seed: u8) -> Self {
        Self {
            seed,
            audit: Mutex::new(SecretAudit::default()),
        }
    }

    /// How many times a key pair was minted.
    ///
    /// This is a real count, not a flag: each mint produces a *different* pair, so a device that
    /// re-minted would present a different public key, and a test that says the keys were reused
    /// is saying something.
    pub fn generations(&self) -> usize {
        locked(&self.audit).generations
    }

    /// How many times a public half was asked for.
    pub fn lookups(&self) -> usize {
        locked(&self.audit).lookups
    }

    /// Every message that was signed, in order.
    pub fn signed_messages(&self) -> Vec<Vec<u8>> {
        locked(&self.audit).signed.clone()
    }
}

/// The stored key pair, minting one if the store holds none.
fn keys(audit: &mut SecretAudit, seed: u8) -> (PublicKey, PublicKey) {
    if audit.wg.is_none() || audit.api.is_none() {
        audit.generations += 1;
        let generation = audit.generations as u8;
        audit.wg = Some(PublicKey::from_bytes([seed.wrapping_add(generation); 32]));
        let api_seed = seed.wrapping_add(generation).wrapping_add(1);
        audit.api = Some(PublicKey::from_bytes([api_seed; 32]));
    }
    let zero = PublicKey::from_bytes([0u8; 32]);
    (audit.wg.unwrap_or(zero), audit.api.unwrap_or(zero))
}

impl SecretStore for FakeSecrets {
    fn wireguard_public_key(&self) -> Result<PublicKey, SecretError> {
        let mut audit = locked(&self.audit);
        audit.lookups += 1;
        Ok(keys(&mut audit, self.seed).0)
    }

    fn public_key(&self) -> Result<PublicKey, SecretError> {
        let mut audit = locked(&self.audit);
        audit.lookups += 1;
        Ok(keys(&mut audit, self.seed).1)
    }

    fn sign(&self, message: &[u8]) -> Result<Signature, SecretError> {
        let mut audit = locked(&self.audit);
        audit.signed.push(message.to_vec());
        let (_, api) = keys(&mut audit, self.seed);
        Ok(Signature::from_bytes(digest(api.as_bytes(), message)))
    }
}

/// A 64-byte value derived from a key and a message. Not a signature; see `FakeSecrets`.
fn digest(key: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let mut state: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in key.iter().chain(message.iter()) {
        state = (state ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    let mut out = [0u8; 64];
    for (index, chunk) in out.chunks_mut(8).enumerate() {
        chunk.copy_from_slice(&state.wrapping_add(index as u64).to_le_bytes());
    }
    out
}

/// A pin that matches nothing, for tests that do not care which pin is in play.
pub fn any_spki(seed: u8) -> Spki {
    Spki::from_bytes([seed; 32])
}

/// A peer record for a state that a test is building by hand.
pub fn peer_record(device: DeviceId, tunnel_ip: Allowed, at: Millis) -> crate::stores::PeerRecord {
    crate::stores::PeerRecord {
        device,
        name: None,
        public_key: PublicKey::from_bytes([device.0 as u8; 32]),
        tunnel_ip: Some(tunnel_ip),
        endpoint: None,
        path: Path::Unknown,
        last_handshake: Some(at),
    }
}

/// A clock that only moves when a test moves it.
pub struct ManualClock {
    now: Mutex<Millis>,
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::at(Millis::ZERO)
    }
}

impl ManualClock {
    /// A clock at the epoch.
    pub fn new() -> Self {
        Self::default()
    }

    /// A clock at `now`.
    pub fn at(now: Millis) -> Self {
        Self {
            now: Mutex::new(now),
        }
    }

    /// Move the clock.
    pub fn set(&self, now: Millis) {
        *locked(&self.now) = now;
    }

    /// Move the clock forward.
    pub fn advance(&self, span: Duration) {
        let now = *locked(&self.now);
        *locked(&self.now) = now.plus(span);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Millis {
        *locked(&self.now)
    }
}

/// The endpoint helper a fake's caller usually wants: a v4 address on a documentation range.
pub fn endpoint(port: u16) -> Endpoint {
    Endpoint::new(std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7)),
        port,
    ))
}
