//! The offline backend: a coordination plane and a WireGuard device that live in this process.
//!
//! Selected with `--backend simulated`. It exists so the whole pipeline — enroll, converge,
//! status, route planning — can be exercised where a kernel WireGuard device cannot be: inside a
//! container without `CAP_NET_ADMIN`, and in CI. It is a test double that ships in the binary, and
//! it says so wherever it is used.
//!
//! What it does not do: touch a kernel, open a socket, or pretend a packet moved. Peers, routes
//! and handshakes are records the daemon writes down, and `wgmesh status` reads them back from the
//! state file exactly as it would from a kernel.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use wgmesh_core::{
    Allowed, Change, DeviceId, Endpoint, Millis, PeerSpec, PublicKey, RelayId, RouteChange,
    RouteSpec, RouteTable,
};
use wgmesh_ports::{
    ApiError, Clock, ConfigSnapshot, CoordinatorApi, EnrollRequest, Enrollment, InterfaceSpec,
    Observation, PeerStatus, PunchReport, RelayAssignment, RouteError, Routes, WireGuard,
    WireGuardError,
};

/// The world the simulated coordination plane hands out.
///
/// It is a file so that a test can write one down and a daemon can be pointed at it. It is
/// deliberately small: an identity, the peers to converge to, and the routes to install.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimulatedWorld {
    /// The device id the simulated coordinator assigns.
    #[serde(default = "one")]
    pub device: u32,
    /// The network name.
    #[serde(default = "default_network")]
    pub network: String,
    /// The tunnel address, `address/prefix`.
    #[serde(default = "default_tunnel_ip")]
    pub tunnel_ip: String,
    /// The relay this device was paired with, as a relay id.
    #[serde(default)]
    pub relay: Option<u16>,
    /// The UDP port this device's slot listens on.
    #[serde(default)]
    pub slot_port: Option<u16>,
    /// The mesh's own bands.
    #[serde(default)]
    pub network_bands: Vec<String>,
    /// Every band the peers advertise.
    #[serde(default)]
    pub advertised: Vec<String>,
    /// The peers this device should converge to.
    #[serde(default)]
    pub peers: Vec<SimulatedPeer>,
    /// The routes this device should install.
    #[serde(default)]
    pub routes: Vec<String>,
    /// The configuration version this world carries.
    #[serde(default = "one")]
    pub version: u32,
    /// The join token the simulated coordinator accepts.
    #[serde(default)]
    pub token: Option<String>,
}

fn one() -> u32 {
    1
}

fn default_network() -> String {
    "default".to_string()
}

fn default_tunnel_ip() -> String {
    "10.77.0.1/16".to_string()
}

/// One peer in the simulated world.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimulatedPeer {
    /// The device id.
    pub id: u32,
    /// What the peer is called.
    #[serde(default)]
    pub name: String,
    /// The peer's WireGuard public key, base64 as `wg(8)` writes it.
    #[serde(default)]
    pub public_key: String,
    /// The AllowedIPs of this peer.
    #[serde(default)]
    pub allowed: Vec<String>,
    /// The peer's endpoint, when it has one.
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// Parse a prefix written `address/prefix-length`.
pub fn parse_prefix(text: &str) -> Result<Allowed, String> {
    let (address, bits) = text
        .split_once('/')
        .ok_or_else(|| format!("not a prefix: {text}"))?;
    let bits: u8 = bits
        .parse()
        .map_err(|_| format!("not a prefix length: {text}"))?;
    match address
        .parse::<std::net::IpAddr>()
        .map_err(|_| format!("not an address: {text}"))?
    {
        std::net::IpAddr::V4(v4) => Ok(Allowed::V4(v4.octets(), bits)),
        std::net::IpAddr::V6(v6) => Ok(Allowed::V6(v6.octets(), bits)),
    }
}

/// Write a prefix the way the configuration writes it.
pub fn write_prefix(prefix: &Allowed) -> String {
    match prefix {
        Allowed::V4(bytes, mask) => {
            format!("{}.{}.{}.{}/{mask}", bytes[0], bytes[1], bytes[2], bytes[3])
        }
        Allowed::V6(bytes, mask) => {
            let mut groups = [0u16; 8];
            for (index, group) in groups.iter_mut().enumerate() {
                *group = u16::from_be_bytes([bytes[index * 2], bytes[index * 2 + 1]]);
            }
            format!(
                "{}/{mask}",
                groups
                    .iter()
                    .map(|group| format!("{group:x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            )
        }
    }
}

/// A peer's public key, decoded from the world's base64.
fn public_key_of(text: &str, id: u32) -> Result<PublicKey, String> {
    match wgmesh_secrets::parse_key(text.as_bytes()) {
        Ok((bytes, _format)) => Ok(PublicKey::from_bytes(bytes)),
        Err(error) => Err(format!("peer {id}: unusable public key: {error}")),
    }
}

impl SimulatedWorld {
    /// Load a world from its JSON file.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|error| {
            format!(
                "no simulated world at {}: {error}; write one before using --backend simulated",
                path.display()
            )
        })?;
        serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))
    }

    /// The peer specs the agent should converge to.
    pub fn peer_specs(&self) -> Result<Vec<PeerSpec>, String> {
        let mut specs = Vec::new();
        for peer in &self.peers {
            let allowed = peer
                .allowed
                .iter()
                .map(|prefix| parse_prefix(prefix))
                .collect::<Result<Vec<_>, _>>()?;
            let endpoint = match &peer.endpoint {
                Some(text) => Some(Endpoint::new(
                    text.parse()
                        .map_err(|_| format!("not an endpoint: {text}"))?,
                )),
                None => None,
            };
            specs.push(PeerSpec {
                id: DeviceId(peer.id),
                key: public_key_of(&peer.public_key, peer.id)?,
                allowed,
                endpoint,
                keepalive: None,
            });
        }
        Ok(specs)
    }

    /// The routes the agent should install.
    pub fn route_specs(&self) -> Result<Vec<RouteSpec>, String> {
        self.routes
            .iter()
            .map(|prefix| {
                Ok(RouteSpec::new(
                    parse_prefix(prefix)?,
                    RouteTable::Main,
                    None,
                ))
            })
            .collect()
    }

    /// The name of the peer with this id, when the world names it.
    pub fn name_of(&self, id: DeviceId) -> Option<&str> {
        self.peers
            .iter()
            .find(|peer| peer.id == id.0)
            .map(|peer| peer.name.as_str())
    }
}

/// A clock reading the wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Millis {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_millis() as u64)
            .unwrap_or(0);
        Millis::from_millis(millis)
    }
}

/// The simulated coordination plane.
pub struct SimulatedCoordinator {
    world: SimulatedWorld,
}

impl SimulatedCoordinator {
    /// A coordinator answering from `world`.
    pub fn new(world: SimulatedWorld) -> Self {
        Self { world }
    }

    /// The world it answers from.
    pub fn world(&self) -> &SimulatedWorld {
        &self.world
    }
}

#[async_trait]
impl CoordinatorApi for SimulatedCoordinator {
    async fn enroll(&self, request: EnrollRequest) -> Result<Enrollment, ApiError> {
        if let Some(expected) = self.world.token.as_deref() {
            if request.token.as_str() != expected {
                return Err(ApiError::fatal("the join token was refused"));
            }
        }
        Ok(Enrollment {
            device: DeviceId(self.world.device),
            network: self.world.network.clone(),
            tunnel_ip: parse_prefix(&self.world.tunnel_ip).map_err(ApiError::fatal)?,
            assignment: match (self.world.relay, self.world.slot_port) {
                (Some(relay), Some(slot_port)) => Some(RelayAssignment {
                    relay: RelayId(relay),
                    slot_port,
                }),
                _ => None,
            },
            etag: Some(self.world.version.to_string()),
        })
    }

    async fn config(&self, _etag: Option<&str>) -> Result<ConfigSnapshot, ApiError> {
        Ok(ConfigSnapshot {
            etag: self.world.version.to_string(),
            network: self
                .world
                .network_bands
                .iter()
                .map(|text| parse_prefix(text))
                .collect::<Result<Vec<_>, _>>()
                .map_err(ApiError::fatal)?,
            advertised: self
                .world
                .advertised
                .iter()
                .map(|text| parse_prefix(text))
                .collect::<Result<Vec<_>, _>>()
                .map_err(ApiError::fatal)?,
            peers: self.world.peer_specs().map_err(ApiError::fatal)?,
        })
    }

    async fn report_observations(&self, _observations: &[Observation]) -> Result<(), ApiError> {
        Ok(())
    }

    async fn report_punch(&self, _report: PunchReport) -> Result<(), ApiError> {
        Ok(())
    }

    async fn rotate(&self, _key: PublicKey) -> Result<(), ApiError> {
        Ok(())
    }
}

/// The simulated WireGuard device.
pub struct SimulatedWireGuard {
    clock: SystemClock,
    interface: Mutex<Option<String>>,
    peers: Mutex<BTreeMap<DeviceId, PeerSpec>>,
    handshakes: Mutex<BTreeMap<DeviceId, Millis>>,
}

impl Default for SimulatedWireGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl SimulatedWireGuard {
    /// An empty device.
    pub fn new() -> Self {
        Self {
            clock: SystemClock,
            interface: Mutex::new(None),
            peers: Mutex::new(BTreeMap::new()),
            handshakes: Mutex::new(BTreeMap::new()),
        }
    }

    /// The interface this device was told to bring up.
    pub fn interface(&self) -> Option<String> {
        self.interface.lock().ok().and_then(|held| held.clone())
    }
}

impl WireGuard for SimulatedWireGuard {
    fn ensure_interface(&self, spec: &InterfaceSpec) -> Result<(), WireGuardError> {
        let mut held = self
            .interface
            .lock()
            .map_err(|_| WireGuardError::fatal("the simulated interface lock was poisoned"))?;
        *held = Some(spec.name.clone());
        Ok(())
    }

    fn apply(&self, changes: &[Change]) -> Result<(), WireGuardError> {
        let mut peers = self
            .peers
            .lock()
            .map_err(|_| WireGuardError::fatal("the simulated peer lock was poisoned"))?;
        let mut handshakes = self
            .handshakes
            .lock()
            .map_err(|_| WireGuardError::fatal("the simulated handshake lock was poisoned"))?;
        let now = self.clock.now();
        for change in changes {
            match change {
                Change::Add(spec) | Change::Update(spec) => {
                    if spec.endpoint.is_some() && !handshakes.contains_key(&spec.id) {
                        // A peer given an endpoint in this backend has, as far as the simulation
                        // is concerned, completed a handshake.
                        handshakes.insert(spec.id, now);
                    }
                    peers.insert(spec.id, spec.clone());
                }
                Change::Remove(id) => {
                    peers.remove(id);
                    handshakes.remove(id);
                }
            }
        }
        Ok(())
    }

    fn status(&self, peers: &[DeviceId]) -> Result<Vec<PeerStatus>, WireGuardError> {
        let held = self
            .peers
            .lock()
            .map_err(|_| WireGuardError::fatal("the simulated peer lock was poisoned"))?;
        let handshakes = self
            .handshakes
            .lock()
            .map_err(|_| WireGuardError::fatal("the simulated handshake lock was poisoned"))?;
        let wanted: Vec<DeviceId> = if peers.is_empty() {
            held.keys().copied().collect()
        } else {
            peers.to_vec()
        };
        Ok(wanted
            .into_iter()
            .filter_map(|id| {
                let spec = held.get(&id)?;
                Some(PeerStatus {
                    device: id,
                    public_key: spec.key,
                    endpoint: spec.endpoint,
                    allowed: spec.allowed.clone(),
                    keepalive: spec.keepalive,
                    last_handshake: handshakes.get(&id).copied(),
                    rx_bytes: 0,
                    tx_bytes: 0,
                })
            })
            .collect())
    }

    fn listen_port(&self) -> Result<u16, WireGuardError> {
        Ok(0)
    }
}

/// The simulated routing table.
pub struct SimulatedRoutes {
    address: Mutex<Option<Allowed>>,
    routes: Mutex<Vec<RouteSpec>>,
}

impl Default for SimulatedRoutes {
    fn default() -> Self {
        Self::new()
    }
}

impl SimulatedRoutes {
    /// An empty table.
    pub fn new() -> Self {
        Self {
            address: Mutex::new(None),
            routes: Mutex::new(Vec::new()),
        }
    }
}

impl Routes for SimulatedRoutes {
    fn ensure_address(&self, address: &Allowed) -> Result<(), RouteError> {
        let mut held = self
            .address
            .lock()
            .map_err(|_| RouteError::fatal("the simulated address lock was poisoned"))?;
        *held = Some(address.clone());
        Ok(())
    }

    fn installed(&self) -> Result<Vec<RouteSpec>, RouteError> {
        self.routes
            .lock()
            .map(|routes| routes.clone())
            .map_err(|_| RouteError::fatal("the simulated route lock was poisoned"))
    }

    fn apply(&self, changes: &[RouteChange]) -> Result<(), RouteError> {
        let mut routes = self
            .routes
            .lock()
            .map_err(|_| RouteError::fatal("the simulated route lock was poisoned"))?;
        for change in changes {
            match change {
                RouteChange::Add(spec) => {
                    if !routes.contains(spec) {
                        routes.push(spec.clone());
                    }
                }
                RouteChange::Remove(spec) => routes.retain(|held| held != spec),
            }
        }
        Ok(())
    }
}
