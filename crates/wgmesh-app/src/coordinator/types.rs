use std::fmt;

use wgmesh_core::{DeviceId, Endpoint, Millis, PublicKey, RelayId};
use wgmesh_ports::PortError;
use wgmesh_ports::coordinator::{DeviceState, Network, RelayState};

macro_rules! error_type {
    ($name:ident) => {
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{self:?}")
            }
        }

        impl std::error::Error for $name {}

        impl From<PortError> for $name {
            fn from(error: PortError) -> Self {
                Self::Store(error)
            }
        }
    };
}

/// How strictly a network treats a device that has just joined.
#[derive(Clone, Copy, Debug)]
pub struct JoinPolicy {
    /// Whether a token's own `auto_approve` may be honoured at all.
    pub allow_auto_approve: bool,
    pub max_devices_per_network: u32,
    /// Addresses at the bottom of the network CIDR that are never handed to a
    /// device.
    pub reserved_hosts: u32,
}

impl Default for JoinPolicy {
    fn default() -> Self {
        Self {
            allow_auto_approve: true,
            max_devices_per_network: 256,
            reserved_hosts: 2,
        }
    }
}

/// When a relay counts as gone, and how much slack a pair gets before it is
/// moved.
#[derive(Clone, Copy, Debug)]
pub struct PlacePolicy {
    pub heartbeat_timeout: Millis,
    pub reassign_after_misses: u32,
}

impl Default for PlacePolicy {
    fn default() -> Self {
        Self {
            heartbeat_timeout: Millis::from_secs(15),
            reassign_after_misses: 3,
        }
    }
}

#[derive(Clone, Debug)]
pub struct JoinRequest {
    /// The token's SHA-256, already decoded by the wire layer. `None` stands for
    /// a token that did not even survive decoding, and is refused the same way
    /// as a spent one.
    pub token_hash: Option<[u8; 32]>,
    pub name: String,
    pub wg_pubkey: PublicKey,
    pub api_pubkey: PublicKey,
    /// Bands this device routes for the mesh. Its own tunnel address is added
    /// whether or not it is listed here.
    pub advertised: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PeerView {
    pub id: DeviceId,
    pub name: String,
    pub wg_pubkey: PublicKey,
    pub tunnel_ip: String,
    pub advertised: Vec<String>,
    /// The relay this pair is assigned to, and the slot the peer listens on
    /// there. Phase one points every peer at its relay slot.
    pub relay: Option<RelayId>,
    pub endpoint: Option<Endpoint>,
    pub state: DeviceState,
}

#[derive(Clone, Debug)]
pub struct RelayPoolEntry {
    pub id: RelayId,
    pub name: String,
    pub endpoint_host: String,
    pub port_range: String,
    pub region: Option<String>,
    pub state: RelayState,
    /// This device's own slot on that relay, once it has one.
    pub slot_port: Option<u16>,
}

#[derive(Clone, Debug)]
pub struct JoinOutcome {
    pub device_id: DeviceId,
    pub state: DeviceState,
    pub network: Network,
    pub tunnel_ip: String,
    pub peers: Vec<PeerView>,
    pub relay_pool: Vec<RelayPoolEntry>,
}

#[derive(Clone, Copy, Debug)]
pub struct SelfObservation {
    pub endpoint: Endpoint,
    pub seen_at: Millis,
}

#[derive(Clone, Debug)]
pub struct MeView {
    pub id: DeviceId,
    pub tunnel_ip: String,
    pub state: DeviceState,
    pub slot_port: Option<u16>,
    /// Where the assigned relay last saw this device's WireGuard socket.
    pub observed: Option<SelfObservation>,
}

#[derive(Clone, Debug)]
pub struct RelayView {
    /// The relay this device falls back to when it is not honouring per-pair
    /// placement.
    pub assigned: Option<RelayId>,
    pub slots: Vec<RelayPoolEntry>,
}

/// The whole of `GET /v1/config`: everything a node needs to program its
/// interface, with no follow-up request.
#[derive(Clone, Debug)]
pub struct ConfigSnapshot {
    pub network: Network,
    pub me: MeView,
    pub relay: RelayView,
    pub peers: Vec<PeerView>,
    pub keepalive_secs: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct Observation {
    pub device: DeviceId,
    pub endpoint: Endpoint,
    pub seen_at: Millis,
}

#[derive(Clone, Copy, Debug)]
pub struct TrafficSample {
    pub device: DeviceId,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub period_start: Millis,
}

#[derive(Clone, Debug)]
pub struct Heartbeat {
    pub at: Millis,
    pub agent_version: Option<String>,
    pub traffic: Vec<TrafficSample>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PunchOutcome {
    Direct,
    Relayed,
    Failed,
}

impl PunchOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relayed => "relayed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PunchReport {
    pub peer: DeviceId,
    pub outcome: PunchOutcome,
    pub at: Millis,
}

/// A pair moved off a relay that stopped answering. `to: None` means the move
/// found nowhere else to put it.
#[derive(Clone, Copy, Debug)]
pub struct RehomeReport {
    pub from: RelayId,
    pub to: Option<RelayId>,
    pub pair: (DeviceId, DeviceId),
}

#[derive(Debug)]
pub enum JoinError {
    /// One answer for a token that is unknown, expired, revoked or exhausted.
    TokenRefused,
    NetworkUnknown(u32),
    NetworkFull {
        limit: u32,
    },
    AddressExhausted,
    Duplicate(&'static str),
    Placement(PlaceError),
    Store(PortError),
}

error_type!(JoinError);

#[derive(Debug)]
pub enum ApproveError {
    UnknownDevice(DeviceId),
    NotApprovable(DeviceState),
    Placement(PlaceError),
    Store(PortError),
}

error_type!(ApproveError);

#[derive(Debug)]
pub enum PlaceError {
    UnknownDevice(DeviceId),
    NotActive(DeviceId),
    NetworkMismatch(DeviceId, DeviceId),
    NoRelayAvailable,
    Store(PortError),
}

error_type!(PlaceError);

#[derive(Debug)]
pub enum ReportError {
    UnknownRelay(RelayId),
    UnknownDevice(DeviceId),
    NotLinked(RelayId, u32),
    Store(PortError),
}

error_type!(ReportError);

#[derive(Debug)]
pub enum ConfigError {
    UnknownDevice(DeviceId),
    UnknownNetwork(u32),
    Store(PortError),
}

error_type!(ConfigError);
