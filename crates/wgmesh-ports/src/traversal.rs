use std::fmt;

use async_trait::async_trait;
use wgmesh_core::{Change, DeviceId, Endpoint, Millis};

/// What the kernel knows about one peer, read back after `apply`.
///
/// `last_handshake` is the only clock the traversal state machine has: a direct
/// path that stops producing handshakes is exactly what `Event::Degraded`
/// reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PeerStatus {
    pub peer: DeviceId,
    pub endpoint: Option<Endpoint>,
    pub last_handshake: Option<Millis>,
}

/// The kernel WireGuard interface. `apply` takes `core::Change` values, so this
/// adapter never decides what the desired state is — `core::diff` does.
pub trait WireGuard: Send + Sync {
    fn apply(&self, changes: &[Change]) -> Result<(), WireGuardError>;

    fn status(&self, peers: &[DeviceId]) -> Result<Vec<PeerStatus>, WireGuardError>;

    fn listen_port(&self) -> Result<u16, WireGuardError>;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Observation {
    pub endpoint: Endpoint,
    pub seen_at: Millis,
}

impl Observation {
    pub const fn new(endpoint: Endpoint, seen_at: Millis) -> Self {
        Self { endpoint, seen_at }
    }
}

/// The control plane as the agent sees it.
///
/// The relay slot and the relay-observed endpoints are deliberately the only
/// things the traversal needs from the coordinator: observations gathered by a
/// relay are only meaningful for the pair that relay actually serves.
#[async_trait]
pub trait CoordinatorApi: Send + Sync {
    async fn relay_slot(&self, peer: DeviceId) -> Result<Option<Endpoint>, ApiError>;

    async fn observations(&self, peer: DeviceId) -> Result<Vec<Observation>, ApiError>;

    async fn report_observations(
        &self,
        device: DeviceId,
        observations: &[Observation],
    ) -> Result<(), ApiError>;
}

pub trait Clock: Send + Sync {
    fn now(&self) -> Millis;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum WireGuardError {
    Interface(String),
    Netlink(String),
    Unsupported(String),
}

impl fmt::Display for WireGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interface(detail) => write!(f, "wireguard interface error: {detail}"),
            Self::Netlink(detail) => write!(f, "wireguard netlink error: {detail}"),
            Self::Unsupported(detail) => write!(f, "wireguard is unavailable: {detail}"),
        }
    }
}

impl std::error::Error for WireGuardError {}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ApiError {
    Transport(String),
    Status(u16, String),
    Decode(String),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(detail) => write!(f, "coordinator transport error: {detail}"),
            Self::Status(code, detail) => write!(f, "coordinator returned {code}: {detail}"),
            Self::Decode(detail) => {
                write!(f, "coordinator response could not be decoded: {detail}")
            }
        }
    }
}

impl std::error::Error for ApiError {}
