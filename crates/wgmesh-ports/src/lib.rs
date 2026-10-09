use wgmesh_core::{Allowed, Change, DeviceId, Endpoint, Millis};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceSpec {
    pub name: String,
    pub address: Allowed,
    pub listen_port: u16,
    pub mtu: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireGuardError {
    NoInterface(String),
    Netlink(String),
    Refused(String),
}

impl core::fmt::Display for WireGuardError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoInterface(name) => write!(f, "there is no interface named {name}"),
            Self::Netlink(message) => write!(f, "the kernel refused the change: {message}"),
            Self::Refused(message) => write!(f, "{message}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerStatus {
    pub id: DeviceId,
    pub endpoint: Option<Endpoint>,
    pub last_handshake: Option<Millis>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub allowed: Vec<Allowed>,
}

// The adapter is told what is wanted and does not decide it: `core::diff` turns
// the coordinator's peer list into `Change` values, and the adapter translates
// those into netlink messages.
pub trait WireGuard: Send + Sync {
    fn ensure_interface(&self, spec: &InterfaceSpec) -> Result<(), WireGuardError>;
    fn apply(&self, changes: &[Change]) -> Result<(), WireGuardError>;
    fn status(&self, peers: &[DeviceId]) -> Result<Vec<PeerStatus>, WireGuardError>;
    fn listen_port(&self) -> Result<u16, WireGuardError>;
}
