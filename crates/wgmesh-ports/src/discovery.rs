use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use wgmesh_core::Endpoint;

/// Where a local address can be used as a direct candidate.
///
/// A private address on the same LAN as the peer beats everything else, because
/// it never leaves the wire. A global IPv6 address has no NAT in front of it, so
/// it is the second best. Everything else has to be learned from outside.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddressScope {
    Lan,
    Ipv6Global,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LocalAddress {
    pub ip: IpAddr,
    pub scope: AddressScope,
}

impl LocalAddress {
    pub const fn new(ip: IpAddr, scope: AddressScope) -> Self {
        Self { ip, scope }
    }
}

/// The addresses this node holds and the port its WireGuard interface listens
/// on. Reading them is a cheap syscall, so this port is synchronous; the
/// adapters that need to talk to the network are the async ones.
pub trait InterfaceInventory: Send + Sync {
    fn addresses(&self) -> Result<Vec<LocalAddress>, DiscoveryError>;

    fn listen_port(&self) -> Result<u16, DiscoveryError>;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MappedPort {
    pub endpoint: Endpoint,
}

impl MappedPort {
    pub const fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }
}

/// NAT-PMP and UPnP-IGD both answer one question: "what is my external
/// address:port for this local port". The agent only asks when the operator has
/// switched `traversal.upnp` on, because both protocols mean talking to the
/// router and are off by default.
#[async_trait]
pub trait PortMapper: Send + Sync {
    async fn map(&self, local_port: u16, lifetime: Duration) -> Result<MappedPort, DiscoveryError>;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DiscoveryError {
    Unsupported(String),
    Protocol(String),
    Io(String),
    NoAddress(String),
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(detail) => write!(f, "port mapping is not supported: {detail}"),
            Self::Protocol(detail) => write!(f, "port mapping protocol error: {detail}"),
            Self::Io(detail) => write!(f, "address discovery failed: {detail}"),
            Self::NoAddress(detail) => write!(f, "no usable local address: {detail}"),
        }
    }
}

impl std::error::Error for DiscoveryError {}
