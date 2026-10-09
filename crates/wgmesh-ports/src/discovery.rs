// Where a direct candidate can come from on this node's side: the addresses it
// holds, and the router that may be willing to map one of them.
//
// Two of the five candidate classes are derived here rather than learned from the
// relay. Both are cheap, and both have a cost the port makes explicit.
//
// **The addresses.** A private address that the peer is also on beats every other
// candidate, because a packet to it never leaves the wire. A global IPv6 address
// is the next best, because there is no address translation in front of it. Both
// are read from the interfaces this node has, which is a syscall rather than a
// conversation, so `InterfaceInventory` is synchronous.
//
// **The mapping.** NAT-PMP and UPnP-IGD answer one question: what is my external
// address and port for this local port. Asking means talking to a device this
// node does not own, over a protocol with a long history of being the weakest
// thing on the network, which is why `PortMapper` is only ever called when the
// operator has switched traversal.upnp on. Off is the default and off means the
// trait is not called at all — not called and filtered, not called.

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use wgmesh_core::Endpoint;

use crate::PortError;

/// The failure of address discovery or of a port mapping request.
///
/// An unsupported or unreachable router is `Recoverable` rather than `Fatal`:
/// nothing is broken, another router — or none — would work, and the traversal
/// proceeds without the class. An interface that cannot be read at all is
/// `Transient` for the same reason: the answer would probably be different a
/// second later.
pub type DiscoveryError = PortError;

/// Where a local address can be used as a direct candidate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddressScope {
    /// A private address — the peer may be behind the same NAT, in which case
    /// this never leaves the wire.
    Lan,
    /// A global IPv6 address, which has no translation in front of it.
    Ipv6Global,
}

/// One address this node holds, with what makes it useful.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LocalAddress {
    /// The address itself.
    pub ip: IpAddr,
    /// Why it is a candidate at all.
    pub scope: AddressScope,
}

impl LocalAddress {
    /// An address and the scope it falls in.
    pub const fn new(ip: IpAddr, scope: AddressScope) -> Self {
        Self { ip, scope }
    }
}

/// The addresses on this node's interfaces, and the UDP port its WireGuard
/// interface listens on.
///
/// The listen port is part of the port because an endpoint is an address *and* a
/// port: `192.168.1.20` is not a candidate, `192.168.1.20:51820` is.
pub trait InterfaceInventory: Send + Sync {
    /// Every address that could serve as a candidate, with its scope.
    fn addresses(&self) -> Result<Vec<LocalAddress>, DiscoveryError>;

    /// The UDP port the WireGuard interface listens on.
    fn listen_port(&self) -> Result<u16, DiscoveryError>;
}

/// The external address a router handed back for a local port.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MappedPort {
    /// The address and port the router says the world sees.
    pub endpoint: Endpoint,
}

impl MappedPort {
    /// A mapping result.
    pub const fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }
}

/// A NAT-PMP or UPnP-IGD gateway, as the agent needs it.
///
/// The lifetime is the caller's because the answer has one: a mapping outlives
/// its request only for as long as the router was asked to keep it, and a
/// candidate that outlives its mapping is worse than no candidate.
#[async_trait]
pub trait PortMapper: Send + Sync {
    /// Ask for the external address and port of `local_port`.
    async fn map(&self, local_port: u16, lifetime: Duration) -> Result<MappedPort, DiscoveryError>;
}
