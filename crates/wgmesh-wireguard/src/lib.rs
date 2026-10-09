/// The translation from `wgmesh_core` values into netlink message content.
///
/// The netlink calls themselves can not run without `CAP_NET_ADMIN`, so
/// everything that can be decided without the kernel lives here as a plain
/// function and is unit tested on its own.
pub mod attrs;

/// base64, the encoding `wg(8)` writes keys in.
pub mod base64;

/// The `wgmesh_ports::WireGuard` driver.
pub mod netlink;

/// The `wgmesh_ports::Routes` adapter.
pub mod routes;

/// The synchronous-over-asynchronous bridge the netlink crates need.
pub mod runtime;

/// `sysctl` reads and writes that can be undone.
pub mod sysctl;

pub use attrs::{
    PeerOp, allowed_from_ip, allowed_ip, device_config, device_properties, peer_config, peer_op,
    removal_peer,
};
pub use netlink::{NetlinkWireGuard, PeerCounters};
pub use routes::{
    NetlinkRoutes, RouteOp, WG_ROUTE_PROTO, installed_from, installed_spec, route_dump_message,
    route_message, route_ops, split_address,
};
pub use runtime::NetlinkRuntime;
pub use sysctl::{Forwarding, SysctlChange, enable_forwarding};

/// The interface the driver is asked to bring up.
///
/// This is deliberately not part of `wgmesh_ports::WireGuard`, which programs
/// peers and reads status but does not own the link: creating the interface is
/// a one-time act of the composition root, and leaving it out of the port
/// keeps every use case from having to think about it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InterfaceSpec {
    /// Interface name, e.g. `wgmesh0`.
    pub name: String,
    /// MTU to set on the link, when the caller has an opinion.
    pub mtu: Option<u32>,
    /// UDP port the interface listens on, when it is pinned.
    pub listen_port: Option<u16>,
    /// base64 encoded X25519 private key, the encoding `wg(8)` writes.
    pub private_key: Option<String>,
}

impl InterfaceSpec {
    /// The interface `name` with no properties beyond its name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mtu: None,
            listen_port: None,
            private_key: None,
        }
    }
}
