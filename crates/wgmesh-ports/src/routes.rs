use std::fmt;

use wgmesh_core::{Allowed, RouteChange, RouteSpec};

/// The kernel routing table, kept apart from the WireGuard driver on purpose.
///
/// AllowedIPs is WireGuard's cryptokey routing table and the kernel routing
/// table is the kernel's; they answer different questions and change for
/// different reasons. The `WireGuard` driver is never allowed to know about
/// `ip route`, and this adapter never decides *which* prefixes are wanted —
/// `wgmesh_core` does, and `apply` only carries the verdict out.
pub trait Routes: Send + Sync {
    /// Make sure the interface carries this address. Adding an address it
    /// already holds is not an error.
    fn ensure_address(&self, address: &Allowed) -> Result<(), RouteError>;

    /// The routes this adapter owns, and only those.
    ///
    /// Ownership is decided by the marker the adapter writes into `proto`,
    /// never by a state file: a state file can be lost, or belong to another
    /// machine's history, and neither may cause a foreign route to be
    /// deleted.
    fn installed(&self) -> Result<Vec<RouteSpec>, RouteError>;

    /// Apply exactly these route changes.
    fn apply(&self, changes: &[RouteChange]) -> Result<(), RouteError>;
}

/// What went wrong while talking to the kernel routing table.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RouteError {
    /// The interface the route belongs to does not exist.
    Interface(String),
    /// The kernel, or the netlink library in front of it, refused.
    Netlink(String),
    /// The request can not be expressed here: a prefix the address family
    /// does not have, or a netlink future this thread can not drive.
    Unsupported(String),
}

impl fmt::Display for RouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interface(detail) => write!(formatter, "route interface error: {detail}"),
            Self::Netlink(detail) => write!(formatter, "route netlink error: {detail}"),
            Self::Unsupported(detail) => {
                write!(formatter, "route adapter is unavailable: {detail}")
            }
        }
    }
}

impl std::error::Error for RouteError {}
