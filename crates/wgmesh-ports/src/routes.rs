// The kernel routing table.
//
// Separate from `WireGuard` on purpose. AllowedIPs say which peer may claim which address
// *inside* the tunnel; a route says which traffic the kernel hands to the interface at all. They
// are set by different code, chosen from different inputs and torn down by different events, so
// they get different ports.
//
// The decision of which routes to install is a pure function in `wgmesh-core`
// (`desired_routes`), and the decision of what has to change is another (`plan_routes`). What is
// left for the adapter is the kernel's own business, and one rule that is not:
//
// **Only routes we installed are removed.** Every route wgmesh installs carries a dedicated
// protocol mark, and `installed` returns only the marked ones. A host's own routes are never in
// the set this port can see, so a device that has forgotten its state cannot remove them.

use wgmesh_core::{Allowed, RouteChange, RouteSpec};

use crate::RouteError;

/// The kernel routing table, as the agent needs it.
pub trait Routes: Send + Sync {
    /// Put an address on the interface, idempotently.
    ///
    /// The tunnel address is not a route, and it belongs to the same kernel object the routes
    /// do, which is why it lives on this port rather than on `WireGuard`.
    fn ensure_address(&self, address: &Allowed) -> Result<(), RouteError>;

    /// The routes wgmesh installed, and only those.
    fn installed(&self) -> Result<Vec<RouteSpec>, RouteError>;

    /// Write a change list to the table.
    fn apply(&self, changes: &[RouteChange]) -> Result<(), RouteError>;
}
