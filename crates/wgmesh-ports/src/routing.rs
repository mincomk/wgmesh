// What the routing policy needs in order to be spoken about: who a peer is, what the plan
// looks like, and the two kernel-side ports `[forwarding]` reaches through.
//
// `wgmesh-core::route` decides; these are the words the decision travels in. The views are
// deliberately free of serde: the command line renders them, and a rendering decision does not
// belong in the crate that names the ports.
//
// Ownership is worth one sentence here, because three of these types depend on it. Every route
// wgmesh installs carries a dedicated protocol mark (see [`crate::MARKER_PROTO`]), and both
// `Routes::installed` and [`reset_routes`] work from that mark alone. There is no `reset` method
// on the port because "the routes we installed" is already what `installed` means: turning that
// list into removals is the whole of reset, and one definition of ownership beats two.

use std::fmt;

use wgmesh_core::{Allowed, DeviceId, PeerSpec, RouteChange, RouteSpec};

use crate::{RouteError, Routes};

/// A peer as the operator knows it: the name `exit_peer` is written with, next to the spec the
/// WireGuard adapter programs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NamedPeer {
    pub name: String,
    pub spec: PeerSpec,
}

impl NamedPeer {
    pub fn new(name: impl Into<String>, spec: PeerSpec) -> Self {
        Self {
            name: name.into(),
            spec,
        }
    }

    pub fn id(&self) -> DeviceId {
        self.spec.id
    }
}

/// The kernel tunables `[forwarding]` reaches, named the way `sysctl` names them.
pub trait Sysctl: Send + Sync {
    fn read(&self, key: &str) -> Result<String, RouteError>;
    fn write(&self, key: &str, value: &str) -> Result<(), RouteError>;
}

/// The forwarding rules this package is willing to own: one nftables table, and nothing else.
pub trait Firewall: Send + Sync {
    fn ensure(&self) -> Result<(), RouteError>;
    fn remove(&self) -> Result<(), RouteError>;
}

/// What `[forwarding]` asks for, with the configuration's own enums left behind.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ForwardingPolicy {
    pub enabled: bool,
    pub sysctl: bool,
    pub manage_firewall: bool,
}

/// One action of a route plan, in the words `wgmesh routes plan` prints.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChangeAction {
    Add,
    Remove,
}

impl ChangeAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Remove => "remove",
        }
    }
}

/// One line of `wgmesh routes plan`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RouteChangeView {
    pub action: ChangeAction,
    pub prefix: String,
    pub table: String,
    pub metric: Option<u32>,
}

impl RouteChangeView {
    pub fn line(&self) -> String {
        let metric = match self.metric {
            Some(metric) => format!(" metric {metric}"),
            None => String::new(),
        };
        format!(
            "{action:<6} {prefix} table {table}{metric}",
            action = self.action.as_str(),
            prefix = self.prefix,
            table = self.table,
        )
    }
}

/// What `wgmesh routes plan` shows: what would be added, what would be removed, and under which
/// policy. A default route can never appear here, because the plan is built from `prefixes` and
/// `core::desired_routes` refuses to hand one over.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RoutePlanView {
    pub table: String,
    pub prefixes: String,
    pub address: Option<String>,
    pub changes: Vec<RouteChangeView>,
    pub installed: Vec<String>,
}

impl RoutePlanView {
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    pub fn text(&self) -> String {
        let mut rendered = String::new();
        rendered.push_str(&format!(
            "table    {}\nprefixes {}\naddress  {}\n",
            self.table,
            self.prefixes,
            self.address.as_deref().unwrap_or("none")
        ));
        if self.changes.is_empty() {
            rendered.push_str("changes  none\n");
        } else {
            rendered.push_str("changes\n");
            for change in &self.changes {
                rendered.push_str("  ");
                rendered.push_str(&change.line());
                rendered.push('\n');
            }
        }
        rendered
    }
}

/// One row of `wgmesh peers`. `allowed_ips` is what the adapter programs, not what the peer
/// advertised: under `any` and `exit_peer` the two differ, and that difference is the point.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PeerReport {
    pub id: u32,
    pub name: String,
    pub policy: String,
    pub carries_catch_all: bool,
    pub allowed_ips: Vec<String>,
    pub advertised: Vec<String>,
}

impl PeerReport {
    pub fn line(&self) -> String {
        let marker = if self.carries_catch_all { "*" } else { " " };
        format!(
            "{marker} {name:<24} {id:<6} {policy:<12} {allowed}",
            name = self.name,
            id = self.id,
            policy = self.policy,
            allowed = self.allowed_ips.join(", ")
        )
    }
}

/// Delete every route the adapter reports as ours, and answer with what was deleted.
///
/// The list comes from `installed`, which sees only marked routes, so a route the host put in
/// the same table is not touched; and because the list is turned into removals rather than into
/// a flush, what is deleted is exactly what was reported.
pub fn reset_routes<R: Routes + ?Sized>(routes: &R) -> Result<Vec<RouteSpec>, RouteError> {
    let installed = routes.installed()?;
    if installed.is_empty() {
        return Ok(installed);
    }
    let changes: Vec<RouteChange> = installed.iter().cloned().map(RouteChange::Remove).collect();
    routes.apply(&changes)?;
    Ok(installed)
}

impl<T: Routes + ?Sized> Routes for std::sync::Arc<T> {
    fn ensure_address(&self, address: &Allowed) -> Result<(), RouteError> {
        (**self).ensure_address(address)
    }

    fn installed(&self) -> Result<Vec<RouteSpec>, RouteError> {
        (**self).installed()
    }

    fn apply(&self, changes: &[RouteChange]) -> Result<(), RouteError> {
        (**self).apply(changes)
    }
}

impl<T: Sysctl + ?Sized> Sysctl for std::sync::Arc<T> {
    fn read(&self, key: &str) -> Result<String, RouteError> {
        (**self).read(key)
    }

    fn write(&self, key: &str, value: &str) -> Result<(), RouteError> {
        (**self).write(key, value)
    }
}

impl<T: Firewall + ?Sized> Firewall for std::sync::Arc<T> {
    fn ensure(&self) -> Result<(), RouteError> {
        (**self).ensure()
    }

    fn remove(&self) -> Result<(), RouteError> {
        (**self).remove()
    }
}

impl fmt::Display for ChangeAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
