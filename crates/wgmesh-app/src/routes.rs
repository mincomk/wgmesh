use std::fmt;

use wgmesh_core::{
    Allowed, AllowedIpsPolicy, DeviceId, RouteChange, RoutePrefixes, RouteSpec, RouteTable,
    RoutingError, desired_routes, is_catch_all, plan_routes, program_allowed_ips,
};
use wgmesh_ports::{
    ChangeAction, NamedPeer, PeerReport, RouteChangeView, RouteError, RoutePlanView, Routes,
    format_prefix, reset_routes,
};

/// Which peer carries the catch-all, in the words the configuration file uses.
///
/// This is the first of two independent paths. It decides AllowedIPs — WireGuard's own
/// cryptokey-routing table — and it has nothing to say about the kernel routing table, which
/// is `[route] prefixes`' business.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CatchAllPolicy {
    /// `allowed_ips = "peer"`: every peer keeps its own prefixes.
    Peer,
    /// `allowed_ips = "any"`: the one peer carries everything. Two peers is an error, because
    /// the kernel keeps whichever catch-all it inserted last, silently.
    Any,
    /// `exit_peer = "<name>"`: that peer carries everything and the mesh keeps its own /32s.
    ExitPeer(String),
}

impl CatchAllPolicy {
    pub fn label(&self, resolved: &AllowedIpsPolicy) -> String {
        match resolved {
            AllowedIpsPolicy::Peer => String::from("peer"),
            AllowedIpsPolicy::Any => String::from("any"),
            AllowedIpsPolicy::ExitPeer(_) => match self {
                Self::ExitPeer(name) => format!("exit:{name}"),
                _ => String::from("exit"),
            },
        }
    }
}

/// A routing refusal in words an operator can act on.
///
/// `core::route` carries no message text — it is pure decision-making — so the words live
/// here, where both the command line and the configuration report can reach them.
pub fn describe_routing(error: &RoutingError) -> String {
    match error {
        RoutingError::CatchAllPrefix(prefix) => format!(
            "the default route ({}) must never be installed; express a default with \
             `exit_peer`, and let the kernel keep the bands you chose",
            format_prefix(prefix)
        ),
        RoutingError::AnyPolicyNeedsOnePeer(count) => format!(
            "`allowed_ips = \"any\"` gives every peer 0.0.0.0/0, which the kernel resolves by \
             insertion order; {count} peers are configured"
        ),
        RoutingError::UnknownExitPeer(device) => format!(
            "the exit peer resolves to device {}, which is not in the peer list",
            device.0
        ),
        RoutingError::PrefixesWithUnmanagedTable(count) => format!(
            "`table = \"off\"` means no route is installed, but `prefixes` lists {count} band(s)"
        ),
    }
}

/// Why a peer policy could not be turned into AllowedIPs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RoutingPolicyError {
    /// `exit_peer` names no peer this device knows. Named for the `DeviceId`-keyed variant
    /// in `core::route`, which can only be raised once a name has resolved to an id.
    UnknownExitPeer(String),
    /// The policy is impossible, which `core::route` decides.
    Core(RoutingError),
}

impl fmt::Display for RoutingPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownExitPeer(name) => {
                write!(
                    formatter,
                    "`exit_peer = \"{name}\"` names no peer this device knows"
                )
            }
            Self::Core(error) => formatter.write_str(&describe_routing(error)),
        }
    }
}

impl std::error::Error for RoutingPolicyError {}

impl RoutingPolicyError {
    /// A stable identifier, for `--json` output and for grep.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownExitPeer(_) => "unknown_exit_peer",
            Self::Core(error) => plan_code(error),
        }
    }
}

impl From<RoutingError> for RoutingPolicyError {
    fn from(error: RoutingError) -> Self {
        Self::Core(error)
    }
}

/// Turn the two switches — `allowed_ips` and `exit_peer` — into the policy `core` programs.
///
/// `exit_peer` wins when both are set, because a name is more specific than a mode; the
/// configuration validator refuses the combination rather than letting this decide quietly.
pub fn resolve_policy(
    policy: &CatchAllPolicy,
    peers: &[NamedPeer],
) -> Result<AllowedIpsPolicy, RoutingPolicyError> {
    match policy {
        CatchAllPolicy::Peer => Ok(AllowedIpsPolicy::Peer),
        CatchAllPolicy::Any => Ok(AllowedIpsPolicy::Any),
        CatchAllPolicy::ExitPeer(name) => peers
            .iter()
            .find(|peer| peer.name == *name)
            .map(|peer| AllowedIpsPolicy::ExitPeer(peer.id()))
            .ok_or_else(|| RoutingPolicyError::UnknownExitPeer(name.clone())),
    }
}

/// What the WireGuard adapter should program: one entry per peer, plus the policy's name.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PeerPlan {
    pub policy: String,
    pub assigned: Vec<(DeviceId, Vec<Allowed>)>,
}

/// The AllowedIPs for the whole peer set.
///
/// This never consults `[route]`. A catch-all here says "this peer may send from anywhere",
/// which is a routing policy for WireGuard, not a kernel route.
pub fn peer_plan(
    policy: &CatchAllPolicy,
    peers: &[NamedPeer],
) -> Result<PeerPlan, RoutingPolicyError> {
    let resolved = resolve_policy(policy, peers)?;
    let label = policy.label(&resolved);
    let specs: Vec<wgmesh_core::PeerSpec> = peers.iter().map(|peer| peer.spec.clone()).collect();
    Ok(PeerPlan {
        policy: label,
        assigned: program_allowed_ips(resolved, &specs)?,
    })
}

/// The rows `wgmesh peers` prints: what each peer is programmed with, next to what it
/// advertised. Under `exit_peer` exactly one row carries the catch-all; the rest keep their
/// own host prefixes.
pub fn peers_report(
    policy: &CatchAllPolicy,
    peers: &[NamedPeer],
) -> Result<Vec<PeerReport>, RoutingPolicyError> {
    let plan = peer_plan(policy, peers)?;
    let mut report = Vec::new();
    for (id, allowed) in &plan.assigned {
        let peer = peers
            .iter()
            .find(|peer| peer.id() == *id)
            .ok_or_else(|| RoutingPolicyError::UnknownExitPeer(String::from("unknown")))?;
        report.push(PeerReport {
            id: id.0,
            name: peer.name.clone(),
            policy: plan.policy.clone(),
            carries_catch_all: allowed.iter().any(is_catch_all),
            allowed_ips: allowed.iter().map(format_prefix).collect(),
            advertised: peer.spec.allowed.iter().map(format_prefix).collect(),
        });
    }
    Ok(report)
}

/// Everything that can be wrong about a routing configuration, so a checker can report all of
/// it at once instead of stopping at the first thing it dislikes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RoutingProblem {
    /// The peer policy cannot be programmed.
    Policy(RoutingPolicyError),
    /// The route plan cannot be built.
    Plan(RoutingError),
}

impl RoutingProblem {
    /// A stable identifier, for `--json` output and for grep.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Policy(RoutingPolicyError::UnknownExitPeer(_)) => "unknown_exit_peer",
            Self::Policy(RoutingPolicyError::Core(error)) => plan_code(error),
            Self::Plan(error) => plan_code(error),
        }
    }

    pub fn detail(&self) -> String {
        match self {
            Self::Policy(error) => error.to_string(),
            Self::Plan(error) => describe_routing(error),
        }
    }

    pub fn remedy(&self) -> &'static str {
        match self {
            Self::Policy(RoutingPolicyError::UnknownExitPeer(_)) => {
                "name a peer `wgmesh peers` shows, or drop `exit_peer`"
            }
            Self::Policy(RoutingPolicyError::Core(RoutingError::AnyPolicyNeedsOnePeer(_))) => {
                "use `allowed_ips = \"peer\"`, or name one gateway with `exit_peer`"
            }
            Self::Policy(RoutingPolicyError::Core(_)) | Self::Plan(_) => match self {
                Self::Policy(RoutingPolicyError::Core(RoutingError::CatchAllPrefix(_)))
                | Self::Plan(RoutingError::CatchAllPrefix(_)) => {
                    "take the catch-all out of `prefixes` and name a gateway in `exit_peer`"
                }
                _ => "set `table = \"main\"` (or a number), or set `prefixes = \"none\"`",
            },
        }
    }
}

impl fmt::Display for RoutingProblem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail())
    }
}

fn plan_code(error: &RoutingError) -> &'static str {
    match error {
        RoutingError::CatchAllPrefix(_) => "catch_all_prefix",
        RoutingError::AnyPolicyNeedsOnePeer(_) => "any_policy_needs_one_peer",
        RoutingError::UnknownExitPeer(_) => "unknown_exit_peer",
        RoutingError::PrefixesWithUnmanagedTable(_) => "prefixes_with_unmanaged_table",
    }
}

/// Check a routing configuration the way `wgmesh config check` does: every problem, one pass.
pub fn validate_routing(
    policy: &CatchAllPolicy,
    peers: &[(String, Vec<Allowed>)],
    prefixes: &RoutePrefixes,
    table: RouteTable,
    metric: Option<u32>,
    network: &[Allowed],
    advertised: &[Allowed],
) -> Vec<RoutingProblem> {
    let mut problems = Vec::new();
    if let Err(error) = peers_view(policy, peers) {
        problems.push(RoutingProblem::Policy(error));
    }
    if let Err(error) = desired_routes(network, advertised, prefixes, table, metric) {
        problems.push(RoutingProblem::Plan(error));
    }
    problems
}

/// The rows `wgmesh peers` prints, from names and advertised bands alone.
///
/// The coordinator's own device ids are not part of this: the report is keyed by name, and
/// the ids the policy programs are used only to carry a peer through the computation. They
/// are positions, not identities, and nothing outside this function sees them.
pub fn peers_view(
    policy: &CatchAllPolicy,
    peers: &[(String, Vec<Allowed>)],
) -> Result<Vec<PeerReport>, RoutingPolicyError> {
    let named: Vec<NamedPeer> = peers
        .iter()
        .enumerate()
        .map(|(position, (name, advertised))| {
            NamedPeer::new(
                name.clone(),
                wgmesh_core::PeerSpec {
                    id: DeviceId(position as u32),
                    key: wgmesh_core::PublicKey::from_bytes([position as u8; 32]),
                    allowed: advertised.clone(),
                    endpoint: None,
                    keepalive: None,
                },
            )
        })
        .collect();
    peers_report(policy, &named)
}

/// How a routing table is named on the command line and in the plan.
pub fn table_label(table: RouteTable) -> String {
    match table {
        RouteTable::Main => String::from("main"),
        RouteTable::Number(number) => number.to_string(),
        RouteTable::Unmanaged => String::from("off"),
    }
}

/// How a prefix policy is named in the plan.
pub fn prefixes_label(prefixes: &RoutePrefixes) -> String {
    match prefixes {
        RoutePrefixes::Auto => String::from("auto"),
        RoutePrefixes::None => String::from("none"),
        RoutePrefixes::Only(list) => list
            .iter()
            .map(format_prefix)
            .collect::<Vec<String>>()
            .join(","),
    }
}

/// The plan `wgmesh routes plan` prints, computed without touching anything.
///
/// The desired side comes from `prefixes` alone, so a default route cannot appear here:
/// `core::desired_routes` refuses one, and `table = "off"` yields nothing at all.
pub fn route_plan_view(
    desired: &[RouteSpec],
    prefixes: &RoutePrefixes,
    table: RouteTable,
    installed: &[RouteSpec],
) -> RoutePlanView {
    let changes = plan_routes(desired, installed);
    RoutePlanView {
        table: table_label(table),
        prefixes: prefixes_label(prefixes),
        address: Some(String::from("auto")),
        changes: changes
            .iter()
            .map(|change| view_of(change, table))
            .collect(),
        installed: installed
            .iter()
            .map(|spec| format_prefix(&spec.prefix))
            .collect(),
    }
}

/// The plan for a table this device does not manage.
///
/// `table = "off"` means wgmesh installs no kernel route and takes none back, so the plan is
/// empty and the kernel is not asked anything. Whatever an earlier configuration left behind
/// is removed by `wgmesh routes reset`, the one command that deletes by marker.
pub fn unmanaged_plan_view(prefixes: &RoutePrefixes) -> RoutePlanView {
    RoutePlanView {
        table: table_label(RouteTable::Unmanaged),
        prefixes: prefixes_label(prefixes),
        address: Some(String::from("auto")),
        changes: Vec::new(),
        installed: Vec::new(),
    }
}

/// The desired routes alone, so a configuration can be refused before the kernel is asked
/// anything at all.
pub fn desired_routes_of(
    prefixes: &RoutePrefixes,
    table: RouteTable,
    metric: Option<u32>,
    network: &[Allowed],
    advertised: &[Allowed],
) -> Result<Vec<RouteSpec>, RoutingError> {
    desired_routes(network, advertised, prefixes, table, metric)
}

fn view_of(change: &RouteChange, table: RouteTable) -> RouteChangeView {
    let (action, spec) = match change {
        RouteChange::Add(spec) => (ChangeAction::Add, spec),
        RouteChange::Remove(spec) => (ChangeAction::Remove, spec),
    };
    RouteChangeView {
        action,
        prefix: format_prefix(&spec.prefix),
        table: table_label(if spec.table == RouteTable::Unmanaged {
            table
        } else {
            spec.table
        }),
        metric: spec.metric,
    }
}

/// Why convergence stopped.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ConvergenceError {
    /// The configuration asks for something impossible; nothing was touched.
    Routing(RoutingError),
    /// The kernel adapter refused or failed.
    Routes(RouteError),
}

impl fmt::Display for ConvergenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Routing(error) => formatter.write_str(&describe_routing(error)),
            Self::Routes(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ConvergenceError {}

impl From<RoutingError> for ConvergenceError {
    fn from(error: RoutingError) -> Self {
        Self::Routing(error)
    }
}

impl From<RouteError> for ConvergenceError {
    fn from(error: RouteError) -> Self {
        Self::Routes(error)
    }
}

/// The one place where the desired routes meet what the kernel carries.
///
/// [`plan`](RouteConvergence::plan) answers "what would change?" and touches nothing, which
/// is what `wgmesh routes plan` prints; [`settle`](RouteConvergence::settle) applies the
/// same list; [`reset`](RouteConvergence::reset) removes what the marker owns.
pub struct RouteConvergence<'a, R: Routes> {
    routes: &'a R,
    prefixes: RoutePrefixes,
    table: RouteTable,
    metric: Option<u32>,
    network: Vec<Allowed>,
    advertised: Vec<Allowed>,
}

impl<'a, R: Routes> RouteConvergence<'a, R> {
    pub fn new(routes: &'a R, table: RouteTable, prefixes: RoutePrefixes) -> Self {
        Self {
            routes,
            prefixes,
            table,
            metric: None,
            network: Vec::new(),
            advertised: Vec::new(),
        }
    }

    pub fn metric(mut self, metric: Option<u32>) -> Self {
        self.metric = metric;
        self
    }

    pub fn network(mut self, network: &[Allowed]) -> Self {
        self.network = network.to_vec();
        self
    }

    pub fn advertised(mut self, advertised: &[Allowed]) -> Self {
        self.advertised = advertised.to_vec();
        self
    }

    pub fn table(&self) -> RouteTable {
        self.table
    }

    pub fn desired(&self) -> Result<Vec<RouteSpec>, RoutingError> {
        desired_routes(
            &self.network,
            &self.advertised,
            &self.prefixes,
            self.table,
            self.metric,
        )
    }

    pub fn installed(&self) -> Result<Vec<RouteSpec>, RouteError> {
        self.routes.installed()
    }

    pub fn plan(&self) -> Result<Vec<RouteChange>, ConvergenceError> {
        let desired = self.desired()?;
        let installed = self.routes.installed()?;
        Ok(plan_routes(&desired, &installed))
    }

    /// Put the tunnel address on the interface and apply the planned changes. Both halves
    /// are idempotent, so a second call after a successful first one runs no route command.
    pub fn settle(
        &self,
        tunnel_ip: Option<&Allowed>,
    ) -> Result<Vec<RouteChange>, ConvergenceError> {
        if let Some(address) = tunnel_ip {
            self.routes.ensure_address(address)?;
        }
        let changes = self.plan()?;
        self.routes.apply(&changes)?;
        Ok(changes)
    }

    /// Delete every route the marker owns. Nothing without the marker is touched.
    pub fn reset(&self) -> Result<Vec<RouteSpec>, RouteError> {
        reset_routes(self.routes)
    }
}
