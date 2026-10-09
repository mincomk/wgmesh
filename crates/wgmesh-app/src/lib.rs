#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

// The use cases. Knows `wgmesh-core` and `wgmesh-ports`, and nothing else.
//
// The agent decides nothing itself: every judgement — which candidates to try, what to add or
// remove, which routes to install, whether the pin moved — is a pure function in `wgmesh-core`,
// and everything here is the sequence those judgements are made in and the calls they turn into.
// That is why the whole of this crate runs in a test with no kernel, no network and no clock.

pub mod agent;
pub mod doctor;
pub mod routes;

pub use agent::discovery::{CandidateDiscovery, Discovery};
pub use agent::effect::{Effect, dispatch, dispatch_all};
pub use agent::error::AppError;
pub use agent::traversal::{
    DEFAULT_KEEPALIVE, HANDSHAKE_DEADLINE, PeerTraversal, TraversalRunner, degraded,
};
pub use agent::{
    Agent, AgentSettings, ConvergeState, Convergence, EnrollDevice, Ports, Startup, TraversePeers,
};

pub mod coordinator;

pub use doctor::{Check, CheckState, ForwardingObservation, forwarding_checks};
pub use routes::{
    CatchAllPolicy, ConvergenceError, PeerPlan, RouteConvergence, RoutingPolicyError,
    RoutingProblem, describe_routing, desired_routes_of, peer_plan, peers_report, peers_view,
    prefixes_label, resolve_policy, route_plan_view, table_label, unmanaged_plan_view,
    validate_routing,
};
