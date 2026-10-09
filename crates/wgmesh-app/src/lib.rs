// The use cases. Knows `wgmesh-core` and `wgmesh-ports`, and nothing else.
//
// The agent decides nothing itself: every judgement — which candidates to try, what to add or
// remove, which routes to install, whether the pin moved — is a pure function in `wgmesh-core`,
// and everything here is the sequence those judgements are made in and the calls they turn into.
// That is why the whole of this crate runs in a test with no kernel, no network and no clock.

pub mod agent;

pub use agent::effect::{Effect, dispatch, dispatch_all};
pub use agent::error::AppError;
pub use agent::{
    Agent, AgentSettings, ConvergeState, Convergence, EnrollDevice, Ports, Startup, TraversePeers,
};
