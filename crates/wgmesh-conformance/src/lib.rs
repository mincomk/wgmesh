// The M0 conformance lab: the Rust translation of the two Python labs the design
// was measured against, and the gate the M0 milestone is held to.
//
// What is real here:
//
//   * real UdpSockets on 127.0.0.1 -- no in-memory packet bus;
//   * the coordinator and every relay run as SEPARATE PROCESSES, so the
//     coordinator's own socket table can be read from /proc and a relay can be
//     genuinely killed;
//   * the path decision is made by wgmesh-core's own state machine (step), not
//     by a reimplementation here.
//
// What is simulated, and why it is honest to do so:
//
//   * Kernel WireGuard is replaced by `agent::Agent`, a stand-in that keeps
//     exactly one property, quoted from wg(8): "This endpoint will be updated
//     automatically to the most recent source IP address and port of correctly
//     authenticated packets from the peer." It verifies the mac1 on every
//     handshake it accepts, so only authenticated traffic moves the endpoint. It
//     is not a WireGuard device and it does no crypto beyond that check.
//   * NAT is `nat::Nat`, a NAPT that implements the RFC 4787 axes explicitly:
//     endpoint-independent vs endpoint-dependent MAPPING and
//     endpoint-independent vs address/port-dependent FILTERING, plus a mapping
//     idle timeout.
//   * mac1-derived routing is replaced by a 2-byte destination tag in front of
//     each relayed packet, which the relay strips. The relay DOES verify the
//     packet's mac1 against the destination's key, so the mac1 computation is
//     exercised on the wire; what is stood in for is the relay's lookup from
//     mac1 to device, which in M0 is the ingress slot port anyway.
//
// This crate also carries the lab's own minimal coordinator and relay binaries
// (`lab-coordinator`, `lab-relayd`). They exist because the conformance gate has
// to be runnable: when `wgmesh-coordinator` and `wgmesh-relay` land real
// implementations, these two should be deleted and the harness pointed at them.
// The engine both use is not duplicated -- relay routing is `wgmesh_core`'s own
// `RelayTable`, and the agent's traversal is its own `step`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

pub mod agent;
pub mod coordinator;
pub mod hex;
pub mod http;
pub mod lab;
pub mod msg;
pub mod nat;
pub mod proc;
pub mod relay;
pub mod wire;

// The control plane as this lab speaks it: the coordinator's wire types, the
// HTTP/1.1 codec that carries them, and the /proc socket accounting. One
// protocol, so one module.
pub mod control {
    pub use crate::hex::*;
    pub use crate::http;
    pub use crate::http::*;
    pub use crate::msg::*;
    pub use crate::proc;
}

pub use agent::{Agent, AgentConfig, Snapshot};
pub use lab::{
    CampaignOutcome, CoordinatorProcess, Duo, Peer, RelayProcess, campaign, relay_forwarded,
    relay_of, spawn_fleet, start_pair, wait_for_fleet, wait_until,
};
pub use msg::*;
pub use nat::{Nat, NatMode};
pub use wgmesh_core::{Path, Phase, TraversalConfig};
